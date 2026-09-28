#!/usr/bin/env python3
"""Read-only structural evidence and at most six explicit-source ICMP requests.

No interface/firewall/service/key mutation is implemented. Results cover the
whole acceptance registry but do not promote partial checks to full acceptance.
Raw observations and exact commands stay in a new private .local/ directory.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import tempfile

import check_inventory
import discover

REPO = Path(__file__).resolve().parents[1]
ROLES = ("gz", "villa", "cave")
IDS = ([f"A{i:02}" for i in range(1, 6)] + [f"S{i:02}" for i in range(1, 11)]
       + [f"O{i:02}" for i in range(1, 5)] + [f"P{i:02}" for i in range(1, 9)])
KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
IDENTITY = {"gz": ("/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key.pub"),
            "villa": ("/etc/dropbear/dropbear_ed25519_host_key",),
            "cave": ("/etc/dropbear/dropbear_ed25519_host_key",)}
WG_FIELDS = ("public-key", "peers", "allowed-ips", "transfer", "listen-port")


def stamp():
    return datetime.now(timezone.utc).isoformat()


def probe_script(commands):
    prefix = '''set -u
probe() {
    label=$1; shift
    printf '\\nWGMVP_BEGIN %s\\n' "$label"
    rc=0
    "$@" || rc=$?
    printf '\\nWGMVP_END %s %s\\n' "$label" "$rc"
}
'''
    return prefix + "\n".join("probe " + shlex.join([label, *command]) for label, command in commands) + "\n"


def parse_probes(output):
    result, label, lines = {}, None, []
    for line in output.splitlines():
        if line.startswith("WGMVP_BEGIN "):
            candidate = line.removeprefix("WGMVP_BEGIN ")
            if label is not None or candidate in result or not re.fullmatch(r"[a-z0-9_-]+", candidate):
                raise ValueError("duplicate or malformed probe framing")
            label, lines = candidate, []
        elif line.startswith("WGMVP_END "):
            parts = line.split()
            if len(parts) != 3 or parts[1] != label or not parts[2].isdigit():
                raise ValueError("unmatched probe completion")
            result[label] = {"returncode": int(parts[2]), "stdout": "\n".join(lines).strip()}
            label, lines = None, []
        elif label is not None:
            lines.append(line)
        elif line.strip():
            raise ValueError("unexpected output outside probe framing")
    if label is not None:
        raise ValueError("incomplete probe output")
    return result


def commands_for(role):
    commands = [("uid", ["id", "-u"])]
    permissions = "ls -ldn \"$@\" | awk '{mode=($1==\"drwx------\" ? \"700\" : ($1==\"-rw-------\" ? \"600\" : \"UNSAFE\")); print $3 \":\" mode \":\" $NF}'"
    if role == "gpu":
        # Filter on GPU before stdout reaches local storage; ProxyCommand may contain secrets.
        commands += [("rt_alias", ["sh", "-c", "ssh -G rt | awk '$1==\"hostname\" || $1==\"user\" || $1==\"port\" {print}'"])]
    else:
        commands += [("identity", ["sha256sum", *IDENTITY[role]]),
                     ("owner_public", ["cat", f"/etc/wgmvp/public.{role}"]),
                     ("backend", ["/etc/wgmvp/controller.sh", "status"]),
                     ("permissions", ["sh", "-c", permissions, "wgmvp-permissions", "/etc/wgmvp", "/etc/wgmvp/private.key", "/etc/wgmvp/config.env"]),
                     ("backup_permissions", ["find", "/etc/wgmvp/backups", "-type", "f", "-exec", "sh", "-c", permissions, "wgmvp-permissions", "{}", ";"])]
        wg = ["ip", "netns", "exec", "wgmvp"] if role == "gz" else []
        commands += [("wg_" + field.replace("-", "_"), [*wg, "wg", "show", "wgmvp", field]) for field in WG_FIELDS]
    commands += [("addresses", ["ip", "-j", "-4", "address", "show"]),
                 ("routes", ["ip", "-j", "-4", "route", "show", "table", "all"]),
                 ("rules", ["ip", "-j", "-4", "rule", "show"])]
    if role == "gz":
        commands += [("host_firewall", ["nft", "-j", "-s", "list", "ruleset"]),
                     ("host_forwarding", ["sysctl", "-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]),
                     ("host_sockets", ["ss", "-H", "-tuln"]),
                     ("ns_links", ["ip", "-n", "wgmvp", "-j", "-d", "link", "show"]),
                     ("ns_routes", ["ip", "-n", "wgmvp", "-j", "-4", "route", "show", "table", "all"]),
                     ("ns_routes6", ["ip", "-n", "wgmvp", "-j", "-6", "route", "show", "table", "all"]),
                     ("ns_firewall", ["ip", "netns", "exec", "wgmvp", "nft", "-j", "-s", "list", "ruleset"]),
                     ("ns_sockets", ["ip", "netns", "exec", "wgmvp", "ss", "-H", "-tuln"])]
    return commands


def read_probe(observations, role, label, *, structured=False):
    record = observations.get(role, {})
    if record.get("transport_ok") is not True:
        raise ValueError(f"{role} transport unavailable")
    item = record.get("probes", {}).get(label)
    if not item or item.get("returncode") != 0:
        raise ValueError(f"{role} {label} unavailable")
    return json.loads(item["stdout"]) if structured else item["stdout"]


def normalized(value):
    """Discard only diagnostic metadata, counters and remaining lifetimes."""
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items()
                if k not in {"handle", "metainfo", "packets", "bytes", "expires", "cache", "used",
                             "valid_life_time", "preferred_life_time"}}
    if isinstance(value, list):
        return [normalized(v) for v in value]
    return value


def host_firewall_without_project(value):
    return [normalized(item) for item in value["nftables"] if "metainfo" not in item
            and not any(isinstance(v, dict) and (v.get("table") == "wgmvp_outer" or
                        (k == "table" and v.get("name") == "wgmvp_outer")) for k, v in item.items())]


def overlaps(value, pool):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return False
    return network.version == 4 and network.prefixlen != 0 and network.overlaps(pool)


def peer_map(text):
    result = {}
    for line in text.splitlines():
        key, *values = line.replace(",", " ").split()
        if not KEY.fullmatch(key) or key in result:
            raise ValueError("invalid or duplicate peer identity")
        result[key] = set(values)
    return result


def transfers(text):
    result = {}
    for line in text.splitlines():
        key, rx, tx = line.split()
        if not KEY.fullmatch(key) or key in result or not rx.isdigit() or not tx.isdigit():
            raise ValueError("invalid transfer counters")
        result[key] = (int(rx), int(tx))
    return result


def zero_loss(text):
    return bool(re.search(r"(?<![\d.])0(?:\.0+)?% packet loss", text))


def registry():
    contexts = {"A01": "Villa, GPU, Cave and gz / management hosts; local HTTPS",
                "A02": "Villa, GPU, Cave and gz / host routes",
                "A04": "gz / host and wgmvp namespace",
                "A05": "Villa and Cave / host; gz / wgmvp namespace",
                "S06": "gz / host and wgmvp namespace",
                "S09": "Villa, Cave and gz / owner-local files"}
    return {test: {"id": test, "status": "NOT_RUN", "observed_at": None,
                   "host_namespace": contexts.get(test), "expected": f"See ACCEPTANCE.md {test}",
                   "observed": None, "evidence_files": [], "checks": [],
                   "limitations": ["Outside this runner's read-only structural and bounded ICMP scope."]}
            for test in IDS}


def add_check(entry, name, function):
    try:
        passed = function()
        status = "PASS" if passed else "FAIL"
        detail = "Observed condition matches expectation." if passed else "Observed condition contradicts expectation."
    except (ValueError, KeyError, TypeError, OSError) as exc:
        status, detail = "BLOCKED", str(exc)
    entry["checks"].append({"name": name, "status": status, "detail": detail})


def finish(entry, evidence, limitation=None):
    statuses = {x["status"] for x in entry["checks"]}
    entry.update(status="FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses or limitation else "PASS",
                 observed_at=stamp(), evidence_files=evidence,
                 observed="; ".join(f"{x['name']}: {x['status']}" for x in entry["checks"]),
                 limitations=[limitation] if limitation else [])


class Runner:
    def __init__(self, inventory, directory, timeout=45):
        self.inventory, self.directory, self.timeout = inventory, directory, timeout
        self.sequence = 0

    def record(self, name, command, script=None):
        result = discover.run_bounded(command, stdin=script, timeout=self.timeout)
        evidence = {"observed_at": stamp(), "command": command, "stdin_script": script, **result}
        filename = name + ".json"
        discover.write_private(self.directory / filename, json.dumps(evidence, indent=2) + "\n")
        return result, filename

    def observe(self, role):
        result, path = self.record(role, discover.command_for(role), probe_script(commands_for(role)))
        data = {"transport_ok": result["returncode"] == 0 and not result["timeout"], "evidence_file": path, "probes": {}}
        try:
            data["probes"] = parse_probes(result["stdout"])
        except ValueError as exc:
            data.update(transport_ok=False, parse_error=str(exc))
        return role, data

    def collect(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            observations = dict(pool.map(self.observe, discover.TARGETS))
        url = self.inventory.get("recovery", {}).get("internet_url")
        if isinstance(url, str) and re.fullmatch(r"https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9_./?=&%+-]*)?", url):
            result, evidence = self.record("internet", ["curl", "--head", "--fail", "--silent", "--show-error", "--max-time", "15", "--", url])
            observations["internet"] = {"transport_ok": result["returncode"] == 0 and not result["timeout"], "evidence_file": evidence}
        return observations

    def positive_pings(self, observations, addresses):
        results = {}
        for role, other in (("villa", "cave"), ("cave", "villa")):
            script = probe_script([("route", ["ip", "-j", "-4", "route", "get", addresses[other], "from", addresses[role]])])
            route, file = self.record(f"route-{role}", discover.command_for(role), script)
            try:
                parsed = parse_probes(route["stdout"])["route"]
                route_ok = route["returncode"] == 0 and not route["timeout"] and parsed["returncode"] == 0 and all(
                    item.get("dev") == "wgmvp" for item in json.loads(parsed["stdout"])) and bool(json.loads(parsed["stdout"]))
            except (ValueError, KeyError, TypeError):
                route_ok = False
            if not route_ok:
                results[role] = {"ok": False, "evidence_files": [file], "reason": "explicit-source route did not verify"}
                continue
            ping, pingfile = self.record(f"ping-{role}", discover.command_for(role),
                                        shlex.join(["ping", "-I", addresses[role], "-c", "3", "-W", "2", addresses[other]]) + "\n")
            results[role] = {"ok": ping["returncode"] == 0 and not ping["timeout"] and
                            zero_loss(ping["stdout"]),
                            "evidence_files": [file, pingfile], "reason": "three explicit-source requests, require zero loss"}
        after = {}
        for role in ROLES:
            prefix = ["ip", "netns", "exec", "wgmvp"] if role == "gz" else []
            result, file = self.record(f"transfer-after-{role}", discover.command_for(role),
                                      probe_script([("transfer", [*prefix, "wg", "show", "wgmvp", "transfer"])]))
            after[role] = {"transport_ok": result["returncode"] == 0 and not result["timeout"], "evidence_file": file, "probes": {}}
            try:
                after[role]["probes"] = parse_probes(result["stdout"])
            except ValueError as exc:
                after[role].update(transport_ok=False, parse_error=str(exc))
        return results, after


def evaluate(inventory, observations, baseline=None):
    tests = registry()
    evidence = [x["evidence_file"] for x in observations.values() if "evidence_file" in x]
    pool = ipaddress.ip_network(inventory["plan"]["overlay_pool"])
    addresses = {k: str(ipaddress.ip_interface(v).ip) for k, v in inventory["plan"]["overlay_addresses"].items()}
    checks = tests["A01"]
    for role in discover.TARGETS:
        add_check(checks, role + " fresh SSH", lambda r=role: read_probe(observations, r, "uid").isdigit())
    for role in ROLES:
        def identity(r=role):
            observed = {line.split()[1]: line.split()[0] for line in read_probe(observations, r, "identity").splitlines()}
            expected = inventory.get("identities", {}).get(r, {})
            if not all(path in expected for path in IDENTITY[r]):
                raise ValueError("reviewed identity fingerprints missing")
            return all(observed.get(path) == expected[path] for path in IDENTITY[r])
        add_check(checks, role + " reviewed identity", identity)
    add_check(checks, "GPU-local rt resolution", lambda: all(key in dict(line.split(maxsplit=1) for line in read_probe(observations, "gpu", "rt_alias").splitlines()) for key in ("hostname", "user", "port")))
    def internet():
        if "internet" not in observations:
            raise ValueError("independent HTTPS probe URL missing or not supported")
        return observations["internet"].get("transport_ok") is True
    add_check(checks, "independent HTTPS", internet)
    finish(checks, evidence)
    tests["A01"]["limitations"] = ["GPU identity uses the user's existing strict SSH host-key trust; the three deployment hosts also match explicit inventory fingerprints."]

    checks = tests["A02"]
    add_check(checks, "recorded non-overlap", lambda: not any(overlaps(p, pool) for p in inventory["observed"]["existing_ipv4_prefixes"]))
    for role in discover.TARGETS:
        def route_conflicts(r=role):
            for interface in read_probe(observations, r, "addresses", structured=True):
                for address in interface.get("addr_info", []):
                    if overlaps(f"{address['local']}/{address['prefixlen']}", pool) and not (
                        r in ("villa", "cave") and interface.get("ifname") == "wgmvp" and
                        address["local"] == addresses[r] and address["prefixlen"] == 32):
                        return False
            for route in read_probe(observations, r, "routes", structured=True):
                if overlaps(route.get("dst"), pool) and not (r in ("villa", "cave") and (
                    (route.get("dev") == "wgmvp" and route.get("dst", "").removesuffix("/32") in addresses.values()) or
                    (route.get("type") == "blackhole" and route.get("dst") == str(pool) and route.get("metric") == 32760 and str(route.get("protocol")) in {"186", "bgp"}))):
                    return False
            return True
        add_check(checks, role + " current host prefixes/routes", route_conflicts)
    finish(checks, evidence, "Current host routes were checked; all namespaces, local VPNs, proxy/TC policies and recovery destinations still require the recorded discovery review. Inventory attestations are not fresh packet-path proof.")

    checks = tests["A04"]
    def namespace():
        links = read_probe(observations, "gz", "ns_links", structured=True)
        if {x["ifname"] for x in links} != {"lo", "wgmvp"} or len(links) != 2:
            return False
        wg = next(x for x in links if x["ifname"] == "wgmvp")
        return wg.get("linkinfo", {}).get("info_kind") == "wireguard"
    add_check(checks, "only loopback and native WireGuard", namespace)
    add_check(checks, "namespace has no default route", lambda: all(x.get("dst") not in ("default", "0.0.0.0/0", "::/0") for label in ("ns_routes", "ns_routes6") for x in read_probe(observations, "gz", label, structured=True)))
    add_check(checks, "namespace has no TCP/UDP listener", lambda: not read_probe(observations, "gz", "ns_sockets"))
    def firewall():
        data = read_probe(observations, "gz", "ns_firewall", structured=True)
        chains = [x["chain"] for x in data["nftables"] if "chain" in x and "hook" in x["chain"]]
        return len(chains) == 3 and {x.get("hook"): x.get("policy") for x in chains} == {"input": "drop", "output": "drop", "forward": "drop"} and not re.search(r'"(?:dnat|snat|masquerade|redirect)"', json.dumps(data))
    add_check(checks, "namespace default-deny policy and no NAT", firewall)
    add_check(checks, "hub backend validates permanent configuration", lambda: bool(read_probe(observations, "gz", "backend")))
    add_check(checks, "host has no project prefix route", lambda: not any(overlaps(x.get("dst"), pool) for x in read_probe(observations, "gz", "routes", structured=True)))
    def unchanged(label, structured=False):
        if baseline is None:
            raise ValueError("pre-deployment observations baseline not supplied")
        return normalized(read_probe(observations, "gz", label, structured=structured)) == normalized(read_probe(baseline, "gz", label, structured=structured))
    add_check(checks, "host routes unchanged from baseline", lambda: unchanged("routes", True))
    add_check(checks, "host forwarding unchanged from baseline", lambda: unchanged("host_forwarding"))
    finish(checks, evidence)

    checks = tests["A05"]
    public = {}
    for role in ROLES:
        def local_key(r=role):
            key = read_probe(observations, r, "owner_public")
            if not KEY.fullmatch(key):
                raise ValueError("owner public key unavailable or malformed")
            public[r] = key
            return read_probe(observations, r, "wg_public_key") == key
        add_check(checks, role + " owner public identity", local_key)
    if len(public) == 3:
        add_check(checks, "three distinct peer identities", lambda: len(set(public.values())) == 3)
        for role in ROLES:
            expected = ({public["villa"]: {addresses["villa"] + "/32"}, public["cave"]: {addresses["cave"] + "/32"}} if role == "gz" else
                        {public["gz"]: {addresses["gz"] + "/32", addresses["cave" if role == "villa" else "villa"] + "/32"}})
            add_check(checks, role + " exact peers and AllowedIPs", lambda r=role, e=expected: peer_map(read_probe(observations, r, "wg_allowed_ips")) == e and set(read_probe(observations, r, "wg_peers").split()) == set(e))
            add_check(checks, role + " permanent backend configuration", lambda r=role: bool(read_probe(observations, r, "backend")))
    finish(checks, evidence, "Packet and transfer-delta checks have not run yet.")

    checks = tests["S06"]
    def namespace_verified():
        if tests["A04"]["status"] == "BLOCKED":
            raise ValueError("namespace checks lack evidence; see A04")
        return tests["A04"]["status"] == "PASS"
    add_check(checks, "isolated namespace structural checks", namespace_verified)
    def host_policy_unchanged():
        if baseline is None:
            raise ValueError("pre-deployment firewall baseline not supplied")
        return host_firewall_without_project(read_probe(observations, "gz", "host_firewall", structured=True)) == host_firewall_without_project(read_probe(baseline, "gz", "host_firewall", structured=True))
    add_check(checks, "host firewall unchanged outside project table", host_policy_unchanged)
    finish(checks, evidence, "Host firewall/namespace observations do not audit all reverse-proxy configuration or cloud ingress. Existing exposures need separate reviewed evidence.")

    checks = tests["S09"]
    for role in ROLES:
        def permissions(r=role):
            lines = read_probe(observations, r, "permissions").splitlines()
            if len(lines) != 3:
                raise ValueError("incomplete host-local permissions")
            return all(line.split(":", 2)[:2] == ["0", "700" if index == 0 else "600"] for index, line in enumerate(lines))
        add_check(checks, role + " root-only key/config permissions", permissions)
        if role != "gz":
            add_check(checks, role + " restricted host-local backups", lambda r=role: bool(read_probe(observations, r, "backup_permissions")) and all(line.split(":", 2)[:2] == ["0", "600"] for line in read_probe(observations, r, "backup_permissions").splitlines()))
    finish(checks, evidence, "Only permissions and this runner's safe selectors are checked. No private key content is read; absence of secrets from all prior logs, process arguments or other machines is not established.")
    return tests, addresses


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=REPO / "inventory.local.json")
    parser.add_argument("--output-dir", type=Path, default=REPO / ".local/acceptance")
    parser.add_argument("--baseline", type=Path, help="pre-deployment observations.json from this runner")
    parser.add_argument("--no-ping", action="store_true", help="collect a read-only baseline without synthetic traffic")
    parser.add_argument("--dry-run", action="store_true", help="show safe commands without connections or files")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args(argv)
    if not 15 <= args.timeout <= 90:
        parser.error("timeout must be 15..90 seconds")
    if args.dry_run:
        for role in discover.TARGETS:
            print(role + ": " + shlex.join(discover.command_for(role)))
            print(probe_script(commands_for(role)))
        print("Pings: at most three ICMP requests each direction, only after identities and exact peer mappings pass.")
        return 0
    inventory = json.loads(args.inventory.read_text())
    plan = inventory["plan"]
    if plan["overlay_pool"] != "10.203.77.0/29" or plan["interface"] != "wgmvp" or plan["gz_namespace"] != "wgmvp" or plan["overlay_addresses"] != {"gz": "10.203.77.1/32", "villa": "10.203.77.2/32", "cave": "10.203.77.3/32"}:
        parser.error("runner requires the reviewed fixed MVP address/name plan")
    os.umask(0o077)
    if args.output_dir.is_symlink():
        parser.error("output directory cannot be a symlink")
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.output_dir.stat().st_mode & 0o077:
        parser.error("output directory must be private (0700)")
    directory = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=args.output_dir))
    runner = Runner(inventory, directory, args.timeout)
    print("Collecting read-only identity, namespace, routing, policy and permissions evidence.", flush=True)
    observations = runner.collect()
    discover.write_private(directory / "observations.json", json.dumps(observations, indent=2) + "\n")
    baseline = json.loads(args.baseline.read_text()) if args.baseline else None
    tests, addresses = evaluate(inventory, observations, baseline)
    candidate = tests["A05"]
    if not args.no_ping and tests["A01"]["status"] == "PASS" and candidate["checks"] and all(x["status"] == "PASS" for x in candidate["checks"]):
        print("Sending three explicit-source overlay pings per direction.", flush=True)
        pings, after = runner.positive_pings(observations, addresses)
        evidence = candidate["evidence_files"][:]
        for role, result in pings.items():
            add_check(candidate, role + " explicit-source zero-loss ping", lambda r=result: r["ok"])
            evidence.extend(result["evidence_files"])
        for role in ROLES:
            def counters(r=role):
                before = transfers(read_probe(observations, r, "wg_transfer"))
                later = transfers(read_probe(after, r, "transfer"))
                return bool(before) and before.keys() == later.keys() and all(later[k][0] > v[0] and later[k][1] > v[1] for k, v in before.items())
            add_check(candidate, role + " both transfer counters increased", counters)
            evidence.append(after[role]["evidence_file"])
        finish(candidate, evidence)
    else:
        candidate["limitations"] = ["Pings disabled or identity/exact-peer prerequisites did not pass."]
    tests["O03"]["limitations"] = ["No reboot is implemented or executed; explicit opt-in plus coordinated recovery test required."]
    result = {"generated_at": stamp(), "kind": "partial live acceptance evidence", "complete_acceptance": False,
              "inventory_validation_errors": check_inventory.validate(inventory), "tests": list(tests.values())}
    discover.write_private(directory / "results.json", json.dumps(result, indent=2) + "\n")
    summary = "\n".join(f"{test}: {entry['status']}" for test, entry in tests.items())
    discover.write_private(directory / "summary.txt", summary + "\n\nPartial evidence only; full acceptance is not established.\n")
    print(summary)
    print(f"Private results: {directory / 'results.json'}")
    return 1 if any(x["status"] == "FAIL" for x in tests.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
