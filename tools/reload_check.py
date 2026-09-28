#!/usr/bin/env python3
"""S08 reload and IPv6 structural evidence through an existing guarded launcher.

Call run_reload while holding the launcher's coordinator lock. Importing this
module performs no work. There is no standalone live command or IPv6 packet test.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex

import acceptance
import wgmvp

ADDRESSES = {"gz": "10.203.77.1", "villa": "10.203.77.2", "cave": "10.203.77.3"}
PAIRS = (("gz", "villa"), ("villa", "gz"), ("gz", "cave"), ("cave", "gz"),
         ("villa", "cave"), ("cave", "villa"))


class Failed(wgmvp.Blocked):
    """A measured policy contradiction, rather than unavailable evidence."""


def require(condition, reason):
    if not condition:
        raise wgmvp.Blocked(reason)


def canonical_nft(document):
    """Remove diagnostic handles/counters only, preserving rule order and policy."""
    require(isinstance(document, dict) and isinstance(document.get("nftables"), list), "invalid nft JSON")

    def clean(value):
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            return {key: None if key == "counter" else clean(item)
                    for key, item in value.items() if key != "handle"}
        return value

    return {"nftables": [clean(item) for item in document["nftables"] if "metainfo" not in item]}


def objects(document, kind):
    return [item[kind] for item in document["nftables"] if kind in item]


def assert_router_guard(document):
    canonical_nft(document)
    tables = objects(document, "table")
    require(len(tables) == 1 and tables[0].get("family") == "inet"
            and tables[0].get("name") == "wgmvp_guard" and tables[0].get("comment") == "wgmvp-r1",
            "independent dual-family router guard ownership missing")
    rules = objects(document, "rule")
    for chain, comment in (("rx", "wgmvp ingress denied all destinations and IPv6"),
                           ("tx", "wgmvp output denied")):
        selected = [rule for rule in rules if rule.get("chain") == chain]
        require(selected and selected[-1].get("comment") == comment,
                f"{chain}: reviewed terminal deny rule missing")
        expressions = [item for item in selected[-1].get("expr", []) if "counter" not in item]
        require(expressions == [{"drop": None}], f"{chain}: terminal denial is not unconditional")
    return canonical_nft(document)


def assert_outer_ipv6_deny(document, port):
    canonical_nft(document)
    tables = objects(document, "table")
    require(len(tables) == 1 and tables[0].get("family") == "inet"
            and tables[0].get("name") == "wgmvp_outer"
            and re.fullmatch(r"wgmvp-r1:[a-f0-9-]{36}", tables[0].get("comment", "")),
            "gz outer table ownership missing")
    chains = objects(document, "chain")
    require(any(chain.get("name") == "input" and chain.get("hook") == "input"
                and chain.get("prio") == -10 for chain in chains), "gz outer deny hook differs")
    rules = [rule for rule in objects(document, "rule") if rule.get("chain") == "input"]
    require(rules and rules[0].get("comment") == "wgmvp IPv6 listener denied", "gz IPv6 deny is not first")
    expected = [{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": port}},
                {"drop": None}]
    require([item for item in rules[0].get("expr", []) if "counter" not in item] == expected,
            "gz outer IPv6 deny does not cover the exact WireGuard UDP listener")


def assert_ipv6_state(probes, role):
    for name, item in probes.items():
        require(item.get("returncode") == 0, f"{role}: IPv6 {name} unavailable")
    peers = acceptance.peer_map(probes["allowed_ips"]["stdout"])
    require(peers, f"{role}: no WireGuard peer evidence")
    for prefixes in peers.values():
        require(prefixes, f"{role}: peer has no reviewed AllowedIPs")
        for prefix in prefixes:
            if ipaddress.ip_network(prefix).version != 4:
                raise Failed(f"{role}: IPv6 payload prefix is allowed")
    if probes["disable_ipv6"]["stdout"] != "1":
        raise Failed(f"{role}: IPv6 is not disabled on the project interface")
    routes = json.loads(probes["routes6"]["stdout"])
    require(isinstance(routes, list), f"{role}: invalid IPv6 routes evidence")
    if routes:
        raise Failed(f"{role}: project interface has IPv6 routes")
    addresses = json.loads(probes["addresses6"]["stdout"])
    require(isinstance(addresses, list) and len(addresses) == 1 and addresses[0].get("ifname") == "wgmvp",
            f"{role}: project interface address evidence is absent or ambiguous")
    # Query both families so the IPv4-only link is present even when ip -6
    # would omit it. Its IPv4 address remains outside this specific check.
    if any(item.get("family") == "inet6" for item in addresses[0].get("addr_info", [])):
        raise Failed(f"{role}: project interface has IPv6 addresses")
    global_values = probes["global_ipv6"]["stdout"].splitlines()
    require(len(global_values) == 2 and all(value in {"0", "1"} for value in global_values),
            f"{role}: host global IPv6 setting evidence unavailable")
    return {"status": "PASS", "basis": "structural", "host_global_disable_ipv6": global_values,
            "project_disable_ipv6": 1, "project_ipv6_routes": 0, "project_ipv6_addresses": 0,
            "ipv6_allowed_prefixes": 0}


RELOAD_BODY = '''exec 9>"$ROOT/state/mutex"
flock -x -n 9
test -f "$ROOT/state/pending"
[ "$(sed -n '1p' "$ROOT/state/pending")" = "$OWNER" ]
[ "$(sed -n '2p' "$ROOT/state/pending")" = "$(cat /proc/sys/kernel/random/boot_id)" ]
tick=$(cut -d. -f1 /proc/uptime)
deadline=$(sed -n '4p' "$ROOT/state/pending")
[ "$deadline" -gt "$((tick+45))" ]
fw4 check
fw4 reload
'''


def run_reload(launcher, active_roles=wgmvp.ROLES):
    """Reload each router separately and return evidence; never invent packet tests."""
    result = {"id": "S08", "observed_at": wgmvp.utcnow(), "status": "BLOCKED", "reloads": [],
              "ipv6_structural": {}, "ipv6_payload_test": "NOT_RUN", "evidence_files": [], "scope_status": "BLOCKED",
              "limitations": ["IPv6 containment is checked structurally; no IPv6 payload packet was generated.",
                              "Host global IPv6 settings are compared before/after these reloads; earlier history needs baseline review."]}

    def read(role, script, label):
        item = launcher.remote(role, "set -eu\n" + script, label)
        result["evidence_files"].append(item["evidence_file"])
        require(item["returncode"] == 0 and not item["timeout"], f"{role}: {label} evidence unavailable")
        return item["stdout"]

    def healthy_and_renew():
        for role in roles:
            launcher.preflight(role)
            read(role, wgmvp.status_script(role), "reload-health")
        for role in roles:
            launcher.mutate(role, 'test -f "$ROOT/state/pending"\n"$ROOT/controller.sh" renew\n',
                            "reload-renew", "renew existing pending lease after healthy policy and fresh independent recovery")

    def ipv6(role):
        prefix = ["ip", "netns", "exec", "wgmvp"] if role == "gz" else []
        commands = [("allowed_ips", [*prefix, "wg", "show", "wgmvp", "allowed-ips"]),
                    ("disable_ipv6", [*prefix, "sysctl", "-n", "net.ipv6.conf.wgmvp.disable_ipv6"]),
                    ("addresses6", [*prefix, "ip", "-j", "address", "show", "dev", "wgmvp"]),
                    ("routes6", [*prefix, "ip", "-j", "-6", "route", "show", "table", "all", "dev", "wgmvp"]),
                    ("global_ipv6", ["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"])]
        text = read(role, acceptance.probe_script(commands), "reload-ipv6-structure")
        probes = acceptance.parse_probes(text)
        require(set(probes) == {name for name, _ in commands}, f"{role}: missing IPv6 probe")
        return assert_ipv6_state(probes, role)

    def positive_controls():
        for source, destination in PAIRS:
            if source not in roles or destination not in roles:
                continue
            prefix = ["ip", "netns", "exec", "wgmvp"] if source == "gz" else []
            argv = ["timeout", "-k", "1", "10", *prefix, "ping", "-n", "-I", ADDRESSES[source],
                    "-c", "3", "-w", "8", ADDRESSES[destination]]
            text = read(source, shlex.join(argv) + "\n", f"reload-positive-{destination}")
            require(re.search(r"(?m)^3 packets transmitted, 3 (?:packets )?received(?:,|\s)", text)
                    and acceptance.zero_loss(text), f"{source} to {destination}: explicit-source positive control failed")
        launcher.recovery()

    try:
        require(len(active_roles) >= 2 and len(set(active_roles)) == len(active_roles)
                and "gz" in active_roles and all(role in wgmvp.ROLES for role in active_roles),
                "active targets must include gz and at least one router, without duplicates")
        roles = tuple(role for role in wgmvp.ROLES if role in active_roles)
        result["active_roles"] = roles
        require(launcher.inventory["plan"]["overlay_addresses"] == {role: ip + "/32" for role, ip in ADDRESSES.items()},
                "reload check requires the reviewed fixed address plan")
        port = launcher.inventory["plan"]["outer_udp_port"]
        require(type(port) is int and 1024 <= port <= 65535, "unreviewed outer UDP port")
        for role in roles:
            launcher.preflight(role)
            read(role, wgmvp.status_script(role), "reload-initial-health")
            result["ipv6_structural"][role] = ipv6(role)
        outer_before = json.loads(read("gz", "nft -j -s list table inet wgmvp_outer\n", "reload-outer-before"))
        assert_outer_ipv6_deny(outer_before, port)
        for role in ("villa", "cave"):
            if role not in roles:
                continue
            healthy_and_renew()
            before = assert_router_guard(json.loads(read(role, "nft -j -s list table inet wgmvp_guard\n", "reload-guard-before")))
            launcher.mutate(role, RELOAD_BODY, "firewall-reload",
                            "check and reload this router's supported fw4 configuration under the host lock; independent project guard must survive",
                            changes_network=True, check_status=True)
            after = assert_router_guard(json.loads(read(role, "nft -j -s list table inet wgmvp_guard\n", "reload-guard-after")))
            if after != before:
                raise Failed(f"{role}: independent project guard changed across fw4 reload")
            read(role, wgmvp.status_script(role), "reload-after-health")
            positive_controls()
            digest = hashlib.sha256(json.dumps(after, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            result["reloads"].append({"role": role, "status": "PASS", "guard_stateless_sha256": digest,
                                      "positive_controls": f"{len([p for p in PAIRS if p[0] in roles and p[1] in roles])} directions, three packets each, zero loss"})
        for role in roles:
            after = ipv6(role)
            if after != result["ipv6_structural"][role]:
                raise Failed(f"{role}: IPv6 structure or host global settings changed during reload tests")
        outer_after = json.loads(read("gz", "nft -j -s list table inet wgmvp_outer\n", "reload-outer-after"))
        assert_outer_ipv6_deny(outer_after, port)
        if canonical_nft(outer_before) != canonical_nft(outer_after):
            raise Failed("gz outer IPv6 guard changed during router reload tests")
        result["scope_status"] = "PASS"
        result["status"] = "PASS" if roles == wgmvp.ROLES else "BLOCKED"
        if roles != wgmvp.ROLES:
            result["limitations"].append("Partial target selection; full S08 acceptance including the omitted router remains pending.")
        result["basis"] = "supported router reloads plus structural IPv6 containment"
    except (RuntimeError, ValueError, KeyError, TypeError, OSError) as exc:
        result["status"] = "FAIL" if isinstance(exc, Failed) else "BLOCKED"
        result["scope_status"] = result["status"]
        result["reason"] = str(exc)
    result["finished_at"] = wgmvp.utcnow()
    wgmvp.json_write(launcher.run_dir / "reload-check-results.json", result, replace=True)
    return result
