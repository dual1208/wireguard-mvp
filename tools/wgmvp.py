#!/usr/bin/env python3
"""Small guarded launcher. Mutations are dry runs unless --apply is supplied.

All evidence stays in .local/. Snapshot refresh observes candidates; it never
promotes an unknown live configuration to an approved deployment baseline.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import sys
import tempfile
import time
from typing import Any

import check_inventory
import discover

REPO = Path(__file__).resolve().parents[1]
ROLES = ("gz", "villa", "cave")
MUTATIONS = ("apply", "benchmark", "rollback", "remove")
IDS = ([f"A{i:02}" for i in range(1, 6)] + [f"S{i:02}" for i in range(1, 11)]
       + [f"O{i:02}" for i in range(1, 5)] + [f"P{i:02}" for i in range(1, 9)])
IDENTITY_FILES = {
    "gz": ("/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key.pub"),
    "villa": ("/etc/dropbear/dropbear_ed25519_host_key", "/etc/config/network", "/etc/config/firewall"),
    "cave": ("/etc/dropbear/dropbear_ed25519_host_key", "/etc/config/network", "/etc/config/firewall"),
}
MUTABLE_FILES = {"/etc/config/network", "/etc/config/firewall"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
BENCHMARK_SCOPES = ("all", "per-leg", "cross-tcp", "cross-udp", "cave-leg")
CAVE_LEG_ROLES = ("gz", "cave")
SECURITY_GATE_IDS = tuple([f"A{i:02}" for i in range(1, 6)] + [f"S{i:02}" for i in range(1, 10)])


class Blocked(RuntimeError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_write(path: Path, value: Any, *, replace: bool = False) -> None:
    if path.is_symlink():
        raise Blocked(f"refusing symlink: {path}")
    if not replace:
        discover.write_private(path, json.dumps(value, indent=2) + "\n")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise Blocked(f"refusing symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise Blocked(f"private directory must be owned by this user and mode 0700: {path}")


@contextmanager
def coordinator_lock(directory: Path):
    private_directory(directory)
    lock_path = directory / "coordinator.lock"
    if lock_path.is_symlink():
        raise Blocked("coordinator lock is a symlink")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Blocked("another local deployment coordinator holds the lock") from exc
        yield
    finally:
        os.close(fd)


def snapshot_function(role: str) -> str:
    if role not in ROLES:
        raise ValueError("unknown role")
    files = " ".join(shlex.quote(path) for path in IDENTITY_FILES[role])
    # No raw config or key leaves the host. Stateful nft counters/handles and
    # dynamic route/address lifetimes do not belong in a stable fingerprint.
    script = r'''
wgmvp_snapshot() {
    for file in FILE_LIST; do
        [ -f "$file" ] || return 1
        hash=$(sha256sum "$file") || return 1
        hash=${hash%% *}
        printf 'FILE\t%s\t%s\n' "$file" "$hash"
    done
UNRELATED_CONFIG
    links=$(ip -o link show) || return 1
    addresses=$(ip -o address show) || return 1
    routes4=$(ip -4 route show table all) || return 1
    routes6=$(ip -6 route show table all) || return 1
    rules4=$(ip -4 rule show) || return 1
    rules6=$(ip -6 rule show) || return 1
    firewall=$(nft -s list ruleset) || return 1
    namespaces=$(ip netns list) || return 1
    forwarding=$(sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding) || return 1
    namespace_state=$(
        printf '%s\n' "$namespaces" | awk 'NF {print $1}' | sort |
        while IFS= read -r name; do
            printf 'NS %s\n' "$name"
            ip -n "$name" -o link show || exit 1
            ip -n "$name" -4 route show table all || exit 1
            ip -n "$name" -6 route show table all || exit 1
            ip -n "$name" -4 rule show || exit 1
            ip -n "$name" -6 rule show || exit 1
            ip netns exec "$name" nft -s list ruleset || exit 1
        done
    ) || return 1
    normalized=$(
        printf 'LINKS\n%s\nADDRESSES\n' "$links"
        printf '%s\n' "$addresses" | awk '{print $2, $3, $4}' | sort
        printf 'ROUTES4\n%s\nROUTES6\n%s\n' "$routes4" "$routes6" |
            sed -E 's/expires [^ ]+//g; s/[[:space:]]+$//'
        printf 'RULES4\n%s\nRULES6\n%s\nFIREWALL\n' "$rules4" "$rules6"
        printf '%s\n' "$firewall" |
            sed -E 's/ expires [0-9]+[a-z0-9.]*/ expires <dynamic>/g; s/ # handle [0-9]+//g'
        printf 'NAMESPACES\n'
        printf '%s\n' "$namespaces" | awk 'NF {print $1}' | sort
        printf 'NAMESPACE_STATE\n%s\n' "$namespace_state" |
            sed -E 's/expires [^ ]+//g; s/ # handle [0-9]+//g'
        printf 'FORWARDING\n%s\n' "$forwarding"
    ) || return 1
    hash=$(printf '%s\n' "$normalized" | sha256sum) || return 1
    printf 'NETWORK\t%s\n' "${hash%% *}"
    if [ -e /etc/wgmvp ]; then printf 'INSTALLED\tyes\n'; else printf 'INSTALLED\tno\n'; fi
}
'''.replace("FILE_LIST", files)
    unrelated = ""
    if role != "gz":
        unrelated = r'''
    network_export=$(uci -q export network) || return 1
    firewall_export=$(uci -q export firewall) || return 1
    unrelated=$(
        printf 'NETWORK_CONFIG\n'
        printf '%s\n' "$network_export" | awk '
            $1=="config" {name=$3; gsub(/\047/, "", name); skip=(name=="wgmvp" || name=="wgmvp_peer")}
            NF && !skip {print}'
        printf 'FIREWALL_CONFIG\n'
        printf '%s\n' "$firewall_export" | awk '
            $1=="config" {name=$3; gsub(/\047/, "", name); skip=(name=="wgmvp" || name=="wgmvp_diag_in" || name=="wgmvp_diag_out")}
            NF && !skip {print}'
    ) || return 1
    hash=$(printf '%s\n' "$unrelated" | sha256sum) || return 1
    printf 'UNRELATED_CONFIG\t%s\n' "${hash%% *}"
'''
    return script.replace("UNRELATED_CONFIG\n", unrelated, 1)


def parse_snapshot(text: str, role: str) -> dict[str, Any]:
    result: dict[str, Any] = {"files": {}}
    for line in text.splitlines():
        columns = line.split("\t")
        if len(columns) == 3 and columns[0] == "FILE":
            path, value = columns[1:]
            if path in result["files"] or path not in IDENTITY_FILES[role] or not HEX.fullmatch(value):
                raise Blocked("invalid or duplicate identity fingerprint")
            result["files"][path] = value
        elif len(columns) == 2 and columns[0] in {"NETWORK", "INSTALLED", "UNRELATED_CONFIG"}:
            key = {"NETWORK": "network_sha256", "INSTALLED": "installed",
                   "UNRELATED_CONFIG": "unrelated_config_sha256"}[columns[0]]
            if key in result:
                raise Blocked("duplicate snapshot field")
            result[key] = columns[1]
        elif line.strip():
            raise Blocked("unexpected snapshot output")
    if set(result["files"]) != set(IDENTITY_FILES[role]) or not HEX.fullmatch(result.get("network_sha256", "")):
        raise Blocked("incomplete snapshot; failed commands are unknowns")
    if result.get("installed") not in {"yes", "no"}:
        raise Blocked("missing installation observation")
    if role != "gz" and not HEX.fullmatch(result.get("unrelated_config_sha256", "")):
        raise Blocked("missing canonical unrelated UCI fingerprint")
    return result


def snapshot_text(snapshot: dict[str, Any], role: str) -> str:
    text = "".join(f"FILE\t{path}\t{snapshot['files'][path]}\n" for path in IDENTITY_FILES[role])
    if role != "gz":
        text += f"UNRELATED_CONFIG\t{snapshot['unrelated_config_sha256']}\n"
    text += f"NETWORK\t{snapshot['network_sha256']}\nINSTALLED\t{snapshot['installed']}\n"
    parse_snapshot(text, role)
    return text.rstrip("\n")


def identity_errors(inventory: dict[str, Any], role: str, snapshot: dict[str, Any], *, initial: bool) -> list[str]:
    expected = inventory.get("identities", {}).get(role, {})
    errors = []
    for path in IDENTITY_FILES[role]:
        if not initial and path in MUTABLE_FILES:
            continue
        if not isinstance(expected.get(path), str) or not HEX.fullmatch(expected[path]):
            errors.append(f"{role}: missing reviewed identity/configuration fingerprint for {path}")
        elif expected[path] != snapshot["files"].get(path):
            errors.append(f"{role}: reviewed file fingerprint changed: {path}")
    return errors


def blockers(inventory: dict[str, Any], *, prepare: bool = False) -> list[str]:
    found = check_inventory.validate(inventory, prepare=prepare)
    listed = inventory.get("blockers", [])
    if not isinstance(listed, list):
        found.append("inventory.blockers must be a list")
    else:
        for item in listed:
            if isinstance(item, str):
                found.append(item)
            elif isinstance(item, dict) and item.get("status") not in {"resolved", "PASS"}:
                found.append(str(item.get("reason") or item.get("description") or item))
    return found


def payload_function(files: dict[str, str]) -> str:
    if not isinstance(files, dict) or not files:
        raise Blocked("renderer returned no payload")
    lines = ['write_payload() {', '    [ -n "${STAGE:-}" ] && [ -d "$STAGE" ] || return 1']
    for name, content in sorted(files.items()):
        path = PurePosixPath(name)
        if (path.is_absolute() or len(path.parts) != 1 or name in {".", "..", "private.key"}
                or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", name) is None):
            raise Blocked(f"unsafe payload name: {name!r}")
        if not isinstance(content, str) or "\0" in content:
            raise Blocked("payload must be NUL-free text")
        digest = hashlib.sha256(content.encode()).hexdigest()
        delimiter = f"WGMVP_PAYLOAD_{digest}"
        if delimiter in content.splitlines():
            raise Blocked("heredoc delimiter collision")
        lines += [f'    cat > "$STAGE/{name}" <<\'{delimiter}\' || return 1', content.removesuffix("\n"), delimiter,
                  f'    chmod 600 "$STAGE/{name}" || return 1']
    lines += ["}", ""]
    return "\n".join(lines)


def status_script(role: str) -> str:
    prefix = "hub" if role == "gz" else "router"
    return f'''set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
ROOT=/etc/wgmvp
if [ ! -f "$ROOT/config.env" ]; then printf 'NOT_INSTALLED\\n'; exit 3; fi
[ "$(cat "$ROOT/owner" 2>/dev/null)" = wgmvp-r1 ] || exit 4
. "$ROOT/config.env"
[ "$ROLE" = {shlex.quote(role)} ] && [ "$ROOT" = /etc/wgmvp ] && [ "$OWNER" = wgmvp-r1 ] || exit 4
. "$ROOT/{prefix}.sh"
{prefix}_status
'''


class Launcher:
    def __init__(self, inventory: dict[str, Any], local: Path, *, timeout: int = 90):
        self.inventory = inventory
        self.local = local
        self.timeout = timeout
        private_directory(local)
        private_directory(local / "runs")
        private_directory(local / "state")
        self.run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"),
                                           dir=local / "runs"))
        self.sequence = 0
        self.operation_deadline: float | None = None

    def bounded_timeout(self, requested: int) -> int:
        if self.operation_deadline is None:
            return requested
        remaining = int(self.operation_deadline - time.monotonic())
        if remaining <= 0:
            raise Blocked("benchmark suite time budget exhausted; host-local expiry remains authoritative")
        return min(requested, remaining)

    def remote(self, role: str, script: str, label: str) -> dict[str, Any]:
        self.sequence += 1
        result = discover.run_bounded(discover.command_for(role), stdin=script, timeout=self.bounded_timeout(self.timeout))
        evidence = self.run_dir / f"{self.sequence:03}-{role}-{label}.json"
        json_write(evidence, {"role": role, "label": label,
                            "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
                            "command": discover.command_for(role), **result})
        result["evidence_file"] = str(evidence)
        return result

    def observe(self, role: str) -> dict[str, Any]:
        result = self.remote(role, "set -u\n" + snapshot_function(role) + "\nwgmvp_snapshot\n", "snapshot")
        if result["returncode"] != 0 or result["timeout"]:
            raise Blocked(f"{role}: fresh snapshot failed ({result['evidence_file']})")
        return parse_snapshot(result["stdout"], role)

    def expected(self, role: str) -> dict[str, Any]:
        state = self.local / "state" / f"{role}.json"
        if state.exists():
            if state.is_symlink() or state.stat().st_mode & 0o077:
                raise Blocked(f"unsafe local reviewed state: {state}")
            record = json.loads(state.read_text())
            if record.get("owner") != "wgmvp-r1" or record.get("role") != role:
                raise Blocked("local reviewed snapshot ownership mismatch")
            return record["snapshot"]
        candidate = self.inventory.get("reviewed_snapshots", {}).get(role)
        if not isinstance(candidate, dict):
            raise Blocked(f"{role}: no reviewed network snapshot; plan --refresh only records candidates")
        snapshot_text(candidate, role)
        return candidate

    def preflight(self, role: str) -> dict[str, Any]:
        expected = self.expected(role)
        observed = self.observe(role)
        errors = identity_errors(self.inventory, role, observed, initial=expected["installed"] == "no")
        if errors:
            raise Blocked("; ".join(errors))
        if observed != expected:
            json_write(self.run_dir / f"drift-{role}-{self.sequence}.json", {"expected": expected, "observed": observed})
            raise Blocked(f"{role}: live state differs from reviewed snapshot; reconcile the recorded delta")
        return observed

    def remember(self, role: str, snapshot: dict[str, Any], action: str, evidence: str) -> None:
        json_write(self.local / "state" / f"{role}.json",
                   {"owner": "wgmvp-r1", "role": role, "recorded_at": utcnow(), "operation": action,
                    "evidence_file": evidence, "snapshot": snapshot}, replace=True)

    def recovery(self) -> None:
        result = self.remote("gpu", "printf 'RECOVERY_OK\\n'\n", "recovery")
        if result["returncode"] != 0 or result["stdout"].strip() != "RECOVERY_OK":
            raise Blocked("fresh independent GPU recovery failed")
        url = self.inventory.get("recovery", {}).get("internet_url")
        if not isinstance(url, str) or not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9_./?=&%+-]*)?", url):
            raise Blocked("inventory.recovery.internet_url must record the established HTTPS recovery check")
        response = discover.run_bounded(["curl", "--head", "--fail", "--silent", "--show-error",
                                        "--max-time", "15", "--", url], timeout=self.bounded_timeout(20))
        self.sequence += 1
        json_write(self.run_dir / f"{self.sequence:03}-local-internet.json", response)
        if response["returncode"] != 0 or response["timeout"]:
            raise Blocked("fresh independent local Internet recovery check failed")

    def mutate(self, role: str, body: str, action: str, delta: str, *, changes_network: bool = False,
               changes_files: bool = False, installation: str | None = None, check_status: bool = False) -> None:
        before = self.preflight(role)
        self.recovery()
        expected_text = snapshot_text(before, role)
        prelude = ("set -eu\numask 077\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n"
                   + f"ROLE={shlex.quote(role)}\nROOT=/etc/wgmvp\nOWNER=wgmvp-r1\n"
                   + snapshot_function(role)
                   + f"\nexpected={shlex.quote(expected_text)}\n"
                   + 'actual=$(wgmvp_snapshot) || exit 70\n'
                   + '[ "$actual" = "$expected" ] || { printf "BLOCKED fingerprint changed before write\\n" >&2; exit 71; }\n')
        self.sequence += 1
        json_write(self.run_dir / f"{self.sequence:03}-{role}-{action}-planned.json",
                   {"recorded_at": utcnow(), "role": role, "operation": action, "delta": delta,
                    "prediction": "Overlay destination uses the project /32 route; unlisted traffic is denied.",
                    "before": before})
        result = self.remote(role, prelude + "\n" + body, action)
        if result["returncode"] != 0 or result["timeout"]:
            raise Blocked(f"{role}: {action} failed; pending host-local rollback remains authoritative")
        after = self.observe(role)
        for path, value in before["files"].items():
            if not (changes_files and path in MUTABLE_FILES) and after["files"][path] != value:
                raise Blocked(f"{role}: unexpected file change after {action}: {path}")
        if role != "gz" and after["unrelated_config_sha256"] != before["unrelated_config_sha256"]:
            raise Blocked(f"{role}: unrelated UCI configuration changed during {action}; snapshot not promoted")
        if not changes_network and after["network_sha256"] != before["network_sha256"]:
            raise Blocked(f"{role}: unexpected network change after {action}")
        if after["installed"] != (installation or before["installed"]):
            raise Blocked(f"{role}: unexpected installation state after {action}")
        if check_status:
            checked = self.remote(role, status_script(role), "post-mutation-status")
            if checked["returncode"] != 0:
                raise Blocked(f"{role}: generated object checks failed; snapshot not promoted")
        self.remember(role, after, action, result["evidence_file"])

    def refresh(self) -> None:
        snapshots = {}
        for role in ROLES:
            try:
                observed = self.observe(role)
                snapshots[role] = {"candidate": observed,
                                   "identity_errors": identity_errors(self.inventory, role, observed,
                                                                      initial=observed["installed"] == "no")}
            except Blocked as exc:
                snapshots[role] = {"error": str(exc)}
        json_write(self.run_dir / "candidate-snapshots.json", {"kind": "UNAPPROVED_CANDIDATES", "roles": snapshots})
        print(f"Candidate snapshots for review: {self.run_dir / 'candidate-snapshots.json'}")
        print("No candidate was promoted and no remote state was changed.")

    def statuses(self) -> dict[str, Any]:
        results = {}
        for role in ROLES:
            result = self.remote(role, status_script(role), "status")
            results[role] = result
            print(f"{role}: {'observed' if result['returncode'] == 0 else 'unavailable or not installed'}")
        if (self.local / "cloud-plan.json").exists():
            from cloud_gate import CloudGate
            try:
                cloud = CloudGate(self).status()
                print("cloud UDP allowance: " + cloud["status"])
                results["cloud"] = {"returncode": 0, **cloud}
            except Blocked as exc:
                results["cloud"] = {"returncode": 2, "reason": str(exc)}
                print("cloud UDP allowance: BLOCKED")
        json_write(self.run_dir / "status.json", results)
        return results

    def verify(self) -> int:
        from acceptance import main as acceptance_main
        path = self.run_dir / "verify-inventory.json"
        json_write(path, self.inventory)
        args = ["--inventory", str(path), "--output-dir", str(self.run_dir / "acceptance")]
        baseline = self.local / "baseline-observations.json"
        if baseline.exists():
            args += ["--baseline", str(baseline)]
        return acceptance_main(args)

    def load_security_gate(self) -> dict[str, Any]:
        path = self.local / "security-gate.json"
        if not path.is_file() or path.is_symlink():
            raise Blocked("reviewed .local/security-gate.json is required before benchmarking")
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077 or metadata.st_nlink != 1:
            raise Blocked("security gate must be a private file owned by this user")
        gate = json.loads(path.read_text())
        if not isinstance(gate, dict) or gate.get("owner") != "wgmvp-r1":
            raise Blocked("security gate ownership mismatch")
        tests, snapshots = gate.get("tests"), gate.get("snapshots")
        if not isinstance(tests, dict) or any(tests.get(test) != "PASS" for test in SECURITY_GATE_IDS):
            raise Blocked("security gate requires reviewed PASS evidence for A01-A05 and S01-S09")
        if not isinstance(snapshots, dict) or set(snapshots) != set(ROLES):
            raise Blocked("security gate requires all three reviewed snapshots")
        for role in ROLES:
            if not isinstance(snapshots[role], dict):
                raise Blocked(f"{role}: invalid security gate snapshot")
            snapshot_text(snapshots[role], role)
            if snapshots[role]["installed"] != "yes" or snapshots[role] != self.expected(role):
                raise Blocked(f"{role}: security evidence does not match the current reviewed snapshot")
        json_write(self.run_dir / "security-gate-used.json", gate)
        return gate

    def load_cave_leg_security_gate(self) -> dict[str, Any]:
        # A separate schema/path prevents partial PASS declarations being
        # mistaken for full-network acceptance or borrowed from global status.
        path = self.local / "security-gate-cave-leg.json"
        if not path.is_file() or path.is_symlink():
            raise Blocked("reviewed private security-gate-cave-leg.json is required for this scope")
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077 or metadata.st_nlink != 1:
            raise Blocked("scoped security gate must be private, singly linked and owned by this user")
        gate = json.loads(path.read_text())
        if (not isinstance(gate, dict) or gate.get("owner") != "wgmvp-r1"
                or gate.get("kind") != "scoped-security-gate"
                or gate.get("selected_scope") != list(CAVE_LEG_ROLES)
                or gate.get("full_acceptance") is not False):
            raise Blocked("Cave-leg gate requires explicit gz/Cave scope and full_acceptance=false")
        tests = gate.get("scope_tests")
        if not isinstance(tests, dict) or set(tests) != set(SECURITY_GATE_IDS):
            raise Blocked("scoped A01-A05/S01-S09 evidence is required; global test statuses are not substituted")
        for test in SECURITY_GATE_IDS:
            record = tests[test]
            if (not isinstance(record, dict) or record.get("status") != "PASS"
                    or record.get("selected_scope") != list(CAVE_LEG_ROLES)
                    or not isinstance(record.get("evidence_files"), list) or not record["evidence_files"]):
                raise Blocked(f"{test}: explicit PASS evidence for gz/Cave is required")
            for evidence in record["evidence_files"]:
                if (not isinstance(evidence, dict) or not isinstance(evidence.get("path"), str)
                        or not isinstance(evidence.get("sha256"), str) or not HEX.fullmatch(evidence["sha256"])):
                    raise Blocked(f"{test}: evidence must include a private path and SHA256")
                evidence_path = Path(evidence["path"])
                if not evidence_path.is_absolute():
                    evidence_path = self.local / evidence_path
                if (evidence_path.is_symlink() or not evidence_path.is_file()
                        or self.local.resolve() not in evidence_path.resolve().parents):
                    raise Blocked(f"{test}: scoped evidence must remain inside the private local directory")
                evidence_meta = evidence_path.stat()
                if (evidence_meta.st_uid != os.getuid() or evidence_meta.st_mode & 0o077
                        or evidence_meta.st_nlink != 1
                        or hashlib.sha256(evidence_path.read_bytes()).hexdigest() != evidence["sha256"]):
                    raise Blocked(f"{test}: scoped evidence permissions or hash differ from reviewed gate")
        snapshots = gate.get("snapshots")
        if not isinstance(snapshots, dict) or set(snapshots) != set(CAVE_LEG_ROLES):
            raise Blocked("Cave-leg gate requires exactly gz and Cave reviewed snapshots")
        for role in CAVE_LEG_ROLES:
            if not isinstance(snapshots[role], dict):
                raise Blocked(f"{role}: invalid scoped security snapshot")
            snapshot_text(snapshots[role], role)
            if snapshots[role]["installed"] != "yes" or snapshots[role] != self.expected(role):
                raise Blocked(f"{role}: scoped security evidence differs from current reviewed state")
        json_write(self.run_dir / "security-gate-cave-leg-used.json", gate)
        return gate

    def benchmark_gate_current(self, gate: dict[str, Any], *, active_roles: tuple[str, ...] = ROLES) -> None:
        for role in active_roles:
            if self.expected(role) != gate["snapshots"][role] or self.preflight(role) != gate["snapshots"][role]:
                raise Blocked(f"{role}: network changed since reviewed security evidence")

    def benchmark_health(self, gate: dict[str, Any], *, active_roles: tuple[str, ...] = ROLES) -> None:
        from benchmark import ADDRESSES, PAIRS
        self.benchmark_gate_current(gate, active_roles=active_roles)
        for role in active_roles:
            result = self.remote(role, status_script(role), "benchmark-health")
            if result["returncode"] != 0 or result["timeout"]:
                raise Blocked(f"{role}: permanent project policy is unhealthy after benchmark cleanup")
        for client, server in PAIRS:
            if client not in active_roles or server not in active_roles:
                continue
            argv = (["timeout", "-s", "TERM", "-k", "2", "8"]
                    + (["ip", "netns", "exec", "wgmvp"] if client == "gz" else [])
                    + ["ping", "-n", "-I", ADDRESSES[client], "-c", "3", "-w", "6", ADDRESSES[server]])
            result = self.remote(client, shlex.join(argv) + "\n", f"benchmark-health-ping-{server}")
            counts = re.search(r"(?m)^3 packets transmitted, 3 (?:packets )?received(?:,|\s)", result["stdout"])
            zero = re.search(r"(?<![\d.])0(?:\.0+)?% packet loss", result["stdout"])
            if result["returncode"] != 0 or result["timeout"] or not counts or not zero:
                raise Blocked(f"{client} to {server}: three-packet health check failed; leases not renewed")
        self.recovery()

    def benchmark(self, scope: str = "all", *, include_udp: bool = False) -> int:
        from benchmark import run_suite, scenarios
        jobs = scenarios(scope, include_udp=include_udp)
        active_roles = CAVE_LEG_ROLES if scope == "cave-leg" else ROLES
        self.operation_deadline = time.monotonic() + 3300
        # No SSH or lease mutation for absent/unreviewed evidence.
        gate = self.load_cave_leg_security_gate() if scope == "cave-leg" else self.load_security_gate()
        self.benchmark_health(gate, active_roles=active_roles)
        for role in active_roles:
            self.mutate(role,
                        'if [ -f "$ROOT/state/pending" ]; then "$ROOT/controller.sh" renew; '
                        'else [ "$(sed -n \'1p\' "$ROOT/state/committed")" = "$OWNER" ] || exit 1; '
                        '"$ROOT/controller.sh" arm; fi\n',
                        "benchmark-arm", "arm or renew pending benchmark rollback after current policy, ping and recovery checks")

        def after_measured() -> None:
            self.benchmark_health(gate, active_roles=active_roles)
            for role in active_roles:
                self.mutate(role, '"$ROOT/controller.sh" renew\n', "benchmark-renew",
                            "renew only after measured load, complete cleanup, healthy policy, selected directed pings and recovery")

        results = run_suite(self, lambda: self.benchmark_gate_current(gate, active_roles=active_roles), jobs,
                            after_measured=after_measured)
        json_write(self.run_dir / "benchmark-scope.json", {"scope": scope, "selected_scope": list(active_roles),
                   "full_acceptance": False, "optional_cave_leg_udp": include_udp,
                   "security_gate": "security-gate-cave-leg-used.json" if scope == "cave-leg" else "security-gate-used.json"})
        measured = sum(item["status"] == "MEASURED" for item in results)
        skipped = sum(item["status"] == "NOT_RUN" for item in results)
        print(f"Benchmark {scope}: {measured} measured runs; {skipped} higher UDP rates skipped after loss exceeded 1%.")
        print("Hosts remain under pending rollback leases. No revision was committed; final review and commit are manual.")
        if scope == "cave-leg":
            print("Only gz and Cave were tested; global acceptance and Villa paths remain unchanged and unverified by this run.")
        return 0 if all(item["status"] in {"MEASURED", "NOT_RUN"} for item in results) else 2

    def apply(self, *, prepare_only: bool = False, targets: tuple[str, ...] = ROLES) -> None:
        if not targets or len(set(targets)) != len(targets) or any(r not in ROLES for r in targets):
            raise Blocked("invalid or duplicate apply targets")
        selected = tuple(r for r in ROLES if r in targets)
        from render import role_files  # Root-owned renderer; no import required for read-only operations.
        bootstrap = REPO / "remote" / "bootstrap.sh"
        if not bootstrap.is_file():
            raise Blocked("reviewed bootstrap implementation is not present")
        bootstrap_source = bootstrap.read_text()
        payloads = {role: payload_function(role_files(self.inventory, role)) for role in selected}
        # Check every target before the first mutation; repeat immediately before each write.
        for role in selected:
            self.preflight(role)
        for role in selected:
            self.mutate(role, payloads[role] + "\n" + bootstrap_source + '\nbootstrap_main "$ROLE"\n',
                        "bootstrap", "install reviewed scripts, owner-local key, backups and persistent lease watcher",
                        installation="yes")
        if prepare_only:
            print("Prepared owner-local keys, backups and service-managed watchers; installed rollback exercised on selected hosts. No network objects started.")
            return
        if (self.local / "cloud-plan.json").exists():
            from cloud_gate import CloudGate
            if "gz" in selected:
                CloudGate(self).apply()
            elif CloudGate(self).status()["status"] != "PRESENT":
                raise Blocked("reviewed gz cloud UDP allowance is absent")
        public = {}
        for role in ROLES:
            result = self.remote(role, f"cat /etc/wgmvp/public.{role}\n", "public-key")
            key = result["stdout"].strip()
            if result["returncode"] != 0 or not PUBLIC_KEY.fullmatch(key):
                raise Blocked(f"{role}: invalid owner-local public key")
            public[role] = key
        if len(set(public.values())) != 3:
            raise Blocked("peer identities must be distinct")
        json_write(self.run_dir / "public-keys.json", public)
        lines = ['[ "$(cat "$ROOT/owner")" = "$OWNER" ] || exit 1']
        for peer, key in public.items():
            lines += [f'if [ -e "$ROOT/public.{peer}" ]; then',
                      f'    [ "$(cat "$ROOT/public.{peer}")" = {shlex.quote(key)} ] || exit 1',
                      'else', f'    printf \'%s\\n\' {shlex.quote(key)} > "$ROOT/public.{peer}"',
                      f'    chmod 600 "$ROOT/public.{peer}"', 'fi']
        for role in selected:
            self.mutate(role, "\n".join(lines), "public-peers", "copy only validated public keys to owned peer files")
        for role in selected:
            state = self.remote(role, '/etc/wgmvp/controller.sh status\n', "revision-state")
            if state["returncode"] != 0:
                raise Blocked(f"{role}: existing project state failed validation")
            committed = "STATE committed" in state["stdout"].splitlines()
            if not committed:
                self.mutate(role,
                            'if [ -f "$ROOT/state/pending" ]; then "$ROOT/controller.sh" renew; '
                            'else "$ROOT/controller.sh" arm; fi\n', "arm", "arm or renew the independently supervised rollback lease")
            self.mutate(role, '"$ROOT/controller.sh" start\n', "start",
                        "start only owned project interfaces, exact routes and narrow firewall policy",
                        changes_network=True, changes_files=role != "gz", check_status=True)
            for earlier in selected[:selected.index(role)]:
                checked = self.remote(earlier, status_script(earlier), "health-before-renew")
                if checked["returncode"] != 0:
                    raise Blocked(f"{earlier}: health failed before lease renewal")
                self.mutate(earlier, 'if [ -f "$ROOT/state/pending" ]; then "$ROOT/controller.sh" renew; fi\n', "renew", "renew pending lease after project/recovery health checks; preserve committed revisions")
        if selected == ROLES:
            self.verify()
        else:
            print("Partial apply: " + ", ".join(selected) + "; omitted hosts were not mutated. Full acceptance remains pending.")
        print("Existing committed revisions remain committed. New revisions remain under bounded pending leases until explicitly committed.")

    def rollback(self) -> None:
        errors = []
        for role in reversed(ROLES):
            try:
                self.mutate(role, '"$ROOT/controller.sh" rollback\n', "rollback",
                            "stop only project interfaces and retain fail-closed guards", changes_network=True)
            except (Blocked, OSError) as exc:
                errors.append(f"{role}: {exc}")
        self.close_cloud(errors)
        if errors:
            raise Blocked("; ".join(errors))

    def close_cloud(self, errors: list[str]) -> None:
        if (self.local / "cloud-plan.json").exists():
            from cloud_gate import CloudGate
            try:
                CloudGate(self).rollback()
            except (Blocked, OSError, ValueError) as exc:
                errors.append("cloud UDP allowance: " + str(exc))

    def remove(self) -> None:
        remover = REPO / "remote" / "bootstrap.sh"
        if not remover.is_file() or "bootstrap_remove()" not in remover.read_text():
            raise Blocked("reviewed owned-object remover is not available; rollback remains separate from removal")
        source = remover.read_text()
        errors = []
        for role in reversed(ROLES):
            try:
                self.mutate(role, source + '\nbootstrap_remove "$ROLE"\n', "remove",
                            "remove owned project routes, rules, UCI sections and service; retain protected backup evidence",
                            changes_network=True, changes_files=True, installation="no")
            except (Blocked, OSError) as exc:
                errors.append(f"{role}: {exc}")
        self.close_cloud(errors)
        if errors:
            raise Blocked("; ".join(errors))


def plan(inventory: dict[str, Any]) -> list[str]:
    problems = blockers(inventory)
    print("PLAN ONLY: exact management paths are unchanged; no remote write is authorized by this output.")
    for role in ROLES:
        print(f"  {role}: {shlex.join(discover.command_for(role))}")
    print("Delta: owner-local backups and lease watcher; gz isolated namespace; two restricted router interfaces; ICMP-only traffic.")
    print("Prediction: an overlay /32 chooses WireGuard; management, LAN forwarding and unlisted protocols are denied.")
    print("Mutation commands default to dry-run. No reboot is part of any automatic action.")
    if problems:
        print("BLOCKED:")
        for problem in problems:
            print(f"  - {problem}")
    else:
        print("Inventory attestations pass; live identity, reviewed snapshots and rollback prerequisites remain mandatory.")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "status", "verify", "benchmark", "rollback", "remove"))
    parser.add_argument("--inventory", type=Path, default=REPO / "inventory.local.json")
    parser.add_argument("--local-dir", type=Path, default=REPO / ".local")
    parser.add_argument("--apply", action="store_true", help="perform the selected live mutation after all gates")
    parser.add_argument("--refresh", action="store_true", help="plan: collect read-only candidate snapshots without approving them")
    parser.add_argument("--prepare", action="store_true", help="apply: bootstrap and exercise rollback only; never start network objects")
    parser.add_argument("--targets", nargs="+", choices=ROLES, help="apply: mutate only these hosts in dependency order; public keys may be read from all hosts")
    parser.add_argument("--benchmark-scope", choices=BENCHMARK_SCOPES, default=None,
                        help="benchmark: all (24 runs), per-leg, cross-tcp, cross-udp or scoped cave-leg (2 TCP runs)")
    parser.add_argument("--cave-leg-udp", action="store_true",
                        help="cave-leg only: after both TCP directions, add finite 1/5/10/20 Mbps UDP sweeps")
    parser.add_argument("--timeout", type=int, default=90, help="bounded seconds per SSH invocation (10..180)")
    parser.add_argument("--allow-router-reboot", action="store_true", help="records opt-in only; this launcher never reboots implicitly")
    args = parser.parse_args(argv)
    if not 10 <= args.timeout <= 180:
        parser.error("--timeout must be in 10..180")
    if args.refresh and args.action != "plan":
        parser.error("--refresh is only valid for plan")
    if args.prepare and args.action != "apply":
        parser.error("--prepare is only valid for apply")
    if args.targets is not None and args.action != "apply":
        parser.error("--targets is only valid for apply")
    if args.targets is not None and len(set(args.targets)) != len(args.targets):
        parser.error("--targets cannot contain duplicates")
    if args.benchmark_scope is not None and args.action != "benchmark":
        parser.error("--benchmark-scope is only valid for benchmark")
    if args.cave_leg_udp and (args.action != "benchmark" or args.benchmark_scope != "cave-leg"):
        parser.error("--cave-leg-udp requires benchmark --benchmark-scope cave-leg")
    if args.apply and args.action not in MUTATIONS:
        parser.error("--apply is only valid for a mutation action")
    os.umask(0o077)
    try:
        inventory = json.loads(args.inventory.read_text())
        if not isinstance(inventory, dict):
            raise Blocked("inventory must be an object")
        if args.action == "plan" or (args.action in MUTATIONS and not args.apply):
            problems = plan(inventory)
            if args.action in MUTATIONS:
                print(f"DRY_RUN {args.action}: no connections or remote changes.")
            if args.action == "benchmark":
                from benchmark import scenarios
                jobs = scenarios(args.benchmark_scope or "all", include_udp=args.cave_leg_udp)
                print(f"Benchmark scope {args.benchmark_scope or 'all'}: {len(jobs)} runs, each 10s plus 2s warmup; port52080 permissions expire after 120s.")
                print("Requires explicit scoped gz/Cave PASS evidence in security-gate-cave-leg.json; global acceptance is not promoted." if args.benchmark_scope == "cave-leg" else
                      "Requires reviewed matching A01-A05/S01-S09 full security gate.")
                print("UDP sweep stops above 1% loss; no automatic commit.")
            if args.refresh:
                Launcher(inventory, args.local_dir, timeout=args.timeout).refresh()
            return 2 if problems else 0
        launcher = Launcher(inventory, args.local_dir, timeout=args.timeout)
        if args.action == "status":
            results = launcher.statuses()
            print(f"Private evidence: {launcher.run_dir}")
            return 0 if all(x["returncode"] == 0 for x in results.values()) else 2
        if args.action == "verify":
            return launcher.verify()
        problems = blockers(inventory, prepare=args.prepare)
        # Incomplete deployment attestations must not obstruct an owned rollback.
        if problems and args.action in {"apply", "benchmark"}:
            raise Blocked("inventory gate: " + "; ".join(problems))
        exit_code = 0
        with coordinator_lock(args.local_dir):
            if args.action == "apply":
                launcher.apply(prepare_only=args.prepare, targets=tuple(args.targets) if args.targets else ROLES)
            elif args.action == "rollback":
                launcher.rollback()
            elif args.action == "remove":
                launcher.remove()
            elif args.action == "benchmark":
                exit_code = launcher.benchmark(args.benchmark_scope or "all", include_udp=args.cave_leg_udp)
        print(f"Private operation evidence: {launcher.run_dir}")
        return exit_code
    except (RuntimeError, OSError, ValueError, KeyError, ImportError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
