#!/usr/bin/env python3
"""Bounded S10 cleanup checks through the existing benchmark/controller backends.

Dry run is the default. Call run_expiry only while holding coordinator_lock.
No remote helper is installed, no lease record is edited, and no process is
signalled by this adapter. The backend alone checks its registered PID identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
import time

import acceptance
import benchmark
import wgmvp
from live_checks import Failed, require, TOKEN

CASES = ("normal-close", "coordinator-interruption", "service-restart", "lease-expiry")


def backend_prefix():
    digest = hashlib.sha256((wgmvp.REPO / "remote/benchmark.sh").read_bytes()).hexdigest()
    return ("ROOT=/etc/wgmvp\n"
            f'[ "$(sha256sum "$ROOT/benchmark.sh" | cut -d" " -f1)" = {digest} ]\n'
            '. "$ROOT/benchmark.sh"\n_bench_context\n')


def observation_script(token=None):
    """Short, locked, secret-free observation; only port52080 sockets are read."""
    require(token is None or TOKEN.fullmatch(token), "invalid benchmark session token")
    script = "set -eu\numask 077\n" + backend_prefix() + "_bench_lock\n"
    script += r'''
summary() {
    read -r up unused < /proc/uptime
    printf 'BOOT %s\nNOW %s\n' "$_bench_boot" "${up%%.*}"
    for name in pending rolledback; do
        file=$ROOT/state/$name
        if [ -e "$file" ]; then
            _bench_safe_file "$file" || return 1
            [ "$(sed -n '1p' "$file")" = "$OWNER" ] || return 1
            printf '%s ' "$name"; tr '\n' ' ' < "$file"; printf '\n'
        else printf '%s ABSENT\n' "$name"; fi
    done
    if [ -e "$_bench_root/active" ]; then
        _bench_load || return 1
        printf 'ACTIVE %s\n' "$_bench_token"
    else printf 'ACTIVE ABSENT\n'; fi
    if [ "$ROLE" = gz ]; then
        names=$(ip netns list) || return 1
        if printf '%s\n' "$names" | awk '$1=="wgmvp" {yes=1} END {exit !yes}'; then
            _bench_namespace || return 1
            printf 'NAMESPACE present\n'
        else printf 'NAMESPACE absent\n'; fi
    else printf 'NAMESPACE host\n'; fi
}
sockets() {
    for proto in tcp tcp6 udp udp6; do
        [ -r "/proc/net/$proto" ] || return 1
        awk -v proto="$proto" 'NR>1 && toupper($2) ~ /:CB70$/ {print proto, $2, $4}' "/proc/net/$proto" || return 1
    done
}
session() {
    [ -n "$requested" ] || return 0
    _bench_token=$requested
    _bench_dir=$_bench_root/sessions/$_bench_token
    _bench_storage && _bench_safe_dir "$_bench_dir" && _bench_safe_file "$_bench_dir/session" || return 1
    [ "$(sed -n '1p' "$_bench_dir/session")" = "$OWNER" ] || return 1
    [ "$(sed -n '2p' "$_bench_dir/session")" = "$_bench_boot" ] || return 1
    [ "$(sed -n '5p' "$_bench_dir/session")" = "$ROLE" ] || return 1
    printf 'SESSION '; tr '\n' ' ' < "$_bench_dir/session"; printf '\n'
    for kind in server.child server.wrapper; do
        file=$_bench_dir/$kind
        _bench_safe_file "$file" || return 1
        [ "$(sed -n '1p' "$file")" = "$_bench_token" ] || return 1
        [ "$(sed -n '2p' "$file")" = "$_bench_boot" ] || return 1
        pid=$(sed -n '3p' "$file"); start=$(sed -n '4p' "$file")
        _bench_uint "$pid" && _bench_uint "$start" && [ "$pid" -gt 1 ] || return 1
        ns=$(sed -n '5p' "$file")
        printf '%s\n' "$ns" | grep -Eq '^net:\[[0-9]+\]$' || return 1
        state=gone; if _bench_pid_matches "$file"; then state=live; fi
        printf 'PID %s %s %s %s %s\n' "$kind" "$pid" "$start" "$ns" "$state"
    done
}
'''
    script += "requested=" + shlex.quote(token or "") + "\n"
    script += acceptance.probe_script([
        ("summary", ["summary"]), ("session", ["session"]),
        ("host_nft", ["nft", "-j", "list", "ruleset"]),
        ("host_sockets", ["sockets"]),
    ])
    # Do not turn a failed namespace query into an empty successful observation.
    script += r'''
if [ "$ROLE" = gz ]; then
    names=$(ip netns list)
    if printf '%s\n' "$names" | awk '$1=="wgmvp" {yes=1} END {exit !yes}'; then
        _bench_namespace
        probe namespace_nft ip netns exec "$NS" nft -j list ruleset
        probe namespace_sockets ip netns exec "$NS" sh -c '
            for proto in tcp tcp6 udp udp6; do
                [ -r "/proc/net/$proto" ] || exit 1
                awk -v proto="$proto" '\''NR>1 && toupper($2) ~ /:CB70$/ {print proto, $2, $4}'\'' "/proc/net/$proto" || exit 1
            done'
    fi
fi
'''
    return script


def parse_observation(output, role, token=None):
    probes = acceptance.parse_probes(output)
    require({"summary", "session", "host_nft", "host_sockets"} <= probes.keys(), "incomplete expiry observation")
    require(all(item["returncode"] == 0 for item in probes.values()), "expiry observation command failed")
    result = {"pids": {}, "sockets": [], "nft": {}}
    for line in probes["summary"]["stdout"].splitlines():
        name, *values = line.split()
        require(name in ("BOOT", "NOW", "pending", "rolledback", "ACTIVE", "NAMESPACE") and name not in result,
                "invalid expiry summary framing")
        result[name] = values
    require(all(name in result for name in ("BOOT", "NOW", "pending", "rolledback", "ACTIVE", "NAMESPACE")),
            "missing expiry summary fields")
    require(len(result["BOOT"]) == 1 and TOKEN.fullmatch(result["BOOT"][0]), "invalid boot identity")
    require(len(result["NOW"]) == 1 and result["NOW"][0].isdigit(), "invalid monotonic clock")
    result["now"] = int(result["NOW"][0]); result["boot"] = result["BOOT"][0]
    require(len(result["ACTIVE"]) == 1 and (result["ACTIVE"] == ["ABSENT"] or TOKEN.fullmatch(result["ACTIVE"][0])),
            "invalid active session identity")
    result["active"] = None if result["ACTIVE"] == ["ABSENT"] else result["ACTIVE"][0]
    pending = result["pending"]
    if pending != ["ABSENT"]:
        require(len(pending) == 5 and pending[:2] == ["wgmvp-r1", result["boot"]]
                and all(value.isdigit() for value in pending[2:]), "malformed or different-boot pending lease")
        begin, deadline, maximum = map(int, pending[2:])
        require(begin <= deadline <= maximum and maximum-begin == 3600, "invalid lease bounds")
        result["lease"] = {"begin": begin, "deadline": deadline, "maximum": maximum}
    else:
        result["lease"] = None
    ns = result["NAMESPACE"]
    require(ns in (["present"], ["absent"]) if role == "gz" else ns == ["host"], "invalid namespace state")
    contexts = ["host"] + (["namespace"] if ns == ["present"] else [])
    for context in contexts:
        require(context+"_nft" in probes and context+"_sockets" in probes, "missing network namespace evidence")
        document = json.loads(probes[context+"_nft"]["stdout"])
        require(isinstance(document.get("nftables"), list), "invalid nft JSON")
        result["nft"][context] = document
        for line in probes[context+"_sockets"]["stdout"].splitlines():
            fields = line.split()
            require(len(fields) == 3 and fields[0] in ("tcp", "tcp6", "udp", "udp6")
                    and re.fullmatch(r"[0-9A-Fa-f]+:CB70", fields[1]) and re.fullmatch(r"[0-9A-Fa-f]{2}", fields[2]),
                    "malformed port52080 socket evidence")
            result["sockets"].append({"context": context, "protocol": fields[0], "local": fields[1], "state": fields[2]})
    if token:
        require(result["active"] in (None, token), "another benchmark session appeared")
        for line in probes["session"]["stdout"].splitlines():
            fields = line.split()
            if fields[0] == "SESSION":
                require("session" not in result and len(fields) == 7 and fields[1:3] == ["wgmvp-r1", result["boot"]]
                        and fields[5] == role and fields[6].isdigit(), "invalid saved benchmark session")
                result["session"] = {"client": fields[3], "server": fields[4], "began": int(fields[6])}
            elif fields[0] == "PID":
                require(len(fields) == 6 and fields[1] in ("server.child", "server.wrapper")
                        and fields[1] not in result["pids"] and fields[2].isdigit() and fields[3].isdigit()
                        and fields[5] in ("live", "gone"), "invalid registered process evidence")
                result["pids"][fields[1]] = fields[5]
            else:
                raise wgmvp.Blocked("unknown saved session evidence")
        require("session" in result and len(result["pids"]) == 2, "missing saved process identities")
    result["bench_objects"] = [obj for document in result["nft"].values() for item in document["nftables"]
        for kind, obj in item.items() if kind in ("rule", "set", "element") and isinstance(obj, dict)
        and (obj.get("name") == "wgmvp_bench_gate" or "wgmvp-r1:bench:" in obj.get("comment", ""))]
    return result


def assert_clean(observed):
    if observed["active"] or observed["bench_objects"] or observed["sockets"] or "live" in observed["pids"].values():
        raise Failed("benchmark active marker, permission, port52080 socket or registered process survived cleanup")


def assert_open(observed, role):
    token = observed["active"]
    require(token and observed.get("session"), "benchmark session was not observed active")
    require(observed["session"]["server"] == benchmark.ADDRESSES[role], "server is not bound to this overlay owner")
    gates = [obj for obj in observed["bench_objects"] if obj.get("name") == "wgmvp_bench_gate"]
    require(len(gates) == 1, "exact timeout gate is absent or ambiguous")
    gate = gates[0]
    # libnftables-json(5) exposes timeouts in seconds, unlike kernel netlink ms.
    require(gate.get("comment") == "wgmvp-r1:bench:"+token and gate.get("timeout") == 120
            and "timeout" in gate.get("flags", []), "native JSON does not establish the 120-second kernel timeout")
    require(gate.get("elem"), "timeout membership not observed")
    require(observed["pids"] == {"server.child": "live", "server.wrapper": "live"}, "registered server not live")
    iphex = "".join(f"{int(part):02X}" for part in benchmark.ADDRESSES[role].split(".")[::-1])+":CB70"
    context = "namespace" if role == "gz" else "host"
    require(observed["sockets"] == [{"context": context, "protocol": "tcp", "local": iphex, "state": "0A"}],
            "server socket is absent, unbound, or ambiguous")


class ExpiryChecks:
    def __init__(self, launcher, active_roles=wgmvp.ROLES, *, sleep=time.sleep, monotonic=time.monotonic):
        require(active_roles and len(set(active_roles)) == len(active_roles) and all(r in wgmvp.ROLES for r in active_roles),
                "invalid active roles")
        require(launcher.inventory["plan"]["overlay_addresses"] == {r: a+"/32" for r, a in benchmark.ADDRESSES.items()},
                "expiry checks require the reviewed address plan")
        self.launcher = launcher
        self.roles = tuple(r for r in wgmvp.ROLES if r in active_roles)
        self.sleep, self.monotonic = sleep, monotonic
        self.last_maintenance = 0
        self.evidence = []
        self.results = []

    def read(self, role, body, label):
        require(role in self.roles, "inactive expiry target")
        response = self.launcher.remote(role, body, label)
        self.evidence.append(response["evidence_file"])
        require(response["returncode"] == 0 and not response["timeout"], f"{role}: {label} unavailable")
        return response["stdout"], response["evidence_file"]

    def observe(self, role, token=None):
        text, evidence = self.read(role, observation_script(token), "expiry-observe")
        observed = parse_observation(text, role, token)
        observed["evidence_file"] = evidence
        return observed

    def healthy(self, role):
        self.launcher.preflight(role)
        self.read(role, wgmvp.status_script(role), "expiry-health")

    def renew(self, role):
        self.launcher.mutate(role, 'test -f "$ROOT/state/pending"\n"$ROOT/controller.sh" renew\n',
                             "expiry-renew", "renew an existing pending lease after independent recovery checks")

    def maintenance(self, excluded=(), force=False):
        if not force and self.monotonic()-self.last_maintenance < 45:
            return
        for role in self.roles:
            if role not in excluded:
                self.healthy(role)
                self.renew(role)
        self.launcher.recovery()
        self.last_maintenance = self.monotonic()

    def bench(self, role, action, *args):
        body = backend_prefix()
        if action == "open":
            body += ('test -f "$ROOT/state/pending"\n'
                     '[ "$(sed -n \'2p\' "$ROOT/state/pending")" = "$_bench_boot" ]\n'
                     'read -r up unused < /proc/uptime\n'
                     '[ $(( $(sed -n \'4p\' "$ROOT/state/pending") - ${up%%.*} )) -ge 15 ]\n')
        body += benchmark.command(action, *args)
        self.launcher.mutate(role, body, "expiry-bench-"+action,
                             "exercise existing owned benchmark "+action+" with native timeout and registered process cleanup",
                             changes_network=action in ("open", "close"))

    def open_server(self, role, *, server_not_before=None):
        other = "cave" if role == "gz" else "gz"
        self.bench(role, "open", benchmark.ADDRESSES[other], benchmark.ADDRESSES[role])
        if server_not_before is not None:
            self.await_time(role, None, server_not_before, excluded=(role,), limit=65)
        self.bench(role, "server")
        initial = self.observe(role)
        require(initial["active"], "benchmark open did not publish a session")
        observed = self.observe(role, initial["active"])
        assert_open(observed, role)
        return observed

    def adopt_known(self, role, expected, evidence):
        observed = self.launcher.observe(role)
        require(observed == expected, f"{role}: automatic transition differs from the previously measured clean state; reconcile manually")
        require(not wgmvp.identity_errors(self.launcher.inventory, role, observed, initial=False), "host identity changed")
        self.launcher.remember(role, observed, "expiry-known-transition", evidence)

    def stopped(self, role):
        if role == "gz":
            body = 'test ! -e /run/netns/wgmvp\n! ip link show dev wgmvp >/dev/null 2>&1\n'
        else:
            body = ('! ip link show dev wgmvp >/dev/null 2>&1\n'
                    'nft -s list table inet wgmvp_guard | cmp -s - /etc/wgmvp/router.guard.canonical\n'
                    'ip -4 route show exact 10.203.77.0/29 | grep -Fq "blackhole 10.203.77.0/29"\n')
        self.read(role, "set -eu\n"+body, "expiry-stopped")

    def restore(self, role):
        self.launcher.mutate(role, 'if [ -f "$ROOT/state/pending" ]; then "$ROOT/controller.sh" renew; '
                             'else "$ROOT/controller.sh" arm; fi\n"$ROOT/controller.sh" start\n',
                             "expiry-restore", "arm or renew and restore only the owned project interface after expiry testing",
                             changes_network=True, check_status=True)
        self.healthy(role)
        self.launcher.recovery()

    def stopped_baseline(self, role):
        attempted = False
        try:
            attempted = True
            self.launcher.mutate(role, '"$ROOT/controller.sh" stop\n', "expiry-baseline-stop",
                                 "measure the exact owned stopped configuration for later automatic rollback comparison",
                                 changes_network=True)
            self.stopped(role)
            return self.launcher.expected(role)
        finally:
            if attempted:
                self.restore(role)

    def pause(self, role, observed, target, *, excluded=()):
        remaining = max(0, target-observed["now"])
        print(f"S10 {role}: waiting {remaining}s to observed monotonic deadline; independent recovery retained", flush=True)
        self.maintenance(excluded=excluded)
        self.sleep(min(15, max(1, remaining)))

    def await_time(self, role, token, target, *, excluded=(), limit=370):
        end = self.monotonic()+limit
        while self.monotonic() < end:
            observed = self.observe(role, token)
            if observed["now"] >= target:
                return observed
            self.pause(role, observed, target, excluded=excluded)
        raise wgmvp.Blocked("bounded expiry observation deadline exhausted")

    def service_restart(self, role):
        command = ('systemctl restart wgmvp.service\nsystemctl is-active --quiet wgmvp.service\n'
                   if role == "gz" else '/etc/init.d/wgmvp restart\n')
        body = ('test -f "$ROOT/state/pending"\n'+command+
                'attempt=0\nuntil "$ROOT/controller.sh" renew; do\n'
                'attempt=$((attempt+1)); [ "$attempt" -lt 12 ] || exit 1; sleep 1\ndone\n')
        self.launcher.mutate(role, body, "expiry-service-restart",
                             "restart only the project service, exercising its normal stop cleanup and watcher restart",
                             changes_network=True)

    def run_case(self, role, case, stopped_baseline):
        detail = {"role": role, "case": case, "status": "BLOCKED", "restored": False}
        token, clean_baseline, error, restore_needed = None, None, None, False
        try:
            self.maintenance(force=True)
            initial = self.observe(role)
            assert_clean(initial)
            clean_baseline = self.launcher.preflight(role)
            if case == "lease-expiry":
                # Only the public controller API renews this record. Its entire
                # original300s interval passes; the adapter never edits fields.
                self.renew(role)
                lease_start = self.observe(role)
                lease = lease_start["lease"]
                require(lease and 275 <= lease["deadline"]-lease_start["now"] <= 300,
                        "fresh controller renewal did not leave a full bounded lease")
                detail["lease"] = lease
                before_open = self.await_time(role, None, lease["deadline"]-50, excluded=(role,))
                require(before_open["lease"] == lease, "target lease changed while waiting for real expiry")
                require(before_open["now"] < lease["deadline"]-15, "too little lease remains to start the bounded diagnostic")
            opened = self.open_server(role, server_not_before=lease["deadline"]-30 if case == "lease-expiry" else None)
            token = opened["active"]
            detail.update(token=token, initial_evidence=opened["evidence_file"], kernel_timeout_seconds=120,
                          server_timeout_seconds=45)
            if case == "normal-close":
                self.bench(role, "close")
                finished = self.observe(role, token)
                assert_clean(finished)
            elif case == "coordinator-interruption":
                # Deliberately issue no benchmark close/expire while observing.
                # The foreground coordinator is simulated absent; read-only
                # observation and unrelated hosts' lease maintenance continue.
                after_server = self.await_time(role, token, opened["now"]+50, excluded=(role,))
                require(not after_server["sockets"] and set(after_server["pids"].values()) == {"gone"},
                        "registered server or port52080 socket survived its finite timeout")
                require(after_server["active"] == token and after_server["bench_objects"],
                        "benchmark closed before its120s gate could be observed independently of server timeout")
                detail["server_expiry_evidence"] = after_server["evidence_file"]
                at_deadline = self.await_time(role, token, opened["session"]["began"]+120, excluded=(role,))
                gates = [obj for obj in at_deadline["bench_objects"] if obj.get("name") == "wgmvp_bench_gate"]
                # The backend records began before checking/applying the nft
                # transaction; permit that bounded setup gap before evaluating
                # actual element absence. Never renew or remove the element.
                if any(gate.get("elem") for gate in gates):
                    at_deadline = self.await_time(role, token, opened["session"]["began"]+132, excluded=(role,))
                    gates = [obj for obj in at_deadline["bench_objects"] if obj.get("name") == "wgmvp_bench_gate"]
                require(not any(gate.get("elem") for gate in gates), "kernel gate still contains membership after deadline")
                detail["kernel_only_runtime_observation"] = "OBSERVED_EMPTY_SET" if gates else "NOT_OBSERVED_WATCHER_ALREADY_CLEANED"
                detail["deadline_evidence"] = at_deadline["evidence_file"]
                finished = self.await_time(role, token, opened["session"]["began"]+132, excluded=(role,))
                assert_clean(finished)
                self.adopt_known(role, clean_baseline, finished["evidence_file"])
            elif case == "service-restart":
                restore_needed = True
                self.service_restart(role)
                finished = self.observe(role, token)
                assert_clean(finished)
                self.stopped(role)
                require(self.launcher.expected(role) == stopped_baseline, "service restart did not reach the measured stopped state")
            elif case == "lease-expiry":
                restore_needed = True
                require(opened["lease"] == lease and opened["now"] < lease["deadline"], "lease changed or expired before server evidence")
                detail["server_start_not_before"] = lease["deadline"]-30
                finished = self.await_time(role, token, lease["deadline"]+15, excluded=(role,))
                require(finished["lease"] is None, "pending lease was not removed by the autonomous rollback")
                rolledback = finished["rolledback"]
                require(len(rolledback) == 4 and rolledback[:2] == ["wgmvp-r1", opened["boot"]]
                        and rolledback[2].isdigit() and int(rolledback[2]) >= lease["deadline"]
                        and rolledback[3] == "lease-expired-or-boot-changed", "missing exact automatic lease rollback record")
                assert_clean(finished)
                self.stopped(role)
                self.adopt_known(role, stopped_baseline, finished["evidence_file"])
                detail["actual_lease_deadline_reached"] = True
            else:
                raise ValueError("unknown expiry case")
            detail["cleanup_evidence"] = finished["evidence_file"]
        except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
            error = exc
        finally:
            if clean_baseline is not None:
                try:
                    current = self.observe(role, token)
                    # Natural cleanup may already have completed. Accept only
                    # an exact previously measured state before another write.
                    if not current["active"] and not current["bench_objects"] and not current["sockets"]:
                        assert_clean(current)
                        known = stopped_baseline if restore_needed and current["lease"] is None else None
                        actual = self.launcher.observe(role)
                        if actual == stopped_baseline:
                            known = stopped_baseline; restore_needed = True
                        elif actual == clean_baseline:
                            known = clean_baseline
                        if known is not None:
                            self.adopt_known(role, known, current["evidence_file"])
                    else:
                        self.bench(role, "close")
                        assert_clean(self.observe(role, token))
                    if restore_needed:
                        self.restore(role)
                    else:
                        self.healthy(role)
                        self.renew(role)
                    self.launcher.recovery()
                    detail["restored"] = True
                except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
                    detail["restore_error"] = str(exc)
                    error = error or exc
        detail["status"] = "FAIL" if isinstance(error, Failed) else "BLOCKED" if error else "PASS"
        if error:
            detail["reason"] = str(error)
        return detail

    def run(self, targets=None, cases=CASES):
        targets = self.roles if targets is None else tuple(targets)
        require(targets and len(set(targets)) == len(targets) and all(role in self.roles for role in targets), "invalid expiry targets")
        require(cases and len(set(cases)) == len(cases) and all(case in CASES for case in cases), "invalid expiry cases")
        old_timeout = self.launcher.timeout
        self.launcher.timeout = min(55, old_timeout)
        try:
            for role in targets:
                self.maintenance(force=True)
                assert_clean(self.observe(role))
                stopped = self.stopped_baseline(role)
                for case in cases:
                    print(f"S10 {role}: {case}; other active hosts retain supervised pending leases", flush=True)
                    result = self.run_case(role, case, stopped)
                    self.results.append(result)
                    self.save(targets, cases)
                    if result["status"] != "PASS":
                        return self.summary(targets, cases)
            return self.summary(targets, cases)
        finally:
            self.launcher.timeout = old_timeout
            self.save(targets, cases)

    def summary(self, targets, cases):
        passed = len(self.results) == len(targets)*len(cases) and all(x["status"] == "PASS" for x in self.results)
        failed = any(x["status"] == "FAIL" for x in self.results)
        full = set(targets) == set(wgmvp.ROLES) and set(cases) == set(CASES)
        return {"id": "S10", "status": "FAIL" if failed else "PASS" if passed and full else "BLOCKED",
                "scope_status": "FAIL" if failed else "PASS" if passed else "BLOCKED",
                "selected_scope": list(targets), "active_roles": list(self.roles), "cases": list(cases),
                "observed_at": wgmvp.utcnow(), "paths": self.results, "evidence_files": self.evidence,
                "limitations": ["No throughput load or established test connection is generated; socket/process and exact temporary permission cleanup are observed.",
                                "Coordinator interruption is simulated by withholding close; the actual observing SSH connection remains available.",
                                "An already deleted set proves combined deadline cleanup, not an independently witnessed kernel timeout.",
                                "Only the project service restarts; router reboot and full network service restart are not tested."]}

    def save(self, targets, cases):
        wgmvp.json_write(self.launcher.run_dir / "expiry-check-results.json", self.summary(targets, cases), replace=True)


def run_expiry(launcher, targets=None, *, active_roles=wgmvp.ROLES, cases=CASES):
    return ExpiryChecks(launcher, active_roles=active_roles).run(targets, cases)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=wgmvp.REPO / "inventory.local.json")
    parser.add_argument("--local-dir", type=Path, default=wgmvp.REPO / ".local")
    parser.add_argument("--targets", nargs="+", choices=wgmvp.ROLES, default=list(wgmvp.ROLES))
    parser.add_argument("--active-roles", nargs="+", choices=wgmvp.ROLES, default=list(wgmvp.ROLES),
                        help="all live project hosts to maintain; a target is never renewed during its real expiry wait")
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if len(set(args.targets)) != len(args.targets) or len(set(args.active_roles)) != len(args.active_roles) or not set(args.targets) <= set(args.active_roles):
        parser.error("unique targets must be included in unique active roles")
    if len(set(args.cases)) != len(args.cases):
        parser.error("cases must be unique")
    if not args.apply:
        print("DRY_RUN S10 targets="+",".join(args.targets)+" cases="+",".join(args.cases)+
              "; maintain="+",".join(args.active_roles)+". Actual120s/300s deadlines; no connections made.")
        return 0
    try:
        inventory = json.loads(args.inventory.read_text())
        with wgmvp.coordinator_lock(args.local_dir):
            launcher = wgmvp.Launcher(inventory, args.local_dir, timeout=55)
            result = run_expiry(launcher, args.targets, active_roles=tuple(args.active_roles), cases=tuple(args.cases))
            print("S10: "+result["status"]+"; selected scope: "+result["scope_status"])
            print("Private evidence: "+str(launcher.run_dir / "expiry-check-results.json"))
            return 0 if result["scope_status"] == "PASS" else 1 if result["status"] == "FAIL" else 2
    except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
        print("BLOCKED: "+str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
