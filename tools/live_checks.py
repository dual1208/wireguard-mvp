#!/usr/bin/env python3
"""Explicitly applied, bounded acceptance operations through wgmvp.Launcher.

Importing or invoking without --apply never connects or changes a host. The
caller is the sole deployment coordinator; raw evidence remains private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
import uuid

import acceptance
import wgmvp

ADDRESSES = {"gz": "10.203.77.1", "villa": "10.203.77.2", "cave": "10.203.77.3"}
PORTS = (22, 80, 443, 53, 9090)
DENY_COMMENT = "wgmvp ingress denied all destinations and IPv6"
TOKEN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
CAPTURE_LOCK = '''[ -d "$ROOT/state" ] && [ ! -L "$ROOT/state/mutex" ]
exec 8>"$ROOT/state/mutex"
flock -x -n 8
'''


def detached_worker(script, output):
    # POSIX ignored signals survive exec. Close the capture mutex before the
    # child starts, redirect every standard descriptor, retain its finite timeout.
    return ("(trap '' HUP\nexec sh -c " + shlex.quote(script) + ") >" + shlex.quote(output)
            + " 2>&1 </dev/null 8>&- &\n")


class Failed(wgmvp.Blocked):
    """Observed contradiction, distinguished from unavailable evidence."""


def require(condition, reason):
    if not condition:
        raise wgmvp.Blocked(reason)


def counter(document, table, chain, comment, verdict):
    rules = [item["rule"] for item in document["nftables"] if "rule" in item
             and item["rule"].get("family") == "inet" and item["rule"].get("table") == table
             and item["rule"].get("chain") == chain and item["rule"].get("comment") == comment]
    require(len(rules) == 1, "exact owned counter rule is absent or ambiguous")
    expressions = rules[0]["expr"]
    require(any(verdict in item for item in expressions), "counter rule verdict differs")
    values = [item["counter"]["packets"] for item in expressions if "counter" in item]
    require(len(values) == 1 and type(values[0]) is int and values[0] >= 0, "counter unavailable")
    return values[0]


def receiver_counter(document):
    chains = [x["chain"] for x in document["nftables"] if "chain" in x]
    require(any(x.get("table") == "wgmvp_guard" and x.get("name") == "prerouting"
                and x.get("hook") == "prerouting" and x.get("prio") == -190 for x in chains),
            "receiver guard is not at reviewed prerouting priority")
    jumps = [x["rule"] for x in document["nftables"] if "rule" in x
             and x["rule"].get("table") == "wgmvp_guard" and x["rule"].get("chain") == "prerouting"]
    require(any({"jump": {"target": "rx"}} in r.get("expr", []) and
                any(e.get("match") == {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wgmvp"}
                    for e in r.get("expr", [])) for r in jumps), "project ingress does not reach receiver rx guard")
    return counter(document, "wgmvp_guard", "rx", DENY_COMMENT, "drop")


def route_is_project(document, source):
    require(isinstance(document, list) and len(document) == 1, "route result absent or ambiguous")
    route = document[0]
    require(route.get("dev") == "wgmvp" and route.get("type", "unicast") == "unicast",
            "explicit-source destination does not use project interface")
    require(route.get("from", route.get("src", route.get("prefsrc"))) == source,
            "route lookup does not retain explicit overlay source")


def nc_results(output):
    result = {}
    for line in output.splitlines():
        parts = line.split()
        require(len(parts) == 3 and parts[0] == "PORT" and parts[1].isdigit() and parts[2].isdigit(),
                "unexpected nc evidence framing")
        port, status = int(parts[1]), int(parts[2])
        require(port in PORTS and port not in result, "duplicate or unreviewed probe port")
        if status == 0:
            raise Failed("management TCP connection unexpectedly succeeded")
        require(status in (1, 124), "netcat invocation or bounded runner failed")
        result[port] = status
    require(set(result) == set(PORTS), "missing management port results")
    return result


def syn_ports(trace, source, receiver):
    pattern = re.compile(r"\bIP " + re.escape(ADDRESSES[source]) + r"\.\d+ > " +
                         re.escape(ADDRESSES[receiver]) + r"\.(\d+): Flags \[S\]")
    observed = {int(match.group(1)) for match in pattern.finditer(trace)}
    require(observed == set(PORTS), "receiver SYN capture lacks an exact-source attempt to every reviewed management port")
    return sorted(observed)


class LiveChecks:
    """Call while holding wgmvp.coordinator_lock; never call concurrently."""
    def __init__(self, launcher, active_roles=wgmvp.ROLES):
        self.launcher = launcher
        require(len(active_roles) >= 2 and len(set(active_roles)) == len(active_roles)
                and "gz" in active_roles and all(role in wgmvp.ROLES for role in active_roles),
                "active targets must include gz and at least one router, without duplicates")
        self.roles = tuple(role for role in wgmvp.ROLES if role in active_roles)
        self.positive_pairs = tuple((source, receiver) for source in self.roles for receiver in self.roles if source != receiver)
        expected = {r: a + "/32" for r, a in ADDRESSES.items()}
        require(launcher.inventory["plan"]["overlay_addresses"] == expected,
                "live checks require the reviewed fixed address plan")
        self.port = launcher.inventory["plan"]["outer_udp_port"]
        require(type(self.port) is int and 1024 <= self.port <= 65535, "unreviewed outer UDP port")
        self.results = {}
        self.probe_hash = hashlib.sha256((wgmvp.REPO / "remote/security-probe.sh").read_bytes()).hexdigest()

    def read(self, role, script, label):
        require(role in self.roles, "read targets an inactive project host")
        result = self.launcher.remote(role, "set -eu\n" + script, label)
        require(result["returncode"] == 0 and not result["timeout"], f"{role}: {label} evidence unavailable")
        return result["stdout"]

    def healthy(self, role):
        require(role in self.roles, "health check targets an inactive host")
        self.launcher.preflight(role)
        self.read(role, wgmvp.status_script(role), "live-check-health")

    def renew(self, role):
        require(role in self.roles, "lease renewal targets an inactive host")
        self.launcher.mutate(role, 'test -f "$ROOT/state/pending"\n"$ROOT/controller.sh" renew\n',
                             "check-renew", "renew existing pending lease after fresh recovery checks")

    def table(self, role):
        return json.loads(self.read(role, "nft -j list table inet wgmvp_guard\n", "receiver-guard-counter"))

    def probe_state(self, role, source):
        prefix = "ip netns exec wgmvp " if role == "gz" else ""
        table = "wgmvp" if role == "gz" else "wgmvp_guard"
        output = self.read(role, "test -f /etc/wgmvp/probe.active\n"
                           "printf 'TOKEN '; sed -n '2p' /etc/wgmvp/probe.active\n" +
                           prefix + f"nft -j list table inet {table}\n", "sender-probe-counter")
        first, text = output.split("\n", 1)
        require(first.startswith("TOKEN ") and TOKEN.fullmatch(first[6:]), "invalid probe ownership token")
        token = first[6:]
        chain = ("output" if source == "gz" else "forward") if role == "gz" else "tx"
        document = json.loads(text)
        packets = counter(document, table, chain, "wgmvp-r1:probe:" + token, "accept")
        return token, packets

    def probe_body(self, action, source=None, receiver=None):
        body = f'[ "$(sha256sum "$ROOT/security-probe.sh" | cut -d" " -f1)" = {self.probe_hash} ]\n'
        body += '"$ROOT/security-probe.sh" ' + action
        if action == "open":
            body += " " + ADDRESSES[source] + " " + ADDRESSES[receiver]
        return body + "\n"

    def probe_ports(self, source, receiver):
        prefix = "ip netns exec wgmvp " if source == "gz" else ""
        src, dst = ADDRESSES[source], ADDRESSES[receiver]
        route = json.loads(self.read(source, prefix + f"ip -j -4 route get {dst} from {src}\n", "management-route"))
        route_is_project(route, src)
        if source != "gz":
            # The audited BusyBox nc lacks -s/-z/-w. Check the kernel-selected
            # source for the unbound socket; timeout bounds its plain connect.
            selected = json.loads(self.read(source, f"ip -j -4 route get {dst}\n", "management-selected-source"))
            route_is_project(selected, src)
        script = ""
        for port in PORTS:
            nc = f"nc -s {src} -z -w 1 {dst} {port}" if source == "gz" else f"nc {dst} {port}"
            script += ("rc=0\ntimeout -k 1 1 " + prefix + nc + " "
                       "</dev/null >/dev/null 2>&1 || rc=$?\n" + f"printf 'PORT {port} %s\\n' \"$rc\"\n")
        return nc_results(self.read(source, script, "management-five-ports"))

    def management_path(self, source, receiver):
        require((source, receiver) in (("gz", "villa"), ("gz", "cave"), ("villa", "cave"), ("cave", "villa")),
                "unreviewed management path")
        require(source in self.roles and receiver in self.roles, "management path touches an inactive target")
        opened, cleanup_errors, detail = [], [], {}
        roles = ["gz"] if source == "gz" else ["gz", source]
        baseline, capture, capture_traces = None, None, None
        error = None
        try:
            for role in self.roles:
                self.healthy(role)
                self.renew(role)
            # Capture before opening anything at sender/transit. Receiver stays unchanged.
            baseline = self.table(receiver)
            before = receiver_counter(baseline)
            for role in roles:
                self.read(role, "test ! -e /etc/wgmvp/probe.active\n", "probe-absent")
                opened.append(role)  # Attempt cleanup even if opening partially fails.
                self.launcher.mutate(role, self.probe_body("open", source, receiver), "management-open",
                                     f"60-second sender/transit-only TCP exception {source} to {receiver}; receiver unchanged",
                                     changes_network=True)
            sender_before = {r: self.probe_state(r, source) for r in roles}
            port_filter = " or ".join(f"dst port {p}" for p in PORTS)
            capture = self.start_capture(receiver, {"syn": f"tcp and src host {ADDRESSES[source]} and dst host {ADDRESSES[receiver]} and tcp[13] & 0x12 = 0x02 and ({port_filter})"}, duration=20)
            self.read(receiver, f"test ! -e {shlex.quote(capture['path']+'/done')}\n", "syn-capture-still-running")
            detail["ports"] = self.probe_ports(source, receiver)
            self.read(receiver, f"test ! -e {shlex.quote(capture['path']+'/done')}\n", "syn-capture-covered-probes")
            after = self.table(receiver)
            received = receiver_counter(after) - before
            require(acceptance.normalized(after) == acceptance.normalized(baseline),
                    "receiver guard changed during denial test")
            require(received >= len(PORTS), "receiver drop counter lacks five attempted management SYNs")
            deltas = {}
            for role in roles:
                token, packets = self.probe_state(role, source)
                require(token == sender_before[role][0], "probe permission ownership changed")
                deltas[role] = packets - sender_before[role][1]
                require(deltas[role] >= len(PORTS), "sender/transit counter lacks actual TCP attempts")
            detail.update(receiver_drop_delta=received, sender_transit_deltas=deltas)
        except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
            error = exc
        finally:
            for role in reversed(opened):
                try:
                    self.launcher.mutate(role, self.probe_body("close"), "management-close",
                                         "remove this test's sender/transit exception; retain receiver guard",
                                         changes_network=True)
                    self.read(role, "test ! -e /etc/wgmvp/probe.active\n", "probe-closed")
                except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
                    cleanup_errors.append(f"{role}: {exc}")
            # Permissions are no longer needed once attempts/counters are read.
            # Close them before waiting for the capture's remaining duration.
            if capture:
                try:
                    capture_traces = self.finish_capture(capture)
                except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
                    cleanup_errors.append(f"{receiver} capture: {exc}")
        if cleanup_errors:
            detail["cleanup_errors"] = cleanup_errors
            error = error or wgmvp.Blocked("probe cleanup incomplete; supervised expiry remains authoritative")
        if error is None:
            try:
                require(capture_traces is not None, "receiver SYN evidence missing")
                detail["receiver_syn_ports"] = syn_ports(capture_traces["syn"], source, receiver)
                for role in set(roles + [receiver]):
                    self.healthy(role)
                self.launcher.recovery()
            except wgmvp.Blocked as exc:
                error = exc
        detail.update(source=source, receiver=receiver, status="FAIL" if isinstance(error, Failed) else "BLOCKED" if error else "PASS")
        if error:
            detail["reason"] = str(error)
        return detail

    def management(self):
        paths = []
        for source, receiver in (("gz", "villa"), ("gz", "cave"), ("villa", "cave"), ("cave", "villa")):
            if source not in self.roles or receiver not in self.roles:
                continue
            result = self.management_path(source, receiver)
            paths.append(result)
            if result["status"] != "PASS":
                break
        statuses = {p["status"] for p in paths}
        self.results["S03"] = {"id": "S03", "observed_at": wgmvp.utcnow(), "paths": paths,
                               "status": "FAIL" if "FAIL" in statuses else "PASS" if len(paths) == 4 and statuses == {"PASS"} else "BLOCKED",
                               "active_roles": self.roles, "scope_status": "FAIL" if "FAIL" in statuses else "PASS" if statuses == {"PASS"} else "BLOCKED",
                               "limitations": ["Selected overlay TCP ports are exercised. All-local-address coverage also relies on the unchanged ingress guard; no LAN prefix is advertised."]}
        if self.roles != wgmvp.ROLES:
            self.results["S03"]["limitations"].append("Partial target selection; full four-path S03 acceptance remains pending.")
        self.save()
        return self.results["S03"]

    def positive_control(self):
        for source, receiver in self.positive_pairs:
            src, dst = ADDRESSES[source], ADDRESSES[receiver]
            prefix = "ip netns exec wgmvp " if source == "gz" else ""
            route = json.loads(self.read(source, prefix + f"ip -j -4 route get {dst} from {src}\n", "restart-route"))
            route_is_project(route, src)
            output = self.read(source, "timeout -k 1 10 " + prefix + f"ping -n -I {src} -c 3 -W 2 {dst}\n", "restart-positive-control")
            require(acceptance.zero_loss(output), "post-restart explicit-source pings did not have zero loss")

    def mutation_stdout(self, role, body, action, delta):
        require(role in self.roles, "mutation targets an inactive host")
        self.launcher.mutate(role, body, action, delta)
        state = json.loads((self.launcher.local / "state" / f"{role}.json").read_text())
        evidence = Path(state["evidence_file"])
        require(evidence.parent.resolve() == self.launcher.run_dir.resolve() and state["operation"] == action,
                "mutation evidence does not belong to this operation")
        return json.loads(evidence.read_text())["stdout"]

    def start_capture(self, role, filters, *, duration=16):
        """Bounded header-only capture; files are root-only and removed on finish."""
        require(role in self.roles, "capture targets an inactive host")
        require(1 <= len(filters) <= 2 and 10 <= duration <= 20, "capture bounds exceeded")
        require(all(re.fullmatch(r"[a-z]+", name) for name in filters), "invalid capture name")
        token = str(uuid.uuid4())
        path = "/etc/wgmvp/check-capture-" + token
        worker, files = ["set -u", "umask 077"], ["scope", "runner.log", "done"]
        for name, filter_text in filters.items():
            files += [name + suffix for suffix in (".txt", ".log", ".rc")]
            worker += [f"timeout -s INT -k 2 {duration} tcpdump -l -nn -i any {shlex.quote(filter_text)} "
                       f">{shlex.quote(path+'/'+name+'.txt')} 2>{shlex.quote(path+'/'+name+'.log')} &",
                       f"pid_{name}=$!"]
        for name in filters:
            worker += [f"rc=0; wait \"$pid_{name}\" || rc=$?",
                       f"printf '%s\\n' \"$rc\" > {shlex.quote(path+'/'+name+'.rc')}"]
        worker += [f"printf 'complete\\n' > {shlex.quote(path+'/done')}"]
        body = (CAPTURE_LOCK + 'test -f "$ROOT/state/pending"\n'
                '[ "$(sed -n \'1p\' "$ROOT/state/pending")" = "$OWNER" ]\n'
                '[ "$(sed -n \'2p\' "$ROOT/state/pending")" = "$(cat /proc/sys/kernel/random/boot_id)" ]\n'
                'tick=$(cut -d. -f1 /proc/uptime)\ndeadline=$(sed -n \'4p\' "$ROOT/state/pending")\n'
                f'[ "$deadline" -gt "$((tick+{duration+15}))" ]\n'
                f'd={shlex.quote(path)}\n[ ! -e "$d" ]\nmkdir -m 700 "$d"\n'
                f"printf '%s\\n' wgmvp-r1 {shlex.quote(token)} > \"$d/scope\"\n"
                + detached_worker("\n".join(worker), path + "/runner.log"))
        for name in filters:
            body += (f'attempt=0\nuntil grep -q "listening on " "$d/{name}.log"; do\n'
                     ' attempt=$((attempt+1)); [ "$attempt" -lt 5 ] || exit 1; sleep 1\ndone\n')
        capture = {"role": role, "path": path, "token": token, "filters": filters, "files": files}
        try:
            self.launcher.mutate(role, body, "capture-start", "start a finite, synthetic-only packet-header capture on host interfaces")
        except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
            try:
                self.finish_capture(capture)
            except (wgmvp.Blocked, ValueError, KeyError, OSError) as cleanup:
                raise wgmvp.Blocked(f"capture startup failed; bounded worker/owned evidence at {path}; cleanup: {cleanup}") from exc
            raise
        return capture

    def finish_capture(self, capture):
        require(capture["role"] in self.roles, "capture cleanup targets an inactive host")
        path, token = capture["path"], capture["token"]
        require(path == "/etc/wgmvp/check-capture-" + token and TOKEN.fullmatch(token), "invalid capture ownership")
        body = ('''safe_capture_dir() {
 [ -d "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
 awk '$1=="drwx------" && $3==0 {good=1} END {exit !good}'
}
safe_capture_file() {
 [ -f "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
 awk '$1=="-rw-------" && $2==1 && $3==0 {good=1} END {exit !good}'
}
''' + f'd={shlex.quote(path)}\n'
                'safe_capture_dir "$d"\nsafe_capture_file "$d/scope"\n'
                '[ "$(sed -n \'1p\' "$d/scope")" = wgmvp-r1 ]\n'
                f'[ "$(sed -n \'2p\' "$d/scope")" = {shlex.quote(token)} ]\n'
                'attempt=0\nuntil [ -f "$d/done" ]; do\n'
                ' attempt=$((attempt+1)); [ "$attempt" -lt 24 ] || exit 1; sleep 1\ndone\n')
        # Waiting is read-only. Keep the mutex hold short so the controller's
        # watchdog heartbeat can continue while tcpdump finishes its interval.
        body += CAPTURE_LOCK + 'safe_capture_dir "$d"\nsafe_capture_file "$d/scope"\n'
        body += ('[ "$(sed -n \'1p\' "$d/scope")" = wgmvp-r1 ]\n'
                 f'[ "$(sed -n \'2p\' "$d/scope")" = {shlex.quote(token)} ]\n')
        for filename in capture["files"]:
            body += f'safe_capture_file "$d/{filename}"\n'
        commands = []
        for name in capture["filters"]:
            commands += [(name + "_trace", ["cat", path + "/" + name + ".txt"]),
                         (name + "_log", ["cat", path + "/" + name + ".log"]),
                         (name + "_rc", ["cat", path + "/" + name + ".rc"])]
        body += acceptance.probe_script(commands)
        body += "rm " + " ".join(shlex.quote(path + "/" + name) for name in capture["files"]) + "\n"
        body += "rmdir " + shlex.quote(path) + "\n"
        output = self.mutation_stdout(capture["role"], body, "capture-finish", "collect synthetic packet-header evidence and remove exact owned capture files")
        probes = acceptance.parse_probes(output)
        traces = {}
        for name in capture["filters"]:
            require(all(probes[name + suffix]["returncode"] == 0 for suffix in ("_trace", "_log", "_rc")), "capture evidence incomplete")
            require(probes[name + "_rc"]["stdout"] == "124", "capture did not finish its bounded observation interval normally")
            require(re.search(r"(?m)^0 packets dropped by kernel\s*$", probes[name + "_log"]["stdout"]),
                    "capture reported drops or its health counters are unavailable")
            traces[name] = probes[name + "_trace"]["stdout"]
        return traces

    def independent_management(self):
        for role in self.roles:
            require(self.read(role, "id -u\n", "lifecycle-independent-ssh").strip() == "0",
                    "independent management identity unavailable")
        self.launcher.recovery()

    def assert_stopped(self, role):
        if role == "gz":
            script = "test ! -e /run/netns/wgmvp\n! ip link show dev wgmvp >/dev/null 2>&1\n"
        else:
            script = ('! ip link show dev wgmvp >/dev/null 2>&1\n'
                      'test -f /etc/wgmvp/router.guard.canonical\n'
                      'nft -s list table inet wgmvp_guard | cmp -s - /etc/wgmvp/router.guard.canonical\n'
                      'ip -4 route show exact 10.203.77.0/29 | grep -Fq "blackhole 10.203.77.0/29"\n')
        self.read(role, script, "project-stopped")

    def lifecycle_path(self, role, *, while_down=None, restart_service=True):
        require(role in self.roles, "inactive lifecycle role")
        attempted_stop, restored, error, detail = False, False, None, {"role": role}
        try:
            for host in self.roles:
                self.healthy(host)
                self.renew(host)
            # Public-only identity proves that a lifecycle test did not rotate keys.
            before_key = self.read(role, f"cat /etc/wgmvp/public.{role}\n", "restart-public-before").strip()
            require(wgmvp.PUBLIC_KEY.fullmatch(before_key), "owner public identity is malformed")
            self.positive_control()
            attempted_stop = True
            self.launcher.mutate(role, 'test -f "$ROOT/state/pending"\n"$ROOT/controller.sh" stop\n',
                                 "check-stop", "stop only this owner's project interface; retain router guards/drop route",
                                 changes_network=True)
            # Launcher.mutate records this deliberate stopped state. The following
            # start preflight compares against it, not a stale running snapshot.
            self.assert_stopped(role)
            self.independent_management()
            if while_down:
                detail["down_probe"] = while_down(role)
            if role == "gz" and restart_service:
                body = ('test -f "$ROOT/state/pending"\n'
                        'systemctl restart wgmvp.service\n'
                        'systemctl is-active --quiet wgmvp.service\n'
                        'attempt=0\nuntil "$ROOT/controller.sh" renew; do\n'
                        ' attempt=$((attempt+1)); [ "$attempt" -lt 12 ] || exit 1; sleep 1\ndone\n')
                self.launcher.mutate(role, body, "check-project-service-restart",
                                     "restart only the new wgmvp service and verify its persistent lease watcher")
                detail["service_restart"] = "wgmvp.service"
        except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
            error = exc
        finally:
            if attempted_stop:
                try:
                    self.launcher.mutate(role, 'test -f "$ROOT/state/pending"\n"$ROOT/controller.sh" start\n',
                                         "check-restore", "restore only this owner's project interface after bounded lifecycle check",
                                         changes_network=True, check_status=True)
                    restored = True
                except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
                    detail["restore_error"] = str(exc)
                    error = error or exc
        if restored:
            try:
                self.healthy(role)
                after_key = self.read(role, f"cat /etc/wgmvp/public.{role}\n", "restart-public-after").strip()
                require(after_key == before_key, "owner public identity changed across restart")
                self.positive_control()
                self.independent_management()
            except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
                error = error or exc
        detail.update(restored=restored, status="FAIL" if isinstance(error, Failed) else "BLOCKED" if error else "PASS")
        if error:
            detail["reason"] = str(error)
        return detail

    def restart(self, roles=None):
        roles = self.roles if roles is None else roles
        paths = []
        for role in roles:
            result = self.lifecycle_path(role)
            paths.append(result)
            if result["status"] != "PASS":
                break
        statuses = {p["status"] for p in paths}
        self.results["O02"] = {"id": "O02", "observed_at": wgmvp.utcnow(), "paths": paths,
                               "status": "FAIL" if "FAIL" in statuses else "PASS" if {p["role"] for p in paths} == set(wgmvp.ROLES) and statuses == {"PASS"} else "BLOCKED",
                               "active_roles": self.roles, "scope_status": "FAIL" if "FAIL" in statuses else "PASS" if statuses == {"PASS"} else "BLOCKED",
                               "limitations": ["Only the new project interfaces and gz project service are restarted. Router reboot O03 is not executed."]}
        if {p["role"] for p in paths} != set(wgmvp.ROLES):
            self.results["O02"]["limitations"].append("Partial target selection; full three-host O02 acceptance remains pending.")
        self.save()
        return self.results["O02"]

    def down_probe(self, role):
        filters = {"plain": "icmp and dst net 10.203.77.0/29 and icmp[0] = 8"}
        if role == "gz":
            filters["outer"] = f"udp dst port {self.port} and udp[8:4] = 0x04000000 and udp[4:2] > 40"
        capture, traces, error = None, None, None
        detail = {"capture_host": role, "capture_interfaces": "any in host namespace"}
        try:
            capture = self.start_capture(role, filters, duration=20)
            senders = tuple(host for host in self.roles if host != "gz") if role == "gz" else (role,)
            attempts = {}
            for sender in senders:
                self.read(role, f"test ! -e {shlex.quote(capture['path']+'/done')}\n", "capture-still-running")
                other = "cave" if sender == "villa" else "villa"
                if other not in self.roles:
                    other = "gz"
                dst = ADDRESSES[other]
                commands = [("route", ["ip", "-j", "-4", "route", "get", dst]),
                            ("ping", ["timeout", "-k", "1", "7", "ping", "-n", "-c", "3", "-W", "1", dst])]
                probes = acceptance.parse_probes(self.read(sender, acceptance.probe_script(commands), "down-unbound-probe"))
                if probes["ping"]["returncode"] == 0:
                    raise Failed("tunnel-down ping unexpectedly succeeded")
                require(probes["ping"]["returncode"] in (1, 2, 124), "down probe command unavailable")
                if role == "gz":
                    require(probes["route"]["returncode"] == 0, "router's retained project route unavailable during hub-down test")
                    route_is_project(json.loads(probes["route"]["stdout"]), ADDRESSES[sender])
                attempts[sender] = {"route_rc": probes["route"]["returncode"], "ping_rc": probes["ping"]["returncode"]}
            self.read(role, f"test ! -e {shlex.quote(capture['path']+'/done')}\n", "capture-covered-probes")
            detail["attempts"] = attempts
        except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
            error = exc
        finally:
            if capture:
                try:
                    traces = self.finish_capture(capture)
                except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
                    error = error or exc
        if error:
            raise error
        require(traces is not None, "capture missing")
        if traces["plain"].strip():
            raise Failed("synthetic overlay ICMP appeared in plaintext on host interfaces while project was stopped")
        detail["plaintext_packets"] = 0
        if role == "gz":
            packets = len(traces["outer"].splitlines())
            require(packets >= 3 * len(senders), "hub-down test lacks encrypted arrivals from bounded router probes")
            detail["encrypted_packets"] = packets
        return detail

    def tunnel_down(self, roles=None):
        roles = self.roles if roles is None else roles
        paths = []
        for role in roles:
            result = self.lifecycle_path(role, while_down=self.down_probe, restart_service=False)
            paths.append(result)
            if result["status"] != "PASS":
                break
        statuses = {p["status"] for p in paths}
        self.results["S07"] = {"id": "S07", "observed_at": wgmvp.utcnow(), "paths": paths,
                               "status": "FAIL" if "FAIL" in statuses else "PASS" if {p["role"] for p in paths} == set(wgmvp.ROLES) and statuses == {"PASS"} else "BLOCKED",
                               "active_roles": self.roles, "scope_status": "FAIL" if "FAIL" in statuses else "PASS" if statuses == {"PASS"} else "BLOCKED",
                               "limitations": ["Captures cover all interfaces in each stopped owner's host namespace. Hub-down probes originate on routers; no unrelated ordinary-host overlay route is created. Reboot is not tested."]}
        if {p["role"] for p in paths} != set(wgmvp.ROLES):
            self.results["S07"]["limitations"].append("Partial target selection; full three-host S07 acceptance remains pending.")
        self.save()
        return self.results["S07"]

    def firewall_reload(self):
        from reload_check import run_reload
        result = run_reload(self.launcher, active_roles=self.roles)
        self.results["S08"] = result
        self.save()
        return result

    def save(self):
        wgmvp.json_write(self.launcher.run_dir / "live-check-results.json",
                         {"generated_at": wgmvp.utcnow(), "complete_acceptance": False,
                          "tests": list(self.results.values()),
                          "evidence_directory": str(self.launcher.run_dir)}, replace=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("management", "restart", "tunnel-down", "firewall-reload"))
    parser.add_argument("--inventory", type=Path, default=wgmvp.REPO / "inventory.local.json")
    parser.add_argument("--local-dir", type=Path, default=wgmvp.REPO / ".local")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--targets", nargs="+", choices=wgmvp.ROLES, default=list(wgmvp.ROLES),
                        help="active hosts only; subset results cannot establish full acceptance")
    args = parser.parse_args(argv)
    if len(args.targets) < 2 or "gz" not in args.targets or len(set(args.targets)) != len(args.targets):
        parser.error("targets must include gz and at least one router, without duplicates")
    if not args.apply:
        print("DRY_RUN targets=" + ",".join(role for role in wgmvp.ROLES if role in args.targets) + ": " +
              ("selected authorized management paths, five TCP ports each; temporary sender/transit exceptions; receiver guard unchanged."
                            if args.action == "management" else "individual project stops/restores with bounded synthetic captures and recovery checks." if args.action == "tunnel-down" else
                            "sequential supported fw4 reloads, unchanged independent guards and IPv6 structural checks." if args.action == "firewall-reload" else
                            "individual project interface restarts and gz project service restart, with recovery checks and positive controls.") + " No connections made.")
        return 0
    try:
        inventory = json.loads(args.inventory.read_text())
        with wgmvp.coordinator_lock(args.local_dir):
            checks = LiveChecks(wgmvp.Launcher(inventory, args.local_dir), active_roles=tuple(args.targets))
            result = {"management": checks.management, "restart": checks.restart, "tunnel-down": checks.tunnel_down,
                      "firewall-reload": checks.firewall_reload}[args.action]()
            print(result["id"] + ": " + result["status"])
            if result.get("scope_status"):
                print("Selected scope: " + result["scope_status"] + " (" + ", ".join(checks.roles) + ")")
            print("Private evidence: " + str(checks.launcher.run_dir))
            return 0 if result.get("scope_status", result["status"]) == "PASS" else 1 if result["status"] == "FAIL" else 2
    except (wgmvp.Blocked, ValueError, KeyError, OSError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
