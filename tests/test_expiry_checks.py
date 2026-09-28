"""Offline expiry state-machine tests; no SSH, sockets or network mutation."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import expiry_checks as check
import wgmvp

BOOT = "12345678-1234-1234-1234-123456789abc"


def frame(name, value, rc=0):
    return f"WGMVP_BEGIN {name}\n{value}\nWGMVP_END {name} {rc}\n"


class Simulator:
    """Independent clock model of watcher deadlines, snapshots and pid lifetime."""
    def __init__(self, directory, roles=wgmvp.ROLES, failure=None):
        self.run_dir = Path(directory)
        self.timeout = 90
        self.clock = 100
        self.counter = 0
        self.events = []
        self.roles = roles
        self.failure = failure
        self.inventory = {"plan": {"overlay_addresses": {r: a+"/32" for r, a in check.benchmark.ADDRESSES.items()}},
                          "identities": {r: {p: "a"*64 for p in wgmvp.IDENTITY_FILES[r]} for r in roles}}
        self.state = {r: {"mode": "running", "lease": {"begin": 100, "deadline": 400, "maximum": 3700},
                          "active": None, "session": None, "gate": False, "server_start": None,
                          "pids_live": False, "rolledback": None} for r in roles}
        self.reviewed = {r: self.snapshot(r) for r in roles}

    def snapshot(self, role):
        s = self.state[role]
        value = {"files": self.inventory["identities"][role].copy(), "installed": "yes",
                 "network_sha256": hashlib.sha256((role+s["mode"]+str(s["gate"])).encode()).hexdigest()}
        if role != "gz": value["unrelated_config_sha256"] = "b"*64
        return value

    def advance(self, seconds):
        self.clock += seconds
        for state in self.state.values():
            if state["server_start"] is not None and self.clock >= state["server_start"]+45:
                state["pids_live"] = False
            if state["active"] and self.clock >= state["session"]["began"]+123:
                state.update(active=None, gate=False, pids_live=False)
            if state["lease"] and self.clock >= state["lease"]["deadline"]+3:
                deadline = state["lease"]["deadline"]
                state.update(mode="stopped", lease=None, active=None, gate=False, pids_live=False,
                             rolledback=["wgmvp-r1", BOOT, str(deadline+3), "lease-expired-or-boot-changed"])

    def sleep(self, seconds):
        assert seconds <= 15
        self.events.append(("sleep", seconds))
        self.advance(seconds)

    def expected(self, role):
        return copy.deepcopy(self.reviewed[role])

    def observe(self, role):
        self.events.append(("snapshot", role))
        self.advance(1)
        value = self.snapshot(role)
        if self.failure == "foreign-drift" and self.state[role]["rolledback"]:
            value["network_sha256"] = "f"*64
        return value

    def preflight(self, role):
        if self.observe(role) != self.reviewed[role]:
            raise wgmvp.Blocked("unreviewed fingerprint drift")
        return self.expected(role)

    def remember(self, role, snapshot, action, evidence):
        self.events.append(("remember", role, action))
        self.reviewed[role] = copy.deepcopy(snapshot)

    def recovery(self):
        self.events.append(("recovery",)); self.advance(1)

    def mutate(self, role, body, action, delta, **kwargs):
        self.preflight(role)
        self.events.append(("mutate", role, action, self.clock, body))
        s = self.state[role]
        if self.failure == "server-start" and action == "expiry-bench-server":
            raise wgmvp.Blocked("server readiness unavailable")
        if action == "expiry-renew":
            if not s["lease"]: raise wgmvp.Blocked("missing pending")
            s["lease"]["deadline"] = min(self.clock+300, s["lease"]["maximum"])
        elif action == "expiry-bench-open":
            self.counter += 1
            token = f"12345678-1234-1234-1234-{self.counter:012x}"
            s.update(active=token, gate=True, pids_live=False, server_start=None,
                     session={"began": self.clock, "client": check.benchmark.ADDRESSES["cave" if role == "gz" else "gz"],
                              "server": check.benchmark.ADDRESSES[role], "token": token})
        elif action == "expiry-bench-server":
            s.update(pids_live=True, server_start=self.clock)
        elif action == "expiry-bench-close":
            s.update(active=None, gate=False, pids_live=False)
        elif action in ("expiry-baseline-stop", "expiry-service-restart"):
            s.update(mode="stopped", active=None, gate=False, pids_live=False)
            if action == "expiry-service-restart": s["lease"]["deadline"] = self.clock+300
        elif action == "expiry-restore":
            s["mode"] = "running"
            if s["lease"]: s["lease"]["deadline"] = self.clock+300
            else: s["lease"] = {"begin": self.clock, "deadline": self.clock+300, "maximum": self.clock+3600}
        else:
            raise AssertionError(action)
        self.advance(1)
        self.reviewed[role] = self.snapshot(role)

    def output(self, role, token):
        s = self.state[role]
        pending = "ABSENT" if s["lease"] is None else " ".join(["wgmvp-r1", BOOT, *map(str, s["lease"].values())])
        rollback = "ABSENT" if s["rolledback"] is None else " ".join(s["rolledback"])
        ns = ("present" if s["mode"] == "running" else "absent") if role == "gz" else "host"
        text = frame("summary", f"BOOT {BOOT}\nNOW {int(self.clock)}\npending {pending}\nrolledback {rollback}\n"
                     f"ACTIVE {s['active'] or 'ABSENT'}\nNAMESPACE {ns}")
        session = ""
        if token:
            saved = s["session"]
            session = f"SESSION wgmvp-r1 {BOOT} {saved['client']} {saved['server']} {role} {saved['began']}\n"
            session += "\n".join(f"PID {kind} 123 456 net:[123] {'live' if s['pids_live'] else 'gone'}"
                                 for kind in ("server.child", "server.wrapper"))
        text += frame("session", session)
        owned = {"nftables": []}
        if s["gate"]:
            owned["nftables"] = [{"set": {"name": "wgmvp_bench_gate", "comment": "wgmvp-r1:bench:"+s["active"],
                                 "timeout": 120, "flags": ["timeout"], "elem": [s["session"]["client"]]}},
                                 {"rule": {"comment": "wgmvp-r1:bench:"+s["active"]+":request-tcp"}}]
        socket = ""
        if s["pids_live"]:
            endpoint = "".join(f"{int(part):02X}" for part in check.benchmark.ADDRESSES[role].split(".")[::-1])+":CB70"
            socket = f"tcp {endpoint} 0A"
        text += frame("host_nft", json.dumps({"nftables": []} if role == "gz" else owned))
        text += frame("host_sockets", "" if role == "gz" else socket)
        if ns == "present":
            text += frame("namespace_nft", json.dumps(owned)) + frame("namespace_sockets", socket)
        return text

    def remote(self, role, body, label):
        if role not in self.roles: raise AssertionError("inactive role: "+role)
        self.events.append(("read", role, label))
        self.advance(1)
        output = "healthy"
        if label == "expiry-observe":
            token = None
            for line in body.splitlines():
                if line.startswith("requested="):
                    token = line.split("=", 1)[1].strip("'") or None
            output = self.output(role, token)
        if label == "expiry-stopped" and self.state[role]["mode"] != "stopped":
            return {"returncode": 1, "timeout": False, "stdout": "", "evidence_file": label+".json"}
        return {"returncode": 0, "timeout": False, "stdout": output, "evidence_file": label+".json"}


class ExpiryTests(unittest.TestCase):
    def fixture(self, directory, roles=wgmvp.ROLES, failure=None):
        launcher = Simulator(directory, roles, failure)
        checks = check.ExpiryChecks(launcher, roles, sleep=launcher.sleep, monotonic=lambda: launcher.clock)
        return launcher, checks

    def test_gz_four_cases_wait_real_deadlines_keep_other_hosts_and_restore(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            launcher, checks = self.fixture(directory)
            result = checks.run(("gz",))
        self.assertEqual(result["scope_status"], "PASS", result)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual([item["case"] for item in result["paths"]], list(check.CASES))
        self.assertTrue(all(item["restored"] for item in result["paths"]))
        self.assertTrue(all(state["mode"] == "running" for state in launcher.state.values()))
        self.assertIsNone(launcher.state["cave"]["rolledback"])
        self.assertIsNone(launcher.state["villa"]["rolledback"])
        mutations = [event for event in launcher.events if event[0] == "mutate"]
        self.assertEqual(sum(event[2] == "expiry-bench-close" for event in mutations), 1)
        abandoned = result["paths"][1]
        self.assertEqual(abandoned["kernel_only_runtime_observation"], "NOT_OBSERVED_WATCHER_ALREADY_CLEANED")
        lease = result["paths"][-1]
        self.assertTrue(lease["actual_lease_deadline_reached"])
        final_server = [event for event in mutations if event[2] == "expiry-bench-server"][-1]
        self.assertGreaterEqual(final_server[3], lease["lease"]["deadline"]-30)
        self.assertLess(final_server[3], lease["lease"]["deadline"])
        self.assertEqual(launcher.timeout, 90)
        self.assertFalse(any("kill " in event[4] or '> "$ROOT/state/pending"' in event[4] for event in mutations))

    def test_full_matrix_pass_requires_every_role_and_case(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            launcher, checks = self.fixture(directory)
            result = checks.run()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(len(result["paths"]), 12)
        self.assertEqual({p["role"] for p in result["paths"]}, set(wgmvp.ROLES))
        self.assertTrue(all(state["mode"] == "running" for state in launcher.state.values()))

    def test_partial_server_failure_closes_own_gate_and_stops_campaign(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            launcher, checks = self.fixture(directory, failure="server-start")
            result = checks.run(("gz",))
        self.assertEqual(result["scope_status"], "BLOCKED")
        self.assertEqual(len(result["paths"]), 1)
        self.assertTrue(result["paths"][0]["restored"])
        self.assertIsNone(launcher.state["gz"]["active"])
        self.assertTrue(any(event[:3] == ("mutate", "gz", "expiry-bench-close") for event in launcher.events))

    def test_unrelated_drift_after_autonomous_expiry_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            launcher, checks = self.fixture(directory, failure="foreign-drift")
            result = checks.run(("cave",), ("lease-expiry",))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["paths"][0]["restored"])
        self.assertFalse(any(event[0] == "remember" for event in launcher.events))
        self.assertIn("restore_error", result["paths"][0])

    def test_subset_never_calls_an_inactive_host(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            launcher, checks = self.fixture(directory, ("gz", "cave"))
            result = checks.run(("cave",), ("normal-close", "lease-expiry"))
        self.assertEqual(result["scope_status"], "PASS", result)
        self.assertNotIn("villa", [event[1] for event in launcher.events if event[0] in ("read", "mutate", "snapshot")])

    def test_failed_probe_cannot_mean_absent_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher, _ = self.fixture(directory)
            output = launcher.output("gz", None).replace("WGMVP_END namespace_nft 0", "WGMVP_END namespace_nft 1")
            with self.assertRaises(wgmvp.Blocked): check.parse_observation(output, "gz")
            missing = launcher.output("gz", None).split("WGMVP_BEGIN namespace_nft")[0]
            with self.assertRaises(wgmvp.Blocked): check.parse_observation(missing, "gz")

    def test_leftover_socket_marker_rule_or_live_pid_is_failure(self):
        clean = {"active": None, "bench_objects": [], "sockets": [], "pids": {"server.child": "gone"}}
        check.assert_clean(clean)
        for name, value in (("active", BOOT), ("bench_objects", [{"comment": "owned"}]),
                            ("sockets", [{"local": "00000000:CB70"}]), ("pids", {"server.child": "live"})):
            item = copy.deepcopy(clean); item[name] = value
            with self.subTest(name=name), self.assertRaises(check.Failed): check.assert_clean(item)

    def test_timeout_json_uses_seconds_and_binding_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher, checks = self.fixture(directory)
            observed = checks.open_server("gz")
        for defect in ("milliseconds", "wildcard-bind", "gone-pid"):
            data = copy.deepcopy(observed)
            if defect == "milliseconds": data["bench_objects"][0]["timeout"] = 120000
            elif defect == "wildcard-bind": data["sockets"][0]["local"] = "00000000:CB70"
            else: data["pids"]["server.child"] = "gone"
            with self.subTest(defect=defect), self.assertRaises(wgmvp.Blocked): check.assert_open(data, "gz")

    def test_observer_scripts_valid_shell_and_no_process_signals(self):
        for token in (None, BOOT):
            script = check.observation_script(token)
            result = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("kill ", script)
            self.assertNotIn("stat -c", script)
            self.assertIn("_bench_pid_matches", script)
            self.assertIn("_bench_lock", script)
        with self.assertRaises(wgmvp.Blocked): check.observation_script("../foreign")

    def test_dry_run_constructs_no_launcher(self):
        with patch.object(check.wgmvp, "Launcher") as launcher, redirect_stdout(io.StringIO()):
            self.assertEqual(check.main(["--targets", "gz"]), 0)
        launcher.assert_not_called()


if __name__ == "__main__": unittest.main()
