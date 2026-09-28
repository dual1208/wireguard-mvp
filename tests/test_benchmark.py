"""Finite benchmark policy/process boundaries; no live network commands."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "remote" / "benchmark.sh"
sys.path.insert(0, str(ROOT / "tools"))
import benchmark


class PolicyTests(unittest.TestCase):
    def shell(self, code, **env):
        return subprocess.run(["/bin/sh", "-c", f". {shlex.quote(str(SCRIPT))}\n{code}"],
                              env={**os.environ, **env}, text=True, capture_output=True, timeout=10)

    def render(self, role, client, server):
        own = benchmark.ADDRESSES[role]
        table = "wgmvp" if role == "gz" else "wgmvp_guard"
        result = self.shell(f"ROLE={role}; _bench_self={own}; _bench_client={client}; _bench_server={server}; "
                            f"_bench_mark=owned-token; _bench_port=52080; _bench_table={table}; _bench_policy")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_source_does_not_execute_or_write(self):
        result = self.shell(":", PATH="/nonexistent")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")

    def test_cross_hub_opens_forward_only_with_timeout_on_every_rule(self):
        lines = self.render("gz", "10.203.77.2", "10.203.77.3")
        self.assertIn("flags timeout; timeout 120s; size 1", lines[0])
        rules = [line for line in lines if line.startswith("add rule")]
        self.assertEqual(len(rules), 4)
        for line in rules:
            self.assertIn("bench_forward", line)
            self.assertIn('@wgmvp_bench_gate', line)
            self.assertIn('iifname "wgmvp" oifname "wgmvp"', line)
            self.assertNotIn("ct state", line)
        self.assertFalse(any("bench_input" in line or "bench_output" in line for line in rules))

    def test_router_client_rules_never_open_client_listen_port(self):
        lines = self.render("villa", "10.203.77.2", "10.203.77.3")
        project = [line for line in lines if line.startswith("add rule")]
        fw4 = [line for line in lines if line.startswith("insert rule")]
        self.assertEqual(len(project), 4)
        self.assertEqual(len(fw4), 4)
        for line in project + fw4:
            if 'ip saddr 10.203.77.2 ip daddr 10.203.77.3' in line:
                self.assertIn("dport 52080", line)
                self.assertIn('oifname "wgmvp"', line)
            else:
                self.assertIn('ip saddr 10.203.77.3 ip daddr 10.203.77.2', line)
                self.assertIn("sport 52080", line)
                self.assertIn('iifname "wgmvp"', line)
        self.assertTrue(all("@wgmvp_bench_gate" in line for line in project))

    def test_hub_endpoint_never_opens_forwarding(self):
        for client, server in (("10.203.77.1", "10.203.77.2"), ("10.203.77.3", "10.203.77.1")):
            lines = self.render("gz", client, server)
            rules = [line for line in lines if line.startswith("add rule")]
            self.assertEqual(sum("bench_input" in line for line in rules), 2)
            self.assertEqual(sum("bench_output" in line for line in rules), 2)
            self.assertFalse(any("bench_forward" in line for line in rules))

    def test_unowned_or_same_host_pair_is_rejected(self):
        for client, server in (("192.168.1.93", "10.203.77.2"), ("10.203.77.2", "10.203.77.2"),
                               ("10.203.77.1", "10.203.77.3")):
            result = self.shell("G=10.203.77.1; V=10.203.77.2; C=10.203.77.3; ROLE=villa; "
                                f"_bench_self=$V; _bench_client={client}; _bench_server={server}; _bench_pair_valid")
            self.assertNotEqual(result.returncode, 0)

    def test_cleanup_revokes_gate_before_processes_and_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "active").write_text("fixture")
            code = f"""
_bench_root={shlex.quote(directory)}; _bench_dir=$_bench_root; _bench_token=fixture
ROLE=villa; _bench_table=wgmvp_guard
_bench_load() {{ :; }}
_bench_table_owned() {{ :; }}
_bench_gate_owned() {{ :; }}
_bench_nft() {{ printf 'nft %s\\n' "$*" >> "$_bench_root/events"; }}
_bench_processes_stop() {{ printf 'processes\\n' >> "$_bench_root/events"; }}
_bench_delete_rules() {{ printf 'rules\\n' >> "$_bench_root/events"; }}
_bench_close_locked
"""
            result = self.shell(code)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = Path(directory, "events").read_text().splitlines()
            revoke = lines.index("nft flush set inet wgmvp_guard wgmvp_bench_gate")
            self.assertLess(revoke, lines.index("processes"))
            self.assertLess(lines.index("processes"), lines.index("rules"))
            self.assertFalse(Path(directory, "active").exists())

    def test_only_matching_registered_processes_receive_signals(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("valid.child", "reused.child", "unrelated.wrapper"):
                Path(directory, name).write_text("fixture")
            code = f"""
_bench_dir={shlex.quote(directory)}
_bench_pid_matches() {{ case "$1" in */valid.child) _bench_pid=12345;; *) return 1;; esac; }}
kill() {{ printf '%s\\n' "$*" >> "$_bench_dir/signals"; }}
sleep() {{ :; }}
_bench_processes_stop
"""
            result = self.shell(code)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(directory, "signals").read_text().splitlines(), ["-TERM 12345", "-KILL 12345"])

    def test_worker_registration_names_the_exec_process(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory, "iperf3")
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$$" > "$TEST_EXEC_PID"\n')
            fake.chmod(0o700)
            code = f"""
_bench_dir={shlex.quote(directory)}; _bench_self=10.203.77.1; _bench_server=$_bench_self; _bench_port=52080
_bench_load() {{ _bench_token=fixture; _bench_boot=boot; _bench_session_boot=boot; }}
_bench_namespace() {{ :; }}
_bench_record_pid() {{ printf '%s\\n' "$1" > "$_bench_dir/registered"; }}
_bench_worker fixture server
"""
            result = self.shell(code, PATH=f"{directory}:{os.environ['PATH']}", TEST_EXEC_PID=str(Path(directory, "exec-pid")))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(directory, "registered").read_text(), Path(directory, "exec-pid").read_text())

    def test_spawn_needs_no_nohup_and_releases_mutex_with_hup_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'sleep').symlink_to(shutil.which('sleep'))
            worker = folder / 'timeout'
            worker.write_text(
                '#!' + sys.executable + '\nimport os, pathlib, signal, sys, time\n'
                'assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN\n'
                'try: os.fstat(9)\n'
                'except OSError: pass\n'
                'else: raise RuntimeError("benchmark mutex leaked")\n'
                f'root = pathlib.Path({directory!r})\n'
                '(root / "args").write_text("\\n".join(sys.argv[1:]))\n'
                '(root / "server.child").write_text(str(os.getpid()))\n'
                'time.sleep(1.5)\n')
            worker.chmod(0o700)
            code = f'''
_bench_dir={shlex.quote(directory)}; _bench_token=fixture; ROLE=villa; ROOT=/etc/wgmvp
_bench_record_pid() {{ printf '%s\\n' "$1" > "$2"; }}
exec 9>"$_bench_dir/mutex"
_bench_spawn server || exit 1
kill -HUP "$_bench_spawned"
wait "$_bench_spawned"
'''
            result = self.shell(code, PATH=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((folder / 'args').read_text().splitlines(),
                             ['-s', 'TERM', '-k', '2', '45', '/etc/wgmvp/benchmark.sh', '_worker', 'fixture', 'server'])
            self.assertEqual((folder / 'server.wrapper').read_text().strip(), (folder / 'server.child').read_text())

    def test_df_worker_uses_only_current_mtu_fixed_rate_and_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory, "iperf3")
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_ARGS"\n')
            fake.chmod(0o700)
            code = f'''
_bench_dir={shlex.quote(directory)}; _bench_self=10.203.77.3; _bench_client=$_bench_self; _bench_server=10.203.77.1; _bench_port=52080
MTU=1380
_bench_load() {{ _bench_token=fixture; _bench_boot=boot; _bench_session_boot=boot; }}
_bench_namespace() {{ :; }}
_bench_record_pid() {{ :; }}
cat() {{ [ "$1" = /sys/class/net/wgmvp/mtu ] && printf '%s\\n' "$LIVE_MTU"; }}
_bench_worker fixture client udp-df 1
'''
            env = {"PATH": f"{directory}:{os.environ['PATH']}", "TEST_ARGS": str(Path(directory, "args")), "LIVE_MTU": "1380"}
            result = self.shell(code, **env)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = Path(directory, "args").read_text().splitlines()
            self.assertIn("--dont-fragment", args)
            self.assertEqual(args[args.index("-l") + 1], "1352")
            self.assertEqual(args[args.index("-b") + 1], "1M")
            self.assertEqual(args[args.index("-t") + 1], "10")
            Path(directory, "args").unlink()
            result = self.shell(code, **{**env, "LIVE_MTU": "1420"})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(Path(directory, "args").exists())

    def test_no_router_stat_dependency_or_broad_firewall_flush(self):
        source = SCRIPT.read_text()
        self.assertNotIn("stat -", source)
        self.assertNotIn("flush ruleset", source)
        self.assertNotIn("flush chain", source)
        self.assertIn("readlink", source)


class MeasurementTests(unittest.TestCase):
    def test_plan_is_finite_and_covers_six_directions(self):
        jobs = benchmark.scenarios()
        self.assertEqual(len(jobs), 24)
        self.assertEqual({(item.client, item.server) for item in jobs}, set(benchmark.PAIRS))
        self.assertEqual(sum(item.protocol == "tcp" for item in jobs), 16)
        self.assertEqual(sum(item.protocol == "udp" for item in jobs), 8)
        self.assertEqual(len(benchmark.scenarios("per-leg")), 4)
        self.assertEqual(len(benchmark.scenarios("cross-tcp")), 12)
        self.assertEqual(len(benchmark.scenarios("cross-udp")), 8)
        for bad in (0, -1, 1000):
            with self.assertRaises(ValueError):
                benchmark.Scenario("villa", "cave", "udp", bad)

    def test_suite_renews_only_measured_cleaned_runs_and_stops_udp_on_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = SimpleNamespace(run_dir=Path(directory), operation_deadline=None)
            events = []
            jobs = benchmark.scenarios("cross-udp")[:4]
            result = {"status": "MEASURED", "scenario": {}, "measurement": {"loss_percent": 1.1},
                      "cleanup": {role: "removed" for role in jobs[0].participants}}
            with patch.object(benchmark, "run_one", return_value=result) as one, patch.object(benchmark, "json_write"):
                results = benchmark.run_suite(launcher, lambda: events.append("gate"), jobs,
                                              after_measured=lambda: events.append("renew"))
            self.assertEqual(one.call_count, 1)
            self.assertEqual(events, ["gate", "renew"])
            self.assertEqual([item["status"] for item in results], ["MEASURED", "NOT_RUN", "NOT_RUN", "NOT_RUN"])

    def test_suite_stops_without_renewal_on_cleanup_failure_or_low_time(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = SimpleNamespace(run_dir=Path(directory), operation_deadline=None)
            with patch.object(benchmark, "run_one", return_value={"status": "BLOCKED"}) as one, \
                 patch.object(benchmark, "json_write"):
                renew = Mock()
                benchmark.run_suite(launcher, lambda: None, benchmark.scenarios("per-leg"), after_measured=renew)
                self.assertEqual(one.call_count, 1)
                renew.assert_not_called()
            launcher.operation_deadline = time.monotonic() + 179
            with patch.object(benchmark, "run_one") as one, patch.object(benchmark, "json_write"):
                results = benchmark.run_suite(launcher, lambda: None)
                one.assert_not_called()
                self.assertEqual(results[0]["status"], "BLOCKED")

    def test_receiver_goodput_and_loss_are_not_sender_offer(self):
        client = {"end": {"sum_sent": {"bits_per_second": 20000000}}}
        server = {"end": {"sum": {"bits_per_second": 15000000, "seconds": 10, "bytes": 18750000,
                                    "lost_percent": 2.5, "jitter_ms": 0.3, "packets": 10000}}}
        result = benchmark.measurement(client, server, "udp")
        self.assertEqual(result["receiver_mbps"], 15)
        self.assertEqual(result["loss_percent"], 2.5)
        with self.assertRaises(benchmark.Blocked):
            benchmark.measurement(client, {}, "udp")

    def test_latency_distinguishes_quantiles_from_mean_and_censored_samples(self):
        text = "\n".join(f"time={value} ms" for value in (1, 2, 3, 100)) + "\n4 packets transmitted, 4 packets received"
        result = benchmark.latency(text)
        self.assertEqual(result["median_ms"], 2.5)
        self.assertEqual(result["p95_ms"], 100)
        censored = benchmark.latency("time<1 ms\ntime=2 ms")
        self.assertNotIn("median_ms", censored)
        self.assertEqual(censored["censored_samples"], 1)


if __name__ == "__main__":
    unittest.main()
