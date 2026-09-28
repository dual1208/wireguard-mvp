"""Offline lease tests. Fake roles and clocks never change host networking.

On macOS a test copy substitutes process liveness for Linux /proc start times,
and a small fcntl wrapper provides the same inherited-descriptor lock interface.
The production /proc parser is tested separately against a fixture.
"""
from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "remote" / "controller.sh"
BOOT = "11111111-1111-1111-1111-111111111111"


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text(BOOT + "\n")
        (self.proc / "uptime").write_text("1000.00 2000.00\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        timeout = shutil.which("timeout") or shutil.which("gtimeout")
        if not timeout:
            self.skipTest("A local timeout implementation is required")
        (self.bin / "timeout").symlink_to(timeout)
        (self.bin / "flock").write_text(
            "#!/usr/bin/env python3\n"
            "import fcntl, sys, time\n"
            "fd=int(sys.argv[-1]); end=time.monotonic()+45\n"
            "while True:\n"
            " try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); break\n"
            " except BlockingIOError:\n"
            "  if '-n' in sys.argv: sys.exit(1)\n"
            "  if time.monotonic() >= end: sys.exit(1)\n"
            "  time.sleep(.02)\n"
        )
        (self.bin / "flock").chmod(0o700)
        source = SOURCE.read_text()
        source = source.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH='{self.bin}':{os.environ['PATH']}")
        source = source.replace("BOOT=$(boot)\n", "process_start() { kill -0 \"$1\" 2>/dev/null || return 1; printf '1\\n'; }\nBOOT=$(boot)\n")
        self.control = self.root / "controller.sh"
        self.control.write_text(source)
        self.control.chmod(0o700)
        (self.root / "config.env").write_text("OWNER=wgmvp-r1\nROLE=gz\n")
        (self.root / "hub.sh").write_text(
            "hub_start() {\n"
            " mkdir \"$ROOT/role-active\" || return 90\n"
            " printf 'start-begin\\n' >> \"$ROOT/events\"\n"
            " [ ! -f \"$ROOT/slow\" ] || sleep 2\n"
            " rmdir \"$ROOT/role-active\"\n"
            " printf 'start-end\\n' >> \"$ROOT/events\"\n"
            "}\n"
            "hub_stop() {\n"
            " [ ! -d \"$ROOT/role-active\" ] || return 91\n"
            " printf 'stop\\n' >> \"$ROOT/events\"\n"
            "}\n"
            "hub_status() { printf 'ROLE fake\\n'; }\n"
        )
        self.env = dict(os.environ, WGMVP_ROOT=str(self.root), WGMVP_PROC_ROOT=str(self.proc))
        self.watchers: list[subprocess.Popen] = []
        self.log = (self.root / "watch.log").open("w+")

    def tearDown(self):
        for process in self.watchers:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        self.log.close()
        self.tmp.cleanup()

    def call(self, action, *, ok=True):
        result = subprocess.run([str(self.control), action], env=self.env, capture_output=True, text=True, timeout=12)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr + self.logs())
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def logs(self):
        self.log.flush()
        return (self.root / "watch.log").read_text()

    def watch(self):
        process = subprocess.Popen([str(self.control), "watch"], env=self.env, stdout=self.log, stderr=self.log, start_new_session=True)
        self.watchers.append(process)
        limit = time.monotonic() + 5
        marker = self.root / "state/watch"
        while time.monotonic() < limit:
            if marker.exists() and marker.read_text().splitlines()[2] == str(process.pid):
                return process
            if process.poll() is not None:
                self.fail(self.logs())
            time.sleep(.02)
        self.fail("watch did not become ready: " + self.logs())

    def kill_watch(self, process):
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)

    def clock(self, value):
        temp = self.proc / "uptime.next"
        temp.write_text(f"{value}.00 2000.00\n")
        temp.replace(self.proc / "uptime")
        marker = self.root / "state/watch"
        if marker.exists():
            parts = marker.read_text().splitlines()
            parts[4] = str(value)
            temp = self.root / "state/watch.next"
            temp.write_text("\n".join(parts) + "\n")
            temp.replace(marker)

    def events(self):
        path = self.root / "events"
        return path.read_text().splitlines() if path.exists() else []

    def test_arm_requires_live_watch(self):
        self.call("arm", ok=False)
        self.assertFalse((self.root / "state/pending").exists())

    def test_status_does_not_create_state(self):
        self.call("status")
        self.assertFalse((self.root / "state").exists())

    def test_arm_start_renew_commit(self):
        self.watch()
        self.call("arm")
        self.assertEqual((self.root / "state/pending").read_text().splitlines()[2:], ["1000", "1300", "4600"])
        self.call("start")
        self.clock(1200)
        self.call("renew")
        self.assertEqual((self.root / "state/pending").read_text().splitlines()[3:], ["1500", "4600"])
        self.call("commit")
        self.assertFalse((self.root / "state/pending").exists())
        self.assertTrue((self.root / "state/committed").exists())

    def test_expired_lease_cannot_be_renewed(self):
        self.watch()
        self.call("arm")
        self.clock(1300)
        self.call("renew", ok=False)
        self.assertIn("stop", self.events())
        self.assertFalse((self.root / "state/pending").exists())

    def test_start_requires_time_to_finish_within_lease(self):
        self.watch()
        self.call("arm")
        self.clock(1260)
        self.call("start", ok=False)
        self.assertEqual(self.events(), [])

    def test_watch_automatically_stops_expired_pending_revision(self):
        self.watch()
        self.call("arm")
        self.call("start")
        self.clock(1300)
        limit = time.monotonic() + 6
        while (self.root / "state/pending").exists() and time.monotonic() < limit:
            time.sleep(.03)
        self.assertFalse((self.root / "state/pending").exists(), self.logs())
        self.assertEqual(self.events()[-1], "stop")

    def test_malformed_pending_stops_role_and_preserves_evidence(self):
        self.watch()
        self.call("arm")
        self.call("start")
        marker = self.root / "state/pending"
        marker.write_text("wgmvp-r1\n" + BOOT + "\nbad-clock\n1300\n4600\n")
        self.call("reconcile", ok=False)
        self.assertEqual(self.events()[-1], "stop")
        self.assertTrue(marker.exists())

    def test_boot_change_rolls_back(self):
        watcher = self.watch()
        self.call("arm")
        self.call("start")
        self.kill_watch(watcher)
        (self.proc / "sys/kernel/random/boot_id").write_text("22222222-2222-2222-2222-222222222222\n")
        self.call("reconcile")
        self.assertEqual(self.events()[-1], "stop")
        self.assertTrue((self.root / "state/rolledback").exists())

    def test_pending_restart_does_not_autostart_old_commit(self):
        watcher = self.watch()
        self.call("arm")
        self.call("commit")
        self.call("arm")
        self.kill_watch(watcher)
        self.watch()
        self.assertEqual(self.events(), [])

    def test_commit_starts_on_service_restart(self):
        watcher = self.watch()
        self.call("arm")
        self.call("commit")
        self.kill_watch(watcher)
        self.watch()
        limit = time.monotonic() + 3
        while "start-end" not in self.events() and time.monotonic() < limit:
            time.sleep(.02)
        self.assertEqual(self.events(), ["start-begin", "start-end"])

    def test_renewal_never_extends_maximum(self):
        self.watch()
        self.call("arm")
        for value in range(1200, 4600, 200):
            self.clock(value)
            self.call("renew")
        self.clock(4599)
        self.call("renew")
        self.assertEqual((self.root / "state/pending").read_text().splitlines()[3:], ["4600", "4600"])
        self.clock(4600)
        self.call("renew", ok=False)

    def test_foreign_lock_metadata_is_not_adopted(self):
        lock = self.root / "state/lock"
        lock.mkdir(parents=True)
        (lock / "identity").write_text("foreign\n" + BOOT + "\n99999999\n1\n")
        self.call("reconcile", ok=False)
        self.assertTrue((lock / "identity").exists())

    def test_two_contenders_reclaim_dead_owner_safely(self):
        lock = self.root / "state/lock"
        lock.mkdir(parents=True)
        (lock / "identity").write_text("wgmvp-r1\n" + BOOT + "\n99999999\n1\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.call("stop"), range(6)))
        self.assertEqual(len(results), 6)
        self.assertEqual(self.events(), ["stop"] * 6)
        self.assertFalse(lock.exists())

    def test_interrupted_empty_mkdir_is_recovered_under_kernel_lock(self):
        lock = self.root / "state/lock"
        lock.mkdir(parents=True)
        self.call("stop")
        self.assertEqual(self.events(), ["stop"])
        self.assertFalse(lock.exists())

    def test_role_child_keeps_lock_when_parent_is_killed(self):
        self.watch()
        self.call("arm")
        (self.root / "slow").touch()
        parent = subprocess.Popen([str(self.control), "start"], env=self.env, stdout=self.log, stderr=self.log)
        limit = time.monotonic() + 3
        while "start-begin" not in self.events() and time.monotonic() < limit:
            time.sleep(.02)
        self.assertIn("start-begin", self.events())
        parent.kill()
        parent.wait()
        self.call("rollback")
        self.assertEqual(self.events(), ["start-begin", "start-end", "stop"])

    def failed_auxiliary(self):
        # A bare failure followed by success reproduces conditional-shell
        # errexit suppression; the trailing event must never execute.
        (self.root / "unknown-key.sh").write_text(
            'unknown_cleanup_locked() {\n'
            ' printf "cleanup-begin\\n" >> "$ROOT/events"\n'
            ' false\n'
            ' printf "cleanup-incorrectly-continued\\n" >> "$ROOT/events"\n'
            '}\n'
        )

    def test_failed_auxiliary_cleanup_still_stops_expired_role(self):
        watcher = self.watch()
        self.call("arm")
        self.call("start")
        self.kill_watch(watcher)
        pending = self.root / "state/pending"
        evidence = pending.read_text()
        self.failed_auxiliary()
        self.clock(1300)
        result = self.call("reconcile", ok=False)
        self.assertEqual(self.events(), ["start-begin", "start-end", "cleanup-begin", "stop"])
        self.assertEqual(pending.read_text(), evidence)
        self.assertFalse((self.root / "state/rolledback").exists())
        self.assertIn("auxiliary cleanup failed", result.stderr)

    def test_failed_auxiliary_cleanup_prevents_start_and_preserves_pending(self):
        self.watch()
        self.call("arm")
        pending = self.root / "state/pending"
        evidence = pending.read_text()
        self.failed_auxiliary()
        self.call("start", ok=False)
        # Failed activation itself invokes rollback, which must still stop.
        self.assertEqual(self.events(), ["cleanup-begin", "cleanup-begin", "stop"])
        self.assertEqual(pending.read_text(), evidence)
        self.assertFalse((self.root / "state/committed").exists())

    def test_fresh_auxiliary_shell_inherits_source_context_and_kernel_lock(self):
        (self.root / "unknown-key.sh").write_text(
            '[ "${WGMVP_UNKNOWN_SOURCE_ONLY:-}" = 1 ] || exit 81\n'
            'unknown_cleanup_locked() {\n'
            ' [ "$ROLE" = gz ] && [ "$OWNER" = wgmvp-r1 ]\n'
            ' [ -n "$WGMVP_LOCK_TOKEN" ]\n'
            ' [ "$(cat "$ROOT/state/lock/identity")" = "$WGMVP_LOCK_TOKEN" ]\n'
            ' flock -x -n 9\n'
            ' exec 8>"$ROOT/state/mutex"\n'
            ' if flock -x -n 8; then printf "cleanup-lock-lost\\n" >> "$ROOT/events"; return 82; fi\n'
            ' exec 8>&-\n'
            ' printf "cleanup-lock-held\\n" >> "$ROOT/events"\n'
            '}\n'
        )
        self.call("stop")
        self.assertEqual(self.events(), ["cleanup-lock-held", "stop"])
        self.assertFalse((self.root / "state/lock").exists())

    def test_original_proc_parser_handles_parentheses_and_zombies(self):
        source = SOURCE.read_text()
        funcs = source[source.index("uint() {"):source.index("alive() {")]
        directory = self.proc / "123"
        directory.mkdir()
        fields = ["S"] + ["0"] * 18 + ["98765"]
        (directory / "stat").write_text("123 (strange ) process) " + " ".join(fields) + "\n")
        result = subprocess.run(["sh", "-c", funcs + '\nprocess_start 123'], env=dict(os.environ, PROC=str(self.proc)), capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "98765")
        fields[0] = "Z"
        (directory / "stat").write_text("123 (zombie) " + " ".join(fields) + "\n")
        result = subprocess.run(["sh", "-c", funcs + '\nprocess_start 123'], env=dict(os.environ, PROC=str(self.proc)), capture_output=True, text=True)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
