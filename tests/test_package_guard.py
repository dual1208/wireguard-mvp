"""Local-only package lease tests: fake rollback actions, real inherited flock."""
from __future__ import annotations
import os
from pathlib import Path
import signal
import subprocess
import time
import unittest
import test_controller as controller_helpers
BOOT = controller_helpers.BOOT

SOURCE = Path(__file__).resolve().parents[1] / "remote/package-guard.sh"

class PackageGuardTests(unittest.TestCase):
    tearDown = controller_helpers.ControllerTests.tearDown
    call = controller_helpers.ControllerTests.call
    logs = controller_helpers.ControllerTests.logs
    kill_watch = controller_helpers.ControllerTests.kill_watch
    # Reuse fixtures only, not the controller test cases below.
    def setUp(self):
        controller_helpers.ControllerTests.setUp(self)
        self.state = self.root / "package-state"
        self.state.mkdir(mode=0o700)
        self.pkglock = self.root / "bootstrap.lock"
        (self.state / "role.env").write_text("OWNER=wgmvp-packages-r1\nMANAGER=apt\n")
        (self.state / "baseline.txt").write_text("existing-package\n")
        (self.state / "baseline.ready").write_text("wgmvp-packages-r1\n")
        (self.state / "new-packages.txt").write_text("new-package\n")
        (self.state / "proposed.txt").write_text("new-package\n")
        (self.state / "rollback.sh").write_text("#!/bin/sh\nset -eu\ncase $1 in\nplan) cat \"$WGMVP_PACKAGE_STATE/proposed.txt\";;\napply) cat \"$2\" >> \"$WGMVP_PACKAGE_STATE/applied.txt\";;\nesac\n")
        (self.state / "rollback.sh").chmod(0o700)
        source = SOURCE.read_text()
        source = source.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH='{self.bin}':{os.environ['PATH']}")
        source = source.replace('secure "$STATE"\n', 'secure() { [ -e "$1" ]; }\nsecure "$STATE"\n', 1)
        source = source.replace('START=$(process_start $$)', 'process_start() { kill -0 "$1" 2>/dev/null || return 1; printf \'1\\n\'; }\nSTART=$(process_start $$)')
        source = source.replace('[ "$PROC/$$/fd/9" -ef "$LOCK" ]', "python3 -c 'import os,sys; a=os.fstat(9); b=os.stat(sys.argv[1]); sys.exit((a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino))' \"$LOCK\"")
        self.control = self.state / "package-guard.sh"
        self.control.write_text(source)
        self.control.chmod(0o700)
        self.env.update(WGMVP_PACKAGE_STATE=str(self.state), WGMVP_PACKAGE_LOCK=str(self.pkglock))

    def watch(self):
        process = subprocess.Popen([str(self.control), "watch"], env=self.env, stdout=self.log, stderr=self.log, start_new_session=True)
        self.watchers.append(process)
        limit = time.monotonic() + 4
        while time.monotonic() < limit:
            marker = self.state / "watch"
            if marker.exists() and marker.read_text().splitlines()[2] == str(process.pid):
                return process
            if process.poll() is not None:
                self.fail(self.logs())
            time.sleep(.02)
        self.fail(self.logs())

    def clock(self, value):
        (self.proc / "uptime").write_text(f"{value}.00 1000.00\n")
        marker = self.state / "watch"
        if marker.exists():
            data = marker.read_text().splitlines(); data[4] = str(value)
            marker.write_text("\n".join(data) + "\n")

    def test_package_guard_requires_watcher(self):
        self.call("arm", ok=False)

    def test_package_commit_clears_pending(self):
        self.watch(); self.call("arm"); self.call("check"); self.call("commit")
        self.assertFalse((self.state / "pending").exists())
        self.assertFalse((self.state / "applied.txt").exists())

    def test_package_expiry_automatically_rolls_back(self):
        self.watch(); self.call("arm"); self.clock(1300)
        limit = time.monotonic() + 6
        while (self.state / "pending").exists() and time.monotonic() < limit: time.sleep(.03)
        self.assertFalse((self.state / "pending").exists(), self.logs())
        self.assertEqual((self.state / "applied.txt").read_text(), "new-package\n")

    def test_package_boot_change_rolls_back_on_service_start(self):
        process = self.watch(); self.call("arm"); self.kill_watch(process)
        (self.proc / "sys/kernel/random/boot_id").write_text("22222222-2222-2222-2222-222222222222\n")
        self.watch()
        limit = time.monotonic() + 4
        while (self.state / "pending").exists() and time.monotonic() < limit: time.sleep(.03)
        self.assertFalse((self.state / "pending").exists(), self.logs())

    def test_package_baseline_removal_is_rejected(self):
        self.watch(); self.call("arm")
        (self.state / "proposed.txt").write_text("existing-package\n")
        self.call("rollback", ok=False)
        self.assertFalse((self.state / "applied.txt").exists())
        self.assertTrue((self.state / "pending").exists())

    def test_package_expiry_waits_for_installer_lock(self):
        self.watch(); self.call("arm")
        command = f'exec 9>"{self.pkglock}"; "{self.bin}/flock" -x 9; touch "{self.state}/installer-held"; sleep 4'
        installer = subprocess.Popen(["sh", "-c", command], env=self.env)
        limit = time.monotonic() + 3
        while not (self.state / "installer-held").exists() and time.monotonic() < limit: time.sleep(.02)
        self.clock(1300)
        time.sleep(1)
        self.assertFalse((self.state / "applied.txt").exists())
        installer.wait(timeout=5)
        limit = time.monotonic() + 6
        while (self.state / "pending").exists() and time.monotonic() < limit: time.sleep(.03)
        self.assertFalse((self.state / "pending").exists(), self.logs())

    def test_package_commit_accepts_correct_inherited_lock(self):
        self.watch(); self.call("arm")
        command = f'exec 9>"{self.pkglock}"; "{self.bin}/flock" -x 9; WGMVP_PACKAGE_LOCK_FD=9 "{self.control}" commit'
        result = subprocess.run(["sh", "-c", command], env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "pending").exists())

if __name__ == "__main__": unittest.main()
