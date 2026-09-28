"""Launcher boundary tests. No SSH, remote writes or live network testing."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import wgmvp
import check_inventory


def sample(role="gz", installed="no"):
    result = {"files": {name: "a" * 64 for name in wgmvp.IDENTITY_FILES[role]},
              "network_sha256": "b" * 64, "installed": installed}
    if role != "gz":
        result["unrelated_config_sha256"] = "c" * 64
    return result


class LauncherTests(unittest.TestCase):
    def test_preparation_only_defers_rollback_readiness(self):
        inventory = json.loads((ROOT / "inventory.example.json").read_text())
        ordinary = check_inventory.validate(inventory)
        preparing = check_inventory.validate(inventory, prepare=True)
        self.assertIn("checks.rollback_ready is not verified", ordinary)
        self.assertNotIn("checks.rollback_ready is not verified", preparing)
        self.assertEqual(set(ordinary) - set(preparing), {"checks.rollback_ready is not verified"})
        self.assertIn("checks.rollback_ready is not verified", check_inventory.validate(inventory, prepare=True, final=True))

    def test_snapshot_roundtrip_and_strictness(self):
        for role in wgmvp.ROLES:
            value = sample(role)
            text = wgmvp.snapshot_text(value, role)
            self.assertEqual(wgmvp.parse_snapshot(text, role), value)
            for bad in (text + "\nNETWORK\t" + "f" * 64,
                        text.replace("a" * 64, "bad", 1),
                        "NETWORK\t" + "a" * 64,
                        text + "\nPRIVATE\tshould-not-appear"):
                with self.assertRaises(wgmvp.Blocked):
                    wgmvp.parse_snapshot(bad, role)

    def test_hashing_never_outputs_raw_key_or_configuration(self):
        script = wgmvp.snapshot_function("villa")
        self.assertIn('hash=$(sha256sum "$file")', script)
        self.assertNotIn('cat "$file"', script)
        self.assertNotIn("showconf", script)
        self.assertNotIn("wg show", script)
        self.assertIn('printf \'NETWORK\\t%s\\n\'', script)
        self.assertIn('nft -s list ruleset', script)

    def test_payload_is_literal_and_does_not_execute_metacharacters(self):
        content = 'echo "$HOME"\n$(touch ESCAPED)\n`touch ESCAPED2`\n\n'
        with tempfile.TemporaryDirectory() as directory:
            payload = wgmvp.payload_function({"fixture.sh": content})
            script = payload + '\nSTAGE="$1"\nwrite_payload\n'
            result = subprocess.run(["/bin/sh", "-c", script, "test", directory],
                                    cwd=directory, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(directory, "fixture.sh").read_text(), content)
            self.assertFalse(Path(directory, "ESCAPED").exists())
            self.assertFalse(Path(directory, "ESCAPED2").exists())

    def test_payload_rejects_private_keys_paths_and_injection(self):
        for name in ("private.key", "../config.env", "/etc/config/network", "x;touch-pwn", "x/y"):
            with self.subTest(name=name), self.assertRaises(wgmvp.Blocked):
                wgmvp.payload_function({name: "data"})

    def test_default_mutations_never_connect(self):
        with patch.object(wgmvp.discover, "run_bounded") as remote:
            for action in wgmvp.MUTATIONS:
                output = io.StringIO()
                with redirect_stdout(output):
                    result = wgmvp.main([action, "--inventory", str(ROOT / "inventory.example.json")])
                self.assertEqual(result, 2)
                self.assertIn("DRY_RUN", output.getvalue())
            remote.assert_not_called()

    def test_immutable_identity_is_checked_after_project_config_changes(self):
        snapshot = sample("villa", "yes")
        inventory = {"identities": {"villa": dict(snapshot["files"])}}
        snapshot["files"]["/etc/config/network"] = "c" * 64
        self.assertEqual(wgmvp.identity_errors(inventory, "villa", snapshot, initial=False), [])
        self.assertTrue(wgmvp.identity_errors(inventory, "villa", snapshot, initial=True))
        snapshot["files"]["/etc/dropbear/dropbear_ed25519_host_key"] = "d" * 64
        self.assertTrue(wgmvp.identity_errors(inventory, "villa", snapshot, initial=False))

    def test_unknown_live_snapshot_cannot_be_promoted_by_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = sample()
            inventory = {"reviewed_snapshots": {"gz": expected},
                         "identities": {"gz": expected["files"]}}
            launcher = wgmvp.Launcher(inventory, Path(directory))
            changed = {**expected, "network_sha256": "c" * 64}
            with patch.object(launcher, "observe", return_value=changed):
                with self.assertRaises(wgmvp.Blocked):
                    launcher.preflight("gz")
            self.assertFalse((Path(directory) / "state" / "gz.json").exists())

    def test_local_coordinator_rejects_second_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            with wgmvp.coordinator_lock(Path(directory)):
                with self.assertRaises(wgmvp.Blocked):
                    with wgmvp.coordinator_lock(Path(directory)):
                        self.fail("second coordinator entered")

    def test_candidate_refresh_never_writes_approved_state(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = {"identities": {role: sample(role)["files"] for role in wgmvp.ROLES}}
            launcher = wgmvp.Launcher(inventory, Path(directory))
            with patch.object(launcher, "observe", side_effect=lambda role: sample(role)), redirect_stdout(io.StringIO()):
                launcher.refresh()
            self.assertEqual(list((Path(directory) / "state").iterdir()), [])
            recorded = json.loads((launcher.run_dir / "candidate-snapshots.json").read_text())
            self.assertEqual(recorded["kind"], "UNAPPROVED_CANDIDATES")

    def test_status_has_no_controller_lock_mutation(self):
        for role in wgmvp.ROLES:
            script = wgmvp.status_script(role)
            self.assertNotIn("controller.sh", script)
            self.assertNotIn("mkdir", script)
            self.assertNotIn("wg showconf", script)

    def test_partial_apply_never_mutates_or_renews_omitted_villa(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            mutations, reads = [], []
            keys = {role: character * 43 + '=' for role, character in zip(wgmvp.ROLES, 'ABC')}
            def remote(role, body, label):
                reads.append((role, body, label))
                if role == 'villa':
                    self.assertEqual(label, 'public-key')
                    self.assertEqual(body, 'cat /etc/wgmvp/public.villa\n')
                return {'returncode': 0, 'timeout': False,
                        'stdout': keys[role] if label == 'public-key' else 'healthy'}
            def mutate(role, body, action, delta, **kwargs):
                self.assertIn(role, ('gz', 'cave'))
                mutations.append((role, action))
            with patch('render.role_files', return_value={'fixture.sh': ':\n'}) as rendered, \
                 patch.object(launcher, 'preflight') as preflight, \
                 patch.object(launcher, 'remote', side_effect=remote), \
                 patch.object(launcher, 'mutate', side_effect=mutate), \
                 patch.object(launcher, 'verify') as verify, redirect_stdout(io.StringIO()):
                # Unsorted selection still uses hub-before-router dependency order.
                launcher.apply(targets=('cave', 'gz'))
            self.assertEqual([call.args[1] for call in rendered.call_args_list], ['gz', 'cave'])
            self.assertEqual([call.args[0] for call in preflight.call_args_list], ['gz', 'cave'])
            self.assertEqual(mutations, [('gz', 'bootstrap'), ('cave', 'bootstrap'),
                                         ('gz', 'public-peers'), ('cave', 'public-peers'),
                                         ('gz', 'arm'), ('gz', 'start'), ('cave', 'arm'),
                                         ('cave', 'start'), ('gz', 'renew')])
            self.assertEqual(len([call for call in reads if call[0] == 'villa']), 1)
            verify.assert_not_called()

    def test_partial_prepare_touches_only_selected_host_and_no_public_key_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            with patch('render.role_files', return_value={'fixture.sh': ':\n'}), \
                 patch.object(launcher, 'preflight') as preflight, \
                 patch.object(launcher, 'remote') as remote, \
                 patch.object(launcher, 'mutate') as mutate, \
                 patch.object(launcher, 'verify') as verify, redirect_stdout(io.StringIO()):
                launcher.apply(prepare_only=True, targets=('cave',))
            self.assertEqual([call.args[0] for call in preflight.call_args_list], ['cave'])
            self.assertEqual([(call.args[0], call.args[2]) for call in mutate.call_args_list], [('cave', 'bootstrap')])
            remote.assert_not_called()
            verify.assert_not_called()

    def test_invalid_apply_targets_fail_before_remote_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            with patch.object(launcher, 'remote') as remote, patch.object(launcher, 'mutate') as mutate:
                for targets in ((), ('gz', 'gz'), ('unknown',)):
                    with self.subTest(targets=targets), self.assertRaises(wgmvp.Blocked):
                        launcher.apply(targets=targets)
            remote.assert_not_called()
            mutate.assert_not_called()

    def test_security_gate_missing_or_incomplete_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            with patch.object(launcher, "remote") as remote, patch.object(launcher, "mutate") as mutate:
                with self.assertRaises(wgmvp.Blocked):
                    launcher.benchmark("per-leg")
                gate = {"owner": "wgmvp-r1", "tests": {test: "PASS" for test in wgmvp.SECURITY_GATE_IDS}}
                gate["tests"]["S09"] = "BLOCKED"
                wgmvp.json_write(Path(directory) / "security-gate.json", gate)
                with self.assertRaises(wgmvp.Blocked):
                    launcher.benchmark("per-leg")
                remote.assert_not_called()
                mutate.assert_not_called()

    def test_security_gate_must_equal_reviewed_and_fresh_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshots = {role: sample(role, "yes") for role in wgmvp.ROLES}
            inventory = {"reviewed_snapshots": snapshots,
                         "identities": {role: snapshots[role]["files"] for role in wgmvp.ROLES}}
            launcher = wgmvp.Launcher(inventory, Path(directory))
            gate = {"owner": "wgmvp-r1", "tests": {test: "PASS" for test in wgmvp.SECURITY_GATE_IDS},
                    "snapshots": snapshots}
            path = Path(directory) / "security-gate.json"
            wgmvp.json_write(path, gate)
            accepted = launcher.load_security_gate()
            with patch.object(launcher, "observe", side_effect=lambda role: sample(role, "yes")):
                launcher.benchmark_gate_current(accepted)
            with patch.object(launcher, "observe", return_value={**sample("gz", "yes"), "network_sha256": "f" * 64}):
                with self.assertRaises(wgmvp.Blocked):
                    launcher.benchmark_gate_current(accepted)
            gate["snapshots"]["gz"] = {**sample("gz", "yes"), "network_sha256": "f" * 64}
            wgmvp.json_write(path, gate, replace=True)
            with patch.object(launcher, "expected", side_effect=lambda role: sample(role, "yes")), self.assertRaises(wgmvp.Blocked):
                launcher.load_security_gate()

    def test_benchmark_health_requires_exact_three_deliveries(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            responses = [{"returncode": 0, "timeout": False, "stdout": "healthy"}] * 3
            responses.append({"returncode": 0, "timeout": False,
                              "stdout": "3 packets transmitted, 2 packets received, 0% packet loss"})
            with patch.object(launcher, "benchmark_gate_current"), patch.object(launcher, "remote", side_effect=responses), \
                 patch.object(launcher, "recovery") as recovery:
                with self.assertRaises(wgmvp.Blocked):
                    launcher.benchmark_health({})
                recovery.assert_not_called()

    def test_benchmark_budget_caps_every_remote_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            launcher.operation_deadline = time.monotonic() + 5
            self.assertLessEqual(launcher.bounded_timeout(90), 5)
            launcher.operation_deadline = time.monotonic() - 1
            with self.assertRaises(wgmvp.Blocked):
                launcher.bounded_timeout(90)


if __name__ == "__main__":
    unittest.main()
