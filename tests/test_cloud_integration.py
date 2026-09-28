"""Cleanup must reach every owner even when a host or cloud step is blocked."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import cloud_gate
import wgmvp


class CloudIntegrationTests(unittest.TestCase):
    def test_blocked_host_does_not_skip_other_hosts_or_cloud_cleanup(self):
        for action in ('rollback', 'remove'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                launcher = wgmvp.Launcher({}, Path(directory))
                (launcher.local / 'cloud-plan.json').write_text('{}')
                called = []
                def mutate(role, *args, **kwargs):
                    called.append(role)
                    if role == 'cave':
                        raise wgmvp.Blocked('reviewed fingerprint changed')
                with patch.object(launcher, 'mutate', side_effect=mutate), patch.object(cloud_gate, 'CloudGate') as gate:
                    gate.return_value.rollback.side_effect = wgmvp.Blocked('cloud unavailable')
                    with self.assertRaises(wgmvp.Blocked) as error:
                        getattr(launcher, action)()
                    self.assertEqual(called, ['cave', 'villa', 'gz'])
                    gate.return_value.rollback.assert_called_once()
                    self.assertIn('fingerprint changed', str(error.exception))
                    self.assertIn('cloud unavailable', str(error.exception))

    def test_no_reviewed_cloud_plan_means_no_cloud_action(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = wgmvp.Launcher({}, Path(directory))
            with patch.object(launcher, 'mutate'), patch.object(cloud_gate, 'CloudGate') as gate:
                launcher.rollback()
                gate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
