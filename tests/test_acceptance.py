"""Offline evidence-parser tests; these do not establish live acceptance."""
import json
from pathlib import Path
import sys
import subprocess
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import acceptance as a


class EvidenceTests(unittest.TestCase):
    def test_loss_parser_rejects_partial_loss(self):
        self.assertTrue(a.zero_loss('3 packets transmitted, 3 received, 0% packet loss'))
        self.assertTrue(a.zero_loss('0.0% packet loss'))
        for value in ('100% packet loss', '10.0% packet loss', '33.333% packet loss', ''):
            self.assertFalse(a.zero_loss(value))

    def test_probe_failure_is_unknown_not_absence(self):
        probes = a.parse_probes('WGMVP_BEGIN routes\n\nWGMVP_END routes 127\n')
        with self.assertRaises(ValueError):
            a.read_probe({'gz': {'transport_ok': True, 'probes': probes}}, 'gz', 'routes')

    def test_probe_records_failure_under_errexit(self):
        script='set -e\n'+a.probe_script([('missing',['sh','-c','exit 7']),('next',['printf','ok'])])
        result=subprocess.run(['sh','-c',script],capture_output=True,text=True)
        self.assertEqual(result.returncode,0)
        probes=a.parse_probes(result.stdout)
        self.assertEqual(probes['missing']['returncode'],7)
        self.assertEqual(probes['next']['stdout'],'ok')

    def test_incomplete_duplicate_and_unframed_results_rejected(self):
        for value in ('WGMVP_BEGIN uid\n0\n', 'banner\n',
                      'WGMVP_BEGIN uid\n0\nWGMVP_END uid 0\nWGMVP_BEGIN uid\n',
                      'WGMVP_BEGIN uid\n0\nWGMVP_END other 0\n'):
            with self.assertRaises(ValueError):
                a.parse_probes(value)

    def test_unknown_baseline_cannot_become_security_failure_or_pass(self):
        inventory = json.loads((a.REPO / 'inventory.example.json').read_text())
        tests, _ = a.evaluate(inventory, {})
        self.assertEqual(tests['A04']['status'], 'BLOCKED')
        self.assertEqual(tests['S06']['status'], 'BLOCKED')
        self.assertEqual(tests['A01']['status'], 'BLOCKED')
        self.assertEqual(len(tests), 27)
        self.assertEqual(tests['S05']['status'], 'NOT_RUN')

    def test_policy_normalization_preserves_security_decisions(self):
        self.assertNotEqual(a.normalized({'policy': 'drop', 'packets': 1}),
                            a.normalized({'policy': 'accept', 'packets': 2}))
        self.assertNotEqual(a.normalized({'dev': 'wgmvp'}), a.normalized({'dev': 'eth0'}))
        self.assertEqual(a.normalized({'policy': 'drop', 'packets': 1}),
                         a.normalized({'policy': 'drop', 'packets': 2}))

    def test_duplicate_transfer_identity_rejected(self):
        key = 'A' * 43 + '='
        with self.assertRaises(ValueError):
            a.transfers(f'{key} 1 2\n{key} 3 4')


if __name__ == '__main__':
    unittest.main()
