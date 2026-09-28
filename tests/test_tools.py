"""Offline tests only. No test connects to a user's machine or any remote IP."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shlex
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_inventory as checker
import discover


def ready_inventory() -> dict:
    data = json.loads((ROOT / 'inventory.example.json').read_text())
    # A global-looking address for syntax validation ONLY; never used for traffic.
    data['plan']['gz_public_ipv4'] = '1.1.1.1'
    data['plan']['mtu'] = 1380
    for key in data['checks']:
        data['checks'][key] = True
    data['observed'].update(villa_version='synthetic-test', cave_version='synthetic-test',
                            gz_os='synthetic-test', gz_public_endpoint_evidence='offline fixture, not real evidence')
    return data


class InventoryTests(unittest.TestCase):
    def test_example_intentionally_not_ready(self):
        data = json.loads((ROOT / 'inventory.example.json').read_text())
        self.assertGreater(len(checker.validate(data)), 10)

    def test_filled_synthetic_inventory_passes_structure(self):
        self.assertEqual(checker.validate(ready_inventory(), final=True), [])

    def test_non_object_rejected(self):
        for data in (None, [], 'bad', 1):
            with self.subTest(data=data):
                self.assertTrue(checker.validate(data))

    def test_nested_non_object_rejected(self):
        for field in ('plan', 'observed', 'policy', 'checks', 'management_facts'):
            data = ready_inventory(); data[field] = None
            self.assertTrue(checker.validate(data))

    def test_model_schema_boolean_not_version(self):
        data = ready_inventory(); data['schema_version'] = True
        self.assertTrue(checker.validate(data))

    def test_each_unsafe_policy_rejected(self):
        for key in checker.FALSE_POLICIES:
            with self.subTest(key=key):
                data = ready_inventory(); data['policy'][key] = True
                self.assertTrue(checker.validate(data))

    def test_no_cave_alias_relocation(self):
        data = ready_inventory(); data['management_facts']['cave_ssh_alias_on_gpu'] = 'local-rt'
        self.assertTrue(checker.validate(data))

    def test_duplicate_addresses_rejected(self):
        data = ready_inventory(); data['plan']['overlay_addresses']['cave'] = data['plan']['overlay_addresses']['villa']
        self.assertTrue(checker.validate(data))

    def test_connected_subnet_assignment_rejected(self):
        data = ready_inventory(); data['plan']['overlay_addresses']['villa'] = '10.203.77.2/29'
        self.assertTrue(checker.validate(data))

    def test_reserved_or_out_of_pool_host_rejected(self):
        for address in ('10.203.77.0/32', '10.203.77.7/32', '10.203.78.2/32'):
            data = ready_inventory(); data['plan']['overlay_addresses']['villa'] = address
            self.assertTrue(checker.validate(data))

    def test_broad_existing_route_conflict_rejected(self):
        data = ready_inventory(); data['observed']['existing_ipv4_prefixes'].append('10.0.0.0/8')
        self.assertTrue(any('overlaps' in error for error in checker.validate(data)))

    def test_default_route_is_not_overlap_conflict(self):
        data = ready_inventory(); data['observed']['existing_ipv4_prefixes'].append('0.0.0.0/0')
        self.assertEqual(checker.validate(data), [])

    def test_management_network_preserved(self):
        data = ready_inventory(); data['observed']['existing_ipv4_prefixes'] = ['172.19.0.0/16']
        self.assertTrue(checker.validate(data))

    def test_non_public_endpoint_rejected(self):
        for address in ('192.168.1.93', '127.0.0.1', '203.0.113.20', '224.0.0.1', None, 'not-an-ip'):
            with self.subTest(address=address):
                data = ready_inventory(); data['plan']['gz_public_ipv4'] = address
                self.assertTrue(checker.validate(data))

    def test_unsafe_identifier_rejected(self):
        data = ready_inventory(); data['plan']['interface'] = 'wgmvp;reboot'
        self.assertTrue(checker.validate(data))

    def test_boolean_cannot_substitute_for_integer(self):
        data = ready_inventory(); data['plan']['outer_udp_port'] = True
        self.assertTrue(checker.validate(data))

    def test_required_check_cannot_be_truthy_string(self):
        data = ready_inventory(); data['checks']['rollback_ready'] = 'yes'
        self.assertTrue(checker.validate(data))

    def test_post_deployment_checks_not_fabricated_for_bootstrap(self):
        data = ready_inventory()
        data['checks']['outer_udp_paths_verified'] = False
        data['checks']['mtu_validated'] = False
        self.assertEqual(checker.validate(data), [])
        self.assertEqual(len(checker.validate(data, final=True)), 2)

    def test_non_rfc1918_pool_rejected(self):
        data = ready_inventory(); data['plan']['overlay_pool'] = '203.0.113.0/29'
        self.assertTrue(checker.validate(data))

    def test_oversized_mtu_rejected(self):
        data = ready_inventory(); data['plan']['mtu'] = 99999
        self.assertTrue(checker.validate(data))


class DiscoveryTests(unittest.TestCase):
    def test_villa_literal_preserved(self):
        command = discover.command_for('villa')
        self.assertEqual(command[-2], 'root@192.168.1.93')
        self.assertEqual(command[-1], 'sh -s -- villa')

    def test_cave_resolved_on_gpu(self):
        command = discover.command_for('cave')
        self.assertEqual(command[-2], 'gpuxtcp')
        self.assertNotIn('rt', command[:-1])
        nested = shlex.split(command[-1])
        self.assertEqual(nested[-2], 'rt')
        self.assertEqual(nested[-1], 'sh -s -- cave')
        self.assertEqual(nested[0], 'ssh')

    def test_host_trust_and_agent_forwarding_controls(self):
        for target in discover.TARGETS:
            command = discover.command_for(target)
            self.assertIn('StrictHostKeyChecking=yes', command)
            self.assertIn('ForwardAgent=no', command)
            self.assertIn('BatchMode=yes', command)
            self.assertNotIn('StrictHostKeyChecking=no', command)

    def test_arbitrary_target_rejected(self):
        with self.assertRaises(ValueError):
            discover.command_for('gz; rm -rf /')

    def test_proxycommand_not_persisted(self):
        raw = 'hostname host.example\nuser root\nport 22\nproxycommand tool --token SECRET\nidentityfile /secret/path\n'
        selected = discover.selected_ssh_fields(raw)
        self.assertEqual(selected['hostname'], 'host.example')
        self.assertEqual(selected['proxycommand'], 'configured (value withheld)')
        self.assertNotIn('SECRET', json.dumps(selected))
        self.assertNotIn('identityfile', selected)

    def test_bounded_runner_success_and_stdin(self):
        result = discover.run_bounded([sys.executable, '-c', 'import sys; print(sys.stdin.read())'], stdin='fixture')
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['stdout'].strip(), 'fixture')
        self.assertFalse(result['timeout'])

    def test_bounded_runner_timeout(self):
        result = discover.run_bounded([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=1)
        self.assertTrue(result['timeout'])
        self.assertNotEqual(result['returncode'], 0)

    def test_missing_executable_is_reported(self):
        result = discover.run_bounded(['/definitely/not/a/real/wgmvp-command'])
        self.assertIsNone(result['returncode'])
        self.assertTrue(result['stderr'])

    def test_probe_excludes_secret_dump_commands(self):
        source = (ROOT / 'tools' / 'probe_remote.sh').read_text()
        for forbidden in ('wg showconf', 'wg show all dump', 'uci show network', 'set -x', 'nft flush ruleset'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
