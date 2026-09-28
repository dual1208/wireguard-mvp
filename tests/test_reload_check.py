"""Local S08 evidence/parser and guarded sequencing tests; never invoke SSH."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import reload_check as check
import wgmvp


def guard():
    return {"nftables": [{"metainfo": {"version": "fixture"}},
                         {"table": {"family": "inet", "name": "wgmvp_guard", "comment": "wgmvp-r1", "handle": 1}},
                         *[{"rule": {"family": "inet", "table": "wgmvp_guard", "chain": chain,
                                     "comment": comment, "handle": 5,
                                     "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]}}
                           for chain, comment in (("rx", "wgmvp ingress denied all destinations and IPv6"),
                                                  ("tx", "wgmvp output denied"))]]}


def outer():
    return {"nftables": [{"table": {"family": "inet", "name": "wgmvp_outer", "comment": "wgmvp-r1:" + "a" * 36}},
                         {"chain": {"name": "input", "hook": "input", "prio": -10}},
                         {"rule": {"chain": "input", "comment": "wgmvp IPv6 listener denied", "expr": [
                             {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}},
                             {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 51820}},
                             {"counter": None}, {"drop": None}]}}]}


def ipv6_probes():
    return {name: {"returncode": 0, "stdout": text} for name, text in {
        "allowed_ips": "A" * 43 + "=\t10.203.77.1/32 10.203.77.3/32",
        "disable_ipv6": "1", "routes6": "[]",
        "addresses6": '[{"ifname":"wgmvp","addr_info":[{"family":"inet","local":"10.203.77.2"}]}]',
        "global_ipv6": "0\n0"}.items()}


class FakeLauncher:
    def __init__(self, directory, fail_reload=False):
        self.run_dir = Path(directory)
        self.inventory = {"plan": {"overlay_addresses": {role: ip + "/32" for role, ip in check.ADDRESSES.items()},
                                   "outer_udp_port": 51820}}
        self.calls = []
        self.fail_reload = fail_reload

    def preflight(self, role):
        self.calls.append(("preflight", role))

    def remote(self, role, script, label):
        self.calls.append(("read", role, label))
        if label == "reload-ipv6-structure":
            output = "\n".join(f"WGMVP_BEGIN {name}\n{item['stdout']}\nWGMVP_END {name} 0" for name, item in ipv6_probes().items())
        elif "guard-" in label:
            output = json.dumps(guard())
        elif "outer-" in label:
            output = json.dumps(outer())
        elif label.startswith("reload-positive-"):
            output = "3 packets transmitted, 3 packets received, 0% packet loss"
        else:
            output = "healthy"
        return {"returncode": 0, "timeout": False, "stdout": output, "evidence_file": label + ".json"}

    def mutate(self, role, body, action, delta, **kwargs):
        self.calls.append(("mutate", role, action, body, kwargs))
        if action == "firewall-reload" and self.fail_reload:
            raise wgmvp.Blocked("fw4 reload unavailable")

    def recovery(self):
        self.calls.append(("recovery",))


class ReloadTests(unittest.TestCase):
    def test_nft_canonical_preserves_verdicts_order_and_match_values(self):
        before = guard()
        after = copy.deepcopy(before)
        after["nftables"][1]["table"]["handle"] = 999
        after["nftables"][2]["rule"]["expr"][0]["counter"]["packets"] = 700
        self.assertEqual(check.canonical_nft(before), check.canonical_nft(after))
        after["nftables"][2]["rule"]["expr"][-1] = {"accept": None}
        self.assertNotEqual(check.canonical_nft(before), check.canonical_nft(after))
        with self.assertRaises(wgmvp.Blocked):
            check.assert_router_guard(after)

    def test_outer_deny_requires_real_ipv6_match_not_just_comment(self):
        document = outer()
        check.assert_outer_ipv6_deny(document, 51820)
        document["nftables"][2]["rule"]["expr"][0]["match"]["right"] = "ipv4"
        with self.assertRaises(wgmvp.Blocked):
            check.assert_outer_ipv6_deny(document, 51820)

    def test_ipv6_positive_structure_and_contradictions(self):
        self.assertEqual(check.assert_ipv6_state(ipv6_probes(), "villa")["status"], "PASS")
        for label, text in (("allowed_ips", "A" * 43 + "=\t::/0"), ("disable_ipv6", "0"),
                            ("routes6", '[{"dev":"wgmvp","dst":"default"}]'),
                            ("addresses6", '[{"ifname":"wgmvp","addr_info":[{"family":"inet6","local":"fe80::1"}]}]')):
            probes = ipv6_probes()
            probes[label]["stdout"] = text
            with self.subTest(label=label), self.assertRaises(check.Failed):
                check.assert_ipv6_state(probes, "villa")

    def test_failed_probe_is_unknown_not_absence(self):
        probes = ipv6_probes()
        probes["routes6"] = {"returncode": 1, "stdout": "[]"}
        with self.assertRaises(wgmvp.Blocked) as error:
            check.assert_ipv6_state(probes, "cave")
        self.assertNotIsInstance(error.exception, check.Failed)

    def test_run_renews_all_roles_then_reloads_one_router_at_a_time(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = FakeLauncher(directory)
            result = check.run_reload(launcher)
            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(result["ipv6_payload_test"], "NOT_RUN")
            mutations = [call for call in launcher.calls if call[0] == "mutate"]
            self.assertEqual([(call[1], call[2]) for call in mutations],
                             [("gz", "reload-renew"), ("villa", "reload-renew"), ("cave", "reload-renew"), ("villa", "firewall-reload"),
                              ("gz", "reload-renew"), ("villa", "reload-renew"), ("cave", "reload-renew"), ("cave", "firewall-reload")])
            for call in mutations:
                if call[2] == "firewall-reload":
                    self.assertTrue(call[4]["check_status"])
                    self.assertIn("flock -x -n 9", call[3])
                    self.assertLess(call[3].index("fw4 check"), call[3].index("fw4 reload"))
            self.assertEqual(sum(call[0] == "read" and call[2].startswith("reload-positive-") for call in launcher.calls), 12)

    def test_failed_reload_stops_before_other_router(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = FakeLauncher(directory, fail_reload=True)
            result = check.run_reload(launcher)
            self.assertEqual(result["status"], "BLOCKED")
            reloads = [call[1] for call in launcher.calls if call[0] == "mutate" and call[2] == "firewall-reload"]
            self.assertEqual(reloads, ["villa"])

    def test_gz_cave_subset_never_calls_villa_or_claims_full_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = FakeLauncher(directory)
            result = check.run_reload(launcher, active_roles=('cave','gz'))
            self.assertEqual(result['status'],'BLOCKED',result)
            self.assertEqual(result['scope_status'],'PASS',result)
            self.assertEqual(result['active_roles'],('gz','cave'))
            self.assertEqual([item['role'] for item in result['reloads']],['cave'])
            self.assertNotIn('villa',[call[1] for call in launcher.calls if len(call)>1])
            self.assertEqual(sum(call[0]=='read' and call[2].startswith('reload-positive-') for call in launcher.calls),2)

    def test_invalid_targets_block_before_any_remote_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher=FakeLauncher(directory)
            result=check.run_reload(launcher,active_roles=('gz','gz'))
            self.assertEqual(result['status'],'BLOCKED')
            self.assertEqual(launcher.calls,[])

    def test_mutation_script_has_no_global_sysctl_write_and_valid_shell(self):
        result = subprocess.run(["sh", "-n"], input=check.RELOAD_BODY, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sysctl", check.RELOAD_BODY)
        self.assertNotIn("flush", check.RELOAD_BODY)
        self.assertNotIn("network restart", check.RELOAD_BODY)


if __name__ == "__main__":
    unittest.main()
