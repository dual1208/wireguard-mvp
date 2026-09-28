"""Local plan and proposed owner-journal tests. No host/network execution."""
import json
import copy
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shlex
import subprocess
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import mtu_probe

PROPOSAL = ROOT / "proposals/mtu-lease.sh"


class PlanTests(unittest.TestCase):
    def test_cli_without_apply_never_connects(self):
        with patch.object(mtu_probe.wgmvp.discover, "run_bounded") as remote, redirect_stdout(io.StringIO()):
            self.assertEqual(mtu_probe.main(["--scope", "cave", "--mtu", "1420"]), 0)
            remote.assert_not_called()

    def test_cave_default_has_only_two_owned_directions_and_no_execution(self):
        plan = mtu_probe.candidate_plan()
        self.assertEqual(plan["scope"], "cave")
        self.assertEqual(plan["status"], "NOT_RUN")
        self.assertFalse(plan["execution_ready"])
        self.assertEqual(plan["ipv4_icmp_or_udp_payload"], 1352)
        self.assertEqual(plan["expected_outer_ipv4_bytes_at_exact_mtu"], 1440)
        self.assertEqual([leg["router"] for leg in plan["legs"]], ["cave"])
        directions = plan["legs"][0]["udp_directions"]
        self.assertEqual({(item["source"], item["destination"]) for item in directions}, {("gz", "cave"), ("cave", "gz")})
        for item in directions:
            args = item["client_argv"]
            self.assertIn("--dont-fragment", args)
            self.assertEqual(args[args.index("-b") + 1], "1M")
            self.assertEqual(args[args.index("-l") + 1], "1352")

    def test_ceiling_is_reviewed_cap_not_assumed_1500_underlay(self):
        for mtu in (True, 1279, 1421, 1440):
            with self.assertRaises(ValueError):
                mtu_probe.candidate_plan(mtu)
        self.assertEqual(mtu_probe.next_candidate(1380), 1420)
        self.assertEqual(mtu_probe.next_candidate(1380, 1420), 1400)
        self.assertIsNone(mtu_probe.next_candidate(1420))
        self.assertIsNone(mtu_probe.next_candidate(1419, 1420))


class CurrentMtuEvidenceTests(unittest.TestCase):
    def fixture(self):
        inner = {"src": "10.203.77.1", "dst": "10.203.77.3", "total_length": 1380, "df": True,
                 "mf": False, "offset": 0, "dport": 52080, "sport": 45678, "id": 1}
        outer = {"src": "8.163.2.191", "dst": "203.0.113.1", "total_length": 1440,
                 "df": False, "mf": False, "offset": 0, "sport": 51820, "dport": 45678,
                 "id": 2, "wireguard_data": True}
        return {role: {"inner": [copy.deepcopy(inner) for _ in range(3)],
                       "outer": [copy.deepcopy(outer) for _ in range(3)]} for role in ("gz", "cave")}

    def test_complete_exact_size_evidence_is_required_at_both_ends(self):
        traces = self.fixture()
        self.assertEqual(mtu_probe.assess_direction(traces, "gz", "cave", 1380)["cave"]["inner_full_size_df_packets"], 3)
        traces["cave"]["outer"] = []
        with self.assertRaises(mtu_probe.wgmvp.Blocked):
            mtu_probe.assess_direction(traces, "gz", "cave", 1380)

    def test_fragments_and_missing_df_cannot_be_passes(self):
        for layer, field, value in (("outer", "mf", True), ("inner", "offset", 1280), ("inner", "df", False)):
            traces = self.fixture()
            traces["cave"][layer][0][field] = value
            with self.subTest(layer=layer, field=field), self.assertRaises(mtu_probe.Failed):
                mtu_probe.assess_direction(traces, "gz", "cave", 1380)
        traces = self.fixture()
        traces["cave"]["outer"][0]["total_length"] = 2880
        with self.assertRaises(mtu_probe.wgmvp.Blocked) as error:
            mtu_probe.assess_direction(traces, "gz", "cave", 1380)
        self.assertNotIsInstance(error.exception, mtu_probe.Failed)

    def test_decoder_preserves_total_size_df_and_noninitial_fragments(self):
        header = bytearray(20)
        header[0], header[9] = 0x45, 17
        header[2:8] = struct.pack("!HHH", 1380, 7, 0x4000)
        header[12:20] = socket.inet_aton("10.203.77.1") + socket.inet_aton("10.203.77.3")
        frame = bytes(header) + struct.pack("!HHHH", 45678, 52080, 1360, 0) + b"data"
        pcap = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 128, 101)
        pcap += struct.pack("<IIII", 1, 0, len(frame), 1380) + frame
        packet = mtu_probe.decode_mtu_packets(pcap)[0]
        self.assertEqual(packet["total_length"], 1380)
        self.assertTrue(packet["df"])
        fragmented = bytearray(pcap)
        fragmented[24 + 16 + 6:24 + 16 + 8] = struct.pack("!H", 160)
        packet = mtu_probe.decode_mtu_packets(bytes(fragmented))[0]
        self.assertEqual(packet["offset"], 1280)
        self.assertNotIn("dport", packet)
        with self.assertRaises(mtu_probe.wgmvp.Blocked):
            mtu_probe.decode_mtu_packets(pcap[:-1])

    def test_missing_scoped_gate_prevents_every_connection_and_mutation(self):
        inventory = {"plan": {"mtu": 1380, "outer_udp_port": 51820, "gz_public_ipv4": "8.163.2.191",
                               "overlay_addresses": {role: ip + "/32" for role, ip in mtu_probe.ADDRESSES.items()}}}
        with tempfile.TemporaryDirectory() as directory:
            launcher = mtu_probe.wgmvp.Launcher(inventory, Path(directory))
            with patch.object(launcher, "remote") as remote, patch.object(launcher, "mutate") as mutate:
                result = mtu_probe.run_current(launcher, "cave")
                self.assertEqual(result["status"], "BLOCKED")
                remote.assert_not_called()
                mutate.assert_not_called()


class RestorationTests(unittest.TestCase):
    def run_proposal(self, directory, body, **env):
        script = f'. {shlex.quote(str(PROPOSAL))}\n' + r'''
ROOT=$TEST_ROOT; OWNER=wgmvp-r1; ROLE=gz; MTU=1380
_mtu_context() { _mtu_record=$ROOT/mtu-probe.pending; _mtu_boot=$BOOT; _mtu_now=$NOW; _mtu_config_hash=config; }
_mtu_lock_assert() { :; }
_mtu_safe() { [ -f "$1" ] && [ ! -L "$1" ]; }
_mtu_identity() { _mtu_ns=$NS_ID; _mtu_index=$INDEX; _mtu_alias=owned; _mtu_public=public; _mtu_current=$(cat "$ROOT/current"); }
_mtu_exec() {
 case "$*" in
  'cat /sys/class/net/wgmvp/mtu') cat "$ROOT/current";;
  'ip link set dev wgmvp mtu '*)
    printf '%s\n' "$*" >> "$ROOT/mutations"
    [ -f "$ROOT/mtu-probe.pending" ] || return 91
    printf '%s\n' "$7" > "$ROOT/current"
    [ "$FAIL_TARGET" != yes ] || [ "$7" != 1420 ];;
  'ip link set dev wgmvp down') printf 'down\n' >> "$ROOT/mutations";;
  *) return 90;;
 esac
}
''' + body
        return subprocess.run(["sh", "-c", script], text=True, capture_output=True, timeout=5,
                              env={**os.environ, "TEST_ROOT": str(directory), "BOOT": "boot", "NOW": "230",
                                   "NS_ID": "net:[77]", "INDEX": "48", "FAIL_TARGET": "no", **env})

    def record(self, directory, current="1420"):
        path = Path(directory)
        (path / "current").write_text(current + "\n")
        (path / "mtu-probe.pending").write_text("wgmvp-r1\nboot\n220\n1380\n1420\nconfig\nnet:[77]\n48\nowned\npublic\n")

    def test_expiry_restores_exact_owned_runtime_mtu_after_coordinator_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            self.record(directory)
            result = self.run_proposal(directory, "mtu_probe_expire_locked")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(directory, "current").read_text(), "1380\n")
            self.assertFalse(Path(directory, "mtu-probe.pending").exists())

    def test_replaced_interface_or_namespace_is_not_modified(self):
        for overrides in ({"INDEX": "49"}, {"NS_ID": "net:[88]"}):
            with tempfile.TemporaryDirectory() as directory:
                self.record(directory)
                result = self.run_proposal(directory, "if mtu_probe_restore_locked; then exit 90; else exit 1; fi", **overrides)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(Path(directory, "mutations").exists())
                self.assertTrue(Path(directory, "mtu-probe.pending").exists())

    def test_unexpected_third_mtu_quiesces_owned_interface_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            self.record(directory, "1400")
            result = self.run_proposal(directory, "mtu_probe_restore_locked")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(Path(directory, "mutations").read_text(), "down\n")
            self.assertEqual(Path(directory, "current").read_text(), "1400\n")

    def test_begin_failure_restores_from_journal_written_before_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "current").write_text("1380\n")
            (root / "state").mkdir()
            (root / "state/pending").write_text("wgmvp-r1\nboot\n100\n600\n3600\n")
            result = self.run_proposal(directory, "mtu_probe_begin_locked 1420", NOW="100", FAIL_TARGET="yes")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual((root / "current").read_text(), "1380\n")
            self.assertFalse((root / "mtu-probe.pending").exists())

    def test_proposal_source_has_no_side_effects(self):
        result = subprocess.run(["/bin/sh", "-c", f'. {shlex.quote(str(PROPOSAL))}'], text=True, capture_output=True,
                                env={"PATH": "/nonexistent"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, "")


if __name__ == "__main__":
    unittest.main()
