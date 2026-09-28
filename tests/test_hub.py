"""Offline boundary tests; these do not establish live kernel/network acceptance."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "remote" / "hub.sh"


class HubShellTests(unittest.TestCase):
    def run_shell(self, code, **env):
        return subprocess.run(
            ["/bin/sh", "-c", f". {shlex.quote(str(SCRIPT))}\n{code}"],
            env={**os.environ, **env}, text=True, capture_output=True, timeout=10,
        )

    def test_source_has_no_side_effects_or_output(self):
        result = self.run_shell(":", PATH="/nonexistent")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")

    def test_unreviewed_address_plan_and_injection_rejected(self):
        for variables in ({"G": "192.168.1.1"}, {"POOL": "0.0.0.0/0"},
                          {"OWNER": 'x"; accept'}, {"NS": "default"},
                          {"PORT": "53"}, {"MTU": "9999"},
                          {"ROOT": "/tmp/../etc/wgmvp"}):
            result = self.run_shell("_hub_config", **variables)
            self.assertNotEqual(result.returncode, 0, variables)

    def test_valid_configuration_and_policy(self):
        result = self.run_shell("_hub_config && _hub_mark=owned && _hub_inner_policy")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("policy drop;"), 3)
        self.assertIn('ip saddr 10.203.77.2 ip daddr 10.203.77.3 icmp type', result.stdout)
        self.assertIn('ip saddr 10.203.77.3 ip daddr 10.203.77.2 icmp type', result.stdout)
        self.assertNotIn("ct state established", result.stdout)
        self.assertNotIn("0.0.0.0/0", result.stdout)
        self.assertNotIn("masquerade", result.stdout)
        for chain in ("input", "output", "forward"):
            self.assertIn(f"chain bench_{chain} {{ }}", result.stdout)
            self.assertLess(result.stdout.index(f"jump bench_{chain}"),
                            result.stdout.index(f'wgmvp {chain} denied'))

    def test_outer_ipv6_listener_drop_precedes_ipv4_allow(self):
        result = self.run_shell("_hub_config && _hub_mark=owned && _hub_outer_policy")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('meta nfproto ipv6 udp dport 51820 counter drop', result.stdout)
        self.assertIn('meta nfproto ipv4 udp dport 51820 counter accept', result.stdout)
        self.assertEqual(result.stdout.count("policy accept;"), 1)

    def test_rule_comment_cannot_impersonate_table_owner(self):
        for policy, expected in (
            ('table inet wgmvp_outer {\n\tcomment "mine"\n}\n', 0),
            ('table inet wgmvp_outer {\n\tcomment "foreign"\n}\n', 1),
            ('table inet wgmvp_outer {\n\tchain input {\n\t\tcomment "mine"\n}\n', 1),
        ):
            code = f"_hub_mark=mine; printf '%s' {shlex.quote(policy)} | _hub_assert_table"
            result = self.run_shell(code)
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_ifindex_and_alias_both_have_to_match(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "interface.ifindex").write_text("9\n")
            for index, alias, expected in ((9, "mine", 0), (8, "mine", 1), (9, "foreign", 1)):
                code = (f"_hub_state={shlex.quote(directory)}; _hub_mark=mine\n"
                        "_hub_file_safe() { :; }\n"
                        f"_hub_assert_link '{index}: wgmvp: <UP> mtu 1380 alias {alias}'")
                result = self.run_shell(code)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_missing_alias_requires_exact_unfinished_down_keyed_move(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory, "hub")
            state.mkdir()
            Path(directory, "public.gz").write_text("public\n")
            (state / "boot-id").write_text("boot\n")
            (state / "namespace.identity").write_text("7:88\n")
            (state / "move.pending").write_text("owned\nboot\n7:88\npublic\n")
            code = '''
_hub_config; _hub_mark=owned
_hub_file_safe() { :; }
_hub_assert_namespace() { [ "$BAD_NAMESPACE" != yes ]; }
cat() { if [ "$1" = /proc/sys/kernel/random/boot_id ]; then printf '%s\\n' "$BOOT"; else command cat "$@"; fi; }
ip() {
 case "$*" in
  '-o link show') printf '1: lo: <UP> mtu 65536\\n';;
  '-n wgmvp -o link show') printf '1: lo: <UP> mtu 65536\\n48: wgmvp: <POINTOPOINT,NOARP> mtu 1420\\n';;
  '-n wgmvp -o address show dev wgmvp') printf '%s' "$ADDRESS";;
  'netns exec wgmvp wg show wgmvp public-key') printf '%s\\n' "$PUBLIC";;
  *) return 1;;
 esac
}
_hub_assert_moving_link "$LINK"
'''
            base = {"ROOT": directory, "BAD_NAMESPACE": "no", "BOOT": "boot", "ADDRESS": "", "PUBLIC": "public",
                    "LINK": "48: wgmvp: <POINTOPOINT,NOARP> mtu 1420 state DOWN wireguard"}
            for changes, expected in (({}, 0), ({"BOOT": "other"}, 1), ({"PUBLIC": "foreign"}, 1),
                                      ({"BAD_NAMESPACE": "yes"}, 1), ({"ADDRESS": "inet 10.203.77.1/32"}, 1),
                                      ({"LINK": "48: wgmvp: <UP> mtu 1420 wireguard"}, 1),
                                      ({"LINK": "48: wgmvp: <POINTOPOINT,NOARP> mtu 1420 alias foreign wireguard"}, 1),
                                      ({"LINK": "48: wgmvp: <POINTOPOINT,NOARP> mtu 1420 dummy"}, 1)):
                result = self.run_shell(code, **{**base, **changes})
                self.assertEqual(result.returncode, expected, (changes, result.stderr))
            (state / "ready").touch()
            self.assertNotEqual(self.run_shell(code, **base).returncode, 0)
            (state / "ready").unlink()
            (state / "move.pending").unlink()
            self.assertNotEqual(self.run_shell(code, **base).returncode, 0)

    def test_start_models_alias_clearing_and_routes_require_up(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "private.key").write_text("not-a-real-key\n")
            Path(directory, "public.gz").write_text("public\n")
            code = r'''
_hub_require_root() { :; }
_hub_inventory_available() { :; }
_hub_ns_exists() { return 1; }
_hub_table_exists() { return 1; }
_hub_read_public_keys() { _hub_gpub=public; _hub_vpub=V; _hub_cpub=C; }
_hub_file_safe() { :; }
_hub_load_state() { _hub_mark=owned; }
_hub_assert_namespace() { :; }
_hub_validate_running() {
 [ "$(command cat "$ROOT/mock-alias")" = owned ] && [ -f "$ROOT/mock-up" ] &&
 [ "$(wc -l < "$ROOT/mock-routes" | tr -d ' ')" = 2 ]
}
ss() { :; }
stat() { printf '7:88\n'; }
cat() { case "$1" in /proc/sys/kernel/random/*) printf 'boot\n';; *) command cat "$@";; esac; }
wg() { case "$1" in pubkey|show) printf 'public\n';; set) : > "$ROOT/mock-key";; *) return 1;; esac; }
nft() { if [ "$1" = -f ]; then : > "$ROOT/mock-outer"; fi; }
mock_link() {
 if [ -f "$ROOT/mock-up" ]; then flags=POINTOPOINT,NOARP,UP; else flags=POINTOPOINT,NOARP; fi
 printf '48: wgmvp: <%s> mtu 1380 ' "$flags"
 if [ -s "$ROOT/mock-alias" ]; then printf 'alias %s ' "$(command cat "$ROOT/mock-alias")"; fi
 printf 'wireguard\n'
}
ip() {
 case "$*" in
  'link show dev wgmvp') [ -f "$ROOT/mock-host" ];;
  'netns add wgmvp') :;;
  'link add name wgmvp alias owned type wireguard') : > "$ROOT/mock-host"; printf 'owned\n' > "$ROOT/mock-alias";;
  'link set dev wgmvp netns wgmvp') [ -f "$ROOT/mock-key" ] || return 91; rm "$ROOT/mock-host"; : > "$ROOT/mock-alias";;
  '-n wgmvp -d -o link show dev wgmvp') mock_link;;
  '-o link show') printf '1: lo: <UP> mtu 65536\n';;
  '-n wgmvp -o link show') printf '1: lo: <UP> mtu 65536\n'; mock_link;;
  '-n wgmvp -o address show dev wgmvp') :;;
  'netns exec wgmvp wg show wgmvp public-key') printf 'public\n';;
  '-n wgmvp link set dev wgmvp alias owned') printf 'owned\n' > "$ROOT/mock-alias";;
  '-n wgmvp link set dev wgmvp up') [ -f "$ROOT/mock-inner" ] && [ -f "$ROOT/mock-outer" ] || return 92; : > "$ROOT/mock-up";;
  '-n wgmvp route add 10.203.77.'*) [ -f "$ROOT/mock-up" ] || { printf 'Device for nexthop is not up\n' >&2; return 93; }; printf '%s\n' "$*" >> "$ROOT/mock-routes";;
  'netns exec wgmvp nft -f '*) : > "$ROOT/mock-inner";;
  'netns exec wgmvp nft '*|'netns exec wgmvp sysctl '*|'netns exec wgmvp wg set '*|'-n wgmvp link set lo up'|'-n wgmvp route add blackhole '*|'-n wgmvp link set dev wgmvp mtu '*|'-n wgmvp address add '*|'-n wgmvp -4 '*|'-n wgmvp -6 '*) :;;
  *) printf 'unexpected mock command: %s\n' "$*" >&2; return 99;;
 esac
}
hub_stop() { printf 'UNEXPECTED_CLEANUP\n' >&2; }
hub_start
'''
            result = self.run_shell(code, ROOT=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("hub: ready", result.stdout)
            self.assertTrue(Path(directory, "hub", "ready").exists())
            self.assertFalse(Path(directory, "hub", "move.pending").exists())
            self.assertEqual(Path(directory, "hub", "interface.ifindex").read_text(), "48\n")

    def test_conflicting_namespace_rejected_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            code = """
_hub_require_root() { :; }
_hub_inventory_available() { :; }
_hub_ns_exists() { return 0; }
ip() { printf 'unexpected ip mutation\n' >&2; return 90; }
nft() { printf 'unexpected nft mutation\n' >&2; return 90; }
hub_start
"""
            result = self.run_shell(code, ROOT=directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unowned project name", result.stderr)
            self.assertNotIn("unexpected", result.stderr)
            self.assertFalse(Path(directory, "hub").exists())

    def test_incomplete_start_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "hub").mkdir()
            code = """
_hub_require_root() { :; }
_hub_inventory_available() { :; }
_hub_load_state() { :; }
hub_start
"""
            result = self.run_shell(code, ROOT=directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("incomplete prior start", result.stderr)

    def test_start_failure_runs_cleanup_even_when_called_in_condition(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "private.key").write_text("not-a-real-key\n")
            code = """
_hub_require_root() { :; }
_hub_inventory_available() { :; }
_hub_ns_exists() { return 1; }
_hub_table_exists() { return 1; }
_hub_read_public_keys() { _hub_gpub=public; }
_hub_file_safe() { :; }
_hub_load_state() { _hub_mark=owned; }
ss() { :; }
wg() { printf 'public\n'; }
cat() {
    case "$1" in /proc/sys/kernel/random/*) printf 'fake\n';;
        *) command cat "$@";; esac
}
ip() { return 1; }
nft() { return 1; }
hub_stop() { printf 'CLEANUP_CALLED\n'; }
if hub_start; then exit 90; else exit 12; fi
"""
            result = self.run_shell(code, ROOT=directory)
            self.assertEqual(result.returncode, 12, result.stderr)
            self.assertIn("CLEANUP_CALLED", result.stderr)
            self.assertIn("incomplete start", result.stderr)


if __name__ == "__main__":
    unittest.main()
