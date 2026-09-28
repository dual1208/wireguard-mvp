"""Unknown-key helper cleanup fault injection; all networking commands mocked."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "remote" / "unknown-key.sh"
TOKEN = "11111111-2222-3333-4444-555555555555"


class UnknownKeyTests(unittest.TestCase):
    def run_shell(self, directory, body, *, extra_route=False, wrong_identity=False):
        prefix = f"""
WGMVP_UNKNOWN_SOURCE_ONLY=1
. {shlex.quote(str(SCRIPT))}
ROOT={shlex.quote(directory)}; OWNER=wgmvp-r1; ROLE=villa
G=10.203.77.1; V=10.203.77.2; C=10.203.77.3; ENDPOINT=192.0.2.1; PORT=51820
expected_ns=wgmvp_uk-{TOKEN}
unknown_safe_file() {{ [ -f "$1" ]; }}
ls() {{ printf 'drwx------ 1 0 0 0 fixture\\n'; }}
cat() {{ case "$1" in
    /proc/sys/kernel/random/boot_id) printf 'boot-fixture\\n';;
    /proc/sys/kernel/random/uuid) printf '{TOKEN}\\n';;
    *) command cat "$@";; esac; }}
wg() {{ case "$1" in genkey) printf 'PRIVATE_TEST_PLACEHOLDER\\n';; pubkey) printf 'UNREGISTERED_TEST_PUBLIC\\n';; *) return 98;; esac; }}
ip() {{
    printf '%s\\n' "$*" >> "$ROOT/commands"
    case "$*" in
        'link show') return 0;;
        'link show dev wgmvp_uk') return 1;;
        'netns list') [ ! -f "$ROOT/ns-created" ] || printf '%s\\n' "$expected_ns";;
        "netns add $expected_ns") : > "$ROOT/ns-created";;
        "netns exec $expected_ns readlink /proc/self/ns/net")
            if [ "${{FAIL_IDENTITY:-}}" = yes ]; then return 1; fi
            printf 'net:[{999 if wrong_identity else 100}]\\n';;
        "netns pids $expected_ns") return 0;;
        "-n $expected_ns -o link show") printf '1: lo: <LOOPBACK> mtu65536 state DOWN\\n';;
        "-n $expected_ns link show dev wgmvp_uk") return 1;;
        "-n $expected_ns -o address show") return 0;;
        "-n $expected_ns -4 route show table all") {'printf "default via10.0.0.1\\n"' if extra_route else 'return 0'};;
        "-n $expected_ns -6 route show table all") return 0;;
        "netns exec $expected_ns nft list tables") return 0;;
        "netns delete $expected_ns") rm "$ROOT/ns-created"; : > "$ROOT/deleted";;
        *) printf 'UNEXPECTED_COMMAND %s\\n' "$*" >&2; return 97;;
    esac
}}
"""
        return subprocess.run(["/bin/sh", "-c", prefix + body], text=True, capture_output=True, timeout=10)

    def state(self, directory, *, identity=None):
        path = Path(directory, "unknown-key")
        path.mkdir(mode=0o700)
        for name, value in {"owner": "wgmvp-r1", "token": TOKEN, "boot": "boot-fixture",
                            "namespace.name": f"wgmvp_uk-{TOKEN}", "creation.intent": TOKEN}.items():
            path.joinpath(name).write_text(value + "\n")
        if identity:
            path.joinpath("ns").write_text(identity + "\n")
        Path(directory, "ns-created").touch()
        return path

    def test_missing_identity_only_allows_pristine_nonce_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            result = self.run_shell(directory, "if unknown_cleanup_locked; then exit0=0; else exit 1; fi\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(state.exists())
            self.assertTrue(Path(directory, "deleted").exists())

    def test_foreign_route_blocks_missing_identity_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            result = self.run_shell(directory, "if unknown_cleanup_locked; then exit 90; else exit 12; fi\n", extra_route=True)
            self.assertEqual(result.returncode, 12, result.stderr)
            self.assertTrue(state.exists())
            self.assertFalse(Path(directory, "deleted").exists())

    def test_namespace_identity_mismatch_stops_even_in_conditional(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory, identity="net:[100]")
            result = self.run_shell(directory, "if unknown_cleanup_locked; then exit 90; else exit 12; fi\n", wrong_identity=True)
            self.assertEqual(result.returncode, 12, result.stderr)
            self.assertTrue(state.exists())
            self.assertFalse(Path(directory, "deleted").exists())

    def test_failure_after_namespace_creation_is_cleaned_by_exit_trap(self):
        with tempfile.TemporaryDirectory() as directory:
            for role in ("gz", "villa", "cave"):
                Path(directory, f"public.{role}").write_text(f"AUTHORIZED_{role}\n")
            result = self.run_shell(directory, "FAIL_IDENTITY=yes\nif unknown_run_locked; then exit 90; else exit 12; fi\n")
            self.assertEqual(result.returncode, 12, result.stderr)
            self.assertFalse(Path(directory, "unknown-key").exists())
            self.assertFalse(Path(directory, "ns-created").exists())
            self.assertTrue(Path(directory, "deleted").exists())

    def test_alias_match_is_exact(self):
        for suffix, expected in (("", 0), ("-foreign", 1)):
            script = f"WGMVP_UNKNOWN_SOURCE_ONLY=1; . {shlex.quote(str(SCRIPT))}; mark=owned; unknown_link_owned '2: wgmvp_uk: alias owned{suffix}'"
            result = subprocess.run(["/bin/sh", "-c", script], text=True, capture_output=True)
            self.assertEqual(result.returncode, expected)

    def test_missing_alias_recovery_requires_down_matching_index_and_key(self):
        for change in ('none', 'up', 'wrong-index', 'foreign-alias', 'wrong-key', 'no-intent'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                state=Path(directory)
                (state/'move.intent').write_text(TOKEN+'\n')
                (state/'interface.ifindex').write_text('17\n')
                (state/'public.key').write_text('EXPECTED_PUBLIC\n')
                if change=='no-intent': (state/'move.intent').unlink()
                flags='POINTOPOINT,NOARP,UP' if change=='up' else 'POINTOPOINT,NOARP'
                index=18 if change=='wrong-index' else 17
                alias=' alias foreign' if change=='foreign-alias' else ''
                link=f'{index}: wgmvp_uk: <{flags}> mtu 1420 state DOWN{alias} wireguard'
                key='FOREIGN_PUBLIC' if change=='wrong-key' else 'EXPECTED_PUBLIC'
                script=(f'WGMVP_UNKNOWN_SOURCE_ONLY=1; . {shlex.quote(str(SCRIPT))}\n'
                        f'state={shlex.quote(directory)}; token={shlex.quote(TOKEN)}; nsname=test\n'
                        'unknown_safe_file() { [ -f "$1" ]; }\n'
                        f'ip() {{ printf "%s\\n" {shlex.quote(key)}; }}\n'
                        f'unknown_move_link_owned {shlex.quote(link)} namespace\n')
                result=subprocess.run(['sh','-c',script],capture_output=True,text=True)
                self.assertEqual(result.returncode==0,change=='none',result.stderr)

    def test_router_role_selection_and_move_order(self):
        source=SCRIPT.read_text()
        self.assertIn('case "$ROLE" in villa) self=$V;; cave) self=$C;;',source)
        self.assertNotIn('ping -I "$V"',source)
        configured=source.index('wg set wgmvp_uk private-key')
        intent=source.index('> "$state/move.intent"',configured)
        moved=source.index('ip link set wgmvp_uk netns',intent)
        alias=source.index('link set wgmvp_uk alias',moved)
        up=source.index('link set wgmvp_uk mtu 1380 up',alias)
        self.assertLess(configured,intent)
        self.assertLess(intent,moved)
        self.assertLess(moved,alias)
        self.assertLess(alias,up)


if __name__ == "__main__":
    unittest.main()
