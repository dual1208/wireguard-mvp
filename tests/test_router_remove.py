"""Interruption/conflict tests for removal; mocked UCI/IP/nft never touch networking."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "remote/router.sh"
SECTIONS = ["network.wgmvp", "network.wgmvp_peer", "firewall.wgmvp",
            "firewall.wgmvp_diag_in", "firewall.wgmvp_diag_out"]
GUARD = 'table inet wgmvp_guard {\n comment "wgmvp-r1"\n}\n'
UNRELATED = {"network.lan": "network.lan=interface\nnetwork.lan.ipaddr='192.0.2.10'\n"}
MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p=Path(os.environ['MOCK_STATE']); state=json.loads(p.read_text())
name=Path(sys.argv[0]).name; a=sys.argv[1:]
def save(): p.write_text(json.dumps(state))
def event(text): state['events'].append(text); save()
def stop(code=0): raise SystemExit(code)
if name=='uci':
 if a and a[0]=='-q': a=a[1:]
 cmd=a[0]; key=a[1]
 if cmd=='show':
  if key in ('network','firewall'):
   for k,v in state['sections'].items():
    if k.startswith(key+'.'): print(v,end='')
  elif key in state['sections']: print(state['sections'][key],end='')
  else: stop(1)
 elif cmd=='get':
  if key.endswith('.wgmvp_owner'):
   section=key[:-12]
   if section not in state['sections']: stop(1)
   print(state['owners'].get(section,'foreign'))
  elif key in state['sections']: print('interface')
  else: stop(1)
 elif cmd=='changes':
  for change in state['changes']:
   if change.lstrip('-').startswith(key+'.'): print(change)
 elif cmd=='delete':
  if state.get('fail_delete')==key: stop(42)
  if key not in state['sections']: stop(1)
  del state['sections'][key];state['changes'].append('-'+key);event('delete '+key)
 elif cmd=='commit':
  state['changes']=[v for v in state['changes'] if not v.lstrip('-').startswith(key+'.')]
  event('commit '+key)
 else: stop(80)
elif name=='ip':
 if a[:3]==['-4','rule','show']:
  for v in state['rules'].values(): print(v)
 elif a[:3]==['-4','route','show']: print(state['route']) if state['route'] else None
 elif a[:3]==['-4','rule','del']:
  pref=a[a.index('pref')+1]
  if state.get('fail_rule')==pref: stop(42)
  del state['rules'][pref];event('delete rule '+pref)
 elif a[:3]==['-4','route','del']: state['route']='';event('delete route')
 elif a[:2]==['link','show']: stop(1 if 'dev' in a else 0)
 else: stop(81)
elif name=='nft':
 if a==['list','tables']: print('table inet unrelated');print('table inet wgmvp_guard') if state['guard'] else None
 elif a in (['list','table','inet','wgmvp_guard'],['-s','list','table','inet','wgmvp_guard']):
  if not state['guard']: stop(1)
  print(state['guard'],end='')
 elif a==['delete','table','inet','wgmvp_guard']: state['guard']='';event('delete guard')
 else: stop(82)
elif name=='fw4': event('fw4 '+a[0])
else: stop(83)
'''


class RouterRemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ["uci", "ip", "nft", "fw4"]:
            executable = self.bin / name
            executable.write_text(MOCK)
            executable.chmod(0o700)
        self.state_path = self.root / "mock.json"
        sections = {s: f"{s}=interface\n{s}.wgmvp_owner='wgmvp-r1'\n" for s in SECTIONS}
        self.state = {
            "sections": dict(sections, **UNRELATED), "owners": {s: "wgmvp-r1" for s in SECTIONS},
            "changes": [], "events": [], "guard": GUARD,
            "rules": {"1000": "1000: from all to 10.203.77.0/29 lookup local",
                      "1001": "1001: from all to 10.203.77.0/29 lookup main",
                      "1002": "1002: from all to 203.0.113.1 fwmark 0x77203 lookup main",
                      "9000": "9000: from all lookup unrelated"},
            "route": "blackhole 10.203.77.0/29 proto 186 metric 32760",
        }
        self.save()
        (self.root / "owner").write_text("wgmvp-r1\n")
        (self.root / "routes.owned").write_text("wgmvp-r1\n")
        (self.root / "router.guard.canonical").write_text(GUARD)
        (self.root / "router.sections.sha256").write_text(
            hashlib.sha256("".join(sections[s] for s in SECTIONS).encode()).hexdigest() + "\n")
        self.env = dict(os.environ, ROOT=str(self.root), ROLE="villa", OWNER="wgmvp-r1",
                        IFACE="wgmvp", V="10.203.77.2", C="10.203.77.3",
                        POOL="10.203.77.0/29", ENDPOINT="203.0.113.1",
                        MOCK_STATE=str(self.state_path), PATH=str(self.bin)+":"+os.environ["PATH"])

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        self.state_path.write_text(json.dumps(self.state))

    def load(self):
        self.state = json.loads(self.state_path.read_text())

    def run_remove(self, success=True):
        # The real stop/check require /etc and /sys. Keep removal's own hash,
        # ownership, conflict and exact-tuple checks intact in this fixture.
        script = f'. "{SOURCE}"\nrouter_check() {{ :; }}\nrouter_stop() {{ :; }}\nrouter_remove\n'
        result = subprocess.run(["sh", "-c", script], env=self.env, capture_output=True, text=True, timeout=20)
        self.load()
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def interrupt(self):
        self.state["fail_delete"] = "firewall.wgmvp_diag_in"
        self.save()
        self.run_remove(False)
        self.assertTrue((self.root / "router.remove/scope").exists())
        self.assertNotIn("network.wgmvp", self.state["sections"])
        self.state.pop("fail_delete")
        self.save()

    def test_partial_uci_deletion_resumes_and_completed_rerun_is_noop(self):
        self.interrupt()
        self.run_remove()
        self.assertEqual(self.state["sections"], UNRELATED)
        self.assertEqual(self.state["rules"], {"9000": "9000: from all lookup unrelated"})
        self.assertEqual(self.state["guard"], "")
        self.assertEqual(self.state["route"], "")
        events = self.state["events"][:]
        self.assertIn("already removed", self.run_remove().stdout)
        self.assertEqual(self.state["events"], events)

    def test_changed_surviving_section_blocks_resume_without_deletions(self):
        self.interrupt()
        self.state["sections"]["firewall.wgmvp"] += "firewall.wgmvp.input='ACCEPT'\n"
        events = self.state["events"][:]
        self.save()
        self.assertIn("surviving UCI section changed", self.run_remove(False).stderr)
        self.assertEqual(self.state["events"], events)

    def test_foreign_rule_blocks_before_configuration_deletion(self):
        self.state["rules"]["1001"] = "1001: from all lookup foreign"
        self.save()
        self.assertIn("foreign rule", self.run_remove(False).stderr)
        self.assertEqual(self.state["events"], [])
        self.assertEqual(len(self.state["sections"]), 6)

    def test_interruption_during_rule_cleanup_resumes_with_absent_sections(self):
        self.state["fail_rule"] = "1001"
        self.save()
        self.run_remove(False)
        self.assertEqual(self.state["sections"], UNRELATED)
        self.assertNotIn("1000", self.state["rules"])
        self.assertTrue(self.state["guard"])
        self.state.pop("fail_rule")
        self.save()
        self.run_remove()
        self.assertEqual(self.state["rules"], {"9000": "9000: from all lookup unrelated"})

    def test_changed_guard_blocks_resume(self):
        self.interrupt()
        self.state["guard"] = GUARD.replace("wgmvp-r1", "foreign")
        events = self.state["events"][:]
        self.save()
        self.assertIn("guard changed", self.run_remove(False).stderr)
        self.assertEqual(self.state["events"], events)

    def test_unrelated_staged_change_is_never_committed(self):
        self.interrupt()
        self.state["changes"].append("network.lan.ipaddr='192.0.2.1'")
        events = self.state["events"][:]
        self.save()
        self.assertIn("unrelated staged UCI", self.run_remove(False).stderr)
        self.assertEqual(self.state["events"], events)


if __name__ == "__main__":
    unittest.main()
