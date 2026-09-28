"""Offline capture-decision and cleanup-boundary tests; no networking occurs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'remote/spoof-lab.sh'
MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name=Path(sys.argv[0]).name; a=sys.argv[1:]
state=json.loads(Path(os.environ['STATE']).read_text())
if name=='timeout':
 if 'tcpdump' in a:
  p=Path(a[a.index('-w')+1]); p.write_text('synthetic fixture')
  print('listening on test',file=sys.stderr)
  raise SystemExit(state.get('capture_rc',124))
 phase=state['phase']; ok=phase!='spoof'
 print('3 packets transmitted, %d received, %d%% packet loss' % (3 if ok else 0,0 if ok else 100))
 raise SystemExit(0 if ok else 1)
elif name=='tcpdump':
 p=Path(a[a.index('-r')+1]); count=state['inner'] if '.inner.' in p.name else state['outer']
 for n in range(count): print('synthetic packet', n)
elif name=='stat':
 p=Path(a[-1]); fmt=a[-2]
 if fmt=='%u:%a': print('0:700')
 elif fmt=='%u:%a:%h': print('0:600:1')
 elif fmt=='%d:%i': print('123:456')
 else: raise SystemExit(95)
elif name=='ip':
 if a[:2]==['netns','exec']:
  print(state.get('public','wrong-key'))
 elif a[:2]==['netns','pids']:
  if state.get('pids_failure'): raise SystemExit(1)
  if state.get('process'): print('99999')
 elif a[:2]==['netns','delete']:
  with open(os.environ['EVENTS'],'a') as f: f.write('delete '+a[2]+'\n')
  (Path(os.environ['NETNS'])/a[2]).unlink()
 elif a[:2]==['-n',state['namespace']]:
  if a[2:4]==['link','set']:
   with open(os.environ['EVENTS'],'a') as f: f.write('link-down\n')
  elif a[2:4]==['link','delete']:
   state['deleted']=True; Path(os.environ['STATE']).write_text(json.dumps(state))
   with open(os.environ['EVENTS'],'a') as f: f.write('link-delete\n')
  else:
   print('1: lo: <UP>')
   if state.get('foreign'): print('2: eth0: <UP>')
   elif state.get('cleared_alias') and not state.get('deleted'): print('2: wgs-a: <UP> wireguard')
   elif not state.get('deleted'): print('2: wgs-a: <UP> alias '+state['mark'])
 else: raise SystemExit(96)
else: raise SystemExit(97)
'''


class LabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        for name in ('timeout', 'tcpdump', 'stat', 'ip'):
            path = self.bin / name; path.write_text(MOCK); path.chmod(0o700)
        self.state = {'phase': 'spoof', 'inner': 0, 'outer': 3}
        self.state_path = self.root / 'state.json'
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'],
                        STATE=str(self.state_path), EVENTS=str(self.root/'events'), NETNS=str(self.root/'netns'))
        (self.root / 'netns').mkdir()
        # Redirect only hard-coded lab storage paths for the local mock harness.
        self.source = self.root / 'lab.sh'
        (self.root/'boot').write_text('current-boot\n')
        self.source.write_text(SOURCE.read_text().replace('/etc/wgmvp', str(self.root/'owner')).replace('/run/netns', str(self.root/'netns')).replace('/proc/sys/kernel/random/boot_id',str(self.root/'boot')))

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, body):
        self.state_path.write_text(json.dumps(self.state))
        return subprocess.run(['sh', '-c', f'. "{self.source}"\n'+body], env=self.env,
                              capture_output=True, text=True, timeout=12)

    def capture(self, phase='spoof'):
        self.state['phase'] = phase
        return self.run_script(f'_sl_dir="{self.root}"; _sl_t=t; _sl_a=a; _sl_b=b; _sl_jobs=""\n_spoof_capture_phase {phase} 10.203.77.3\n')

    def test_spoof_requires_outer_arrival_and_zero_inner_delivery(self):
        result = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.state['inner'] = 1
        self.assertNotEqual(self.capture().returncode, 0)
        self.state.update(inner=0, outer=0)
        self.assertNotEqual(self.capture().returncode, 0)

    def test_positive_requires_three_delivered_requests(self):
        self.state.update(inner=3, outer=3)
        self.assertEqual(self.capture('positive').returncode, 0)
        self.state['inner'] = 2
        self.assertNotEqual(self.capture('positive').returncode, 0)

    def test_capture_tool_failure_cannot_be_negative_success(self):
        self.state['capture_rc'] = 137
        self.assertNotEqual(self.capture().returncode, 0)

    def prepare_cleanup(self, *, identity='123:456'):
        token='12345678-1234-1234-1234-123456789abc'
        directory=self.root/'owner'/('spoof-lab-'+token); directory.mkdir(parents=True)
        namespace='wgs-a-12345678'
        (directory/'scope').write_text(token+'\n'+namespace+' wgs-b-12345678 wgs-t-12345678\n')
        (directory/(namespace+'.identity')).write_text(identity+'\n')
        (directory/'a.key').write_text('dummy key fixture')
        (self.root/'netns'/namespace).touch()
        self.state.update(namespace=namespace, mark='wgmvp-r1:spoof:'+token)
        return directory

    def test_cleanup_deletes_only_owned_namespace_and_exact_key(self):
        directory=self.prepare_cleanup()
        (directory/'unrelated').write_text('retain')
        result=self.run_script(f'spoof_lab_cleanup "{directory}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((directory/'a.key').exists())
        self.assertTrue((directory/'unrelated').exists())
        self.assertEqual((self.root/'events').read_text(),'link-down\nlink-delete\ndelete wgs-a-12345678\n')

    def test_cleanup_refuses_replaced_namespace(self):
        directory=self.prepare_cleanup(identity='999:999')
        result=self.run_script(f'spoof_lab_cleanup "{directory}"')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'events').exists())

    def test_cleanup_refuses_foreign_link_or_remaining_process(self):
        directory=self.prepare_cleanup()
        for flags in ({'foreign': True, 'process': False}, {'foreign': False, 'process': True}):
            self.state.update(flags)
            self.assertNotEqual(self.run_script(f'spoof_lab_cleanup "{directory}"').returncode,0)
            self.assertFalse((self.root/'events').exists())

    def test_cleanup_treats_process_query_failure_as_unknown(self):
        directory=self.prepare_cleanup()
        self.state['pids_failure']=True
        self.assertNotEqual(self.run_script(f'spoof_lab_cleanup "{directory}"').returncode,0)
        self.assertFalse((self.root/'events').exists())

    def test_cleanup_refuses_empty_identity_record(self):
        directory=self.prepare_cleanup(identity='')
        self.assertNotEqual(self.run_script(f'spoof_lab_cleanup "{directory}"').returncode,0)
        self.assertFalse((self.root/'events').exists())

    def test_cleanup_wrong_scope_stops_even_in_error_handler(self):
        directory=self.prepare_cleanup()
        (directory/'scope').write_text('12345678-1234-1234-1234-123456789abc\nforeign-names\n')
        result=self.run_script(f'spoof_lab_cleanup "{directory}" || exit 77')
        self.assertEqual(result.returncode,77)
        self.assertTrue((directory/'a.key').exists())
        self.assertFalse((self.root/'events').exists())

    def test_cleanup_finished_rerun_is_noop(self):
        directory=self.prepare_cleanup()
        script=f'spoof_lab_cleanup "{directory}" && spoof_lab_cleanup "{directory}"'
        result=self.run_script(script)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.root/'events').read_text().count('link-delete'),1)

    def test_interrupted_move_requires_exact_index_namespace_boot_and_public_key(self):
        directory=self.prepare_cleanup()
        self.state.update(cleared_alias=True,public='A'*43+'=')
        expected=['2',self.state['namespace'],'current-boot',self.state['public']]
        record=directory/'wgs-a.move'
        for index in range(4):
            wrong=expected[:]; wrong[index]='mismatch'
            record.write_text('\n'.join(wrong)+'\n')
            self.assertNotEqual(self.run_script(f'spoof_lab_cleanup "{directory}"').returncode,0)
            self.assertFalse((self.root/'events').exists())
        record.write_text('\n'.join(expected)+'\n')
        result=self.run_script(f'spoof_lab_cleanup "{directory}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.root/'events').read_text(),'link-down\nlink-delete\ndelete wgs-a-12345678\n')

    def test_missing_move_record_cannot_adopt_aliasless_wireguard(self):
        directory=self.prepare_cleanup()
        self.state.update(cleared_alias=True,public='A'*43+'=')
        result=self.run_script(f'spoof_lab_cleanup "{directory}"')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'events').exists())

    def test_sourcing_alone_has_no_side_effects(self):
        self.assertEqual(self.run_script(':').returncode,0)
        self.assertFalse((self.root/'events').exists())


if __name__ == '__main__':
    unittest.main()
