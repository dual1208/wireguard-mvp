"""Scoped gate/host-boundary tests; no SSH or live benchmark is executed."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import benchmark
import wgmvp


def snapshot(role):
    result={'files':{name:'a'*64 for name in wgmvp.IDENTITY_FILES[role]},
            'network_sha256':'b'*64,'installed':'yes'}
    if role!='gz': result['unrelated_config_sha256']='c'*64
    return result


class ScopedBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.local=Path(self.temp.name)
        self.snapshots={role:snapshot(role) for role in wgmvp.CAVE_LEG_ROLES}
        self.launcher=wgmvp.Launcher({'reviewed_snapshots':self.snapshots},self.local)
        evidence=self.local/'scoped-evidence.json'
        wgmvp.json_write(evidence,{'scope_status':'PASS','active_roles':['gz','cave'],
                                  'status':'BLOCKED','note':'synthetic offline fixture'})
        item={'path':'scoped-evidence.json','sha256':hashlib.sha256(evidence.read_bytes()).hexdigest()}
        self.gate={'owner':'wgmvp-r1','kind':'scoped-security-gate','selected_scope':['gz','cave'],
                   'full_acceptance':False,'snapshots':self.snapshots,
                   'scope_tests':{test:{'status':'PASS','selected_scope':['gz','cave'],'evidence_files':[item.copy()]}
                                  for test in wgmvp.SECURITY_GATE_IDS},
                   'global_tests':{test:'BLOCKED' for test in wgmvp.SECURITY_GATE_IDS}}
        self.gate_path=self.local/'security-gate-cave-leg.json'

    def tearDown(self):
        self.temp.cleanup()

    def write_gate(self):
        wgmvp.json_write(self.gate_path,self.gate,replace=self.gate_path.exists())

    def test_two_tcp_directions_then_only_explicit_finite_udp(self):
        jobs=benchmark.scenarios('cave-leg')
        self.assertEqual([(j.client,j.server,j.protocol,j.setting) for j in jobs],
                         [('cave','gz','tcp',1),('gz','cave','tcp',1)])
        optional=benchmark.scenarios('cave-leg',include_udp=True)
        self.assertEqual(optional[:2],jobs)
        self.assertEqual(len(optional),10)
        self.assertEqual({j.setting for j in optional[2:]},{1,5,10,20})
        self.assertTrue(all(set(j.participants)=={'gz','cave'} for j in optional))
        with self.assertRaises(ValueError): benchmark.scenarios('all',include_udp=True)

    def test_global_gate_never_substitutes_for_scoped_evidence(self):
        global_gate={'owner':'wgmvp-r1','tests':{test:'PASS' for test in wgmvp.SECURITY_GATE_IDS},
                     'snapshots':{role:snapshot(role) for role in wgmvp.ROLES}}
        global_gate['tests']['A05']='BLOCKED'
        wgmvp.json_write(self.local/'security-gate.json',global_gate)
        with patch.object(self.launcher,'remote') as remote, patch.object(self.launcher,'mutate') as mutate:
            with self.assertRaises(wgmvp.Blocked): self.launcher.benchmark('cave-leg')
        remote.assert_not_called(); mutate.assert_not_called()
        self.gate['scope_tests']['A05']['status']='BLOCKED'
        self.gate['tests']={test:'PASS' for test in wgmvp.SECURITY_GATE_IDS}
        self.write_gate()
        with self.assertRaises(wgmvp.Blocked): self.launcher.load_cave_leg_security_gate()

    def test_scoped_evidence_does_not_promote_global_blocked_status(self):
        self.write_gate()
        before=self.gate_path.read_bytes()
        accepted=self.launcher.load_cave_leg_security_gate()
        self.assertTrue(all(value=='BLOCKED' for value in accepted['global_tests'].values()))
        self.assertEqual(self.gate_path.read_bytes(),before)
        self.assertFalse((self.local/'security-gate.json').exists())
        # Writing a scoped object at the full gate path cannot bypass full gates.
        wgmvp.json_write(self.local/'security-gate.json',self.gate)
        with self.assertRaises(wgmvp.Blocked): self.launcher.load_security_gate()

    def test_wrong_scope_stale_snapshot_and_changed_evidence_are_rejected(self):
        original=copy.deepcopy(self.gate)
        for defect in ('scope','test-scope','full-claim','snapshot','evidence-hash','evidence-absent'):
            self.gate=copy.deepcopy(original)
            if defect=='scope': self.gate['selected_scope']=['gz','villa']
            elif defect=='test-scope': self.gate['scope_tests']['S03']['selected_scope']=['gz','villa']
            elif defect=='full-claim': self.gate['full_acceptance']=True
            elif defect=='snapshot': self.gate['snapshots']['cave']['network_sha256']='f'*64
            elif defect=='evidence-hash': self.gate['scope_tests']['S03']['evidence_files'][0]['sha256']='f'*64
            else: self.gate['scope_tests']['S03']['evidence_files']=[]
            self.write_gate()
            with self.subTest(defect=defect), self.assertRaises(wgmvp.Blocked):
                self.launcher.load_cave_leg_security_gate()

    def test_gate_and_evidence_must_remain_private(self):
        self.write_gate()
        self.gate_path.chmod(0o644)
        with self.assertRaises(wgmvp.Blocked): self.launcher.load_cave_leg_security_gate()
        self.gate_path.chmod(0o600)
        (self.local/'scoped-evidence.json').chmod(0o644)
        with self.assertRaises(wgmvp.Blocked): self.launcher.load_cave_leg_security_gate()

    def test_scoped_suite_never_reads_mutates_or_renews_villa(self):
        self.write_gate()
        events=[]
        def preflight(role):
            self.assertIn(role,('gz','cave')); events.append(('preflight',role)); return self.snapshots[role]
        def remote(role,script,label):
            self.assertIn(role,('gz','cave')); events.append(('read',role,label))
            output='3 packets transmitted, 3 received, 0% packet loss' if 'ping' in label else 'healthy'
            return {'returncode':0,'timeout':False,'stdout':output,'evidence_file':'fixture.json'}
        def mutate(role,body,action,delta,**kwargs):
            self.assertIn(role,('gz','cave')); events.append(('mutate',role,action))
        def run_suite(launcher,gate,jobs,*,after_measured):
            gate()
            for job in jobs:
                self.assertEqual(set(job.participants),{'gz','cave'})
                after_measured()
            return [{'status':'MEASURED'} for _ in jobs]
        with patch.object(self.launcher,'preflight',side_effect=preflight), \
             patch.object(self.launcher,'remote',side_effect=remote), \
             patch.object(self.launcher,'mutate',side_effect=mutate), \
             patch.object(self.launcher,'recovery') as recovery, \
             patch.object(benchmark,'run_suite',side_effect=run_suite), redirect_stdout(io.StringIO()):
            self.assertEqual(self.launcher.benchmark('cave-leg'),0)
        mutations=[event[1:] for event in events if event[0]=='mutate']
        self.assertEqual(mutations,[('gz','benchmark-arm'),('cave','benchmark-arm'),
                                    ('gz','benchmark-renew'),('cave','benchmark-renew'),
                                    ('gz','benchmark-renew'),('cave','benchmark-renew')])
        self.assertEqual(recovery.call_count,3)
        self.assertEqual(sum(event[0]=='read' and 'ping' in event[2] for event in events),6)
        metadata=json.loads((self.launcher.run_dir/'benchmark-scope.json').read_text())
        self.assertEqual(metadata['selected_scope'],['gz','cave'])
        self.assertFalse(metadata['full_acceptance'])

    def test_cli_scoped_dry_run_never_connects(self):
        with patch.object(wgmvp.discover,'run_bounded') as remote, redirect_stdout(io.StringIO()) as output:
            result=wgmvp.main(['benchmark','--benchmark-scope','cave-leg','--cave-leg-udp',
                               '--inventory',str(wgmvp.REPO/'inventory.example.json')])
        remote.assert_not_called()
        self.assertEqual(result,2)  # Example inventory intentionally remains incomplete.
        self.assertIn('10 runs',output.getvalue())
        self.assertIn('global acceptance is not promoted',output.getvalue())


if __name__=='__main__': unittest.main()
