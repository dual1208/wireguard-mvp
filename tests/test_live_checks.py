"""Offline acceptance decision and cleanup-flow tests; never opens SSH."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import live_checks as live


def guard(packets=0):
    return {'nftables': [
        {'chain': {'table': 'wgmvp_guard', 'name': 'prerouting', 'hook': 'prerouting', 'prio': -190}},
        {'rule': {'family': 'inet', 'table': 'wgmvp_guard', 'chain': 'prerouting', 'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'wgmvp'}}, {'jump': {'target': 'rx'}}]}},
        {'rule': {'family': 'inet', 'table': 'wgmvp_guard', 'chain': 'rx', 'comment': live.DENY_COMMENT,
                  'expr': [{'counter': {'packets': packets, 'bytes': packets * 60}}, {'drop': None}]}}
    ]}


class LiveCheckTests(unittest.TestCase):
    def test_portable_detached_worker_ignores_hup_and_closes_mutex(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'sh').symlink_to('/bin/sh')
            ready, done = folder / 'ready', folder / 'done'
            child = (
                'import os, pathlib, time\n'
                'try: os.fstat(8)\n'
                'except OSError: pass\n'
                'else: raise RuntimeError("capture mutex leaked")\n'
                f'pathlib.Path({str(ready)!r}).write_text(str(os.getpid()))\n'
                'time.sleep(.5)\n'
                f'pathlib.Path({str(done)!r}).write_text("complete")\n')
            worker = live.detached_worker('exec ' + shlex.join([sys.executable, '-c', child]), str(folder / 'runner'))
            self.assertNotIn('nohup', worker)
            result = subprocess.run(['/bin/sh', '-c', 'exec 8>' + shlex.quote(str(folder / 'mutex')) + '\n' + worker],
                                    env={**os.environ, 'PATH': directory}, text=True, capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 0, result.stderr)
            deadline = time.monotonic() + 2
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(ready.exists(), (folder / 'runner').read_text())
            os.kill(int(ready.read_text()), signal.SIGHUP)
            while not done.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(done.exists(), (folder / 'runner').read_text())

    def test_receiver_counter_requires_exact_ingress_rule(self):
        self.assertEqual(live.receiver_counter(guard(7)), 7)
        for mutation in ('wrong-hook', 'wrong-comment', 'duplicate', 'wrong-verdict'):
            data=guard()
            if mutation=='wrong-hook': data['nftables'][0]['chain']['prio']=0
            elif mutation=='wrong-comment': data['nftables'][-1]['rule']['comment']='unrelated'
            elif mutation=='duplicate': data['nftables'].append(copy.deepcopy(data['nftables'][-1]))
            else: data['nftables'][-1]['rule']['expr'][-1]={'accept':None}
            with self.assertRaises(live.wgmvp.Blocked): live.receiver_counter(data)

    def test_timeouts_alone_do_not_prove_receiver_denial(self):
        output=''.join(f'PORT {p} 124\n' for p in live.PORTS)
        self.assertEqual(len(live.nc_results(output)),5)
        with self.assertRaises(live.Failed): live.nc_results(output.replace('22 124','22 0'))
        with self.assertRaises(live.wgmvp.Blocked): live.nc_results(output.replace('22 124','22 2'))
        with self.assertRaises(live.wgmvp.Blocked): live.nc_results(output+'PORT 22 1\n')

    def test_route_requires_expected_device_and_source(self):
        live.route_is_project([{'dev':'wgmvp','from':'10.203.77.1'}],'10.203.77.1')
        for value in ([], [{'dev':'eth0','from':'10.203.77.1'}], [{'dev':'wgmvp','from':'192.0.2.1'}]):
            with self.assertRaises(live.wgmvp.Blocked): live.route_is_project(value,'10.203.77.1')

    def fixture(self, active_roles=live.wgmvp.ROLES):
        launcher=Mock()
        launcher.inventory={'plan':{'overlay_addresses':{r:a+'/32' for r,a in live.ADDRESSES.items()},'outer_udp_port':51820}}
        checks=live.LiveChecks(launcher,active_roles=active_roles)
        checks.healthy=Mock(); checks.renew=Mock(); checks.read=Mock()
        checks.probe_ports=Mock(return_value={p:124 for p in live.PORTS})
        checks.start_capture=Mock(return_value={'path':'/etc/wgmvp/check-capture-fixture'})
        checks.finish_capture=Mock(return_value={'syn':''})
        return launcher,checks

    def test_missing_receiver_delta_blocks_despite_nc_timeouts(self):
        launcher,checks=self.fixture()
        checks.table=Mock(side_effect=[guard(0),guard(0)])
        checks.probe_state=Mock(return_value=('token',0))
        result=checks.management_path('villa','cave')
        self.assertEqual(result['status'],'BLOCKED')
        closes=[call.args[0] for call in launcher.mutate.call_args_list if call.args[2]=='management-close']
        self.assertEqual(closes,['villa','gz'])

    def test_all_counters_required_and_receiver_change_blocks(self):
        launcher,checks=self.fixture()
        checks.table=Mock(side_effect=[guard(0),guard(5)])
        checks.probe_state=Mock(side_effect=[('same',0),('same',0)])
        result=checks.management_path('gz','villa')
        self.assertEqual(result['status'],'BLOCKED')
        self.assertIn('sender/transit',result['reason'])

    def test_partial_open_always_attempts_both_closes(self):
        launcher,checks=self.fixture()
        checks.table=Mock(return_value=guard())
        def mutate(role, body, action, delta, **kwargs):
            if action=='management-open' and role=='villa': raise live.wgmvp.Blocked('partial open')
            if action=='management-close' and role=='villa': raise live.wgmvp.Blocked('close drift')
        launcher.mutate.side_effect=mutate
        result=checks.management_path('villa','cave')
        self.assertEqual(result['status'],'BLOCKED')
        self.assertTrue(result['cleanup_errors'])
        closes=[call.args[0] for call in launcher.mutate.call_args_list if call.args[2]=='management-close']
        self.assertEqual(closes,['villa','gz'])

    def test_dry_run_never_constructs_launcher(self):
        with patch.object(live.wgmvp,'Launcher') as launcher, redirect_stdout(io.StringIO()):
            self.assertEqual(live.main(['management']),0)
            self.assertEqual(live.main(['restart']),0)
            self.assertEqual(live.main(['tunnel-down']),0)
            self.assertEqual(live.main(['firewall-reload']),0)
        launcher.assert_not_called()

    def test_lifecycle_restores_after_down_probe_failure(self):
        launcher,checks=self.fixture()
        checks.read=Mock(return_value='A'*43+'=')
        checks.assert_stopped=Mock(); checks.independent_management=Mock(); checks.positive_control=Mock()
        def failure(role): raise live.wgmvp.Blocked('capture unavailable')
        result=checks.lifecycle_path('villa',while_down=failure)
        self.assertEqual(result['status'],'BLOCKED')
        self.assertTrue(result['restored'])
        actions=[call.args[2] for call in launcher.mutate.call_args_list]
        self.assertEqual(actions,['check-stop','check-restore'])
        self.assertTrue(launcher.mutate.call_args_list[-1].kwargs['check_status'])

    def test_failed_restore_is_visible(self):
        launcher,checks=self.fixture()
        checks.read=Mock(return_value='A'*43+'=')
        checks.assert_stopped=Mock(); checks.independent_management=Mock(); checks.positive_control=Mock()
        def mutate(role,body,action,delta,**kwargs):
            if action=='check-restore': raise live.wgmvp.Blocked('configuration drift')
        launcher.mutate.side_effect=mutate
        result=checks.lifecycle_path('cave')
        self.assertFalse(result['restored'])
        self.assertEqual(result['status'],'BLOCKED')
        self.assertIn('configuration drift',result['restore_error'])

    def test_hub_service_restart_uses_only_project_unit(self):
        launcher,checks=self.fixture()
        checks.read=Mock(return_value='A'*43+'=')
        checks.assert_stopped=Mock(); checks.independent_management=Mock(); checks.positive_control=Mock()
        result=checks.lifecycle_path('gz')
        self.assertEqual(result['status'],'PASS')
        bodies=[call.args[1] for call in launcher.mutate.call_args_list]
        self.assertIn('systemctl restart wgmvp.service',bodies[1])
        self.assertEqual(len(bodies),3)

    def test_receiver_syn_capture_requires_every_port_and_exact_source(self):
        trace='\n'.join(f'12:00:00 IP 10.203.77.1.3456 > 10.203.77.2.{p}: Flags [S], seq 1' for p in live.PORTS)
        self.assertEqual(live.syn_ports(trace,'gz','villa'),sorted(live.PORTS))
        for missing in (trace.replace('.9090:','.9000:'), trace.replace('10.203.77.1.','10.203.77.3.')):
            with self.assertRaises(live.wgmvp.Blocked): live.syn_ports(missing,'gz','villa')

    def test_capture_script_is_valid_shell_without_execution(self):
        launcher,checks=self.fixture()
        capture=live.LiveChecks.start_capture(checks,'villa',{'plain':'icmp and dst net 10.203.77.0/29'})
        import subprocess
        body=launcher.mutate.call_args.args[1]
        result=subprocess.run(['sh','-n'],input=body,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('timeout -s INT -k 2 16 tcpdump',body)
        self.assertNotIn('nohup',body)
        self.assertIn("(trap '' HUP",body)
        self.assertIn('</dev/null 8>&- &',body)
        self.assertTrue(capture['path'].startswith('/etc/wgmvp/check-capture-'))

    def test_plaintext_leak_is_failed_and_capture_is_finished(self):
        _,checks=self.fixture()
        def read(role,script,label):
            if label=='down-unbound-probe':
                return 'WGMVP_BEGIN route\n\nWGMVP_END route 2\nWGMVP_BEGIN ping\nunreachable\nWGMVP_END ping 2\n'
            return ''
        checks.read=Mock(side_effect=read)
        checks.finish_capture=Mock(return_value={'plain':'synthetic plaintext echo'})
        with self.assertRaises(live.Failed): checks.down_probe('villa')
        checks.finish_capture.assert_called_once()

    def test_ended_capture_cannot_establish_no_plaintext(self):
        _,checks=self.fixture()
        checks.read=Mock(side_effect=live.wgmvp.Blocked('capture already ended'))
        with self.assertRaises(live.wgmvp.Blocked): checks.down_probe('villa')
        checks.finish_capture.assert_called_once()

    def test_capture_completion_requires_health_and_uses_portable_permissions(self):
        _,checks=self.fixture()
        token='12345678-1234-1234-1234-123456789abc'
        capture={'role':'villa','path':'/etc/wgmvp/check-capture-'+token,'token':token,
                 'filters':{'plain':'icmp'},'files':['scope','runner.log','done','plain.txt','plain.log','plain.rc']}
        def framed(drops=0):
            return ('WGMVP_BEGIN plain_trace\n\nWGMVP_END plain_trace 0\n'
                    f'WGMVP_BEGIN plain_log\n{drops} packets dropped by kernel\nWGMVP_END plain_log 0\n'
                    'WGMVP_BEGIN plain_rc\n124\nWGMVP_END plain_rc 0\n')
        checks.mutation_stdout=Mock(return_value=framed())
        self.assertEqual(live.LiveChecks.finish_capture(checks,capture),{'plain':''})
        body=checks.mutation_stdout.call_args.args[1]
        import subprocess
        self.assertEqual(subprocess.run(['sh','-n'],input=body,text=True,capture_output=True).returncode,0)
        self.assertNotIn('stat -c',body)
        self.assertLess(body.index('until [ -f "$d/done" ]'),body.index('exec 8>'))
        checks.mutation_stdout.return_value=framed(1)
        with self.assertRaises(live.wgmvp.Blocked): live.LiveChecks.finish_capture(checks,capture)

    def test_startup_failure_attempts_capture_cleanup(self):
        launcher,checks=self.fixture()
        launcher.mutate.side_effect=live.wgmvp.Blocked('readiness failed after spawn')
        checks.finish_capture=Mock(return_value={})
        with self.assertRaises(live.wgmvp.Blocked): live.LiveChecks.start_capture(checks,'villa',{'plain':'icmp'})
        checks.finish_capture.assert_called_once()

    def test_partial_management_never_reads_or_renews_villa(self):
        launcher,checks=self.fixture(('gz','cave'))
        checks.table=Mock(side_effect=[guard(0),guard(5)])
        checks.probe_state=Mock(side_effect=[('same',0),('same',5)])
        trace='\n'.join(f'12:00:00 IP 10.203.77.1.1234 > 10.203.77.3.{p}: Flags [S], seq 1' for p in live.PORTS)
        checks.finish_capture=Mock(return_value={'syn':trace})
        checks.save=Mock()
        result=checks.management()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['scope_status'],'PASS')
        self.assertEqual([(p['source'],p['receiver']) for p in result['paths']],[('gz','cave')])
        for method in (checks.healthy,checks.renew,checks.read,launcher.mutate):
            self.assertNotIn('villa',[call.args[0] for call in method.call_args_list])

    def test_partial_lifecycle_never_touches_villa(self):
        launcher,checks=self.fixture(('gz','cave'))
        checks.read=Mock(return_value='A'*43+'=')
        checks.assert_stopped=Mock(); checks.independent_management=Mock(); checks.positive_control=Mock(); checks.save=Mock()
        result=checks.restart()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['scope_status'],'PASS')
        self.assertEqual([p['role'] for p in result['paths']],['gz','cave'])
        self.assertEqual(checks.positive_pairs,(('gz','cave'),('cave','gz')))
        for method in (checks.healthy,checks.renew,checks.read,launcher.mutate):
            self.assertNotIn('villa',[call.args[0] for call in method.call_args_list])

    def test_partial_adapter_rejects_inactive_capture_before_mutation(self):
        launcher,checks=self.fixture(('gz','cave'))
        with self.assertRaises(live.wgmvp.Blocked): live.LiveChecks.start_capture(checks,'villa',{'plain':'icmp'})
        with self.assertRaises(live.wgmvp.Blocked): live.LiveChecks.read(checks,'villa','id -u','forbidden')
        with self.assertRaises(live.wgmvp.Blocked): live.LiveChecks.renew(checks,'villa')
        launcher.mutate.assert_not_called()
        launcher.remote.assert_not_called()

    def test_partial_hub_down_uses_only_cave_to_hub(self):
        _,checks=self.fixture(('gz','cave'))
        def read(role,script,label):
            self.assertIn(role,('gz','cave'))
            if label=='down-unbound-probe':
                self.assertIn('10.203.77.1',script)
                self.assertNotIn('10.203.77.2',script)
                return ('WGMVP_BEGIN route\n[{"dev":"wgmvp","prefsrc":"10.203.77.3"}]\nWGMVP_END route 0\n'
                        'WGMVP_BEGIN ping\n3 packets transmitted, 0 received\nWGMVP_END ping 1\n')
            return ''
        checks.read=Mock(side_effect=read)
        checks.finish_capture=Mock(return_value={'plain':'','outer':'packet1\npacket2\npacket3'})
        result=checks.down_probe('gz')
        self.assertEqual(set(result['attempts']),{'cave'})
        self.assertEqual(result['encrypted_packets'],3)


if __name__=='__main__': unittest.main()
