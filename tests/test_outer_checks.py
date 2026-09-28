"""Offline packet attribution and scoped cleanup tests; no network calls."""
from contextlib import redirect_stdout
import base64
import copy
import io
import os
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import outer_checks as outer

NONCE = 'a'*32
KEY = 'A'*43+'='


def pcap(records=(), link=101, order='<'):
    magic = b'\xd4\xc3\xb2\xa1' if order == '<' else b'\xa1\xb2\xc3\xd4'
    result = magic + struct.pack(order+'HHIIII', 2, 4, 0, 0, 128, link)
    for protocol, sport, dport, payload in records:
        transport = (struct.pack('!HHHH', sport, dport, len(payload)+8, 0)+payload
                     if protocol == 17 else struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 80, 2, 10, 0, 0))
        ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20+len(transport), 0, 0, 64, protocol, 0,
                         socket.inet_aton('192.0.2.9'), socket.inet_aton(outer.PUBLIC))+transport
        header = {101:b'', 228:b'', 1:b'\0'*12+b'\x08\0',
                  113:b'\0'*14+b'\x08\0', 276:b'\x08\0'+b'\0'*18}[link]
        frame=header+ip
        result += struct.pack(order+'IIII', 1, 0, min(len(frame),128), len(frame))+frame[:128]
    return result


def external_packets():
    prefix=('WGMVP-OUTER-'+NONCE).encode()
    records=[(17, 33000, outer.PORT, prefix+bytes([i])) for i in range(3)]
    records += [(6, 33001+i, port, b'') for i,port in enumerate(outer.TCP_PORTS)]
    return outer.packets(pcap(records))


class OuterCheckTests(unittest.TestCase):
    def fixture(self, routers=()):
        launcher=Mock()
        launcher.inventory={'plan': {'overlay_addresses': {r:a+'/32' for r,a in outer.live_checks.ADDRESSES.items()},
                                     'gz_public_ipv4':outer.PUBLIC, 'outer_udp_port':outer.PORT}}
        directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        launcher.run_dir=Path(directory.name)
        checks=outer.OuterChecks(launcher, routers)
        return launcher, checks

    def test_capture_transport_without_base64(self):
        raw = pcap([(17, 1234, outer.PORT, b'test')])
        for encoder in ('od', 'hexdump'):
            with self.subTest(encoder=encoder), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                (folder / 'capture.pcap').write_bytes(raw)
                (folder / encoder).symlink_to(shutil.which(encoder))
                result = subprocess.run(['/bin/sh', '-c', outer.CAPTURE_ENCODER + '\nencode_capture "$1"',
                                         'test', str(folder / 'capture.pcap')], text=True, capture_output=True,
                                        env={**os.environ, 'PATH': directory})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith('WGMVP_HEX\n'))
                self.assertEqual(outer.capture_bytes(result.stdout), raw)
        self.assertEqual(outer.capture_bytes(base64.b64encode(raw).decode()), raw)
        for malformed in ('WGMVP_HEX\n0', 'WGMVP_HEX\nzz', 'WGMVP_HEX\n00' * (outer.CAPTURE_MAX_BYTES + 1)):
            with self.assertRaises(outer.wgmvp.Blocked): outer.capture_bytes(malformed)

    def test_encoder_preflight_fails_before_lock_or_capture_creation(self):
        launcher, checks = self.fixture()
        capture = checks.capture_descriptor('gz', {'outer': ('host', 'udp port 51820')})
        checks.start_outer_capture(capture)
        body = launcher.mutate.call_args.args[1]
        preflight = body[:body.index('exec 8>')]
        self.assertIn('encode_capture /dev/null', preflight)
        self.assertNotIn('mkdir', preflight)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['/bin/sh', '-c', preflight + '\nprintf started'],
                                    text=True, capture_output=True, env={**os.environ, 'PATH': directory})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('No supported capture encoder', result.stderr)

    def test_failed_collection_preserves_every_owned_file(self):
        launcher, checks = self.fixture()
        capture = checks.capture_descriptor('gz', {'outer': ('host', 'udp port 51820')})
        encoded = base64.b64encode(pcap()).decode()
        checks.mutation_stdout = Mock(return_value=''.join(
            f'WGMVP_BEGIN outer_{part}\n{value}\nWGMVP_END outer_{part} 0\n'
            for part, value in [('pcap', encoded), ('log', 'listening on any\n0 packets dropped by kernel'), ('rc', '0')]))
        checks.finish_outer_capture(capture)
        body = checks.mutation_stdout.call_args.args[1]
        tail = body[body.index(outer.CAPTURE_ENCODER):]
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            evidence = folder / 'evidence'
            evidence.mkdir()
            expected = ['scope', 'outer.pid', 'outer.pcap', 'outer.log', 'outer.rc', 'outer.runner']
            for filename in expected:
                (evidence / filename).write_bytes(pcap() if filename.endswith('.pcap') else b'fixture')
            failing = folder / 'base64'
            failing.write_text('#!/bin/sh\nprintf partial\nexit 7\n')
            failing.chmod(0o700)
            script = 'd=' + str(evidence) + '\n' + tail.replace(capture['path'], str(evidence))
            result = subprocess.run(['/bin/sh', '-c', script], text=True, capture_output=True,
                                    env={**os.environ, 'PATH': directory + ':' + os.environ['PATH']})
            self.assertEqual(result.returncode, 1)
            self.assertEqual(outer.acceptance.parse_probes(result.stdout)['outer_pcap']['returncode'], 7)
            self.assertEqual(sorted(p.name for p in evidence.iterdir()), sorted(expected))
            self.assertIn('owned evidence preserved', result.stderr)

    def test_capture_formats_and_bounds(self):
        for order in ('<','>'):
            for link in (1,101,113,228,276):
                records=outer.packets(pcap([(17,1234,outer.PORT,b'test')],link,order))
                self.assertEqual(records[0]['payload'],b'test')
                self.assertEqual(records[0]['src'],'192.0.2.9')
        for invalid in (b'',pcap()+b'1',pcap([(17,1,2,b'abc')])[:-1],
                        pcap([(17,1,2,b'abc')])*2):
            with self.assertRaises(outer.wgmvp.Blocked): outer.packets(invalid)

    def test_unknown_evidence_matches_index_across_nat(self):
        payload=b'\1\0\0\0'+b'abcd'+b'\0'*140
        outbound=outer.packets(pcap([(17,44123,outer.PORT,payload)]))
        arrivals=outer.packets(pcap([(17,59999,outer.PORT,payload)]))
        self.assertEqual(outer.unknown_arrivals(outbound,arrivals,44123),1)
        for bad in ([],outer.packets(pcap([(17,59999,outer.PORT,payload[:4]+b'efgh'+payload[8:])]))):
            with self.assertRaises(outer.wgmvp.Blocked): outer.unknown_arrivals(outbound,bad,44123)
        with self.assertRaises(outer.wgmvp.Blocked): outer.unknown_arrivals(outbound,arrivals,44124)

    def test_unknown_report_requires_fresh_marker_and_zero_handshake(self):
        report=f'FRESH_UNREGISTERED_PUBLIC_KEY {KEY}\nUNKNOWN_KEY_LISTEN_PORT 41000\nUNKNOWN_KEY_PING_EXIT 1\n{KEY}\t0\n'
        self.assertEqual(outer.unknown_report(report,KEY)['listen_port'],41000)
        for bad in (report.replace('\t0','\t7'),report+f'FRESH_UNREGISTERED_PUBLIC_KEY {KEY}\n',
                    report.replace('PING_EXIT 1','PING_EXIT 0'),report.replace('PORT 41000','PORT 0')):
            with self.assertRaises(outer.wgmvp.Blocked): outer.unknown_report(bad,KEY)

    def test_external_evidence_requires_all_datagrams_and_both_tcp_ports(self):
        good=external_packets()
        self.assertEqual(outer.external_arrivals(good,NONCE)['tcp_syn_ports'],list(outer.TCP_PORTS))
        for bad in (good[1:],good[:-1], [{**p,'src':'192.0.2.10'} if p['protocol']==6 else p for p in good]):
            with self.assertRaises(outer.wgmvp.Blocked): outer.external_arrivals(bad,NONCE)
        with self.assertRaises(outer.wgmvp.Blocked): outer.external_arrivals(good,'b'*32)

    def test_local_probe_is_five_bounded_owned_endpoint_actions(self):
        clients=[Mock() for _ in range(3)]
        for client in clients:
            client.__enter__=Mock(return_value=client); client.__exit__=Mock(return_value=False)
            client.connect_ex.return_value=111
            client.sendto.side_effect=lambda payload,target: len(payload)
            client.recv.return_value=b''
        with patch.object(outer.socket,'socket',side_effect=clients) as factory, patch.object(outer.time,'sleep'):
            result=outer.local_probes(NONCE)
        self.assertEqual(result['udp_sent'],3)
        self.assertEqual(factory.call_count,3)
        for client,port in zip(clients,outer.TCP_PORTS):
            client.connect_ex.assert_called_once_with((outer.PUBLIC,port)); client.settimeout.assert_called_once_with(2)
        self.assertEqual(len(clients[2].sendto.call_args_list),3)
        for call in clients[2].sendto.call_args_list:
            self.assertEqual(call.args[1],(outer.PUBLIC,outer.PORT)); self.assertEqual(len(call.args[0]),45)
        clients[0].connect_ex.return_value=0
        clients[2].sendto.reset_mock()
        with patch.object(outer.socket,'socket',side_effect=clients), patch.object(outer.time,'sleep'):
            result=outer.local_probes(NONCE)
        self.assertEqual(result['tcp'][str(outer.PORT)],0)
        self.assertEqual(result['udp_sent'],3)
        self.assertEqual(clients[2].sendto.call_count,3)
        clients[0].sendall.assert_called_once_with(('WGMVP-PROBE-'+NONCE).encode())
        clients[0].recv.assert_called_once_with(1)
        self.assertLessEqual(result['tcp_io'][str(outer.PORT)]['sent_bytes'],64)

    def test_local_acceptance_without_gz_response_is_inconclusive(self):
        report={}
        with self.assertRaises(outer.wgmvp.Blocked) as raised:
            outer.external_arrivals(external_packets(),NONCE,{'tcp':{'51820':0,'52080':111}},report)
        self.assertNotIsInstance(raised.exception,outer.Failed)
        self.assertEqual(report['udp_datagrams'],3)
        self.assertEqual(report['tcp_synack_ports'],[])
        self.assertEqual(report['local_accepted_ports'],[51820])

    def test_gz_failure_requires_outgoing_matching_synack_and_ack_number(self):
        observed=external_packets()
        syn=observed[-2]
        reply={'src':syn['dst'],'dst':syn['src'],'sport':syn['dport'],'dport':syn['sport'],
               'protocol':6,'flags':0x12,'direction':'out','acknowledgment':syn['sequence']+1}
        with self.assertRaises(outer.Failed): outer.external_arrivals(observed+[reply],NONCE)
        for change in ({'direction':'in'},{'acknowledgment':50},{'dport':123},{'flags':0x14}):
            result=outer.external_arrivals(observed+[{**reply,**change}],NONCE)
            self.assertEqual(result['tcp_synack_ports'],[])
        # A proxy may accept locally before the actual gz endpoint refuses.
        report=outer.external_arrivals(observed+[{**reply,'flags':0x14}],NONCE,{'tcp':{'51820':0,'52080':111}})
        self.assertEqual(report['tcp_reset_ports'],[51820])

    def test_linux_cooked_direction_is_decoded(self):
        raw=bytearray(pcap([(6,51820,4444,b'')],link=276))
        raw[24+16+10]=4
        self.assertEqual(outer.packets(bytes(raw))[0]['direction'],'out')
        self.assertEqual(outer.packets(pcap([(6,51820,4444,b'')],link=276))[0]['direction'],'in')

    def test_selected_scope_and_dry_run(self):
        _,checks=self.fixture()
        checks.healthy=Mock(); checks.renew=Mock(); checks.positive_scope=Mock()
        checks.prepare()
        self.assertEqual(checks.roles,('gz',))
        checks.healthy.assert_called_once_with('gz'); checks.renew.assert_called_once_with('gz')
        with self.assertRaises(outer.wgmvp.Blocked): checks.run_check('unknown-key','cave')
        with patch.object(outer.wgmvp,'Launcher') as launcher, patch.object(outer.socket,'socket') as sock, redirect_stdout(io.StringIO()):
            self.assertEqual(outer.main(['external','--routers']),0)
        launcher.assert_not_called(); sock.assert_not_called()

    def test_capture_shell_and_exact_owned_cleanup(self):
        launcher,checks=self.fixture()
        capture=checks.capture_descriptor('gz',{'outer':('host','udp dst port 51820'),'inner':('wgmvp','ip and (tcp or udp)')})
        checks.start_outer_capture(capture)
        start=launcher.mutate.call_args.args[1]
        self.assertEqual(subprocess.run(['sh','-n'],input=start,text=True,capture_output=True).returncode,0)
        self.assertIn('timeout -s INT -k 2 50',start)
        self.assertIn('exec ip netns exec wgmvp tcpdump',start)
        self.assertIn('exec 8>&-',start)
        self.assertNotIn('nohup',start)
        self.assertIn("(trap '' HUP",start)
        self.assertIn('</dev/null 8>&- &',start)
        self.assertIn('/proc/$$/stat',start)
        encoded=base64.b64encode(pcap()).decode()
        def evidence(drops=0):
            return ''.join(f'WGMVP_BEGIN {name}_{part}\n{value}\nWGMVP_END {name}_{part} 0\n'
                           for name in capture['specs'] for part,value in
                           [('pcap',encoded),('log',f'listening on any\n0 packets captured\n{drops} packets dropped by kernel'),('rc','0')])
        checks.mutation_stdout=Mock(return_value=evidence())
        self.assertEqual(checks.finish_outer_capture(capture),{'outer':[],'inner':[]})
        finish=checks.mutation_stdout.call_args.args[1]
        self.assertEqual(subprocess.run(['sh','-n'],input=finish,text=True,capture_output=True).returncode,0)
        self.assertIn('[ "$current" = "$original" ]',finish)
        self.assertIn('kill -INT "$pid"',finish)
        self.assertNotIn('rm -r',finish); self.assertNotIn('pkill',finish); self.assertNotIn('stat -c',finish)
        self.assertLess(finish.index('exec 8>&-'),finish.index('until [ -f "$d/outer.rc" ]'))
        self.assertEqual(finish.count('flock -x -n 8'),4)  # Scope, two signals, final owned removal.
        for name in ('outer','inner'):
            signal=finish.index(f'safe_file "$d/{name}.pid"')
            self.assertGreater(finish.rfind('flock -x -n 8',0,signal),finish.rfind('exec 8>&-',0,signal))
        removal=finish.index('\nrm ')
        self.assertGreater(finish.rfind('flock -x -n 8',0,removal),finish.rfind('exec 8>&-',0,removal))
        checks.mutation_stdout.return_value=evidence(1)
        with self.assertRaises(outer.wgmvp.Blocked): checks.finish_outer_capture(capture)

    def test_partial_capture_start_is_cleaned_and_blocks(self):
        launcher,checks=self.fixture()
        checks.prepare=Mock(); checks.peer_state=Mock(return_value=({'gz':KEY},{'B'*43+'='}))
        checks.start_outer_capture=Mock(side_effect=outer.wgmvp.Blocked('partial capture'))
        checks.finish_outer_capture=Mock(return_value={'outer':[],'inner':[]})
        result=checks.run_check('external')
        self.assertEqual(result['status'],'BLOCKED'); checks.finish_outer_capture.assert_called_once()
        self.assertIn('NOT_RUN',result['authorized_positive_control'])

    def test_capture_custom_decoder_and_bounds(self):
        launcher,checks=self.fixture()
        for limits in ({'packet_limit':2049},{'duration':61},{'packet_limit':True},{'duration':0}):
            with self.assertRaises(outer.wgmvp.Blocked):
                checks.capture_descriptor('gz',{'outer':('host','ip')},**limits)
        capture=checks.capture_descriptor('gz',{'outer':('host','ip')},packet_limit=2048,duration=60)
        checks.start_outer_capture(capture)
        body=launcher.mutate.call_args.args[1]
        self.assertIn('-c 2048',body); self.assertIn('timeout -s INT -k 2 60',body)
        self.assertIn('tick+75',body)
        raw=b'caller-decodes-and-validates'
        encoded=base64.b64encode(raw).decode()
        checks.mutation_stdout=Mock(return_value=''.join(
            f'WGMVP_BEGIN outer_{part}\n{value}\nWGMVP_END outer_{part} 0\n'
            for part,value in [('pcap',encoded),('log','listening on any\n0 packets dropped by kernel'),('rc','0')]))
        decode=Mock(return_value=['decoded'])
        self.assertEqual(checks.finish_outer_capture(capture,decode=decode),{'outer':['decoded']})
        decode.assert_called_once_with(raw)

    def test_gz_only_external_can_pass_without_claiming_router_health(self):
        launcher,checks=self.fixture()
        checks.prepare=Mock(); checks.peer_state=Mock(return_value=({'gz':KEY},{'B'*43+'='}))
        checks.start_outer_capture=Mock(); checks.capture_covering=Mock()
        checks.finish_outer_capture=Mock(return_value={'outer':external_packets(),'inner':[]})
        checks.positive_scope=Mock(); checks.healthy=Mock(); checks.read=Mock(return_value='0\n')
        with patch.object(outer,'local_probes',return_value={'udp_sent':3}),patch.object(outer.uuid,'uuid4',return_value=Mock(hex=NONCE)):
            result=checks.run_check('external')
        self.assertEqual(result['status'],'PASS',result)
        self.assertIn('NOT_RUN',result['authorized_positive_control'])
        checks.healthy.assert_called_once_with('gz'); launcher.recovery.assert_called_once()

    def test_cloud_tcp_denial_rejects_every_permissive_or_ambiguous_tcp_form(self):
        rule={'SecurityGroupRuleId':'sgr-fixture','Direction':'ingress','Policy':'Accept','IpProtocol':'TCP','PortRange':'443/443'}
        def document(r):return {'Permissions':{'Permission':[r]}}
        self.assertEqual(outer.cloud_tcp_denial(document(rule))['denied_tcp_ports'],list(outer.TCP_PORTS))
        for change in ({'IpProtocol':'ALL'},{'IpProtocol':'unknown'},{'PortRange':'51820/51820'},
                       {'PortRange':'52000/53000'},{'PortRange':'-1/-1'},{'PortRange':''},
                       {'PortRange':'0/65535'},{'PortRange':'500/1'},{'PortRangeListId':'prl-fixture'},
                       {'Policy':'unknown'},{'Direction':''}):
            with self.subTest(change=change),self.assertRaises(outer.wgmvp.Blocked):
                outer.cloud_tcp_denial(document({**rule,**change}))
        # A selected-port allowance blocks even if its source looks restrictive
        # or an earlier drop might override it; this proof does not evaluate that.
        with self.assertRaises(outer.wgmvp.Blocked):
            outer.cloud_tcp_denial(document({**rule,'PortRange':'51820/51820','SourceCidrIp':'192.0.2.1/32'}))
        for change in ({'Direction':'egress','PortRange':'51820/51820'},
                       {'Policy':'Drop','PortRange':'51820/51820'},{'IpProtocol':'UDP','PortRange':'51820/51820'}):
            outer.cloud_tcp_denial(document({**rule,**change}))

    def external_fixture(self,traces):
        launcher,checks=self.fixture()
        checks.prepare=Mock();checks.peer_state=Mock(return_value=({'gz':KEY},{'B'*43+'='}))
        checks.start_outer_capture=Mock();checks.capture_covering=Mock()
        checks.finish_outer_capture=Mock(return_value=traces)
        checks.positive_scope=Mock();checks.healthy=Mock();checks.read=Mock(return_value='0\n')
        checks.cloud_denial=Mock(return_value={'denied_tcp_ports':list(outer.TCP_PORTS),'baseline_unchanged':True})
        return launcher,checks

    def external_result(self,checks):
        with patch.object(outer,'local_probes',return_value={'tcp':{'51820':0,'52080':0},'udp_sent':3}), \
             patch.object(outer.uuid,'uuid4',return_value=Mock(hex=NONCE)):
            return checks.run_check('external')

    def test_fresh_cloud_denial_plus_three_udp_arrivals_can_prove_s02(self):
        _,checks=self.external_fixture({'outer':external_packets()[:3],'inner':[]})
        result=self.external_result(checks)
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['arrivals']['tcp_syn_ports'],[])
        self.assertIn('cloud ingress denial',result['arrivals']['basis'])
        self.assertEqual(result['arrivals']['udp_datagrams'],3)
        self.assertIn('NOT_RUN',result['authorized_positive_control'])
        checks.cloud_denial.assert_called_once()

    def test_missing_udp_capture_or_cloud_failure_never_becomes_pass(self):
        for udp in ([],external_packets()[:2]):
            _,checks=self.external_fixture({'outer':udp,'inner':[]})
            self.assertEqual(self.external_result(checks)['status'],'BLOCKED')
            checks.cloud_denial.assert_not_called()
        _,checks=self.external_fixture({'outer':external_packets()[:3],'inner':[]})
        checks.cloud_denial.side_effect=outer.wgmvp.Blocked('live cloud policy differs')
        self.assertEqual(self.external_result(checks)['status'],'BLOCKED')

    def test_cloud_denial_cannot_override_inner_or_matching_synack_failure(self):
        observed=external_packets();syn=observed[-2]
        reply={'src':syn['dst'],'dst':syn['src'],'sport':syn['dport'],'dport':syn['sport'],
               'protocol':6,'flags':0x12,'direction':'out','acknowledgment':syn['sequence']+1}
        for trace in ({'outer':observed,'inner':[{'protocol':17}]},{'outer':observed+[reply],'inner':[]}):
            _,checks=self.external_fixture(trace)
            self.assertEqual(self.external_result(checks)['status'],'FAIL')
            checks.cloud_denial.assert_not_called()
        # A response that cannot be attributed still prevents cloud-only PASS.
        _,checks=self.external_fixture({'outer':observed[:3]+[reply],'inner':[]})
        self.assertEqual(self.external_result(checks)['status'],'BLOCKED')
        checks.cloud_denial.assert_not_called()

    def test_cloud_path_performs_fresh_mapping_and_full_rule_inspection(self):
        import cloud_gate
        launcher,checks=self.fixture()
        plan={'mapping':{'instance_id':'fixture'}}
        current={'Permissions':{'Permission':[{'SecurityGroupRuleId':'sgr-fixture','Direction':'ingress',
                 'Policy':'Accept','IpProtocol':'TCP','PortRange':'443/443'}]}}
        gate=Mock();gate.load_plan.return_value=plan;gate.read.return_value=current
        gate.state.return_value={'token':'fixture'};gate.inspect.return_value={'SecurityGroupRuleId':'sgr-owned'}
        with patch.object(cloud_gate,'CloudGate',return_value=gate) as factory:
            proof=checks.cloud_denial()
        factory.assert_called_once_with(launcher);gate.read.assert_called_once_with(plan)
        gate.inspect.assert_called_once_with(plan,current,{'token':'fixture'})
        self.assertTrue(Path(proof['evidence_file']).is_file())
        self.assertEqual(proof['security_group_sha256'],cloud_gate.digest(current))
        gate.read.side_effect=outer.wgmvp.Blocked('instance or sole-membership changed')
        gate.inspect.reset_mock()
        with patch.object(cloud_gate,'CloudGate',return_value=gate),self.assertRaises(outer.wgmvp.Blocked):
            checks.cloud_denial()
        gate.inspect.assert_not_called()


if __name__ == '__main__': unittest.main()
