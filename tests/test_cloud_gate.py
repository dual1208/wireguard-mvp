"""Offline exact-rule cloud transaction tests; never invokes a cloud CLI."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import cloud_gate as cloud


def instance():
    return {'TotalCount':1,'Instances':{'Instance':[{'RegionId':cloud.REGION,'InstanceId':'i-test',
        'InstanceNetworkType':'vpc','PublicIpAddress':{'IpAddress':[cloud.PUBLIC]},
        'VpcAttributes':{'PrivateIpAddress':{'IpAddress':['172.22.166.84']},'VpcId':'vpc-test'},
        'SecurityGroupIds':{'SecurityGroupId':['sg-test']}}]}}


def group():
    return {'RegionId':cloud.REGION,'SecurityGroupId':'sg-test','VpcId':'vpc-test','InnerAccessPolicy':'Accept',
        'RequestId':'volatile','Permissions':{'Permission':[{'SecurityGroupRuleId':'sgr-existing',
        'IpProtocol':'TCP','PortRange':'721/721','SourceCidrIp':'0.0.0.0/0','DestCidrIp':'',
        'Policy':'Accept','Priority':100,'NicType':'intranet','Direction':'ingress','Description':'existing SSH'}]}}


class CloudGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.local=Path(self.temp.name);(self.local/'audit').mkdir(mode=0o700);(self.local/'run').mkdir(mode=0o700)
        self.launcher=Mock(local=self.local,run_dir=self.local/'run',inventory={'plan':{'gz_public_ipv4':cloud.PUBLIC,'outer_udp_port':51820}})
        self.launcher.remote.return_value={'returncode':0,'timeout':False,'stdout':''}
        self.instance=instance();self.group=group();self.calls=[];self.serial=0;self.lose_add=False
        for name,value in [('ecs-gz-instances.json',self.instance),('ecs-group-members.json',self.instance),('ecs-gz-security-group.json',self.group)]:
            cloud.wgmvp.json_write(self.local/'audit'/name,value)
        self.gate=cloud.CloudGate(self.launcher,runner=self.run_api)
        self.gate.plan()

    def run_api(self,argv,**kwargs):
        self.calls.append(argv);action=argv[2];params=dict(zip(argv[3::2],argv[4::2]))
        self.assertEqual(params['--profile'],'tyson');self.assertEqual(params['--region'],cloud.REGION)
        self.assertEqual(params['--RegionId'],cloud.REGION);self.assertFalse(kwargs.get('shell',False))
        if action=='DescribeInstances':result=copy.deepcopy(self.instance)
        elif action=='DescribeSecurityGroupAttribute':result=copy.deepcopy(self.group)
        elif action=='AuthorizeSecurityGroup':
            self.serial+=1
            rule={k.removeprefix('--Permissions.1.'):v for k,v in params.items() if k.startswith('--Permissions.1.')}
            rule.update(SecurityGroupRuleId='sgr-own'+str(self.serial),Direction='ingress',Priority=int(rule['Priority']))
            self.group['Permissions']['Permission'].append(rule);result={'RequestId':'added'}
            if self.lose_add:raise subprocess.TimeoutExpired(argv,40)
        elif action=='RevokeSecurityGroup':
            target=params['--SecurityGroupRuleId.1']
            self.group['Permissions']['Permission']=[p for p in self.group['Permissions']['Permission'] if p['SecurityGroupRuleId']!=target]
            result={'RequestId':'removed'}
        else:self.fail('unexpected API')
        return subprocess.CompletedProcess(argv,0,json.dumps(result),'')

    def writes(self):return [a for a in self.calls if a[2] in ('AuthorizeSecurityGroup','RevokeSecurityGroup')]

    def test_plan_has_no_cloud_calls_and_is_private(self):
        self.assertEqual(self.calls,[])
        self.assertEqual((self.local/'cloud-plan.json').stat().st_mode&0o777,0o600)
        plan=self.gate.plan();self.assertEqual(plan['delta']['DestCidrIp'],'172.22.166.84/32')
        self.assertEqual(plan['delta']['IpProtocol'],'udp')
        self.assertEqual(plan['delta']['PortRange'],'51820/51820')

    def test_add_idempotent_revoke_readd_preserves_other_permissions(self):
        before=copy.deepcopy(self.group['Permissions']['Permission'])
        self.assertTrue(self.gate.apply()['changed']);self.assertFalse(self.gate.apply()['changed'])
        self.assertEqual(self.gate.status()['status'],'PRESENT')
        self.assertTrue(self.gate.rollback()['changed']);self.assertFalse(self.gate.remove()['changed'])
        self.assertEqual(self.group['Permissions']['Permission'],before)
        self.assertTrue(self.gate.apply()['changed'])
        self.assertEqual([a[2] for a in self.writes()],['AuthorizeSecurityGroup','RevokeSecurityGroup','AuthorizeSecurityGroup'])
        revoke=self.writes()[1]
        self.assertIn('--SecurityGroupRuleId.1',revoke);self.assertNotIn('--IpProtocol',revoke)
        self.assertEqual(self.launcher.preflight.call_count,3)
        self.assertEqual(self.launcher.recovery.call_count,3)
        self.assertEqual(self.launcher.remote.call_count,2)

    def test_foreign_drift_blocks_add_and_delete(self):
        for adding in (True,False):
            with self.subTest(adding=adding):
                if not adding:self.gate.apply()
                self.group['Permissions']['Permission'][0]['PortRange']='22/22'
                before=len(self.writes())
                with self.assertRaises(cloud.wgmvp.Blocked):getattr(self.gate,'apply' if adding else 'rollback')()
                self.assertEqual(len(self.writes()),before)
                self.group['Permissions']['Permission'][0]['PortRange']='721/721'

    def test_mapping_drift_and_shared_group_block(self):
        for field in ('public','membership'):
            original=copy.deepcopy(self.instance)
            if field=='public':self.instance['Instances']['Instance'][0]['PublicIpAddress']['IpAddress']=['192.0.2.1']
            else:self.instance['TotalCount']=2
            with self.assertRaises(cloud.wgmvp.Blocked):self.gate.apply()
            self.instance=original
        self.assertEqual(self.writes(),[])

    def test_owned_rule_tampering_and_replaced_id_block_revoke(self):
        self.gate.apply();rule=self.group['Permissions']['Permission'][-1]
        for field,value in [('DestCidrIp','0.0.0.0/0'),('IpProtocol','tcp'),('PortRange','1/65535'),('SecurityGroupRuleId','sgr-replaced')]:
            old=rule[field];rule[field]=value
            with self.assertRaises(cloud.wgmvp.Blocked):self.gate.rollback()
            rule[field]=old
        self.assertEqual(len(self.writes()),1)

    def test_lost_add_response_reconciles_exact_tag_and_binds_id(self):
        self.lose_add=True
        with self.assertRaisesRegex(cloud.wgmvp.Blocked, 'timed out'):self.gate.apply()
        self.assertIsNone(self.gate.state()['rule_id'])
        self.lose_add=False
        self.assertFalse(self.gate.apply()['changed'])
        self.assertEqual(self.gate.state()['rule_id'],'sgr-own1')
        self.assertEqual(len(self.writes()),1)
        self.gate.rollback();self.assertEqual(self.group['Permissions']['Permission'],group()['Permissions']['Permission'])

    def test_host_gate_and_last_moment_drift_block_writes(self):
        self.launcher.remote.return_value={'returncode':1,'timeout':False}
        with self.assertRaises(cloud.wgmvp.Blocked):self.gate.apply()
        self.assertEqual(self.writes(),[])
        self.launcher.remote.return_value={'returncode':0,'timeout':False}
        self.launcher.recovery.side_effect=lambda:self.group.update(InnerAccessPolicy='Drop')
        with self.assertRaises(cloud.wgmvp.Blocked):self.gate.apply()
        self.assertEqual(self.writes(),[])

    def test_cloud_errors_do_not_print_or_persist_authentication_diagnostics(self):
        gate=cloud.CloudGate(self.launcher,runner=Mock(return_value=subprocess.CompletedProcess([],1,'secret diagnostic','secret diagnostic')))
        with self.assertRaises(cloud.wgmvp.Blocked) as exc:gate.status()
        self.assertNotIn('secret diagnostic',str(exc.exception))
        self.assertFalse(list((self.local/'run').glob('cloud-*')))

    def test_failed_listener_inspection_is_not_an_empty_listener_set(self):
        self.gate.apply()
        script=self.launcher.remote.call_args.args[1]
        guard=script[script.index('listeners='):]
        for body,expected in [('return 1',1),('return 0',0),('printf listener',1)]:
            result=subprocess.run(['sh','-c','set -eu\nss() { '+body+'; }\n'+guard],capture_output=True,text=True)
            self.assertEqual(result.returncode,expected)

    def test_cli_default_never_connects(self):
        with patch.object(cloud.wgmvp,'Launcher') as launcher,redirect_stdout(io.StringIO()):
            for action in ('apply','rollback','remove'):self.assertEqual(cloud.main([action]),0)
        launcher.assert_not_called()


if __name__=='__main__':unittest.main()
