#!/usr/bin/env python3
"""Exact owned ECS UDP ingress. Planning is local; writes require --apply."""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

import wgmvp

OWNER = 'wgmvp-r1'
PROFILE = 'tyson'
REGION = 'cn-guangzhou'
PUBLIC = '8.163.2.191'
RULE_ID = re.compile(r'sgr-[a-zA-Z0-9]+\Z')
TOKEN = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')


def require(value, reason):
    if not value: raise wgmvp.Blocked(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def private_json(path):
    require(path.is_file() and not path.is_symlink(), 'missing or unsafe private cloud file: '+str(path))
    st=path.stat()
    require(st.st_uid==os.getuid() and not st.st_mode&0o077 and st.st_nlink==1, 'cloud file must be private and singly linked: '+str(path))
    return json.loads(path.read_text())


def instance_mapping(document):
    rows=document.get('Instances',{}).get('Instance',[])
    require(document.get('TotalCount')==1 and not document.get('NextToken') and len(rows)==1, 'cloud instance/membership query must identify exactly one instance')
    row=rows[0]
    public=row.get('PublicIpAddress',{}).get('IpAddress',[])
    private=row.get('VpcAttributes',{}).get('PrivateIpAddress',{}).get('IpAddress',[])
    groups=row.get('SecurityGroupIds',{}).get('SecurityGroupId',[])
    require(row.get('RegionId')==REGION and public==[PUBLIC] and len(private)==1 and len(groups)==1, 'unreviewed instance address/region/security-group mapping')
    require(ipaddress.ip_address(private[0]).version==4 and ipaddress.ip_address(private[0]).is_private, 'expected one private IPv4 address')
    require(row.get('InstanceNetworkType')=='vpc' and row.get('InstanceId','').startswith('i-'), 'expected VPC ECS instance')
    return {'instance_id':row['InstanceId'],'public_ipv4':PUBLIC,'private_ipv4':private[0],
            'security_group_id':groups[0],'vpc_id':row['VpcAttributes']['VpcId'],'region':REGION}


def canonical_group(document):
    require(not document.get('NextToken'), 'security-group response is paginated; no write allowed')
    result=copy.deepcopy(document)
    for key in ('RequestId','NextToken','MaxResults','TotalCount'):result.pop(key,None)
    permissions=result.get('Permissions',{}).get('Permission')
    require(isinstance(permissions,list), 'missing security-group permissions')
    ids=[p.get('SecurityGroupRuleId','') for p in permissions]
    require(all(RULE_ID.fullmatch(i) for i in ids) and len(set(ids))==len(ids), 'missing/duplicate native security-group rule IDs')
    result['Permissions']['Permission']=sorted(permissions,key=lambda p:p['SecurityGroupRuleId'])
    return result


def desired(plan,token):
    return {'IpProtocol':'udp','PortRange':'51820/51820','SourceCidrIp':'0.0.0.0/0',
            'DestCidrIp':plan['mapping']['private_ipv4']+'/32','Policy':'accept','Priority':'1',
            'NicType':'intranet','Description':OWNER+':udp51820:'+token}


def exact_rule(rule,plan,token):
    wanted=desired(plan,token)
    require(rule.get('Direction','').lower()=='ingress' and RULE_ID.fullmatch(rule.get('SecurityGroupRuleId','')), 'owned cloud rule direction/ID differs')
    for key,value in wanted.items():
        actual=str(rule.get(key,''))
        require((actual.lower() if key in ('IpProtocol','Policy','NicType') else actual)==value, 'owned cloud rule differs: '+key)
    for key in ('Ipv6SourceCidrIp','Ipv6DestCidrIp','SourceGroupId','DestGroupId','SourcePrefixListId','DestPrefixListId','PortRangeListId','SourcePortRange'):
        require(not rule.get(key), 'owned cloud rule has an unexpected selector: '+key)


class CloudGate:
    """Caller holds the existing coordinator lock; no host mutation is made."""
    def __init__(self,launcher,*,runner=subprocess.run):
        self.launcher=launcher; self.local=launcher.local; self.runner=runner
        self.plan_path=self.local/'cloud-plan.json'; self.directory=self.local/'cloud'
        self.state_path=self.directory/'state.json'; self.sequence=0

    def plan(self):
        inputs={name:private_json(self.local/'audit'/name) for name in
                ('ecs-gz-instances.json','ecs-gz-security-group.json','ecs-group-members.json')}
        mapping=instance_mapping(inputs['ecs-gz-instances.json'])
        require(instance_mapping(inputs['ecs-group-members.json'])==mapping, 'reviewed group membership does not contain only gz')
        baseline=canonical_group(inputs['ecs-gz-security-group.json'])
        require(baseline.get('SecurityGroupId')==mapping['security_group_id'] and baseline.get('VpcId')==mapping['vpc_id'] and baseline.get('RegionId')==REGION,'reviewed security-group identity differs')
        require(self.launcher.inventory['plan']['gz_public_ipv4']==PUBLIC and self.launcher.inventory['plan']['outer_udp_port']==51820,'inventory endpoint differs')
        require(not any(p.get('Description','').startswith(OWNER+':udp51820:') for p in baseline['Permissions']['Permission']), 'reviewed baseline already contains a project cloud rule')
        plan={'owner':OWNER,'profile':PROFILE,'mapping':mapping,'baseline':baseline,'baseline_sha256':digest(baseline),
              'source_sha256':{name:hashlib.sha256((self.local/'audit'/name).read_bytes()).hexdigest() for name in inputs}}
        if self.plan_path.exists():require(private_json(self.plan_path)==plan, 'existing reviewed cloud plan differs; reconcile without overwriting')
        else:wgmvp.json_write(self.plan_path,plan)
        return {'status':'PLANNED','mapping':mapping,'baseline_sha256':plan['baseline_sha256'],
                'delta':desired(plan,'<unique-owner-token>'),'note':'Only this IPv4 UDP rule; initial apply requires tested gz rollback and a closed listener.'}

    def load_plan(self):
        plan=private_json(self.plan_path)
        require(plan.get('owner')==OWNER and plan.get('profile')==PROFILE and plan.get('baseline_sha256')==digest(plan['baseline']), 'invalid reviewed cloud plan')
        require(plan['mapping']['region']==REGION and plan['mapping']['public_ipv4']==PUBLIC, 'cloud plan endpoint differs')
        for name,expected in plan['source_sha256'].items():
            require(name in ('ecs-gz-instances.json','ecs-gz-security-group.json','ecs-group-members.json'), 'unrecognized cloud baseline source')
            private_json(self.local/'audit'/name)
            require(hashlib.sha256((self.local/'audit'/name).read_bytes()).hexdigest()==expected, 'reviewed cloud baseline source changed')
        return plan

    def api(self,action,parameters):
        allowed={'DescribeInstances','DescribeSecurityGroupAttribute','AuthorizeSecurityGroup','RevokeSecurityGroup'}
        require(action in allowed,'unapproved cloud API')
        argv=['aliyun','ecs',action,'--profile',PROFILE,'--region',REGION,'--RegionId',REGION]
        for key,value in parameters.items():argv.extend(['--'+key,str(value)])
        result = None
        for attempt in range(3 if action.startswith('Describe') else 1):
            try:
                result=self.runner(argv,capture_output=True,text=True,timeout=40,check=False)
            except subprocess.TimeoutExpired:
                if not action.startswith('Describe') or attempt == 2:
                    raise wgmvp.Blocked('cloud API timed out: '+action+'; reconcile exact owned state before retrying writes')
                time.sleep(attempt+1)
                continue
            if result.returncode == 0:
                break
            if action.startswith('Describe') and attempt < 2:
                time.sleep(attempt+1)
        self.sequence+=1
        # Errors may contain authentication diagnostics; never persist/print them.
        require(result is not None and result.returncode==0,'cloud API failed: '+action+'; authentication diagnostics withheld')
        document=json.loads(result.stdout)
        require(isinstance(document,dict),'invalid cloud response')
        wgmvp.json_write(self.launcher.run_dir/f'cloud-{self.sequence:03}-{action}.json',document)
        return document

    def read(self,plan):
        mapping=plan['mapping']
        actual=instance_mapping(self.api('DescribeInstances',{'InstanceIds':json.dumps([mapping['instance_id']]),'PageSize':100}))
        members=instance_mapping(self.api('DescribeInstances',{'SecurityGroupId':mapping['security_group_id'],'PageSize':100}))
        require(actual==mapping and members==mapping,'live instance/group membership differs from reviewed mapping')
        return canonical_group(self.api('DescribeSecurityGroupAttribute',{'SecurityGroupId':mapping['security_group_id'],'Direction':'all','MaxResults':1000}))

    def state(self):
        if not self.state_path.exists():return None
        state=private_json(self.state_path)
        require(state.get('owner')==OWNER and TOKEN.fullmatch(state.get('token','')),'invalid cloud ownership state')
        require(state.get('rule_id') is None or RULE_ID.fullmatch(state['rule_id']),'invalid owned cloud rule ID')
        return state

    def save(self,state):
        wgmvp.private_directory(self.directory)
        wgmvp.json_write(self.state_path,state,replace=self.state_path.exists())

    def inspect(self,plan,current,state):
        if state:require(state.get('baseline_sha256')==plan['baseline_sha256'],'cloud ownership state belongs to a different baseline')
        rules=current['Permissions']['Permission']
        owned=[r for r in rules if state and (r.get('Description')==desired(plan,state['token'])['Description'] or r.get('SecurityGroupRuleId')==state.get('rule_id'))]
        require(len(owned)<=1,'multiple cloud rules claim the project identity')
        if owned:
            exact_rule(owned[0],plan,state['token'])
            require(state['rule_id'] in (None,owned[0]['SecurityGroupRuleId']),'owned cloud rule ID changed')
        others=copy.deepcopy(current); others['Permissions']['Permission']=[r for r in rules if r not in owned]
        require(others==plan['baseline'],'security-group drift outside exact owned rule; nothing changed')
        return owned[0] if owned else None

    def before_write(self,plan,state,action,*,closed=False):
        self.launcher.preflight('gz'); self.launcher.recovery()
        if closed:
            script='''set -eu
test "$(sed -n '1p' /etc/wgmvp/state/rolledback)" = wgmvp-r1
test "$(sed -n '2p' /etc/wgmvp/state/rolledback)" = "$(cat /proc/sys/kernel/random/boot_id)"
test ! -e /run/netns/wgmvp
! ip link show dev wgmvp >/dev/null 2>&1
listeners=$(ss -H -lun '( sport = :51820 )') || exit 1
test -z "$listeners"
'''
            result=self.launcher.remote('gz',script,'cloud-closed-endpoint')
            require(result['returncode']==0 and not result['timeout'],'same-boot tested rollback and closed gz endpoint required before cloud addition')
        current=self.read(plan); owned=self.inspect(plan,current,state)
        wgmvp.json_write(self.launcher.run_dir/f'cloud-before-{action}-{self.sequence:03}.json',
                         {'at':wgmvp.utcnow(),'action':action,'mapping':plan['mapping'],'before':current,'owned_rule':owned,
                          'delta':desired(plan,state['token']) if action=='add' else {'revoke_rule_id':owned['SecurityGroupRuleId'] if owned else None},
                          'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        return current,owned

    def status(self):
        plan=self.load_plan(); state=self.state(); owned=self.inspect(plan,self.read(plan),state)
        return {'status':'PRESENT' if owned else 'ABSENT','rule_id':owned['SecurityGroupRuleId'] if owned else None,'baseline_unchanged':True}

    def apply(self):
        plan=self.load_plan(); state=self.state(); current=self.read(plan); owned=self.inspect(plan,current,state)
        if owned:
            if state['rule_id'] is None:
                state.update(rule_id=owned['SecurityGroupRuleId'],phase='active');self.save(state)
            return {'status':'PRESENT','rule_id':owned['SecurityGroupRuleId'],'changed':False}
        # A fresh token follows each completed revoke; an interrupted add retains
        # its token so a lost response can be reconciled by exact ID/tag/readback.
        if state is None or state.get('phase')=='removed':
            state={'owner':OWNER,'token':str(uuid.uuid4()),'rule_id':None,'phase':'adding','baseline_sha256':plan['baseline_sha256']}
            self.save(state)
        require(state['rule_id'] is None,'owned rule disappeared unexpectedly; reconcile before re-adding')
        _,owned=self.before_write(plan,state,'add',closed=True)
        require(owned is None,'cloud rule appeared before add; rerun status')
        parameters={'SecurityGroupId':plan['mapping']['security_group_id'],'ClientToken':state['token']}
        parameters.update({'Permissions.1.'+k:v for k,v in desired(plan,state['token']).items()})
        self.api('AuthorizeSecurityGroup',parameters)
        owned=self.inspect(plan,self.read(plan),state)
        require(owned is not None,'new cloud rule not observed; retain adding state for reconciliation')
        state.update(rule_id=owned['SecurityGroupRuleId'],phase='active'); self.save(state)
        return {'status':'PRESENT','rule_id':state['rule_id'],'changed':True}

    def rollback(self):
        plan=self.load_plan(); state=self.state(); current=self.read(plan); owned=self.inspect(plan,current,state)
        if owned is None:
            if state:state.update(phase='removed'); self.save(state)
            return {'status':'ABSENT','changed':False}
        _,owned=self.before_write(plan,state,'revoke')
        require(owned is not None,'cloud rule disappeared before revoke; rerun status')
        state.update(rule_id=owned['SecurityGroupRuleId'],phase='removing');self.save(state)
        self.api('RevokeSecurityGroup',{'SecurityGroupId':plan['mapping']['security_group_id'],'SecurityGroupRuleId.1':state['rule_id']})
        require(self.inspect(plan,self.read(plan),state) is None,'owned cloud rule remains after revoke')
        state.update(phase='removed');self.save(state)
        return {'status':'ABSENT','changed':True}

    def remove(self):return self.rollback()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('plan','apply','status','rollback','remove'))
    parser.add_argument('--inventory',type=Path,default=wgmvp.REPO/'inventory.local.json')
    parser.add_argument('--local-dir',type=Path,default=wgmvp.REPO/'.local')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    if args.action in ('apply','rollback','remove') and not args.apply:
        print('DRY_RUN: exact owned UDP51820 cloud rule; supply --apply for cloud writes.');return 0
    try:
        with wgmvp.coordinator_lock(args.local_dir):
            launcher=wgmvp.Launcher(private_json(args.inventory),args.local_dir)
            print(json.dumps(getattr(CloudGate(launcher),args.action)(),indent=2))
        return 0
    except (wgmvp.Blocked,OSError,ValueError,KeyError,subprocess.TimeoutExpired) as exc:
        print('BLOCKED: '+str(exc),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
