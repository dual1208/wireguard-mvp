"""Render nonsecret, fixed-scope deployment files. Keys never enter this module."""
from __future__ import annotations
import ipaddress
from pathlib import Path
import shlex

REPO = Path(__file__).resolve().parents[1]

def role_files(inventory: dict, role: str) -> dict[str, str]:
    if role not in {'gz', 'villa', 'cave'}:
        raise ValueError('invalid role')
    p = inventory['plan']
    if p['overlay_pool'] != '10.203.77.0/29' or p['interface'] != 'wgmvp' or p['gz_namespace'] != 'wgmvp':
        raise ValueError('address/name change requires backend review')
    ips = {k: str(ipaddress.IPv4Interface(v).ip) for k, v in p['overlay_addresses'].items()}
    if ips != {'gz':'10.203.77.1','villa':'10.203.77.2','cave':'10.203.77.3'}:
        raise ValueError('unexpected address plan')
    endpoint = str(ipaddress.IPv4Address(p['gz_public_ipv4']))
    if not ipaddress.ip_address(endpoint).is_global:
        raise ValueError('endpoint must be verified global IPv4')
    for field, low, high in [('outer_udp_port',1024,65535),('mtu',1280,1420)]:
        if type(p[field]) is not int or not low <= p[field] <= high:
            raise ValueError(field)
    values = dict(ROOT='/etc/wgmvp', ROLE=role, OWNER='wgmvp-r1', IFACE='wgmvp', NS='wgmvp',
                  POOL=p['overlay_pool'], G=ips['gz'], V=ips['villa'], C=ips['cave'],
                  ENDPOINT=endpoint, PORT=p['outer_udp_port'], MTU=p['mtu'])
    files = {'config.env': ''.join(f'{k}={shlex.quote(str(v))}\n' for k,v in values.items()),
             'owner': 'wgmvp-r1\n'}
    for name in ['controller.sh', 'benchmark.sh', 'security-probe.sh', 'unknown-key.sh', 'hub.sh' if role=='gz' else 'router.sh',
                 'wgmvp.service' if role=='gz' else 'wgmvp.init']:
        files[name] = (REPO/'remote'/name).read_text()
    if role == 'gz':
        files['spoof-lab.sh'] = (REPO/'remote/spoof-lab.sh').read_text()
    if role != 'gz':
        own, other = ips[role], ips['cave' if role=='villa' else 'villa']
        files['router-guard.nft'] = router_guard(own, other, ips['gz'], p['overlay_pool'])
        files['router-config.batch'] = router_batch(own, other, ips['gz'], endpoint, p['outer_udp_port'], p['mtu'])
    return files

def router_guard(own: str, other: str, hub: str, pool: str) -> str:
    return f'''table inet wgmvp_guard {{
    comment "wgmvp-r1"
    chain bench_rx {{ }}
    chain bench_tx {{ }}
    chain rx {{
        ip saddr {{ {hub}, {other} }} ip daddr {own} icmp type {{ echo-request, echo-reply }} counter accept
        ip saddr {{ {hub}, {other} }} ip daddr {own} icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} ct state related counter accept
        jump bench_rx
        counter drop comment "wgmvp ingress denied all destinations and IPv6"
    }}
    chain prerouting {{
        type filter hook prerouting priority -190; policy accept;
        iifname "wgmvp" jump rx
        iifname != "wgmvp" ip daddr {pool} counter drop comment "wgmvp nonproject ingress denied"
    }}
    chain input {{
        type filter hook input priority -190; policy accept;
        iifname "wgmvp" jump rx
    }}
    chain forward {{
        type filter hook forward priority -190; policy accept;
        iifname "wgmvp" counter drop comment "wgmvp forward from tunnel denied"
        oifname "wgmvp" counter drop comment "wgmvp forward into tunnel denied"
        ip daddr {pool} counter drop comment "wgmvp forwarded fallback denied"
    }}
    chain tx {{
        ip saddr {own} ip daddr {{ {hub}, {other} }} icmp type {{ echo-request, echo-reply }} counter accept
        ip saddr {own} ip daddr {{ {hub}, {other} }} icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} ct state related counter accept
        jump bench_tx
        counter drop comment "wgmvp output denied"
    }}
    chain output {{
        type filter hook output priority -190; policy accept;
        ip daddr {pool} oifname != "wgmvp" counter drop comment "wgmvp no plaintext fallback"
        oifname "wgmvp" jump tx
    }}
    chain postrouting {{
        type filter hook postrouting priority 310; policy accept;
        ip daddr {pool} oifname != "wgmvp" counter drop
        ip saddr {pool} oifname != "wgmvp" counter drop
        ct original ip daddr {pool} oifname != "wgmvp" counter drop comment "wgmvp no redirected fallback"
    }}
}}
'''

def router_batch(own: str, other: str, hub: str, endpoint: str, port: int, mtu: int) -> str:
    # Private/public key options are appended on the owner by shell builtins.
    return f'''set network.wgmvp=interface
set network.wgmvp.wgmvp_owner='wgmvp-r1'
set network.wgmvp.proto='wireguard'
set network.wgmvp.auto='0'
set network.wgmvp.mtu='{mtu}'
set network.wgmvp.fwmark='0x77203'
set network.wgmvp.nohostroute='1'
add_list network.wgmvp.addresses='{own}/32'
set network.wgmvp_peer=wireguard_wgmvp
set network.wgmvp_peer.wgmvp_owner='wgmvp-r1'
set network.wgmvp_peer.route_allowed_ips='1'
set network.wgmvp_peer.endpoint_host='{endpoint}'
set network.wgmvp_peer.endpoint_port='{port}'
set network.wgmvp_peer.persistent_keepalive='25'
add_list network.wgmvp_peer.allowed_ips='{hub}/32'
add_list network.wgmvp_peer.allowed_ips='{other}/32'
set firewall.wgmvp=zone
set firewall.wgmvp.wgmvp_owner='wgmvp-r1'
set firewall.wgmvp.name='wgmvp'
add_list firewall.wgmvp.network='wgmvp'
add_list firewall.wgmvp.device='wgmvp'
set firewall.wgmvp.input='DROP'
set firewall.wgmvp.output='DROP'
set firewall.wgmvp.forward='DROP'
set firewall.wgmvp_diag_in=rule
set firewall.wgmvp_diag_in.wgmvp_owner='wgmvp-r1'
set firewall.wgmvp_diag_in.name='wgmvp exact ICMP input'
set firewall.wgmvp_diag_in.src='wgmvp'
set firewall.wgmvp_diag_in.family='ipv4'
set firewall.wgmvp_diag_in.proto='icmp'
add_list firewall.wgmvp_diag_in.src_ip='{hub}'
add_list firewall.wgmvp_diag_in.src_ip='{other}'
set firewall.wgmvp_diag_in.dest_ip='{own}'
set firewall.wgmvp_diag_in.target='ACCEPT'
set firewall.wgmvp_diag_out=rule
set firewall.wgmvp_diag_out.wgmvp_owner='wgmvp-r1'
set firewall.wgmvp_diag_out.name='wgmvp exact ICMP output'
set firewall.wgmvp_diag_out.dest='wgmvp'
set firewall.wgmvp_diag_out.family='ipv4'
set firewall.wgmvp_diag_out.proto='icmp'
set firewall.wgmvp_diag_out.src_ip='{own}'
add_list firewall.wgmvp_diag_out.dest_ip='{hub}'
add_list firewall.wgmvp_diag_out.dest_ip='{other}'
set firewall.wgmvp_diag_out.target='ACCEPT'
'''
