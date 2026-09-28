#!/usr/bin/env python3
"""S01/S02 bounded owned-endpoint evidence; dry-run unless explicitly --apply."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import sys
import time
import uuid
import acceptance
import live_checks
import wgmvp

PUBLIC = '8.163.2.191'
PORT = 51820
TCP_PORTS = (51820, 52080)
OWNER = 'wgmvp-r1'
ERRORS = (wgmvp.Blocked, ValueError, KeyError, OSError)
require = live_checks.require
Failed = live_checks.Failed


class ExternalAttributionUnavailable(wgmvp.Blocked):
    """UDP proof succeeded, but this vantage cannot establish the TCP path."""


def cloud_tcp_denial(document):
    """Conservative SG rule proof; never infer denial from a failed API query."""
    permissions=document.get('Permissions',{}).get('Permission')
    require(isinstance(permissions,list) and not document.get('NextToken'), 'incomplete cloud permissions')
    reviewed=[]
    for rule in permissions:
        require(isinstance(rule,dict),'malformed cloud permission')
        direction=str(rule.get('Direction','')).lower()
        policy=str(rule.get('Policy','')).lower()
        require(direction in ('ingress','egress') and policy in ('accept','drop'),'ambiguous cloud direction/policy')
        if direction!='ingress' or policy!='accept':continue
        protocol=str(rule.get('IpProtocol','')).lower()
        require(protocol in ('tcp','udp','icmp','icmpv6','gre','all'),'ambiguous cloud protocol')
        if protocol not in ('tcp','all'):continue
        require(protocol!='all','cloud ALL ingress permission prevents selected TCP denial proof')
        require(not rule.get('PortRangeListId') and not rule.get('PortRangeListName'),'cloud TCP port-list selector is unresolved')
        match=re.fullmatch(r'([0-9]+)/([0-9]+)',str(rule.get('PortRange','')))
        require(match is not None,'ambiguous or unrestricted cloud TCP port range')
        low,high=map(int,match.groups())
        require(1<=low<=high<=65535,'invalid cloud TCP port range')
        require(not any(low<=port<=high for port in TCP_PORTS),'cloud accepts a selected TCP port; upstream denial is not established')
        reviewed.append(rule.get('SecurityGroupRuleId'))
    return {'denied_tcp_ports':list(TCP_PORTS),'reviewed_tcp_rule_ids':reviewed,
            'reason':'No ingress Accept TCP/ALL permission covers either selected TCP port; ECS security-group default ingress denial applies.'}
CAPTURE_MAX_BYTES = 24 + 2048 * (16 + 128)
CAPTURE_ENCODER = r'''
encode_capture() {
    if command -v base64 >/dev/null 2>&1; then
        base64 "$1"
    elif command -v od >/dev/null 2>&1; then
        printf 'WGMVP_HEX\n'
        od -An -v -tx1 "$1"
    elif command -v hexdump >/dev/null 2>&1; then
        printf 'WGMVP_HEX\n'
        hexdump -v -e '1/1 "%02x"' "$1"
    else
        printf 'No supported capture encoder (base64, od, hexdump)\n' >&2
        return 1
    fi
}
'''


def capture_evidence_script(commands):
    # A failed encoder/read must preserve the whole owned evidence directory.
    # Emit every command's status, then fail explicitly before any removal.
    script = r'''
capture_failed=0
capture_probe() {
    label=$1; shift
    printf '\nWGMVP_BEGIN %s\n' "$label"
    capture_rc=0
    "$@" || { capture_rc=$?; capture_failed=1; }
    printf '\nWGMVP_END %s %s\n' "$label" "$capture_rc"
}
'''
    script += '\n'.join('capture_probe ' + shlex.join([label, *command]) for label, command in commands)
    return script + r'''
if [ "$capture_failed" != 0 ]; then
    printf 'Capture collection failed; owned evidence preserved at %s\n' "$d" >&2
    exit 1
fi
'''


def capture_bytes(text):
    """Read existing base64 evidence or the portable, explicitly tagged hex form."""
    lines = text.splitlines()
    is_hex = bool(lines and lines[0] == 'WGMVP_HEX')
    encoded = ''.join((''.join(lines[1:]) if is_hex else text).split())
    require(len(encoded) <= CAPTURE_MAX_BYTES * 2, 'capture transport bound exceeded')
    if is_hex:
        require(len(encoded) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]*', encoded), 'invalid hex capture transport')
        data = bytes.fromhex(encoded)
    else:
        data = base64.b64decode(encoded, validate=True)
    require(len(data) <= CAPTURE_MAX_BYTES, 'capture transport bound exceeded')
    return data


def packets(data):
    """Decode bounded IPv4 headers/synthetic UDP bytes from classic pcap."""
    orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    require(len(data) >= 24 and data[:4] in orders, 'unsupported pcap header')
    order = orders[data[:4]]
    _, _, _, _, snaplen, link = struct.unpack(order+'HHIIII', data[4:24])
    require(64 <= snaplen <= 128 and link in (1, 101, 113, 228, 276), 'unexpected capture format')
    offset, result = 24, []
    while offset < len(data):
        require(len(data)-offset >= 16, 'truncated pcap header')
        _, _, captured, original = struct.unpack(order+'IIII', data[offset:offset+16]); offset += 16
        require(captured <= snaplen and captured <= original and offset+captured <= len(data), 'truncated pcap packet')
        frame = data[offset:offset+captured]; offset += captured
        if link in (1, 113, 276):
            start, field = {1: (14, 12), 113: (16, 14), 276: (20, 0)}[link]
            require(len(frame) >= start and struct.unpack('!H', frame[field:field+2])[0] == 0x0800, 'non-IPv4 capture')
        else: start = 0
        header = frame[start:]
        require(len(header) >= 20, 'short IPv4 header')
        ihl = (header[0] & 15)*4
        require(header[0] >> 4 == 4 and ihl >= 20 and len(header) >= ihl, 'invalid IPv4 header')
        require(struct.unpack('!H', header[6:8])[0] & 0x3fff == 0, 'fragmented probe evidence')
        item = {'src': socket.inet_ntoa(header[12:16]), 'dst': socket.inet_ntoa(header[16:20]), 'protocol': header[9]}
        if link in (113, 276):
            kind = struct.unpack('!H', frame[:2])[0] if link == 113 else frame[10]
            item['direction'] = 'out' if kind == 4 else 'in'
        transport = header[ihl:]
        if item['protocol'] in (6, 17):
            require(len(transport) >= 8, 'short transport header')
            item['sport'], item['dport'] = struct.unpack('!HH', transport[:4])
            if item['protocol'] == 17:
                item['payload'] = transport[8:]
                item['length'] = struct.unpack('!H', transport[4:6])[0]-8
            else:
                require(len(transport) >= 20, 'short TCP header')
                item['flags'] = transport[13]
                item['sequence'], item['acknowledgment'] = struct.unpack('!II', transport[4:12])
        result.append(item)
        require(len(result) <= 256, 'capture packet bound exceeded')
    return result


def unknown_report(output, hub_key):
    def one(label, pattern):
        values = re.findall(r'(?m)^'+label+' '+pattern+r'$', output)
        require(len(values) == 1, 'unknown-key evidence missing/ambiguous: '+label)
        return values[0]
    key = one('FRESH_UNREGISTERED_PUBLIC_KEY', r'([A-Za-z0-9+/]{43}=)')
    port = int(one('UNKNOWN_KEY_LISTEN_PORT', r'([0-9]+)'))
    status = int(one('UNKNOWN_KEY_PING_EXIT', r'([0-9]+)'))
    require(1 <= port <= 65535 and status in (1, 124), 'unknown-key ping did not fail normally')
    values = re.findall(r'(?m)^'+re.escape(hub_key)+r'\s+([0-9]+)$', output)
    require(values == ['0'], 'unknown peer handshake accepted or evidence missing')
    return {'public_key': key, 'listen_port': port, 'ping_exit': status}


def unknown_arrivals(outbound, arrivals, listen_port):
    def initiation(p):
        return (p.get('protocol') == 17 and p.get('dport') == PORT and p.get('length') == 148 and
                p.get('payload', b'')[:4] == b'\1\0\0\0' and len(p.get('payload', b'')) >= 8)
    indexes = {p['payload'][4:8] for p in outbound if initiation(p) and p['sport'] == listen_port and p['dst'] == PUBLIC}
    require(bool(indexes), 'unknown-key interface has no captured outbound initiation')
    matched = [p for p in arrivals if initiation(p) and p['payload'][4:8] in indexes]
    require(bool(matched), 'gz did not receive the captured unknown-key initiation')
    return len(matched)


def local_probes(nonce):
    """Two connects, <=64 nonce bytes each, and three 45-byte datagrams."""
    require(re.fullmatch(r'[a-f0-9]{32}', nonce), 'invalid probe nonce')
    payload = ('WGMVP-PROBE-'+nonce).encode('ascii')
    require(len(payload) <= 64, 'TCP payload bound exceeded')
    result = {'tcp': {}, 'tcp_io': {}, 'udp_sent': 0}
    for port in TCP_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            code = client.connect_ex((PUBLIC, port)); result['tcp'][str(port)] = code
            if code == 0:
                io = {'sent_bytes': 0, 'received_bytes': 0}
                result['tcp_io'][str(port)] = io
                try:
                    client.sendall(payload)
                    io['sent_bytes'] = len(payload)
                    io['received_bytes'] = len(client.recv(1))
                except OSError as exc:
                    io['error'] = type(exc).__name__
    payload = ('WGMVP-OUTER-'+nonce).encode('ascii')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        for index in range(3):
            require(client.sendto(payload+bytes([index]), (PUBLIC, PORT)) == len(payload)+1, 'incomplete UDP send')
            result['udp_sent'] += 1
            time.sleep(.15)
    return result


def external_arrivals(observed, nonce, local=None, report=None):
    """Attribute probes at gz; a local connect result alone is never exposure."""
    if report is None: report = {}
    report.update(udp_datagrams=0, tcp_syn_ports=[], tcp_synack_ports=[], tcp_reset_ports=[],
                  local_accepted_ports=sorted(int(port) for port, code in (local or {}).get('tcp', {}).items() if code == 0),
                  limitation='TCP attribution uses nonce-confirmed egress address and bounded interval; local proxy acceptance or split paths block this check.')
    prefix = ('WGMVP-OUTER-'+nonce).encode('ascii')
    udp = [p for p in observed if p.get('protocol') == 17 and p.get('dport') == PORT and p.get('payload', b'').startswith(prefix)]
    report['udp_datagrams'] = len({p['payload'][len(prefix):] for p in udp})
    require({p['payload'][len(prefix):] for p in udp} == {b'\0', b'\1', b'\2'}, 'missing nonce-tagged UDP arrivals')
    sources = {p['src'] for p in udp}
    syns = [p for p in observed if p.get('protocol') == 6 and p.get('flags', 0) & 0x17 == 2 and
            p.get('direction') != 'out' and p['src'] in sources and p['dport'] in TCP_PORTS]
    report['tcp_syn_ports'] = sorted({p['dport'] for p in syns})
    replies = [p for p in observed if p.get('protocol') == 6 and p.get('direction') == 'out' and any(
                   (p['src'],p['dst'],p['sport'],p['dport']) == (s['dst'],s['src'],s['dport'],s['sport']) and
                   p.get('acknowledgment') == (s['sequence']+1) % 2**32 for s in syns)]
    report['tcp_synack_ports'] = sorted({p['sport'] for p in replies if p.get('flags',0) & 0x17 == 0x12})
    report['tcp_reset_ports'] = sorted({p['sport'] for p in replies if p.get('flags',0) & 0x17 == 0x14})
    if report['tcp_synack_ports']: raise Failed('gz emitted a matching SYN-ACK for an attributed external probe on selected TCP port(s): '+','.join(map(str,report['tcp_synack_ports'])))
    if set(report['local_accepted_ports']) - set(report['tcp_reset_ports']):
        raise ExternalAttributionUnavailable('local TCP acceptance has no matching gz SYN-ACK; proxy interception or path ambiguity, not confirmed exposure')
    if set(report['tcp_syn_ports']) != set(TCP_PORTS):
        raise ExternalAttributionUnavailable('TCP arrivals not attributable to nonce-confirmed external vantage')
    report['basis']='host TCP/UDP packet captures'
    return report


class OuterChecks(live_checks.LiveChecks):
    def __init__(self, launcher, routers=('cave',)):
        require(len(set(routers)) == len(routers) and set(routers) <= {'villa', 'cave'}, 'invalid router scope')
        self.launcher = launcher
        require(launcher.inventory['plan']['overlay_addresses'] == {r:a+'/32' for r,a in live_checks.ADDRESSES.items()}, 'unreviewed overlay plan')
        self.results = {}
        self.routers = tuple(routers); self.roles = ('gz', *self.routers)
        plan = launcher.inventory['plan']
        require(plan['gz_public_ipv4'] == PUBLIC and plan['outer_udp_port'] == PORT, 'unreviewed public endpoint/port')
        self.unknown_hash = hashlib.sha256((wgmvp.REPO/'remote/unknown-key.sh').read_bytes()).hexdigest()

    def capture_descriptor(self, role, specs, *, packet_limit=256, duration=50):
        require(role in self.roles and 1 <= len(specs) <= 2, 'capture scope exceeded')
        require(type(packet_limit) is int and 1 <= packet_limit <= 2048 and
                type(duration) is int and 1 <= duration <= 60, 'capture bound exceeded')
        require(all(name in ('outer', 'inner') and context in ('host', 'wgmvp') and
                    (context == 'host' or role == 'gz') for name, (context, _) in specs.items()), 'invalid capture context')
        token = str(uuid.uuid4())
        return {'role': role, 'token': token, 'path': '/etc/wgmvp/outer-capture-'+token, 'specs': specs,
                'packet_limit': packet_limit, 'duration': duration}

    def start_outer_capture(self, capture):
        path = capture['path']
        packet_limit, duration = capture.get('packet_limit',256), capture.get('duration',50)
        require(type(packet_limit) is int and 1 <= packet_limit <= 2048 and
                type(duration) is int and 1 <= duration <= 60, 'capture bound exceeded')
        body = (CAPTURE_ENCODER + 'encode_capture /dev/null >/dev/null || exit 1\n'
                'exec 8>"$ROOT/state/mutex"\nflock -x -n 8\n'
                'test -f "$ROOT/state/pending"\n'
                '[ "$(sed -n \'2p\' "$ROOT/state/pending")" = "$(cat /proc/sys/kernel/random/boot_id)" ]\n'
                'tick=$(cut -d. -f1 /proc/uptime)\n'
                f'[ "$(sed -n \'4p\' "$ROOT/state/pending")" -gt "$((tick+{duration+15}))" ]\n'
                f'd={shlex.quote(path)}\n[ ! -e "$d" ]\nmkdir -m 700 "$d"\n'
                f"printf '%s\\n' {OWNER} {capture['token']} > \"$d/scope\"\n")
        for name, (context, bpf) in capture['specs'].items():
            prefix = 'ip netns exec wgmvp ' if context == 'wgmvp' else ''
            child = ('set -eu\numask 077\n'+f'd={shlex.quote(path)}\n'
                     'line=$(cat /proc/$$/stat)\nstart=$(printf \'%s\\n\' "${line##*) }" | awk \'{print $20}\')\n'
                     f"printf '%s\\n' {OWNER} {capture['token']} \"$(cat /proc/sys/kernel/random/boot_id)\" \"$$\" \"$start\" > \"$d/{name}.pid\"\n"
                     f'exec {prefix}tcpdump -U -nn -s 128 -i any -c {packet_limit} -w - {shlex.quote(bpf)} > "$d/{name}.pcap"\n')
            worker = (f'exec 8>&-\nd={shlex.quote(path)}\nrc=0\n'
                      f'timeout -s INT -k 2 {duration} sh -c {shlex.quote(child)} 2>"$d/{name}.log" || rc=$?\n'
                      f'printf \'%s\\n\' "$rc" > "$d/{name}.rc"\n')
            body += live_checks.detached_worker(worker, path + '/' + name + '.runner')
        for name in capture['specs']:
            body += (f'attempt=0\nuntil grep -q "listening on " "$d/{name}.log"; do\n'
                     f' [ ! -f "$d/{name}.rc" ]; attempt=$((attempt+1)); [ "$attempt" -lt 6 ]; sleep 1\ndone\n')
        self.launcher.mutate(capture['role'], body, 'outer-capture-start', 'bounded synthetic captures with owner/PID/start/boot records')

    def capture_covering(self, capture):
        script = ''.join(f'test ! -e {shlex.quote(capture["path"]+"/"+name+".rc")}\n' for name in capture['specs'])
        self.read(capture['role'], script, 'outer-capture-coverage')

    def finish_outer_capture(self, capture, *, decode=packets):
        path, token = capture['path'], capture['token']
        duration = capture.get('duration',50)
        require(type(duration) is int and 1 <= duration <= 60, 'capture bound exceeded')
        require(path == '/etc/wgmvp/outer-capture-'+token and live_checks.TOKEN.fullmatch(token), 'invalid capture identity')
        body = f'd={shlex.quote(path)}\n'+r'''
exec 8>"$ROOT/state/mutex"
flock -x -n 8
[ -d "$d" ] && [ ! -L "$d" ]
ls -ldn "$d" | awk '$1=="drwx------" && $3==0 {good=1} END {exit !good}'
safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
        awk '$1=="-rw-------" && $2==1 && $3==0 {good=1} END {exit !good}'
}
safe_file "$d/scope"
[ "$(sed -n '1p' "$d/scope")" = wgmvp-r1 ]
'''+f'[ "$(sed -n \'2p\' "$d/scope")" = {shlex.quote(token)} ]\nexec 8>&-\n'
        files = ['scope']
        for name in capture['specs']:
            body += f'''exec 8>"$ROOT/state/mutex"
flock -x -n 8
safe_file "$d/{name}.pid"
[ "$(sed -n '1p' "$d/{name}.pid")" = wgmvp-r1 ]
[ "$(sed -n '2p' "$d/{name}.pid")" = {shlex.quote(token)} ]
[ "$(sed -n '3p' "$d/{name}.pid")" = "$(cat /proc/sys/kernel/random/boot_id)" ]
pid=$(sed -n '4p' "$d/{name}.pid"); original=$(sed -n '5p' "$d/{name}.pid")
case "$pid:$original" in *[!0-9:]*) exit 1;; esac
[ "$pid" -gt 1 ] && [ -n "$original" ]
if [ ! -f "$d/{name}.rc" ] && [ -r "/proc/$pid/stat" ]; then
    line=$(cat "/proc/$pid/stat"); current=$(printf '%s\\n' "${{line##*) }}" | awk '{{print $20}}')
    [ "$current" = "$original" ]
    kill -INT "$pid"
fi
exec 8>&-
attempt=0
until [ -f "$d/{name}.rc" ]; do
    attempt=$((attempt+1)); [ "$attempt" -lt {duration+5} ]; sleep 1
done
'''
            files += [name+suffix for suffix in ('.pid', '.pcap', '.log', '.rc', '.runner')]
        body += ('exec 8>"$ROOT/state/mutex"\nflock -x -n 8\n'
                 '[ -d "$d" ] && [ ! -L "$d" ]\n'
                 'ls -ldn "$d" | awk \'$1=="drwx------" && $3==0 {good=1} END {exit !good}\'\n'
                 'safe_file "$d/scope"\n[ "$(sed -n \'1p\' "$d/scope")" = wgmvp-r1 ]\n'
                 f'[ "$(sed -n \'2p\' "$d/scope")" = {shlex.quote(token)} ]\n')
        for filename in files:
            body += f'safe_file "$d/{filename}"\n'
        body += CAPTURE_ENCODER
        commands = [(name+suffix, [command, path+'/'+name+extension])
                    for name in capture['specs'] for suffix, command, extension in
                    (('_pcap', 'encode_capture', '.pcap'), ('_log', 'cat', '.log'), ('_rc', 'cat', '.rc'))]
        body += capture_evidence_script(commands)
        body += 'rm '+' '.join(shlex.quote(path+'/'+f) for f in files)+'\nrmdir '+shlex.quote(path)+'\n'
        output = self.mutation_stdout(capture['role'], body, 'outer-capture-finish', 'stop matching capture identities; collect/remove exact owned files')
        evidence = acceptance.parse_probes(output)
        result = {}
        for name in capture['specs']:
            require(all(evidence[name+suffix]['returncode'] == 0 for suffix in ('_pcap', '_log', '_rc')), 'capture evidence unavailable')
            require(evidence[name+'_rc']['stdout'] in ('0', '124'), 'capture terminated abnormally')
            log = evidence[name+'_log']['stdout']
            require('listening on ' in log and re.search(r'(?m)^0 packets dropped by kernel\s*$', log), 'capture health/drops unavailable')
            result[name] = decode(capture_bytes(evidence[name+'_pcap']['stdout']))
        return result

    def positive_scope(self):
        for router in self.routers:
            for source, destination in (('gz', router), (router, 'gz')):
                prefix = 'ip netns exec wgmvp ' if source == 'gz' else ''
                src, dst = live_checks.ADDRESSES[source], live_checks.ADDRESSES[destination]
                output = self.read(source, prefix+f'timeout -k 1 10 ping -n -I {src} -c 3 -W 2 {dst}\n', 'outer-positive-control')
                require(acceptance.zero_loss(output), 'selected authorized path failed positive control')

    def prepare(self):
        for role in self.roles:
            self.healthy(role)
            self.renew(role)
        self.positive_scope()

    def peer_state(self):
        keys = {role: self.read('gz', f'cat /etc/wgmvp/public.{role}\n', 'outer-public-identity').strip() for role in self.roles}
        require(all(wgmvp.PUBLIC_KEY.fullmatch(k) for k in keys.values()) and len(set(keys.values())) == len(keys), 'invalid public identities')
        peers = set(self.read('gz', 'ip netns exec wgmvp wg show wgmvp peers\n', 'outer-peers').split())
        require({keys[role] for role in self.routers} <= peers and 1 <= len(peers) <= 2 and
                all(wgmvp.PUBLIC_KEY.fullmatch(k) for k in peers), 'hub peer membership differs from reviewed scope')
        return keys, peers

    def cloud_denial(self):
        # Read-only cloud queries validate the reviewed plan, live instance and
        # sole-group membership, owned UDP rule, and every other permission.
        import cloud_gate
        gate=cloud_gate.CloudGate(self.launcher)
        plan=gate.load_plan()
        current=gate.read(plan)
        owned=gate.inspect(plan,current,gate.state())
        require(owned is not None,'owned IPv4 UDP cloud allowance is not present')
        proof=cloud_tcp_denial(current)
        proof.update(observed_at=wgmvp.utcnow(),mapping=plan['mapping'],
                     security_group_sha256=cloud_gate.digest(current),owned_udp_rule_id=owned['SecurityGroupRuleId'],
                     baseline_unchanged=True)
        path=self.launcher.run_dir/'s02-cloud-denial.json'
        wgmvp.json_write(path,proof)
        return {**proof,'evidence_file':str(path)}

    def run_check(self, action, source=None):
        require(action in ('unknown-key', 'external'), 'unknown outer check')
        source = source or (self.routers[0] if self.routers else None)
        if action == 'unknown-key': require(source in self.routers, 'unknown-key source outside selected routers')
        test_id = 'S01' if action == 'unknown-key' else 'S02'
        captures, traces, cleanup_errors, detail, error = [], {}, [], {'selected_routers': list(self.routers),
            'authorized_positive_control': 'planned' if self.routers else 'NOT_RUN: no router path selected; S02 uses fixed namespace policy and external/inner captures'}, None
        before, attempted_unknown = None, False
        try:
            self.prepare()
            before = self.peer_state()
            inner = (f'icmp and src host {live_checks.ADDRESSES[source]} and dst host 10.203.77.1 and icmp[0] = 8'
                     if action == 'unknown-key' else 'ip and (tcp or udp)')
            outer = ('udp dst port 51820 and udp[8:4] = 0x01000000' if action == 'unknown-key' else
                     'ip and ((udp dst port 51820 and udp[8:4] = 0x57474d56) or (tcp and (port 51820 or port 52080) and tcp[13] & 0x06 != 0))')
            captures.append(self.capture_descriptor('gz', {'outer': ('host', outer), 'inner': ('wgmvp', inner)}))
            self.start_outer_capture(captures[-1])
            if action == 'unknown-key':
                captures.append(self.capture_descriptor(source, {'outer': ('host', 'udp dst port 51820 and udp[8:4] = 0x01000000')}))
                self.start_outer_capture(captures[-1])
            for capture in captures: self.capture_covering(capture)
            if action == 'unknown-key':
                attempted_unknown = True
                body = f'[ "$(sha256sum "$ROOT/unknown-key.sh" | cut -d" " -f1)" = {self.unknown_hash} ]\n'
                body += '"$ROOT/unknown-key.sh" run\n'
                output = self.mutation_stdout(source, body, 'unknown-key-run', 'fresh owner-local unregistered key; bounded ping; unchanged hub peer set')
                detail['unknown'] = unknown_report(output, before[0]['gz'])
                require(detail['unknown']['public_key'] not in set(before[0].values()) | before[1], 'test key is already authorized')
                self.read(source, 'test ! -e /etc/wgmvp/unknown-key\n! ip link show dev wgmvp_uk >/dev/null 2>&1\n', 'unknown-cleaned')
            else:
                detail['nonce'] = uuid.uuid4().hex
                detail['local'] = local_probes(detail['nonce'])
                wgmvp.json_write(self.launcher.run_dir/'external-local-probes.json', detail)
            for capture in captures: self.capture_covering(capture)
        except ERRORS as exc:
            error = exc
        finally:
            for capture in reversed(captures):
                try: traces[capture['role']] = self.finish_outer_capture(capture)
                except ERRORS as exc: cleanup_errors.append(capture['role']+': '+str(exc))
            if attempted_unknown:
                try:
                    self.launcher.mutate(source, '"$ROOT/unknown-key.sh" cleanup\n', 'unknown-key-cleanup', 'clean only recorded disposable unknown-key objects')
                except ERRORS as exc: cleanup_errors.append('unknown-key: '+str(exc))
        if cleanup_errors:
            detail['cleanup_errors'] = cleanup_errors
            error = error or wgmvp.Blocked('capture/unknown-key cleanup incomplete; finite workers remain bounded')
        if error is None:
            try:
                if traces['gz']['inner']: raise Failed('unexpected synthetic packet appeared inside project namespace')
                if action == 'unknown-key':
                    detail['matched_unknown_initiations'] = unknown_arrivals(traces[source]['outer'], traces['gz']['outer'], detail['unknown']['listen_port'])
                else:
                    detail['arrivals'] = {}
                    try:
                        external_arrivals(traces['gz']['outer'], detail['nonce'], detail['local'], detail['arrivals'])
                    except ExternalAttributionUnavailable as exc:
                        # This narrow exception occurs only after all three
                        # nonce UDP arrivals and SYN-ACK failure checks. Capture
                        # health and empty inner traffic were verified above.
                        require(not any(p.get('protocol')==6 and p.get('direction')=='out' and
                                        p.get('flags',0)&0x17==0x12 and p.get('sport') in TCP_PORTS
                                        for p in traces['gz']['outer']),
                                'unattributed gz SYN-ACK contradicts cloud-only denial proof')
                        detail['arrivals']['tcp_attribution_limitation']=str(exc)
                        detail['arrivals']['cloud_denial']=self.cloud_denial()
                        detail['arrivals']['basis']='cloud ingress denial plus nonce UDP host capture and empty inner capture'
                require(self.peer_state() == before, 'authorized public identities/peers changed')
                self.positive_scope()
                if self.routers: detail['authorized_positive_control'] = 'PASS'
                for role in self.roles:
                    self.healthy(role)
                    require(self.read(role, 'id -u\n', 'outer-independent-ssh').strip() == '0', 'independent management unavailable')
                self.launcher.recovery()
            except ERRORS as exc: error = exc
        detail.update(id=test_id, observed_at=wgmvp.utcnow(), status='FAIL' if isinstance(error, Failed) else 'BLOCKED' if error else 'PASS',
                      limitations=['Finite selected-endpoint probes; selected authorized paths only. No peer, route, forwarding or firewall authorization is added.'])
        if error: detail['reason'] = str(error)
        self.results[test_id] = detail
        wgmvp.json_write(self.launcher.run_dir/'outer-check-results.json', {'complete_acceptance': False, 'tests': list(self.results.values())}, replace=True)
        return detail


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('unknown-key', 'external'))
    parser.add_argument('--routers', nargs='*', choices=('villa', 'cave'), default=['cave'], help='Use --routers with no values for gz-only S02.')
    parser.add_argument('--source', choices=('villa', 'cave'))
    parser.add_argument('--inventory', type=Path, default=wgmvp.REPO/'inventory.local.json')
    parser.add_argument('--local-dir', type=Path, default=wgmvp.REPO/'.local')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if not args.apply:
        print('DRY_RUN: bounded owned-endpoint probes with host/namespace evidence; no connections made.')
        return 0
    try:
        inventory = json.loads(args.inventory.read_text())
        with wgmvp.coordinator_lock(args.local_dir):
            checks = OuterChecks(wgmvp.Launcher(inventory, args.local_dir), args.routers)
            result = checks.run_check(args.action, args.source)
            print(result['id']+': '+result['status'])
            print('Private evidence: '+str(checks.launcher.run_dir))
            return 0 if result['status'] == 'PASS' else 1 if result['status'] == 'FAIL' else 2
    except ERRORS as exc:
        print('BLOCKED: '+str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
