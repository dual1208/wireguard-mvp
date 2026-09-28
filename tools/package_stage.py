#!/usr/bin/env python3
"""Stage authenticated release repositories through existing SSH (no new listener).

Simulation writes only a fresh private temporary directory and removes it on
exit/reboot. Installation is a separate explicit operation after reviewing the
solver output. No force/untrusted flags and no OS/kernel upgrades are permitted.
"""
from __future__ import annotations
import argparse, hashlib, io, json, os, re, shlex, subprocess, sys, tarfile
from datetime import datetime, timezone
from pathlib import Path
import discover

def transport(target: str, script: str) -> list[str]:
    cmd = discover.command_for(target)
    remote = shlex.join(['sh','-c',script])
    cmd[-1] = shlex.join(['ssh',*discover.SSH_OPTIONS,'rt',remote]) if target=='cave' else remote
    return cmd

def streamed_transaction(target: str, script: str, payload: bytes, checks: str) -> tuple[list[str], bytes]:
    """Keep Dropbear exec requests small; stream the reviewed script as data."""
    archive = io.BytesIO()
    script_bytes = script.encode()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for name, data in [('transaction.sh', script_bytes), ('payload.tar.gz', payload)]:
            info = tarfile.TarInfo(name)
            info.size = len(data); info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
    wrapper = 'set -eu\numask 077\n' + checks + '''
u=$(mktemp -d /tmp/wgmvp-upload.XXXXXX)
trap 'rm -rf "$u"' EXIT
trap 'exit 1' HUP INT TERM
tar -xzf - -C "$u"
cd "$u"
sha256sum -c - >/dev/null <<'WGMVP_UPLOAD_DIGESTS'
''' + hashlib.sha256(script_bytes).hexdigest() + '  transaction.sh\n' + hashlib.sha256(payload).hexdigest() + '''  payload.tar.gz
WGMVP_UPLOAD_DIGESTS
sh "$u/transaction.sh" < "$u/payload.tar.gz"
'''
    return transport(target, wrapper), archive.getvalue()

def bundle(root: Path) -> bytes:
    files = sorted(p for p in root.rglob('*') if p.is_file() and p.name not in {'manifest.json', 'SHA256SUMS'})
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w:gz') as tar:
        hashes=[]
        for path in files:
            rel=path.relative_to(root).as_posix()
            if path.is_symlink() or not re.fullmatch(r'[A-Za-z0-9_./+~-]+',rel): raise ValueError('unsafe bundle name')
            data=path.read_bytes(); hashes.append(hashlib.sha256(data).hexdigest()+'  '+rel)
            info=tarfile.TarInfo(rel);info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
        data=('\n'.join(hashes)+'\n').encode();info=tarfile.TarInfo('SHA256SUMS');info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
    return buf.getvalue()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('target',choices=['cave','villa']);ap.add_argument('operation',choices=['simulate','install'])
    ap.add_argument('--apply',action='store_true');a=ap.parse_args()
    if a.operation == 'install':
        ap.error('installation requires tools/install_packages.py and its supervised rollback lease')
    if not a.apply: print('DRY_RUN: private temporary package staging; supply --apply after reviewing PLAN.md');return 0
    os.umask(0o077);inv=json.loads(Path('inventory.local.json').read_text())
    expected=inv['identities'][a.target]
    checks='\n'.join(f'[ "$(sha256sum {shlex.quote(p)} | cut -d " " -f1)" = {shlex.quote(h)} ]' for p,h in expected.items() if p in ['/etc/dropbear/dropbear_ed25519_host_key','/etc/config/network','/etc/config/firewall'])
    # Fresh recovery, independent of the future overlay.
    for t in discover.TARGETS:
        r=discover.run_bounded(discover.command_for(t),stdin='id -u\n',timeout=20)
        if r['returncode']!=0: raise RuntimeError('fresh recovery failed: '+t)
    subprocess.run(['curl','-fIsS','--max-time','15','https://www.apple.com/library/test/success.html'],check=True,stdout=subprocess.DEVNULL)
    root=Path('.local/packages')/a.target/'repos'
    if a.target!='cave': raise RuntimeError('Villa staging is prepared separately for opkg signature verification')
    manifest=json.loads((Path('.local/packages')/a.target/'manifest.json').read_text())
    packages=manifest['packages']
    exact=[x['name']+'='+x['version'] for x in packages]
    if any(not re.fullmatch(r'[A-Za-z0-9_.+~=-]+',x) for x in exact):raise ValueError('unsafe package metadata')
    script='set -eu\numask 077\n'+checks+'''
d=$(mktemp -d /tmp/wgmvp-packages.XXXXXX)
trap 'rm -rf "$d"' EXIT HUP INT TERM
tar -xzf - -C "$d"
cd "$d"
sha256sum -c SHA256SUMS
for f in "$d"/*/packages.adb; do printf 'ndx %s\n' "$f"; done > "$d/repositories"
printf '\nPLANNED_DELTA: simulation only; signed indexes, no installation\n'
apk --no-cache --no-network --repositories-file "$d/repositories" --simulate add kmod-wireguard wireguard-tools ip-full coreutils-timeout
'''
    if a.operation=='install':
        sim=json.loads((Path('.local/packages')/a.target/'simulation.json').read_text())
        if sim['returncode']!=0 or 'Upgrading' in sim['stdout'] or 'Removing' in sim['stdout']:raise RuntimeError('reviewed additive simulation required')
        verify='\n'.join('apk --no-cache --no-network --repositories-file \"$d/repositories\" fetch --stdout '+shlex.quote(x)+' >/dev/null' for x in exact)
        script+=verify+'\n'
        script+='''
backup=/root/wgmvp-packages-before
[ ! -e "$backup" ]
mkdir -m 700 "$backup"
cp /etc/apk/world "$backup/world"
apk info -v > "$backup/installed.txt"
cat > "$backup/rollback.sh" <<'WGMVP_ROLLBACK'
#!/bin/sh
set -eu
# Review --simulate output first; removes only newly requested capabilities.
apk --no-network --simulate del kmod-wireguard wireguard-tools ip-full coreutils-timeout
[ "${1:-}" = --apply ] || exit 0
apk --no-network del kmod-wireguard wireguard-tools ip-full coreutils-timeout
WGMVP_ROLLBACK
chmod 600 "$backup/world" "$backup/installed.txt"
chmod 700 "$backup/rollback.sh"
apk --no-cache --no-network --repositories-file "$d/repositories" add kmod-wireguard wireguard-tools ip-full coreutils-timeout
wg --version
ip -Version
timeout -s TERM -k 1 2 true
'''
    print('PLANNED_DELTA:',a.target,'private /tmp package staging and authenticated solver simulation; trap cleanup; no network changes',flush=True)
    r=subprocess.run(transport(a.target,script),input=bundle(root),capture_output=True,timeout=90)
    out={'observed_at':datetime.now(timezone.utc).isoformat(),'target':a.target,'operation':a.operation,'command':script,'returncode':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')}
    p=Path('.local/packages')/a.target/(a.operation+'.json');p.write_text(json.dumps(out,indent=2));print(out['stdout']);print(out['stderr']);return r.returncode

if __name__=='__main__':sys.exit(main())
