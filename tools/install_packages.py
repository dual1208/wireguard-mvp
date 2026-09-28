#!/usr/bin/env python3
"""Serial additive package preparation with a separately supervised rollback lease."""
from __future__ import annotations
import argparse, json, os, re, shlex, subprocess, sys, hashlib
from pathlib import Path
from datetime import datetime, timezone
import discover, package_stage, wgmvp
from concurrent.futures import ThreadPoolExecutor

BASE=Path(__file__).resolve().parents[1]

# Native solver output is evidence, never shell input. Fail on any replacement.
SOLVER_AWK = r'''
function reject() { bad=1; print "unapproved package solver action: " $0 > "/dev/stderr" }
{
 line=$0; sub(/^\([[:space:]]*[0-9]+\/[0-9]+\)[[:space:]]*/, "", line)
 n=split(line,a,/[[:space:]]+/); action=a[1]
 if (action ~ /^(Upgrading|Downgrading|Reinstalling|Replacing)$/) {reject(); next}
 if (action=="Inst" || action=="Installing") {
   if (mode!="install" || a[3] !~ /^\(/) {reject(); next}
   version=a[3]; sub(/^\(/,"",version); sub(/\)$/,"",version)
   print a[2] "=" version; next
 }
 if (action=="Remv" || action=="Purg" || action=="Purging" || action=="Removing") {
   if (mode!="remove") {reject(); next}
   if (action=="Removing" && a[2]!="package") {reject(); next}
   print (action=="Removing" ? a[3] : a[2]); next
 }
 if (action=="Conf" && mode!="install") reject()
}
END { if (bad) exit 1 }
'''

def version_snapshot(role: str) -> str:
    return {'gz': "dpkg-query -W -f='${Package}=${Version} ${Status}\\n' | awk '$4==\"installed\" {print $1}' | sort",
            'villa': "opkg list-installed | awk '{print $1 \"=\" $3}' | sort",
            'cave': 'apk info -v | sort'}[role]

def fingerprints(role: str, inv: dict) -> str:
    return '\n'.join(f'[ "$(sha256sum {shlex.quote(p)} | cut -d " " -f1)" = {shlex.quote(h)} ]' for p,h in inv['identities'][role].items())+'\n'

def watcher_check(role: str) -> str:
    command = ('systemctl show wgmvp-package-guard.service -p MainPID --value' if role=='gz'
               else "ubus call service list '{\"name\":\"wgmvp-package-guard\"}' | jsonfilter -e '@[\"wgmvp-package-guard\"].instances.*.pid'")
    return '''watcher_owned() {
    managed=$('''+command+''') || return 1
    case "$managed" in ''|*[!0-9]*) return 1;; esac
    [ "$managed" -gt 1 ] && [ -f "$b/watch" ] || return 1
    [ "$managed" = "$(sed -n '3p' "$b/watch")" ] || return 1
    kill -0 "$managed" || return 1
    "$b/package-guard.sh" status | grep -qx 'WATCH healthy'
}
attempt=0
until watcher_owned; do
    attempt=$((attempt+1)); [ "$attempt" -lt 10 ] || exit 1
    sleep 1
done
'''

def here(name: str, content: str) -> str:
    delim='WGMVP_'+hashlib.sha256(content.encode()).hexdigest()
    return f'cat > "$b/{name}" <<\'{delim}\'\n{content.rstrip()}\n{delim}\n'

def rollback_script(role: str) -> str:
    installed_names={'gz': "dpkg-query -W -f='${Package} ${Status}\\n' | awk '$4==\"installed\" {print $1}'",
                     'villa': "opkg list-installed | awk '{print $1}'", 'cave':'apk info'}[role]
    if role=='gz':
        requested='iperf3 libiperf0 libsctp1 wireguard-tools'
        simulation='apt-get --simulate --no-auto-remove purge "$@"'
        apply='DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get --no-auto-remove -y purge "$@"'
    elif role=='cave':
        requested='kmod-wireguard wireguard-tools ip-full coreutils-timeout'
        simulation='apk --no-network --simulate del "$@"'
        apply='apk --no-network del "$@"'
    else:
        # Essential runtime libraries must never be force-removed.
        requested='coreutils-timeout coreutils iperf3 libiperf3'
        simulation='opkg --noaction remove "$@"'
        apply='opkg remove "$@"'
    return f'''#!/bin/sh
set -eu
b=/root/wgmvp-packages-before
export LC_ALL=C
simulate() {{
    {simulation} > "$b/rollback-simulation.txt" 2>&1 || {{ cat "$b/rollback-simulation.txt" >&2; return 1; }}
    awk -v mode=remove -f "$b/solver.awk" "$b/rollback-simulation.txt" > "$b/rollback-parsed.txt" || return 1
    sort -u "$b/rollback-parsed.txt"
}}
case "${{1:-}}" in
 plan) {installed_names} > "$b/rollback-installed.txt"
       set --
       while IFS= read -r name; do
           {('case "$name" in librt|libatomic1) continue;; esac' if role=='villa' else ':')}
           if grep -Fxq "$name" "$b/rollback-installed.txt"; then set -- "$@" "$name"; fi
       done < "$b/new-packages.txt"
       [ "$#" -gt 0 ] || exit 0
       simulate "$@";;
 apply) plan=${{2:?plan}}; set --
        while IFS= read -r name; do [ -n "$name" ] && set -- "$@" "$name"; done < "$plan"
        [ "$#" -gt 0 ] || exit 0
        simulate "$@" > "$b/rollback-rechecked.txt"
        sort -u "$plan" > "$b/rollback-approved.txt"
        cmp "$b/rollback-approved.txt" "$b/rollback-rechecked.txt"
        {apply}
        {version_snapshot(role)} > "$b/versions-after-rollback.txt"
        {installed_names} > "$b/rollback-installed-after.txt"
        : > "$b/rollback-retained.txt"
        while IFS= read -r name; do
            if grep -Fxq "$name" "$b/rollback-installed-after.txt"; then printf '%s\\n' "$name" >> "$b/rollback-retained.txt"; fi
        done < "$b/new-packages.txt"
        if [ -s "$b/rollback-retained.txt" ]; then printf 'Package rollback retained approved runtime libraries; see %s\\n' "$b/rollback-retained.txt" >&2; fi;;
 *) exit 1;;
esac
'''

def script_for(role: str, inv: dict, manifest: dict) -> str:
    checks=fingerprints(role,inv)
    manager={'gz':'apt','villa':'opkg','cave':'apk'}[role]
    entries=sorted(manifest['packages'],key=lambda p:p['name'])
    packages=[p['name'] for p in entries]
    if len(set(packages)) != len(packages) or not packages: raise ValueError('duplicate or empty package set')
    for p in entries:
        if not re.fullmatch(r'[A-Za-z0-9_.+-]+',p['name']) or not re.fullmatch(r'[A-Za-z0-9_.+~:-]+',p['version']): raise ValueError('unsafe package metadata')
        if not re.fullmatch(r'[a-f0-9]{64}',p['sha256']): raise ValueError('invalid package digest')
    exact=' '.join(shlex.quote(p['name']+'='+p['version']) for p in entries)
    requested=' '.join(shlex.quote(p['name']+'='+p['version']) for p in entries if p['name'] in {'kmod-wireguard','wireguard-tools','ip-full','coreutils-timeout'})
    s='set -eu\numask 077\nexport LC_ALL=C\n'+checks+'''
[ ! -L /var/lock/wgmvp-bootstrap.lock ]
exec 9>/var/lock/wgmvp-bootstrap.lock
flock -x -n 9
d=$(mktemp -d /tmp/wgmvp-packages.XXXXXX)
trap 'rm -rf "$d"' EXIT
trap 'exit 1' HUP INT TERM
tar -xzf - -C "$d"
cd "$d"
sha256sum -c SHA256SUMS >/dev/null
b=/root/wgmvp-packages-before
[ ! -e "$b" ]
mkdir -m 700 "$b"
'''
    s+=here('solver.awk',SOLVER_AWK)
    s+=here('expected-additions.txt','\n'.join(sorted(p['name']+'='+p['version'] for p in entries))+'\n')
    s+=version_snapshot(role)+' > "$b/baseline-versions.txt"\n'
    baseline={'gz':"dpkg-query -W -f='${Package} ${Status}\\n' | awk '$4==\"installed\" {print $1}' | sort -u",'villa':"opkg list-installed | awk '{print $1}' | sort -u",'cave':'apk info | sort -u'}[role]
    s+=baseline+' > "$b/baseline.txt"\n'
    backup={'gz':'cp /var/lib/dpkg/status "$b/package-status.before"', 'villa':'cp /usr/lib/opkg/status "$b/package-status.before"', 'cave':'cp /lib/apk/db/installed "$b/package-status.before"\ncp /etc/apk/world "$b/world.before"'}[role]
    s+=backup+'\n'
    if role!='cave': s+=wgmvp.snapshot_function(role)+'\nwgmvp_snapshot > "$b/config-network.before"\n'
    else: s+='sha256sum /etc/config/network /etc/config/firewall > "$b/config-network.before"\n'
    s+=here('new-packages.txt','\n'.join(packages)+'\n')
    s+='while IFS= read -r name; do ! grep -Fxq "$name" "$b/baseline.txt"; done < "$b/new-packages.txt"\n'
    if role=='cave':
        s+='for f in "$d"/*/packages.adb; do printf "ndx %s\\n" "$f"; done > "$d/repositories"\n'
        for p in entries:
            # APK 3.0.5 fetch's nonrecursive query compares the full argument
            # to a package name, so name=version does not match. The signed,
            # release-specific index plus exact payload digest pins this fetch;
            # simulation and add still use normal exact version constraints.
            name=shlex.quote(p['name'])
            s+=f'apk --no-cache --no-network --repositories-file "$d/repositories" fetch --stdout {name} > "$d/verified-{p["name"]}.apk"\n'
            s+=f'printf \'%s\\n\' \'{p["sha256"]}  verified-{p["name"]}.apk\' | sha256sum -c -\n'
        simulation='apk --no-cache --no-network --repositories-file "$d/repositories" --simulate add '+requested
        install='apk --no-cache --no-network --repositories-file "$d/repositories" add '+requested
    elif role=='villa':
        s+='sh "$d/verify.sh" "$d"\n'
        simulation='opkg --noaction install "$d"/*.ipk'
        install='opkg install "$d"/*.ipk'
    else:
        simulation='apt-get --simulate --no-upgrade --no-remove --no-install-recommends install '+exact
        install='DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get --no-upgrade --no-remove --no-install-recommends -y install '+exact
        s+='''[ -z "$(dpkg --audit)" ]
! getent passwd iperf3 >/dev/null
! getent group iperf3 >/dev/null
[ ! -e /etc/default/iperf3 ]
[ ! -e /etc/systemd/system/iperf3.service ]
[ ! -e /lib/systemd/system/iperf3.service ]
[ -z "$(debconf-show iperf3 2>/dev/null)" ]
[ -z "$(systemctl list-units --all --no-legend 'wg-quick@*.service')" ]
'''
    s+=simulation+' > "$b/install-simulation.txt" 2>&1\n'
    s+='awk -v mode=install -f "$b/solver.awk" "$b/install-simulation.txt" > "$b/install-parsed.txt"\nsort -u "$b/install-parsed.txt" > "$b/install-additions.txt"\ncmp "$b/expected-additions.txt" "$b/install-additions.txt"\n'
    s+=here('role.env',f'OWNER=wgmvp-packages-r1\nMANAGER={manager}\n')
    expected_versions='\n'.join(p['name']+('-' if role=='cave' else '=')+p['version'] for p in entries)+'\n'
    s+=here('new-versions.txt',expected_versions)
    s+='cat "$b/baseline-versions.txt" "$b/new-versions.txt" | sort > "$b/expected-versions.txt"\n'
    s+=here('rollback.sh',rollback_script(role))
    s+=here('package-guard.sh',(BASE/'remote/package-guard.sh').read_text())
    service='package-guard.service' if role=='gz' else 'package-guard.init'
    s+=here(service,(BASE/'remote'/service).read_text())
    s+=here('baseline.ready','wgmvp-packages-r1\n')
    s+='chmod 600 "$b/"*\nchmod 700 "$b/package-guard.sh" "$b/rollback.sh"\n'
    # The service must acquire this same lock and publish its own process identity.
    s+='exec 9>&-\n'
    if role=='gz':
        s+='''[ ! -e /etc/systemd/system/wgmvp-package-guard.service ]
cp "$b/package-guard.service" /etc/systemd/system/wgmvp-package-guard.service
systemctl daemon-reload
systemctl enable --now wgmvp-package-guard.service
'''
    else:
        s+='''[ ! -e /etc/init.d/wgmvp-package-guard ]
cp "$b/package-guard.init" /etc/init.d/wgmvp-package-guard
chmod 700 /etc/init.d/wgmvp-package-guard
/etc/init.d/wgmvp-package-guard enable
/etc/init.d/wgmvp-package-guard start
'''
    s+=watcher_check(role)+'''"$b/package-guard.sh" arm
# Exercise the host-local handler with an empty, baseline-disjoint removal plan.
"$b/package-guard.sh" rollback
[ ! -e "$b/pending" ]
[ "$(sed -n '2p' "$b/result")" = rolledback ]
"$b/package-guard.sh" arm
exec 9>/var/lock/wgmvp-bootstrap.lock
flock -x -n 9
export WGMVP_PACKAGE_LOCK_FD=9
"$b/package-guard.sh" check
'''
    s+=checks+version_snapshot(role)+' > "$b/versions-before-write.txt"\ncmp "$b/baseline-versions.txt" "$b/versions-before-write.txt"\n'
    if role!='cave': s+='wgmvp_snapshot > "$b/config-network.before-write"\n'
    else: s+='sha256sum /etc/config/network /etc/config/firewall > "$b/config-network.before-write"\n'
    s+='cmp "$b/config-network.before" "$b/config-network.before-write"\n'
    if role=='gz':
        s+='''printf '%s\n' 'iperf3 iperf3/start_daemon boolean false' | debconf-set-selections
'''
    s+=install+'\n'
    if role=='gz':
        s+='''! systemctl is-enabled --quiet iperf3.service
! systemctl is-active --quiet iperf3.service
! ss -lntup | grep -q ':5201 '
'''
    s+=version_snapshot(role)+' > "$b/versions-after.txt"\ncmp "$b/expected-versions.txt" "$b/versions-after.txt"\n'+checks
    if role!='cave': s+='wgmvp_snapshot > "$b/config-network.after"\n'
    else: s+='sha256sum /etc/config/network /etc/config/firewall > "$b/config-network.after"\n'
    s+='cmp "$b/config-network.before" "$b/config-network.after"\n'
    s+='''wg --version
timeout -s TERM -k 1 2 true
"$b/package-guard.sh" check
exec 9>&-
unset WGMVP_PACKAGE_LOCK_FD
echo PACKAGES_INSTALLED_LEASE_PENDING
'''
    return s

def commit_script(role: str, inv: dict) -> str:
    s='set -eu\nexport LC_ALL=C\nb=/root/wgmvp-packages-before\n'+fingerprints(role,inv)+watcher_check(role)
    s+='''exec 9>/var/lock/wgmvp-bootstrap.lock
flock -x -n 9
export WGMVP_PACKAGE_LOCK_FD=9
"$b/package-guard.sh" check
'''
    s+=version_snapshot(role)+' > "$b/versions-at-commit.txt"\ncmp "$b/expected-versions.txt" "$b/versions-at-commit.txt"\n'
    if role!='cave': s+=wgmvp.snapshot_function(role)+'\nwgmvp_snapshot > "$b/config-network.at-commit"\n'
    else:s+='sha256sum /etc/config/network /etc/config/firewall > "$b/config-network.at-commit"\n'
    s+='cmp "$b/config-network.before" "$b/config-network.at-commit"\n'
    service='package-guard.service' if role=='gz' else 'package-guard.init'
    dest='/etc/systemd/system/wgmvp-package-guard.service' if role=='gz' else '/etc/init.d/wgmvp-package-guard'
    s+=f'cmp "$b/{service}" {shlex.quote(dest)}\n'
    s+='"$b/package-guard.sh" commit\nexec 9>&-\nunset WGMVP_PACKAGE_LOCK_FD\n'
    if role=='gz':
        s+='''systemctl disable --now wgmvp-package-guard.service
cmp "$b/package-guard.service" /etc/systemd/system/wgmvp-package-guard.service
rm /etc/systemd/system/wgmvp-package-guard.service
systemctl daemon-reload
'''
    else:
        s+='''/etc/init.d/wgmvp-package-guard disable
/etc/init.d/wgmvp-package-guard stop
cmp "$b/package-guard.init" /etc/init.d/wgmvp-package-guard
rm /etc/init.d/wgmvp-package-guard
'''
    s+='echo PACKAGES_COMMITTED_NO_TUNNEL_CREATED\n'
    return s

def recovery(inv: dict) -> None:
    def probe(target):
        result=discover.run_bounded(discover.command_for(target),stdin='id -u\n',timeout=20)
        if result['returncode']!=0: raise RuntimeError('fresh recovery failed: '+target)
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(probe,discover.TARGETS))
    subprocess.run(['curl','-fIsS','--max-time','15',inv['recovery']['internet_url']],stdout=subprocess.DEVNULL,check=True)

def apply_transaction(a, root: Path, inv: dict, manifest: dict) -> int:
    recovery(inv)
    script=script_for(a.role,inv,manifest)
    (root/'install-planned.sh').write_text(script)
    print('PLANNED_DELTA',a.role,'add reviewed packages; arm host-local lease; no network interfaces/routes/firewall changes',flush=True)
    transport, payload = package_stage.streamed_transaction(a.role, script,
        package_stage.bundle(root/'repos' if a.role=='cave' else root), fingerprints(a.role, inv))
    r=subprocess.run(transport,input=payload,capture_output=True,timeout=240)
    out={'observed_at':datetime.now(timezone.utc).isoformat(),'returncode':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')};(root/'install-result.json').write_text(json.dumps(out,indent=2));print(out['stdout']);print(out['stderr'])
    if r.returncode: return r.returncode
    if 'PACKAGES_INSTALLED_LEASE_PENDING' not in out['stdout']: raise RuntimeError('installer completion marker absent; lease remains pending')
    # A separate SSH recovery pass is required before accepting the transaction.
    recovery(inv)
    commit=commit_script(a.role,inv);(root/'commit-planned.sh').write_text(commit)
    r=subprocess.run(discover.command_for(a.role),input=commit.encode(),capture_output=True,timeout=35)
    out={'observed_at':datetime.now(timezone.utc).isoformat(),'returncode':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')};(root/'commit-result.json').write_text(json.dumps(out,indent=2));print(out['stdout']);print(out['stderr']);return r.returncode

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('role',choices=['gz','villa','cave']);ap.add_argument('--apply',action='store_true');a=ap.parse_args()
    os.umask(0o077);root=BASE/'.local/packages'/a.role
    inv=json.loads((BASE/'inventory.local.json').read_text());manifest=json.loads((root/'manifest.json').read_text())
    if not a.apply:print('DRY_RUN',a.role,'add only reviewed missing packages with independently supervised 300-second rollback lease');return 0
    with wgmvp.coordinator_lock(BASE/'.local'):
        return apply_transaction(a,root,inv,manifest)

if __name__=='__main__':sys.exit(main())
