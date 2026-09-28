#!/usr/bin/env python3
"""Replace one explicitly reviewed nonsecret helper, retaining its owner-local original."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import wgmvp

FILES = {'hub.sh', 'router.sh', 'unknown-key.sh', 'spoof-lab.sh', 'benchmark.sh', 'security-probe.sh'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('role',choices=wgmvp.ROLES);p.add_argument('file',choices=sorted(FILES))
    p.add_argument('--expected-sha256',required=True);p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    if not re.fullmatch('[0-9a-f]{64}',a.expected_sha256):p.error('expected SHA256 must be the reviewed installed source hash')
    source=(wgmvp.REPO/'remote'/a.file).read_text();new=hashlib.sha256(source.encode()).hexdigest()
    print(f'Delta {a.role}/{a.file}: {a.expected_sha256} -> {new}; retain original locally on owner')
    if not a.apply:return 0
    L=wgmvp.Launcher(json.loads((wgmvp.REPO/'inventory.local.json').read_text()),wgmvp.REPO/'.local')
    delimiter='SOURCE_'+new;assert delimiter not in source.splitlines()
    body='''exec 8>"$ROOT/state/mutex"
flock -x -n 8
'''+f'f="$ROOT/{a.file}"\nold={a.expected_sha256}\nnew={new}\n'+'''
[ -f "$f" ] && [ ! -L "$f" ]
current=$(sha256sum "$f"); current=${current%% *}
[ "$current" = "$old" ] || [ "$current" = "$new" ]
if [ "$current" = "$new" ]; then echo 'SOURCE unchanged'; exit 0; fi
mode=$(ls -ldn "$f" | awk '$2==1 && $3==0 {if($1=="-rw-------") print "600"; else if($1=="-rwx------") print "700"}')
[ -n "$mode" ]
saved="$ROOT/backups/source-'''+a.file+'''-$old"
if [ -e "$saved" ]; then [ ! -L "$saved" ] && cmp -s "$saved" "$f";
else cp -p "$f" "$saved"; chmod 600 "$saved"; fi
stage=$(mktemp "$ROOT/.source.XXXXXX")
trap 'rm -f "$stage"' EXIT HUP INT TERM
cat > "$stage" <<\''''+delimiter+"'\n"+source+delimiter+'''
actual=$(sha256sum "$stage"); [ "${actual%% *}" = "$new" ]
sh -n "$stage"
chmod "$mode" "$stage"
mv "$stage" "$f"
trap - EXIT HUP INT TERM
printf 'SOURCE updated; original retained on owner\n'
'''
    with wgmvp.coordinator_lock(L.local):
        L.mutate(a.role,body,'update-reviewed-source',f'atomic replacement of reviewed nonsecret {a.file}; exact original SHA, backup and syntax check; no network state change')
    print(L.run_dir)
    return 0
if __name__=='__main__':raise SystemExit(main())
