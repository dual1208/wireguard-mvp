"""Offline native solver and lease integration checks; never contact a host."""
import json
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import install_packages as installer
import package_stage


class PackageInstallerTests(unittest.TestCase):
    def parse(self,text,mode='install'):
        return subprocess.run(['awk','-v','mode='+mode,installer.SOLVER_AWK],input=text,text=True,capture_output=True)

    def test_native_install_formats(self):
        samples=[('Inst libsctp1 (1.0.21+dfsg-1 Debian:13.7/stable [amd64])','libsctp1=1.0.21+dfsg-1'),
                 ('Installing iperf3 (3.17.1-r4) to root...','iperf3=3.17.1-r4'),
                 ('( 1/16) Installing coreutils (9.9-r2)','coreutils=9.9-r2'),
                 ('(10/16) Installing kmod-wireguard (6.12.74-r1)','kmod-wireguard=6.12.74-r1')]
        for line,expected in samples:
            with self.subTest(line=line):
                result=self.parse(line+'\n')
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout.strip(),expected)

    def test_rejects_upgrade_and_install_removal(self):
        for line in ['Inst existing [1.0] (2.0 Debian [amd64])','( 1/2) Upgrading existing (1.0 -> 2.0)',
                     'Removing package existing from root...','Purg existing [1.0]',
                     'Downgrading existing (2.0 to 1.0)']:
            self.assertNotEqual(self.parse(line+'\n').returncode,0,line)

    def test_native_remove_formats(self):
        text='Purg iperf3 [3.18-2]\nRemv libiperf0 [3.18-2]\n( 1/16) Purging coreutils (9.9-r2)\nRemoving package libiperf3 from root...\n'
        result=self.parse(text,'remove')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.splitlines(),['iperf3','libiperf0','coreutils','libiperf3'])
        self.assertNotEqual(self.parse('Inst existing (1.0)\n','remove').returncode,0)

    def test_captured_solver_matches_real_manifests(self):
        for role,source in [('cave','.local/packages/cave/simulation.json'),('gz','.local/packages/gz-package-preparation.json')]:
            if not (ROOT/source).exists(): continue
            result=self.parse(json.loads((ROOT/source).read_text())['stdout'])
            expected=sorted(p['name']+'='+p['version'] for p in json.loads((ROOT/'.local/packages'/role/'manifest.json').read_text())['packages'])
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(sorted(result.stdout.splitlines()),expected)

    def test_all_generated_shell_and_lease_ordering(self):
        inv={'identities':{role:{'/identity':'a'*64} for role in ('gz','villa','cave')}}
        manifest={'packages':[{'name':'wireguard-tools','version':'1.0-r1','sha256':'a'*64}]}
        for role in ('gz','villa','cave'):
            script=installer.script_for(role,inv,manifest)
            for generated in (script,installer.commit_script(role,inv),installer.rollback_script(role)):
                checked=subprocess.run(['sh','-n'],input=generated,text=True,capture_output=True)
                self.assertEqual(checked.returncode,0,checked.stderr)
            self.assertLess(script.index('baseline.ready'),script.index('"$b/package-guard.sh" arm'))
            self.assertLess(script.index('until watcher_owned'),script.index('"$b/package-guard.sh" arm'))
            self.assertNotIn('"$b/package-guard.sh" commit',script)
            self.assertIn('PACKAGES_INSTALLED_LEASE_PENDING',script)
            self.assertIn('cmp "$b/expected-additions.txt" "$b/install-additions.txt"',script)
            self.assertIn('cmp "$b/expected-versions.txt" "$b/versions-after.txt"',script)

    def test_duplicate_manifest_rejected(self):
        item={'name':'wireguard-tools','version':'1.0','sha256':'a'*64}
        with self.assertRaises(ValueError):
            installer.script_for('gz',{'identities':{'gz':{}}},{'packages':[item,item]})

    def test_install_bypass_rejected_before_ssh(self):
        with patch.object(sys,'argv',['package_stage.py','cave','install','--apply']), patch.object(package_stage.discover,'run_bounded') as remote:
            with self.assertRaises(SystemExit): package_stage.main()
            remote.assert_not_called()

    def test_bundle_omits_stale_checksum_manifest(self):
        import io,tarfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'SHA256SUMS').write_text('stale\n');(root/'package').write_text('payload')
            with tarfile.open(fileobj=io.BytesIO(package_stage.bundle(root)),mode='r:gz') as tar:
                self.assertEqual(tar.getnames().count('SHA256SUMS'),1)

    def opkg_gate(self, output):
        packages=[{'name':name,'version':'9.7-r1','sha256':'a'*64}
                  for name in ('coreutils','coreutils-timeout')]
        generated=installer.script_for('villa',{'identities':{'villa':{}}},{'packages':packages})
        # Execute the actual emitted solver gate, avoiding host setup/install.
        fragments=[]
        for name in ('solver.awk','expected-additions.txt'):
            match=re.search(r'(?m)^cat > "\$b/'+re.escape(name)+r'" <<\'([^\']+)\'\n[\s\S]*?^\1\n',generated)
            self.assertIsNotNone(match)
            fragments.append(match.group())
        gate=re.search(r'(?m)^awk -v mode=install[^\n]*\n^sort[^\n]*\n^cmp[^\n]*\n',generated)
        self.assertIsNotNone(gate)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'install-simulation.txt').write_text(output)
            script='set -eu\nexport LC_ALL=C\nb=$1\n'+''.join(fragments)+gate.group()
            result=subprocess.run(['sh','-c',script,'solver-test',directory],capture_output=True,text=True)
            return result,(root/'expected-additions.txt').read_text(),(root/'install-additions.txt').read_text()

    def test_opkg_repeated_dependency_lines_and_serialized_sort(self):
        # --noaction revisits dependencies for each supplied IPK.
        output=('Installing coreutils (9.7-r1) to root...\n'
                'Installing coreutils-timeout (9.7-r1) to root...\n'
                'Installing coreutils (9.7-r1) to root...\n'
                'Installing coreutils-timeout (9.7-r1) to root...\n')
        result,expected,actual=self.opkg_gate(output)
        self.assertEqual(result.returncode,0,result.stderr)
        # Full name=version serialization sorts '-' before '='.
        self.assertEqual(expected,'coreutils-timeout=9.7-r1\ncoreutils=9.7-r1\n')
        self.assertEqual(actual,expected)

    def test_opkg_deduplication_still_rejects_conflicting_version_or_extra_name(self):
        output='Installing coreutils (9.7-r1) to root...\nInstalling coreutils-timeout (9.7-r1) to root...\n'
        for extra in ('Installing coreutils (9.8-r1) to root...\n','Installing foreign-package (1.0) to root...\n'):
            with self.subTest(extra=extra):
                result,expected,actual=self.opkg_gate(output+extra)
                self.assertNotEqual(result.returncode,0)
                self.assertNotEqual(actual,expected)

    def streamed_fixture(self, directory, script, payload, checks='true\n'):
        root=Path(directory); binaries=root/'bin'; binaries.mkdir()
        upload=root/'upload'
        # Keep the real wrapper unchanged; substitute only its mktemp location.
        (binaries/'mktemp').write_text('#!/bin/sh\nset -eu\n[ "$#" = 2 ]\n[ "$1" = -d ]\n[ "$2" = /tmp/wgmvp-upload.XXXXXX ]\nmkdir -m 700 "$WGMVP_TEST_UPLOAD"\nprintf "%s\\n" "$WGMVP_TEST_UPLOAD"\n')
        (binaries/'mktemp').chmod(0o700)
        with patch.object(package_stage,'transport',side_effect=lambda target,wrapper:['sh','-c',wrapper]):
            command,archive=package_stage.streamed_transaction('villa',script,payload,checks)
        env=dict(os.environ,PATH=str(binaries)+':'+os.environ['PATH'],WGMVP_TEST_UPLOAD=str(upload),WGMVP_TEST_MARKER=str(root/'executed'))
        return command,archive,env,upload

    def test_streamed_large_script_keeps_small_exec_and_exact_binary_framing(self):
        script='# large reviewed script\n'+('# bounded filler\n'*2000)+'printf "%s\\n" "$PWD"\ncat\n'
        payload=b'\x00binary payload\xff\n$(this must stay data)\n'
        with tempfile.TemporaryDirectory() as directory:
            command,archive,env,upload=self.streamed_fixture(directory,script,payload)
            self.assertLess(len(command[-1].encode()),2048)
            with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
                self.assertEqual(tar.getnames(),['transaction.sh','payload.tar.gz'])
                self.assertTrue(all(member.mode==0o600 for member in tar.getmembers()))
                self.assertEqual(tar.extractfile('transaction.sh').read(),script.encode())
                self.assertEqual(tar.extractfile('payload.tar.gz').read(),payload)
            result=subprocess.run(command,input=archive,env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            location,data=result.stdout.split(b'\n',1)
            self.assertEqual(Path(os.fsdecode(location)).resolve(),upload.resolve())
            self.assertEqual(data,payload)
            self.assertFalse(upload.exists())

    def test_streamed_digest_mismatch_never_executes_and_cleans_stage(self):
        for changed in ('transaction.sh','payload.tar.gz'):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as directory:
                command,archive,env,upload=self.streamed_fixture(directory,'touch "$WGMVP_TEST_MARKER"\n',b'original')
                tampered=io.BytesIO()
                with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as source,tarfile.open(fileobj=tampered,mode='w:gz') as dest:
                    for member in source.getmembers():
                        data=source.extractfile(member).read()
                        if member.name==changed: data+=b'\n# tampered\n'
                        member.size=len(data);dest.addfile(member,io.BytesIO(data))
                result=subprocess.run(command,input=tampered.getvalue(),env=env,capture_output=True,timeout=10)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(Path(env['WGMVP_TEST_MARKER']).exists())
                self.assertFalse(upload.exists())

    def test_streamed_failed_preflight_creates_no_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            command,archive,env,upload=self.streamed_fixture(directory,'touch "$WGMVP_TEST_MARKER"\n',b'data','false\n')
            result=subprocess.run(command,input=archive,env=env,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(Path(env['WGMVP_TEST_MARKER']).exists())
            self.assertFalse(upload.exists())

    def test_streamed_transaction_failure_preserves_exit_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            command,archive,env,upload=self.streamed_fixture(directory,'exit 37\n',b'data')
            result=subprocess.run(command,input=archive,env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,37,result.stderr)
            self.assertFalse(upload.exists())


if __name__=='__main__': unittest.main()
