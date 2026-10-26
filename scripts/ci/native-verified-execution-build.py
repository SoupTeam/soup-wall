#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline read-only Linux compiler and kernel controls; NOT runtime acceptance."""
import argparse,hashlib,json,os,platform,re,subprocess,time
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True)
    p.add_argument('--scratch',type=Path,required=True);p.add_argument('--cargo',type=Path,required=True)
    p.add_argument('--expected-commit',required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);scratch=a.scratch.resolve(strict=True)
    record={'format':'sou155-native-build/1','status':'incomplete','runtime_qualification':False,
            'source_commit':a.expected_commit,'source_read_only':True,'writes':'isolated-scratch-only',
            'network':'private-loopback-only','steps':[]}
    destination=scratch/'native-build.json'
    def save():destination.write_text(json.dumps(record,indent=2)+'\n')
    save()
    try:
        assert platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()!=0
        assert re.fullmatch('[0-9a-f]{40}',a.expected_commit)
        assert os.statvfs(source).f_flag & os.ST_RDONLY
        assert not scratch.is_relative_to(source)
        env={'PATH':str(a.cargo.parent)+':/usr/bin:/bin','HOME':str(scratch/'home'),
             'TMPDIR':str(scratch/'tmp'),'CARGO_HOME':str(scratch/'cargo-home'),
             'CARGO_TARGET_DIR':str(scratch/'target'),'CARGO_NET_OFFLINE':'true',
             'CARGO_BUILD_JOBS':'2','RUSTUP_AUTO_INSTALL':'0','GIT_CONFIG_NOSYSTEM':'1',
             'GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0'}
        def clean():
            assert subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=source,env=env,timeout=10).decode().strip()==a.expected_commit
            assert not subprocess.check_output(['/usr/bin/git','status','--porcelain','--untracked-files=all'],cwd=source,env=env,timeout=10)
        clean()
        steps=[('native-build',['build','--offline','--locked','-p','agentfw','--bins'],None),
               ('native-closure-unit',['test','--offline','--locked','-p','agentfw','--lib','verified_closure'],r'test result: ok\. [1-9][0-9]* passed; 0 failed;'),
               ('native-execution-unit',['test','--offline','--locked','-p','agentfw','--lib','native::execution'],r'test result: ok\. [1-9][0-9]* passed; 0 failed;'),
               ('native-owner-unit',['test','--offline','--locked','-p','agentfw','--lib','mcp::linux_owner'],r'test result: ok\. [1-9][0-9]* passed; 0 failed;'),
               ('native-clippy',['clippy','--offline','--locked','-p','agentfw','--all-targets','--','-D','warnings'],None)]
        for label,words,witness in steps:
            step={'label':label,'status':'incomplete'};record['steps'].append(step);save()
            log=scratch/(label+'.private.log');start=time.monotonic()
            with log.open('wb') as stream:
                result=subprocess.run([str(a.cargo),*words],cwd=source,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=1200)
            raw=log.read_bytes();step.update(exit_code=result.returncode,elapsed_seconds=round(time.monotonic()-start,2),log_sha256=hashlib.sha256(raw).hexdigest())
            assert result.returncode==0,label+'_failed'
            if witness:assert re.search(witness,raw.decode(errors='replace')),label+'_empty'
            step['status']='passed';save()
        clean();binary=scratch/'target/debug/agentfw';record['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        record['status']='passed';save();return 0
    except (AssertionError,OSError,subprocess.SubprocessError) as error:
        record.update(status='failed',reason=str(error) if isinstance(error,AssertionError) else 'native_build_incomplete')
        save();return 1

if __name__=='__main__':raise SystemExit(main())
