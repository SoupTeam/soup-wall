#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Online trusted public-input setup; never executes candidate code or packages."""
import argparse,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path

BASE='3c9cfb08c0f1498676dcc70de131bd2f324dd13b'
DOWNLOADS={
 'node':('https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz','9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37'),
 'bwrap':('https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz','0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d')}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--expected-commit',required=True);a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.resolve(strict=True)
 os.umask(0o077);assert not out.is_relative_to(source)
 record={'format':'sou155-public-inputs/1','status':'incomplete','source_commit':a.expected_commit,'candidate_code_executed':False,'steps':[]}
 def save():(out/'setup.json').write_text(json.dumps(record,indent=2)+'\n')
 save()
 def git(*words):return subprocess.check_output(['/usr/bin/git',*words],cwd=source,timeout=20)
 env={'PATH':'/usr/bin:/bin','HOME':str(out/'home'),'TMPDIR':str(out/'tmp'),'LANG':'C.UTF-8',
      'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
 for name in ('home','tmp','assets','npm-cache'):(out/name).mkdir(mode=0o700)
 def run(label,words,selected=None):
  step={'label':label,'status':'incomplete'};record['steps'].append(step);save();log=out/(label+'.private.log')
  with log.open('xb') as stream:result=subprocess.run(list(map(str,words)),cwd=out,env=selected or env,stdout=stream,stderr=subprocess.STDOUT,timeout=600)
  step.update(exit_code=result.returncode,log_sha256=sha(log),status='passed' if result.returncode==0 else 'failed');save()
  if result.returncode:raise RuntimeError(label+'_failed')
 try:
  assert git('rev-parse','HEAD').decode().strip()==a.expected_commit and not git('status','--porcelain','--untracked-files=all')
  for name in ('package.json','package-lock.json','upstream-identity.json'):
   path='profiles/mcp/filesystem-readonly-v1/'+name;assert (source/path).read_bytes()==git('show',BASE+':'+path)
  for name,(url,digest) in DOWNLOADS.items():
   archive=out/'assets'/(name+'.tar.xz');run('download-'+name,['curl','--fail','--location','--retry','3',url,'--output',archive]);assert sha(archive)==digest
   directory=out/'assets'/name;directory.mkdir(mode=0o700)
   run('extract-'+name,['tar','-xf',archive,'-C',directory,'--strip-components=1','--no-same-owner','--no-same-permissions'])
  cap=out/'assets/libcap';cap.mkdir();run('download-libcap',['apt-get','download','libcap-dev'])
  deb=list(out.glob('libcap-dev_*.deb'));assert len(deb)==1
  run('extract-libcap',['dpkg-deb','-x',deb[0],cap]);lib=cap/'usr/lib/x86_64-linux-gnu'
  shutil.copyfile('/lib/x86_64-linux-gnu/libcap.so.2',lib/'libcap.so.2')
  if (lib/'libcap.so').exists() or (lib/'libcap.so').is_symlink():(lib/'libcap.so').unlink()
  (lib/'libcap.so').symlink_to('libcap.so.2');(cap/'usr/lib64').symlink_to(lib)
  run('meson',['/usr/bin/python3','-m','pip','--isolated','install','--disable-pip-version-check','--target',out/'assets/tools','meson==1.9.1'])
  run('download-ninja',['apt-get','download','ninja-build']);ninja=out/'assets/ninja';ninja.mkdir();deb=list(out.glob('ninja-build_*.deb'));assert len(deb)==1
  run('extract-ninja',['dpkg-deb','-x',deb[0],ninja])
  build=dict(env,PYTHONPATH=str(out/'assets/tools'),PATH=str(ninja/'usr/bin')+':/usr/bin:/bin',
    PKG_CONFIG_LIBDIR=str(lib/'pkgconfig'),PKG_CONFIG_SYSROOT_DIR=str(cap))
  run('configure-bwrap',['/usr/bin/python3','-m','mesonbuild.mesonmain','setup',out/'assets/bwrap-build',out/'assets/bwrap',
      '-Dtests=false','-Dman=disabled','-Dselinux=disabled','-Dbash_completion=disabled','-Dzsh_completion=disabled'],build)
  run('compile-bwrap',['/usr/bin/python3','-m','mesonbuild.mesonmain','compile','-C',out/'assets/bwrap-build'],build)
  seed=out/'assets/fs-seed';seed.mkdir();
  for name in ('package.json','package-lock.json'):shutil.copyfile(source/'profiles/mcp/filesystem-readonly-v1'/name,seed/name)
  for name in ('empty-user.npmrc','empty-global.npmrc'):(out/name).write_bytes(b'')
  node_env=dict(env,PATH=str(out/'assets/node/bin')+':/usr/bin:/bin')
  run('cache-filesystem',[out/'assets/node/bin/npm','ci','--ignore-scripts','--no-audit','--no-fund',
      '--userconfig='+str(out/'empty-user.npmrc'),'--globalconfig='+str(out/'empty-global.npmrc'),
      '--cache',out/'npm-cache','--prefix',seed],node_env)
  record.update(status='prepared',node_sha256=sha(out/'assets/node/bin/node'),bwrap_sha256=sha(out/'assets/bwrap-build/bwrap'))
  save();return 0
 except (AssertionError,OSError,RuntimeError,subprocess.SubprocessError) as error:
  record.update(status='failed',reason=str(error) if isinstance(error,RuntimeError) else 'public_input_setup_incomplete');save();return 1
if __name__=='__main__':raise SystemExit(main())
