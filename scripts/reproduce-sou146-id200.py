#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Direct pinned original-server reproduction, not protected-host acceptance.

Run with the Python 3.11 environment installed from the shipped hash-locked
original Git requirements. Only a new owned synthetic Git repository is used.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]


def original_environment(git):
    # A caller's GIT_DIR/config/object paths must never redirect this owned fixture.
    env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',
        GIT_AUTHOR_DATE='2026-10-25T04:47:21+0000',GIT_COMMITTER_DATE='2026-10-25T04:47:21+0000',
        GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0',GIT_PYTHON_GIT_EXECUTABLE=str(git))
    return env


def main(args):
    if importlib.metadata.version('mcp-server-git') != '2026.10.10':
        raise ValueError('original_server_version')
    args.output.mkdir(parents=True,exist_ok=True)
    env=original_environment(args.git)
    with tempfile.TemporaryDirectory(prefix='sou109-id200-') as directory:
        repo=Path(directory)
        def git(*words):
            return subprocess.check_output([str(args.git),'-c','user.name=SOU146 Synthetic',
                '-c','user.email=sou146@example.invalid',*words],cwd=repo,env=env,
                stderr=subprocess.PIPE,timeout=10).decode().strip()
        git('init','--initial-branch=main','--template=')
        paths=('notes.txt','docs/機能 notes.txt','docs/café.txt','.hidden.txt')
        for phase,expected in [('first','a1e90c69c86298f5e4a408bb076288b2a5a63e02'),
                               ('second','c8bc56ae3efc68049f4ba1131dfb30d3c13e18f3')]:
            for name in paths:
                path=repo/name;path.parent.mkdir(exist_ok=True)
                path.write_bytes(('Synthetic per-file '+phase+' version.\n').encode())
            git('add','.')
            git('commit','-m','Synthetic per-file '+('baseline' if phase=='first' else 'second version'))
            if git('rev-parse','HEAD') != expected: raise ValueError('commit_identity')
        (repo/'notes.txt').write_bytes(b'Synthetic staged version.\n');git('add','notes.txt')
        (repo/'notes.txt').write_bytes(b'Synthetic working version.\n')
        before=git('status','--porcelain=v1')
        received=queue.Queue()
        with (args.output/'stderr.log').open('wb') as err:
            process=subprocess.Popen([sys.executable,'-I','-B','-m','mcp_server_git',
                '--repository',str(repo)],env=env,cwd=repo,stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=err,start_new_session=True)
            def reader():
                for raw in process.stdout: received.put(raw)
            threading.Thread(target=reader,daemon=True).start()
            def send(v):
                process.stdin.write((json.dumps(v,separators=(',',':'))+'\n').encode());process.stdin.flush()
            def response(identifier):
                while True:
                    raw=received.get(timeout=10)
                    if json.loads(raw).get('id')==identifier:return raw
            try:
                send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
                    'protocolVersion':'2025-11-25','capabilities':{},
                    'clientInfo':{'name':'sou109-id200-reproduction','version':'1'}}})
                response(1)
                send({'jsonrpc':'2.0','method':'notifications/initialized'})
                send({'jsonrpc':'2.0','id':200,'method':'tools/call','params':{
                    'name':'git_show','arguments':{'repo_path':str(repo),'revision':'HEAD'}}})
                raw=response(200)
                (args.output/'server-response200.jsonl').write_bytes(raw)
            finally:
                process.stdin.close()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
            if process.returncode != 0: raise ValueError('original_cleanup')
        if git('status','--porcelain=v1') != before: raise ValueError('repository_changed')
        retained=json.loads(args.expected_frame.read_bytes())
        fresh=json.loads(raw)
        if fresh['result'] != retained['result']: raise ValueError('result_bytes_changed')
    report={'source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip(),
        'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'original_server':'mcp-server-git '+importlib.metadata.version('mcp-server-git'),
        'runtime':'CPython '+sys.version.split()[0],
        'python_binary_sha256':hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
        'git_binary_sha256':hashlib.sha256(args.git.read_bytes()).hexdigest(),
        'git_version':subprocess.check_output([str(args.git),'--version']).decode().strip(),
        'scope':'fresh direct original-server ID200; not historical raw ID200 or protected admission',
        'commit':'c8bc56ae3efc68049f4ba1131dfb30d3c13e18f3','result_equals_retained_id20':True,
        'workspace_unchanged':True,'returncode':process.returncode,
        'frame_sha256':hashlib.sha256(raw).hexdigest(),
        'channel_sha256':hashlib.sha256(fresh['result']['content'][0]['text'].encode()).hexdigest(),
        'requirements_lock_sha256':hashlib.sha256((ROOT/'profiles/mcp/git-readonly-v1/requirements.lock').read_bytes()).hexdigest()}
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git',type=Path,default=Path('/usr/bin/git'))
    parser.add_argument('--expected-frame',type=Path,default=ROOT/'crates/agent/tests/fixtures/result_detector/sou146-original/server-response20.jsonl')
    parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args())
