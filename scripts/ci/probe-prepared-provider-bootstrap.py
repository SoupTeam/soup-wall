#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Diagnostic only: pinned host --version, never provider credentials or tools."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import signal
import struct
import subprocess

HOST_SHA = 'fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7'
PREFIX = b'import {createRequire} from "node:module"; const require=createRequire("file:///agentfw-provider-preload.cjs");\n'
TERMS = ('permission denied', 'preload', 'bunfig', 'config', 'cache', 'read', 'write',
         'module', 'require', 'unsupported', 'code generation', 'not found', 'syntaxerror',
         'sw-provider-bootstrap-failed/hooks', 'sw-provider-bootstrap-failed/descriptors',
         'sw-provider-bootstrap-failed/ready', 'sw-provider-bootstrap-failed/delivery',
         'sw-provider-bootstrap-failed/values')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'host', 'scratch', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--run', action='store_true')
    a = p.parse_args()
    if not a.run:
        print(json.dumps({'status':'plan', 'provider_values_supplied':False, 'tools_started':False}))
        return 0
    if os.geteuid() == 0 or {name for _,name in socket.if_nameindex()} != {'lo'}:
        raise ValueError('ordinary_user_private_loopback_required')
    if hashlib.file_digest(a.host.open('rb'), 'sha256').hexdigest() != HOST_SHA:
        raise ValueError('pinned_host_required')
    if not os.statvfs(a.source).f_flag & os.ST_RDONLY or a.scratch.resolve().is_relative_to(a.source.resolve()):
        raise ValueError('read_only_source_and_isolated_scratch_required')
    a.scratch.mkdir(mode=0o700)
    code = (a.source / 'crates/agentfw/src/pilot_host/provider_preload.cjs').read_bytes()
    inline = base64.b64encode(PREFIX + code).decode()
    results=[]
    for name in ('plain-version', 'inline-version', 'inline-no-cache', 'inline-restricted-version'):
        root=a.scratch/name;root.mkdir(mode=0o700)
        config=root/'empty.toml';config.write_text('')
        env={'PATH':'/usr/bin:/bin', 'HOME':str(root), 'TMPDIR':str(root), 'LANG':'C.UTF-8',
             'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1', 'DISABLE_AUTOUPDATER':'1'}
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        parent.settimeout(3)
        child.setsockopt(socket.SOL_SOCKET,socket.SO_RCVTIMEO,struct.pack("ll",3,0))
        fd=os.memfd_create('owned-bootstrap-code-probe',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        os.write(fd,code)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK)
        args=[str(a.host)]
        if name=='inline-restricted-version':args.append('--restricted')
        args.append('--version')
        if name!='plain-version':
            env.update(BUN_OPTIONS='--preload=data:text/javascript;base64,'+inline+' --config='+str(config)+' --no-env-file',
                       AGENTFW_PROVIDER_CHANNEL=str(child.fileno()),AGENTFW_PROVIDER_CODE=str(fd))
        if name=='inline-no-cache':env['BUN_RUNTIME_TRANSPILER_CACHE_PATH']='0'
        row={'case':name,'greeting_received':False,'provider_values_supplied':False,'tools_started':False}
        process=None
        try:
            with (root/'stdout.private').open('xb') as out, (root/'stderr.private').open('xb') as err:
                command=['/usr/bin/strace','-f','-qq','-s','256','-e','trace=openat','-o',str(root/'trace.private'),*args]
                process=subprocess.Popen(command,env=env,cwd=root,pass_fds=(child.fileno(),fd),stdout=out,stderr=err,start_new_session=True)
                child.close();os.close(fd);fd=None
                if name!='plain-version':
                    try:
                        row['greeting_received']=parent.recv(64)==b'sw-provider-ready/1'
                        if row['greeting_received']:parent.send(b'{}')
                    except (OSError,TimeoutError):pass
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
                row['exit_code']=process.returncode
            error=(root/'stderr.private').read_bytes()[:65536].decode(errors='replace').lower()
            row['error_terms']=[term for term in TERMS if term in error]
            row['version_reported']=b'2.1.251' in (root/'stdout.private').read_bytes()[:1024]
            refused={}
            for line in (root/'trace.private').read_text().splitlines():
                m=re.search(r'openat\([^,]+, "([^"\n]+)".* = -1 (EACCES|EPERM|EROFS)',line)
                if m:
                    path,errno=m.groups()
                    role='bun-config' if path.endswith('empty.toml') else 'proc-fd' if path.startswith('/proc/self/fd/') else \
                         'runtime-cache' if 'cache' in path or 'transpiler' in path else 'other'
                    key=role+':'+errno;refused[key]=refused.get(key,0)+1
            row['denied_open_categories']=refused
        finally:
            if process is not None and process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
            child.close();parent.close()
            if fd is not None:os.close(fd)
        row['status']='passed' if row.get('exit_code')==0 and row.get('version_reported') and \
            (name=='plain-version' or row['greeting_received']) else 'failed'
        results.append(row)
    a.output.write_text(json.dumps({'format':'sou143-pinned-bootstrap-probe/1','status':'diagnostic-completed',
        'host_sha256':HOST_SHA,'provider_values_supplied':False,'tools_started':False,'cases':results},indent=2)+'\n')
    return 0


if __name__=='__main__':raise SystemExit(main())
