#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Four real Agents: gated waves, adverse ACKs, restart, encrypted recovery and confirmed rollback.

SQLite is disposable automatically. PostgreSQL requires two explicitly supplied,
owned disposable databases: source and empty restore target. Never use production URLs.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import console_recovery as recovery

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTCOME = ROOT / 'target' / 'managed-group-rollout-evidence.json'


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(method, url, payload=None, headers=None, expected=200):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method=method,
        headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status, raw = response.status, response.read(120000)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(120000)
    assert status == expected, f'{method} {req.selector.split("?")[0]}: expected {expected}, got {status}'
    return json.loads(raw) if raw else None


def wait(label, fn, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.2)
    raise AssertionError(label + ' timed out')


def stop(process):
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=10)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--backend', choices=['sqlite', 'postgres'], default='sqlite')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTCOME)
    parser.add_argument('--database-url-env', default='SOUP_GROUP_DEMO_DATABASE_URL')
    parser.add_argument('--restore-url-env', default='SOUP_GROUP_DEMO_RESTORED_URL')
    parser.add_argument('--age', default='age')
    parser.add_argument('--age-keygen', default='age-keygen')
    parser.add_argument('--psql', default='psql')
    parser.add_argument('--pg-dump', default='pg_dump')
    parser.add_argument('--pg-restore', default='pg_restore')
    args = parser.parse_args()
    if not args.no_build:
        subprocess.run(['cargo', 'build', '--locked', '-p', 'llm-firewall', '-p', 'agentfw'], cwd=ROOT, check=True)
    console_bin, agent_bin = [ROOT / 'target/debug' / name for name in ('llm-firewall', 'agentfw')]
    inputs = [Path(__file__).resolve(), ROOT / 'scripts/console_recovery.py', ROOT / 'scripts/fixtures/console_recovery_inventory_v1.json', ROOT / 'Cargo.lock', ROOT / 'Cargo.toml']
    for crate in ('core','proxy','agent','agentfw'):
        inputs += [ROOT / 'crates' / crate / 'Cargo.toml']
        inputs += sorted((ROOT / 'crates' / crate / 'src').rglob('*.rs'))
        if (ROOT / 'crates' / crate / 'build.rs').exists(): inputs.append(ROOT / 'crates' / crate / 'build.rs')
    report = {'schema_version': 1, 'backend': args.backend, 'started_at_unix': int(time.time()),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=ROOT)).hexdigest(),
        'source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in inputs},
        'binary_sha256': {'llm-firewall': digest(console_bin), 'agentfw': digest(agent_bin)},
        'checks': {}, 'passed': False, 'cleanup_passed': False,
        'configuration': {'transport': 'literal loopback HTTP', 'agents': 4, 'pilots': 1,
                          'external_provider_calls': 0, 'recovery_schema': 27},
        'limitations': ['Disposable local processes; no production multi-host or remote-attestation claim']}
    def check(label, value):
        report['checks'][label] = bool(value)
        assert value, label
        print('PASS: ' + label, flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='sou47-live-') as folder, ExitStack() as stack:
            temp = Path(folder).resolve()
            os.chmod(temp, 0o700)
            source_sqlite = temp / 'source.sqlite'
            restored_sqlite = temp / 'restored.sqlite'
            source_url = os.environ.get(args.database_url_env) if args.backend == 'postgres' else None
            restore_url = os.environ.get(args.restore_url_env) if args.backend == 'postgres' else None
            if args.backend == 'postgres':
                assert source_url and restore_url, 'two explicit disposable database URLs required'
                recovery.PostgresBackend(restore_url, directory=temp, psql=args.psql).require_owned()
                recovery.PostgresBackend(restore_url, directory=temp, psql=args.psql).require_empty()
            cp = port()
            base = f'http://127.0.0.1:{cp}'
            cfg = temp / 'firewall.yaml'
            admin = {'x-llm-firewall-admin-token': 'Bearer ' + secrets.token_urlsafe(32)}
            env = os.environ.copy()
            env.update({'LLM_FW_ADMIN_TOKEN': admin['x-llm-firewall-admin-token'][7:],
                'SOUP_AGENT_POLICY_KEY_ID': 'group-demo-key', 'SOUP_AGENT_POLICY_SEED_HEX': secrets.token_hex(32),
                'SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED_KEY': secrets.token_hex(32),
                'OPENAI_API_KEY': '', 'LLM_FW_OPENAI_API_KEY': ''})
            def configuration(database):
                cfg.write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n  backend: {args.backend}\n' +
                    (f'  database_path: "{database}"\n' if args.backend == 'sqlite' else ''))
                if args.backend == 'postgres':
                    env['LLM_FW_POSTGRES_URL'] = database
            configuration(str(source_sqlite) if args.backend == 'sqlite' else source_url)
            if args.backend == 'postgres':
                subprocess.run([str(console_bin), 'migrate'], cwd=temp, env=env, check=True, stdout=subprocess.DEVNULL)
            children = []
            def spawn(binary, environment, log):
                output = stack.enter_context((temp / log).open('ab'))
                child = subprocess.Popen([str(binary), *(['serve'] if binary == agent_bin else [])], cwd=temp,
                    env=environment, stdout=output, stderr=subprocess.STDOUT)
                children.append(child)
                stack.callback(stop, child)
                return child
            console = spawn(console_bin, env, 'console.log')
            wait('Console healthy', lambda: request('GET', base + '/healthz'))
            tenant = request('POST', base + '/admin/v1/tenants', {'name': 'SOU-47 live controls'}, admin, 201)['id']
            api = base + f'/admin/v1/tenants/{tenant}/groups/fleet'
            request('POST', base + f'/admin/v1/tenants/{tenant}/groups', {'group_id': 'fleet', 'name': 'Fleet'}, admin, 201)
            public = request('GET', base + '/admin/v1/managed-issuer', headers=admin)['public_key_hex']
            agents = {}
            for name, pilot in [('pilot', True), ('worker-1', False), ('worker-2', False), ('worker-3', False)]:
                enrollment = request('POST', base + f'/admin/v1/tenants/{tenant}/agents', {'agent_id': name}, admin, 201)
                request('POST', api + '/members', {'agent_id': name, 'is_pilot': pilot}, admin, 201)
                home = temp / name
                (home / '.agentfw').mkdir(parents=True)
                ap = port()
                (home / '.agentfw/config.yaml').write_text(f'bind: 127.0.0.1\nport: {ap}\nenforce: true\n')
                agent_env = {k:v for k,v in env.items() if k not in ('SOUP_AGENT_POLICY_SEED_HEX', 'SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED_KEY', 'LLM_FW_ADMIN_TOKEN', 'LLM_FW_POSTGRES_URL')}
                agent_env.update({'HOME': str(home), 'SOUP_MANAGED_AGENT_CONSOLE': base + '/',
                    'SOUP_MANAGED_AGENT_TOKEN': enrollment['token'], 'SOUP_MANAGED_AGENT_TENANT': tenant,
                    'SOUP_MANAGED_AGENT_ID': name, 'SOUP_MANAGED_AGENT_KEY_ID': 'group-demo-key',
                    'SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX': public})
                process = spawn(agent_bin, agent_env, name + '.log')
                agents[name] = {'env': agent_env, 'home': home, 'url': f'http://127.0.0.1:{ap}',
                                'process': process, 'token': enrollment['token']}
                wait(name + ' healthy', lambda name=name: request('GET', agents[name]['url'] + '/health'))
            def current(): return request('GET', api + '/rollout', headers=admin)
            def phase(wanted):
                value = current()
                return value if value['phase'] == wanted else None
            def revision(name, value):
                request('POST', api + '/revisions', {'revision': name, 'policy_yaml': f'default: {value}\n'}, admin, 201)
                request('POST', api + f'/revisions/{name}/approve', {}, admin, 204)
            def applied(name, rev, seq):
                value = request('GET', agents[name]['url'] + '/health').get('managed_policy')
                return value if value and value['revision'] == rev and value['deployment_sequence'] == seq else None
            def hook(name):
                token = wait('hook token', lambda: (agents[name]['home'] / '.agentfw/token').read_text().strip()
                    if (agents[name]['home'] / '.agentfw/token').exists() else None)
                data = request('POST', agents[name]['url'] + '/hook', {'session_id':'sou47-live','hook_event_name':'PreToolUse',
                    'tool_name':'Bash','tool_input':{'command':'echo sou47-controlled'}}, {'Authorization': 'Bearer ' + token})
                return data.get('hookSpecificOutput', {}).get('permissionDecision', 'allow')
            revision('baseline', 'deny')
            request('POST', api + '/rollout', {'revision':'baseline'}, admin, 201)
            wait('baseline complete', lambda: phase('completed'))
            for name in agents:
                wait(name + ' baseline', lambda name=name: applied(name, 'baseline', 1))
                check(name + '-baseline-hook-deny', hook(name) == 'deny')
            # Offline canary makes the gate observable, without fabricating an ACK.
            stop(agents['pilot']['process'])
            revision('candidate', 'allow')
            candidate = request('POST', api + '/rollout', {'revision':'candidate'}, admin, 201)
            check('only-pilot-issued-before-gate', set(candidate['active_deployments']) == {'pilot'})
            for name in agents:
                if name != 'pilot':
                    check(name + '-offline-canary-keeps-baseline', hook(name) == 'deny')
            expected_seq = candidate['active_deployments']['pilot']
            for label, name, sequence, sha in [('wrong-digest','pilot',expected_seq,'0'*64),
                ('stale-sequence','pilot',1,candidate['policy_sha256']),('wrong-agent','worker-1',expected_seq,candidate['policy_sha256'])]:
                result = request('POST', base + '/agent/v1/policy/ack', {'deployment_sequence':sequence,
                    'revision':'candidate','policy_sha256':sha,'status':'applied'},
                    {'Authorization':'Bearer '+agents[name]['token']}, 409)
                check(label + '-does-not-open-gate', current()['phase']=='pilot')
            request('POST', api + '/rollout/pause', {}, admin)
            stop(console)
            # Both recovery backends retain the actual paused plan and all per-Agent identities.
            identity, archive = temp / 'identity.age', temp / 'backup.age'
            subprocess.run([args.age_keygen,'-o',str(identity)], check=True, capture_output=True)
            os.chmod(identity,0o600)
            recipient = subprocess.check_output([args.age_keygen,'-y',str(identity)],text=True).strip()
            if args.backend == 'sqlite':
                os.chmod(source_sqlite,0o600)
                backed = recovery.backup_sqlite(source_sqlite,archive,recipient,workdir=temp,age=args.age)
                restored = recovery.restore_sqlite(archive,restored_sqlite,identity,workdir=temp,age=args.age)
                configuration(str(restored_sqlite))
            else:
                backed = recovery.backup_postgres(source_url,archive,recipient,workdir=temp,age=args.age,
                    psql=args.psql,pg_dump=args.pg_dump,source_quiesced=True)
                restored = recovery.restore_postgres(archive,restore_url,identity,workdir=temp,age=args.age,
                    psql=args.psql,pg_restore=args.pg_restore)
                configuration(restore_url)
            check('encrypted-recovery-full-private-state-equal', backed['private_state_sha256']==restored['private_state_sha256'])
            report['recovery'] = {'tables_verified': restored['tables_verified'], 'sequences_verified':restored['sequences_verified']}
            console = spawn(console_bin,env,'console-restored.log')
            wait('restored Console',lambda: request('GET',base+'/healthz'))
            recovered = current()
            check('restart-and-recovery-preserve-paused-plan', recovered['phase']=='paused' and recovered['rollout_id']==candidate['rollout_id'] and recovered['active_deployments']==candidate['active_deployments'])
            request('POST',api+'/rollout/resume',{},admin)
            retried = request('POST',api+'/rollout',{'revision':'candidate'},admin,201)
            check('retried-start-keeps-identities', retried['rollout_id']==candidate['rollout_id'] and retried['active_deployments']==candidate['active_deployments'])
            agents['pilot']['process']=spawn(agent_bin,agents['pilot']['env'],'pilot-restarted.log')
            wait('candidate complete',lambda: phase('completed'))
            for name in agents:
                wait(name+' candidate applied',lambda name=name:applied(name,'candidate',2))
                check(name+'-candidate-hook-allow',hook(name)=='allow')
            rb=request('POST',api+'/rollout/rollback',{},admin)
            check('manual-rollback-is-pending',rb['phase']=='rolling_back')
            wait('confirmed rollback',lambda:phase('rolled_back'))
            for name in agents:
                wait(name+' rollback applied',lambda name=name:applied(name,'baseline',3))
                check(name+'-rollback-hook-deny',hook(name)=='deny')
            revision('untrusted','allow')
            request('POST',api+'/rollout',{'revision':'untrusted','issuer_key_id':'untrusted-key'},admin,201)
            rejected=wait('rejection confirmed rollback',lambda:phase('rolled_back'))
            check('untrusted-canary-rejected', 'rejected' in rejected['failure_reason'])
            wait('pilot rejection recovery',lambda:applied('pilot','baseline',5))
            for name in agents:
                check(name+'-after-rejection-hook-deny',hook(name)=='deny')
                if name!='pilot': check(name+'-never-received-untrusted-wave',bool(applied(name,'baseline',3)))
            report['passed']=True
        report['cleanup_passed']=all(p.poll() is not None for p in children)
    finally:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    assert report['cleanup_passed']
    print('Evidence: '+str(args.output))

if __name__=='__main__':
    main()
