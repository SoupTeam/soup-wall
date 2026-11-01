#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in mapped original Git consumer; public plans never provide authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PREP = load('sou157_preparation', 'prepare-sou157-git.py')
sha, canonical, require = PREP.sha, PREP.canonical, PREP.require


def frame_text(frame, identifier):
    value = json.loads(frame)
    require(value.get('jsonrpc') == '2.0' and type(value.get('id')) is int
            and value['id'] == identifier and 'error' not in value, 'original_frame_binding')
    result = value.get('result', {})
    parts = result.get('content')
    require(result.get('isError') is not True and isinstance(parts, list) and len(parts) == 1
            and parts[0].get('type') == 'text' and isinstance(parts[0].get('text'), str),
            'original_text_shape')
    return parts[0]['text'].encode('utf-8')


def validate_reply(value, call, profile, identifier, expected, release):
    """Strict response checks; only a real private endpoint may supply value."""
    receipt = value.get('receipt', {})
    require(value.get('completed') is True and value.get('profile_sha256') == sha(canonical(profile)),
            'private_profile_completion')
    require(receipt.get('release') is release, 'unexpected_release')
    require(receipt.get('verdict', '').lower() == ('allow' if release else 'deny'), 'unexpected_verdict')
    frame = value.get('frame')
    if release:
        require(isinstance(frame, str) and sha(frame.encode()) == receipt.get('content_sha256'),
                'private_channel_digest')
        require(frame_text(frame, identifier) == expected, 'private_original_bytes_changed')
    else:
        require(frame is None, 'refused_frame_exposed')
    return {'release': release, 'verdict': receipt.get('verdict'),
            'content_sha256': receipt.get('content_sha256'), 'call_id': call['call_id'],
            'binding_sha256': call['binding_sha256']}


def main(args):
    require(sys.platform == 'linux' and os.geteuid() != 0, 'ordinary_native_linux_required')
    require(re.fullmatch('[0-9a-f]{40}', args.expected_commit or ''), 'exact_source_required')
    for pin in (args.profile_sha256, args.binary_sha256):
        require(re.fullmatch('[0-9a-f]{64}', pin or ''), 'independent_input_pins_required')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, timeout=10).decode().strip()
    require(source == args.expected_commit and not subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT, timeout=10), 'clean_exact_source_required')
    binary = Path(args.binary).resolve(strict=True)
    require(sha(binary.read_bytes()) == args.binary_sha256, 'binary_pin_mismatch')
    require(args.build_report is not None, 'exact_source_build_report_required')
    build = json.loads(args.build_report.read_bytes())
    require(build.get('format') == 'sou155-native-build/1' and build.get('status') == 'passed'
            and build.get('source_commit') == source and build.get('binary_sha256') == args.binary_sha256,
            'build_source_binary_mismatch')
    require(os.statvfs(ROOT).f_flag & os.ST_RDONLY and os.statvfs(binary).f_flag & os.ST_RDONLY,
            'readonly_source_and_binary_required')
    require({name for _, name in socket.if_nameindex()} == {'lo'}, 'private_loopback_required')
    raw = args.template_profile.read_bytes()
    require(sha(raw) == args.profile_sha256, 'template_pin_mismatch')
    profile = json.loads(raw)
    require(profile.get('format') == 'sw-mcp/git-readonly/1', 'default_profile_only')
    base = load('sou157_transport', 'verify-sou62-real-mcp.py')
    witness = load('sou157_git_witness', 'verify-sou146-git-file-revisions.py')
    install = load('sou157_installer', 'install-sou68-git-profile.py')
    def pins():
        for path, digest in [(profile['runtimePath'], profile['runtimeSha256']),
                             (profile['bwrapPath'], profile['bwrapSha256']),
                             *[(profile[k]['path'], profile[k]['sha256']) for k in ('git', 'gitLauncher')],
                             *[(lib['path'], lib['sha256']) for lib in profile['libraries']]]:
            require(sha(Path(path).read_bytes()) == digest, 'runtime_asset_changed')
        require(install.tree_sha(Path(profile['packageRoot'])) == profile['packageTreeSha256'], 'package_tree_changed')
    pins()
    output = Path(args.output).absolute()
    # Exclusively allocate the evidence file and a genuinely owned private parent.
    os.umask(0o077)
    with output.open('xb') as stream:
        stream.write(b'{"status":"incomplete"}\n')
    owned = Path(tempfile.mkdtemp(prefix='sou157-native-git-'))
    st = owned.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
            and stat.S_IMODE(st.st_mode) == 0o700, 'private_parent_not_owned')
    report = {'format': 'sou157-mapped-git-native/1', 'status': 'incomplete', 'source_commit': source,
              'binary_sha256': args.binary_sha256, 'template_profile_sha256': args.profile_sha256,
              'owned_parent': str(owned), 'model_calls': 0, 'frozen_false_refusals': 10,
              'production_authority': False, 'task_complete': False, 'cases': []}
    report['independent_attack_controls'] = {
        'g01-b': 'reviewer-directed shell execution', 'g03-b': 'matched original attack',
        'g07-a': 'Spanish agent-directed credential instruction',
        'g09-a': 'Kazakh agent-directed credential exfiltration'}
    def save():
        output.write_bytes(canonical(report) + b'\n')
    try:
        plan = PREP.prepare_repositories(owned / 'cases', profile['git']['path'], profile['git']['sha256'])
        report['preparation'] = plan
        save()
        manifest = json.loads((ROOT / 'profiles/mcp/git-readonly-v1/upstream-tools-list.json').read_bytes())
        registry = canonical(install.registry(manifest))
        policy = (ROOT / 'profiles/mcp/git-readonly-v1/policy.yaml').read_bytes()
        report['registry_sha256'], report['policy_sha256'] = sha(registry), sha(policy)
        for case, prepared in zip(PREP.inventory(), plan['cases'], strict=True):
            row = {**PREP.mapped_case(case), 'status': 'incomplete', 'controls': {}}
            report['cases'].append(row)
            save()
            if not prepared['commit_matches_frozen_header']:
                row['status'] = 'non_comparable_commit'
                continue
            repo = Path(prepared['repository'])
            root = owned / case['case_id']
            root.mkdir(mode=0o700)
            env = base.environment(root)
            env.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', GIT_CONFIG_NOSYSTEM='1',
                       GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null',
                       GIT_OPTIONAL_LOCKS='0', GIT_PYTHON_GIT_EXECUTABLE=profile['git']['path'])
            before = base.snapshot(repo)
            # Independent original stdio reference, in the private no-network
            # qualification unit. Its host path is explicit reference metadata,
            # never the mapped protected request or execution authority.
            with (root / 'reference.private.log').open('xb') as log:
                reference = base.Client([profile['runtimePath'], '-I', '-B', '-m', 'mcp_server_git',
                                         '--repository', str(repo)], env, repo, log, 'sou157-reference')
                try:
                    reference.exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                        'protocolVersion': '2025-11-25', 'capabilities': {},
                        'clientInfo': {'name': 'sou157-reference', 'version': '1'}}})
                    reference.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                    discovered, _ = reference.exchange({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
                    require(discovered.get('result') == manifest['result'], 'reference_manifest_changed')
                    _, original_frame = reference.exchange({'jsonrpc': '2.0', 'id': 10, 'method': 'tools/call',
                        'params': {'name': 'git_show', 'arguments': {'repo_path': str(repo), 'revision': 'HEAD'}}})
                    original = frame_text(original_frame, 10)
                finally:
                    require(reference.close() == 0 and not reference.forced_cleanup
                            and reference.process_witness.final['all_stopped'], 'reference_cleanup_failed')
            row['reference_host_arguments'] = {'repo_path': str(repo), 'revision': 'HEAD'}
            row['reference_frame_sha256'] = sha(original_frame)
            row['byte_gate'] = PREP.compare_original_text(case, original)
            require(base.snapshot(repo) == before, 'reference_changed_source')
            if not row['byte_gate']['comparable']:
                row['status'] = 'non_comparable_original_text'
                save()
                continue
            selected = dict(profile)
            st = repo.stat()
            selected.update(workspace=str(repo), workspaceIdentity={'device': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid})
            profile_path = root / 'profile.json'
            profile_path.write_bytes(canonical(selected))
            row['selected_profile_sha256'] = sha(profile_path.read_bytes())
            for mode in ('allow', 'ask', 'deny', 'expired') if case['label'] == 'benign' else ('allow',):
                result = run_daemon(binary, root / mode, repo, selected, profile_path, registry,
                                    policy, original, original_frame, case, mode, env, witness.DaemonProcessWitness)
                row['controls'][mode] = result
                save()
            require(base.snapshot(repo) == before, 'qualification_changed_source')
            row['source_unchanged'] = True
            row['status'] = 'mapped_delivery_controls_passed'
            save()
        pins()
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, timeout=10).decode().strip() == source
                and not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT, timeout=10),
                'qualification_source_changed')
        # A mapped qualification never changes original frozen-corpus counts.
        report['all_mapped_cases_comparable'] = all(r['status'] == 'mapped_delivery_controls_passed' for r in report['cases'])
        report['status'] = ('mapped_controls_passed_requires_independent_review'
                            if report['all_mapped_cases_comparable'] else 'non_comparable')
        return 0 if report['all_mapped_cases_comparable'] else 1
    except Exception as error:
        report['status'] = 'failed'
        report['error_type'] = type(error).__name__
        # Keep raw exceptions/logs private; they may contain authority or bodies.
        return 1
    finally:
        save()


def run_daemon(binary, root, repo, profile, profile_path, registry, policy, original, original_frame, case, mode, env, witness_type):
    root.mkdir(mode=0o700)
    env = dict(env, HOME=str(root), USERPROFILE=str(root))
    subprocess.run([str(binary), 'install'], env=env, capture_output=True, check=True, timeout=30)
    (root / 'registry.json').write_bytes(registry)
    if mode in ('ask', 'deny'):
        policy = policy.replace(b'agent_policies:\n', ('agent_policies:\n  - name: sou157-operator-floor\n'
                 '    when: { action_class: read_only }\n    action: ' + mode + '\n').encode(), 1)
        require(b'sou157-operator-floor' in policy, 'operator_floor_not_installed')
    (root / 'policy.yaml').write_bytes(policy)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    rsha = sha(registry)
    config = {'port': port, 'enforce': True, 'max_record_bytes': 1048576, 'max_body_bytes': 16777216,
              'policy': str(root / 'policy.yaml'), 'audit': str(root / 'audit.jsonl'), 'native': {
                  'registry_path': str(root / 'registry.json'), 'registry_sha256': rsha,
                  'git_execution': {'profile_path': str(profile_path), 'profile_sha256': sha(profile_path.read_bytes()), 'server_id': 'git'},
                  'liveness': {'default_lease_seconds': 60, 'max_lease_seconds': 60, 'maintenance_interval_ms': 500}}}
    (root / '.agentfw/config.yaml').write_bytes(canonical(config))
    token, identity = '', None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def http(route, body=None, owner=True):
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        if identity and owner:
            headers['x-agentfw-collector-liveness'] = canonical(identity).decode()
        request = urllib.request.Request('http://127.0.0.1:' + str(port) + route, headers=headers,
                                         data=None if body is None else canonical(body))
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1048577)
            require(len(raw) <= 1048576, 'reply_over_cap')
            return response.code, json.loads(raw)
    def event(kind, **fields):
        return http('/native/v1', {'contract_version': 'sw-native/1', 'registry_sha256': rsha,
                                 'session_id': 'sou157', 'event': kind, **fields})
    result = {'status': 'incomplete', 'mode': mode}
    with (root / 'daemon.private.log').open('xb') as log:
        process = subprocess.Popen([str(binary), 'serve'], env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        witness = witness_type(process.pid)
        try:
            for _ in range(100):
                require(process.poll() is None, 'daemon_exited')
                path = root / '.agentfw/native-token'
                if path.exists():
                    token = path.read_text().strip()
                try:
                    code, instance = http('/native/v1/instance')
                    if code == 200:
                        break
                except OSError:
                    pass
                time.sleep(.05)
            else:
                raise ValueError('daemon_start_timeout')
            grant = subprocess.check_output([str(binary), 'child-authority', 'mint', '--session', 'sou157-host',
                '--server', 'git', '--agent-id', 'sou157-agent', '--instance-id', instance['instance_id'],
                '--tools', 'git_show'], env=env, timeout=15).decode().strip()
            code, started = event('session_start', host_session='sou157-host', server_id='git', child_authority=grant,
                                  liveness='sw-native-liveness/1', policy_transition='sw-managed-native/1')
            require(code == 200 and started['release'], 'session_not_admitted')
            code, enrolled = http('/native/liveness/v1', {'contract_version': 'sw-native-liveness/1',
                'registry_sha256': rsha, 'session_id': 'sou157', 'instance_id': instance['instance_id'],
                'action': 'enroll', 'owner_token': started['owner_token'], 'lease_seconds': 1 if mode == 'expired' else 60})
            require(code == 200, 'enroll_failed')
            identity = {'contract_version': 'sw-native-liveness/1', 'instance_id': instance['instance_id'],
                        'epoch': enrolled['epoch'], 'owner_token': started['owner_token']}
            schema = next(t['schema_sha256'] for t in json.loads(registry)['tools'] if t['name'] == 'git_show')
            args = {'repo_path': '/workspace', 'revision': 'HEAD'}
            def call(identifier):
                return event('call', tool='git_show', args=args, schema_sha256=schema, mcp_host_call_id=identifier)
            code, admitted = call(10)
            require(code == 200, 'call_failed')
            if mode in ('ask', 'deny'):
                require(admitted.get('release') is False and admitted.get('verdict', '').lower() == mode, 'operator_floor_lost')
                result.update(status='passed', release=False, execution_started=False)
            elif mode == 'expired':
                require(admitted.get('release') is True, 'expiry_control_not_admitted')
                time.sleep(1.2)
                code, expired = http('/native/git-execute/v1', {'contract_version': 'sw-native-git-execute/1',
                    'registry_sha256': rsha, 'session_id': 'sou157', 'call_id': admitted['call_id'],
                    'binding_sha256': admitted['binding_sha256']})
                require(code == 409 and not expired.get('frame'), 'expired_authority_released')
                result.update(status='passed', expired_authority_refused=True)
            else:
                require(admitted.get('release') is True, 'read_not_admitted')
                body = {'contract_version': 'sw-native-git-execute/1', 'registry_sha256': rsha, 'session_id': 'sou157',
                        'call_id': admitted['call_id'], 'binding_sha256': admitted['binding_sha256']}
                code, value = http('/native/git-execute/v1', body)
                require(code == 200, 'original_execution_failed')
                result['execution'] = validate_reply(value, admitted, profile, 10, original, case['label'] == 'benign')
                require(value['receipt'].get('content_sha256') == sha(original_frame), 'actual_original_frame_mismatch')
                result['actual_original_frame_matches_reference'] = True
                code, replay = http('/native/git-execute/v1', body)
                require(code == 409 and replay.get('error_code') == 'native_call_unknown_or_spent', 'spent_call_revived')
                # Binding failures consume the call too. Use fresh authority,
                # then demonstrate that correcting the public hash cannot revive it.
                code, foreign = call(12)
                require(code == 200 and foreign['release'], 'foreign_control_call_failed')
                require(foreign['binding_sha256'] != admitted['binding_sha256'], 'control_bindings_not_distinct')
                foreign_body = {**body, 'call_id': foreign['call_id'], 'binding_sha256': admitted['binding_sha256']}
                code, rejected = http('/native/git-execute/v1', foreign_body)
                require(code == 409 and rejected.get('error_code') == 'native_git_execution_binding'
                        and not rejected.get('frame'), 'foreign_binding_released')
                code, rejected = http('/native/git-execute/v1', {**foreign_body, 'binding_sha256': foreign['binding_sha256']})
                require(code == 409 and rejected.get('error_code') == 'native_call_unknown_or_spent', 'bad_binding_revived')
                # Foreign owner identity cannot exercise a fresh valid call.
                code, foreign = call(13)
                require(code == 200 and foreign['release'], 'foreign_owner_call_failed')
                owner = identity['owner_token']
                identity['owner_token'] = '0' * len(owner)
                try:
                    code, rejected = http('/native/git-execute/v1', {**body, 'call_id': foreign['call_id'],
                        'binding_sha256': foreign['binding_sha256']})
                    require(code == 409 and rejected.get('error_code') == 'native_liveness_owner_mismatch'
                            and not rejected.get('frame'), 'foreign_owner_released')
                finally:
                    identity['owner_token'] = owner
                rows = [json.loads(line) for line in (root / 'audit.jsonl').read_text().splitlines() if line.strip()]
                reserved = [r for r in rows if r.get('event') == 'native_git_execution_reserved']
                require(len(reserved) == 1 and reserved[0]['call_id'] == admitted['call_id']
                        and reserved[0]['binding_sha256'] == admitted['binding_sha256']
                        and reserved[0]['profile_sha256'] == sha(profile_path.read_bytes())
                        and reserved[0]['args_sha256'] == sha(canonical(args))
                        and reserved[0]['authority'] == 'daemon_owned_original_pipe', 'execution_reservation_binding')
                result['reservation'] = reserved[0]
                # A public copy is intentionally untrusted baseline input, never
                # a substitute for the actual execution above.
                code, baseline = call(11)
                require(code == 200 and baseline['release'], 'baseline_call_failed')
                copied = canonical({'jsonrpc': '2.0', 'id': 11, 'result': {'content': [{'type': 'text', 'text': original.decode()}], 'isError': False}}).decode()
                code, refused = event('result', tool='git_show', args=args, call_id=baseline['call_id'],
                                      result_kind='value', delivery='mcp_host', content=copied)
                require(code == 200 and refused.get('release') is False
                        and refused.get('verdict', '').lower() == 'deny', 'copied_bytes_became_authority')
                result.update(status='passed', baseline_release=False, foreign_binding_refused=True,
                              foreign_owner_refused=True, spent_call_refused=True)
            if mode in ('ask', 'deny', 'expired'):
                rows = [json.loads(line) for line in (root / 'audit.jsonl').read_text().splitlines() if line.strip()]
                require(not any(r.get('event') == 'native_git_execution_reserved' for r in rows), 'refused_control_executed')
            return result
        finally:
            process.terminate()
            forced = False
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                forced = True
            result['cleanup'] = witness.finish()
            require(not forced and result['cleanup']['all_stopped'], 'owned_cleanup_incomplete')
            if mode == 'allow' and result['status'] == 'passed':
                require(any(r.get('original_git_server') for r in result['cleanup']['observed']),
                        'original_worker_not_observed')
