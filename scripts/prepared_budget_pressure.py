# SPDX-License-Identifier: Apache-2.0
"""Owned actual-host calibration attempts over original FS/Git servers.

No injected workers, substituted servers or observer cleanup. Non-exhaustion is
retained as incomplete, never silently changed into a successful refusal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from prepared_budget_observer import BudgetObserver

PRESSURE_BYTES = 40 * 1024 * 1024


def finish_useful(pilot):
    # Finite peer/recovery providers deliberately have no post-tool hold barrier.
    # Prepared.useful() is for stop witnesses whose host must remain alive.
    pilot.provider.release.set()
    result = pilot.finish()
    pilot.check_useful()
    return result


def kernel_refusal(snapshot, server, kind):
    if not isinstance(snapshot,dict) or snapshot.get('errors') != []:
        return False
    for row in snapshot.get('rows',[]):
        if row.get('servers') != [server] or row.get('original_runtime_seen') is not True \
                or row.get('errors') != [] or row.get('observer_errors') != []:
            continue
        if kind == 'wall':
            if row.get('removed') is True:return True
        else:
            count=row.get('counter_max',{}).get('oom_kill' if kind=='memory' else 'pids_max')
            if type(count) is int and count>0:return True
    return False


def qualify(context, selection, paths, profiles, delegation, output, commit, on_progress=None):
    base, resource = context.BASE, context.RESOURCE
    paths = {key: Path(value) for key, value in paths.items()}
    output.mkdir(mode=0o700)
    normal = {'format': 'sw-mcp/linux-cgroup-budget/1', 'delegationRoot': str(delegation),
        'memoryMaxBytes': 512 * 1024 * 1024, 'pidsMax': 64, 'cpuQuotaMicros': 100000,
        'wallMillis': 120000}
    runtimes = {server: Path(json.loads(Path(value['profile']['path']).read_bytes())['runtimePath'])
                for server, value in profiles.items()}
    workspaces = {server: Path(json.loads(Path(value['profile']['path']).read_bytes())['workspace'])
                  for server, value in profiles.items()}
    before = {key: base.snapshot(path) for key, path in workspaces.items()}
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'TMPDIR': str(output), 'LANG': 'C.UTF-8'}
    attempts = []
    from types import SimpleNamespace
    q = context.QUALIFIER
    peer_context = SimpleNamespace(args=argparse.Namespace(selection=selection, expected_commit=commit,
        strace=Path('/usr/bin/strace'), linux_budget=context.budget, linux_budget_peer=context.peer_budget),
        source=context.ROOT, run=q.RUN, launch=q.LAUNCH, ask=q.ASK, base=base, paths=paths, env=env,
        notes=(workspaces['filesystem'] / 'notes.txt').read_text(), useful=q.useful_result)

    def classify(pid):
        start = base.ProcessWitness.identity(pid)
        if start is None:
            return None
        try:
            for server, runtime in runtimes.items():
                if Path(f'/proc/{pid}/exe').samefile(runtime) and base.ProcessWitness.identity(pid) == start:
                    return {'server': server, 'original_runtime_seen': True}
        except (OSError, ValueError):
            pass
        return None

    for server in ('filesystem', 'git'):
        for kind in ('memory', 'pids', 'wall'):
            label = server + '-' + kind
            root = output / label
            root.mkdir(mode=0o700)
            state = root / 'state'
            state.mkdir(mode=0o700)
            limits = dict(normal)
            limits.update({'memoryMaxBytes': 64 * 1024 * 1024} if kind == 'memory' else
                          {'pidsMax': 16} if kind == 'pids' else {'wallMillis': 1000})
            budget = root / 'budget.json'
            budget.write_text(json.dumps(limits, sort_keys=True) + '\n')
            budget.chmod(0o600)
            digest = hashlib.sha256(json.dumps(limits, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            row = {'server': server, 'resource': kind, 'status': 'incomplete', 'budget_sha256': digest,
                   'limits': {key: limits[key] for key in ('memoryMaxBytes', 'pidsMax', 'cpuQuotaMicros', 'wallMillis')},
                   'server_origin': 'pinned-original', 'forced_cleanup': False}
            attempts.append(row)
            def phase(name):
                row['phase']=name
                if on_progress is not None:
                    on_progress({'format':'sou142-original-pressure/1','status':'incomplete',
                        'workspace_unchanged':False,'attempts':attempts,
                        'raw_process_metadata_exported':False,'observer_cleanup_performed':False})
            payload, original = None, None
            if kind == 'memory':
                payload = workspaces[server] / ('sou142-pressure.txt' if server == 'filesystem' else 'tracked.txt')
                original = payload.read_bytes() if payload.exists() else None
                # Fixed owned calibration bytes; original package and executable
                # remain unchanged. No data or payload bytes are exported.
                payload.write_bytes(b'owned-resource-calibration\n' * (PRESSURE_BYTES // 27))
            model = base.DEMO.ScriptedModel([])
            model.server.handle_error = lambda *_: None
            offered = set()
            def next_step(body):
                for message in body.get('messages', []):
                    for block in message.get('content', []) if isinstance(message.get('content'), list) else []:
                        if isinstance(block, dict) and block.get('type') == 'tool_result' and block.get('tool_use_id') in offered:
                            model.results[block['tool_use_id']] = bool(block.get('is_error'))
                tools = {tool.get('name') for tool in body.get('tools', [])}
                tool = 'read_text_file' if server == 'filesystem' else 'git_diff' if kind == 'memory' else 'git_status'
                name = f'mcp__{server}__{tool}'
                if name not in tools:
                    return [{'type': 'text', 'text': 'Owned calibration startup.'}]
                if kind == 'wall':
                    time.sleep(2)
                    return [{'type': 'text', 'text': 'Owned wall calibration.'}]
                if not offered:
                    count = 8 if kind == 'pids' else 1
                    arguments = {'path': '/workspace/sou142-pressure.txt' if kind == 'memory' else '/workspace/notes.txt'} \
                        if server == 'filesystem' else {'repo_path': '/workspace'}
                    if server == 'git' and kind == 'memory':
                        arguments['target'] = 'HEAD'
                    frames = []
                    for ordinal in range(count):
                        identifier = f'toolu_pressure_{ordinal}'
                        offered.add(identifier)
                        frames.append({'type': 'tool_use', 'id': identifier, 'name': name, 'input': arguments})
                    return frames
                return [{'type': 'text', 'text': 'Owned calibration completed.'}]
            model.next = next_step
            process = witness = observer = peer = recovery = None
            peer_released = False
            peer_release_ns = None
            peer_after_kernel = False
            try:
                if any(path.is_dir() for path in delegation.iterdir()):
                    raise ValueError('pressure_root_not_empty')
                phase('peer-start')
                peer = q.STOP.Prepared(peer_context, root / 'peer', hold_after=False)
                # Peer tools remain behind its owned provider barrier until
                # the subject has completed its real resource refusal.
                if peer.observe()['calls']:
                    raise ValueError('pressure_peer_dispatched_before_barrier')
                phase('subject-start')
                observer = BudgetObserver(delegation, resource, classify_member=classify)
                command = ['/usr/bin/strace', '-f', '-qq', '-s', '4096', '-e', 'trace=execve',
                    '-o', str(root / 'trace.private'), sys.executable, '-B', str(context.ROOT / 'scripts/pilot-run.py'),
                    '--run', '--selection', str(selection), '--expected-commit', commit,
                    '--state-root', str(state), '--timeout-seconds', '60', '--linux-budget', str(budget)]
                run_env = dict(env, ANTHROPIC_BASE_URL=model.url, ANTHROPIC_API_KEY='owned-loopback-only',
                    HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9', NO_PROXY='127.0.0.1,localhost,::1')
                with (root / 'stdout.private').open('wb') as out, (root / 'stderr.private').open('wb') as err:
                    process = subprocess.Popen(command, cwd=root, env=run_env, stdout=out, stderr=err,
                                               start_new_session=True)
                    witness = base.ProcessWitness(process.pid)
                    deadline=time.monotonic()+100
                    while process.poll() is None:
                        if not peer_released and kernel_refusal(observer.snapshot(),server,kind):
                            if peer.process.poll() is not None:
                                raise ValueError('pressure_changed_independent_peer')
                            peer_release_ns=time.monotonic_ns()
                            peer.provider.release.set()
                            peer_released=peer_after_kernel=True
                            phase('subject-resource-refused')
                        if time.monotonic()>=deadline:
                            raise subprocess.TimeoutExpired(command,100)
                        time.sleep(.05)
                outcome = json.loads((root / 'stdout.private').read_text().splitlines()[-1])
                phase('subject-observation')
                cleanup = witness.finish()
                observed = observer.finish()
                budget_result = outcome.get('resource_budget', {})
                target = [item for item in observed if item.get('servers') == [server]
                          and item.get('original_runtime_seen') is True]
                receipts = [item for item in budget_result.get('observations', []) if item.get('server_id') == server]
                reason = {'memory': 'mcp_budget_memory_exhausted', 'pids': 'mcp_budget_pids_exhausted',
                          'wall': 'mcp_budget_wall_expired'}[kind]
                verified = bool(target) and all(item.get('status') == 'removed' for item in target)
                if kind != 'wall':
                    key = 'oom_kill' if kind == 'memory' else 'pids_max'
                    verified = verified and any(item.get('counter_max', {}).get(key, 0) > 0 for item in target)
                else:
                    # The independent observer starts after creation and cannot
                    # attest the unobserved leading interval. Retain its actual
                    # lifetime, and require the bound product wall receipt plus
                    # the separately tested unchanged owner/adoption epoch.
                    verified = verified and any(item.get('leaf_duration_millis', 0) > 0 for item in target)
                verified = verified and bool(receipts) and any(item.get('reason') == reason and item.get('phase') == 'closed'
                    for item in receipts) and budget_result.get('budget_sha256') == digest
                verified = verified and process.returncode != 0 and outcome.get('status') == 'failed' \
                    and cleanup.get('all_stopped') is True and not any(path.is_dir() for path in delegation.iterdir())
                # Keep partial kernel/refusal evidence even if a later peer or
                # recovery control fails; private cleanup identities stay private.
                row.update(original_runtime_observed=bool(target),
                    kernel_observations=[{'counter_max':item.get('counter_max'),
                        'memory_peak_bytes':item.get('memory_peak_bytes'),'tasks_peak':item.get('tasks_peak'),
                        'leaf_duration_millis':item.get('leaf_duration_millis'),'removed':item.get('removed'),
                        'errors':item.get('errors'),'incomplete_reasons':item.get('incomplete_reasons')}
                        for item in target], target_receipts=receipts,
                    observed_children=budget_result.get('observed_children'),
                    owned_cleanup_verified=cleanup.get('all_stopped') is True)
                if not peer_released:
                    if peer.process.poll() is not None:
                        raise ValueError('pressure_changed_independent_peer')
                    peer_after_kernel=verified and kernel_refusal({'errors':[],'rows':observed},server,kind)
                    peer_release_ns=time.monotonic_ns()
                    peer.provider.release.set()
                    peer_released=True
                phase('peer-finish')
                peer_result = peer.finish()
                peer.check_useful()
                if not all(peer.provider.offered_at.get('toolu_prepared_stop_'+str(index),0)>=peer_release_ns
                           for index in (0,1)):
                    raise ValueError('pressure_peer_dispatched_before_refusal_barrier')
                verified = verified and peer_after_kernel
                row['peer_survived_kernel_refusal']=peer_after_kernel
                # A new real prepared run on the reclaimed subject substrate
                # creates fresh host authority/binding; no grant is replayed.
                phase('recovery-start')
                recovery = q.STOP.Prepared(peer_context, root / 'recovery', hold_after=False)
                phase('recovery-finish')
                recovery_result = finish_useful(recovery)
                row.update(status='passed' if verified else 'incomplete',
                    reason='original_resource_refusal_verified' if verified else 'original_resource_refusal_unproven',
                    original_runtime_observed=bool(target), kernel_observations=[{
                        'counter_max': item.get('counter_max'), 'memory_peak_bytes': item.get('memory_peak_bytes'),
                        'tasks_peak': item.get('tasks_peak'), 'leaf_duration_millis': item.get('leaf_duration_millis'),
                        'removed': item.get('removed'), 'errors': item.get('errors'),
                        'incomplete_reasons': item.get('incomplete_reasons')} for item in target],
                    observed_children=budget_result.get('observed_children'),
                    target_receipts=receipts, owned_cleanup_verified=cleanup.get('all_stopped') is True,
                    peer_useful_after_subject=True, peer_budget=peer_result.get('resource_budget'),
                    fresh_prepared_recovery_useful=True, recovery_budget=recovery_result.get('resource_budget'),
                    trace_sha256=base.sha(root / 'trace.private'))
            except (OSError, ValueError, subprocess.TimeoutExpired, IndexError) as error:
                row['reason'] = 'bounded_calibration_attempt_incomplete'
                row['error_type']=type(error).__name__
                message=str(error)
                import re,traceback
                if isinstance(error,ValueError) and re.fullmatch(r'(?:pressure_|stop_)[a-z0-9_]{1,100}',message):
                    row['error_code']=message
                if isinstance(error,OSError):row['errno']=error.errno
                row['error_frames']=[{'source':str(Path(frame.filename).relative_to(context.ROOT)),
                    'line':frame.lineno} for frame in traceback.extract_tb(error.__traceback__)
                    if Path(frame.filename).is_relative_to(context.ROOT)][-8:]

            finally:
                phase('cleanup-subject')
                if process is not None and process.poll() is None:
                    for manifest in state.glob('*/run.json'):
                        record = json.loads(manifest.read_bytes())
                        pid = record.get('supervisor_pid')
                        known = [start for (observed_pid, start) in witness.observed if observed_pid == pid]
                        try:
                            if type(pid) is int and len(known) == 1 and base.ProcessWitness.identity(pid) == known[0] \
                                    and Path(f'/proc/{pid}').stat().st_uid == os.geteuid() \
                                    and str(context.ROOT / 'scripts/pilot-run.py').encode() in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0'):
                                os.kill(pid, signal.SIGTERM)
                        except (OSError, ProcessLookupError):
                            pass
                    try: process.wait(timeout=18)
                    except subprocess.TimeoutExpired:
                        row['forced_cleanup'] = True
                        process.kill(); process.wait(timeout=5)
                if witness is not None: witness.finish()
                phase('cleanup-observer')
                if observer is not None: observer.finish()
                phase('cleanup-peer')
                if recovery is not None: recovery.close()
                if peer is not None: peer.close()
                phase('cleanup-provider')
                model.close()
                if payload is not None:
                    if original is None: payload.unlink(missing_ok=True)
                    else: payload.write_bytes(original)
                row['phase']='finished'
                (output / 'attempts.json').write_text(json.dumps(attempts, indent=2) + '\n')
                if on_progress is not None:
                    on_progress({'format':'sou142-original-pressure/1', 'status':'incomplete',
                        'workspace_unchanged': before == {key:base.snapshot(path) for key,path in workspaces.items()},
                        'attempts':attempts, 'raw_process_metadata_exported':False,
                        'observer_cleanup_performed':False})
    unchanged = before == {key: base.snapshot(path) for key, path in workspaces.items()}
    return {'format': 'sou142-original-pressure/1', 'status': 'passed' if unchanged and
            all(row['status'] == 'passed' and not row['forced_cleanup'] for row in attempts) else 'incomplete',
            'workspace_unchanged': unchanged, 'attempts': attempts,
            'raw_process_metadata_exported': False, 'observer_cleanup_performed': False}
