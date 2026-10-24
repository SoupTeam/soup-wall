#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""offline SOU143 actual-host runtime; reuses fast-phase binaries.

Run only in the ordinary-user, read-only-source, private-network transient unit.
The full original qualification report and logs remain private. A separate
trusted parent projects finite evidence after this process and unit stop.
"""
import argparse
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


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Refusal(Exception):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--scratch', type=Path, required=True)
    p.add_argument('--expected-commit', required=True)
    p.add_argument('--bwrap', type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    src, out = a.source.resolve(strict=True), a.scratch.resolve(strict=True)
    record = {'format': 'sou143-offline-host-attempt/1', 'status': 'incomplete',
              'source_commit': a.expected_commit, 'steps': [], 'qualifier_exit_code': None,
              'provider': 'owned-scripted-loopback', 'paid_api_calls': 0}
    def save():
        temporary = out / 'runtime-attempt.next'
        temporary.write_text(json.dumps(record, indent=2) + '\n')
        temporary.replace(out / 'runtime-attempt.json')
    save()
    try:
        require(re.fullmatch(r'[0-9a-f]{40}', a.expected_commit), 'full_candidate_source_required')
        require(os.geteuid() != 0 and {name for _, name in socket.if_nameindex()} == {'lo'},
                'ordinary_user_private_loopback_required')
        require(os.statvfs(src).f_flag & os.ST_RDONLY, 'read_only_source_mount_required')
        assets = json.loads((out / 'assets.json').read_text())
        paths, identity = assets['paths'], assets['identity']
        require(identity['source'] == a.expected_commit, 'same_source_selected_inputs_required')
        for role, digest in identity['binaries'].items():
            require(sha(paths[role]) == digest, 'selected_runtime_input_changed')
        for role in ('agentfw', 'git_launcher', 'sandbox_tests'):
            require(os.statvfs(paths[role]).f_flag & os.ST_RDONLY, 'reused_fast_binaries_must_be_read_only')
        bwrap = a.bwrap.resolve(strict=True)
        info = bwrap.stat()
        require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022
                and sha(bwrap) == identity['binaries']['bwrap_source'], 'staged_job_bwrap_identity_unproven')
        paths['bwrap'] = str(bwrap)
        for name in ('home', 'runtime-tmp'):
            (out / name).mkdir(mode=0o700)
        env = {'PATH': str(Path(paths['node']).parent) + ':/usr/bin:/bin', 'HOME': str(out / 'home'),
               'TMPDIR': str(out / 'runtime-tmp'), 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'}
        # Provider inputs are supplied by the owned offline qualifier per case.
        # No ambient provider, loader, project, Rustup or proxy setting survives.
        os.environ.clear()
        os.environ.update(env)
        def git(*words):
            return subprocess.check_output(['/usr/bin/git', *words], cwd=src, env=env, timeout=20)
        require(git('rev-parse', 'HEAD').decode().strip() == a.expected_commit
                and not git('status', '--porcelain', '--untracked-files=all'), 'clean_exact_source_required')
        record.update(source_read_only=True, reused_binaries_read_only=True, network='private-loopback-only',
                      selected_sha256=identity['binaries'])
        save()
        def run(label, words, timeout):
            step = {'label': label, 'status': 'incomplete'}
            record['steps'].append(step)
            save()
            log = out / (label + '.private.log')
            try:
                with log.open('wb') as stream:
                    done = subprocess.run(list(map(str, words)), cwd=src, env=env,
                                          stdin=subprocess.DEVNULL, stdout=stream,
                                          stderr=subprocess.STDOUT, timeout=timeout)
                step.update(status='passed' if done.returncode == 0 else 'failed', exit_code=done.returncode)
            except subprocess.TimeoutExpired:
                step.update(status='incomplete', exit_code=124)
            finally:
                if log.exists():
                    step['log_sha256'] = sha(log)
                    if step.get('exit_code', 0):
                        tail = log.read_text(errors='replace')[-16384:]
                        print('=== ' + label + ' FAILED (' + str(step['exit_code']) + ') ===\n' + tail, file=sys.stderr)
                        step['failure_tail'] = tail[-2000:]
                save()
            return step['exit_code'], log
        # The accepted AppArmor install already proves direct and pinned-FD use
        # outside the unit; this verifies namespace startup inside these exact
        # read-only/network/NoNewPrivileges mounts before candidate preparation.
        code, _ = run('same-unit-namespace-probe', [bwrap, '--unshare-all', '--unshare-user',
            '--disable-userns', '--assert-userns-disabled', '--ro-bind', '/', '/',
            '--proc', '/proc', '--dev', '/dev', '--', '/usr/bin/true'], 15)
        require(code == 0, 'same_unit_namespace_probe_failed')
        spec = importlib.util.spec_from_file_location('sou143_offline_policy', src / 'scripts/qualify-installed-pilot.py')
        pilot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pilot)
        policy = out / 'policy.yaml'
        pilot.owned_bytes(policy, pilot.PILOT_POLICY.encode())
        code, log = run('offline-preparation', [sys.executable, '-B', src / 'scripts/prepare-installed-pilot.py',
            '--prepare', '--output', out / 'preparation', '--expected-commit', a.expected_commit,
            '--agentfw', paths['agentfw'], '--git-launcher', paths['git_launcher'],
            '--sandbox-tests', paths['sandbox_tests'], '--node-archive', paths['node_archive'],
            '--python-archive', paths['python_archive'], '--npm-cache', out / 'npm-cache',
            '--wheelhouse', out / 'wheelhouse', '--bwrap', bwrap, '--git', paths['git'],
            '--claude', paths['claude'], '--python', paths['python'],
            '--filesystem-classifier', src / 'rule_baseline/rule_baseline.py',
            '--git-classifier', src / 'rule_baseline/git_readonly_v1/rule_baseline.py', '--policy', policy], 600)
        require(code == 0, 'offline_preparation_failed')
        preparation = json.loads(log.read_text())
        require(preparation.get('status') == 'prepared-not-active', 'prepared_selection_unavailable')
        selection = Path(preparation['selection']).resolve(strict=True)
        require(selection.is_relative_to(out / 'preparation'), 'selected_generation_escaped_scratch')
        record['selection_sha256'] = sha(selection)
        save()
        code, _ = run('actual-host-provider-qualification', [sys.executable, '-B',
            src / 'scripts/qualify-prepared-pilot-run.py', '--selection', selection,
            '--expected-commit', a.expected_commit, '--strace', '/usr/bin/strace',
            '--validation-timeout-seconds', '120', '--verify-provider-isolation',
            '--output', out / 'prepared-native'], 850)
        record['qualifier_exit_code'] = code
        require(code == 0, 'actual_host_provider_qualification_failed')
        require(git('rev-parse', 'HEAD').decode().strip() == a.expected_commit
                and not git('status', '--porcelain', '--untracked-files=all'), 'closing_source_identity_changed')
        for role, digest in identity['binaries'].items():
            require(sha(paths[role]) == digest, 'closing_runtime_input_identity_changed')
        # The trusted parent still must project the raw report and verify all
        # cases/roles. Unit success alone is explicitly not final qualification.
        record['status'] = 'runtime-completed-pending-parent-projection'
        return 0
    except BaseException as error:
        record['status'] = 'failed'
        record['reason'] = str(error) if isinstance(error, Refusal) else 'runtime_failure'
        if isinstance(error, OSError):
            record['errno'] = error.errno
        return 1
    finally:
        save()


if __name__ == '__main__':
    raise SystemExit(main())
