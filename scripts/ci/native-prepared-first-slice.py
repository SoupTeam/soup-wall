#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused native slice: invoke only inside the trusted transient unit below."""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--issue', choices=('142', '143'), required=True)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--scratch', type=Path, required=True)
    p.add_argument('--cargo', type=Path, required=True)
    p.add_argument('--expected-commit', required=True)
    p.add_argument('--unit', required=True)
    a = p.parse_args()
    src, out = a.source.resolve(strict=True), a.scratch.resolve(strict=True)
    os.umask(0o077)
    record = {'format': 'sou142143-native-first-slice/1', 'status': 'incomplete',
              'issue': a.issue, 'source': a.expected_commit, 'steps': [],
              'full_original_host_qualification': False}
    diagnostics = []
    def save():
        temporary = out / 'native-first-slice.next'
        temporary.write_text(json.dumps(record, indent=2) + '\n')
        temporary.replace(out / 'native-first-slice.json')
    save()
    env = {'PATH': str(a.cargo.parent) + ':/usr/bin:/bin', 'HOME': str(out / 'home'),
           'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8', 'CARGO_BUILD_JOBS': '2',
           'RUSTUP_TOOLCHAIN': '1.94.1', 'RUSTUP_AUTO_INSTALL': '0',
           'CARGO_HOME': str(out / 'cargo-home'), 'CARGO_TARGET_DIR': str(out / 'target'),
           'CARGO_NET_OFFLINE': 'true', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    def run(label, words):
        step = {'label': label, 'status': 'incomplete'}
        record['steps'].append(step)
        save()
        log = out / (label + '.log')
        try:
            with log.open('wb') as stream:
                value = subprocess.run(list(map(str, words)), cwd=src, env=env,
                                       stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
            step.update(exit_code=value.returncode, status='passed' if value.returncode == 0 else 'failed')
        finally:
            if log.exists():
                raw = log.read_bytes()
                step['log_sha256'] = hashlib.sha256(raw).hexdigest()
                # Compiler's structured primary messages only: no rendered
                # snippets, source text, argv, environment, stdout or test panic.
                for line in raw.decode('utf-8', errors='replace').splitlines():
                    if not line.startswith('{'):
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    value = row.get('message', {}) if row.get('reason') == 'compiler-message' else {}
                    if value.get('level') not in ('error', 'warning') or len(diagnostics) >= 64:
                        continue
                    message = value.get('message', '')
                    message = ''.join(char if char >= ' ' else ' ' for char in message)[:1000]
                    message = re.sub(r'(?:sou143-owned-[A-Za-z0-9_-]+|owned-api-canary)', '[synthetic-redacted]', message)
                    code = (value.get('code') or {}).get('code')
                    diagnostics.append({'phase': label, 'severity': value['level'],
                                        'code': code if code and re.fullmatch(r'[A-Za-z0-9_:]+', code) else None,
                                        'message': message})
                (out / 'compiler-diagnostics.json').write_text(json.dumps(diagnostics, indent=2) + '\n')
            save()
        if step['status'] != 'passed':
            raise RuntimeError(label + '_failed')
        return log
    try:
        if os.geteuid() == 0 or {name for _, name in socket.if_nameindex()} != {'lo'}:
            raise RuntimeError('ordinary_user_private_loopback_required')
        if not os.statvfs(src).f_flag & os.ST_RDONLY:
            raise RuntimeError('source_read_only_mount_required')
        if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=src, env=env, text=True).strip() != a.expected_commit:
            raise RuntimeError('source_commit_mismatch')
        if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=src, env=env):
            raise RuntimeError('source_dirty')
        record.update(source_read_only=True, writes='isolated-scratch-and-owned-delegation-only',
                      network='private-loopback-only', toolchain='1.94.1')
        save()
        run('native-build', [a.cargo, 'build', '--offline', '--locked', '-p', 'agentfw',
                             '--bins', '--message-format=json'])
        test_log = run('native-test-build', [a.cargo, 'test', '--offline', '--locked', '-p',
                       'agentfw', '--lib', '--no-run', '--message-format=json'])
        rows = [json.loads(line) for line in test_log.read_text().splitlines() if line.startswith('{')]
        tests = [row['executable'] for row in rows if row.get('reason') == 'compiler-artifact'
                 and row.get('target', {}).get('name') == 'agentfw'
                 and row.get('profile', {}).get('test') and row.get('executable')]
        if len(tests) != 1:
            raise RuntimeError('one_exact_native_library_test_binary_required')
        exact = tests[0]
        if a.issue == '143':
            run('native-provider-unit', [exact, 'pilot_host::tests::', '--test-threads=1'])
        else:
            run('native-budget-unit', [exact, 'pilot_budget::tests::', '--test-threads=1'])
            run('native-budget-cli', [a.cargo, 'test', '--offline', '--locked', '-p', 'agentfw',
                                     '--test', 'pilot_budget', '--', '--test-threads=1'])
            expected = '/system.slice/' + a.unit
            record['active_probe'] = 'owned_delegation_setup'
            save()
            if Path('/proc/self/cgroup').read_text().strip() != '0::' + expected:
                raise RuntimeError('exact_owned_systemd_service_required')
            root = Path('/sys/fs/cgroup' + expected)
            if root.stat().st_uid != os.geteuid() or any(path.is_dir() for path in root.iterdir()):
                raise RuntimeError('fresh_owned_delegation_required')
            if not {'cpu', 'memory', 'pids'} <= set((root / 'cgroup.controllers').read_text().split()):
                raise RuntimeError('required_delegated_controllers_missing')
            manager = root / 'manager'
            manager.mkdir(mode=0o700)
            (manager / 'cgroup.procs').write_text(str(os.getpid()))
            if (root / 'cgroup.procs').read_text().strip():
                raise RuntimeError('delegation_parent_not_empty')
            (root / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
            delegated = root / 'budgets'
            delegated.mkdir(mode=0o700)
            (delegated / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
            if stat.S_IMODE(delegated.stat().st_mode) != 0o700:
                raise RuntimeError('private_budget_root_required')
            one = os.open(delegated, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            two = os.open(delegated, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            record['active_probe'] = 'cgroup_directory_flock'
            save()
            try:
                fcntl.flock(one, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    fcntl.flock(two, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise RuntimeError('cgroup_root_flock_exclusion_missing')
                fcntl.flock(one, fcntl.LOCK_UN)
                fcntl.flock(two, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(one)
                os.close(two)
            record['kernel_preflight'] = {'root_flock_exclusion_release': True,
                                          'owned_cgroup_kill_available': (delegated / 'cgroup.kill').is_file()}
            config = out / 'linux-budget.json'
            config.write_text(json.dumps({'format': 'sw-mcp/linux-cgroup-budget/1',
                'delegationRoot': str(delegated), 'memoryMaxBytes': 512 * 1024 * 1024,
                'pidsMax': 64, 'cpuQuotaMicros': 100000, 'wallMillis': 120000}) + '\n')
            record['config_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
            env['SOU142_BUDGET_CONFIG'] = str(config)
            record['active_probe'] = 'native_readonly_preflight'
            save()
            run('native-readonly-preflight', [exact,
                'pilot_budget::tests::native_readonly_preflight_and_bound_root_identity',
                '--exact', '--ignored', '--test-threads=1'])
            if any(path.is_dir() for path in delegated.iterdir()) or (delegated / 'cgroup.procs').read_text().strip():
                raise RuntimeError('native_preflight_changed_owned_inventory')
            record['kernel_preflight']['zero_owned_members_and_leaves'] = True
        run('native-clippy', [a.cargo, 'clippy', '--offline', '--locked', '-p', 'agentfw',
                             '--all-targets', '--message-format=json', '--', '-D', 'warnings'])
        record['binary_sha256'] = {name: hashlib.sha256((out / 'target/debug' / name).read_bytes()).hexdigest()
                                   for name in ('agentfw', 'agentfw-git-sandbox')}
        record['status'] = 'passed'
    except BaseException as error:
        record['status'] = 'failed'
        record['reason'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        if isinstance(error, OSError):
            record['errno'] = error.errno
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
