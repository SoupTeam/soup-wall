#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Job-scoped AppArmor userns permission for pinned bubblewrap on hosted Ubuntu.

This is runner provisioning, never part of the product installer. No sysctl,
global AppArmor profile, setuid bit, host network or runtime policy is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile

RESTRICTION = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
MAX_BINARY = 16 * 1024 * 1024


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def identity(env):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('CI') == 'true'
            and env.get('SOUP_CI_RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('RUNNER_OS') == 'Linux' and env.get('RUNNER_ARCH') == 'X64',
            'explicit_disposable_github_hosted_linux_only')
    run, attempt, job = (env.get(key, '') for key in
                         ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'))
    require(re.fullmatch(r'[1-9][0-9]{0,19}', run)
            and re.fullmatch(r'[1-9][0-9]{0,5}', attempt)
            and re.fullmatch(r'[A-Za-z0-9_-]{1,150}', job), 'invalid_job_identity')
    suffix = f'{run}-{attempt}-{hashlib.sha256(job.encode()).hexdigest()[:16]}'
    name = 'soup-wall-ci-bwrap-' + suffix
    return name, Path('/opt') / name, Path('/etc/apparmor.d') / name


def guard():
    selected = identity(os.environ)
    require(os.geteuid() != 0, 'qualification_must_run_as_non_root')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                   if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu'
            and release.get('VERSION_ID', '').strip('"') == '24.04'
            and 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower(),
            'native_ubuntu_24_04_only')
    require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y'
            and RESTRICTION.read_text().strip() == '1', 'apparmor_restriction_must_remain_enabled')
    return selected


def profile(name, binary):
    # Both strings are derived from validated numeric/job identities, not input paths.
    return (f'abi <abi/4.0>,\ninclude <tunables/global>\n'
            f'profile {name} "{binary}" flags=(unconfined) {{\n  userns,\n}}\n').encode()


def regular(path, owner=None):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID), 'unsafe_regular_file')
    if owner is not None:
        require(info.st_uid == owner and not info.st_mode & 0o022, 'unsafe_root_file')
    return info


def root_parent(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unsafe_root_directory')


def sudo(*args, data=None, check=True):
    return subprocess.run(['sudo', '-n', *map(str, args)], input=data,
                          stdout=subprocess.DEVNULL, check=check, timeout=30)


def root_write(path, data, mode):
    require(not path.exists() and not path.is_symlink(), 'root_target_already_exists')
    sudo('tee', '--', path, data=data)
    sudo('chmod', mode, '--', path)
    regular(path, 0)


def owned_report(path, value):
    path = path.absolute()
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(path.parent.resolve(strict=True).is_relative_to(temp), 'report_must_be_in_runner_temp')
    with path.open('x', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')


CHILD = r'''
import json, os, socket, subprocess, sys
names = {key: os.readlink('/proc/self/ns/' + key) for key in ('user', 'net', 'mnt', 'pid')}
try:
    with open(sys.argv[1], 'a') as stream: stream.write('forbidden')
    readonly = False
except OSError:
    readonly = True
with socket.socket() as connection:
    connection.settimeout(2)
    try: network_blocked = connection.connect_ex(('127.0.0.1', int(sys.argv[2]))) != 0
    except OSError: network_blocked = True
nested = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--', '/usr/bin/true'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
print(json.dumps({'namespaces': names, 'readonly': readonly, 'network_blocked': network_blocked,
                  'nested_userns_refused': nested.returncode != 0,
                  'effective_capabilities': int(status['CapEff'].strip(), 16),
                  'no_new_privileges': status['NoNewPrivs'].strip()}))
'''


def probe(binary, sentinel, port, descriptor=False):
    args = ['--unshare-all', '--unshare-user', '--disable-userns', '--assert-userns-disabled',
            '--die-with-parent', '--new-session', '--ro-bind', '/', '/', '--proc', '/proc',
            '--dev', '/dev', '--', sys.executable, '-I', '-c', CHILD, str(sentinel), str(port)]
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        executable = f'/proc/self/fd/{fd}' if descriptor else str(binary)
        result = subprocess.run([executable, *args], pass_fds=(fd,), capture_output=True,
                                text=True, timeout=15)
    finally:
        os.close(fd)
    return {'exit': result.returncode, 'stdout': result.stdout[:8192], 'stderr': result.stderr[:2048]}


def verify(source, binary, expected, report):
    guard()
    regular(binary, 0)
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == expected, 'selected_bwrap_changed')
    parent_ns = {key: os.readlink('/proc/self/ns/' + key) for key in ('user', 'net', 'mnt', 'pid')}
    context = Path('/proc/self/attr/current').read_text()
    with tempfile.TemporaryDirectory(prefix='sou111-userns-', dir=os.environ['RUNNER_TEMP']) as work:
        sentinel = Path(work) / 'readonly.txt'
        sentinel.write_text('owned immutable probe\n')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(0.1)
            results = {label: probe(path, sentinel, listener.getsockname()[1], descriptor)
                       for label, path, descriptor in [('direct', binary, False),
                                                        ('pinned_fd', binary, True),
                                                        ('unapproved_path', source, False)]}
            for label in ('direct', 'pinned_fd'):
                row = results[label]
                require(row['exit'] == 0, f'{label}_sandbox_failed: {row["stderr"]}')
                data = json.loads(row['stdout'])
                require(all(data['namespaces'][key] != value for key, value in parent_ns.items())
                        and data['readonly'] and data['network_blocked']
                        and data['nested_userns_refused'] and data['effective_capabilities'] == 0
                        and data['no_new_privileges'] == '1', f'{label}_isolation_control_failed')
                row['observed'] = data
            require(results['unapproved_path']['exit'] != 0, 'unapproved_path_gained_permission')
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise RuntimeError('isolated_probe_reached_host_listener')
        require(sentinel.read_text() == 'owned immutable probe\n', 'readonly_probe_mutated')
    require(Path('/proc/self/attr/current').read_text() == context
            and RESTRICTION.read_text().strip() == '1', 'host_security_context_changed')
    report.update(status='qualified-runner-sandbox', probes=results,
                  apparmor_restrict_unprivileged_userns=1, host_context_unchanged=True)


def install(args):
    name, directory, policy = guard()
    source = args.source.absolute()
    info = regular(source)
    require(info.st_size <= MAX_BINARY and re.fullmatch(r'[0-9a-f]{64}', args.sha256),
            'bounded_digest_pinned_bwrap_required')
    raw = source.read_bytes()
    require(raw.startswith(b'\x7fELF') and hashlib.sha256(raw).hexdigest() == args.sha256,
            'source_bwrap_digest_mismatch')
    root_parent(directory.parent)
    root_parent(policy.parent)
    require(not directory.exists() and not directory.is_symlink()
            and not policy.exists() and not policy.is_symlink(), 'job_provisioning_already_exists')
    binary = directory / 'bwrap'
    receipt = {'format': 'sou111-ci-userns/1', 'job': name, 'sha256': args.sha256}
    sudo('mkdir', '-m', '0755', '--', directory)
    # Root never opens a caller-controlled source path; it receives already hashed bytes.
    root_write(directory / 'owner.json', json.dumps(receipt, sort_keys=True).encode(), '0644')
    root_write(binary, raw, '0755')
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256, 'staged_bwrap_digest_mismatch')
    root_write(policy, profile(name, binary), '0644')
    sudo('apparmor_parser', '-r', '-T', policy)
    report = dict(receipt, selected_bwrap=str(binary), profile_sha256=hashlib.sha256(policy.read_bytes()).hexdigest())
    try:
        verify(source, binary, args.sha256, report)
    except Exception as error:
        report.update(status='failed', reason=str(error)[:2048])
        raise
    finally:
        owned_report(args.report, report)
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write(f'SOU111_BWRAP={binary}\n')


def cleanup(args):
    name, directory, policy = guard()
    if not directory.exists():
        require(not directory.is_symlink() and not policy.exists() and not policy.is_symlink(),
                'unexpected_cleanup_target')
        owned_report(args.report, {'status': 'no-job-provisioning', 'job': name})
        return
    root_parent(directory)
    marker = directory / 'owner.json'
    regular(marker, 0)
    receipt = json.loads(marker.read_bytes())
    require(set(receipt) == {'format', 'job', 'sha256'} and receipt['format'] == 'sou111-ci-userns/1'
            and receipt['job'] == name and re.fullmatch(r'[0-9a-f]{64}', receipt['sha256']),
            'foreign_cleanup_marker')
    binary = directory / 'bwrap'
    require(set(item.name for item in directory.iterdir()) <= {'owner.json', 'bwrap'}, 'foreign_cleanup_file')
    if binary.exists():
        regular(binary, 0)
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == receipt['sha256'], 'changed_cleanup_binary')
    if policy.exists() or policy.is_symlink():
        regular(policy, 0)
        require(policy.read_bytes() == profile(name, binary), 'changed_cleanup_profile')
        sudo('apparmor_parser', '-R', policy)
        sudo('rm', '--', policy)
    if binary.exists():
        sudo('rm', '--', binary)
    sudo('rm', '--', marker)
    sudo('rmdir', '--', directory)
    require(RESTRICTION.read_text().strip() == '1', 'host_restriction_changed')
    owned_report(args.report, {'status': 'removed-owned-profile-and-binary', 'job': name,
                              'apparmor_restrict_unprivileged_userns': 1})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prepare = sub.add_parser('install')
    prepare.add_argument('--source', type=Path, required=True)
    prepare.add_argument('--sha256', required=True)
    prepare.add_argument('--report', type=Path, required=True)
    remove = sub.add_parser('cleanup')
    remove.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        (install if args.command == 'install' else cleanup)(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
