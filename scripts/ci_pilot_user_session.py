#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Observe or quiesce an empty owned hosted-CI user session before pilot use.

This is optional disposable-environment preparation, never removal authorization.
No sudo, signals, user-account changes, service configuration or security changes.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CERT = ROOT / 'scripts/fixtures/sou216-process-recipient.crt'
CERT_SHA256 = '70fe2f78676803487c792babc7d49d867c6c12877790d79b93593fd6b8ba69f4'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


H = load('sou216_process_observer', 'pilot_clean_user_acceptance.py')
require = H.require


def raw_bytes(path, cap=65536):
    with path.open('rb') as stream: value = stream.read(cap + 1)
    require(len(value) <= cap, 'session_observation_bound')
    return value


def raw_process(pid):
    path = Path('/proc') / str(pid)
    before = raw_bytes(path / 'stat', 8192).rsplit(b')', 1)[1].split()
    status = dict(line.split(b':', 1) for line in raw_bytes(path / 'status').splitlines() if b':' in line)
    result = {'pid': pid, 'parent': int(before[1]), 'start_ticks': int(before[19]),
        'comm': raw_bytes(path / 'comm', 256).decode().strip(),
        'uids': [int(n) for n in status[b'Uid'].split()], 'state': before[0].decode(),
        'capabilities': {key: int(status[key.encode()], 16) for key in ('CapEff', 'CapPrm', 'CapAmb')},
        'tracer_pid': int(status[b'TracerPid']),
        'dumpable': int(status[b'Dumpable']) if b'Dumpable' in status else None,
        'no_new_privileges': int(status[b'NoNewPrivs']),
        'cgroup': raw_bytes(path / 'cgroup', 16384).decode(), 'namespaces': {}}
    require(len(result['uids']) == 4, 'session_process_credentials_missing')
    for kind in ('user', 'pid', 'mnt', 'net', 'cgroup'):
        try: value = str((path / 'ns' / kind).readlink())
        except OSError as error: value = {'errno': error.errno}
        result['namespaces'][kind] = value
    after = raw_bytes(path / 'stat', 8192).rsplit(b')', 1)[1].split()
    require(before[19] == after[19], 'session_process_identity_changed')
    return result


def identity(row):
    return H.digest({'pid': row['pid'], 'start': str(row['start_ticks'])})


def kernel_snapshot():
    rows = {}
    entries = list(Path('/proc').iterdir()); require(len(entries) <= 8192, 'session_process_count_bound')
    for path in entries:
        if not path.name.isdecimal(): continue
        try:
            if path.stat().st_uid != os.getuid(): continue
            rows[path.name] = raw_process(int(path.name))
        except (FileNotFoundError, ProcessLookupError): pass
    parent = os.getpid()
    for _ in range(16):
        if parent == 0: break
        key = str(parent)
        if key not in rows: rows[key] = raw_process(parent)
        parent = rows[key]['parent']
    return rows


def context():
    self = raw_process(os.getpid())
    return {'uid': os.getuid(), 'effective_capabilities': self['capabilities']['CapEff'],
        'namespaces': self['namespaces'], 'cgroup_sha256': H.digest(self['cgroup']),
        'ptrace_scope': raw_bytes(Path('/proc/sys/kernel/yama/ptrace_scope'), 32).decode().strip(),
        'apparmor_restrict_userns': raw_bytes(Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns'), 32).decode().strip(),
        'apparmor_context_sha256': hashlib.sha256(raw_bytes(Path('/proc/self/attr/current'), 4096)).hexdigest()}


def control(*words):
    if 'exit' in words:
        require(words == ('--user', 'exit'), 'session_root_exit_forbidden')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': str(Path.home()),
        'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()), 'SYSTEMD_COLORS': '0',
        'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/dbus/system_bus_socket'}
    result = subprocess.run(['/usr/bin/systemctl', '--no-ask-password', '--no-pager', *words],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    require(len(result.stdout) <= 256 * 1024 and len(result.stderr) <= 8192, 'session_control_bound')
    require(result.returncode == 0, 'session_control_refused')
    return result.stdout.decode()


def properties(user, name, fields):
    args = ['--user'] if user else []
    return dict(line.split('=', 1) for line in control(*args, 'show',
        '--property=' + ','.join(fields), '--', name).splitlines() if '=' in line)


def vendor_file(path):
    selected = Path(path).resolve(strict=True)
    require(selected.is_relative_to(Path('/usr/lib/systemd/user')), 'session_nonvendor_user_unit')
    for parent in selected.parents:
        if not parent.is_relative_to(Path('/usr/lib/systemd/user')): break
        info = parent.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, 'session_untrusted_unit_parent')
    info = selected.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
        'session_untrusted_user_unit')
    return hashlib.sha256(raw_bytes(selected)).hexdigest()


def unit_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.strip(): continue
        fields = line.split(None, 4)
        require(len(fields) >= 4 and fields[1] == 'loaded', 'session_unit_listing_unrecognized')
        rows.append(dict(unit=fields[0], active=fields[2], sub=fields[3]))
    require(len(rows) <= 64, 'session_unit_count_bound')
    return rows


def user_units(private=None):
    listing = control('--user', 'list-units', '--all', '--plain', '--full', '--no-legend',
        '--type=service,scope,socket,target,timer,path', '--state=active,activating,deactivating,reloading')
    if private is not None: private['user_unit_listing'] = listing
    units = unit_rows(listing)
    result = []
    for row in units:
        name = row['unit']; require(row['active'] == 'active', 'session_user_unit_transitioning')
        if name == 'init.scope':
            result.append({'unit': name, 'sub': row['sub']}); continue
        require(not name.endswith('.scope'), 'session_other_active_scope')
        fields = properties(True, name, ('FragmentPath', 'DropInPaths', 'Transient', 'MainPID', 'ControlPID'))
        require(fields.get('Transient') == 'no', 'session_transient_user_unit')
        require(fields.get('MainPID', '0') == fields.get('ControlPID', '0') == '0', 'session_user_work_running')
        hashes = [vendor_file(fields['FragmentPath'])]
        hashes += [vendor_file(p) for p in shlex.split(fields.get('DropInPaths', ''))]
        result.append({'unit_sha256': H.digest(name), 'sub': row['sub'], 'vendor_file_sha256': hashes})
    jobs = control('--user', 'list-jobs', '--plain', '--no-legend').strip()
    if private is not None: private['user_job_listing'] = jobs
    require(jobs in ('', 'No jobs running.'), 'session_user_jobs_pending')
    return result


def group_processes(group):
    require(group.startswith('/user.slice/user-') and '..' not in Path(group).parts, 'session_cgroup_invalid')
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    require(root.resolve(strict=True) == root, 'session_cgroup_redirected')
    pids, count = set(), 0
    for leaf in root.rglob('cgroup.procs'):
        count += 1; require(count <= 64, 'session_cgroup_bound')
        pids.update(int(v) for v in raw_bytes(leaf).split())
        require(len(pids) <= 64, 'session_cgroup_process_bound')
    require(count > 0, 'session_cgroup_missing')
    return pids


def validate_empty_session(uid, unit, cohort, before, unavailable, driver):
    require(unit['User'] == str(uid) and unit['ActiveState'] == 'active', 'session_root_unit_not_owned_active')
    manager = int(unit['MainPID']); require(manager in cohort and len(cohort) == 2, 'session_not_empty')
    rows = [before[str(pid)] for pid in cohort]
    require({row['comm'] for row in rows} == {'systemd', '(sd-pam)'}, 'session_unexpected_member')
    require(all(row['uids'] == [uid] * 4 and row['tracer_pid'] == 0 for row in rows), 'session_member_credentials')
    main = before[str(manager)]; pam = next(row for row in rows if row['pid'] != manager)
    require(main['comm'] == 'systemd' and main['parent'] == 1 and pam['parent'] == manager
        and before['1']['uids'] == [0] * 4, 'session_root_parentage_unverified')
    require({identity(row) for row in rows} == {row['process_identity_sha256'] for row in unavailable},
        'session_other_unavailable_process')
    parent = driver
    for _ in range(16):
        require(parent not in cohort, 'session_contains_ci_driver')
        if parent == 0: break
        parent = before[str(parent)]['parent']
    return rows


def quiesce(report, private):
    unit_name = 'user@' + str(os.getuid()) + '.service'
    fields = ('MainPID', 'User', 'ControlGroup', 'ActiveState', 'SubState')
    unit = properties(False, unit_name, fields); private['root_unit'] = unit
    cohort = group_processes(unit['ControlGroup'])
    rows = validate_empty_session(os.getuid(), unit, cohort, private['before'],
        report['before']['unavailable'], os.getpid())
    units = user_units(private); report['empty_vendor_user_units'] = units
    require(user_units() == units and properties(False, unit_name, fields) == unit, 'session_scope_changed')
    require(all(identity(raw_process(row['pid'])) == identity(row) for row in rows), 'session_identity_changed')
    report['quiescence'] = {'scope': 'empty owned per-user service manager on disposable hosted CI only',
        'target_process_identities_sha256': [identity(row) for row in rows],
        'root_unit_attested': True, 'command': 'systemctl --user exit', 'exit_requested': True}
    control('--user', 'exit')
    until = time.monotonic() + 20
    while time.monotonic() < until:
        live = []
        for row in rows:
            try: current = raw_process(row['pid'])
            except (FileNotFoundError, ProcessLookupError): continue
            if identity(current) == identity(row) and current['state'] != 'Z': live.append(current)
        if not live: break
        time.sleep(0.1)
    require(not live, 'session_exit_not_confirmed')
    report['quiescence']['original_processes_exited'] = True
    report['after'] = H.process_observation()
    require(not report['after']['unavailable'], 'session_visibility_still_unavailable')
    require(context() == report['context_before'], 'session_changed_security_context')
    report['status'] = 'quiesced-empty-ci-user-session'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quiesce', action='store_true')
    args = parser.parse_args()
    report = {'diagnostic': 'SOU-216 owned CI user-session preparation', 'authorization': False,
        'installed_host_executed': False, 'native_removal_guard_changed': False, 'status': 'failed'}
    private = {}
    directory = None
    try:
        load('sou216_ci_guard', 'ci_bwrap_userns.py').guard()
        os.umask(0o077)
        directory = Path(os.environ['RUNNER_TEMP']) / 'sou216-user-session'
        directory.mkdir(mode=0o700)
        report.update(driver_source=H.source(ROOT, H.git(ROOT, 'rev-parse', 'HEAD')),
            boot_identity_sha256=H.sha('/proc/sys/kernel/random/boot_id'), context_before=context())
        require(report['context_before']['effective_capabilities'] == 0, 'session_driver_capabilities_present')
        private['before'] = kernel_snapshot(); report['before'] = H.process_observation()
        if args.quiesce and report['before']['unavailable']:
            quiesce(report, private)
        else:
            report['after'] = H.process_observation()
            require(not args.quiesce or not report['after']['unavailable'], 'session_visibility_unavailable')
            report['status'] = 'observed' if not args.quiesce else 'already-visible'
        private['after'] = kernel_snapshot()
    except Exception as error:
        message = str(error)
        report['error'] = message if re.fullmatch(r'[a-z0-9_]{1,120}', message) else type(error).__name__
    if directory is not None:
        raw = H.canonical(private); require(len(raw) <= 2 * 1024 * 1024, 'private_session_observation_bound')
        raw_path = directory / 'private-provenance.json'; raw_path.write_bytes(raw)
        require(H.sha(CERT) == CERT_SHA256, 'process_recipient_changed')
        encrypted = directory / 'private-provenance.cms'
        subprocess.run(['/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm',
            '-in', str(raw_path), '-out', str(encrypted), '-outform', 'DER', str(CERT)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        report.update(private_provenance_sha256=H.sha(raw_path), encrypted_provenance_sha256=H.sha(encrypted),
            recipient_certificate_sha256=CERT_SHA256, private_provenance='CMS encrypted; private key retained locally, no raw argv/environment captured')
        H.save(directory / 'report.json', report)
    print(json.dumps(report, sort_keys=True))
    return 1 if report['status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
