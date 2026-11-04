# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only native Linux prerequisites; never removal authorization.

No child, selected executable, network, service control or host mutation. The
native doctor uses the removal scanner; this pre-build counterpart needs no
Agent executable. All public fields are a fixed allowlist, never kernel text.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import re
import time

FORMAT = 'sw-pilot-lifecycle-preflight/1'
MAX_BYTES = 64 * 1024 * 1024
MAX_PROCESSES = 4096
MAX_FDS = 1024
MAX_SECONDS = 10
GUIDANCE = {
    'setup': 'Use an ordinary native Ubuntu 24.04 x86-64 session with readable kernel namespace controls. An operator must select a supported environment; diagnosis changes no settings.',
    'protected_run': 'The existing exact selected bubblewrap/runtime admission must still succeed before a protected host starts. Static controls do not prove namespace admission or active protection.',
    'removal': 'Use an operator-owned environment with complete same-user process visibility in the host user namespace. Review owned services privately or choose a clean environment. Do not use sudo, ignore EACCES, or relax ptrace/AppArmor. Preview removal again in its actual current state.',
}


class Unavailable(Exception):
    def __init__(self, code):
        self.code = code


class Reader:
    """Fixed production paths; tests inject a reader, never a CLI/env proc root."""
    def __init__(self):
        self.started = time.monotonic()
        self.bytes = 0

    def tick(self, size=0):
        self.bytes += size
        if self.bytes > MAX_BYTES or time.monotonic() - self.started >= MAX_SECONDS:
            raise Unavailable('inspection_budget_exhausted')

    def read(self, path, cap):
        self.tick()
        if path == '/etc/os-release':
            path = os.path.realpath(path)
            if path not in ('/etc/os-release', '/usr/lib/os-release'):
                raise Unavailable('platform_metadata_unverified')
        remaining = MAX_BYTES - self.bytes
        if remaining <= 0:
            raise Unavailable("inspection_budget_exhausted")
        limit = min(cap + 1, remaining)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(limit)
        self.tick(len(data))
        if len(data) == limit and limit < cap + 1:
            raise Unavailable("inspection_budget_exhausted")
        if len(data) > cap:
            raise Unavailable('individual_read_bound')
        return data

    def link(self, path):
        self.tick()
        if MAX_BYTES - self.bytes < 8192:
            raise Unavailable("inspection_budget_exhausted")
        value = os.readlink(path)
        self.tick(len(os.fsencode(value)))
        if len(os.fsencode(value)) > 8192:
            raise Unavailable('individual_read_bound')
        return value

    def metadata(self, path, *, follow=True):
        self.tick()
        return os.stat(path, follow_symlinks=follow)

    def verify_procfs(self):
        self.tick()
        fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            data = ctypes.create_string_buffer(2048)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.fstatfs(fd, ctypes.byref(data)) != 0 or ctypes.c_long.from_buffer(data).value != 0x9fa0:
                raise Unavailable('proc_inventory_hidden_or_unverified')
        finally:
            os.close(fd)
        self.tick()

    def names(self, path, cap):
        count = 0
        with os.scandir(path) as entries:
            for entry in entries:
                self.tick()
                count += 1
                if count > cap:
                    raise Unavailable('process_inventory_bound')
                yield entry.name


def aggregate(rows):
    values = {row['outcome'] for row in rows}
    return next((v for v in ('blocked', 'unknown') if v in values), 'satisfied')


def row(check, outcome, reason):
    return {'id': check, 'outcome': outcome, 'reason_code': reason}


def failure(error):
    if isinstance(error, Unavailable):
        return error.code
    if isinstance(error, OSError) and error.errno in (errno.EACCES, errno.EPERM):
        return 'process_evidence_inaccessible'
    return 'process_evidence_unavailable_or_inconsistent'


def identity(raw, pid):
    # Kernel comm can contain spaces and parentheses; use the final delimiter.
    head, tail = raw.rsplit(b')', 1)
    fields = tail.split()
    if (head.split(b' (', 1)[0] != str(pid).encode() or len(fields) < 20
            or not fields[19].isdigit() or len(fields[0]) != 1):
        raise Unavailable('process_identity_inconsistent')
    return fields[19], fields[0]


def credentials(raw):
    values = [line.split()[1:] for line in raw.splitlines() if line.startswith(b'Uid:')]
    if len(values) != 1 or len(values[0]) != 4 or not all(v.isdigit() for v in values[0]):
        raise Unavailable('process_identity_inconsistent')
    return values[0]


def visible_processes(reader, uid, own_pid):
    reasons = set()
    count = 0
    for name in reader.names('/proc', MAX_PROCESSES + 256):
        if not name.isdecimal() or int(name) == own_pid:
            continue
        count += 1
        if count > MAX_PROCESSES:
            raise Unavailable('process_inventory_bound')
        p = '/proc/' + name
        try:
            before_meta = reader.metadata(p)
            before = identity(reader.read(p + '/stat', 8192), int(name))
            before_uids = credentials(reader.read(p + '/status', 16384))
            owned = str(uid).encode() in before_uids or before_meta.st_uid == uid
            if owned and before_uids != [str(uid).encode()] * 4:
                raise Unavailable('process_identity_inconsistent')
            if owned and before[1] != b'Z':
                for leaf in ('cwd', 'exe', 'root'):
                    reader.link(p + '/' + leaf)
                    reader.metadata(p + '/' + leaf)
                for leaf in ('cmdline', 'environ', 'maps'):
                    reader.read(p + '/' + leaf, 1024 * 1024)
                for fd in reader.names(p + '/fd', MAX_FDS):
                    try:
                        reader.link(p + '/fd/' + fd)
                        reader.metadata(p + '/fd/' + fd)
                    except FileNotFoundError:
                        pass  # A closed fd is not an inaccessible live object.
            after = identity(reader.read(p + '/stat', 8192), int(name))
            after_meta = reader.metadata(p)
            if before_uids != credentials(reader.read(p + '/status', 16384)):
                raise Unavailable('process_identity_inconsistent')
            if (before[0] != after[0] or (before[1] == b'Z' and after[1] != b'Z') or before_meta.st_ino != after_meta.st_ino
                    or before_meta.st_dev != after_meta.st_dev or before_meta.st_uid != after_meta.st_uid):
                raise Unavailable('process_identity_inconsistent')
        except (OSError, ValueError, Unavailable) as error:
            if isinstance(error, Unavailable) and error.code.endswith(('bound', 'exhausted')):
                raise
            try:
                reader.metadata(p, follow=False)
            except FileNotFoundError:
                continue  # Only a confirmed disappearance is safe to disregard.
            except OSError:
                reasons.add('process_evidence_unavailable_or_inconsistent')
            else:
                reasons.add(failure(error))
    return [row('same_uid_process_evidence', 'blocked' if code == 'process_evidence_inaccessible' else 'unknown', code)
            for code in sorted(reasons)] or [row('same_uid_process_evidence', 'satisfied', 'visible_process_evidence_readable')]


def proc_mount(reader):
    reader.verify_procfs()
    raw = reader.read('/proc/self/mountinfo', 1024 * 1024).decode('utf-8', 'strict')
    found = []
    for line in raw.splitlines():
        left, right = line.split(' - ', 1)
        fields, extra = left.split(), right.split()
        if fields[4] == '/proc':
            found.append((fields, extra))
    if len(found) != 1 or found[0][1][0] != 'proc' or found[0][0][3] != '/':
        raise Unavailable('proc_inventory_hidden_or_unverified')
    options = set(found[0][0][5].split(',')) | set(found[0][1][2].split(','))
    if any(v.startswith('hidepid=') and v != 'hidepid=0' for v in options) or 'subset=pid' in options:
        raise Unavailable('proc_inventory_hidden_or_unverified')


def inspect(*, _reader=None, _system=None, _machine=None, _uid=None, _pid=None):
    r = _reader or Reader()
    system, machine = _system or platform.system(), _machine or platform.machine()
    uid = os.geteuid() if _uid is None else _uid
    pid = os.getpid() if _pid is None else _pid
    checks = []
    setup, protected, removal = [], [], []
    try:
        if system != 'Linux' or machine != 'x86_64':
            setup.append(row('native_platform', 'blocked', 'native_linux_x86_64_required'))
        else:
            distro = r.read('/etc/os-release', 16384).decode()
            release = r.read('/proc/sys/kernel/osrelease', 4096).decode().lower()
            if 'microsoft' in release:
                setup.append(row('native_platform', 'unknown', 'wsl_existing_qualification_boundary'))
            elif not re.search(r'^ID=\"?ubuntu\"?$', distro, re.M) or not re.search(r'^VERSION_ID=\"?24\.04\"?$', distro, re.M):
                setup.append(row('native_platform', 'blocked', 'native_ubuntu_24_04_required'))
            else:
                setup.append(row('native_platform', 'satisfied', 'native_ubuntu_24_04_x86_64'))
            setup.append(row('ordinary_operator', 'blocked' if uid == 0 else 'satisfied',
                             'ordinary_operator_required' if uid == 0 else 'ordinary_operator'))
            # These static controls are necessary, never sufficient for admission.
            link = r.link('/proc/self/ns/user')
            if not re.fullmatch(r'user:\[[0-9]+\]', link):
                raise Unavailable('namespace_identity_unknown')
            maximum = r.read('/proc/sys/user/max_user_namespaces', 64).strip()
            if not maximum.isdigit():
                raise Unavailable('namespace_controls_unknown')
            controls = int(maximum) > 0
            try:
                clone = r.read('/proc/sys/kernel/unprivileged_userns_clone', 64).strip()
                if clone not in (b'0', b'1'):
                    raise Unavailable('namespace_controls_unknown')
                controls = controls and clone == b'1'
            except FileNotFoundError:
                pass  # This optional distro knob is not a kernel requirement.
            setup.append(row('namespace_controls', 'satisfied' if controls else 'blocked',
                             'namespace_controls_observed' if controls else 'user_namespaces_disabled'))
            protected.append(row('selected_namespace_admission', 'unknown' if controls else 'blocked',
                                 'selected_runtime_admission_unmeasured' if controls else 'user_namespaces_disabled'))
    except (OSError, ValueError, Unavailable):
        setup.append(row('namespace_controls', 'unknown', 'namespace_or_platform_evidence_unavailable'))
    if system == 'Linux':
        try:
            uid_map = r.read('/proc/self/uid_map', 4096).split()
            if uid_map == [b'0', b'0', b'4294967295']:
                removal.append(row('host_user_namespace', 'satisfied', 'host_user_namespace_observed'))
            elif len(uid_map) >= 3 and all(v.isdigit() for v in uid_map) and len(uid_map) % 3 == 0:
                removal.append(row('host_user_namespace', 'blocked', 'removal_host_user_namespace_required'))
            else:
                removal.append(row('host_user_namespace', 'unknown', 'namespace_identity_unknown'))
            proc_mount(r)
            removal.extend(visible_processes(r, uid, pid))
        except (OSError, ValueError, Unavailable) as error:
            removal.append(row('same_uid_process_evidence', 'unknown', failure(error)))
    else:
        removal.append(row('native_process_evidence', 'unknown', 'native_linux_evidence_unavailable'))
    if not protected:
        protected.append(row('selected_namespace_admission', 'unknown', 'selected_runtime_admission_unmeasured'))
    for phase, items in (('setup', setup), ('protected_run', protected), ('removal', removal)):
        checks.extend(dict(item, phase=phase) for item in items)
    return {'format': FORMAT, 'scope': 'current_environment_prerequisites_only',
            'setup': aggregate(setup), 'protected_run': aggregate(protected), 'removal': aggregate(removal),
            'active_protection': 'not_measured', 'removal_authorized': False,
            'future_inactivity': 'not_proven', 'checks': checks, 'guidance': GUIDANCE,
            'limits': {'seconds': MAX_SECONDS, 'total_bytes': MAX_BYTES, 'processes': MAX_PROCESSES,
                       'fds_per_process': MAX_FDS, 'individual_bytes': 1024 * 1024}}


class Refusal(Exception):
    def __init__(self, report):
        self.report = {'status': 'failed', 'executed': False, 'reason': 'lifecycle_prerequisite_unavailable',
                       'lifecycle_preflight': report}


def require_preparation(report, *, removal=False):
    if report['setup'] != 'satisfied' or (removal and report['removal'] != 'satisfied'):
        raise Refusal(report)


def human(report):
    return '\n'.join('Lifecycle ' + phase + ': ' + report[phase] + '. ' + GUIDANCE[phase]
                     for phase in ('setup', 'protected_run', 'removal'))
