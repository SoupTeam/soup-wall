# SPDX-License-Identifier: Apache-2.0
"""Named installed Linux resource-budget presets; a preset never grants execution authority.

A preset stores the accepted nonsecret ``sw-mcp/linux-cgroup-budget/1`` limits and two
separate identities: the canonical configuration digest and the delegated root's
device/inode/owner. Selection, probing and witnessed enforcement stay distinct: this
module only configures. The existing launcher revalidates and enforces every run.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

if os.name == 'posix':
    import fcntl

FORMAT = 'sw-pilot-budget-presets/1'
CONFIG_FORMAT = 'sw-mcp/linux-cgroup-budget/1'
DIRECTORY = 'pilot-budget-presets'
CAP = 128 * 1024
LIMIT = 16
NAME = re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
VERSION = re.compile(r'[0-9a-f]{32}\Z')
ROOT_PREFIX = '/sys/fs/cgroup/'
ROOT_PART = re.compile(r'[A-Za-z0-9._@-]{1,255}\Z')
TEMPORARY = re.compile(r'\.next-[0-9a-f]{32}\Z')
STAGING = re.compile(r'\.stage-[0-9a-f]{32}\Z')
FIELDS = ('memoryMaxBytes', 'pidsMax', 'cpuQuotaMicros', 'wallMillis')
# These mirror the engine's accepted bounds (crates/agentfw/src/mcp/linux_budget.rs
# Config::validate); a source-pinned test fails when either side drifts.
FLOORS = {'memoryMaxBytes': 64 * 1024 * 1024, 'pidsMax': 16, 'cpuQuotaMicros': 1_000, 'wallMillis': 1_000}
MEMORY_STEP = 65_536
BASELINES = {
    # Every value the accepted engine configuration permits.
    'accepted-bounds': {'memoryMaxBytes': 16 * 1024 * 1024 * 1024, 'pidsMax': 4_096,
                        'cpuQuotaMicros': 1_600_000, 'wallMillis': 3_600_000},
    # The documented prepared-pilot selection; presets may only tighten it.
    'prepared-pilot-default': {'memoryMaxBytes': 268_435_456, 'pidsMax': 64,
                               'cpuQuotaMicros': 100_000, 'wallMillis': 30_000},
}
FAILURES = frozenset('budget_preset_' + code for code in (
    'agentfw_invalid', 'baseline_unknown', 'canonical_directory_required',
    'catalog_missing', 'config_invalid', 'confirmation_required', 'delegation_busy',
    'delegation_unverified', 'engine_refused', 'exists_or_limit', 'home_invalid',
    'in_use', 'input_changed', 'limit_exceeds_baseline', 'limit_out_of_range',
    'name_invalid', 'native_linux_required', 'private_directory_required', 'private_file_required',
    'record_invalid', 'root_changed', 'root_invalid', 'missing', 'stale',
    'store_busy', 'store_changed', 'store_inventory_invalid', 'store_invalid', 'store_limit',
    'store_missing', 'store_parent_changed', 'unchanged', 'version_stale', 'selection_conflict'))


def require(ok, code):
    if not ok:
        raise ValueError('budget_preset_' + code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def record_digest(record):
    return digest(encoded(record))


def identity(m):
    return (m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_mode, m.st_nlink,
            m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def open_absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'canonical_directory_required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            following = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def private_directory(fd):
    m = os.fstat(fd)
    require(stat.S_ISDIR(m.st_mode) and m.st_uid == os.getuid() and stat.S_IMODE(m.st_mode) == 0o700,
            'private_directory_required')
    return [m.st_dev, m.st_ino, m.st_uid]


def read_at(fd, leaf, cap=CAP):
    try:
        before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
            and before.st_size <= cap and not before.st_mode & 0o077, 'private_file_required')
    f = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        require(identity(before) == identity(os.fstat(f)), 'input_changed')
        raw = bytearray()
        while len(raw) <= cap:
            block = os.read(f, min(4096, cap + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(f))
                and identity(before) == identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False)), 'input_changed')
        return bytes(raw)
    finally:
        os.close(f)


def write_private(fd, leaf, raw):
    out = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    with os.fdopen(out, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def config_identity(config):
    """Same compact sorted-property SHA-256 as Config::identity in the Rust engine."""
    return digest(encoded(config))


def root_path(config):
    path = config.get('delegationRoot')
    require(isinstance(path, str) and path.startswith(ROOT_PREFIX) and len(path) <= 4096, 'config_invalid')
    parts = path[len(ROOT_PREFIX):].split('/')
    require(all(ROOT_PART.fullmatch(part) and part not in ('.', '..') for part in parts), 'config_invalid')
    return Path(path)


def validate_config(config, baseline):
    require(baseline in BASELINES, 'baseline_unknown')
    require(isinstance(config, dict) and set(config) == {'format', 'delegationRoot', *FIELDS}
            and config['format'] == CONFIG_FORMAT, 'config_invalid')
    root_path(config)
    ceiling = BASELINES[baseline]
    for field in FIELDS:
        value = config[field]
        require(type(value) is int, 'config_invalid')
        require(FLOORS[field] <= value <= BASELINES['accepted-bounds'][field], 'limit_out_of_range')
        require(value <= ceiling[field], 'limit_exceeds_baseline')
    require(config['memoryMaxBytes'] % MEMORY_STEP == 0, 'limit_out_of_range')
    return config


def root_identity(path):
    """Owner-private delegated directory identity. Never creates or enables anything."""
    require(sys.platform.startswith('linux'), 'native_linux_required')
    path = Path(path)
    try:
        fd = open_absolute(path)
    except OSError:
        raise ValueError('budget_preset_root_invalid') from None
    try:
        m = os.fstat(fd)
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == os.getuid() and not m.st_mode & 0o077, 'root_invalid')
        return {'device': m.st_dev, 'inode': m.st_ino, 'uid': m.st_uid}
    finally:
        os.close(fd)


def validate_record(name, record):
    require(NAME.fullmatch(name) is not None, 'name_invalid')
    require(isinstance(record, dict) and set(record) == {'version', 'baseline', 'config', 'config_sha256', 'root'}
            and isinstance(record['version'], str) and VERSION.fullmatch(record['version'])
            and isinstance(record['config_sha256'], str) and HEX.fullmatch(record['config_sha256']),
            'record_invalid')
    require(isinstance(record['baseline'], str), 'record_invalid')
    config = validate_config(record['config'], record['baseline'])
    root = record['root']
    require(record['config_sha256'] == config_identity(config), 'record_invalid')
    require(isinstance(root, dict) and set(root) == {'device', 'inode', 'uid'}
            and all(type(root[k]) is int and root[k] >= 0 for k in root), 'record_invalid')


class Store:
    """No-follow, owner-private catalog. A killed writer leaves the old or the new
    complete catalog; stale staging entries are ignored and swept by the next writer."""

    def __init__(self, home, create=False):
        self.home = Path(home)
        self.parent = self.fd = None
        try:
            require(self.home.is_absolute() and '..' not in self.home.parts, 'home_invalid')
            self.parent = open_absolute(self.home)
            private_directory(self.parent)
            if create:
                self.bootstrap()
            try:
                self.fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=self.parent)
            except FileNotFoundError:
                require(False, 'store_missing')
            self.check()
        except BaseException:
            self.close()
            raise

    @classmethod
    def exists(cls, home):
        try:
            with cls(home):
                return True
        except ValueError as error:
            if str(error) == 'budget_preset_store_missing':
                return False
            raise

    def bootstrap(self):
        """The store directory appears only with a complete empty catalog (staged rename)."""
        try:
            fcntl.flock(self.parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('budget_preset_store_busy') from None
        try:
            try:
                os.close(os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=self.parent))
                return
            except FileNotFoundError:
                pass
            with os.scandir(self.parent) as entries:
                stale = [e.name for e in entries if STAGING.fullmatch(e.name)]
            for leftover in stale:
                self.sweep_stage(leftover)
            stage = '.stage-' + uuid.uuid4().hex
            os.mkdir(stage, 0o700, dir_fd=self.parent)
            sfd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            try:
                write_private(sfd, 'catalog.json', encoded({'format': FORMAT, 'records': {}}))
                os.fsync(sfd)
            finally:
                os.close(sfd)
            os.rename(stage, DIRECTORY, src_dir_fd=self.parent, dst_dir_fd=self.parent)
            os.fsync(self.parent)
        finally:
            fcntl.flock(self.parent, fcntl.LOCK_UN)

    def sweep_stage(self, leftover):
        try:
            sfd = os.open(leftover, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
        except OSError:
            return
        try:
            m = os.fstat(sfd)
            if m.st_uid != os.getuid():
                return
            for entry in os.listdir(sfd):
                if entry == 'catalog.json':
                    os.unlink(entry, dir_fd=sfd)
            os.rmdir(leftover, dir_fd=self.parent)
        except OSError:
            pass
        finally:
            os.close(sfd)

    def check(self):
        require(private_directory(open_absolute(self.home)) == private_directory(self.parent), 'store_parent_changed')
        if self.fd is not None:
            m = os.fstat(self.fd)
            named = os.stat(DIRECTORY, dir_fd=self.parent, follow_symlinks=False)
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == os.getuid() and stat.S_IMODE(m.st_mode) == 0o700
                    and (m.st_dev, m.st_ino) == (named.st_dev, named.st_ino), 'store_changed')

    def close(self):
        for name in ('fd', 'parent'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def read(self):
        self.check()
        with os.scandir(self.fd) as entries:
            names = [entry.name for entry in entries]
        require(len(names) <= 8 and all(n == 'catalog.json' or TEMPORARY.fullmatch(n) for n in names),
                'store_inventory_invalid')
        raw = read_at(self.fd, 'catalog.json')
        require(raw is not None, 'catalog_missing')
        try:
            value = json.loads(raw)
        except ValueError:
            raise ValueError('budget_preset_store_invalid') from None
        require(isinstance(value, dict) and set(value) == {'format', 'records'} and value['format'] == FORMAT
                and isinstance(value['records'], dict) and len(value['records']) <= LIMIT
                and encoded(value) == raw, 'store_invalid')
        for name, record in value['records'].items():
            validate_record(name, record)
        self.check()
        return value

    def sweep_temporaries(self):
        with os.scandir(self.fd) as entries:
            stale = [e.name for e in entries if TEMPORARY.fullmatch(e.name)]
        for leftover in stale:
            m = os.stat(leftover, dir_fd=self.fd, follow_symlinks=False)
            require(stat.S_ISREG(m.st_mode) and m.st_uid == os.getuid(), 'store_inventory_invalid')
            os.unlink(leftover, dir_fd=self.fd)

    def write(self, operation, name, fields=None, expected=None, revalidate=None):
        require(NAME.fullmatch(name) is not None, 'name_invalid')
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('budget_preset_store_busy') from None
        temporary = '.next-' + uuid.uuid4().hex
        try:
            self.sweep_temporaries()
            value = self.read()
            old = value['records'].get(name)
            if operation == 'create':
                require(old is None and len(value['records']) < LIMIT, 'exists_or_limit')
            else:
                require(old is not None and record_digest(old) == expected, 'version_stale')
            if operation == 'remove':
                del value['records'][name]
            else:
                record = dict(fields, version=uuid.uuid4().hex)
                validate_record(name, record)
                value['records'][name] = record
            raw = encoded(value)
            require(len(raw) <= CAP, 'store_limit')
            write_private(self.fd, temporary, raw)
            self.check()
            if revalidate is not None:
                revalidate()
            self.check()
            os.replace(temporary, 'catalog.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            return value['records'].get(name)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass
            fcntl.flock(self.fd, fcntl.LOCK_UN)


def load_record(home, name):
    require(NAME.fullmatch(name) is not None, 'name_invalid')
    with Store(home) as store:
        record = store.read()['records'].get(name)
    require(record is not None, 'missing')
    return record


def resolve(home, name, expected):
    """Per-run revalidation. Returns the exact canonical configuration bytes to freeze.

    Any missing, changed, corrupt or relocated state refuses; there is no fallback to an
    unbudgeted run, an older version or a different root."""
    require(isinstance(expected, str) and HEX.fullmatch(expected), 'confirmation_required')
    record = load_record(home, name)
    require(record_digest(record) == expected, 'stale')
    require(root_identity(root_path(record['config'])) == record['root'], 'root_changed')
    return encoded(record['config']), record


def reference(home, name):
    """Digest-bound selection stored in a named project record."""
    record = load_record(home, name)
    require(root_identity(root_path(record['config'])) == record['root'], 'root_changed')
    return {'preset': name, 'digest': record_digest(record)}


def engine(agentfw, raw, expected_sha, probe):
    """Run the existing strict validator; with probe also its read-only delegation check."""
    agentfw = Path(agentfw)
    require(agentfw.is_absolute() and agentfw.resolve(strict=True) == agentfw, 'agentfw_invalid')
    m = agentfw.stat()
    require(stat.S_ISREG(m.st_mode) and m.st_uid in (0, os.getuid()) and not m.st_mode & 0o022
            and m.st_mode & 0o100, 'agentfw_invalid')
    scratch = Path(tempfile.mkdtemp(prefix='budget-preset-'))
    try:
        os.chmod(scratch, 0o700)
        config = scratch / 'budget.json'
        with open(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(raw)
        words = [str(agentfw), 'pilot-budget', '--config', str(config)] + (['--probe'] if probe else [])
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        result = subprocess.run(words, cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise ValueError('budget_preset_engine_refused') from None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if result.returncode != 0:
        busy = b'pilot_budget_root_busy' in result.stderr[:16384]
        raise ValueError('budget_preset_delegation_busy' if busy and probe else
                         'budget_preset_delegation_unverified' if probe else 'budget_preset_engine_refused')
    try:
        value = json.loads(result.stdout[:65536])
    except ValueError:
        raise ValueError('budget_preset_engine_refused') from None
    require(isinstance(value, dict) and value.get('format') == 'sw-prepared-pilot-budget/1'
            and value.get('budget_sha256') == expected_sha
            and value.get('scope') == 'per-original-server-process-tree'
            and value.get('protected_children_started') is False
            and value.get('status') == ('available-not-active' if probe else 'selected-not-active'),
            'engine_refused')
    return value['status']


def referenced_by(home, name, front):
    projects = front.load('budget_preset_projects', 'pilot_project_presets.py')
    with projects.Store(home, front.provider_profiles()) as store:
        records = store.read()['records']
    return sorted(n for n, r in records.items()
                  if isinstance(r['binding']['budget'], dict) and r['binding']['budget'].get('preset') == name)


def candidate(args):
    config = {'format': CONFIG_FORMAT, 'delegationRoot': str(args.root), 'memoryMaxBytes': args.memory_max_bytes,
              'pidsMax': args.pids_max, 'cpuQuotaMicros': args.cpu_quota_micros, 'wallMillis': args.wall_millis}
    validate_config(config, args.baseline)
    return {'baseline': args.baseline, 'config': config, 'config_sha256': config_identity(config),
            'root': root_identity(root_path(config))}


def summary(name, record):
    config = record['config']
    return {'name': name, 'version': record['version'], 'digest': record_digest(record),
            'baseline': record['baseline'], 'config_sha256': record['config_sha256'],
            'limits': {k: config[k] for k in FIELDS}, 'delegation_root': config['delegationRoot'],
            'root_identity': record['root']}


def main(argv, front):
    parser = argparse.ArgumentParser(prog=front.PROG + ' budget-preset', description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'check', 'create', 'update', 'remove'):
        sub = commands.add_parser(action)
        sub.add_argument('--name', required=action != 'inspect')
        sub.add_argument('--apply', action='store_true')
        if action in ('update', 'remove'):
            sub.add_argument('--expected-version', help='exact record digest from inspect/check/update preview')
        if action in ('check', 'create', 'update'):
            sub.add_argument('--agentfw', type=Path, required=True,
                             help='absolute installed agentfw used only for its strict validator/probe')
        if action == 'check':
            sub.add_argument('--probe', action='store_true',
                             help='also run the engine read-only delegation probe (no cgroup is created)')
        if action in ('create', 'update'):
            sub.add_argument('--root', type=Path, required=True, help='already delegated owner-private cgroup root')
            sub.add_argument('--memory-max-bytes', type=int, required=True)
            sub.add_argument('--pids-max', type=int, required=True)
            sub.add_argument('--cpu-quota-micros', type=int, required=True)
            sub.add_argument('--wall-millis', type=int, required=True)
            sub.add_argument('--baseline', choices=sorted(BASELINES), default='accepted-bounds')
            sub.add_argument('--expected-config-sha256', help='configuration digest from the preview')
    args = parser.parse_args(argv)
    home = front.PROJECT_HOME
    report = {'format': FORMAT, 'status': 'refused', 'executed': False, 'authority': False,
              'observed_protection': 'not-observed'}
    try:
        require(sys.platform.startswith('linux'), 'native_linux_required')
        require(front.platform_reason() is None, 'native_linux_required')
        require(args.name is None or NAME.fullmatch(args.name), 'name_invalid')
        writing = args.apply and args.action in ('create', 'update', 'remove')
        fields = candidate(args) if args.action in ('create', 'update') else None
        if args.action in ('inspect', 'create') and not Store.exists(home):
            records, old = {}, None
        else:
            with Store(home) as store:
                records = store.read()['records']
            old = records.get(args.name)
        report['states'] = {'configured': False, 'probed': False, 'witnessed_active': False}
        if args.action == 'inspect':
            if args.name is not None:
                require(old is not None, 'missing')
                records = {args.name: old}
            report.update(status='configured-not-running', presets=[summary(n, r) for n, r in sorted(records.items())])
        elif args.action == 'check':
            require(old is not None, 'missing')
            require(root_identity(root_path(old['config'])) == old['root'], 'root_changed')
            raw = encoded(old['config'])
            observed = engine(args.agentfw, raw, old['config_sha256'], args.probe)
            report.update(status='configured-not-active', digest=record_digest(old), version=old['version'],
                          config_sha256=old['config_sha256'],
                          resource_budget='available-not-active' if args.probe else 'selected-not-validated',
                          engine=observed, selected_by=referenced_by(home, args.name, front),
                          states={'configured': True, 'probed': bool(args.probe), 'witnessed_active': False})
        else:
            if args.action == 'create':
                require(old is None and len(records) < LIMIT, 'exists_or_limit')
            else:
                require(old is not None and record_digest(old) == args.expected_version, 'version_stale')
            if fields is not None:
                require(old is None or old['config'] != fields['config'] or old['root'] != fields['root']
                        or old['baseline'] != fields['baseline'], 'unchanged')
                engine(args.agentfw, encoded(fields['config']), fields['config_sha256'], False)
            users = referenced_by(home, args.name, front) if args.action != 'create' else []
            if args.action == 'remove':
                require(not users, 'in_use')
            plan = {'old_digest': None if old is None else record_digest(old),
                    'old_config_sha256': None if old is None else old['config_sha256'],
                    'new_config_sha256': None if fields is None else fields['config_sha256'],
                    'selected_by': users}
            if not writing:
                report.update(status='preview', mutates=False, **plan)
            else:
                if fields is not None:
                    require(args.expected_config_sha256 == fields['config_sha256'], 'confirmation_required')
                    same_root = old is not None and old['root'] == fields['root'] \
                        and old['config']['delegationRoot'] == fields['config']['delegationRoot']
                    try:
                        engine(args.agentfw, encoded(fields['config']), fields['config_sha256'], True)
                    except ValueError as error:
                        # A running instance holds its unchanged root; changing limits there is allowed,
                        # a different or newly selected busy root is not.
                        if not (str(error) == 'budget_preset_delegation_busy' and same_root):
                            raise
                        report['delegation'] = 'busy-root-unchanged'
                    else:
                        report['delegation'] = 'verified-idle'

                def revalidate():
                    if fields is not None:
                        require(root_identity(root_path(fields['config'])) == fields['root'], 'root_changed')
                    if args.action == 'remove':
                        require(not referenced_by(home, args.name, front), 'in_use')

                with Store(home, create=args.action == 'create') as store:
                    saved = store.write(args.action, args.name, fields, getattr(args, 'expected_version', None), revalidate)
                report.update(status='removed' if saved is None else 'saved',
                              digest=None if saved is None else record_digest(saved),
                              config_sha256=None if fields is None else fields['config_sha256'],
                              states={'configured': saved is not None, 'probed': False, 'witnessed_active': False},
                              **{k: v for k, v in plan.items() if k != 'new_config_sha256'})
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error)
        report['reason'] = reason if reason in FAILURES else 'budget_preset_input_unavailable'
        report['action'] = 'Inspect the exact inputs and explicitly update the preset; no automatic retry or unbudgeted fallback.'
        print(json.dumps(report, sort_keys=True))
        return 2
