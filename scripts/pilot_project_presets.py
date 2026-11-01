# SPDX-License-Identifier: Apache-2.0
"""Bounded operator shortcuts; checks never grant execution authority."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

if os.name == 'posix':
    import fcntl

FORMAT = 'sw-pilot-project-presets/1'
DIRECTORY = 'pilot-projects'
CAP = 128 * 1024
NAME = re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, code):
    if not ok:
        raise ValueError('project_' + code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(m):
    return (m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_mode, m.st_nlink,
            m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def directory_identity(path, profiles):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'canonical_directory_required')
    fd = profiles._open_absolute_directory(Path(path))
    try:
        m = os.fstat(fd)
        require(m.st_uid == os.getuid() and stat.S_IMODE(m.st_mode) == 0o700, 'private_directory_required')
        return [m.st_dev, m.st_ino, m.st_uid]
    finally:
        os.close(fd)


def read_at(fd, leaf, cap=CAP):
    try:
        before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_size <= cap and not before.st_mode & 0o077,
            'private_file_required')
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


def reference(path, profiles, cap=CAP):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'canonical_input_required')
    fd = profiles._open_absolute_directory(path.parent)
    try:
        raw = read_at(fd, path.name, cap)
        require(raw is not None, 'input_missing')
        return {'path': str(path), 'sha256': digest(raw)}
    finally:
        os.close(fd)


def provider_reference(home, name, version, expected, profiles):
    require(isinstance(version, str) and re.fullmatch(r'[0-9a-f]{32}', version), 'provider_version_required')
    with profiles.Store(home) as store:
        index = store.index()
        require(index is not None and name in index['profiles']
                and index['profiles'][name]['current'] == version, 'provider_version_changed')
        profile, bound = store.profile(name, version)
        require(expected is None or bound == expected, 'provider_changed')
        # Credentials remain transient in the accepted provider loader.
        return profile, {'name': name, 'version': version, 'sha256': bound}


class Store:
    def __init__(self, home, profiles, create=False):
        self.home, self.profiles = Path(home), profiles
        self.parent = self.fd = None
        self.new = False
        try:
            directory_identity(self.home, profiles)
            self.parent = profiles._open_absolute_directory(self.home)
            if create:
                try:
                    os.mkdir(DIRECTORY, 0o700, dir_fd=self.parent)
                    self.new = True
                except FileExistsError:
                    pass
            try:
                self.fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=self.parent)
            except FileNotFoundError:
                require(not create, 'store_missing')
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        require(directory_identity(self.home, self.profiles) ==
                [os.fstat(self.parent).st_dev, os.fstat(self.parent).st_ino, os.getuid()], 'store_parent_changed')
        if self.fd is not None:
            m = os.fstat(self.fd)
            named = os.stat(DIRECTORY, dir_fd=self.parent, follow_symlinks=False)
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == os.getuid()
                    and stat.S_IMODE(m.st_mode) == 0o700
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
        if self.fd is None:
            return {'format': FORMAT, 'records': {}}
        # Bound enumeration as well as bytes; unknown/interrupted state refuses.
        with os.scandir(self.fd) as entries:
            for count, entry in enumerate(entries):
                require(count == 0 and entry.name == 'catalog.json', 'store_inventory_invalid')
        raw = read_at(self.fd, 'catalog.json')
        if raw is None:
            require(self.new, 'catalog_missing')
            return {'format': FORMAT, 'records': {}}
        value = self.profiles.strict(raw)
        require(isinstance(value, dict) and set(value) == {'format', 'records'}
                and value['format'] == FORMAT and isinstance(value['records'], dict)
                and len(value['records']) <= 16 and encoded(value) == raw, 'store_invalid')
        for name, record in value['records'].items():
            require(NAME.fullmatch(name) and isinstance(record, dict)
                    and set(record) == {'version', 'binding'}
                    and re.fullmatch(r'[0-9a-f]{32}', record['version']), 'record_invalid')
            validate_binding(record['binding'])
        self.check()
        return value

    def write(self, operation, name, binding=None, expected=None, revalidate=None):
        require(NAME.fullmatch(name) is not None, 'name_invalid')
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        temporary = '.next-' + uuid.uuid4().hex
        try:
            value = self.read()
            old = value['records'].get(name)
            if operation == 'create':
                require(old is None and len(value['records']) < 16, 'exists_or_limit')
            else:
                require(old is not None and digest(encoded(old)) == expected, 'version_stale')
            if operation == 'remove':
                del value['records'][name]
            else:
                validate_binding(binding)
                value['records'][name] = {'version': uuid.uuid4().hex, 'binding': binding}
            raw = encoded(value)
            require(len(raw) <= CAP, 'store_limit')
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=self.fd)
            with os.fdopen(out, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.check()
            if revalidate is not None:
                revalidate()
            self.check()
            os.replace(temporary, 'catalog.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            self.new = False
            return value['records'].get(name)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass
            fcntl.flock(self.fd, fcntl.LOCK_UN)


def validate_binding(b):
    require(isinstance(b, dict) and set(b) == {'selection', 'commit', 'tree', 'workspaces', 'runtime_profiles_sha256', 'snapshot_sha256', 'provider', 'budget', 'state_root'},
            'binding_invalid')
    require(re.fullmatch(r'[0-9a-f]{40}', b['commit']) and HEX.fullmatch(b['snapshot_sha256']), 'binding_invalid')
    require(re.fullmatch(r'[0-9a-f]{40}', b['tree']) and HEX.fullmatch(b['runtime_profiles_sha256']), 'binding_invalid')
    require(isinstance(b['workspaces'], dict) and set(b['workspaces']) == {'filesystem', 'git'}, 'binding_invalid')
    for root in b['workspaces'].values():
        require(isinstance(root, dict) and set(root) == {'path','device','inode','uid'}
                and Path(root['path']).is_absolute()
                and all(type(root[k]) is int and root[k] >= 0 for k in ('device','inode','uid')), 'binding_invalid')
    for ref in (b['selection'], b['budget']):
        if ref is not None:
            require(isinstance(ref, dict) and set(ref) == {'path', 'sha256'}
                    and Path(ref['path']).is_absolute() and HEX.fullmatch(ref['sha256']), 'binding_invalid')
    require(b['selection'] is not None and isinstance(b['provider'], dict)
            and set(b['provider']) == {'name', 'version', 'sha256'}
            and NAME.fullmatch(b['provider']['name']) and HEX.fullmatch(b['provider']['sha256'])
            and re.fullmatch(r'[0-9a-f]{32}', b['provider']['version']), 'binding_invalid')
    require(isinstance(b['state_root'], dict) and set(b['state_root']) == {'path', 'identity'}
            and Path(b['state_root']['path']).is_absolute()
            and isinstance(b['state_root']['identity'], list) and len(b['state_root']['identity']) == 3
            and all(type(i) is int and i >= 0 for i in b['state_root']['identity']), 'binding_invalid')


def snapshot(args, front, profiles):
    runner = front.load('project_accepted_runner', 'pilot-run.py')
    source = front.source()
    require(not source['dirty'], 'clean_source_required')
    chosen = argparse.Namespace(selection=args.selection, expected_commit=source['commit'],
                                timeout_seconds=180, ask_wait_seconds=0, port=0)
    selection, _, _ = runner.selected(chosen)
    roots = front.PREP.workspace_paths(selection, args.selection.parent)
    require('prepared_workspaces' in selection, 'explicit_existing_projects_required')
    root_ids = {k: front.PREP.root_identity(p) for k, p in roots.items()}
    selected_ref = reference(args.selection, profiles)
    _, provider = provider_reference(args.agent_home, args.provider_name, args.provider_version, None, profiles)
    budget = None if args.linux_budget is None else reference(args.linux_budget, profiles, 16384)
    if budget is not None:
        require(digest(runner.budget_input(args.linux_budget)) == budget['sha256'], 'budget_changed')
    state = {'path': str(args.state_root), 'identity': directory_identity(args.state_root, profiles)}
    for path in (args.agent_home, args.state_root, args.selection.parent):
        require(all(not Path(path).is_relative_to(root) for root in roots.values()), 'state_overlaps_workspace')
    return {'selection': selected_ref, 'commit': chosen.expected_commit, 'tree': source['tree'],
            'workspaces': root_ids,
            'runtime_profiles_sha256': digest(encoded({'files': selection['files'], 'profiles': selection['prepared_profiles']})),
            'snapshot_sha256': digest(encoded({'selection': selection, 'roots': root_ids})),
            'provider': provider, 'budget': budget, 'state_root': state}


def binding_args(binding, home):
    return argparse.Namespace(agent_home=home, selection=Path(binding['selection']['path']),
                              provider_name=binding['provider']['name'], provider_version=binding['provider']['version'],
                              linux_budget=None if binding['budget'] is None else Path(binding['budget']['path']),
                              state_root=Path(binding['state_root']['path']))


def verify(binding, home, front, profiles):
    validate_binding(binding)
    args = binding_args(binding, home)
    require(snapshot(args, front, profiles) == binding and snapshot(args, front, profiles) == binding, 'inputs_changed')


def main(argv, front):
    parser = argparse.ArgumentParser(prog=front.PROG + ' project', description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'check', 'create', 'update', 'remove', 'run'):
        sub = commands.add_parser(action)
        sub.add_argument('--name', required=action != 'inspect')
        sub.add_argument('--expected-version', help='exact record digest from inspect/check')
        sub.add_argument('--apply', action='store_true')
        if action in ('create', 'update'):
            sub.add_argument('--selection', type=Path, required=True)
            sub.add_argument('--provider-name', required=True)
            sub.add_argument('--provider-version', required=True)
            sub.add_argument('--state-root', type=Path, required=True)
            sub.add_argument('--linux-budget', type=Path)
        if action == 'run':
            sub.add_argument('--prompt')
            sub.add_argument('--timeout-seconds', type=int, default=180)
    args = parser.parse_args(argv)
    args.agent_home = front.PROJECT_HOME
    report = {'format': FORMAT, 'status': 'refused', 'executed': False, 'authority': False,
              'observed_protection': 'not-observed'}
    try:
        require(sys.platform.startswith('linux'), 'native_linux_required')
        profiles = front.provider_profiles()
        require(args.name is None or NAME.fullmatch(args.name), 'name_invalid')
        writing = args.apply and args.action in ('create', 'update', 'remove')
        binding = snapshot(args, front, profiles) if args.action in ('create', 'update') else None
        if binding is not None:
            verify(binding, args.agent_home, front, profiles)
        with Store(args.agent_home, profiles, create=writing) as store:
            records = store.read()['records']
            record = records.get(args.name)
            if args.action == 'inspect':
                report.update(status='configured-not-running', presets=[{'name': n, 'version': r['version'],
                    'digest': digest(encoded(r)), 'provider':{k:r['binding']['provider'][k]for k in ('name','version')},
                    'selection_sha256':r['binding']['selection']['sha256'],
                    'workspace_binding_sha256':r['binding']['snapshot_sha256']} for n, r in sorted(records.items())])
            elif writing:
                record = store.write(args.action, args.name, binding, args.expected_version,
                                     None if binding is None else lambda: verify(binding, args.agent_home, front, profiles))
                report.update(status='removed' if record is None else 'saved',
                              digest=None if record is None else digest(encoded(record)))
            elif args.action in ('create', 'update', 'remove'):
                if args.action == 'create':
                    require(record is None and len(records) < 16, 'exists_or_limit')
                if args.action != 'create':
                    require(record is not None and digest(encoded(record)) == args.expected_version, 'version_stale')
                report.update(status='preview', mutates=False)
            else:
                require(record is not None, 'preset_missing')
                verify(record['binding'], args.agent_home, front, profiles)
                report.update(status='configured-not-running', digest=digest(encoded(record)), version=record['version'],
                              resource_budget='unbudgeted' if record['binding']['budget'] is None else 'selected-not-validated')
                if args.action == 'run':
                    require(args.apply and args.expected_version == digest(encoded(record)), 'run_confirmation_required')
                    b = record['binding']
                    words = [sys.executable, *front.PYTHON_FLAGS, str(front.RUNNER), '--run', '--selection', b['selection']['path'],
                             '--expected-commit', b['commit'], '--expected-selection-sha256', b['selection']['sha256'],
                             '--provider-home', str(args.agent_home), '--provider-name', b['provider']['name'],
                             '--provider-version', b['provider']['version'], '--provider-sha256', b['provider']['sha256'],
                             '--state-root', b['state_root']['path'], '--expected-state-identity', ':'.join(map(str,b['state_root']['identity'])),
                             '--timeout-seconds', str(args.timeout_seconds)]
                    if b['budget'] is not None:
                        words += ['--linux-budget', b['budget']['path'], '--expected-budget-sha256', b['budget']['sha256']]
                    if args.prompt is not None:
                        words += ['--prompt', args.prompt]
        if args.action == 'run':
            os.execve(sys.executable, words, dict(os.environ))
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error)
        report['reason'] = reason if re.fullmatch(r'project_[a-z_]{1,80}', reason) else 'project_input_unavailable'
        report['action'] = 'Inspect the exact inputs and explicitly update the preset; no automatic retry.'
        print(json.dumps(report, sort_keys=True))
        return 2
