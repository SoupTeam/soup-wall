# SPDX-License-Identifier: Apache-2.0
"""Explicit, separately bound read-only roots for the original filesystem server."""
import argparse
import json
import os
from pathlib import Path
import re
import stat

FORMAT = 'sw-pilot-filesystem-roots/1'
PROFILE = 'sw-mcp/filesystem-multi-root-readonly/1'
ID = 'filesystem-multi-root-readonly-v1'
MAX_ENTRIES = 32768
MAX_DIRECTORIES = 128


def require(condition, code):
    if not condition:
        raise ValueError('filesystem_roots_' + code)


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def directory(path):
    path = Path(path)
    require(path.is_absolute() and path != Path('/') and str(path) == str(path.resolve(strict=True))
            and '..' not in path.parts, 'canonical_root_required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        value = os.fstat(fd)
        require(value.st_uid == os.getuid() and not value.st_mode & 0o022, 'owned_root_required')
        return fd, {'path': str(path), 'identity': {
            'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid}}
    except BaseException:
        os.close(fd)
        raise


def topology(fd, counts, depth=0):
    require(depth <= 32, 'tree_bound')
    counts[1] += 1
    require(counts[1] <= MAX_DIRECTORIES, 'tree_bound')
    before = os.fstat(fd)
    for name in os.listdir(fd):
        counts[0] += 1
        require(counts[0] <= MAX_ENTRIES, 'tree_bound')
        value = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(value.st_uid == os.getuid() and not value.st_mode & 0o022
                and (stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode) and value.st_nlink == 1),
                'unsafe_entry')
        if stat.S_ISDIR(value.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                opened = os.fstat(child)
                require((opened.st_dev, opened.st_ino) == (value.st_dev, value.st_ino), 'tree_changed')
                topology(child, counts, depth + 1)
            finally:
                os.close(child)
    after = os.fstat(fd)
    require((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns), 'tree_changed')


def inventory(roots):
    require(isinstance(roots, list) and 2 <= len(roots) <= 4, 'count')
    result = []
    counts = [0, 0]
    for root_id, path in sorted(roots):
        require(isinstance(root_id, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', root_id), 'id')
        fd, value = directory(path)
        try:
            topology(fd, counts)
        finally:
            os.close(fd)
        value.update(id=root_id, scope='read-only')
        for other in result:
            require(other['id'] != root_id and other['identity'] != value['identity'], 'duplicate_root')
            a, b = Path(other['path']), Path(value['path'])
            require(not a.is_relative_to(b) and not b.is_relative_to(a), 'overlapping_roots')
        result.append(value)
    return {'format': FORMAT, 'roots': result}


def verify(value, workspace=None):
    require(isinstance(value, dict) and set(value) == {'format', 'roots'} and value['format'] == FORMAT,
            'binding_schema')
    roots = value['roots']
    require(isinstance(roots, list) and 2 <= len(roots) <= 4, 'count')
    for root in roots:
        require(isinstance(root, dict) and set(root) == {'id', 'path', 'identity', 'scope'}
                and root['scope'] == 'read-only' and isinstance(root['identity'], dict)
                and set(root['identity']) == {'device', 'inode', 'uid'}
                and all(type(v) is int and v >= 0 for v in root['identity'].values()), 'binding_schema')
    observed = inventory([(r['id'], r['path']) for r in roots])
    require(value == observed, 'selected_root_changed')
    require(workspace is None or str(workspace) == roots[0]['path'], 'workspace_mismatch')
    return value


def load(path, workspace=None):
    path = Path(path)
    fd, _ = directory(path.parent)
    try:
        file = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(file)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and not before.st_mode & 0o077 and before.st_nlink == 1 and before.st_size <= 65536,
                    'private_manifest_required')
            raw = os.read(file, 65537)
            after = os.fstat(file)
            named = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            stamp = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
            require(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(named), 'manifest_changed')
        finally:
            os.close(file)
    finally:
        os.close(fd)
    return verify(strict(raw), workspace)


def outside(paths, binding):
    for path in paths:
        if path is None:
            continue
        resolved = Path(path).resolve()
        for root in binding['roots']:
            selected = Path(root['path'])
            require(not resolved.is_relative_to(selected) and not selected.is_relative_to(resolved),
                    'state_or_runtime_overlaps_root')


def arguments(binding):
    return ['/workspace/' + root['id'] for root in binding['roots']]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', action='append', required=True, metavar='ID=ABSOLUTE_PATH')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    require(all('=' in root for root in args.root), 'root_argument')
    binding = inventory([tuple(root.split('=', 1)) for root in args.root])
    if args.apply:
        require(args.output is not None and args.output.is_absolute(), 'absolute_output_required')
        outside([args.output], binding)
        fd, _ = directory(args.output.parent)
        try:
            require(not os.fstat(fd).st_mode & 0o077, 'private_output_parent_required')
            require(verify(binding) == binding, 'selected_root_changed')
            file = os.open(args.output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                           0o600, dir_fd=fd)
            with os.fdopen(file, 'wb') as stream:
                stream.write((json.dumps(binding, sort_keys=True, indent=2) + '\n').encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(fd)
        finally:
            os.close(fd)
    print(json.dumps({'status': 'configured' if args.apply else 'plan', 'binding': binding,
                      'executed': False, 'protection': 'not-observed'}))
    return 0
