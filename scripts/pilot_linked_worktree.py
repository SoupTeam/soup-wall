# SPDX-License-Identifier: Apache-2.0
"""Explicit source selection for the separately selected linked-worktree profile.

Repository path strings are compared with operator-selected roots, never followed
as authority. Native startup independently captures and validates the same inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

FORMAT = 'sw-pilot-linked-worktree/1'
PROFILE = 'sw-mcp/git-linked-worktree-readonly/1'
ID = 'git-linked-worktree-readonly-v1'
MAX_BYTES = 16 * 1024 * 1024


def require(ok, code):
    if not ok:
        raise ValueError('linked_worktree_' + code)


def strict(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate_field')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def directory(path):
    path = Path(path)
    require(path.is_absolute() and path != Path('/') and path.resolve(strict=True) == path
            and '..' not in path.parts, 'canonical_root_required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        m = os.fstat(fd)
        require(m.st_uid == os.getuid() and not m.st_mode & 0o022, 'owned_root_required')
        return fd, {'path': str(path), 'identity': {'device': m.st_dev, 'inode': m.st_ino, 'uid': m.st_uid}}
    except BaseException:
        os.close(fd)
        raise


def names(fd, cap=1024):
    result = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(result) < cap, 'metadata_count')
            result.append(entry.name)
    return sorted(result)


def stamp(m):
    return (m.st_dev, m.st_ino, m.st_uid, m.st_mode, m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def read(fd, name, cap=MAX_BYTES):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and not before.st_mode & 0o022 and before.st_nlink == 1 and before.st_size <= cap,
            'unsafe_file')
    file = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        require(stamp(before) == stamp(os.fstat(file)), 'input_changed')
        data = bytearray()
        while len(data) <= cap:
            block = os.read(file, min(65536, cap + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        require(len(data) == before.st_size and stamp(before) == stamp(os.fstat(file))
                and stamp(before) == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'input_changed')
        return bytes(data)
    finally:
        os.close(file)


def inventory(workspace, git_dir, common_dir):
    opened = []
    try:
        for root in (workspace, git_dir, common_dir):
            opened.append(directory(root))
        (w, wr), (g, gr), (c, cr) = opened
        workspace, git_dir, common_dir = map(Path, (wr['path'], gr['path'], cr['path']))
        require(git_dir.parent.parent == common_dir and git_dir.parent.name == 'worktrees'
                and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', git_dir.name), 'ordinary_layout_required')
        require(not workspace.is_relative_to(common_dir) and not common_dir.is_relative_to(workspace), 'overlapping_roots')
        leaves = names(g, 16)
        require(set(leaves) <= {'HEAD','index','gitdir','commondir','logs','refs','ORIG_HEAD','COMMIT_EDITMSG'},
                'admin_metadata_unsupported')
        if 'COMMIT_EDITMSG' in leaves:
            m = os.stat('COMMIT_EDITMSG', dir_fd=g, follow_symlinks=False)
            require(stat.S_ISREG(m.st_mode) and m.st_uid == os.getuid() and not m.st_mode & 0o022
                    and m.st_nlink == 1 and m.st_size <= 65536, 'inert_commit_message_unsafe')
        try:
            refs = os.open('refs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=g)
        except FileNotFoundError:
            pass
        else:
            try:
                m = os.fstat(refs)
                require(m.st_uid == os.getuid() and not m.st_mode & 0o022 and not names(refs, 1),
                        'private_refs_unsupported')
            finally:
                os.close(refs)
        controls = {'.control/gitfile': read(w, '.git', 8192),
                    '.control/gitdir': read(g, 'gitdir', 8192),
                    '.control/commondir': read(g, 'commondir', 8192)}
        require(controls['.control/gitfile'] == ('gitdir: ' + str(git_dir) + '\n').encode()
                and controls['.control/gitdir'] == (str(workspace / '.git') + '\n').encode()
                and controls['.control/commondir'] == b'../..\n', 'redirection_or_selection_mismatch')
        images = dict(controls)
        def optional(fd, name, key, cap):
            try:
                images[key] = read(fd, name, cap)
            except FileNotFoundError:
                pass
        images['.git/config'] = read(c, 'config', 8192)
        images['.git/HEAD'] = read(g, 'HEAD', 256)
        optional(g, 'index', '.git/index', 8 * 1024 * 1024)
        optional(c, 'packed-refs', '.git/packed-refs', 65536)
        def tree(fd, name, prefix, depth=0):
            require(depth <= 10, 'metadata_depth')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                before = stamp(os.fstat(child))
                leaves = names(child)
                for leaf in leaves:
                    require(not leaf.endswith('.lock'), 'metadata_busy')
                    m = os.stat(leaf, dir_fd=child, follow_symlinks=False)
                    require(m.st_uid == os.getuid() and not m.st_mode & 0o022, 'unsafe_file')
                    if stat.S_ISDIR(m.st_mode):
                        tree(child, leaf, prefix + '/' + leaf, depth + 1)
                    else:
                        images[prefix + '/' + leaf] = read(child, leaf)
                    require(len(images) <= 512 and sum(map(len, images.values())) <= MAX_BYTES, 'metadata_bound')
                require(before == stamp(os.fstat(child)), 'input_changed')
            finally:
                os.close(child)
        tree(c, 'refs', '.git/refs')
        # objects/info is not an authority source and is never copied. The
        # native parser separately rejects alternates and unsupported envelopes.
        objects = os.open('objects', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=c)
        try:
            for leaf in names(objects):
                require(leaf == 'info' or leaf == 'pack' or re.fullmatch(r'[0-9a-f]{2}', leaf), 'object_directory')
                if leaf != 'info':
                    tree(objects, leaf, '.git/objects/' + leaf)
        finally:
            os.close(objects)
        try:
            info = os.open('info', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=c)
        except FileNotFoundError:
            pass
        else:
            try:
                optional(info, 'exclude', '.git/info/exclude', 65536)
            finally:
                os.close(info)
        require(sum(map(len, images.values())) <= MAX_BYTES, 'metadata_bound')
        raw = b''.join(k.encode() + b'\0' + hashlib.sha256(v).hexdigest().encode() + b'\n' for k, v in sorted(images.items()))
        return {'format': FORMAT, 'workspace': wr, 'gitDir': gr, 'commonDir': cr,
                'inputsSha256': hashlib.sha256(raw).hexdigest()}
    finally:
        for fd, _ in opened:
            os.close(fd)


def load(path, workspace=None):
    fd, _ = directory(Path(path).parent)
    try:
        value = strict(read(fd, Path(path).name, 65536))
    finally:
        os.close(fd)
    return verify(value, workspace)


def verify(value, workspace=None):
    require(isinstance(value, dict) and set(value) == {'format', 'workspace', 'gitDir', 'commonDir', 'inputsSha256'}
            and value['format'] == FORMAT, 'binding_schema')
    require(workspace is None or str(workspace) == value['workspace']['path'], 'workspace_mismatch')
    observed = inventory(*(value[k]['path'] for k in ('workspace', 'gitDir', 'commonDir')))
    require(value == observed, 'selected_inputs_changed')
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'git-dir', 'common-dir'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--apply', action='store_true')
    args = p.parse_args(argv)
    binding = inventory(args.workspace, args.git_dir, args.common_dir)
    if args.apply:
        require(args.output is not None and args.output.is_absolute(), 'explicit_output_required')
        for root in (args.workspace, args.common_dir):
            require(not args.output.is_relative_to(root), 'output_overlaps_source')
        require(binding == inventory(args.workspace, args.git_dir, args.common_dir), 'input_changed')
        parent, _ = directory(args.output.parent)
        try:
            require(stat.S_IMODE(os.fstat(parent).st_mode) == 0o700, 'private_output_parent_required')
            descriptor = os.open(args.output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=parent)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write((json.dumps(binding, sort_keys=True) + '\n').encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)
    print(json.dumps({'status': 'selected-not-running' if args.apply else 'preview',
                      'executed': False, 'protection': 'not-observed', 'binding': binding}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
