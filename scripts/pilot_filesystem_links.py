# SPDX-License-Identifier: Apache-2.0
"""Explicit bounded relative file links; the strict multi-root default is unchanged."""
import os
from pathlib import Path, PurePosixPath
import stat
import pilot_filesystem_roots as roots

FORMAT = 'sw-pilot-filesystem-root-file-links/1'
PROFILE = 'sw-mcp/filesystem-multi-root-file-links-readonly/1'
MAX_ENTRIES = 512
MAX_FILES = 256
MAX_LINKS = 128
MAX_CHAIN = 8


def require(ok, code):
    if not ok:
        raise ValueError('filesystem_links_' + code)


def identity(m):
    return dict(device=m.st_dev, inode=m.st_ino, uid=m.st_uid)


def normalized(parent, target):
    require(target and not target.startswith('/') and len(os.fsencode(target)) <= 4096, 'relative_file_link_required')
    result = list(parent.parts)
    for part in target.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            require(result, 'root_escape')
            result.pop()
        else:
            result.append(part)
    require(result, 'directory_link_unsupported')
    return PurePosixPath(*result)


def scan(fd, nodes, prefix=PurePosixPath(), depth=0, counts=None, device=None):
    counts = [0, 0, 0] if counts is None else counts
    require(depth <= 32 and counts[0] < 128, 'tree_bound')
    counts[0] += 1
    before = os.fstat(fd)
    device = before.st_dev if device is None else device
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(nodes) < MAX_ENTRIES, 'tree_bound')
            name = entry.name
            require(not any(ord(c) < 32 for c in name), 'unsupported_name')
            m = os.stat(name, dir_fd=fd, follow_symlinks=False)
            path = prefix / name
            require(m.st_uid == os.getuid() and m.st_dev == device, 'unsafe_entry')
            if stat.S_ISLNK(m.st_mode):
                counts[2] += 1
                require(counts[2] <= MAX_LINKS and m.st_nlink == 1, 'link_bound')
                target = os.readlink(name, dir_fd=fd)
                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require((m.st_ino, m.st_ctime_ns) == (after.st_ino, after.st_ctime_ns), 'entry_changed')
                normalized(path.parent, target)
                nodes[path] = ('link', identity(m), target)
                continue
            require(not m.st_mode & 0o022 and (stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode) and m.st_nlink == 1), 'unsafe_entry')
            child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC |
                            (os.O_DIRECTORY if stat.S_ISDIR(m.st_mode) else 0), dir_fd=fd)
            try:
                opened = os.fstat(child)
                require(identity(m) == identity(opened), 'entry_changed')
                if stat.S_ISDIR(m.st_mode):
                    nodes[path] = ('directory', identity(m), None)
                    scan(child, nodes, path, depth + 1, counts, device)
                else:
                    counts[1] += 1
                    require(counts[1] <= MAX_FILES, 'file_bound')
                    nodes[path] = ('file', identity(m), None)
            finally:
                os.close(child)
    after = os.fstat(fd)
    require((before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_ino, after.st_mtime_ns, after.st_ctime_ns), 'tree_changed')


def selections(root_id, nodes):
    result = []
    for path in sorted(nodes, key=str):
        if nodes[path][0] != 'link':
            continue
        current, chain = path, []
        while True:
            require(current in nodes, 'missing_link_target')
            # No directory aliases, including aliases in the middle of a path.
            for parent in current.parents:
                if str(parent) != '.':
                    require(parent in nodes and nodes[parent][0] == 'directory', 'directory_link_unsupported')
            kind, obj, target = nodes[current]
            if kind != 'link':
                require(kind == 'file', 'directory_link_unsupported')
                break
            require(len(chain) < MAX_CHAIN and str(current) not in [c['path'] for c in chain], 'cycle_or_chain_bound')
            chain.append(dict(path=str(current), target=target, identity=obj))
            current = normalized(current.parent, target)
        result.append(dict(root=root_id, path=str(path), chain=chain, final_path=str(current), final_identity=obj))
    return result


def inventory(pairs):
    require(isinstance(pairs, list) and 2 <= len(pairs) <= 4, 'count')
    selected, links, counts = [], [], [0, 0, 0]
    import re
    for root_id, path in sorted(pairs):
        require(isinstance(root_id, str) and re.fullmatch('[a-z][a-z0-9_-]{0,31}', root_id), 'id')
        fd, value = roots.directory(path)
        try:
            nodes = {}
            scan(fd, nodes, counts=counts)
            links.extend(selections(root_id, nodes))
        finally:
            os.close(fd)
        value.update(id=root_id, scope='read-only')
        for other in selected:
            a, b = Path(other['path']), Path(value['path'])
            require(root_id != other['id'] and value['identity'] != other['identity'] and
                    not a.is_relative_to(b) and not b.is_relative_to(a), 'duplicate_or_overlap')
        selected.append(value)
    require(len(links) <= MAX_LINKS, 'link_bound')
    return dict(format=FORMAT, roots=selected, links=links)


def verify(value, workspace=None):
    require(set(value) == {'format', 'roots', 'links'} and value['format'] == FORMAT, 'binding_schema')
    require(isinstance(value['roots'], list) and all(isinstance(r, dict) and
            set(r) == {'id', 'path', 'scope', 'identity'} for r in value['roots']), 'binding_schema')
    def scalar_types(item):
        if isinstance(item, dict):
            return all(isinstance(k, str) and scalar_types(v) for k,v in item.items())
        if isinstance(item, list):
            return all(scalar_types(v) for v in item)
        return isinstance(item, str) or type(item) is int and item >= 0
    require(scalar_types(value), 'binding_schema')
    observed = inventory([(r['id'], r['path']) for r in value['roots']])
    require(value == observed, 'selected_object_changed')
    require(workspace is None or str(workspace) == value['roots'][0]['path'], 'workspace_mismatch')
    return value
