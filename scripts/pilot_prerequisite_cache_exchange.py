#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private, bounded exchange of the two accepted prerequisite download bytes.

The selected cache is never a build or execution authority. The preparer must
still hash both archives against its own pins and perform its normal extraction,
build, binary verification and generation selection.
"""
from __future__ import annotations

import hashlib
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

import pilot_resumable_download as resume

FORMAT = "sw-pilot-prerequisite-download-exchange/1"
SELECTED = "import-current.json"
IMPORTED = "imported"
GIT = "git.verified.tar.xz"
NAMES = {"git": GIT, "bwrap": resume.VERIFIED}
MEMBERS = ("manifest.json", "git.tar.xz", "bwrap.tar.xz")
MAX_MANIFEST = 4096
MAX_OVERHEAD = 16384
BLOCK = 65536
AT_EMPTY_PATH = 0x1000


def _private_dir_fd(path):
    path = _directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    try:
        named = path.lstat()
        require((info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)
                and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "exchange_directory_unsafe")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _same_dir(path, fd, original):
    named = path.lstat()
    pinned = os.fstat(fd)
    require((named.st_dev, named.st_ino) == (pinned.st_dev, pinned.st_ino)
            == (original.st_dev, original.st_ino)
            and pinned.st_uid == os.getuid()
            and stat.S_IMODE(pinned.st_mode) == 0o700,
            "exchange_directory_changed")


def _link_inode(source_fd, directory_fd, name):
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    linkat.restype = ctypes.c_int
    encoded = os.fsencode(name)
    if linkat(source_fd, b"", directory_fd, encoded, AT_EMPTY_PATH) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise Refusal("exchange_destination_exists")
    if error not in (errno.EPERM, errno.ENOENT, errno.EACCES):
        raise OSError(error, "exchange_publication_failed")
    # Linux's documented unprivileged fallback still names the pinned descriptor,
    # never a replaceable staging pathname.
    proc_fd = os.open("/proc/self/fd", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        statfs = ctypes.create_string_buffer(256)
        require(libc.fstatfs(proc_fd, statfs) == 0
                and ctypes.cast(statfs, ctypes.POINTER(ctypes.c_long))[0] == 0x9fa0,
                "exchange_proc_source_unsafe")
        before = os.fstat(source_fd)
        via_proc = os.stat(str(source_fd), dir_fd=proc_fd)
        require((before.st_dev, before.st_ino, before.st_nlink) ==
                (via_proc.st_dev, via_proc.st_ino, via_proc.st_nlink)
                and before.st_nlink == 0 and stat.S_ISREG(before.st_mode),
                "exchange_publication_source_changed")
        if linkat(proc_fd, os.fsencode(str(source_fd)), directory_fd, encoded, 0x400) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise Refusal("exchange_destination_exists")
            raise OSError(error, "exchange_publication_failed")
    finally:
        os.close(proc_fd)


def _publish_private(directory, name, writer, claim):
    """Write a new regular inode, then publish that exact inode under one leaf."""
    dir_fd, original = _private_dir_fd(directory)
    try:
        try:
            file_fd = os.open(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC,
                              0o600, dir_fd=dir_fd)
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL):
                raise Refusal("exchange_filesystem_unsupported") from None
            raise Refusal("exchange_publication_unavailable") from None
        try:
            writer(file_fd)
            os.fsync(file_fd)
            inode = os.fstat(file_fd)
            require(stat.S_ISREG(inode.st_mode) and inode.st_uid == os.getuid()
                    and stat.S_IMODE(inode.st_mode) == 0o600 and inode.st_nlink == 0
                    and inode.st_dev == original.st_dev, "exchange_publication_unsafe")
            claim.verify()
            _same_dir(directory, dir_fd, original)
            _link_inode(file_fd, dir_fd, name)
            os.fsync(dir_fd)
            _same_dir(directory, dir_fd, original)
            published = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            require((published.st_dev, published.st_ino, published.st_size, published.st_mode)
                    == (inode.st_dev, inode.st_ino, inode.st_size, inode.st_mode)
                    and published.st_nlink == 1, "exchange_publication_changed")
            return inode.st_size
        finally:
            os.close(file_fd)
    finally:
        os.close(dir_fd)


class Refusal(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def require(value, reason):
    if not value:
        raise Refusal(reason)


def _pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "exchange_manifest_invalid")
        value[key] = item
    return value


def _json(raw):
    require(len(raw) <= MAX_MANIFEST, "exchange_manifest_limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: require(False, "exchange_manifest_invalid"))
    except (UnicodeError, ValueError, RecursionError):
        raise Refusal("exchange_manifest_invalid") from None
    require(type(value) is dict, "exchange_manifest_invalid")
    return value


def _raw(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    require(len(raw) <= MAX_MANIFEST, "exchange_manifest_limit")
    return raw


def _regular(fd, *, limit, modes, public_source=False):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode)
            and (public_source or (info.st_uid == os.getuid()
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes))
            and 0 < info.st_size <= limit, "exchange_file_unsafe")
    return info


def _open(path, *, limit, modes=(0o600,), public_source=False):
    path = Path(path)
    require(path.is_absolute(), "exchange_absolute_path_required")
    try:
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except (OSError, ValueError):
        raise Refusal("exchange_file_unavailable") from None
    try:
        after = _regular(fd, limit=limit, modes=modes, public_source=public_source)
        require((before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
                 before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                 after.st_size, after.st_mtime_ns), "exchange_file_changed")
        return fd, after
    except BaseException:
        os.close(fd)
        raise


def _hash(fd, size):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(fd, min(BLOCK, remaining))
        require(block, "exchange_file_changed")
        digest.update(block)
        remaining -= len(block)
    require(os.fstat(fd).st_size == size, "exchange_file_changed")
    return digest.hexdigest()


def _directory(path, *, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "exchange_directory_unsafe")
    return path


def _cache(root, *, create=False):
    _directory(root)
    return _directory(Path(root) / resume.DIRECTORY, create=create)


def _manifest(pins, sizes):
    return {"format": FORMAT, "archives": {
        kind: {"member": kind + ".tar.xz", "version": pins[kind][0],
               "url": pins[kind][2], "sha256": pins[kind][3], "bytes": sizes[kind]}
        for kind in NAMES}}


def _validate_manifest(value, pins):
    require(set(value) == {"format", "archives"} and value["format"] == FORMAT
            and type(value["archives"]) is dict
            and set(value["archives"]) == set(NAMES), "exchange_manifest_invalid")
    sizes = {}
    for kind in NAMES:
        item = value["archives"][kind]
        require(type(item) is dict and set(item) == {"member", "version", "url", "sha256", "bytes"}
                and type(item["bytes"]) is int and 0 < item["bytes"] <= pins[kind][4],
                "exchange_manifest_invalid")
        sizes[kind] = item["bytes"]
    require(value == _manifest(pins, sizes), "exchange_pin_changed")
    return sizes


def _imported_sources(root, pins):
    cache = _cache(root)
    fd, info = _open(cache / SELECTED, limit=MAX_MANIFEST)
    try:
        marker = _json(os.read(fd, info.st_size))
        require(set(marker) == {"format", "manifest_sha256"}
                and marker["format"] == FORMAT and type(marker["manifest_sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", marker["manifest_sha256"]),
                "exchange_selection_invalid")
    finally:
        os.close(fd)
    imported = _directory(cache / IMPORTED)
    paths = {kind: imported / NAMES[kind] for kind in NAMES}
    sizes = {}
    for kind, path in paths.items():
        fd, info = _open(path, limit=pins[kind][4])
        try:
            require(_hash(fd, info.st_size) == pins[kind][3], "exchange_member_digest_mismatch")
            sizes[kind] = info.st_size
        finally:
            os.close(fd)
    require(hashlib.sha256(_raw(_manifest(pins, sizes))).hexdigest() == marker["manifest_sha256"],
            "exchange_selection_changed")
    return paths


def _selected_sources(root, pins):
    """Read the existing complete cache; allow accepted older selected roots."""
    _directory(root)
    cache = Path(root) / resume.DIRECTORY
    if cache.exists() or cache.is_symlink():
        _directory(cache)
        if (cache / SELECTED).exists() or (cache / SELECTED).is_symlink():
            return _imported_sources(root, pins)
    paths = {}
    marker = Path(root) / "current.json"
    generation = None
    for kind, name in NAMES.items():
        direct = cache / name
        if direct.exists() or direct.is_symlink():
            paths[kind] = direct
            continue
        if generation is None:
            fd, info = _open(marker, limit=MAX_MANIFEST)
            try:
                value = _json(os.read(fd, info.st_size))
            finally:
                os.close(fd)
            require(value.get("format") == "sw-native-pilot-current/1"
                    and type(value.get("generation")) is str
                    and re.fullmatch(r"[0-9a-f]{32}", value["generation"]),
                    "exchange_source_missing")
            generation = _directory(Path(root) / "generations") / value["generation"]
            generation_info = generation.lstat()
            require(stat.S_ISDIR(generation_info.st_mode)
                    and generation_info.st_uid == os.getuid()
                    and stat.S_IMODE(generation_info.st_mode) == 0o500,
                    "exchange_source_unsafe")
        paths[kind] = generation / (kind + ".tar.xz")
    return paths


def preview(root, pins):
    """Pure read: no root, lock, cache or file is created."""
    available = {}
    try:
        paths = _selected_sources(root, pins)
    except (OSError, Refusal):
        paths = {}
    for kind in NAMES:
        try:
            fd, info = _open(paths[kind], limit=pins[kind][4], modes=(0o600, 0o400))
            try:
                available[kind] = (info.st_size <= pins[kind][4]
                                   and _hash(fd, info.st_size) == pins[kind][3])
            finally:
                os.close(fd)
        except (KeyError, OSError, Refusal):
            available[kind] = False
    return {"status": "preview", "executed": False, "available": available,
            "complete": all(available.values()),
            "inventory": {kind: {"version": pins[kind][0], "sha256": pins[kind][3]}
                          for kind in NAMES}}


def _bundle_limit(pins):
    return sum(pins[kind][4] for kind in NAMES) + MAX_OVERHEAD


def export(root, bundle, pins, claim):
    claim.verify()
    sources = _selected_sources(root, pins)
    opened = {}
    try:
        for kind in NAMES:
            fd, info = _open(sources[kind], limit=pins[kind][4], modes=(0o600, 0o400))
            opened[kind] = fd, info
            require(_hash(fd, info.st_size) == pins[kind][3], "exchange_source_digest_mismatch")
        sizes = {kind: opened[kind][1].st_size for kind in NAMES}
        manifest = _raw(_manifest(pins, sizes))
        bundle = Path(bundle)
        require(bundle.is_absolute() and not bundle.is_relative_to(root), "exchange_destination_unsafe")
        parent = _directory(bundle.parent)
        require(not bundle.exists() and not bundle.is_symlink(), "exchange_destination_exists")
        def write_bundle(fd):
            with os.fdopen(os.dup(fd), "wb") as stream, tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name, source in (("manifest.json", io.BytesIO(manifest)),
                                     ("git.tar.xz", os.fdopen(os.dup(opened["git"][0]), "rb")),
                                     ("bwrap.tar.xz", os.fdopen(os.dup(opened["bwrap"][0]), "rb"))):
                    size = len(manifest) if name == "manifest.json" else sizes[name.split(".")[0]]
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode, entry.mtime = size, 0o600, 0
                    if name != "manifest.json":
                        source.seek(0)
                    try:
                        tar.addfile(entry, source)
                    finally:
                        source.close()
                stream.flush()
            for kind in NAMES:
                require(_hash(opened[kind][0], sizes[kind]) == pins[kind][3],
                        "exchange_source_changed")
        total = _publish_private(parent, bundle.name, write_bundle, claim)
        return {"status": "exported", "bundle": str(bundle), "bytes": total,
                "archives": sizes, "active_protection": False}
    finally:
        for fd, _ in opened.values():
            os.close(fd)


def _inspect_bundle(fd, size, pins, *, target=None):
    """Only an uncompressed USTAR with three contiguous regular members."""
    os.lseek(fd, 0, os.SEEK_SET)
    sizes = {}
    manifest = None
    with os.fdopen(os.dup(fd), "rb") as stream, tarfile.open(fileobj=stream, mode="r:") as tar:
        members = []
        for member in tar:
            require(len(members) < len(MEMBERS), "exchange_inventory_invalid")
            members.append(member)
        require(len(members) == len(MEMBERS), "exchange_inventory_invalid")
        expected_offset = 0
        for member, expected in zip(members, MEMBERS):
            require(member.name == expected and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and not member.pax_headers and member.offset == expected_offset
                    and member.offset_data == member.offset + 512
                    and member.linkname == "", "exchange_inventory_invalid")
            bound = MAX_MANIFEST if expected == "manifest.json" else pins[expected.split(".")[0]][4]
            require(0 < member.size <= bound, "exchange_member_limit")
            expected_offset = member.offset_data + ((member.size + 511) // 512) * 512
        require(size - expected_offset <= 10240 and size >= expected_offset + 1024,
                "exchange_trailing_data")
        os.lseek(fd, expected_offset, os.SEEK_SET)
        tail = os.read(fd, size - expected_offset)
        require(not any(tail), "exchange_trailing_data")
        for member in members:
            source = tar.extractfile(member)
            require(source is not None, "exchange_inventory_invalid")
            if member.name == "manifest.json":
                manifest = source.read(MAX_MANIFEST + 1)
                require(len(manifest) == member.size, "exchange_manifest_invalid")
                sizes = _validate_manifest(_json(manifest), pins)
            else:
                kind = member.name.split(".")[0]
                require(member.size == sizes[kind], "exchange_member_size_changed")
                digest = hashlib.sha256()
                remaining = member.size
                destination = None
                if target is not None:
                    destination = (Path(target) / NAMES[kind]).open("xb")
                    os.fchmod(destination.fileno(), 0o600)
                try:
                    while remaining:
                        block = source.read(min(BLOCK, remaining))
                        require(block, "exchange_member_truncated")
                        digest.update(block)
                        if destination is not None:
                            destination.write(block)
                        remaining -= len(block)
                    require(digest.hexdigest() == pins[kind][3], "exchange_member_digest_mismatch")
                    if destination is not None:
                        destination.flush()
                        os.fsync(destination.fileno())
                finally:
                    if destination is not None:
                        destination.close()
    return manifest, sizes


def import_bundle(root, bundle, pins, claim):
    claim.verify()
    require(not (Path(root) / "current.json").exists()
            and not (Path(root) / "current.json").is_symlink(),
            "exchange_destination_not_fresh")
    cache = _cache(root, create=not (Path(root) / resume.DIRECTORY).exists())
    require(not (cache / SELECTED).exists() and not (cache / SELECTED).is_symlink()
            and not (cache / resume.VERIFIED).exists() and not (cache / GIT).exists(),
            "exchange_destination_not_fresh")
    bundle = Path(bundle)
    _directory(bundle.parent)
    fd, info = _open(bundle, limit=_bundle_limit(pins))
    try:
        original_digest = _hash(fd, info.st_size)
        try:
            manifest, sizes = _inspect_bundle(fd, info.st_size, pins)
        except (tarfile.TarError, EOFError, UnicodeError):
            raise Refusal("exchange_bundle_invalid") from None
        claim.verify()
        stage_path = cache / IMPORTED
        if stage_path.exists() or stage_path.is_symlink():
            # An owner may have died before selection. Reclaim only the two
            # identity-checked files of this format; never touch a sibling.
            stage = _directory(stage_path)
            entries = list(stage.iterdir())
            require(len(entries) <= len(NAMES) and
                    all(entry.name in NAMES.values() for entry in entries),
                    "exchange_incomplete_stage_unsafe")
            for entry in entries:
                try:
                    before = entry.lstat()
                    entry_fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    try:
                        after = os.fstat(entry_fd)
                        require(stat.S_ISREG(after.st_mode) and after.st_uid == os.getuid()
                                and after.st_nlink == 1 and stat.S_IMODE(after.st_mode) == 0o600
                                and after.st_size <= pins[entry.name.split(".")[0]][4]
                                and (before.st_dev, before.st_ino, before.st_mode, before.st_size)
                                == (after.st_dev, after.st_ino, after.st_mode, after.st_size),
                                "exchange_incomplete_stage_unsafe")
                    finally:
                        os.close(entry_fd)
                except OSError:
                    raise Refusal("exchange_incomplete_stage_unsafe") from None
                entry.unlink()
            stage.rmdir()
        stage = _directory(stage_path, create=True)
        try:
            _inspect_bundle(fd, info.st_size, pins, target=stage)
        except (tarfile.TarError, EOFError, UnicodeError):
            raise Refusal("exchange_bundle_invalid") from None
        require(_hash(fd, info.st_size) == original_digest, "exchange_file_changed")
        marker = _raw({"format": FORMAT, "manifest_sha256": hashlib.sha256(manifest).hexdigest()})
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        # The stage is rechecked before selection; consumers independently hash
        # every selected member again, including after interrupted publication.
        for kind, name in NAMES.items():
            member_fd, member_info = _open(stage / name, limit=pins[kind][4])
            try:
                require(_hash(member_fd, member_info.st_size) == pins[kind][3],
                        "exchange_member_digest_mismatch")
            finally:
                os.close(member_fd)
        def write_marker(marker_fd):
            with os.fdopen(os.dup(marker_fd), "wb") as output:
                output.write(marker)
                output.flush()
        _publish_private(cache, SELECTED, write_marker, claim)
        _imported_sources(root, pins)
        return {"status": "imported-not-prepared", "archives": sizes,
                "active_protection": False}
    finally:
        os.close(fd)


def consume(root, destination, kind, pins, claim):
    claim.verify()
    paths = _imported_sources(root, pins)
    files = {}
    try:
        for item in NAMES:
            fd, info = _open(paths[item], limit=pins[item][4])
            files[item] = fd, info
            require(_hash(fd, info.st_size) == pins[item][3], "exchange_member_digest_mismatch")
        fd, info = files[kind]
        destination = Path(destination)
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            with os.fdopen(target, "wb") as output:
                remaining = info.st_size
                while remaining:
                    block = os.read(fd, min(BLOCK, remaining))
                    require(block, "exchange_member_changed")
                    output.write(block)
                    remaining -= len(block)
                output.flush()
                os.fsync(output.fileno())
            require(_hash(fd, info.st_size) == pins[kind][3], "exchange_member_changed")
            claim.verify()
            return destination
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    finally:
        for fd, _ in files.values():
            os.close(fd)


def seed(root, archives, pins, claim):
    """Create immutable direct entries from fully verified preparation inputs."""
    claim.verify()
    cache = _cache(root, create=not (Path(root) / resume.DIRECTORY).exists())
    for kind, name in NAMES.items():
        source_fd, info = _open(archives[kind], limit=pins[kind][4], public_source=True)
        try:
            require(_hash(source_fd, info.st_size) == pins[kind][3], "exchange_source_digest_mismatch")
            dest = cache / name
            if dest.exists() or dest.is_symlink():
                existing, current = _open(dest, limit=pins[kind][4])
                try:
                    require(current.st_size == info.st_size and _hash(existing, current.st_size) == pins[kind][3],
                            "exchange_cache_conflict")
                finally:
                    os.close(existing)
                continue
            def write_source(target):
                os.lseek(source_fd, 0, os.SEEK_SET)
                with os.fdopen(os.dup(target), "wb") as output:
                    remaining = info.st_size
                    while remaining:
                        block = os.read(source_fd, min(BLOCK, remaining))
                        require(block, "exchange_source_changed")
                        output.write(block)
                        remaining -= len(block)
                    output.flush()
                require(_hash(source_fd, info.st_size) == pins[kind][3], "exchange_source_changed")
            _publish_private(cache, name, write_source, claim)
        finally:
            os.close(source_fd)
