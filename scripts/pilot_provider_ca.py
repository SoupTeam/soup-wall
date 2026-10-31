#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run-pinned provider CA bytes for the installed Linux pilot host.

The source pathname is never passed as authority to the host. The caller sends
the sealed, anonymous descriptor only to the native launcher, which binds a
host-only trust path to these exact bytes. This module performs no network I/O.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import re
import ssl
import stat

MAX_CA_BYTES = 2 * 1024 * 1024
MAX_CERTIFICATES = 64
BLOCK = 65536
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?")
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK


class Refusal(ValueError):
    """Finite, path-free refusal returned by the outer pilot boundary."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source(path):
    """Read one canonical regular file through no-follow directory descriptors."""
    require(type(path) is str and path.startswith("/") and "\0" not in path,
            "provider_ca_input_invalid")
    source = Path(path)
    require(source.is_absolute() and ".." not in source.parts and str(source) == path,
            "provider_ca_input_invalid")
    directory = descriptor = None
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for part in source.parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=directory)
            os.close(directory)
            directory = following
        name = source.name
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        opened = os.fstat(descriptor)
        require(identity(before) == identity(opened) and stat.S_ISREG(opened.st_mode)
                and opened.st_uid in (0, os.getuid()) and opened.st_nlink == 1
                and not opened.st_mode & 0o022 and 0 < opened.st_size <= MAX_CA_BYTES,
                "provider_ca_input_invalid")
        remaining, chunks = opened.st_size, []
        while remaining:
            block = os.read(descriptor, min(BLOCK, remaining))
            require(block, "provider_ca_source_changed")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        selected = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(identity(opened) == identity(after) == identity(selected),
                "provider_ca_source_changed")
        return b"".join(chunks), identity(opened)
    except OSError:
        raise Refusal("provider_ca_input_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _validate(raw):
    """Accept only a bounded certificate-only PEM bundle loadable by OpenSSL."""
    require(0 < len(raw) <= MAX_CA_BYTES, "provider_ca_input_invalid")
    offset = count = 0
    for match in PEM.finditer(raw):
        require(re.fullmatch(rb"(?:\r?\n)*", raw[offset:match.start()]) is not None,
                "provider_ca_material_invalid")
        offset = match.end()
        count += 1
        require(count <= MAX_CERTIFICATES, "provider_ca_material_invalid")
    require(count > 0 and re.fullmatch(rb"(?:\r?\n)*", raw[offset:]) is not None,
            "provider_ca_material_invalid")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=raw.decode("ascii"))
    except (UnicodeError, ValueError, ssl.SSLError):
        raise Refusal("provider_ca_material_invalid") from None


class Snapshot:
    def __init__(self, descriptor, source, source_identity, sha256):
        self.fd = descriptor
        self.source = source
        self.source_identity = source_identity
        self.sha256 = sha256

    def verify_source(self):
        raw, selected = _source(self.source)
        require(selected == self.source_identity and hashlib.sha256(raw).hexdigest() == self.sha256,
                "provider_ca_source_changed")

    def close(self):
        if self.fd is not None:
            descriptor, self.fd = self.fd, None
            os.close(descriptor)


def pin(path):
    """Return a sealed anonymous snapshot, or None when no CA was selected."""
    if path is None:
        return None
    raw, selected = _source(path)
    _validate(raw)
    try:
        descriptor = os.memfd_create("sw-provider-ca", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except (AttributeError, OSError):
        raise Refusal("provider_ca_snapshot_unavailable") from None
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            require(written > 0, "provider_ca_snapshot_unavailable")
            remaining = remaining[written:]
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & SEALS == SEALS
                and os.fstat(descriptor).st_nlink == 0,
                "provider_ca_snapshot_unavailable")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return Snapshot(descriptor, path, selected, hashlib.sha256(raw).hexdigest())
    except (OSError, ValueError):
        os.close(descriptor)
        raise Refusal("provider_ca_snapshot_unavailable") from None
