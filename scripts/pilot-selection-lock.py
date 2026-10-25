#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cooperative lifetime lock for one prepared pilot selection."""
from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # Importable for Windows-only unit tests; execution is Linux-only.
    fcntl = None
import os
from pathlib import Path
import stat

CONTRACT = "sw-pilot-selection-lock/1"
NAME = ".pilot-selection.lock"


@contextmanager
def hold(output: Path, *, exclusive: bool):
    if fcntl is None:
        raise ValueError("native_linux_selection_lock_required")
    output = Path(output)
    info = output.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private_selection_root_required")
    fd = os.open(output / NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("owned_selection_lock_required")
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("selected_generation_in_use_or_transitioning") from None
        yield
    finally:
        os.close(fd)
