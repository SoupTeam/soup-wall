#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Process-lifetime coordination for one private pilot build output root.

The persistent, empty inode is only a rendezvous point. Neither its name nor
its contents confer authority: the caller must verify the selected generation
again after acquiring the descriptor lock.
"""
from __future__ import annotations

from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # The build entry points execute on Linux only.
    fcntl = None
import math
import os
from pathlib import Path
import stat
import time

NAME = ".pilot-input-preparation.lock"
MAX_WAIT_SECONDS = 2700


class Busy(Exception):
    def __init__(self, reason, waited_seconds):
        super().__init__(reason)
        self.reason = reason
        self.waited_seconds = waited_seconds


class Unsafe(Exception):
    pass


def bounded_wait(value):
    try:
        seconds = float(value)
    except (TypeError, ValueError) as error:
        raise Unsafe("wait_seconds_out_of_bounds") from error
    if not math.isfinite(seconds) or not 0 <= seconds <= MAX_WAIT_SECONDS:
        raise Unsafe("wait_seconds_out_of_bounds")
    return seconds


class Claim:
    def __init__(self, output, directory_fd, lock_fd, directory_identity, lock_identity,
                 waited_seconds, contended):
        self.output = output
        self.directory_fd = directory_fd
        self.lock_fd = lock_fd
        self.directory_identity = directory_identity
        self.lock_identity = lock_identity
        self.waited_seconds = round(waited_seconds, 3)
        self.contended = contended

    def verify(self):
        """Refuse publication if the root or the lock name changed under us."""
        directory = os.fstat(self.directory_fd)
        named_directory = self.output.lstat()
        if (not stat.S_ISDIR(named_directory.st_mode)
                or (directory.st_dev, directory.st_ino) != self.directory_identity
                or (named_directory.st_dev, named_directory.st_ino) != self.directory_identity
                or directory.st_uid != os.getuid()
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise Unsafe("preparation_root_changed")
        lock = os.fstat(self.lock_fd)
        try:
            named_lock = os.stat(NAME, dir_fd=self.directory_fd, follow_symlinks=False)
        except FileNotFoundError as error:
            raise Unsafe("preparation_lock_changed") from error
        if (not stat.S_ISREG(lock.st_mode) or lock.st_nlink != 1
                or lock.st_uid != os.getuid() or stat.S_IMODE(lock.st_mode) != 0o600
                or lock.st_size != 0
                or (lock.st_dev, lock.st_ino) != self.lock_identity
                or (named_lock.st_dev, named_lock.st_ino) != self.lock_identity):
            raise Unsafe("preparation_lock_changed")


@contextmanager
def hold(output: Path, *, wait_seconds=0):
    if fcntl is None:
        raise Unsafe("native_linux_preparation_lock_required")
    wait_seconds = bounded_wait(wait_seconds)
    output = Path(output)
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock_fd = None
    try:
        directory = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise Unsafe("private_preparation_root_required")
        try:
            lock_fd = os.open(NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                              os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        except OSError as error:
            raise Unsafe("unsafe_preparation_lock_record") from error
        lock = os.fstat(lock_fd)
        claim = Claim(output, directory_fd, lock_fd,
                      (directory.st_dev, directory.st_ino),
                      (lock.st_dev, lock.st_ino), 0, False)
        claim.verify()
        start = time.monotonic()
        deadline = start + wait_seconds
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                claim.contended = True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Busy("bounded_wait_expired" if wait_seconds else
                               "preparation_in_progress", round(time.monotonic() - start, 3))
                time.sleep(min(0.1, remaining))
                claim.verify()
        claim.waited_seconds = round(time.monotonic() - start, 3)
        claim.verify()
        yield claim
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)
