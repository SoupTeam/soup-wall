# SPDX-License-Identifier: Apache-2.0
"""Bounded prepared-run syscall projection, not a runtime security decision.

Keep every exec/write/writev/process record, exact synthetic target opens and
all metadata which can affect the existing private-log descriptor witness.
Only proven unrelated openat/close records are omitted. Unknown metadata is
retained unchanged for the existing strict validators, never assumed absent.
"""
import ast
import hashlib
import os
from pathlib import Path
import re
import threading
import time

LIMIT = 32 * 1024 * 1024
TARGETS = frozenset(('/workspace/notes.txt', '/workspace/credentials.txt'))
LOGS = ('/host.private.log', '/daemon.private.log')


class Invalid(ValueError):
    pass


class Projection:
    def __init__(self):
        self.handles, self.pending = set(), {}
        self.opaque = set()
        self.opaque_pending = set()
        self.pending_bytes = 0
        self.omitted = {'openat': 0, 'close': 0}

    def decision(self, pid, name, rest, complete):
        success = re.search(rb'\)\s*=\s*(\d+)\s*$', rest) if complete else None
        failed = complete and re.search(rb'\)\s*=\s*-1 [A-Z]', rest)
        if name == b'close':
            match = re.match(rb'close\((\d+)(?:\)|\s)', rest)
            if match is None:
                raise Invalid('private_trace_metadata_unknown')
            fd = int(match[1])
            keep = (pid, fd) in self.handles
            if success and int(success[1]) == 0:
                self.handles.discard((pid, fd))
            return keep, False, False, fd
        match = re.match(rb'openat\([^,]+,\s*("(?:[^"\\]|\\.)*")\s*,', rest)
        if match is None:
            if failed:
                return False, False, False, None
            raise Invalid('private_trace_metadata_unknown')
        try:
            # Match the existing private-log observer's strace string semantics,
            # including literal UTF-8 and byte escapes in unrelated filenames.
            path = ast.literal_eval(match[1].decode('utf-8'))
        except (ValueError, SyntaxError, UnicodeError):
            raise Invalid('private_trace_metadata_unknown') from None
        target, log = path in TARGETS, path.endswith(LOGS)
        # An unrelated successful open can replace an existing log descriptor
        # after an implicit close. Retain it so the original verifier clears
        # its binding. Conservatively keep stale handles until explicit close.
        fd = int(success[1]) if success else None
        keep = target or log or ((pid, fd) in self.handles if complete else
                                any(owner == pid for owner, _ in self.handles))
        if log and fd is not None:
            self.handles.add((pid, fd))
            if len(self.handles) > 4096:
                raise Invalid('private_trace_handle_limit')
        return keep, target, log, fd

    def line(self, row):
        identity = re.match(rb'^\s*(\d+)\s+', row)
        if identity and int(identity[1]) in self.opaque:
            pid = int(identity[1])
            if re.match(rb'^\s*\d+\s+<\.\.\. (?:openat|close) resumed>', row):
                self.opaque_pending.discard(pid)
            if re.match(rb'^\s*\d+\s+(?:openat|close)\(', row) and row.rstrip().endswith(b'<unfinished ...>'):
                self.opaque_pending.add(pid)
            return row
        start = re.match(rb'^\s*(\d+)\s+(openat|close)\(', row)
        resumed = re.match(rb'^\s*(\d+)\s+<\.\.\. (openat|close) resumed>(.*)', row)
        if resumed:
            pid, name = int(resumed[1]), resumed[2]
            saved = self.pending.pop(pid, None)
            if saved is None or saved[0] != name:
                raise Invalid('private_trace_metadata_orphan')
            _, keep, target, log, fd, header = saved
            emitted = keep
            self.pending_bytes -= len(header)
            result = re.search(rb'\)\s*=\s*(\d+)\s*$', resumed[3])
            if name == b'openat' and not keep and result and (pid, int(result[1])) in self.handles:
                keep = True
            if keep and result:
                if name == b'openat' and log:
                    self.handles.add((pid, int(result[1])))
                    if len(self.handles) > 4096:
                        raise Invalid('private_trace_handle_limit')
                elif name == b'close' and int(result[1]) == 0:
                    self.handles.discard((pid, fd))
            if not keep:
                self.omitted[name.decode()] += 1
            return (row if emitted else header + row) if keep else b''
        if start is None:
            return row
        pid, name = int(start[1]), start[2]
        if pid in self.pending:
            raise Invalid('private_trace_metadata_overlap')
        rest = row[start.start(2):].rstrip()
        unfinished = rest.endswith(b'<unfinished ...>')
        try:
            keep, target, log, fd = self.decision(pid, name, rest, not unfinished)
        except Invalid as error:
            if str(error) != 'private_trace_metadata_unknown':
                raise
            if unfinished:
                # A split unclassified record may later alter a log binding.
                # Keep this PID's remaining metadata in full rather than guess
                # its FD state. Complete unclassified records cannot establish
                # a binding which the existing quoted-path parser understands.
                self.opaque.add(pid)
                self.opaque_pending.add(pid)
                if len(self.opaque) > 4096:
                    raise Invalid('private_trace_scope_limit')
            return row
        if unfinished:
            if len(self.pending) >= 4096:
                raise Invalid('private_trace_metadata_overlap')
            if name == b'openat' and not target and not log and keep:
                # Only the return FD can show whether this unrelated path
                # replaced a log handle. No same-TID syscall can interleave
                # before its resume, so defer these two records together.
                keep = False
            self.pending_bytes += len(row)
            if self.pending_bytes > LIMIT:
                raise Invalid('private_trace_pending_limit')
            self.pending[pid] = (name, keep, target, log, fd, row)
        elif not keep:
            self.omitted[name.decode()] += 1
        return row if keep else b''

    def target_pending(self):
        return bool(self.opaque_pending) or any(row[2] for row in self.pending.values())

    def remainder(self):
        # A never-resumed record is not proven irrelevant to completeness.
        # Retain its original prefix at EOF so existing strict final log/wire
        # validators still reject an incomplete supervisor/collector witness.
        return b''.join(row[5] for row in self.pending.values() if not row[1])


class Capture:
    """Drain strace through a private FIFO; retained witness remains <=32 MiB.

    sync() drains the currently queued FIFO before a live zero observation.
    A partial input row, backlogged stream or sticky error cannot prove zero.
    No input tail/rotation is substituted for complete required records.
    """
    def __init__(self, path):
        self.path = Path(path)
        self.fifo = self.path.with_suffix('.fifo')
        os.mkfifo(self.fifo, 0o600)
        self.reader = self.writer = None
        try:
            self.reader = os.open(self.fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.writer = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except Exception:
            if self.reader is not None:
                os.close(self.reader)
            self.fifo.unlink()
            raise
        self.projection = Projection()
        self.lock, self.stop = threading.RLock(), threading.Event()
        self.buffer = bytearray()
        self.error, self.closed = None, False
        self.input_bytes = self.output_bytes = 0
        self.digest = hashlib.sha256()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _feed(self, chunk):
        self.input_bytes += len(chunk)
        self.digest.update(chunk)
        if self.error:
            return  # Drain on error so strace/owned cleanup cannot deadlock.
        self.buffer.extend(chunk)
        rows = self.buffer.split(b'\n')
        self.buffer = bytearray(rows.pop())
        if len(self.buffer) > LIMIT:
            raise Invalid('private_trace_line_limit')
        for piece in rows:
            row = bytes(piece) + b'\n'
            if len(row) > LIMIT:
                raise Invalid('private_trace_line_limit')
            self._write(self.projection.line(row))

    def _write(self, kept):
        if self.output_bytes + len(kept) > LIMIT:
            raise Invalid('private_trace_limit')
        view = memoryview(kept)
        while view:
            written = os.write(self.writer, view)
            if written <= 0:
                raise Invalid('private_trace_write_failed')
            view = view[written:]
        self.output_bytes += len(kept)

    def _drain(self, deadline):
        while time.monotonic() < deadline:
            try:
                chunk = os.read(self.reader, 65536)
            except BlockingIOError:
                return True
            if not chunk:
                return True
            try:
                self._feed(chunk)
            except Exception as error:
                self.error = str(error) if isinstance(error, Invalid) else 'private_trace_capture_failed'
                self.buffer.clear()
        return False

    def _run(self):
        try:
            while not self.stop.is_set():
                with self.lock:
                    self._drain(time.monotonic() + .01)
                self.stop.wait(.002)
        except Exception:
            self.error = self.error or 'private_trace_capture_failed'

    def sync(self):
        with self.lock:
            drained = self._drain(time.monotonic() + .1) if not self.closed else True
            if self.error:
                raise Invalid(self.error)
            return drained and not self.buffer and not self.projection.target_pending()

    def finish(self):
        if self.closed:
            if self.error:
                raise Invalid(self.error)
            return
        self.stop.set()
        self.thread.join(timeout=2)
        with self.lock:
            try:
                if self.thread.is_alive() or not self._drain(time.monotonic() + .1):
                    self.error = self.error or 'private_trace_capture_incomplete'
                if self.buffer or self.projection.target_pending():
                    self.error = self.error or 'private_trace_capture_incomplete'
                if not self.error:
                    try:
                        self._write(self.projection.remainder())
                    except Invalid as error:
                        self.error = str(error)
            finally:
                os.close(self.reader)
                os.close(self.writer)
                self.fifo.unlink()
                self.closed = True
        if self.error:
            raise Invalid(self.error)

    def summary(self):
        return {'format': 'prepared-effect-and-wire/1', 'input_bytes': self.input_bytes,
                'input_sha256': self.digest.hexdigest(), 'retained_bytes': self.output_bytes,
                'retained_limit': LIMIT, 'omitted_non_witness_metadata': dict(self.projection.omitted),
                'unclassified_metadata_processes': len(self.projection.opaque),
                'complete': self.closed and self.error is None, 'raw_stream_exported': False}
