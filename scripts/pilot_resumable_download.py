#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One locked, owner-private, pinned prerequisite transfer.

The caller owns the SOU-139 output-root claim. Nothing in a partial or HTTP
validator is authority for an archive: every reuse and publication hashes the
whole pinned object, and extraction remains the caller's existing gate.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time
import urllib.error
import urllib.request
import uuid

FORMAT = "sw-pilot-prerequisite-resume/1"
DIRECTORY = "download-cache"
PARTIAL = "bwrap.partial"
RECORD = "bwrap.resume.json"
VERIFIED = "bwrap.verified.tar.xz"
EVIDENCE = "bwrap.transfer-evidence.json"
MAX_RECORD = 4096
MAX_ATTEMPTS = 3
DOWNLOAD_SECONDS = 120
READ_SECONDS = 25
BLOCK = 65536
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
RANGE = re.compile(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)\Z")
UNSATISFIED = re.compile(r"bytes \*/([0-9]+)\Z")


class Refusal(Exception):
    def __init__(self, reason, progress=None):
        super().__init__(reason)
        self.reason = reason
        self.progress = progress or {}


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink


def _private_regular(info, *, limit):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
            and 0 <= info.st_size <= limit, "download_cache_unsafe")


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "download_record_invalid")
        result[key] = value
    return result


def _digest(fd, length):
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = length
    while remaining:
        block = os.read(fd, min(BLOCK, remaining))
        require(bool(block), "download_partial_changed")
        h.update(block)
        remaining -= len(block)
    return h.hexdigest()


def _validator(headers):
    value = headers.get("ETag")
    if value is None or not isinstance(value, str) or len(value) > 200:
        return None
    # Only a strong, quoted entity tag is usable with If-Range. Final SHA-256
    # remains mandatory even when the validator matches.
    return value if re.fullmatch(r'"[\x21\x23-\x7e]{1,198}"', value) else None


class Cache:
    def __init__(self, output, claim):
        self.output, self.claim, self.fd = Path(output), claim, None
        claim.verify()
        try:
            os.mkdir(DIRECTORY, 0o700, dir_fd=claim.directory_fd)
        except FileExistsError:
            pass
        self.fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=claim.directory_fd)
        self.check()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def check(self):
        self.claim.verify()
        opened = os.fstat(self.fd)
        named = os.stat(DIRECTORY, dir_fd=self.claim.directory_fd, follow_symlinks=False)
        require(stat.S_ISDIR(opened.st_mode) and opened.st_uid == os.getuid()
                and stat.S_IMODE(opened.st_mode) == 0o700
                and _identity(opened) == _identity(named), "download_cache_changed")

    def open_file(self, name, *, writable=False, limit):
        self.check()
        try:
            before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        _private_regular(before, limit=limit)
        flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = os.open(name, flags, dir_fd=self.fd)
        try:
            opened = os.fstat(descriptor)
            require(_identity(before) == _identity(opened) and before.st_size == opened.st_size
                    and before.st_mtime_ns == opened.st_mtime_ns, "download_cache_changed")
            self.check()
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def read_record(self):
        fd = self.open_file(RECORD, limit=MAX_RECORD)
        if fd is None:
            return None
        try:
            raw = os.read(fd, MAX_RECORD + 1)
            require(len(raw) <= MAX_RECORD and len(raw) == os.fstat(fd).st_size,
                    "download_record_invalid")
            try:
                value = json.loads(raw, object_pairs_hook=_pairs,
                                   parse_constant=lambda _: require(False, "download_record_invalid"))
            except (ValueError, UnicodeError, RecursionError):
                raise Refusal("download_record_invalid") from None
            require(type(value) is dict, "download_record_invalid")
            return value
        finally:
            os.close(fd)

    def write_record(self, value, *, name=RECORD):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        require(len(raw) <= MAX_RECORD, "download_record_invalid")
        self.check()
        temporary = ".resume-" + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            old = self.open_file(name, limit=MAX_RECORD)
            if old is not None:
                os.close(old)
            self.check()
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def new_partial(self):
        self.check()
        fd = os.open(PARTIAL, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        os.fsync(self.fd)
        return fd

    def clear(self, *, limit):
        """Explicit cleanup only; no generation or unrelated name is touched."""
        for name, bound in ((PARTIAL, limit), (RECORD, MAX_RECORD),
                            (VERIFIED, limit), (EVIDENCE, MAX_RECORD)):
            fd = self.open_file(name, limit=bound)
            if fd is None:
                continue
            try:
                self.check()
                require(_identity(os.fstat(fd)) == _identity(os.stat(
                    name, dir_fd=self.fd, follow_symlinks=False)), "download_cache_changed")
                os.unlink(name, dir_fd=self.fd)
            finally:
                os.close(fd)
        os.fsync(self.fd)


def _record(url, sha256, expected, limit, fd):
    info = os.fstat(fd)
    return {"format": FORMAT, "url": url, "sha256": sha256, "expected_bytes": expected,
            "limit_bytes": limit, "dev": info.st_dev, "ino": info.st_ino,
            "offset": 0, "prefix_sha256": EMPTY_SHA256, "validator": None,
            "attempts": 0, "transferred_bytes": 0, "last_reason": None,
            "failed_attempts": []}


def _validate_record(value, url, sha256, expected, limit, fd):
    require(set(value) == set(_record(url, sha256, expected, limit, fd)), "download_record_invalid")
    require(value["format"] == FORMAT and value["url"] == url and value["sha256"] == sha256
            and value["expected_bytes"] == expected and value["limit_bytes"] == limit,
            "download_record_binding_changed")
    info = os.fstat(fd)
    require(type(value["dev"]) is int and type(value["ino"]) is int
            and value["dev"] == info.st_dev and value["ino"] == info.st_ino,
            "download_partial_identity_changed")
    offset, attempts, transferred = value["offset"], value["attempts"], value["transferred_bytes"]
    require(all(type(item) is int for item in (offset, attempts, transferred))
            and 0 <= offset <= expected and 0 <= attempts <= MAX_ATTEMPTS
            and 0 <= transferred <= 2 * limit and info.st_size >= offset
            and info.st_size <= expected, "download_record_invalid")
    require(type(value["prefix_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["prefix_sha256"])
            and (value["validator"] is None or _validator({"ETag": value["validator"]}) == value["validator"])
            and (value["last_reason"] is None or value["last_reason"] in {
                "download_interrupted", "download_truncated", "download_timeout", "download_size_limit",
                "download_digest_mismatch", "download_range_refused", "download_validator_changed",
                "download_protocol_refused", "download_timeout_unenforceable",
                "download_insecure_redirect"}), "download_record_invalid")
    require(type(value["failed_attempts"]) is list and len(value["failed_attempts"]) <= MAX_ATTEMPTS
            and all(type(item) is dict and set(item) == {"attempt", "reason", "retained_bytes",
                                                    "transferred_bytes_total"}
                    and type(item["attempt"]) is int and 1 <= item["attempt"] <= attempts
                    and item["reason"] in {"download_interrupted", "download_truncated",
                                           "download_timeout", "download_size_limit",
                                           "download_digest_mismatch", "download_range_refused",
                                           "download_validator_changed", "download_protocol_refused",
                                           "download_timeout_unenforceable", "download_insecure_redirect"}
                    and type(item["retained_bytes"]) is int
                    and 0 <= item["retained_bytes"] <= expected
                    and type(item["transferred_bytes_total"]) is int
                    and 0 <= item["transferred_bytes_total"] <= transferred
                    for item in value["failed_attempts"]), "download_record_invalid")
    require(_digest(fd, offset) == value["prefix_sha256"], "download_partial_changed")
    # A terminated writer may have appended after its last fsynced checkpoint.
    # Keep the recorded prefix, account for and discard only that uncommitted tail.
    discarded = info.st_size - offset
    if discarded:
        os.ftruncate(fd, offset)
        os.fsync(fd)
    return discarded


def _progress(record, *, source, this_attempt=0, discarded=0):
    return {"format": FORMAT, "source": source, "expected_bytes": record["expected_bytes"],
            "retained_bytes": record["offset"], "attempts": record["attempts"],
            "transferred_bytes_total": record["transferred_bytes"],
            "transferred_bytes_this_attempt": this_attempt,
            "discarded_uncommitted_bytes": discarded,
            "failed_attempts": record.get("failed_attempts", [])}


def _copy_verified(cache, destination, expected, sha256, limit):
    fd = cache.open_file(VERIFIED, limit=limit)
    require(fd is not None, "download_verified_missing")
    try:
        require(os.fstat(fd).st_size == expected and _digest(fd, expected) == sha256,
                "download_verified_changed")
        cache.check()
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            remaining = expected
            while remaining:
                block = os.read(fd, min(BLOCK, remaining))
                require(bool(block), "download_verified_changed")
                view = memoryview(block)
                while view:
                    count = os.write(target, view)
                    require(count > 0, "download_copy_changed")
                    view = view[count:]
                remaining -= len(block)
            os.fsync(target)
        finally:
            os.close(target)
        require(_digest(fd, expected) == sha256 and
                _identity(os.fstat(fd)) == _identity(os.stat(VERIFIED, dir_fd=cache.fd,
                                                          follow_symlinks=False)),
                "download_verified_changed")
    finally:
        os.close(fd)
    copied = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(copied)
        _private_regular(info, limit=limit)
        require(info.st_size == expected and _digest(copied, expected) == sha256,
                "download_copy_changed")
    finally:
        os.close(copied)


def _read_response(response, fd, record, cache, deadline, limit, *, source, discarded):
    this_attempt = 0
    os.lseek(fd, record["offset"], os.SEEK_SET)
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "download_timeout")
        # A fixed per-read timeout alone could extend the accepted aggregate
        # deadline by another full socket wait.
        stream = getattr(response, "fp", None)
        if stream is None:
            break  # http.client closed the stream after its declared response length.
        sock = getattr(getattr(stream, "raw", None), "_sock", None)
        require(sock is not None and callable(getattr(response, "read1", None)),
                "download_timeout_unenforceable")
        sock.settimeout(min(READ_SECONDS, remaining))
        budget = 2 * limit - record["transferred_bytes"]
        require(budget > 0, "download_size_limit")
        amount = min(BLOCK, record["expected_bytes"] - record["offset"] + 1, budget)
        try:
            # read1 returns after at most one underlying read. read(amount) may
            # aggregate a slow drip indefinitely by resetting socket timeouts.
            block = response.read1(amount)
        except http.client.IncompleteRead as error:
            block = error.partial
            if block:
                try:
                    _append(block, fd, record, cache, limit)
                except Refusal as failure:
                    failure.progress = _progress(record, source=source,
                        this_attempt=this_attempt + len(block), discarded=discarded)
                    raise
                this_attempt += len(block)
            raise Refusal("download_interrupted", _progress(record, source=source,
                          this_attempt=this_attempt, discarded=discarded)) from None
        except TimeoutError:
            raise Refusal("download_timeout", _progress(record, source=source,
                          this_attempt=this_attempt, discarded=discarded)) from None
        except (OSError, urllib.error.URLError):
            raise Refusal("download_interrupted", _progress(record, source=source,
                          this_attempt=this_attempt, discarded=discarded)) from None
        if not block:
            break
        try:
            _append(block, fd, record, cache, limit)
        except Refusal as failure:
            failure.progress = _progress(record, source=source,
                this_attempt=this_attempt + len(block), discarded=discarded)
            raise
        this_attempt += len(block)
    require(record["offset"] == record["expected_bytes"], "download_truncated")
    require(_digest(fd, record["expected_bytes"]) == record["sha256"], "download_digest_mismatch")
    return _progress(record, source=source, this_attempt=this_attempt, discarded=discarded)


def _append(block, fd, record, cache, limit):
    require(len(block) <= BLOCK and record["transferred_bytes"] + len(block) <= 2 * limit,
            "download_size_limit")
    record["transferred_bytes"] += len(block)
    cache.write_record(record)
    require(record["offset"] + len(block) <= record["expected_bytes"]
            and record["offset"] + len(block) <= limit, "download_size_limit")
    view = memoryview(block)
    while view:
        written = os.write(fd, view)
        require(written > 0, "download_interrupted")
        view = view[written:]
    os.fsync(fd)
    record["offset"] += len(block)
    record["prefix_sha256"] = _digest(fd, record["offset"])
    cache.write_record(record)


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        require(newurl.startswith("https://"), "download_insecure_redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)

    def http_error_302(self, request, fp, code, msg, headers):
        try:
            return super().http_error_302(request, fp, code, msg, headers)
        except BaseException:
            # urllib reads the intermediate body before following a redirect.
            # An aggregate-deadline refusal can interrupt that read before
            # urllib reaches its own fp.close(). Preserve the refusal while
            # releasing the response and socket we still own.
            try:
                fp.close()
            except Exception:
                pass
            raise

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _secure_open(request, timeout):
    # No ambient proxy, cookie, auth or provider setting enters this opener.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SecureRedirect())
    return opener.open(request, timeout=timeout)


def _open_before_deadline(open_request, request, deadline):
    """Bound connect, headers, and every redirect by the one request deadline.

    urllib passes its socket timeout to each redirect. That timeout alone is
    per operation, so a sequence of slow but valid HTTPS hops could otherwise
    exceed the transfer budget before returning a response.
    """
    remaining = deadline - time.monotonic()
    require(remaining > 0, "download_timeout")
    require(hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread(),
            "download_timeout_unenforceable")
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    require(prior_timer == (0.0, 0.0), "download_timeout_unenforceable")

    def expired(*_):
        raise Refusal("download_timeout")

    prior_handler = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining)
        return open_request(request, min(READ_SECONDS, remaining))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior_handler)


def acquire(output, claim, destination, *, url, sha256, expected, limit,
            allow_download, reset=False, open_request=None, fixture_http=False):
    """Return a verified private archive copy and finite progress.

    fixture_http is used only by the controlled local HTTP protocol tests; the
    production wrapper supplies the exact accepted HTTPS pin.
    """
    require(type(url) is str and (url.startswith("https://") or
            fixture_http and url.startswith("http://127.0.0.1:")), "download_url_invalid")
    require(type(expected) is int and type(limit) is int and 0 < expected <= limit,
            "download_pin_invalid")
    require(type(sha256) is str and re.fullmatch(r"[0-9a-f]{64}", sha256), "download_pin_invalid")
    open_request = open_request or _secure_open
    with Cache(output, claim) as cache:
        if reset:
            cache.clear(limit=limit)
        verified = cache.open_file(VERIFIED, limit=limit)
        if verified is not None:
            os.close(verified)
            _copy_verified(cache, destination, expected, sha256, limit)
            return _progress({"expected_bytes": expected, "offset": expected,
                              "attempts": 0, "transferred_bytes": 0}, source="verified-cache")
        record = cache.read_record()
        fd = cache.open_file(PARTIAL, writable=True, limit=limit)
        if record is None and fd is not None or record is not None and fd is None:
            if fd is not None:
                os.close(fd)
            raise Refusal("download_orphan_partial")
        if fd is None:
            require(allow_download, "download_offline_cache_missing")
            fd = cache.new_partial()
            record = _record(url, sha256, expected, limit, fd)
            cache.write_record(record)
        discarded = 0
        started_attempt = False
        try:
            discarded = _validate_record(record, url, sha256, expected, limit, fd)
            require(allow_download, "download_offline_cache_missing")
            require(record["attempts"] < MAX_ATTEMPTS and record["transferred_bytes"] < 2 * limit,
                    "download_budget_exhausted")
            offset = record["offset"]
            validator = record["validator"]
            ranged = offset > 0 and validator is not None
            headers = {"User-Agent": "soup-wall-sou173/1"}
            if ranged:
                headers.update(Range=f"bytes={offset}-", **{"If-Range": validator})
            request = urllib.request.Request(url, headers=headers)
            record["attempts"] += 1
            started_attempt = True
            cache.write_record(record)
            deadline = time.monotonic() + DOWNLOAD_SECONDS
            try:
                response = _open_before_deadline(open_request, request, deadline)
            except urllib.error.HTTPError as error:
                with error:
                    if error.code == 416 and ranged:
                        span = UNSATISFIED.fullmatch(error.headers.get("Content-Range", ""))
                        require(span is not None and int(span[1]) == expected and offset == expected,
                                "download_range_refused")
                        require(_digest(fd, expected) == sha256, "download_digest_mismatch")
                        progress = _progress(record, source="complete-range-416", discarded=discarded)
                        cache.check()
                        cache.write_record({"format": FORMAT, "progress": progress}, name=EVIDENCE)
                        os.rename(PARTIAL, VERIFIED, src_dir_fd=cache.fd, dst_dir_fd=cache.fd)
                        os.unlink(RECORD, dir_fd=cache.fd)
                        os.fsync(cache.fd)
                        _copy_verified(cache, destination, expected, sha256, limit)
                        return progress
                    raise Refusal("download_range_refused" if ranged else "download_protocol_refused") from None
            with response:
                final_url = response.geturl()
                require(final_url.startswith("http://127.0.0.1:") if fixture_http else
                        final_url.startswith("https://"), "download_insecure_redirect")
                status = response.status
                if ranged and status == 206:
                    match = RANGE.fullmatch(response.headers.get("Content-Range", ""))
                    require(match is not None and int(match[1]) == offset
                            and int(match[2]) == expected - 1 and int(match[3]) == expected,
                            "download_range_refused")
                    require(_validator(response.headers) == validator,
                            "download_validator_changed")
                    source = "resumed-range"
                elif status == 200:
                    source = "range-ignored-restarted" if offset else "fresh"
                    if offset:
                        os.ftruncate(fd, 0)
                        os.fsync(fd)
                        record["offset"] = 0
                        record["prefix_sha256"] = EMPTY_SHA256
                    record["validator"] = _validator(response.headers)
                    cache.write_record(record)
                else:
                    raise Refusal("download_protocol_refused")
                progress = _read_response(response, fd, record, cache, deadline, limit,
                                          source=source, discarded=discarded)
            cache.check()
            other = cache.open_file(VERIFIED, limit=limit)
            if other is not None:
                os.close(other)
                raise Refusal("download_verified_changed")
            cache.write_record({"format": FORMAT, "progress": progress}, name=EVIDENCE)
            os.rename(PARTIAL, VERIFIED, src_dir_fd=cache.fd, dst_dir_fd=cache.fd)
            os.unlink(RECORD, dir_fd=cache.fd)
            os.fsync(cache.fd)
            _copy_verified(cache, destination, expected, sha256, limit)
            return progress
        except KeyboardInterrupt:
            record["last_reason"] = "download_interrupted"
            if started_attempt:
                record["failed_attempts"].append({"attempt": record["attempts"],
                                                   "reason": "download_interrupted",
                                                   "retained_bytes": record["offset"],
                                                   "transferred_bytes_total": record["transferred_bytes"]})
            cache.write_record(record)
            raise Refusal("download_interrupted", _progress(record, source="partial")) from None
        except Refusal as error:
            if error.reason in {"download_interrupted", "download_truncated", "download_timeout",
                                "download_size_limit", "download_digest_mismatch", "download_range_refused",
                                "download_validator_changed", "download_protocol_refused",
                                "download_timeout_unenforceable", "download_insecure_redirect"}:
                record["last_reason"] = error.reason
                if started_attempt:
                    record["failed_attempts"].append({"attempt": record["attempts"],
                                                       "reason": error.reason,
                                                       "retained_bytes": record["offset"],
                                                       "transferred_bytes_total": record["transferred_bytes"]})
                cache.write_record(record)
            if not error.progress:
                error.progress = _progress(record, source="partial", discarded=discarded)
            raise
        except (OSError, TimeoutError, urllib.error.URLError):
            record["last_reason"] = "download_interrupted"
            if started_attempt:
                record["failed_attempts"].append({"attempt": record["attempts"],
                                                   "reason": "download_interrupted",
                                                   "retained_bytes": record["offset"],
                                                   "transferred_bytes_total": record["transferred_bytes"]})
            cache.write_record(record)
            raise Refusal("download_interrupted", _progress(record, source="partial",
                          discarded=discarded)) from None
        finally:
            os.close(fd)
