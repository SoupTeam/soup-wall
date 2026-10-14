# SPDX-License-Identifier: Apache-2.0
"""Durable, bounded Alertmanager v4 receiver with an operator-owned source policy.

Bearer authentication authorizes credential possession, not a sender's network
identity. SQLite receipts provide at-least-once delivery evidence and deduplicate
within the configured retention horizon; they do not claim exactly-once effects.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import ssl
import stat
import threading
import time
from urllib.parse import parse_qs, urlsplit

MAX_BODY_BYTES = 64 * 1024
MAX_HEADER_BYTES = 8 * 1024
MAX_ALERTS = 128
SOURCE_LABELS = frozenset({"job", "instance", "alertname", "severity", "component"})
TOP_FIELDS = frozenset({"version", "groupKey", "truncatedAlerts", "status", "receiver",
                        "groupLabels", "commonLabels", "commonAnnotations", "externalURL", "alerts"})
ALERT_FIELDS = frozenset({"status", "labels", "annotations", "startsAt", "endsAt", "generatorURL", "fingerprint"})
RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})\Z")
LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*\Z")


class ValidationError(ValueError):
    """Invalid configuration or unsupported webhook data (safe, fixed messages)."""


class CapacityError(RuntimeError):
    """An unexpired deduplication record must not be discarded to admit new data."""


def _text(value, maximum=512, *, nonempty=True):
    if not isinstance(value, str) or (nonempty and not value):
        raise ValidationError("invalid string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValidationError("invalid Unicode") from None
    if len(encoded) > maximum or any(ord(c) < 32 for c in value):
        raise ValidationError("invalid string bounds")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValidationError("non-finite JSON number")


def strict_json(raw):
    try:
        return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValidationError("invalid JSON") from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8", errors="strict")


def _timestamp(value):
    value = _text(value, 40)
    match = RFC3339.fullmatch(value)
    if match is None:
        raise ValidationError("invalid RFC3339 timestamp")
    year, month, day, hour, minute, second = (int(x) for x in match.groups()[:6])
    fraction = (match.group(7) or "").rstrip("0")
    offset = match.group(8)
    try:
        if offset == "Z":
            zone = timezone.utc
        else:
            offset_hour, offset_minute = int(offset[1:3]), int(offset[4:6])
            if offset_hour > 23 or offset_minute > 59:
                raise ValueError
            delta = timedelta(hours=offset_hour, minutes=offset_minute)
            zone = timezone(delta if offset[0] == "+" else -delta)
        instant = datetime(year, month, day, hour, minute, second, tzinfo=zone).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValidationError("invalid RFC3339 timestamp") from None
    canonical = (f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}T"
                 f"{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}"
                 + ("." + fraction if fraction else "") + "Z")
    return canonical, (instant, int(fraction.ljust(9, "0") or "0"))


def _url(value):
    value = _text(value, 4096)
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise ValidationError("invalid source URL") from None
    return value


class ReceiverPolicy:
    def __init__(self, receiver, external_url, source_tuples, optional_labels):
        self.receiver = receiver
        self.external_url = external_url
        self.source_tuples = frozenset(source_tuples)
        self.optional_labels = optional_labels
        self.allowed_values = {name: {values[index] for values in self.source_tuples}
                               for index, name in enumerate(sorted(SOURCE_LABELS))}
        self.allowed_values.update(optional_labels)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) - {"receiver", "external_url", "sources", "optional_labels"}:
            raise ValidationError("unsupported source policy")
        if not {"receiver", "external_url", "sources"}.issubset(value):
            raise ValidationError("incomplete source policy")
        receiver = _text(value["receiver"], 128)
        external_url = _url(value["external_url"])
        sources = value["sources"]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 128:
            raise ValidationError("invalid source list")
        tuples = set()
        for source in sources:
            if not isinstance(source, dict) or set(source) != {"job", "instance", "alerts"}:
                raise ValidationError("invalid source")
            job, instance = _text(source["job"], 256), _text(source["instance"], 256)
            alerts = source["alerts"]
            if not isinstance(alerts, list) or not 1 <= len(alerts) <= 128:
                raise ValidationError("invalid source alerts")
            for alert in alerts:
                if not isinstance(alert, dict) or set(alert) != {"alertname", "severity", "component"}:
                    raise ValidationError("invalid source alert")
                labels = {"job": job, "instance": instance,
                          **{key: _text(item, 256) for key, item in alert.items()}}
                tuples.add(tuple(labels[key] for key in sorted(SOURCE_LABELS)))
        if len(tuples) > 1024:
            raise ValidationError("too many source combinations")
        optional = value.get("optional_labels", {})
        if not isinstance(optional, dict) or len(optional) > 8:
            raise ValidationError("invalid optional labels")
        checked = {}
        for name, values in optional.items():
            _text(name, 64)
            if not LABEL_NAME.fullmatch(name) or name in SOURCE_LABELS:
                raise ValidationError("invalid optional label name")
            if not isinstance(values, list) or not 1 <= len(values) <= 32:
                raise ValidationError("invalid optional label values")
            checked[name] = frozenset(_text(item, 256) for item in values)
        return cls(receiver, external_url, tuples, checked)

    @classmethod
    def from_file(cls, path):
        path = _private_file(path, secret=False)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                    or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022):
                raise ValidationError("source policy ownership or permissions are invalid")
            raw = source.read(MAX_BODY_BYTES + 1)
        if len(raw) > MAX_BODY_BYTES:
            raise ValidationError("source policy is too large")
        return cls.from_dict(strict_json(raw))

    def labels(self, value, *, complete):
        if not isinstance(value, dict) or len(value) > len(self.allowed_values):
            raise ValidationError("invalid labels")
        for name, item in value.items():
            if name not in self.allowed_values or _text(item, 256) not in self.allowed_values[name]:
                raise ValidationError("unapproved labels")
        if complete:
            if not SOURCE_LABELS.issubset(value):
                raise ValidationError("missing source labels")
            if tuple(value[name] for name in sorted(SOURCE_LABELS)) not in self.source_tuples:
                raise ValidationError("unapproved source")
        return dict(sorted(value.items()))

    @staticmethod
    def annotations(value):
        if not isinstance(value, dict) or len(value) > 16:
            raise ValidationError("invalid annotations")
        for name, item in value.items():
            if name not in {"summary", "description", "runbook", "runbook_url"}:
                raise ValidationError("unsupported annotation")
            if not isinstance(item, str):
                raise ValidationError("invalid annotation")
            try:
                if len(item.encode("utf-8", errors="strict")) > 4096:
                    raise ValidationError("annotation exceeds bounds")
            except UnicodeError:
                raise ValidationError("invalid annotation Unicode") from None

    def validate(self, raw):
        if not raw or len(raw) > MAX_BODY_BYTES:
            raise ValidationError("invalid body size")
        value = strict_json(raw)
        if not isinstance(value, dict) or set(value) != TOP_FIELDS:
            raise ValidationError("unsupported webhook fields")
        if value["version"] != "4" or value["receiver"] != self.receiver or value["externalURL"] != self.external_url:
            raise ValidationError("unapproved webhook source")
        if type(value["truncatedAlerts"]) is not int or value["truncatedAlerts"] != 0:
            raise ValidationError("truncated alerts are unsupported")
        _text(value["groupKey"], 2048)
        group = self.labels(value["groupLabels"], complete=False)
        common = self.labels(value["commonLabels"], complete=False)
        if any(common[key] != group[key] for key in common.keys() & group.keys()):
            raise ValidationError("conflicting grouped labels")
        self.annotations(value["commonAnnotations"])
        alerts = value["alerts"]
        if not isinstance(alerts, list) or not 1 <= len(alerts) <= MAX_ALERTS:
            raise ValidationError("invalid alert count")
        events = []
        has_firing = False
        for alert in alerts:
            if not isinstance(alert, dict) or set(alert) != ALERT_FIELDS:
                raise ValidationError("unsupported alert fields")
            status = alert["status"]
            if status not in {"firing", "resolved"}:
                raise ValidationError("unsupported alert status")
            has_firing |= status == "firing"
            labels = self.labels(alert["labels"], complete=True)
            if any(labels.get(key) != item for key, item in {**common, **group}.items()):
                raise ValidationError("inconsistent grouped labels")
            self.annotations(alert["annotations"])
            starts_at, start_order = _timestamp(alert["startsAt"])
            ends_at, end_order = _timestamp(alert["endsAt"])
            if start_order[0].year < 1970:
                raise ValidationError("invalid alert start")
            if status == "resolved" and end_order < start_order:
                raise ValidationError("invalid resolved time")
            if status == "firing" and end_order[0].year != 1 and end_order < start_order:
                raise ValidationError("invalid firing time")
            _url(alert["generatorURL"])
            fingerprint = _text(alert["fingerprint"], 16)
            if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
                raise ValidationError("invalid alert fingerprint")
            cycle = {"labels": labels, "starts_at": starts_at}
            cycle_id = hashlib.sha256(_canonical(cycle)).hexdigest()
            event_id = hashlib.sha256(_canonical({**cycle, "status": status})).hexdigest()
            events.append({"event_id": event_id, "cycle_id": cycle_id, "status": status,
                           "labels": labels, "starts_at": starts_at, "ends_at": ends_at})
        expected = "firing" if has_firing else "resolved"
        if value["status"] != expected:
            raise ValidationError("inconsistent webhook status")
        return events


def _private_file(path, *, secret=True):
    path = Path(path)
    try:
        details = path.lstat()
    except OSError:
        raise ValidationError("protected file is unavailable") from None
    if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) & (0o077 if secret else 0o022)):
        raise ValidationError("protected file ownership or permissions are invalid")
    return path


def read_token(path):
    path = _private_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                    or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077):
                raise ValidationError("protected token permissions are invalid")
            raw = source.read(259)
    except OSError:
        raise ValidationError("protected token is unavailable") from None
    raw = raw.removesuffix(b"\n").removesuffix(b"\r")
    if not 32 <= len(raw) <= 256 or any(byte < 33 or byte > 126 for byte in raw):
        raise ValidationError("protected token format is invalid")
    return raw


class ReceiptStore:
    """One atomic durable batch; capacity never evicts unexpired identities."""

    def __init__(self, data_dir, retention_days=30, max_events=100000, *, clock=time.time):
        if type(retention_days) is not int or not 1 <= retention_days <= 365:
            raise ValidationError("retention must be between 1 and 365 days")
        if type(max_events) is not int or not 1 <= max_events <= 1000000:
            raise ValidationError("event capacity must be between 1 and 1000000")
        self.directory = Path(data_dir)
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        details = self.directory.lstat()
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) & 0o077):
            raise ValidationError("data directory ownership or permissions are invalid")
        self.path = self.directory / "receipts.sqlite3"
        if self.path.exists() or self.path.is_symlink():
            _private_file(self.path)
        else:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(descriptor)
        self.clock, self.retention_days, self.max_events = clock, retention_days, max_events
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, timeout=5, check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in {0, 1}:
            self.connection.close()
            raise ValidationError("unsupported receipt database version")
        self.connection.executescript("""
          CREATE TABLE IF NOT EXISTS receipts (
            event_id TEXT PRIMARY KEY, cycle_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('firing','resolved')),
            labels_json TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL,
            first_received_at INTEGER NOT NULL, last_received_at INTEGER NOT NULL,
            duplicate_count INTEGER NOT NULL DEFAULT 0 CHECK(duplicate_count >= 0),
            first_body_sha256 TEXT NOT NULL, last_body_sha256 TEXT NOT NULL,
            changed_body_count INTEGER NOT NULL DEFAULT 0 CHECK(changed_body_count >= 0)
          );
          CREATE INDEX IF NOT EXISTS receipts_retention ON receipts(last_received_at);
          PRAGMA user_version=1;
        """)
        with self.lock:
            self.connection.execute("DELETE FROM receipts WHERE last_received_at < ?", (self._cutoff(),))

    def _cutoff(self):
        return int(self.clock()) - self.retention_days * 86400

    def accept(self, events, body_sha256):
        now = int(self.clock())
        with self.lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("DELETE FROM receipts WHERE last_received_at < ?", (self._cutoff(),))
                count = self.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
                incoming = sorted({event["event_id"] for event in events})
                placeholders = ",".join("?" for _ in incoming)
                existing = {row[0] for row in self.connection.execute(
                    "SELECT event_id FROM receipts WHERE event_id IN (" + placeholders + ")", incoming)}
                unique_new = set(incoming) - existing
                if unique_new and count + len(unique_new) > self.max_events:
                    raise CapacityError("receipt capacity is full")
                accepted, duplicates = 0, 0
                for event in events:
                    changed = self.connection.execute("""
                      INSERT OR IGNORE INTO receipts
                      (event_id,cycle_id,status,labels_json,starts_at,ends_at,first_received_at,last_received_at,
                       first_body_sha256,last_body_sha256)
                      VALUES (?,?,?,?,?,?,?,?,?,?)
                    """, (event["event_id"], event["cycle_id"], event["status"],
                          _canonical(event["labels"]).decode("utf-8"), event["starts_at"], event["ends_at"],
                          now, now, body_sha256, body_sha256)).rowcount
                    if changed:
                        accepted += 1
                    else:
                        self.connection.execute("""
                          UPDATE receipts SET last_received_at=?, duplicate_count=MIN(duplicate_count+1,9223372036854775807),
                            last_body_sha256=?, changed_body_count=MIN(changed_body_count +
                              CASE WHEN first_body_sha256<>? THEN 1 ELSE 0 END,9223372036854775807)
                          WHERE event_id=?
                        """, (now, body_sha256, body_sha256, event["event_id"]))
                        duplicates += 1
                self.connection.execute("COMMIT")
                return {"accepted": accepted, "duplicates": duplicates}
            except BaseException:
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
                raise

    def receipts(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValidationError("receipt limit must be between 1 and 1000")
        with self.lock:
            count = self.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            records = []
            for row in self.connection.execute("SELECT * FROM receipts ORDER BY first_received_at,event_id LIMIT ?", (limit,)):
                record = dict(row)
                record["labels"] = json.loads(record.pop("labels_json"))
                records.append(record)
            return {"total_unique_events": count, "records": records, "retention_days": self.retention_days,
                    "returned_records": len(records), "has_more": count > len(records)}

    def close(self):
        with self.lock:
            self.connection.close()


class AlertReceiverServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, token, policy, store, *, read_timeout=5, max_workers=8):
        if not 0.1 <= read_timeout <= 30 or type(max_workers) is not int or not 1 <= max_workers <= 8:
            raise ValidationError("invalid receiver resource bounds")
        self.token, self.policy, self.store = token, policy, store
        self.read_timeout = read_timeout
        self.worker_slots = threading.BoundedSemaphore(max_workers)
        self.active_workers = 0
        self.workers_lock = threading.Lock()
        super().__init__(address, AlertReceiverHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.read_timeout)
        return connection, address

    def process_request(self, request, client_address):
        if not self.worker_slots.acquire(blocking=False):
            try:
                # A TLS write would negotiate in the accept thread before a
                # worker is available. Close it; send refusals only on plaintext.
                if not isinstance(request, ssl.SSLSocket):
                    request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        with self.workers_lock:
            self.active_workers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.workers_lock:
                self.active_workers -= 1
            self.worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.workers_lock:
                self.active_workers -= 1
            self.worker_slots.release()

    def handle_error(self, request, client_address):
        # Never print a request, credential, source URL, or exception payload.
        return


class AlertReceiverHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SoupWallAlertReceiver"
    sys_version = ""

    def log_message(self, *_):
        return

    def parse_request(self):
        # Error replies before the base parser need its response bookkeeping.
        self.command = None
        self.requestline = ""
        if len(self.raw_requestline) > 4096:
            self.request_version = "HTTP/1.1"
            self.close_connection = True
            self.send_error(414)
            return False
        original = self.rfile
        headers, count = bytearray(), 0
        while True:
            line = original.readline(MAX_HEADER_BYTES + 1 - len(headers))
            headers.extend(line)
            if len(headers) > MAX_HEADER_BYTES or not line.endswith(b"\r\n"):
                self.request_version = "HTTP/1.1"
                self.close_connection = True
                self.send_error(431)
                return False
            if line == b"\r\n":
                break
            count += 1
            if count > 32 or line[:1] in {b" ", b"\t"} or b":" not in line:
                self.request_version = "HTTP/1.1"
                self.close_connection = True
                self.send_error(431)
                return False
        self.rfile = io.BytesIO(headers)
        try:
            parsed = super().parse_request()
        finally:
            self.rfile = original
        self.close_connection = True
        if parsed:
            for name in ("Authorization", "Content-Length", "Content-Type", "Transfer-Encoding", "Host"):
                if len(self.headers.get_all(name, [])) > 1:
                    self._reply(400, {"error": "duplicate request header"})
                    return False
        return parsed

    def handle_expect_100(self):
        self._reply(417, {"error": "expectation is unsupported"})
        return False

    def _reply(self, status, body):
        encoded = _canonical(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _authenticate(self):
        value = self.headers.get("Authorization", "")
        supplied = value[7:] if value.startswith("Bearer ") else ""
        try:
            valid = hmac.compare_digest(supplied.encode("ascii", errors="strict"), self.server.token)
        except UnicodeError:
            valid = False
        if not valid:
            self._reply(401, {"error": "unauthorized"})
        return valid

    def do_POST(self):
        if not self._authenticate():
            return
        if self.path != "/alerts":
            self._reply(404, {"error": "unknown endpoint"})
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._reply(400, {"error": "transfer encoding is unsupported"})
            return
        content_type = self.headers.get("Content-Type", "").lower().replace(" ", "")
        if content_type not in {"application/json", "application/json;charset=utf-8"}:
            self._reply(415, {"error": "JSON content type is required"})
            return
        length = self.headers.get("Content-Length", "")
        if not re.fullmatch(r"[0-9]{1,6}", length):
            self._reply(411, {"error": "bounded content length is required"})
            return
        size = int(length)
        if not 1 <= size <= MAX_BODY_BYTES:
            self._reply(413, {"error": "body is outside configured bounds"})
            return
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValidationError("incomplete body")
            events = self.server.policy.validate(raw)
        except (ValidationError, UnicodeError, ValueError, TypeError, OverflowError):
            self._reply(400, {"error": "unsupported or malformed alert batch"})
            return
        except (OSError, TimeoutError):
            self._reply(408, {"error": "incomplete request"})
            return
        try:
            outcome = self.server.store.accept(events, hashlib.sha256(raw).hexdigest())
        except (sqlite3.Error, OSError, CapacityError, RuntimeError):
            self._reply(503, {"error": "durable receipt storage is unavailable"})
            return
        self._reply(200, {"status": "committed", **outcome})

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"status": "serving"})
            return
        if not self._authenticate():
            return
        parsed = urlsplit(self.path)
        if parsed.path != "/receipts":
            self._reply(404, {"error": "unknown endpoint"})
            return
        try:
            query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True, max_num_fields=1)
            if set(query) - {"limit"}:
                raise ValidationError("unsupported receipt query")
            values = query.get("limit", ["100"])
            if len(values) != 1 or not re.fullmatch(r"[0-9]{1,4}", values[0]):
                raise ValidationError("invalid receipt limit")
            result = self.server.store.receipts(int(values[0]))
        except (ValueError, ValidationError):
            self._reply(400, {"error": "invalid receipt query"})
            return
        except (sqlite3.Error, OSError, RuntimeError):
            self._reply(503, {"error": "durable receipt storage is unavailable"})
            return
        self._reply(200, result)


def create_server(address, token, policy, store, *, tls_cert=None, tls_key=None, read_timeout=5, max_workers=8):
    try:
        ip = ipaddress.ip_address(address[0])
    except ValueError:
        raise ValidationError("listen address must be an explicit IP address") from None
    if bool(tls_cert) != bool(tls_key):
        raise ValidationError("TLS requires both a certificate and a private key")
    if not ip.is_loopback and not tls_cert:
        raise ValidationError("non-loopback listeners require TLS")
    if not isinstance(token, bytes) or not 32 <= len(token) <= 256:
        raise ValidationError("invalid protected token")
    server_type = AlertReceiverServer
    if ip.version == 6:
        class IPv6ReceiverServer(AlertReceiverServer):
            address_family = socket.AF_INET6
        server_type = IPv6ReceiverServer
    context = None
    if tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(_private_file(tls_cert, secret=False)), str(_private_file(tls_key)))
    server = server_type(address, token, policy, store, read_timeout=read_timeout, max_workers=max_workers)
    if context:
        # TLS handshakes run inside bounded request workers, never in accept().
        original_get = server.get_request
        def get_request():
            connection, peer = original_get()
            return context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), peer
        server.get_request = get_request
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9081)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--policy-file", type=Path, required=True)
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--max-events", type=int, default=100000)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--read-timeout", type=float, default=5)
    parser.add_argument("--max-workers", type=int, default=8)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if os.name != "posix":
        parser.error("the protected receiver requires Unix file ownership and permissions")
    os.umask(0o077)
    store = server = None
    try:
        token = read_token(args.token_file)
        policy = ReceiverPolicy.from_file(args.policy_file)
        store = ReceiptStore(args.data_dir, args.retention_days, args.max_events)
        server = create_server((args.listen, args.port), token, policy, store, tls_cert=args.tls_cert,
                               tls_key=args.tls_key, read_timeout=args.read_timeout, max_workers=args.max_workers)
        def stop(_signal, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print("Protected alert receiver started; durable receipt storage is ready.", flush=True)
        server.serve_forever(poll_interval=0.2)
    except (ValidationError, OSError, sqlite3.Error, ssl.SSLError):
        print("Protected alert receiver could not start; check owned configuration and storage.", flush=True)
        return 1
    finally:
        if server:
            server.server_close()
            deadline = time.monotonic() + args.read_timeout + 1
            while server.active_workers and time.monotonic() < deadline:
                time.sleep(0.05)
        if store:
            store.close()
    return 0
