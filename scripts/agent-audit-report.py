#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate a bounded, private, self-contained Agent audit report on Linux.

The source JSONL is untrusted and may contain secrets. Only explicitly projected
fields enter the report. This tool never modifies the source or opens a browser.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_RECORDS = 10_000
MAX_DEPTH = 16
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 8
PRIVATE_LINUX_FILESYSTEMS = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "tmpfs", "overlay"})
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SEGMENT_BYTES = 16 * 1024 * 1024
VERDICTS = frozenset({"allow", "ask", "deny"})
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
ORIGINS = frozenset({"user", "project", "system", "network", "mcp", "subagent", "native"})
EVENTS = frozenset({
    "pre_tool_use", "post_tool_use", "subagent_stop", "session_start",
    "session_end", "unknown", "mcp_handshake",
    "native_session_start", "native_session_end", "native_call",
    "native_result", "native_context",
})
APPROVAL_EVENTS = frozenset({"native_approval_requested", "native_approval_cancelled"})
KNOWN_RULES = frozenset({
    "deny-tainted-destructive", "deny-tainted-privilege", "deny-subagent-escalation",
    "deny-secret-egress", "ask-sensitive-path-egress", "ask-pii-egress",
    "ask-injection-in-result", "ask-injection-in-tool-description",
    "ask-manifest-drift", "ask-tool-shadow", "ask-unknown-host",
    "escalate-tainted-side-effect", "taint-history-incomplete",
    "unsupported-pre-tool-use-shape", "invalid-session", "unrecognized-protected-event",
    "managed-policy-transition", "native_hook_tool_unsupported",
})
KNOWN_TOOLS = frozenset({"Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "Task", "NotebookRead", "NotebookEdit"})
KNOWN_DETECTORS = frozenset({
    "injection", "injection.ml", "pii", "pii.credit_card", "pii.email",
    "pii.ipv4", "pii.ssn", "secret", "secret.aws_key", "secret.generic",
    "secret.github_pat", "secret.jwt", "secret.private_key", "secret.slack",
    "output", "output.exfil.markdown_image", "output.html.event_handler",
    "output.html.iframe", "output.html.js_uri", "output.html.script",
    "output.shell.disk", "output.shell.fork_bomb", "output.shell.pipe_exec",
    "output.shell.power", "output.shell.rm_rf",
})


class ReportError(Exception):
    """Expected input or report-generation failure."""


def _pair_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_depth(raw: bytes) -> bool:
    """Reject deep JSON before decoding; account for quoted brackets and escapes."""
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif byte in (93, 125):
            depth -= 1
    return True


def _enum(value: object, allowed: frozenset[str]) -> str | None:
    return value if type(value) is str and value in allowed else None


def _int(value: object, max_value: int = 2**53 - 1) -> int | None:
    return value if type(value) is int and 0 <= value <= max_value else None


def _catalog_label(value: object, known: frozenset[str], aliases: dict[str, str], prefix: str) -> str | None:
    if type(value) is not str or not value or len(value) > 256:
        return None
    if value in known:
        return value
    if value not in aliases:
        aliases[value] = f"{prefix} {len(aliases) + 1}"
    return aliases[value]


def _time(value: object) -> str | None:
    number = _int(value)
    if number is None:
        return None
    try:
        return dt.datetime.fromtimestamp(number / 1000, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _stage(event: str) -> str:
    return {"native_call": "admission", "native_result": "result", "native_context": "context",
            "post_tool_use": "observation"}.get(
                event, "decision" if not event.startswith("native_") else "other")


def _identity(value: object, aliases: dict[str, str], prefix: str) -> str | None:
    if type(value) is not str or not value or len(value) > 256:
        return None
    if value not in aliases:
        aliases[value] = f"{prefix} {len(aliases) + 1}"
    return aliases[value]


def _project(record: dict[str, object], ordinal: int,
             sessions: dict[str, str], servers: dict[str, str],
             agents: dict[str, str],
             calls: dict[tuple[str, str], str], tools: dict[str, str],
             rules: dict[str, str], detectors: dict[str, str]) -> dict[str, object] | None:
    event = _enum(record.get("event"), EVENTS | APPROVAL_EVENTS)
    if event is None:
        return None
    verdict = _enum(record.get("verdict"), VERDICTS)
    if event not in APPROVAL_EVENTS and verdict is None:
        return None
    if event in APPROVAL_EVENTS:
        # These are accepted audit records, but they do not carry a policy verdict.
        verdict = None
    shadow = record.get("shadow")
    if event not in APPROVAL_EVENTS and type(shadow) is not bool:
        return None
    session = record.get("session")
    session_alias = _identity(session, servers if event == "mcp_handshake" else sessions,
                              "Server" if event == "mcp_handshake" else "Session")
    agent_alias = _identity(record.get("agent_id"), agents, "Agent")
    parent_alias = _identity(record.get("parent_id"), agents, "Agent")
    stage = _stage(event)
    if event in APPROVAL_EVENTS:
        stage = "other"
    findings = record.get("findings")
    severities: list[str] = []
    detector_names: list[str] = []
    finding_details: list[dict[str, str]] = []
    if type(findings) is list:
        for index, item in enumerate(findings[:MAX_FINDINGS], 1):
            if type(item) is dict:
                severity = _enum(item.get("severity"), SEVERITIES)
                if severity and severity not in severities:
                    severities.append(severity)
                detector_name = _catalog_label(item.get("detector"), KNOWN_DETECTORS, detectors, "Detector")
                if detector_name:
                    if detector_name not in detector_names:
                        detector_names.append(detector_name)
                    finding_details.append({"label": f"Finding {index}",
                                            "value": detector_name + " · " + (severity or "severity unavailable")})
    taint = record.get("taint")
    taint_origin = _enum(taint.get("origin"), ORIGINS) if type(taint) is dict else None
    latency = _int(record.get("latency_us"), 10**12)
    correlation = None
    # Native call/result correlation is supported only when both original fields
    # are present. The opaque source call_id never appears in the HTML.
    call_id = record.get("call_id")
    if event in ("native_call", "native_result", "native_context") and session_alias and type(call_id) is str and 0 < len(call_id) <= 256:
        key = (session, call_id)
        if key not in calls:
            calls[key] = f"Call {len(calls) + 1}"
        correlation = calls[key]
    missing: list[str] = []
    if type(findings) is list and len(findings) > MAX_FINDINGS:
        missing.append("Additional detector findings were omitted by the report limit")
    if session_alias is None:
        missing.append("Session identity unavailable")
    if event == "mcp_handshake":
        missing.append("Handshake identity is an MCP server, not an Agent session")
    if stage == "admission":
        missing.append("Tool execution is not proven by admission")
        if correlation is None:
            missing.append("Call identifier unavailable; result cannot be linked")
    elif stage == "result":
        if correlation is None:
            missing.append("Call identifier unavailable; admission cannot be linked")
    elif stage == "decision" and event == "pre_tool_use":
        missing.append("Host execution is not proven by a hook decision")
    elif stage == "observation":
        missing.append("Post-hook callback does not reveal full tool effects")
    if record.get("truncated") is True:
        missing.append("Source event was truncated")
    if event in APPROVAL_EVENTS:
        missing.append("Approval event has no policy verdict")
    released = record.get("released")
    if stage in ("admission", "result", "context") and type(released) is not bool:
        missing.append("Release status unavailable")
    if stage == "result" and released is True:
        missing.append("A released result does not prove model consumption")
    details = finding_details
    if agent_alias:
        details.append({"label": "Agent alias", "value": agent_alias})
    if parent_alias:
        details.append({"label": "Parent alias", "value": parent_alias})
    seq = _int(record.get("seq"))
    if seq is not None:
        details.append({"label": "Sequence", "value": str(seq)})
    score = _int(record.get("risk_score"), 100)
    if score is not None:
        details.append({"label": "Risk score", "value": str(score)})
    if type(released) is bool and stage in ("admission", "result", "context"):
        details.append({"label": "Released", "value": "yes" if released else "no"})
    reason = None
    if stage == "admission" and released is True:
        reason = "Call admitted; execution not observed"
    elif stage == "result" and released is False:
        reason = "Result withheld; prior side effects may remain"
    elif stage == "result" and released is True:
        reason = "Result released; model consumption not proven"
    elif shadow is True:
        reason = "Computed in shadow mode; not enforced"
    elif event == "pre_tool_use" and verdict == "allow":
        reason = "No objection; host permission flow still applies"
    elif event in APPROVAL_EVENTS:
        reason = "Approval lifecycle event; decision unavailable"
    return {
        "id": ordinal, "timestamp": _time(record.get("at_ms")), "event": event,
        "verdict": verdict, "tool": _catalog_label(record.get("tool"), KNOWN_TOOLS, tools, "Tool"),
        "session_alias": session_alias, "mode": "shadow" if shadow is True else "enforced" if shadow is False else "unknown",
        "stage": stage, "rule": _catalog_label(record.get("rule"), KNOWN_RULES, rules, "Rule"),
        "reason": reason, "severity": severities, "detectors": detector_names, "taint_origin": taint_origin,
        "latency_ms": round(latency / 1000, 3) if latency is not None else None,
        "released": released if type(released) is bool and stage in ("admission", "result", "context") else None,
        "correlation": correlation, "evidence_missing": missing, "details": details,
    }


def _check_path_components(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ReportError("symlink path components are refused")


def _open_dir_nofollow(path: Path) -> int:
    """Walk from root with held directory handles; no ancestor may be a link."""
    if not path.is_absolute():
        raise ReportError("internal error: expected absolute path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            if component in ("", ".", ".."):
                raise ReportError("unsafe path component")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _linux_filesystem(path: Path) -> str:
    """Return the mount type for the longest matching mount point."""
    target = str(path.resolve(strict=True))
    best_mount = ""
    filesystem = ""
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ReportError("cannot verify output filesystem") from error
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        after = right.split()
        if len(fields) < 5 or not after:
            continue
        mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        if target == mount or target.startswith(mount.rstrip("/") + "/"):
            if len(mount) > len(best_mount):
                best_mount = mount
                filesystem = after[0]
    if not filesystem:
        raise ReportError("cannot verify output filesystem")
    return filesystem


def _open_input(path: Path):
    _check_path_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    parent_fd = _open_dir_nofollow(path.parent)
    try:
        fd = os.open(path.name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode):
        os.close(fd)
        raise ReportError("input must be a regular file")
    return os.fdopen(fd, "rb")


def _read_report(path: Path) -> dict[str, object]:
    sessions: dict[str, str] = {}
    servers: dict[str, str] = {}
    agents: dict[str, str] = {}
    calls: dict[tuple[str, str], str] = {}
    tools: dict[str, str] = {}
    rules: dict[str, str] = {}
    detectors: dict[str, str] = {}
    events: list[dict[str, object]] = []
    native_link_candidates: dict[str, list[tuple[dict[str, object], object, object]]] = {}
    counts = {"lines": 0, "accepted": 0, "malformed": 0, "unsupported": 0, "skipped": 0}
    notices: list[str] = []
    partial = False
    unknown_record_schema = False
    consumed = 0
    export_meta: dict[str, object] | None = None
    with _open_input(path) as stream:
        while True:
            if counts["lines"] >= MAX_RECORDS:
                if stream.read(1):
                    partial = True
                    notices.append("Record limit reached; later records were not read")
                    counts["skipped"] += 1  # Lower bound; later count is unknown.
                break
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            consumed += len(raw)
            if consumed > MAX_INPUT_BYTES:
                partial = True
                notices.append("Input byte limit reached; later records were not read")
                counts["skipped"] += 1
                break
            counts["lines"] += 1
            if len(raw) > MAX_LINE_BYTES:
                partial = True
                notices.append("Line limit reached; later records were not read")
                counts["skipped"] += 1
                break
            if not raw.endswith(b"\n"):
                partial = True
                notices.append("Final line lacks a newline; it may be incomplete")
            if not _bounded_json_depth(raw):
                counts["malformed"] += 1
                continue
            try:
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pair_object,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite number")))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                counts["malformed"] += 1
                continue
            if type(value) is not dict:
                counts["malformed"] += 1
                continue
            if counts["lines"] == 1 and "audit_export_version" in value:
                if (value.get("audit_export_version") != 1 or
                        type(value.get("notices")) is not list or
                        type(value.get("gaps")) is not dict):
                    raise ReportError("unsupported audit export schema")
                allowed_notices = {
                    "intentional_retention", "missing_segment", "corrupt_segment",
                    "partial_tail", "unknown_schema", "interrupted_publication",
                    "export_limit", "selected_range", "malformed_record",
                }
                if any(type(item) is not str or item not in allowed_notices
                       for item in value["notices"]):
                    raise ReportError("invalid audit export metadata")
                export_meta = value
                continue
            # Current Agent audit JSONL has no version field. A future explicit
            # version must be reviewed before it can be interpreted as current.
            if "version" in value or "format_version" in value or "contract_version" in value:
                counts["unsupported"] += 1
                unknown_record_schema = True
                continue
            item = _project(value, counts["lines"], sessions, servers, agents, calls,
                            tools, rules, detectors)
            if item is None:
                counts["unsupported"] += 1
                continue
            events.append(item)
            counts["accepted"] += 1
            if item["correlation"] and item["stage"] in ("admission", "result"):
                native_link_candidates.setdefault(item["correlation"], []).append(
                    (item, value.get("tool"), value.get("binding_sha256")))
    for alias, candidates in native_link_candidates.items():
        admissions = [candidate for candidate in candidates if candidate[0]["stage"] == "admission"]
        results = [candidate for candidate in candidates if candidate[0]["stage"] == "result"]
        ambiguous = len(admissions) > 1 or len(results) > 1
        if admissions and results:
            call = admissions[0]
            result = results[0]
            ambiguous = (ambiguous or call[0]["id"] >= result[0]["id"] or
                         call[1] != result[1] or
                         (call[2] is not None and result[2] is not None and call[2] != result[2]))
        if ambiguous:
            for item, _, _ in candidates:
                item["correlation"] = None
                item["evidence_missing"].append("Call/result linkage ambiguous in this report")
    native_by_call: dict[str, set[str]] = {}
    for item in events:
        alias = item["correlation"]
        if alias:
            native_by_call.setdefault(alias, set()).add(item["stage"])
    for item in events:
        alias = item["correlation"]
        if alias:
            stages = native_by_call[alias]
            if item["stage"] == "admission" and "result" not in stages:
                item["evidence_missing"].append("No linked result record in this report")
            if item["stage"] == "result" and "admission" not in stages:
                item["evidence_missing"].append("No linked admission record in this report")
    if counts["malformed"]:
        notices.append("Malformed records were omitted")
    if counts["unsupported"]:
        notices.append("Unsupported events or record versions were omitted")
    if unknown_record_schema:
        notices.append("Unknown audit record schema was omitted")
    if partial:
        notices.append("Counts of unread records are lower bounds; source evidence is incomplete")
    if export_meta is not None:
        labels = {
            "intentional_retention": "Older segments were intentionally pruned by retention policy",
            "missing_segment": "A retained segment is missing; evidence has an unexplained gap",
            "corrupt_segment": "A retained segment failed verification; its records were omitted",
            "partial_tail": "An incomplete final record was retained but omitted",
            "unknown_schema": "The segment manifest or export schema is not recognized",
            "interrupted_publication": "A manifest or pruning operation was interrupted",
            "export_limit": "Export limit reached; later records were omitted",
            "selected_range": "The operator selected only part of retained history",
            "malformed_record": "A malformed source record was omitted",
        }
        notices.extend(labels[item] for item in export_meta["notices"])
        gaps = export_meta["gaps"]
        if set(gaps) != {"intentional", "unexplained", "corrupt"} or any(type(v) is not int or v < 0 or v > 2**53 - 1 for v in gaps.values()):
            raise ReportError("invalid audit export gaps")
        if any(gaps.values()) or export_meta["notices"]:
            partial = True
    return {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "source_status": "partial" if partial or counts["malformed"] or counts["unsupported"] else "complete",
            "totals": counts,
            "limits": {"input_bytes": MAX_INPUT_BYTES, "line_bytes": MAX_LINE_BYTES,
                       "records": MAX_RECORDS, "depth": MAX_DEPTH, "output_bytes": MAX_OUTPUT_BYTES},
            "notices": notices,
            "gaps": export_meta["gaps"] if export_meta is not None else
                    {"intentional": 0, "unexplained": 0, "corrupt": 0},
        }, "events": events,
    }


def _private_output(path: Path, body: bytes) -> None:
    _check_path_components(path)
    parent = path.parent
    if not parent.exists():
        parent.mkdir(mode=0o700)
    if _linux_filesystem(parent) not in PRIVATE_LINUX_FILESYSTEMS:
        raise ReportError("output requires a Linux filesystem with verifiable owner-only permissions")
    parent_fd = _open_dir_nofollow(parent)
    try:
        current = os.fstat(parent_fd)
        if current.st_uid != os.getuid() or current.st_mode & 0o077:
            raise ReportError("output directory must be owner-only (mode 0700) and owned by this user")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        try:
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                raise ReportError("cannot verify private output mode 0600")
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(body)
        except BaseException:
            try:
                os.unlink(path.name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def export_retained(directory: Path, output: Path, from_segment: int | None = None,
                    to_segment: int | None = None, from_ms: int | None = None,
                    to_ms: int | None = None) -> dict[str, object]:
    """Verify and export a bounded selection of real retained JSONL records.

    The export is owner-only raw evidence. The HTML generator still applies its
    allowlist and report-local aliases; this local digest is not authentication.
    """
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise ReportError("retained export currently supports Linux only")
    directory, output = directory.absolute(), output.absolute()
    if directory == output or directory in output.parents:
        raise ReportError("export output must be outside the retained directory")
    if any(v is not None and (v < 0 or v > 2**53 - 1)
           for v in (from_segment, to_segment, from_ms, to_ms)):
        raise ReportError("selection must be a nonnegative finite integer")
    if ((from_segment is not None and to_segment is not None and from_segment > to_segment) or
            (from_ms is not None and to_ms is not None and from_ms > to_ms)):
        raise ReportError("selection range is reversed")
    _check_path_components(directory)
    if _linux_filesystem(directory) not in PRIVATE_LINUX_FILESYSTEMS:
        raise ReportError("retained input requires a supported private Linux filesystem")
    notices: set[str] = set()
    gaps = {"intentional": 0, "unexplained": 0, "corrupt": 0}
    records: list[bytes] = []
    parent_fd = _open_dir_nofollow(directory.parent)
    dir_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent_fd)
    try:
        root_stat = os.fstat(dir_fd)
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o077:
            raise ReportError("retained directory must be owner-only")

        def read_verified(name: str, limit: int) -> bytes | None:
            named_dir = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
            if (named_dir.st_dev, named_dir.st_ino) != (root_stat.st_dev, root_stat.st_ino):
                raise ReportError("retained directory was replaced")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            except FileNotFoundError:
                return None
            except OSError as error:
                raise ReportError("retained segment cannot be opened safely") from error
            try:
                held = os.fstat(fd)
                named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or
                        not stat.S_ISREG(held.st_mode) or held.st_uid != os.getuid() or
                        held.st_nlink != 1 or held.st_mode & 0o077 or held.st_size > limit):
                    raise ReportError("retained segment is unsafe or exceeds limit")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    body = stream.read(limit + 1)
                if len(body) > limit:
                    raise ReportError("retained segment exceeds limit")
                final = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if (final.st_dev, final.st_ino) != (held.st_dev, held.st_ino):
                    raise ReportError("retained segment was replaced during export")
                return body
            finally:
                os.close(fd)

        manifest_raw = read_verified("manifest.json", MAX_MANIFEST_BYTES)
        if manifest_raw is None:
            raise ReportError("retention manifest missing")
        if read_verified("manifest.pending", MAX_MANIFEST_BYTES) is not None:
            notices.add("interrupted_publication")
        try:
            manifest = json.loads(manifest_raw, object_pairs_hook=_pair_object)
            if (type(manifest) is not dict or set(manifest) != {
                    "version", "limits", "generation", "next_id", "pruned_through", "pending_prune", "segments"} or
                    manifest.get("version") != 1 or
                    type(manifest.get("segments")) is not list or
                    type(manifest.get("pruned_through")) is not int or
                    type(manifest.get("next_id")) is not int or
                    type(manifest.get("generation")) is not int or manifest["generation"] < 1 or
                    manifest["pruned_through"] < 0 or manifest["next_id"] < 2):
                raise ValueError("unknown manifest schema")
            limits = manifest.get("limits")
            if (type(limits) is not dict or set(limits) != {
                    "segment_size_bytes", "segment_count", "total_disk_bytes", "max_record_bytes"} or
                    any(type(value) is not int for value in limits.values()) or
                    not 65536 <= limits["segment_size_bytes"] <= MAX_SEGMENT_BYTES or
                    not 2 <= limits["segment_count"] <= 64 or
                    not 256 <= limits["max_record_bytes"] <= MAX_LINE_BYTES or
                    limits["max_record_bytes"] > limits["segment_size_bytes"] or
                    not (limits["segment_count"] * limits["segment_size_bytes"] + 2 * MAX_MANIFEST_BYTES + 4096
                         <= limits["total_disk_bytes"] <= 1024 * 1024 * 1024)):
                raise ValueError("unknown retention limits")
            segments = manifest["segments"]
            if not 1 <= len(segments) <= limits["segment_count"]:
                raise ValueError("invalid segment count")
            previous = manifest["pruned_through"]
            for segment in segments:
                if (type(segment) is not dict or set(segment) != {
                        "id", "closed", "bytes", "sha256", "partial_tail"} or
                        type(segment.get("id")) is not int or
                        segment["id"] != previous + 1 or segment["id"] >= manifest["next_id"] or
                        type(segment.get("closed")) is not bool or
                        type(segment.get("partial_tail")) is not bool or
                        type(segment.get("bytes")) is not int or
                        segment["bytes"] < 0 or segment["bytes"] > limits["segment_size_bytes"]):
                    raise ValueError("manifest order or bound is invalid")
                digest = segment["sha256"]
                if segment["closed"] != (type(digest) is str) or (
                        digest is not None and (len(digest) != 64 or
                                                any(c not in "0123456789abcdef" for c in digest))) or (
                        not segment["closed"] and segment["partial_tail"]):
                    raise ValueError("manifest segment digest is invalid")
                previous = segment["id"]
            if previous + 1 != manifest["next_id"]:
                raise ValueError("manifest order is invalid")
            pending = manifest["pending_prune"]
            if pending is not None and (type(pending) is not int or
                                        len(segments) != limits["segment_count"] or
                                        pending != segments[0]["id"] or not segments[0]["closed"]):
                raise ValueError("manifest prune state is invalid")
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            notices.add("unknown_schema")
            gaps["corrupt"] += 1
            segments = []
            manifest = {}
        if manifest.get("pruned_through", 0) > 0:
            gaps["intentional"] = min(manifest["pruned_through"], 2**53 - 1)
            notices.add("intentional_retention")
        if manifest.get("pending_prune") is not None:
            notices.add("interrupted_publication")
        if any(v is not None for v in (from_segment, to_segment, from_ms, to_ms)):
            notices.add("selected_range")
        used = 0
        for segment in segments:
            segment_id = segment["id"]
            if ((from_segment is not None and segment_id < from_segment) or
                    (to_segment is not None and segment_id > to_segment)):
                continue
            name = f"segment-{segment_id:020}.jsonl"
            body = read_verified(name, limits["segment_size_bytes"])
            if body is None:
                gaps["unexplained"] += 1
                notices.add("missing_segment")
                continue
            if segment["closed"] and (len(body) != segment["bytes"] or
                    hashlib.sha256(body).hexdigest() != segment.get("sha256") or
                    (bool(body) and not body.endswith(b"\n")) != segment["partial_tail"]):
                gaps["corrupt"] += 1
                notices.add("corrupt_segment")
                continue
            if not body.endswith(b"\n") and body:
                notices.add("partial_tail")
                body = body[:body.rfind(b"\n") + 1]
            for raw in body.splitlines(keepends=True):
                if len(raw) > limits["max_record_bytes"]:
                    notices.add("malformed_record")
                    continue
                try:
                    value = json.loads(raw, object_pairs_hook=_pair_object)
                except (UnicodeDecodeError, ValueError):
                    notices.add("malformed_record")
                    continue
                if type(value) is not dict:
                    notices.add("malformed_record")
                    continue
                at_ms = value.get("at_ms")
                if ((from_ms is not None and (type(at_ms) is not int or at_ms < from_ms)) or
                        (to_ms is not None and (type(at_ms) is not int or at_ms > to_ms))):
                    continue
                if used + len(raw) > MAX_INPUT_BYTES - 4096 or len(records) >= MAX_RECORDS - 1:
                    notices.add("export_limit")
                    break
                records.append(raw)
                used += len(raw)
            if "export_limit" in notices:
                break
        if read_verified("manifest.json", MAX_MANIFEST_BYTES) != manifest_raw:
            raise ReportError("retention changed during export; retry")
    finally:
        os.close(dir_fd)
        os.close(parent_fd)
    header = {"audit_export_version": 1, "notices": sorted(notices), "gaps": gaps}
    payload = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode() + b"\n" + b"".join(records)
    if len(payload) > MAX_INPUT_BYTES:
        raise ReportError("export exceeds input byte limit")
    _private_output(output, payload)
    return {"records": len(records), "notices": sorted(notices), "gaps": gaps}


def generate(source: Path, output: Path, template: Path | None = None) -> dict[str, object]:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise ReportError("report generation currently supports Linux file permissions only")
    source = source.absolute()
    output = output.absolute()
    if source == output:
        raise ReportError("source and output must differ")
    report = _read_report(source)
    template = template or Path(__file__).with_name("agent-audit-explorer.html")
    markup = template.read_text(encoding="utf-8")
    marker = "__AUDIT_DATA__"
    if markup.count(marker) != 1:
        raise ReportError("HTML template must contain exactly one data placeholder")
    payload = json.dumps(report, ensure_ascii=True, separators=(",", ":"))
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    payload = payload.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    body = markup.replace(marker, payload).encode("utf-8")
    if len(body) > MAX_OUTPUT_BYTES:
        raise ReportError(f"report exceeds {MAX_OUTPUT_BYTES} byte limit")
    _private_output(output, body)
    return report["meta"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="explicit regular Agent audit JSONL or export path")
    source.add_argument("--retained-dir", type=Path, help="verified Linux retention directory to export")
    parser.add_argument("--output", required=True, type=Path, help="new private HTML report or JSONL export")
    parser.add_argument("--from-segment", type=int)
    parser.add_argument("--to-segment", type=int)
    parser.add_argument("--from-ms", type=int)
    parser.add_argument("--to-ms", type=int)
    args = parser.parse_args()
    try:
        if args.retained_dir:
            meta = export_retained(args.retained_dir, args.output, args.from_segment,
                                   args.to_segment, args.from_ms, args.to_ms)
            print(f"Private verified export written: {args.output} ({meta['records']} records; {', '.join(meta['notices']) or 'no gaps detected'})")
            return 0
        if any(value is not None for value in (args.from_segment, args.to_segment, args.from_ms, args.to_ms)):
            raise ReportError("range options require --retained-dir")
        meta = generate(args.input, args.output)
    except (ReportError, OSError) as error:
        parser.exit(2, f"audit report: {error}\n")
    print(f"Report written: {args.output} ({meta['totals']['accepted']} accepted records; {meta['source_status']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
