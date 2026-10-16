#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish bounded owned CI diagnostics without changing raw evidence or verdicts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

MAX_SUMMARY_BYTES = 149000
MAX_INPUT_BYTES = 32 * 1024 * 1024


def bounded_text(value, limit):
    raw = value.encode("utf-8")
    if len(raw) <= limit:
        return value
    notice = "\n[TRUNCATED: section exceeded its diagnostic byte limit; complete bytes remain in the retained CI artifact]\n"
    return raw[:max(0, limit - len(notice.encode()))].decode("utf-8", errors="ignore") + notice


def sanitize(value):
    # Sources are owned fixture logs, not arbitrary environment or transcript
    # dumps. Still redact accidental authentication fields defensively.
    value = re.sub(r"(?i)\bBearer\s+[^\s\"',;]+", "Bearer [REDACTED]", value)
    value = re.sub(r'(?i)("(?:token|native-token|password|authorization)"\s*:\s*)"[^"\r\n]*"', r'\1"[REDACTED]"', value)
    return value.replace("~~~", "~~ ~")


def read_text(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("owned diagnostic input exceeds 32 MiB")
    return raw.decode("utf-8-sig", errors="replace")


def diagnostics(root):
    sections = []
    router = root / "sou60-router.log"
    sections.append(("Native router regression log", read_text(router) if router.is_file() else "Router log unavailable.", 45000))
    output = root / "sou60-standard-user"
    acceptance = output / "acceptance.json"
    if acceptance.is_file():
        try:
            report = json.loads(read_text(acceptance))
            status = {key: report.get(key) for key in
                ("status", "acceptance_passed", "error", "summary", "source_binary_stable",
                 "binary_sha256", "native_test_binary_sha256", "driver_sha256", "fixture_sha256",
                 "reused_helpers_sha256", "reused_windows_helpers_sha256", "kill_on_close_process_job")}
            # Provenance is explicitly selected: no working paths, transcripts,
            # security descriptors, arguments or additional report fields.
            source = report.get("source_before") or {}
            environment = report.get("environment") or {}
            status["source_before"] = {key: source.get(key) for key in ("commit", "tracked_dirty", "untracked_present")}
            standard = report.get("standard_user") or {}
            status["standard_user"] = {key: standard.get(key) for key in ("is_administrator", "administrator_group_present")}
            status["environment"] = {key: environment.get(key) for key in ("os", "architecture", "python")}
            sections.append(("Standard-user acceptance status", json.dumps(status, indent=2), 7000))
            native = report.get("native_tests") or {}
            sections.append(("Standard-user native tests stdout", str(native.get("stdout", "Native test stdout unavailable.")), 40000))
            sections.append(("Standard-user native tests stderr", str(native.get("stderr", "Native test stderr unavailable.")), 10000))
            cases = [{key: row.get(key) for key in ("case", "error", "grade", "owned_fixture_removed")}
                     for row in report.get("cases", [])]
            sections.append(("Standard-user case errors and grades", json.dumps(cases, indent=2), 25000))
        except (OSError, ValueError, TypeError) as error:
            sections.append(("Standard-user report parsing", type(error).__name__ + ": " + str(error), 3000))
    else:
        sections.append(("Standard-user acceptance", "acceptance.json unavailable; no passing evidence inferred.", 3000))
    launcher = output / "launcher.json"
    if launcher.is_file():
        try:
            report = json.loads(read_text(launcher))
            sections.append(("Standard-user launcher errors", json.dumps({key: report.get(key) for key in
                ("status", "error", "cleanup_error", "child_exit_code", "timed_out", "account_removed", "staging_removed")}, indent=2), 5000))
        except (OSError, ValueError, TypeError) as error:
            sections.append(("Standard-user launcher parsing", type(error).__name__ + ": " + str(error), 3000))
    else:
        sections.append(("Standard-user launcher", "launcher.json unavailable.", 3000))
    parts = ["## Native Windows diagnostics\n\nOwned fixture diagnostics only. Raw evidence and failing job outcomes remain unchanged.\n\n"]
    used = len(parts[0].encode())
    for label, value, limit in sections:
        body = bounded_text(sanitize(value), limit)
        block = "### " + label + "\n\n~~~text\n" + body + "\n~~~\n\n"
        remaining = MAX_SUMMARY_BYTES - used
        if len(block.encode()) > remaining:
            block = bounded_text(block, max(0, remaining - 128))
            parts.append(block + "\n[TRUNCATED: total diagnostic summary reached its 149000-byte limit]\n")
            break
        parts.append(block)
        used += len(block.encode())
    return "".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    with args.summary.open("a", encoding="utf-8") as stream:
        stream.write(diagnostics(args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
