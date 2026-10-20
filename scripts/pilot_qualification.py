# SPDX-License-Identifier: Apache-2.0
"""Bounded, content-free outcome contract for the installed development pilot.

This is measurement bookkeeping, not an approval or a security oracle. Runtime
assertions use original host results, native audit and independent OS witnesses.
An interrupted case keeps its original denominator and cannot become a pass.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import time

FORMAT = "sw-installed-pilot/1"
CASES = (
    "exact-installed-inputs", "sandbox-positive", "witness-calibration",
    "read-and-history", "inspect-and-diff", "untrusted-input-refusal",
    "independent-conversation", "parallel-cancellation", "collector-recovery",
    "daemon-fresh-conversation", "bad-input-controls", "final-cleanup",
)
STATES = ("passed", "failed", "incomplete", "unsupported")
LIMITS = {"case_seconds": 180, "setup_seconds": 600, "recovery_seconds": 15,
          "host_bytes": 8 * 1024 * 1024, "report_bytes": 256 * 1024,
          "provider_requests": 32, "benign_workflows": 2}


class Failure(ValueError):
    def __init__(self, code):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            raise ValueError("static_failure_code_required")
        super().__init__(code)
        self.code = code


def require(value, code):
    if not value:
        raise Failure(code)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def new_report():
    return {"format": FORMAT, "observed_at": datetime.now(timezone.utc).isoformat(),
            "status": "incomplete", "scope": "development-installed-host-scripted-provider",
            "live_model_effectiveness": "not_measured", "pilot_readiness": "not_certified",
            "limits": LIMITS.copy(), "required": len(CASES),
            "cases": [{"id": name, "status": "incomplete", "reason": "not_executed",
                       "elapsed_ms": None, "evidence": {}} for name in CASES],
            "benign_workflows": {"required": 2, "completed": 0, "false_interruptions": 0,
                                 "incomplete": 2}, "remaining_blockers": []}


def finish(report):
    rows = report["cases"]
    require([r["id"] for r in rows] == list(CASES), "original_case_denominator_changed")
    for row in rows:
        require(row["status"] in STATES, "invalid_outcome")
        duration = row["elapsed_ms"]
        require(duration is None or (type(duration) in (int, float)
                and math.isfinite(duration) and duration >= 0), "invalid_duration")
        require(row["status"] != "passed" or (duration is not None and row["reason"] is None
                and row["evidence"]), "pass_without_evidence")
    report["counts"] = {state: sum(row["status"] == state for row in rows) for state in STATES}
    workflows = report["benign_workflows"]
    require(workflows["required"] == 2 and all(type(workflows[k]) is int and 0 <= workflows[k] <= 2
            for k in ("completed", "false_interruptions", "incomplete"))
            and workflows["completed"] + workflows["false_interruptions"] + workflows["incomplete"] == 2,
            "benign_denominator_changed")
    report["status"] = ("passed" if report["counts"]["passed"] == len(CASES)
                         and workflows["completed"] == 2 else "failed" if report["counts"]["failed"]
                         else "unsupported" if report["counts"]["unsupported"] else "incomplete")
    require(len(canonical(report)) <= LIMITS["report_bytes"], "public_report_exceeds_bound")
    return report


def measure(report, name, action, *, timeout=None):
    row = next(row for row in report["cases"] if row["id"] == name)
    require(row["reason"] == "not_executed", "case_already_executed")
    started = time.monotonic()
    try:
        row["evidence"] = action()
        require(row["evidence"], "empty_case_evidence")
        require(time.monotonic() - started <= (timeout or LIMITS["case_seconds"]), "case_deadline_exceeded")
        row.update(status="passed", reason=None)
        return True
    except Failure as error:
        row.update(status="failed", reason=error.code)
    except Exception as error:
        # Imported driver messages may contain original arguments, tokens or
        # host text. Only the exception type goes into the public result.
        row.update(status="failed", reason="runtime_" + type(error).__name__.lower())
    finally:
        row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return False


def write_report(path, report):
    payload = json.dumps(finish(report), indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with Path(path).open("x", encoding="utf-8") as stream:
        Path(path).chmod(0o600)
        stream.write(payload)
