#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare cold Cargo and receipt-verified test-binary execution in one native job."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re


RESULT = re.compile(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def timing(path: Path) -> tuple[float, float]:
    fields = path.read_text(encoding="ascii").strip().split()
    if len(fields) != 3:
        raise ValueError("timing_record_invalid")
    elapsed, user, system = map(float, fields)
    if not all(math.isfinite(value) and value >= 0 for value in (elapsed, user, system)):
        raise ValueError("timing_record_invalid")
    return elapsed, user + system


def cases(path: Path) -> int:
    data = path.read_text(encoding="utf-8", errors="replace")
    matches = RESULT.findall(data)
    if len(matches) != 1:
        raise ValueError("test_result_missing_or_ambiguous")
    passed, failed, ignored = map(int, matches[0])
    if not passed or failed or ignored:
        raise ValueError("test_result_incomplete")
    return passed


def compare(records: Path, expected_commit: str) -> dict:
    verified = json.loads((records / "verified-source-build.json").read_text())
    receipt = json.loads(Path(verified["receipt"]).read_text())
    if verified["status"] != "verified-reuse" or receipt["source"]["commit"] != expected_commit:
        raise ValueError("source_identity_mismatch")
    cold_cases, reused_cases = cases(records / "cold.log"), cases(records / "reused.log")
    if cold_cases != reused_cases:
        raise ValueError("acceptance_coverage_mismatch")
    cold_elapsed, cold_cpu = timing(records / "cold.time")
    verify_elapsed, verify_cpu = timing(records / "verify.time")
    reuse_elapsed, reuse_cpu = timing(records / "reused.time")
    after_elapsed, after_cpu = verify_elapsed + reuse_elapsed, verify_cpu + reuse_cpu
    return {
        "format": "sou217-native-lib-test-reuse/1", "status": "passed",
        "source_commit": expected_commit, "receipt_sha256": verified["receipt_sha256"],
        "selected_test_cases": cold_cases, "cold_compilation_and_test": {
            "elapsed_seconds": cold_elapsed, "cpu_seconds": cold_cpu},
        "verified_reuse_and_test": {
            "elapsed_seconds": round(after_elapsed, 3), "cpu_seconds": round(after_cpu, 3)},
        "repeated_segment_elapsed_reduction_percent": round(
            100 * (cold_elapsed - after_elapsed) / cold_elapsed, 1) if cold_elapsed else 0,
        "repeated_segment_cpu_reduction_percent": round(
            100 * (cold_cpu - after_cpu) / cold_cpu, 1) if cold_cpu else 0,
        "cold_execution_replaced_by_reuse": False,
        "runtime_qualification_inferred": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(compare(args.records, args.expected_commit), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)[:120]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
