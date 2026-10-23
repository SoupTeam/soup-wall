# SPDX-License-Identifier: Apache-2.0
"""SOU-124 latency bookkeeping. Never changes timeouts or admission policy."""
import math


def summarize(cases, planned_per_profile):
    if type(planned_per_profile) is not int or not 20 <= planned_per_profile <= 100:
        raise ValueError("latency_sample_plan_invalid")
    report = {}
    for profile in ("filesystem", "git"):
        rows = [r for r in cases if r.get("profile") == profile and r.get("case") == "approve"]
        indices = [r.get("sample_index") for r in rows]
        if (len(rows) > planned_per_profile or len(set(indices)) != len(indices)
                or any(type(i) is not int or not 0 <= i < planned_per_profile for i in indices)):
            raise ValueError("latency_duplicate_or_invalid_sample")
        successful, failed = [], 0
        for row in rows:
            elapsed = row.get("decision_to_result_ms")
            if (row.get("passed") is True and row.get("approved") is True
                    and row.get("released") is True and type(row.get("dispatched")) is int
                    and row.get("dispatched") == 1
                    and type(row.get("kernel_effects")) is int and row.get("kernel_effects") == 1 and type(elapsed) in (int, float)
                    and math.isfinite(elapsed) and elapsed >= 0):
                successful.append(elapsed)
            else:
                failed += 1
        successful.sort()
        def percentile(fraction):
            return successful[math.ceil(len(successful) * fraction) - 1] if successful else None
        p95 = percentile(.95)
        incomplete = planned_per_profile - len(rows)
        report[profile] = {
            "planned": planned_per_profile, "successful": len(successful),
            "failed": failed, "incomplete": incomplete,
            "p50_ms": percentile(.5), "p95_ms": p95,
            "metric": "operator_attempt_to_correlated_original_result_monotonic",
            "target_ms": 3000,
            "target_met": failed == incomplete == 0 and p95 is not None and p95 <= 3000,
        }
    report["status"] = ("target_met" if all(report[p]["target_met"] for p in ("filesystem", "git"))
                        else "performance_blocker")
    return report


def collector_stderr_rows(lines, collector_pid):
    """Decode only a selected collector's bounded, kernel-observed stderr."""
    import ast
    import json
    import re
    buffer = b""
    observations = []
    active = {collector_pid}
    for line in lines:
        owner = re.match(r'^(\d+)\s+', line)
        if not owner or int(owner[1]) not in active:
            continue
        clone = re.match(r'^\d+\s+clone(?:3)?\(.*?flags=([^,}]+).*\)\s*=\s*(\d+)$', line)
        if clone and 'CLONE_THREAD' in clone[1].split('|'):
            active.add(int(clone[2]))
        if re.match(r'^\d+\s+exit_group\(', line):
            active.clear()
        elif re.match(r'^\d+\s+(?:exit\(|\+\+\+ (?:exited with|killed by))', line):
            active.discard(int(owner[1]))
        if not re.match(r'^\d+\s+(?:write|writev)\(2,', line):
            continue
        scalar = re.fullmatch(r'\d+\s+write\(2,\s*("(?:[^"\\]|\\.)*"),\s*(\d+)\)\s*=\s*(\d+|-1 [^\n]+)', line)
        vector = re.fullmatch(r'\d+\s+writev\(2,\s*\[(.*)\],\s*\d+\)\s*=\s*(\d+|-1 [^\n]+)', line)
        if scalar:
            raw = ast.literal_eval("b" + scalar[1])
            count = int(scalar[2])
            result = scalar[3]
        elif vector:
            pieces = re.findall(r'iov_base=("(?:[^"\\]|\\.)*"), iov_len=(\d+)', vector[1])
            if not pieces or len(pieces) != vector[1].count("iov_base="):
                raise ValueError("reuse_diagnostic_write_unobserved")
            decoded = [(ast.literal_eval("b" + raw), int(size)) for raw, size in pieces]
            if any(len(raw) != size for raw, size in decoded):
                raise ValueError("reuse_diagnostic_write_truncated")
            raw = b"".join(raw for raw, _ in decoded)
            count, result = len(raw), vector[2]
        else:
            raise ValueError("reuse_diagnostic_write_unobserved")
        written = 0 if result.startswith("-1 ") else int(result)
        if len(raw) < written or written > count:
            raise ValueError("reuse_diagnostic_write_truncated")
        buffer += raw[:written]
        if len(buffer) > 262144:
            raise ValueError("reuse_diagnostic_limit")
        while b"\n" in buffer:
            payload, buffer = buffer.split(b"\n", 1)
            try:
                row = json.loads(payload)
            except (ValueError, UnicodeError):
                continue
            if isinstance(row, dict):
                observations.append(row)
    return observations


def reuse_observation(lines, collector_pid):
    """Counts are an exact selected collector event, not a timing inference."""
    observations = []
    for row in collector_stderr_rows(lines, collector_pid):
        if row.get("event") != "mcp_verified_inputs_resume":
            continue
        keys = ("immutable_files", "leased_files", "rehashed_files")
        if any(type(row.get(key)) is not int or row[key] < 0 for key in keys):
            raise ValueError("reuse_counts_invalid")
        observations.append({key: row[key] for key in keys})
    if len(observations) != 1:
        raise ValueError("one_selected_reuse_observation_required")
    return dict(observations[0], observer="collector mcp_verified_inputs_resume")
