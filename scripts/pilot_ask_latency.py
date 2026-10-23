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
