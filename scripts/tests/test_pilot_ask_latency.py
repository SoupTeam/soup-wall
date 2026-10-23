# SPDX-License-Identifier: Apache-2.0
"""Measurement controls, not Linux performance or host qualification evidence."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("ask_latency", Path(__file__).resolve().parents[1] / "pilot_ask_latency.py")
LATENCY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LATENCY)


class AskLatencyAccounting(unittest.TestCase):
    def rows(self):
        return [dict(profile=p, case="approve", sample_index=i, passed=True, approved=True,
                     released=True, dispatched=1, kernel_effects=1, decision_to_result_ms=100 + i)
                for p in ("filesystem", "git") for i in range(20)]

    def test_nearest_rank_percentiles_and_complete_denominator(self):
        result = LATENCY.summarize(self.rows(), 20)
        self.assertEqual(result["status"], "target_met")
        self.assertEqual(result["git"]["p50_ms"], 109)
        self.assertEqual(result["git"]["p95_ms"], 118)
        self.assertEqual(result["filesystem"]["successful"], 20)

    def test_failed_and_unrun_samples_are_never_dropped(self):
        rows = self.rows()[:-1]
        rows[0]["passed"] = False
        result = LATENCY.summarize(rows, 20)
        self.assertEqual(result["status"], "performance_blocker")
        self.assertEqual(result["filesystem"]["failed"], 1)
        self.assertEqual(result["git"]["incomplete"], 1)

    def test_target_miss_is_a_performance_blocker(self):
        rows = self.rows()
        for row in rows:
            row["decision_to_result_ms"] = 3001
        result = LATENCY.summarize(rows, 20)
        self.assertEqual(result["status"], "performance_blocker")
        self.assertEqual(result["git"]["p95_ms"], 3001)

    def test_missing_effects_invalid_values_and_bool_timings_fail(self):
        for update in ({"dispatched": 0}, {"kernel_effects": 0}, {"approved": False},
                       {"released": False}, {"decision_to_result_ms": True},
                       {"decision_to_result_ms": float("nan")}, {"decision_to_result_ms": -1}):
            rows = self.rows()
            rows[0].update(update)
            self.assertEqual(LATENCY.summarize(rows, 20)["filesystem"]["failed"], 1)

    def test_duplicates_and_small_denominators_refuse(self):
        rows = self.rows()
        rows[1]["sample_index"] = 0
        with self.assertRaises(ValueError):
            LATENCY.summarize(rows, 20)
        for size in (0, 19, True, 101):
            with self.assertRaises(ValueError):
                LATENCY.summarize([], size)
