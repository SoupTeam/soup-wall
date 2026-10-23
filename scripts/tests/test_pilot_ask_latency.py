# SPDX-License-Identifier: Apache-2.0
"""Measurement controls, not Linux performance or host qualification evidence."""
import importlib.util
from pathlib import Path
import unittest
import io
import itertools
import json
import sys
import tempfile
from unittest.mock import Mock, patch

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


class AskPerformanceCli(unittest.TestCase):
    def test_accounting_and_cleanup_failures_cannot_skip_remaining_owned_cleanup(self):
        spec = importlib.util.spec_from_file_location("ask_cleanup_cli", Path(__file__).resolve().parents[1] / "qualify-pilot-ask.py")
        ask = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ask)
        for accounting_fails, host_fails, daemon_fails in itertools.product((False, True), repeat=3):
            with self.subTest(accounting=accounting_fails, host=host_fails, daemon=daemon_fails):
                report, cases = {}, []
                first, second, daemon = Mock(), Mock(), Mock()
                if host_fails:
                    first.close.side_effect = RuntimeError("owned_cleanup_failed")
                metric_error = ValueError("latency_sample_plan_invalid") if accounting_fails else None
                daemon_error = RuntimeError("owned_daemon_cleanup_failed") if daemon_fails else None
                with patch.object(ask.LATENCY, "summarize", side_effect=metric_error,
                                  return_value={"status": "performance_blocker"}), patch.object(ask, "stop", side_effect=daemon_error) as stop:
                    if accounting_fails or host_fails or daemon_fails:
                        expected = RuntimeError if host_fails or daemon_fails else ValueError
                        with self.assertRaises(expected):
                            ask.finish_qualification(report, cases, 20, [first, second], daemon)
                    else:
                        ask.finish_qualification(report, cases, 20, [first, second], daemon)
                self.assertIs(report["cases"], cases)
                first.close.assert_called_once_with()
                second.close.assert_called_once_with()
                stop.assert_called_once_with(daemon)

    def test_cli_never_reports_success_for_a_missed_performance_target(self):
        spec = importlib.util.spec_from_file_location("ask_latency_cli", Path(__file__).resolve().parents[1] / "qualify-pilot-ask.py")
        ask = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ask)
        for samples, target_met in [(0, False), (20, False), (20, True)]:
            with self.subTest(samples=samples, target_met=target_met), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                argv = ["qualify-pilot-ask"]
                for name in ("agentfw", "git-launcher", "claude", "node", "npm", "bwrap", "git", "strace"):
                    argv += ["--" + name, str(root / "not-executed")]
                argv += ["--output", str(root / "out"), "--approval-samples", str(samples)]
                def qualified(_args, _private, report):
                    report.update(status="pass", latency={"status": "target_met" if target_met else "performance_blocker"})
                with patch.object(ask, "qualify", side_effect=qualified), patch.object(sys, "argv", argv), patch("sys.stdout", new_callable=io.StringIO):
                    code = ask.main()
                report = json.loads((root / "out" / "qualification.json").read_text())
                blocked = samples != 0 and not target_met
                self.assertEqual(code, 1 if blocked else 0)
                self.assertEqual(report["status"], "performance_blocker" if blocked else "pass")
