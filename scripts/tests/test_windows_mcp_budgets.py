# SPDX-License-Identifier: Apache-2.0
"""Adversarial report grading; these synthetic rows are NOT Windows acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-windows-mcp-budgets.py"
SPEC = importlib.util.spec_from_file_location("windows_budget_acceptance", SCRIPT)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def row(name="wall"):
    config = H.BASE_CONFIG.copy()
    if name == "cpu":
        config["cpuUserMillis"] = 1000
    if name == "wall":
        config["wallMillis"] = 5000
    ordered = {key: config[key] for key in ("format", "memoryMaxBytes", "memoryPressureBytes", "activeProcessMax", "cpuUserMillis", "wallMillis")}
    return {"case": name, "passed": True, "useful": True, "collector_pid": 50,
            "capture_complete": True, "forced_cleanup": False, "late_result_released": False, "exit_code": 1,
            "native_epoch_sha256": "a" * 64, "native_terminal": "native_session_retired", "native_calls": 2, "native_results": 1,
            "configuration": config.copy(), "executed_effect_retained": True,
            "elapsed_seconds": 6, "witness": {"peak_owned_processes": 5,
                "observer_stopped": True, "observer_error": None, "all_stopped": True,
                "peak_aggregate_private_bytes": 120 * 1024**2,
                "peak_owned_child_private_bytes": 120 * 1024**2,
                "processes": [{"pid": 50, "stopped": True, "cpu_user_100ns": 20000000, "peak_private_bytes": 30 * 1024**2}] + [
                    {"pid": pid, "stopped": True, "cpu_user_100ns": 3000000, "peak_private_bytes": 50 * 1024**2} for pid in (51, 52, 53)]},
            "budget_events": [{"cleanup_verified": True, "effects_rolled_back": False,
                "budget": {"launch_ownership": "job_list_before_execution", "configuration": config.copy(), "configuration_sha256": H.sha(json.dumps(ordered,separators=(",", ":")).encode()), "observed": {
                    "reason": "windows_budget_wall_deadline", "closed": True, "raw_job_peak_bytes": 170 * 1024**2,
                    "peak_active_processes": 5, "total_processes": 6}}}]}


def memory_controls():
    return [{"mode": mode, "exit_code": 0, "status": "complete", "hard_bytes": 64 * 1024**2,
             "successful_commit_bytes": 16 * 1024**2, "large_request_bytes": 96 * 1024**2,
             "virtual_refused": True, "virtual_error": 1816, "heap_refused": True,
             "before": {"private_committed_bytes": 30 * 1024**2, "raw_job_peak_bytes": 30 * 1024**2},
             **{phase: {"private_committed_bytes": 30 * 1024**2, "raw_job_peak_bytes": 128 * 1024**2}
                for phase in ("after_virtual", "after_heap")}}
            for mode in ("hard_only", "with_notification")]


class ReportGrading(unittest.TestCase):
    def test_complete_typed_wall_row_passes(self):
        H.grade(row())

    def test_prior_pass_cannot_hide_failure_or_incomplete_cleanup(self):
        for mutation in (lambda r: r.update(passed=False),
                         lambda r: r["budget_events"][0].update(cleanup_verified=False),
                         lambda r: r.update(useful=False),
                         lambda r: r.update(executed_effect_retained=False),
                         lambda r: r.update(elapsed_seconds=14),
                         lambda r: r.update(forced_cleanup=True),
                         lambda r: r.update(late_result_released=True),
                         lambda r: r.update(capture_complete=False),
                         lambda r: r["witness"].update(peak_owned_child_private_bytes=r["configuration"]["memoryMaxBytes"] + 65536),
                         lambda r: r["witness"].update(observer_error="TimeoutError"),
                         lambda r: r["witness"]["processes"][1].update(stopped=False),
                         lambda r: r["budget_events"][0].update(effects_rolled_back=True)):
            with self.subTest(mutation=mutation):
                candidate = row()
                mutation(candidate)
                with self.assertRaises(ValueError):
                    H.grade(candidate)

    def test_cpu_uses_descendants_and_never_collector_cpu(self):
        candidate = row("cpu")
        candidate["budget_events"][0]["budget"]["observed"]["reason"] = "windows_budget_cpu_time"
        H.grade(candidate)
        for process in candidate["witness"]["processes"]:
            if process["pid"] != candidate["collector_pid"]:
                process["cpu_user_100ns"] = 0
        with self.assertRaisesRegex(ValueError, "independent_cpu"):
            H.grade(candidate)

    def test_memory_needs_aggregate_and_independent_allocation(self):
        candidate = row("memory")
        candidate["budget_events"][0]["budget"]["observed"]["reason"] = "windows_budget_memory_pressure"
        H.grade(candidate)
        bad = copy.deepcopy(candidate)
        bad["witness"]["peak_owned_child_private_bytes"] = 0
        with self.assertRaises(ValueError):
            H.grade(bad)
        bad = copy.deepcopy(candidate)
        bad["witness"]["processes"][1]["peak_private_bytes"] = 200 * 1024**2
        with self.assertRaisesRegex(ValueError, "not_aggregate"):
            H.grade(bad)

    def test_launch_refusal_that_executes_server_cannot_pass(self):
        candidate = row("missing-config")
        candidate["server_started"] = True
        with self.assertRaisesRegex(ValueError, "executed_server"):
            H.grade(candidate)

    def test_hard_memory_requires_two_successes_then_actual_refusal_below_the_cap(self):
        candidate = row("memory-hard")
        candidate.update(allocation_attempts=3, allocation_successes=2, allocation_refusals=1)
        candidate["budget_events"][0]["budget"]["observed"]["reason"] = "windows_budget_memory_limit"
        for process in candidate["witness"]["processes"][1:3]:
            process["peak_private_bytes"] = 80 * 1024**2
        H.grade(candidate)
        for mutation in (lambda r: r.update(allocation_attempts=2),
                         lambda r: r.update(allocation_successes=1),
                         lambda r: r.update(allocation_refusals=0),
                         lambda r: r["witness"]["processes"][2].update(peak_private_bytes=0),
                         lambda r: r["budget_events"][0]["budget"]["observed"].update(
                             raw_job_peak_bytes=r["configuration"]["memoryMaxBytes"] + 65536)):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(candidate)
                mutation(bad)
                with self.assertRaises(ValueError):
                    H.grade(bad)

    def test_wrong_bootstrap_error_cannot_earn_a_launch_refusal_pass(self):
        for name, code in H.REFUSALS.items():
            candidate = row(name)
            candidate.update(server_started=False, launch_refusal_code=code)
            H.grade(candidate)
            candidate["launch_refusal_code"] = None
            with self.assertRaisesRegex(ValueError, "wrong_launch_refusal_reason"):
                H.grade(candidate)
        self.assertIsNone(H.refusal_code(b"unrelated bootstrap or authentication failure"))
        self.assertEqual(H.refusal_code(b"Error: native_child_spawn"), "native_child_spawn")
        self.assertIsNone(H.refusal_code(b"native_child_spawn windows_budget_configuration_refused"))

    def test_atomic_launch_controls_cannot_pass_by_zero_tests_or_skips(self):
        controls = [{"test": name, "exit_code": 0, "exact_one_passed": True} for name in H.LAUNCH_CONTROLS]
        H.grade_launch_controls(controls)
        with self.assertRaises(ValueError):
            H.grade_launch_controls(controls[:1])
        controls[0]["exact_one_passed"] = False
        with self.assertRaises(ValueError):
            H.grade_launch_controls(controls)

    def test_memory_calibration_requires_actual_refusals_and_bounded_private_commit(self):
        controls = memory_controls()
        H.grade_memory_controls(controls)
        for mutation in (lambda c: c.pop(), lambda c: c[0].update(virtual_refused=False),
                         lambda c: c[0].update(heap_refused=False), lambda c: c[0].update(virtual_error=5),
                         lambda c: c[0]["after_virtual"].update(private_committed_bytes=65 * 1024**2)):
            bad = copy.deepcopy(controls)
            mutation(bad)
            with self.assertRaises(ValueError):
                H.grade_memory_controls(bad)

    def test_raw_peak_excess_requires_calibration_and_real_bounded_allocations(self):
        candidate = row("memory-hard")
        candidate.update(allocation_attempts=3, allocation_successes=2, allocation_refusals=1)
        observed = candidate["budget_events"][0]["budget"]["observed"]
        observed.update(reason="windows_budget_memory_limit", raw_job_peak_bytes=323 * 1024**2)
        for process in candidate["witness"]["processes"][1:3]:
            process["peak_private_bytes"] = 80 * 1024**2
        H.grade(candidate, memory_controls())
        with self.assertRaisesRegex(ValueError, "uncalibrated"):
            H.grade(candidate)
        for mutation in (lambda r: r.update(allocation_successes=1),
                         lambda r: r.update(allocation_refusals=0),
                         lambda r: r["witness"].update(peak_owned_child_private_bytes=257 * 1024**2)):
            bad = copy.deepcopy(candidate)
            mutation(bad)
            with self.assertRaises(ValueError):
                H.grade(bad, memory_controls())
        for mutation in (lambda c: c[0].update(virtual_refused=False),
                         lambda c: c[0]["after_virtual"].update(raw_job_peak_bytes=63 * 1024**2),
                         lambda c: c[0]["after_virtual"].update(private_committed_bytes=65 * 1024**2),
                         lambda c: c[0]["before"].update(raw_job_peak_bytes=128 * 1024**2)):
            bad = memory_controls()
            mutation(bad)
            with self.assertRaises(ValueError):
                H.grade(candidate, bad)

    def test_case_set_contains_every_required_positive_and_restart(self):
        self.assertEqual(len(H.CASES), 20)
        self.assertEqual(len(set(H.CASES)), len(H.CASES))
        self.assertTrue({"memory", "process", "cpu", "wall", "collector-death", "cancel", "breakaway"} <= set(H.CASES))
        self.assertEqual(sum(name.startswith("restart-") for name in H.CASES), 6)


if __name__ == "__main__":
    unittest.main()
