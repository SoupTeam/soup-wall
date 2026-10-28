# SPDX-License-Identifier: Apache-2.0
"""Adversarial report grading; these synthetic rows are NOT Windows acceptance."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest import mock

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


class FailureRetention(unittest.TestCase):
    def test_unconsumed_log_frames_do_not_stall_a_long_lived_daemon_pipe(self):
        raw = b'{"event":"owned-log"}\n' * 200
        log = H.Capture(io.BytesIO(raw), protocol_frames=False)
        self.assertEqual(log.finish(), raw)
        self.assertIsNone(log.error)
        self.assertFalse(log.thread.is_alive())
        self.assertEqual(log.frames.qsize(), 0)
        # A real protocol queue retains its original finite overflow refusal.
        protocol = H.Capture(io.BytesIO(raw))
        self.assertLess(len(protocol.finish()), len(raw))
        self.assertEqual(protocol.error, "Full")
        self.assertEqual(protocol.frames.qsize(), 64)

    def test_log_mode_keeps_original_line_and_total_byte_refusals(self):
        for raw in (b'x' * 16385 + b'\n', (b'x' * 1023 + b'\n') * 257):
            capture = H.Capture(io.BytesIO(raw), protocol_frames=False)
            data = capture.finish()
            self.assertEqual(capture.error, "ValueError")
            self.assertLessEqual(len(data), 256 * 1024)
            self.assertFalse(capture.thread.is_alive())

    def test_fallback_cleanup_retains_primary_error_and_still_fails(self):
        report = {"status": "fail", "error": "protocol_result_missing",
                  "active_case": "restart-2", "active_phase": "initialize_client"}
        H.cleanup_failure(report, "unfinished_owned_collector")
        self.assertEqual(report["error"], "protocol_result_missing")
        self.assertEqual(report["active_case"], "restart-2")
        self.assertEqual(report["active_phase"], "initialize_client")
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["cleanup_errors"], ["unfinished_owned_collector"])
        with self.assertRaises(ValueError):
            H.grade_report(report)

    def test_cleanup_failure_cannot_leave_an_otherwise_successful_report_green(self):
        report = {"status": "pass", "error": None}
        H.cleanup_failure(report, "unfinished_owned_collector")
        H.cleanup_failure(report, "unfinished_owned_collector")
        self.assertEqual(report["error"], "unfinished_owned_collector")
        self.assertEqual(report["status"], "fail")
        self.assertEqual(len(report["cleanup_errors"]), 1)
        with self.assertRaises(ValueError):
            H.grade_report(report)


class ProcessAPI:
    """Deterministic Toolhelp/handle races, not native Windows acceptance."""
    def __init__(self):
        self.k = self.p = self
        self.clock, self.next_handle = 10000, 0
        self.current, self.open_handles, self.closed, self.snapshot_rows = {}, {}, [], []
        self.add(10, 0, 100)

    def add(self, pid, parent, created, exited=0):
        self.current[pid] = SimpleNamespace(created=created, exited=exited, private=1024,
                                            kernel=2, user=3)
        self.snapshot_rows = [(p, pp) for p, pp in self.snapshot_rows if p != pid] + [(pid, parent)]
        return self.current[pid]

    def now_100ns(self):
        return self.clock

    def snapshot(self):
        return list(self.snapshot_rows)

    def OpenProcess(self, access, inherit, pid):
        if pid not in self.current:
            return None
        self.next_handle += 1
        self.open_handles[self.next_handle] = self.current[pid]
        return self.next_handle

    def CloseHandle(self, handle):
        self.closed.append(handle)
        del self.open_handles[handle]
        return True

    def times(self, handle):
        p = self.open_handles[handle]
        return p.created, p.exited, p.kernel, p.user

    def WaitForSingleObject(self, handle, timeout):
        return 0 if self.open_handles[handle].exited else 258

    def GetProcessMemoryInfo(self, handle, memory, size):
        memory._obj.private = self.open_handles[handle].private
        return True


def observed(api):
    thread = mock.Mock()
    thread.is_alive.return_value = False
    with mock.patch.object(H.threading, "Thread", return_value=thread):
        return H.Witness(api, SimpleNamespace(pid=10))


class ProcessAttribution(unittest.TestCase):
    def test_stale_parent_pids_cannot_expand_foreign_tree_or_exhaust_bound(self):
        api = ProcessAPI()
        # These predate the collector; Toolhelp still names its recycled PID.
        for pid in range(100, 180):
            api.add(pid, 10, 50)
        api.add(11, 10, 110)
        api.add(12, 11, 120)
        witness = observed(api)
        self.assertEqual({r["pid"] for r in witness.rows.values()}, {10, 11, 12})
        self.assertEqual(witness.peak_alive, 3)
        self.assertEqual(witness.peak_child_private, 2048)
        witness.finish()
        self.assertEqual(api.open_handles, {})

    def test_child_must_be_born_within_pinned_parent_lifetime(self):
        api = ProcessAPI()
        api.add(11, 10, 110, exited=150)
        api.add(12, 11, 140)  # A real child can outlive its parent.
        api.add(13, 11, 160)  # A later reuse of the numeric parent is foreign.
        witness = observed(api)
        self.assertEqual({r["pid"] for r in witness.rows.values()}, {10, 11, 12})
        self.assertEqual(witness.peak_alive, 2)
        witness.finish()
        self.assertEqual(api.open_handles, {})

    def test_new_process_after_snapshot_cannot_inherit_stale_parent_row(self):
        api = ProcessAPI()
        api.add(11, 10, 10001)
        witness = observed(api)
        self.assertEqual(set(witness.handles), {(10, 100)})
        # A later fresh snapshot can positively attribute that generation.
        api.clock = 10002
        witness.sample()
        self.assertEqual(set(witness.handles), {(10, 100), (11, 10001)})
        witness.finish()

    def test_reused_child_pid_keeps_distinct_handles_births_and_cleanup(self):
        api = ProcessAPI()
        original = api.add(11, 10, 110)
        witness = observed(api)
        original.exited = 120
        api.add(11, 10, 130)
        witness.sample()
        self.assertEqual(set(witness.handles), {(10, 100), (11, 110), (11, 130)})
        self.assertTrue(witness.rows[(11, 110)]["stopped"])
        self.assertFalse(witness.rows[(11, 130)]["stopped"])
        proof = witness.finish()
        self.assertFalse(proof["all_stopped"])
        self.assertEqual(api.open_handles, {})

    def test_actual_owned_generations_still_fail_at_unchanged_64_bound(self):
        api = ProcessAPI()
        witness = observed(api)
        for pid in range(100, 164):
            api.add(pid, 10, 110)
        with self.assertRaisesRegex(ValueError, "owned_process_count_bound"):
            witness.sample()
        self.assertEqual(len(witness.handles), 64)
        self.assertEqual(len(api.open_handles), 64)
        proof = witness.finish()
        self.assertEqual(proof["observer_error"], "owned_process_count_bound")
        self.assertEqual(api.open_handles, {})

    def test_process_disappearing_before_open_never_becomes_evidence(self):
        api = ProcessAPI()
        api.snapshot_rows.append((11, 10))
        witness = observed(api)
        self.assertEqual(set(witness.handles), {(10, 100)})
        witness.finish()

    def test_parent_exit_during_candidate_open_cannot_attribute_later_child(self):
        api = ProcessAPI()
        parent = api.add(11, 10, 110)
        witness = observed(api)
        api.add(12, 11, 160)
        open_process = api.OpenProcess

        def raced_open(access, inherit, pid):
            handle = open_process(access, inherit, pid)
            if pid == 12:
                parent.exited = 150
            return handle

        with mock.patch.object(api, "OpenProcess", side_effect=raced_open):
            witness.sample()
        self.assertEqual(set(witness.handles), {(10, 100), (11, 110)})
        witness.finish()
        self.assertEqual(api.open_handles, {})

    def test_initial_snapshot_bound_failure_closes_every_acquired_handle(self):
        api = ProcessAPI()
        for pid in range(100, 164):
            api.add(pid, 10, 110)
        with self.assertRaisesRegex(ValueError, "owned_process_count_bound"):
            observed(api)
        self.assertEqual(api.open_handles, {})

    def test_collector_alone_cannot_satisfy_breakaway_grade(self):
        candidate = row("breakaway")
        candidate.update(exit_code=0, breakaway_refused=True)
        candidate["budget_events"][0]["budget"]["observed"]["reason"] = None
        candidate["witness"]["processes"] = candidate["witness"]["processes"][:1]
        with self.assertRaisesRegex(ValueError, "owned_child_memory_witness_missing"):
            H.grade(candidate)


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
