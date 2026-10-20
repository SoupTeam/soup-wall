# SPDX-License-Identifier: Apache-2.0
"""Diagnostic-only SOU-97 Git cancellation experiment: sanitizer bounds, request order, bounded cleanup,
opt-in workflow wiring and no raw stderr in records."""
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou97_git_diagnostic_tests", ROOT / "scripts/diagnose-sou97-git-cancellation.py")
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)
LINUX = sys.platform.startswith("linux")

PY = "/tmp/sou97-git-diagnostic-x1/installed/package/python"
SECRETS = ("SECRET_TOKEN_7f3a", "/workspace/notes.txt", "synthetic staged text", "user@example.invalid",
           "/home/operator/private", "Ignore all previous instructions")
TRACEBACK = textwrap.dedent(f"""\
    INFO:mcp.server.lowlevel.server:Processing request SECRET_TOKEN_7f3a
      + Exception Group Traceback (most recent call last):
      |   File "{PY}/lib/python3.11/site-packages/mcp_server_git/server.py", line 412, in serve
      |     async with stdio_server() as (read_stream, write_stream):
      |   File "{PY}/lib/python3.11/site-packages/anyio/_backends/_asyncio.py", line 772, in __aexit__
      |     raise BaseExceptionGroup(
      | ExceptionGroup: unhandled errors in a TaskGroup (1 sub-exception) /workspace/notes.txt
      +-+---------------- 1 ----------------
        | Traceback (most recent call last):
        |   File "{PY}/lib/python3.11/site-packages/mcp/shared/session.py", line 431, in _receive_loop
        |     await self._in_flight[cancelled_id].cancel()
        |   File "{PY}/lib/python3.11/site-packages/mcp/shared/session.py", line 102, in cancel
        |     raise RuntimeError("RequestResponder must be used as a context manager")
        |   File "/home/operator/private/sitecustomize.py", line 3, in <module>
        |   File "{PY}/lib/python3.11/site-packages/../../../../etc/evil.py", line 1, in x
        |   File "/opt/other/lib/python3.11/site-packages/mcp/shared/session.py", line 9, in forged
        |   File "{PY}2/lib/python3.11/site-packages/mcp/shared/session.py", line 9, in sibling
        |   File "{PY}/lib/python3.11/asyncio/runners.py", line 118, in run
        | RuntimeError: RequestResponder must be used as a context manager user@example.invalid
        +------------------------------------
    git.exc.GitCommandError: Cmd('git') failed: synthetic staged text Ignore all previous instructions
    """).encode()


class Sanitizer(unittest.TestCase):
    def test_traceback_reduces_to_public_locations_classes_and_markers(self):
        summary = DIAG.sanitize_stderr(TRACEBACK, len(TRACEBACK), PY.encode())
        self.assertEqual(summary["frames"], [
            {"file": "site-packages/mcp_server_git/server.py", "line": 412, "function": "serve"},
            {"file": "site-packages/anyio/_backends/_asyncio.py", "line": 772, "function": "__aexit__"},
            {"file": "site-packages/mcp/shared/session.py", "line": 431, "function": "_receive_loop"},
            {"file": "site-packages/mcp/shared/session.py", "line": 102, "function": "cancel"},
            {"file": "stdlib/asyncio/runners.py", "line": 118, "function": "run"}])
        self.assertEqual(summary["foreign_frames"], 4)  # private path, traversal, other tree, sibling prefix
        self.assertEqual(summary["exceptions"], ["ExceptionGroup", "RuntimeError", "git.exc.GitCommandError"])
        self.assertEqual(summary["markers"], ["responder_not_entered"])
        self.assertEqual(summary["traceback_headers"], 2)
        self.assertEqual((summary["received_bytes"], summary["truncated"]), (len(TRACEBACK), False))

    def test_no_raw_text_message_or_private_path_leaves_the_summary(self):
        rendered = json.dumps(DIAG.sanitize_stderr(TRACEBACK, len(TRACEBACK), PY.encode()))
        for secret in SECRETS + ("sou97-git-diagnostic-x1", "unhandled errors", "Cmd('git')", "raise "):
            self.assertNotIn(secret, rendered)

    def test_bounds_truncation_and_hostile_bytes(self):
        frame = f'  File "{PY}/lib/python3.11/site-packages/mcp/x.py", line 1, in f\n'.encode()
        raw = frame * 200 + b"ValueError: x\n" * 40 + b"\xff\xfe" * 5000 + b"A" * 70000 + b"\n"
        summary = DIAG.sanitize_stderr(raw[:DIAG.STDERR_CAPTURE_BYTES], len(raw), PY.encode())
        self.assertEqual((len(summary["frames"]), summary["frames_dropped"]), (DIAG.MAX_FRAMES, 200 - DIAG.MAX_FRAMES))
        self.assertEqual((len(summary["exceptions"]), summary["exceptions_dropped"]), (DIAG.MAX_EXCEPTIONS, 40 - DIAG.MAX_EXCEPTIONS))
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["captured_bytes"], DIAG.STDERR_CAPTURE_BYTES)
        self.assertNotIn("AAAA", json.dumps(summary))

    def test_empty_stderr(self):
        summary = DIAG.sanitize_stderr(b"", 0)
        self.assertEqual((summary["received_bytes"], summary["frames"], summary["exceptions"], summary["markers"]), (0, [], [], []))

    def test_capture_counts_everything_but_keeps_only_the_bound(self):
        stream = io.BufferedReader(io.BytesIO(b"x" * 100000))
        captured, total, closed = DIAG.StderrCapture(stream, limit=1000).finish()
        self.assertEqual((len(captured), total, closed), (1000, 100000, True))


class Records(unittest.TestCase):
    def test_responses_keep_ids_codes_and_usefulness_only(self):
        rows = [(0, {"id": 101, "result": {"content": [{"type": "text", "text": "SOU-68 synthetic SECRET_TOKEN_7f3a"}]}}),
                (0, {"id": 100, "error": {"code": 0, "message": "Request cancelled SECRET_TOKEN_7f3a"}}),
                (0, {"id": 100, "result": {"content": [{"type": "text", "text": "other"}]}}),
                (0, {"id": "s", "result": {}}), (0, {"method": "notifications/message"})]
        got = DIAG.classify_responses(rows, "SOU-68 synthetic", [101, 102])
        self.assertEqual(got, {"by_id": {"100": ["error:0", "result_other"], "101": ["result_useful"]},
                               "duplicate_ids": [100], "missing_ids": [102]})
        self.assertNotIn("SECRET", json.dumps(got))

    def test_exit_status(self):
        self.assertEqual(DIAG.exit_status(None), {"exited": False, "code": None, "signal": None})
        self.assertEqual(DIAG.exit_status(1), {"exited": True, "code": 1, "signal": None})
        self.assertEqual(DIAG.exit_status(-9)["signal"], "SIGKILL")
        self.assertEqual(DIAG.exit_status(-31)["signal"], "SIGSYS")  # seccomp kill must stay distinguishable

    def test_plans_mirror_the_overlap_slots(self):
        control = DIAG.plan("stop_no_cancel")
        self.assertEqual(control, {"stop": True, "initial": list(range(100, 108)), "refill": list(range(108, 115)),
                                   "cancelled": None})
        for name, stop in (("stop_cancel", True), ("burst_cancel", False)):
            steps = DIAG.plan(name)
            self.assertEqual(steps, {"stop": stop, "initial": [*range(100, 108), ("cancel", 100), 108],
                                     "refill": list(range(109, 115)), "cancelled": 100})
        self.assertNotIn(115, DIAG.plan("stop_cancel")["refill"])  # cancelled while queued on the host
        with self.assertRaises(ValueError):
            DIAG.plan("other")

    def test_frames_use_the_native_cancel_frame_and_overlap_calls(self):
        source = (ROOT / "crates/agentfw/src/mcp/admission/real_server.rs").read_text(encoding="utf-8")
        self.assertEqual(source.count('json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":call.id}})'), 2)
        built = DIAG.frames([100, ("cancel", 100)], lambda i: {"id": i})
        self.assertEqual(built, [{"id": 100}, {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 100}}])
        driver = (ROOT / "scripts/verify-sou68-real-mcp.py").read_text(encoding="utf-8")
        self.assertIn('def call(identifier, tool="git_show", extra=None, repo="/workspace"):', driver)
        self.assertIn('extra if extra is not None else {"revision": "HEAD"}', driver)  # overlap()'s call(i)
        self.assertIn("client.send(*[call(i) for i in range(100, 108)])", driver)
        self.assertIn("client.send(BASE.cancel(100), BASE.cancel(115))", driver)

    def test_report_format_is_never_runtime_evidence(self):
        replay = (ROOT / "scripts/sou97_runtime_replay.py").read_text(encoding="utf-8")
        self.assertNotIn(DIAG.FORMAT, replay)
        self.assertIn('"sou97-runtime-evidence/1"', replay)
        for consumer in ("eval/tools/check_pilot_gate.py", "scripts/verify-sou68-real-mcp.py", "scripts/verify-sou62-real-mcp.py"):
            self.assertNotIn("diagnose-sou97", (ROOT / consumer).read_text(encoding="utf-8"))

    def record(self, **changes):
        base = {"scenario": "stop_no_cancel", "initialized": True, "server_terminated": False, "forced_cleanup": False,
                "process_cleanup_all_stopped": True, "status_after_close": {"code": 0, "signal": None},
                "responses": {"duplicate_ids": [], "missing_ids": []},
                "stderr": {"received_bytes": 0, "exceptions": [], "markers": []}}
        return {**base, **changes}

    def test_aggregate(self):
        crashed = self.record(scenario="stop_cancel", server_terminated=True, status_after_close={"code": 1, "signal": None},
                              responses={"duplicate_ids": [], "missing_ids": [109]},
                              stderr={"received_bytes": 3113, "exceptions": ["RuntimeError"], "markers": ["responder_not_entered"]})
        summary = DIAG.aggregate([self.record(), crashed])
        self.assertEqual(summary["stop_no_cancel"]["server_terminated"], 0)
        self.assertEqual((summary["stop_cancel"]["nonzero_exit"], summary["stop_cancel"]["missing_response_trials"],
                          summary["stop_cancel"]["exceptions"]), (1, 1, ["RuntimeError"]))
        self.assertEqual(summary["burst_cancel"]["trials"], 0)

    def test_status_is_complete_only_for_full_clean_rounds(self):
        full = [self.record(scenario=name) for name in DIAG.SCENARIOS]
        self.assertEqual(DIAG.overall_status(full, 1), "complete")
        # A crash is a finding, not an experiment failure.
        self.assertEqual(DIAG.overall_status([*full[:2], self.record(scenario="burst_cancel", server_terminated=True)], 1), "complete")
        self.assertEqual(DIAG.overall_status(full, 2), "partial")
        self.assertEqual(DIAG.overall_status([], 1), "inconclusive")
        for change in ({"driver_error": "ValueError"}, {"initialized": False}, {"close_error": "OSError"},
                       {"process_cleanup_all_stopped": False}):
            with self.subTest(change=change):
                self.assertEqual(DIAG.overall_status([*full[:2], self.record(**change)], 1), "inconclusive")

    def test_step_summary_is_labelled_diagnostic_and_content_free(self):
        report = {"status": "fail", "error": "ValueError", "error_stage": "install",
                  "summary": DIAG.aggregate([self.record(stderr={"received_bytes": 10, "exceptions": ["RuntimeError"],
                                                                 "markers": []})])}
        text = DIAG.step_summary(report)
        self.assertIn("DIAGNOSTIC ONLY, never acceptance evidence", text)
        self.assertIn("status: `fail` (install: ValueError)", text)
        self.assertIn("| stop_no_cancel | 1 | 0 | 0 | 1 | 0 | 0 | RuntimeError | - |", text)

    def test_plan_mode_executes_nothing(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/diagnose-sou97-git-cancellation.py"),
                                 "--git", "g", "--bwrap", "b", "--git-launcher", "l", "--output", "o",
                                 "--git-sha256", "0" * 64, "--expected-commit", "0" * 40],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"status": "plan", "executed": False, "diagnostic_only": True,
                                                     "scenarios": list(DIAG.SCENARIOS)})

    def test_worst_case_round_is_bounded(self):
        # initialize (2 exchanges), trial deadline + settle, close (8 + 8 + 3), witness finish (5), stderr join (3)
        per_trial = 2 * DIAG.INITIALIZE_SECONDS + DIAG.TRIAL_SECONDS + DIAG.SETTLE_SECONDS + 19 + 5 + 3
        self.assertLessEqual(per_trial * len(DIAG.SCENARIOS), 240)
        self.assertLessEqual(DIAG.DEFAULT_BUDGET_SECONDS + per_trial * len(DIAG.SCENARIOS), 20 * 60 - 180)


class Workflow(unittest.TestCase):
    """The diagnostic is opt-in, separate from acceptance and cannot run in normal CI."""

    def step(self, text, name):
        match = re.search(r"(?ms)^      - name: " + re.escape(name) + r"\n(.*?)(?=^      - name: |\Z)", text)
        self.assertIsNotNone(match, name)
        return match.group(1)

    def test_input_and_steps(self):
        for path in (".github/workflows/mcp-real-git.yml", ".github/workflows/ci-components.yml"):
            with self.subTest(path=path):
                text = (ROOT / path).read_text(encoding="utf-8")
                gate = "github.event_name == 'workflow_dispatch' && github.event.inputs.sou97_git_diagnostic == 'true'"
                run = self.step(text, "SOU-97 diagnostic only (never acceptance) - original Git server cancellation overlap")
                self.assertIn("if: ${{ !cancelled() && " + gate + " }}", run)
                self.assertIn("continue-on-error: true", run)
                self.assertIn("timeout-minutes: 20", run)
                self.assertIn("--trials 20 --max-seconds 480", run)
                self.assertIn('--output "$RUNNER_TEMP/diagnostic-sou97-git"', run)
                # The diagnostic's own tests run first and are required: a failure or any skip stops the experiment.
                tests = run.index('pattern="test_sou97_git_cancellation_diagnostic.py"')
                self.assertLess(tests, run.index("scripts/diagnose-sou97-git-cancellation.py --run"))
                self.assertIn("sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 and not result.skipped else 1)", run)
                self.assertRegex(run, r"(?s)::error title=SOU-97 Git diagnostic tests::[^\n]*\n\s*exit 1\n\s*fi\n")
                # Normal CI and default acceptance never run these tests.
                self.assertEqual(text.count("test_sou97_git_cancellation_diagnostic"), 1)
                upload = self.step(text, "Retain SOU-97 diagnostic-only output (never acceptance evidence)")
                self.assertIn("${{ runner.temp }}/diagnostic-sou97-git-tests.log", upload)
                self.assertIn("if: ${{ always() && " + gate + " }}", upload)
                self.assertIn("name: sou97-git-cancellation-diagnostic", upload)
                self.assertNotIn("continue-on-error", upload)
                # Only diagnostic steps may continue on error; acceptance steps keep failing the job.
                for name, block in re.findall(r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - name: |\Z)", text):
                    if "continue-on-error" in block:
                        self.assertTrue(name.startswith("SOU-97 diagnostic only"), name)
                acceptance = self.step(text, "Retain exact-source synthetic evidence")
                for pattern in re.findall(r"\$\{\{ runner\.temp \}\}/(\S+)", acceptance):
                    self.assertFalse(Path("diagnostic-sou97-git.log").match(pattern), pattern)
                    self.assertFalse(Path("diagnostic-sou97-git-tests.log").match(pattern), pattern)
                    self.assertFalse(Path("diagnostic-sou97-git/diagnostic.json").match(pattern), pattern)
        source = (ROOT / ".github/workflows/mcp-real-git.yml").read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^      sou97_git_diagnostic:\n        description: Diagnostic only[^\n]*\n"
                                 r"        type: boolean\n        default: false$")
        # The generated copy runs under workflow_call from ci.yml, whose dispatch has no such input.
        self.assertNotIn("sou97_git_diagnostic:", (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            if path.name not in ("mcp-real-git.yml", "ci-components.yml"):
                self.assertNotIn("test_sou97_git_cancellation_diagnostic", path.read_text(encoding="utf-8"), path.name)


FAKE_SERVER = textwrap.dedent("""\
    import json, sys, time
    mode, log = sys.argv[1], sys.argv[2]
    for line in sys.stdin:
        row = json.loads(line)
        with open(log, "a") as stream:
            stream.write(json.dumps(["cancel", row["params"]["requestId"]] if row.get("method") == "notifications/cancelled"
                                    else row.get("id")) + "\\n")
        if mode == "hang":
            continue
        if row.get("method") == "notifications/cancelled" and mode == "crash":
            sys.stderr.write('Traceback (most recent call last):\\n  File "/home/operator/private/x.py", line 1, in f\\n'
                             'RuntimeError: RequestResponder must be used as a context manager SECRET_TOKEN_7f3a\\n')
            sys.stderr.flush()
            sys.exit(1)
        if "id" in row:
            text = "SOU-68 synthetic SECRET_TOKEN_7f3a"
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": row["id"], "result": {"content": [{"type": "text", "text": text}]}}) + "\\n")
            sys.stdout.flush()
    if mode == "hang":
        time.sleep(60)  # ignores stdin EOF: only the forced process-group kill ends it
    """)


class FakeServerTrial(unittest.TestCase):
    """End-to-end trial() against an owned fake server: termination and order are recorded, raw stderr never is."""

    def run_trial(self, mode, scenario):
        verify = importlib.util.spec_from_file_location("sou97_diag_fake_base", ROOT / "scripts/verify-sou62-real-mcp.py")
        base = importlib.util.module_from_spec(verify)
        verify.loader.exec_module(base)

        class Client(base.Client):
            def initialize(self):
                pass

        sou68 = type("Sou68", (), {"Client": Client, "call": staticmethod(lambda i, tool, args, repo: {
            "jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args}})})
        with tempfile.TemporaryDirectory() as tmp:
            server, log = Path(tmp, "fake_server.py"), Path(tmp, "received.jsonl")
            server.write_text(FAKE_SERVER, encoding="utf-8")
            record = DIAG.trial(scenario, 0, sou68=sou68, command=[sys.executable, str(server), mode, str(log)],
                                python_root=None, workspace=Path(tmp), env=dict(os.environ))
            received = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return record, received

    def test_crash_on_cancel_is_recorded_without_raw_stderr(self):
        record, _ = self.run_trial("crash", "burst_cancel")
        self.assertTrue(record["server_terminated"])
        self.assertEqual(record["status_after_close"]["code"], 1)
        self.assertEqual(record["stderr"]["exceptions"], ["RuntimeError"])
        self.assertEqual(record["stderr"]["markers"], ["responder_not_entered"])
        self.assertEqual(record["stderr"]["foreign_frames"], 1)
        self.assertGreater(record["stderr"]["received_bytes"], 0)
        rendered = json.dumps(record)
        for secret in SECRETS:
            self.assertNotIn(secret, rendered)

    def test_healthy_server_receives_the_overlap_order_and_answers_every_call(self):
        record, received = self.run_trial("healthy", "burst_cancel")
        self.assertEqual(received, [*range(100, 108), ["cancel", 100], *range(108, 115)])
        self.assertFalse(record["server_terminated"])
        self.assertEqual(record["status_after_close"], {"exited": True, "code": 0, "signal": None})
        self.assertEqual(sorted(map(int, record["responses"]["by_id"])), list(range(100, 115)))
        self.assertEqual((record["responses"]["missing_ids"], record["refill_unsent"]), ([], 0))
        self.assertEqual(record["stderr"]["received_bytes"], 0)
        self.assertNotIn("SECRET", json.dumps(record))

    @unittest.skipUnless(LINUX, "Linux job control and process groups required")
    def test_stopped_scenarios_resume_the_server_in_order(self):
        for scenario, order in (("stop_no_cancel", [*range(100, 115)]),
                                ("stop_cancel", [*range(100, 108), ["cancel", 100], *range(108, 115)])):
            with self.subTest(scenario=scenario):
                record, received = self.run_trial("healthy", scenario)
                self.assertEqual(received, order)
                self.assertFalse(record["server_terminated"])
                self.assertTrue(record["process_cleanup_all_stopped"])
                self.assertEqual(record["responses"]["missing_ids"], [])

    @unittest.skipUnless(LINUX, "Linux process-group cleanup required")
    def test_silent_server_is_bounded_and_cleaned_up(self):
        with patch.object(DIAG, "TRIAL_SECONDS", 2):
            began = time.monotonic()
            record, received = self.run_trial("hang", "stop_cancel")
        self.assertLess(time.monotonic() - began, 30)
        self.assertEqual(received, [*range(100, 108), ["cancel", 100], 108])  # nothing completed, nothing refilled
        self.assertEqual(record["refill_unsent"], 6)
        self.assertEqual(record["responses"]["missing_ids"], list(range(101, 115)))
        self.assertTrue(record["process_cleanup_all_stopped"])
        self.assertFalse(record["server_terminated"])
        self.assertTrue(record["forced_cleanup"])
        self.assertEqual(record["status_after_close"]["signal"], "SIGKILL")


if __name__ == "__main__":
    unittest.main()
