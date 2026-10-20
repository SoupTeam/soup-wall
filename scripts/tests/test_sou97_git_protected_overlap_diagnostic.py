# SPDX-License-Identifier: Apache-2.0
"""Diagnostic-only SOU-97 protected overlap experiment: control fidelity, sanitized collector parsing,
explicit cleanup verification, opt-in workflow wiring. Linux tests drive the unchanged overlap()."""
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIAG = load("sou97_protected_diag_tests", "scripts/diagnose-sou97-git-protected-overlap.py")
SOU68 = load("sou97_protected_diag_tests_sou68", "scripts/verify-sou68-real-mcp.py")
LINUX = sys.platform.startswith("linux")
SECRETS = ("SECRET_TOKEN_7f3a", "/home/operator/private", "synthetic staged text leaked", "instance-7f3a")


def body(function):
    """Stripped statements of a function, without its def line and docstring."""
    lines = [line.strip() for line in inspect.getsource(function).splitlines()[1:]]
    return [line for line in lines if line and not line.startswith('"""')]


class Fidelity(unittest.TestCase):
    def test_control_is_overlap_without_only_its_cancellations(self):
        production = [line.replace("BASE.", "base.").replace("call(i)", "sou68.call(i)").replace("text(r)", "sou68.text(r)")
                      for line in body(SOU68.overlap)]
        removed = ["client.send(base.cancel(100), base.cancel(115))",
                   "cancelled = [client.receive()[0] for _ in range(2)]",
                   'require({r["id"] for r in cancelled} == {100, 115} and all(r.get("error", {}).get("code") == -32800 for r in cancelled),',
                   '"inflight/queued cancellation not correlated")']
        for line in removed:
            self.assertIn(line, production)  # the production overlap still cancels exactly this way
        expected = [line for line in production if line not in removed]
        changes = {"replies = [client.receive()[0] for _ in range(14)]": "replies = [client.receive()[0] for _ in range(16)]",
                   'require({r["id"] for r in replies} == set(range(101, 115)) and all("SOU-68 synthetic" in sou68.text(r) for r in replies),':
                   'require({r["id"] for r in replies} == set(range(100, 116)) and all("SOU-68 synthetic" in sou68.text(r) for r in replies),',
                   'report["overlap"] = {"owned_server_pid": pid, "cancelled": cancelled, "replies": replies, "passed": True}':
                   'report["overlap"] = {"owned_server_pid": pid, "cancelled": [], "replies": replies, "passed": True}'}
        for old in changes:
            self.assertIn(old, expected)
        expected = [changes.get(line, line) for line in expected]
        control = body(DIAG.overlap_without_cancel)
        self.assertEqual(control[0], "base, require = sou68.BASE, sou68.require")
        self.assertEqual(control[1:], expected)

    def test_session_prefix_and_command_are_protected_s_own(self):
        protected = "\n".join(line.replace("BASE.", "base.").replace("INJECTION", "sou68.INJECTION")
                              .replace("READS", "sou68.READS").replace(" call(", " sou68.call(").replace("(call(", "(sou68.call(")
                              .replace(" text(", " sou68.text(") for line in body(SOU68.protected))
        prefix = body(DIAG.session_prefix)[1:]
        for line in prefix[:-1]:  # the last read check omits only the unwrapped-originals comparison
            self.assertIn(line, protected)
        self.assertEqual(prefix[-1], 'require(not base.refused(response) and fragment in sou68.text(response), "protected useful read failed")')
        source = inspect.getsource(SOU68.protected)
        stack = SimpleNamespace(install=Path("/i"), env={"PATH": "p"}, git=Path("/g"), binary=Path("/b"))
        command, env = DIAG.protected_command(stack, {"path": "/c/rule_baseline.py"})
        self.assertIn('command = [str(stack.binary), "mcp", "--native-admission", "--id", "sou68-git", "--", str(python),\n'
                      '               "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]', source)
        self.assertEqual(command, [str(Path("/b")), "mcp", "--native-admission", "--id", "sou68-git", "--",
                                   str(Path("/i/package/python/bin/python3.11")), "-I", "-B", "-m", "mcp_server_git",
                                   "--repository", "/workspace"])
        for key, value in (("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_CONFIG_GLOBAL", "/dev/null"), ("GIT_OPTIONAL_LOCKS", "0"),
                           ("GIT_TERMINAL_PROMPT", "0"), ("AGENTFW_CLASSIFIER", "rule-baseline")):
            self.assertIn(f'{key}="{value}"', source)
            self.assertEqual(env[key], value)
        self.assertEqual((env["AGENTFW_RULE_BASELINE"], env["PATH"]), ("/c/rule_baseline.py", "p"))

    def test_phase2_calls_the_driver_functions_in_the_failing_order(self):
        source = inspect.getsource(DIAG.replay_iteration)
        self.assertIn('for name in ("startup_refusals", "candidate_replay", "protected"):', source)
        run = inspect.getsource(SOU68.run)
        self.assertLess(run.index("startup_refusals(stack, report)"), run.index("candidate_replay(stack, report)"))
        self.assertLess(run.index("candidate_replay(stack, report)"), run.index("protected(stack, report)"))

    def test_matrix_interleaves_every_cell(self):
        cells = DIAG.matrix(2)
        self.assertEqual(cells[:4], [("default", "cancel", 0), ("default", "no_cancel", 0),
                                     ("candidate", "cancel", 0), ("candidate", "no_cancel", 0)])
        self.assertEqual(len(cells), 8)


LOG = "\n".join([
    json.dumps({"event": "mcp_real_server_start", "sandbox_pid": 41, "profile": "sw-mcp/git-readonly/1"}),
    json.dumps({"event": "mcp_real_call", "host_call_id": 100, "state": "inflight", "execution_dispatched": True, "active": 8}),
    json.dumps({"event": "mcp_real_call", "host_call_id": 100, "state": "cancelled"}),
    json.dumps({"event": "mcp_real_call", "host_call_id": 115, "state": "queued", "tool": "SECRET_TOKEN_7f3a"}),
    json.dumps({"event": "mcp_real_call", "host_call_id": 7, "state": "inflight"}),
    json.dumps({"event": "mcp_real_call", "host_call_id": 101, "state": "unheard-of-state"}),
    json.dumps({"event": "mcp_real_stderr", "received_bytes": 3113, "released": False}),
    json.dumps({"event": "mcp_real_owner_end", "cleanup_verified": True, "observed_failure": True,
                "owner": {"instance": "instance-7f3a", "reason": "mcp_owner_sandbox_failed", "failed": True,
                          "cleanup": {"instance": "instance-7f3a", "process_reaped": True, "namespace_terminated": True,
                                      "owned_resources_removed": True, "runtime_failure": True,
                                      "reason": "mcp_owner_sandbox_failed"}}}),
    json.dumps({"event": "mcp_real_server_end", "cleanup_verified": True, "transport_complete": False,
                "budget_failure_observed": False, "owner_failure_observed": True, "owner": {"instance": "instance-7f3a"}}),
    "Error: selected MCP server closed with incomplete state",
    "Error: /home/operator/private SECRET_TOKEN_7f3a",
    "Traceback (most recent call last): synthetic staged text leaked",
    "{not json",
]) + "\n"


class Collector(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "collector.log")
            path.write_text(text, encoding="utf-8")
            return DIAG.parse_collector(path, SOU68.DIAGNOSTIC_TERMINALS)

    def test_failing_log_reduces_to_allowlisted_fields(self):
        got = self.parse(LOG)
        self.assertTrue(got["sandbox_failure"])
        self.assertTrue(got["transport_incomplete"])
        self.assertFalse(got["owner_cleanup_unverified"] or got["server_cleanup_unverified"] or got["server_end_missing"])
        self.assertEqual(got["stderr_bytes"], 3113)
        self.assertEqual(got["terminal_codes"], ["server_closed_incomplete"])
        self.assertEqual((got["unknown_terminal_rows"], got["invalid_rows"]), (1, 2))
        self.assertEqual(got["calls"], {"100": {"states": ["inflight", "cancelled"], "dispatched": True},
                                        "115": {"states": ["queued"], "dispatched": False}})
        self.assertEqual(got["owner_ends"][0]["reason"], "mcp_owner_sandbox_failed")
        rendered = json.dumps(got)
        for secret in SECRETS:
            self.assertNotIn(secret, rendered)

    def test_unknown_reason_missing_end_and_unverified_cleanup_are_explicit(self):
        got = self.parse("\n".join([
            json.dumps({"event": "mcp_real_server_start"}),
            json.dumps({"event": "mcp_real_owner_end", "cleanup_verified": False,
                        "owner": {"reason": "SECRET_TOKEN_7f3a", "cleanup": {"process_reaped": False}}})]))
        self.assertEqual(got["owner_ends"][0]["reason"], "unrecognized")
        self.assertTrue(got["owner_cleanup_unverified"] and got["server_end_missing"])
        self.assertEqual(DIAG.cleanup_failures({"all_stopped": True}, got), ["owner_cleanup_unverified", "server_end_missing"])
        self.assertNotIn("SECRET", json.dumps(got))

    def test_bounds(self):
        rows = "\n".join([json.dumps({"event": "mcp_real_stderr", "received_bytes": 1})] * (DIAG.LOG_ROWS + 5))
        got = self.parse(rows + "\n" + "x" * (DIAG.ROW_BYTES + 1))
        self.assertTrue(got["row_limited"])
        self.assertEqual(self.parse("x" * (DIAG.ROW_BYTES + 1))["oversized_rows"], 1)
        self.assertFalse(DIAG.parse_collector(Path(tempfile.gettempdir(), "absent-sou97.log"), {})["available"])

    def test_cleanup_failures_cover_every_boundary(self):
        clean = self.parse(json.dumps({"event": "mcp_real_server_start"}) + "\n" + json.dumps(
            {"event": "mcp_real_server_end", "cleanup_verified": True, "transport_complete": True}))
        self.assertEqual(DIAG.cleanup_failures({"all_stopped": True, "forced_cleanup": False}, clean), [])
        self.assertEqual(DIAG.cleanup_failures({"all_stopped": False, "forced_cleanup": True}, clean),
                         ["process_tree_survived", "forced_kill"])


class Status(unittest.TestCase):
    def record(self, **changes):
        collector = {"sandbox_failure": False, "transport_incomplete": False, "stderr_bytes": 0}
        base = {"classifier": "default", "variant": "cancel", "outcome": "passed", "collector": collector,
                "cleanup_failures": [], "daemon_alive": True}
        return {**base, **changes}

    def test_outcome_codes_never_carry_messages(self):
        self.assertEqual(DIAG.outcome_code(ValueError("eight real calls did not enter flight")), "inflight_not_reached")
        self.assertEqual(DIAG.outcome_code(ValueError("protected original Git closed before correlated response")),
                         "closed_before_response")
        self.assertEqual(DIAG.outcome_code(ValueError('original server call refused: {"SECRET_TOKEN_7f3a": 1}')),
                         "server_call_refused")
        self.assertEqual(DIAG.outcome_code(ValueError("SECRET_TOKEN_7f3a")), "other:ValueError")
        self.assertEqual(DIAG.outcome_code(DIAG.queue.Empty()), "response_timeout")
        self.assertEqual(DIAG.outcome_code(OSError("/home/operator/private")), "other:OSError")
        sources = "".join((ROOT / path).read_text(encoding="utf-8") for path in (
            "scripts/verify-sou68-real-mcp.py", "scripts/verify-sou62-real-mcp.py", "scripts/diagnose-sou97-git-protected-overlap.py"))
        for message in DIAG.OUTCOMES:  # every mapped message is a static require() string of the reused code
            self.assertRegex(sources, r',\s*"' + re.escape(message) + r'"\)')

    def test_reproduction_means_a_crash_like_signal(self):
        self.assertFalse(DIAG.reproduced([self.record(), self.record(outcome="read_failed")]))
        self.assertTrue(DIAG.reproduced([self.record(outcome="closed_before_response")]))
        self.assertTrue(DIAG.reproduced([self.record(collector={"sandbox_failure": True, "transport_incomplete": True,
                                                                "stderr_bytes": 3113})]))

    def test_status(self):
        report = {"sessions": [self.record()], "iterations": [], "planned_sessions": 1, "planned_iterations": 0}
        self.assertEqual(DIAG.overall_status(report), "complete")
        crash = self.record(outcome="closed_before_response")
        self.assertEqual(DIAG.overall_status(dict(report, sessions=[crash])), "complete")  # a finding, not a failure
        self.assertEqual(DIAG.overall_status(dict(report, planned_sessions=2)), "partial")
        self.assertEqual(DIAG.overall_status(dict(report, planned_iterations=1)), "partial")
        self.assertEqual(DIAG.overall_status(dict(report, sessions=[self.record(cleanup_failures=["forced_kill"])])), "inconclusive")
        self.assertEqual(DIAG.overall_status(dict(report, sessions=[self.record(daemon_alive=False)])), "inconclusive")
        self.assertEqual(DIAG.overall_status(dict(report, sessions=[])), "inconclusive")
        iteration = {"cleanup_failures": ["daemon_survived"]}
        self.assertEqual(DIAG.overall_status(dict(report, iterations=[iteration], planned_iterations=1)), "inconclusive")

    def test_summary_is_labelled_and_content_free(self):
        iteration = {"outcome": "passed", "collector": {"sandbox_failure": False, "stderr_bytes": 0},
                     "replay": {"collectors": {"sandbox_failures": 0}}, "cleanup_failures": []}
        report = {"status": "complete", "phase2_decision": "run",
                  "summary": DIAG.aggregate([self.record(), self.record(variant="no_cancel", outcome="closed_before_response")],
                                            [iteration])}
        text = DIAG.step_summary(report)
        self.assertIn("DIAGNOSTIC ONLY, never acceptance evidence", text)
        self.assertIn("| default/cancel | 1 | 1 | 0 | 0 | 0 | 0 | passed=1 |", text)
        self.assertIn("| default/no_cancel | 1 | 0 | 0 | 0 | 0 | 0 | closed_before_response=1 |", text)
        self.assertIn("| candidate/cancel | 0 | 0 | 0 | 0 | 0 | 0 | - |", text)
        self.assertIn("| candidate after replay (phase 2: run) | 1 | 1 | 0 | 0 | - | 0 | passed=1 |", text)

    def test_plan_mode_and_bounds(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/diagnose-sou97-git-protected-overlap.py"),
                                 "--agentfw", "a", "--git", "g", "--bwrap", "b", "--git-launcher", "l", "--output", "o",
                                 "--classifier-script", "c", "--classifier-sha256", "0" * 64, "--git-sha256", "0" * 64,
                                 "--expected-commit", "0" * 40], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {
            "status": "plan", "executed": False, "diagnostic_only": True,
            "cells": ["default/cancel", "default/no_cancel", "candidate/cancel", "candidate/no_cancel"],
            "sessions_per_cell": 6, "replay_arm": "auto", "replay_iterations": 2})
        # Phase 1 leaves the replay reserve; the step timeout exceeds the largest allowed budget plus one unit.
        self.assertGreaterEqual(DIAG.DEFAULT_BUDGET_SECONDS - DIAG.DEFAULT_REPLAY_ITERATIONS * DIAG.REPLAY_RESERVE_SECONDS, 300)
        self.assertLessEqual(DIAG.DEFAULT_BUDGET_SECONDS + DIAG.REPLAY_RESERVE_SECONDS, 25 * 60 - 120)

    def test_report_format_is_never_runtime_evidence(self):
        self.assertNotIn(DIAG.FORMAT, (ROOT / "scripts/sou97_runtime_replay.py").read_text(encoding="utf-8"))
        for consumer in ("eval/tools/check_pilot_gate.py", "scripts/verify-sou68-real-mcp.py", "scripts/verify-sou62-real-mcp.py"):
            self.assertNotIn("diagnose-sou97", (ROOT / consumer).read_text(encoding="utf-8"))


class Workflow(unittest.TestCase):
    NAME = "SOU-97 diagnostic only (never acceptance) - protected Git overlap through sandbox and native relay"
    UPLOAD = "Retain SOU-97 protected overlap diagnostic output (never acceptance evidence)"

    def steps(self, text):
        return dict(re.findall(r"(?ms)^      - name: ([^\n]+)\n(.*?)(?=^      - name: |\Z)", text))

    def test_opt_in_step_tests_first_and_separate_artifact(self):
        gate = "github.event_name == 'workflow_dispatch' && github.event.inputs.sou97_git_protected_diagnostic == 'true'"
        for path in (".github/workflows/mcp-real-git.yml", ".github/workflows/ci-components.yml"):
            with self.subTest(path=path):
                text = (ROOT / path).read_text(encoding="utf-8")
                steps = self.steps(text)
                run = steps[self.NAME]
                self.assertIn("if: ${{ !cancelled() && " + gate + " }}", run)
                self.assertIn("continue-on-error: true", run)
                self.assertIn("timeout-minutes: 25", run)
                tests = run.index('pattern="test_sou97_git_protected_overlap_diagnostic.py"')
                self.assertLess(tests, run.index("scripts/diagnose-sou97-git-protected-overlap.py --run"))
                self.assertIn("sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 and not result.skipped else 1)", run)
                self.assertRegex(run, r"(?s)::error title=SOU-97 Git protected diagnostic tests::[^\n]*\n\s*exit 1\n\s*fi\n")
                self.assertIn("--sessions 6 --replay-iterations 2 --replay-arm auto --max-seconds 900", run)
                self.assertIn('--classifier-script "$PWD/rule_baseline/pilot_readonly_v1/rule_baseline.py"', run)
                self.assertEqual(text.count("test_sou97_git_protected_overlap_diagnostic"), 1)
                upload = steps[self.UPLOAD]
                self.assertIn("if: ${{ always() && " + gate + " }}", upload)
                self.assertIn("name: sou97-git-protected-overlap-diagnostic", upload)
                for item in ("diagnostic-sou97-git-protected-tests.log", "diagnostic-sou97-git-protected.log",
                             "diagnostic-sou97-git-protected/diagnostic.json"):
                    self.assertIn("${{ runner.temp }}/" + item, upload)
                    for pattern in re.findall(r"\$\{\{ runner\.temp \}\}/(\S+)", steps["Retain exact-source synthetic evidence"]):
                        self.assertFalse(Path(item).match(pattern), (item, pattern))
                for name, block in steps.items():  # only diagnostic steps may continue on error
                    if "continue-on-error" in block:
                        self.assertTrue(name.startswith("SOU-97 diagnostic only"), name)
        source = (ROOT / ".github/workflows/mcp-real-git.yml").read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^      sou97_git_protected_diagnostic:\n        description: Diagnostic only[^\n]*\n"
                                 r"        type: boolean\n        default: false$")
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            if path.name not in ("mcp-real-git.yml", "ci-components.yml"):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("sou97_git_protected_diagnostic:", text, path.name)
                self.assertNotIn("test_sou97_git_protected_overlap_diagnostic", text, path.name)


FAKE_COLLECTOR = textwrap.dedent("""\
    # Owned fake collector: speaks the client protocol, writes collector-format events to its stderr (the session
    # log) and owns one child whose /proc cmdline matches overlap()'s server selector.
    import json, os, subprocess, sys, time
    mode, assets = sys.argv[1], sys.argv[2]
    # Healthy modes block in the shell builtin `read` (no grandchild); leak mode forks a sleep that outlives us.
    leak = mode == "leak"
    child = subprocess.Popen(["/mcp-server/python/bin/python3.11", "-c", "sleep 6; :" if leak else "read line",
                              "mcp_server_git"], executable="/bin/sh", stdin=subprocess.DEVNULL if leak else subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def event(**row):
        sys.stderr.write(json.dumps(row) + "\\n"); sys.stderr.flush()
    def reply(row):
        sys.stdout.write(json.dumps(row) + "\\n"); sys.stdout.flush()
    def text(identifier):
        return {"jsonrpc": "2.0", "id": identifier, "result": {"content": [{"type": "text", "text":
                "SOU-68 synthetic initial commit notes.txt synthetic changed text synthetic staged text SECRET_TOKEN_7f3a"}]}}
    def end(reason, complete, code):
        event(event="mcp_real_owner_end", cleanup_verified=True, observed_failure=reason != "mcp_owner_stop_requested",
              owner={"instance": "instance-7f3a", "reason": reason, "failed": reason != "mcp_owner_stop_requested",
                     "cleanup": {"process_reaped": True, "namespace_terminated": True, "owned_resources_removed": True,
                                 "runtime_failure": reason != "mcp_owner_stop_requested", "reason": reason}})
        event(event="mcp_real_server_end", cleanup_verified=True, transport_complete=complete)
        if mode != "leak":
            child.kill(); child.wait()
        sys.exit(code)
    event(event="mcp_real_server_start", sandbox_pid=child.pid)
    active, cancels = 0, []
    for line in sys.stdin:
        row = json.loads(line)
        identifier, method = row.get("id"), row.get("method")
        if method == "initialize":
            reply({"jsonrpc": "2.0", "id": identifier, "result": json.load(open(os.path.join(assets, "upstream-initialize.json")))["result"]})
        elif method == "tools/list":
            reply({"jsonrpc": "2.0", "id": identifier, "result": json.load(open(os.path.join(assets, "upstream-tools-list.json")))["result"]})
        elif method == "notifications/cancelled":
            if mode == "crash":
                event(event="mcp_real_stderr", received_bytes=3113, released=False)
                sys.stderr.write("Traceback (most recent call last): SECRET_TOKEN_7f3a /home/operator/private\\n")
                end("mcp_owner_sandbox_failed", False, 1)
            cancels.append(row["params"]["requestId"])
            event(event="mcp_real_call", host_call_id=cancels[-1], state="cancelled")
            reply({"jsonrpc": "2.0", "id": cancels[-1], "error": {"code": -32800, "message": "cancelled"}})
            if len(cancels) == 2:
                for i in range(101, 115):
                    reply(text(i))
        elif identifier == 8:
            reply({"jsonrpc": "2.0", "id": 8, "error": {"code": -32603, "message": "withheld"}})
        elif type(identifier) is int and 100 <= identifier < 108:
            active += 1
            event(event="mcp_real_call", host_call_id=identifier, state="inflight", execution_dispatched=True, active=active)
        elif type(identifier) is int and 108 <= identifier < 116:
            event(event="mcp_real_call", host_call_id=identifier, state="queued", active=active, queued=identifier - 107)
            if identifier == 115 and mode == "control":
                for i in range(100, 116):
                    reply(text(i))
        elif identifier is not None:
            reply(text(identifier))
    end("mcp_owner_stop_requested", True, 0)
    """)


@unittest.skipUnless(LINUX, "Linux /proc, job control and process groups required")
class UnchangedOverlapAgainstFakeCollector(unittest.TestCase):
    """The real overlap() and session() against an owned fake collector; required on the Linux runner."""

    class Witness:
        def __init__(self, root):
            pass

        def drain(self):
            return 1

        def close(self):
            pass

    def run_session(self, mode, variant):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "fake_collector.py"
            fake.write_text(FAKE_COLLECTOR, encoding="utf-8")
            stack = SimpleNamespace(workspace=root, poison="0" * 40, daemon=None)
            record = DIAG.session(SOU68, stack, {"mode": "candidate"}, variant, 0, root,
                                  command=[sys.executable, str(fake), mode, str(SOU68.INSTALL.ASSETS)],
                                  env=dict(os.environ), witness_cls=self.Witness)
        for secret in SECRETS:
            self.assertNotIn(secret, json.dumps(record))
        return record

    def test_cancellation_arm_passes_the_production_overlap(self):
        record = self.run_session("cancel", "cancel")
        self.assertEqual((record["outcome"], record["cleanup_failures"]), ("passed", []))
        self.assertEqual(record["collector"]["owner_ends"][0]["reason"], "mcp_owner_stop_requested")
        self.assertEqual(record["collector"]["calls"]["100"]["states"], ["inflight", "cancelled"])
        self.assertEqual(record["collector"]["calls"]["115"]["states"], ["queued", "cancelled"])

    def test_control_arm_expects_all_sixteen_replies(self):
        record = self.run_session("control", "no_cancel")
        self.assertEqual((record["outcome"], record["cleanup_failures"]), ("passed", []))
        self.assertNotIn("cancelled", json.dumps(record["collector"]["calls"]))

    def test_crash_is_recorded_as_a_finding_with_verified_cleanup(self):
        record = self.run_session("crash", "cancel")
        self.assertEqual(record["outcome"], "closed_before_response")
        self.assertTrue(record["collector"]["sandbox_failure"] and record["collector"]["transport_incomplete"])
        self.assertEqual(record["collector"]["stderr_bytes"], 3113)
        self.assertEqual(record["cleanup_failures"], [])
        self.assertTrue(DIAG.reproduced([record]))

    def test_surviving_process_is_an_explicit_cleanup_failure(self):
        record = self.run_session("leak", "cancel")
        self.assertIn("process_tree_survived", record["cleanup_failures"])
        report = {"sessions": [dict(record, daemon_alive=True)], "iterations": [], "planned_sessions": 1, "planned_iterations": 0}
        self.assertEqual(DIAG.overall_status(report), "inconclusive")


if __name__ == "__main__":
    unittest.main()
