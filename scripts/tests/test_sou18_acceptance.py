# SPDX-License-Identifier: Apache-2.0
"""The aggregate runner must not turn partial probe evidence into acceptance."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


SUITE = module("sou18_suite_tests", ROOT / "scripts/run-sou18-acceptance.py")
STATUS_FIXTURE = module("suite_status_fixture", ROOT / "scripts/tests/test_sou18_status.py")
LATENCY_FIXTURE = module("suite_latency_fixture", ROOT / "scripts/tests/test_sou17_latency.py")
HELPERS = {name: SUITE.load(ROOT, name) for name in SUITE.SCRIPTS}
SOURCE = {"commit": "a" * 40, "dirty": False, "inputs_digest": "b" * 64}
BINARY = "c" * 64
PROCESS = {"exit_code": 0, "timed_out": False}


def reports():
    setup = {"schema_version": 1, "status": "pass", "source": SOURCE,
             "binary_sha256": BINARY, "checks": [
                 {"name": "install_preserves_settings_and_hides_token", "status": "pass"},
                 *[{"name": name, "status": "pass", "preflight_exit": code}
                   for name, code in (("shadow", 4), ("enforcing", 0), ("unavailable", 2), ("recovery", 0))],
                 {"name": "remove_owned_install_and_profile", "status": "pass"}]}
    cases = dict(zip(HELPERS["status"].CASE_IDS,
                     ("allow", "deny", "ask", "result_withheld", "unavailable", "allow", "shadow")))
    status = {"schema_version": SUITE.SCHEMAS["status"], "status": "pass",
              "binary_sha256": BINARY, "source_before": SOURCE, "source_after": SOURCE,
              "initial_path_verified": True, "final_ledger_matches": True, "inventory_preserved": True,
              "receiver_final_count": 0, "source_binary_stable": True, "owned_profile_removed": True,
              "rows": [json.loads(json.dumps(STATUS_FIXTURE.observation(expected)).replace("test-call", name))
                       for name, expected in cases.items()]}
    rows = [LATENCY_FIXTURE.observation(index, path, index == -1)
            for index in range(-1, 30) for path in ("direct", "protected")]
    for row in rows:
        HELPERS["latency"].grade(row, row["path"] == "protected", LATENCY_FIXTURE.DIGEST)
    latency = {"schema_version": SUITE.SCHEMAS["latency"], "source_before": SOURCE, "source_after": SOURCE,
               "agentfw": {"sha256": BINARY}, "classifier": {"sha256": LATENCY_FIXTURE.DIGEST},
               "pairs": 30, "excluded_warmup_pairs": 1, "rows": rows,
               "post_stop_reconciliation": {"direct": True, "protected": True},
               "summary": HELPERS["latency"].summarize(rows, 30, True)}
    return copy.deepcopy({"setup": setup, "status": status, "latency": latency})


class EvidenceTests(unittest.TestCase):
    def evaluate(self, name, data, process=None):
        return SUITE.evaluate(name, data, process or PROCESS, SOURCE, BINARY, 30, HELPERS)[0]

    def test_complete_reports_pass_only_the_bounded_probes(self):
        for name, data in reports().items():
            self.assertEqual(self.evaluate(name, data), "pass", name)

    def test_missing_malformed_schema_status_and_nonzero_exit_do_not_pass(self):
        for name, data in reports().items():
            for broken in (None, [], {}, dict(data, schema_version=True), dict(data, schema_version="future")):
                self.assertEqual(self.evaluate(name, broken), "incomplete")
            for process in ({"exit_code": 1}, {"exit_code": False}, {"exit_code": 0, "timed_out": True}):
                self.assertEqual(self.evaluate(name, data, process), "incomplete")
            field = data["summary"] if name == "latency" else data
            for value in (None, "not_run", "skip", "unknown"):
                field["status"] = value
                self.assertEqual(self.evaluate(name, data), "incomplete")
            field["status"] = "fail"
            self.assertEqual(self.evaluate(name, data, {"exit_code": 1}), "fail")

    def test_source_and_binary_mismatch_cannot_pass(self):
        for name in SUITE.SCRIPTS:
            data = reports()[name]
            if name == "latency":
                data["agentfw"]["sha256"] = "wrong"
            else:
                data["binary_sha256"] = "wrong"
            self.assertEqual(self.evaluate(name, data), "incomplete")
            data = reports()[name]
            field = "source" if name == "setup" else "source_after"
            data[field] = dict(SOURCE, commit="d" * 40)
            self.assertEqual(self.evaluate(name, data), "incomplete")

    def test_missing_duplicate_or_wrong_typed_setup_witnesses_do_not_pass(self):
        for mutate in (lambda checks: checks.pop(), lambda checks: checks.append(checks[0]),
                       lambda checks: checks[2].update(preflight_exit=False),
                       lambda checks: checks[0].update(status="skip")):
            data = reports()["setup"]
            mutate(data["checks"])
            self.assertEqual(self.evaluate("setup", data), "incomplete")

    def test_success_label_does_not_override_execution_and_delivery_witnesses(self):
        for field in ("executor_raw", "server_result_raw", "released_raw"):
            data = reports()["status"]
            data["rows"][0][field] = ""
            self.assertEqual(self.evaluate("status", data), "incomplete")
        data = reports()["status"]
        data["rows"][1]["executor_raw"] = data["rows"][1]["submitted_frame"] + "\n"
        self.assertEqual(self.evaluate("status", data), "incomplete")

    def test_latency_requires_actual_samples_recomputed_summary_and_reconciliation(self):
        for mutate in (lambda data: data["rows"].pop(),
                       lambda data: data["summary"]["paired_overhead_ms"].update(p95=0),
                       lambda data: data["rows"][1].update(executor_delta_raw=""),
                       lambda data: data["post_stop_reconciliation"].update(protected=False),
                       lambda data: data.update(pairs=31)):
            data = reports()["latency"]
            mutate(data)
            self.assertEqual(self.evaluate("latency", data), "incomplete")

    def test_incomplete_or_changed_run_cannot_pass(self):
        stages = [{"name": name, "status": "pass"} for name in SUITE.SCRIPTS]
        self.assertEqual(SUITE.outcome(stages, True), "pass")
        self.assertEqual(SUITE.outcome(stages, False), "incomplete")
        self.assertEqual(SUITE.outcome(stages[:-1], True), "incomplete")
        for value in ("skip", "not_run", "unknown", "incomplete", "fail"):
            stages[-1]["status"] = value
            self.assertEqual(SUITE.outcome(stages, True), "fail" if value == "fail" else "incomplete")


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.repo = self.directory / "candidate"
        self.repo.mkdir()
        self.binary = self.directory / "agentfw"
        self.binary.write_bytes(b"synthetic test executable")
        self.args = argparse.Namespace(repo=self.repo, agentfw=self.binary, expected_commit=SOURCE["commit"],
                                       output=self.directory / "results", pairs=30)
        self.helpers = {name: mock.Mock(wraps=helper) for name, helper in HELPERS.items()}
        self.helpers["setup"].sha.return_value = BINARY
        self.helpers["latency"].snapshot.return_value = SOURCE
        self.calls = []
        self.payloads = reports()

    def execute(self, command, repo, env, timeout):
        name = next(name for name, filename in SUITE.SCRIPTS.items() if filename == Path(command[2]).name)
        self.calls.append((name, env.copy()))
        self.assertEqual(repo, self.repo)
        self.assertEqual(command[1], "-I")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertNotEqual(env["HOME"], os.environ.get("HOME"))
        path = self.args.output / SUITE.REPORTS[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.payloads[name]), encoding="utf-8")
        return dict(PROCESS)

    def run_suite(self, execute=None, host=None):
        with mock.patch.object(SUITE, "load", side_effect=lambda repo, name: self.helpers[name]), \
                mock.patch.object(SUITE, "execute", side_effect=execute or self.execute), \
                mock.patch.object(SUITE.sys, "platform", host or sys.platform), \
                mock.patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-secret", "HTTPS_PROXY": "synthetic-proxy"}), \
                contextlib.redirect_stdout(io.StringIO()):
            code = SUITE.run(self.args)
        return code, json.loads((self.args.output / "results.json").read_text())

    def test_default_does_not_start_probes(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/run-sou18-acceptance.py")],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["processes_started"], 0)

    def test_existing_output_and_output_inside_candidate_are_refused(self):
        self.args.output.mkdir()
        marker = self.args.output / "keep.txt"
        marker.write_text("keep")
        with self.assertRaises(FileExistsError):
            SUITE.run(self.args)
        self.assertEqual(marker.read_text(), "keep")
        self.args.output = self.repo / "output"
        with self.assertRaisesRegex(ValueError, "outside_candidate"):
            SUITE.run(self.args)
        self.assertFalse(self.args.output.exists())

    def test_wrong_commit_and_dirty_source_prevent_execution(self):
        for before in (dict(SOURCE, dirty=True), dict(SOURCE, commit="d" * 40)):
            self.args.output = self.directory / str(len(list(self.directory.iterdir())))
            self.helpers["latency"].snapshot.return_value = before
            code, report = self.run_suite()
            self.assertEqual(code, 2)
            self.assertEqual(self.calls, [])
            self.assertEqual(report["error"], "clean_exact_candidate_required")

    def test_success_keeps_child_reports_isolates_profiles_and_leaves_acceptance_pending(self):
        code, report = self.run_suite(host="linux")
        self.assertEqual(code, 0)
        self.assertTrue(report["owned_profiles_removed"])
        self.assertFalse(report["acceptance_passed"])
        self.assertEqual(report["generic_candidate_acceptance"], "pending_sou15")
        for name, env in self.calls:
            self.assertFalse(Path(env["HOME"]).exists())
            self.assertTrue((self.args.output / SUITE.REPORTS[name]).exists())

    def test_missing_corrupt_duplicate_and_nonfinite_reports_stay_incomplete(self):
        for index, raw in enumerate((None, "{broken", '{"status":"pass","status":"fail"}', '{"n":NaN}')):
            self.args.output = self.directory / f"invalid-{index}"

            def invalid(command, repo, env, timeout):
                result = self.execute(command, repo, env, timeout)
                path = self.args.output / SUITE.REPORTS[self.calls[-1][0]]
                if raw is None:
                    path.unlink()
                else:
                    path.write_text(raw)
                return result

            code, report = self.run_suite(execute=invalid, host="linux")
            self.assertEqual(code, 2)
            self.assertTrue(all(s["status"] == "incomplete" for s in report["stages"]))

    def test_candidate_change_between_stages_stops_later_probes(self):
        self.helpers["latency"].snapshot.side_effect = [SOURCE, SOURCE, dict(SOURCE, dirty=True), SOURCE]
        code, report = self.run_suite()
        self.assertEqual(code, 2)
        self.assertEqual([name for name, _ in self.calls], ["setup"])
        self.assertEqual(report["error"], "candidate_or_binary_changed")

    def test_windows_latency_skip_is_not_a_green_suite(self):
        code, report = self.run_suite(host="win32")
        self.assertEqual(code, 2)
        self.assertEqual([name for name, _ in self.calls], ["setup", "status"])
        self.assertEqual(report["stages"][-1]["status"], "skip")

    def test_timeout_retains_evidence_and_stops_later_probes(self):
        def timeout(*args):
            return dict(self.execute(*args), timed_out=True)

        code, report = self.run_suite(execute=timeout)
        self.assertEqual(code, 2)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(report["stages"][1]["status"], "not_run")
        self.assertTrue((self.args.output / "setup.json").exists())

    @unittest.skipUnless(os.name == "posix", "owned process-group termination requires POSIX")
    def test_deadline_terminates_owned_process(self):
        result = SUITE.execute([sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                               self.repo, HELPERS["setup"].private_environment(self.directory), .1)
        self.assertTrue(result["timed_out"])
        self.assertNotIn("error", result)
        self.assertLess(result["elapsed_ms"], 10000)

    def test_markdown_escapes_values_and_preserves_incomplete_status(self):
        _, report = self.run_suite(host="win32")
        report["error"] = "<tag>|`code`\nnext"
        output = SUITE.markdown(report)
        self.assertIn("**incomplete**", output)
        self.assertIn("&lt;tag&gt;&#124;&#96;code&#96; next", output)
        self.assertIn("| latency | skip |", output)


if __name__ == "__main__":
    unittest.main()
