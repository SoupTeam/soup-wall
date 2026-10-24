import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile
import json
import ast

PATH = Path(__file__).resolve().parents[1] / "pilot_operator_results.py"
SPEC = importlib.util.spec_from_file_location("operator_results", PATH)
RESULTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESULTS)


class ResultContract(unittest.TestCase):
    def test_terminal_diagnostics_do_not_export_arguments(self):
        path = PATH.parent / "qualify-ask-inbox.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "terminal_diagnostic")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
        result = namespace["terminal_diagnostic"](
            'private-sentinel {"state":"rejected"} Decision outcome unavailable.', None)
        self.assertTrue(result["markers"]["rejection_compact"])
        self.assertTrue(result["markers"]["decision_unavailable"])
        self.assertNotIn("private-sentinel", json.dumps(result))
        self.assertIsNone(result["exit_code"])

    def test_harness_resolves_default_adapter_at_call_time(self):
        path = PATH.parent / "qualify-pilot-ask.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "qualify")
        prefix = []
        for statement in function.body:
            if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr == "prepare_original_launch" for node in ast.walk(statement)):
                break
            prefix.append(statement)
        function.body = prefix + [ast.Return(value=ast.Name(id="pilot_class", ctx=ast.Load()))]
        module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
        original, replacement, explicit = object(), object(), object()
        namespace = {"Pilot": original}
        exec(compile(module, str(path), "exec"), namespace)
        namespace["Pilot"] = replacement
        self.assertIs(namespace["qualify"](None, None, {}), replacement)
        self.assertIs(namespace["qualify"](None, None, {}, pilot_class=explicit), explicit)

    def test_native_driver_has_a_runnable_cli(self):
        result = subprocess.run([sys.executable, "-B", str(PATH.parent / "qualify-operator-results.py"), "--help"],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_driver_does_not_overwrite_an_earlier_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "operator-results.json"
            evidence.write_text("retained attempt", encoding="utf-8")
            command = [sys.executable, "-B", str(PATH.parent / "qualify-operator-results.py")]
            for name in ("agentfw", "git-launcher", "claude", "node", "npm", "bwrap", "git", "strace"):
                command.extend(["--" + name, "missing-owned-test-tool"])
            result = subprocess.run([*command, "--output", directory], capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(evidence.read_text(encoding="utf-8"), "retained attempt")

    def test_failed_native_attempt_keeps_a_safe_producer_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "attempt"
            command = [sys.executable, "-B", str(PATH.parent / "qualify-operator-results.py")]
            for name in ("agentfw", "git-launcher", "claude", "node", "npm", "bwrap", "git", "strace"):
                command.extend(["--" + name, "missing-owned-test-tool"])
            result = subprocess.run([*command, "--output", str(output)], capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            record = json.loads((output / "operator-results.json").read_text())
            self.assertIn(record["failure_reason"], ("linux_required", "native_ubuntu_24_04_required", "unknown"))
            self.assertNotIn("missing-owned-test-tool", json.dumps(record))

    def record(self, operation="approve", outcome="decision_submitted", reason="approval_submitted"):
        return {"format": "sw-pilot-operator-result/1", "operation": operation,
                "outcome": outcome, "reason": reason,
                "identity": {"run_id": "a" * 32, "run_sha256": "b" * 64,
                             "instance_id": "daemon", "registry_sha256": "c" * 64,
                             "pending_id": "pending", "binding_sha256": "d" * 64},
                "data": {"pending_id": "pending", "state": "decision_submitted", "decision": "approve",
                         "dispatched": "not_observed", "released": "not_observed"}}

    def test_submission_is_not_an_execution_claim(self):
        record = self.record()
        self.assertEqual(RESULTS.validate(record, "approve", 0), record)
        record["data"]["dispatched"] = True
        with self.assertRaises(ValueError):
            RESULTS.validate(record, "approve", 0)

    def test_failure_cannot_be_accepted_as_success(self):
        for record, code in [(self.record(), 4), (self.record(outcome="unknown", reason="unknown"), 0)]:
            with self.assertRaises(ValueError):
                RESULTS.validate(record, "approve", code)

    def test_wrong_operation_unknown_format_and_extra_fields_are_rejected(self):
        for field, value in [("operation", "stop"), ("format", "unknown"), ("private", "token")]:
            record = self.record()
            record[field] = value
            with self.assertRaises(ValueError):
                RESULTS.validate(record, "approve", 0)

    def test_unavailable_has_no_data_or_invented_identity(self):
        record = {"format": "sw-pilot-operator-result/1", "operation": "list",
                  "outcome": "unavailable", "reason": "run_unavailable", "identity": None, "data": None}
        self.assertEqual(RESULTS.validate(record, "list", 4), record)

    def test_reason_exit_and_outcome_must_agree(self):
        record = {"format": "sw-pilot-operator-result/1", "operation": "list",
                  "outcome": "refused", "reason": "daemon_unavailable", "identity": None, "data": None}
        with self.assertRaises(ValueError):
            RESULTS.validate(record, "list", 3)


if __name__ == "__main__":
    unittest.main()
