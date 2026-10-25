"""Focused audit qualification must never replace the full prepared pilot gate."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FULL = "Qualify owned prepared-selection launch and failures with the original host"
AUDIT = "Qualify prepared-run audit rotation and failed-store continuation"


def step(text, name):
    marker = "      - name: " + name + "\n"
    start = text.index(marker) + len(marker)
    end = text.find("\n      - ", start)
    return text[start:end if end >= 0 else len(text)]


def enabled(body, **overrides):
    values = {
        "github.event_name": "pull_request",
        "github.event.inputs.ask_latency_baseline_sha": "",
        "github.event.inputs.existing_project_only": "",
        "github.event.inputs.audit_retention_only": "",
        "github.event.inputs.storage_recovery_only": "",
    }
    values.update(overrides)
    condition = next(line.strip()[4:] for line in body.splitlines() if line.strip().startswith("if: "))
    for name in sorted(values, key=len, reverse=True):
        condition = condition.replace(name, repr(values[name]))
    tree = ast.parse(condition.replace("&&", " and ").replace("||", " or "), mode="eval")

    def read(node):
        if isinstance(node, ast.Expression):
            return read(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool)):
            return node.value
        if isinstance(node, ast.BoolOp):
            operands = [read(value) for value in node.values]
            if isinstance(node.op, ast.And):
                return all(operands)
            if isinstance(node.op, ast.Or):
                return any(operands)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = read(node.left), read(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        raise AssertionError("Unreviewed qualification condition")

    return bool(read(tree))


class PreparedQualificationCoverage(unittest.TestCase):
    def workflows(self):
        for name in ("mcp-real-filesystem.yml", "ci-components.yml"):
            yield name, (ROOT / ".github/workflows" / name).read_text()

    def test_ordinary_pr_keeps_full_prepared_lifecycle_suite(self):
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                body = step(text, FULL)
                self.assertTrue(enabled(body))
                self.assertNotIn("--audit-retention-only", body)
                self.assertIn('$RUNNER_TEMP/sou116-qualification', body)

    def test_audit_has_distinct_retained_output_and_runs_in_both_modes(self):
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                body = step(text, AUDIT)
                self.assertTrue(enabled(body))
                self.assertTrue(enabled(body, **{
                    "github.event_name": "workflow_dispatch",
                    "github.event.inputs.audit_retention_only": "true",
                }))
                self.assertIn("--audit-retention-only", body)
                self.assertIn('$RUNNER_TEMP/sou132-qualification', body)
                self.assertNotIn('$RUNNER_TEMP/sou116-qualification', body)
                self.assertIn('${{ runner.temp }}/sou132-qualification/report.json', text)

    def test_manual_focused_dispatch_does_not_claim_full_qualification(self):
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                full, audit = step(text, FULL), step(text, AUDIT)
                self.assertFalse(enabled(full, **{
                    "github.event_name": "workflow_dispatch",
                    "github.event.inputs.audit_retention_only": "true",
                }))
                for selected in ("github.event.inputs.existing_project_only", "github.event.inputs.ask_latency_baseline_sha",
                                 "github.event.inputs.storage_recovery_only"):
                    context = {"github.event_name": "workflow_dispatch", selected: "true"}
                    self.assertFalse(enabled(full, **context))
                    self.assertFalse(enabled(audit, **context))

    def test_storage_faults_are_explicit_manual_evidence_with_separate_output(self):
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                body = step(text, "Qualify bounded storage faults and fresh-authority recovery")
                self.assertFalse(enabled(body))
                self.assertTrue(enabled(body, **{
                    "github.event_name": "workflow_dispatch",
                    "github.event.inputs.storage_recovery_only": "true",
                }))
                self.assertIn("scripts/qualify-pilot-storage.py --run", body)
                self.assertIn('$RUNNER_TEMP/pilot-storage-qualification', body)
                self.assertIn('${{ runner.temp }}/pilot-storage-qualification/**', text)


if __name__ == "__main__":
    unittest.main()
