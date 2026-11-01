"""Focused audit qualification must never replace the full prepared pilot gate."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
FULL = "Qualify owned prepared-selection launch and failures with the original host"
AUDIT = "Qualify prepared-run audit rotation and failed-store continuation"
OPERATIONS = "Qualify prepared-run discovery and private archival"


def step(text, name):
    marker = "      - name: " + name + "\n"
    start = text.index(marker) + len(marker)
    end = text.find("\n      - ", start)
    return text[start:end if end >= 0 else len(text)]


def enabled(body, **overrides):
    values = {
        "github.event_name": "pull_request",
        "github.event.inputs.ask_latency_baseline_sha": "",
        "github.event.inputs.ask_series": "",
        "github.event.inputs.existing_project_only": "",
        "github.event.inputs.audit_retention_only": "",
        "github.event.inputs.storage_recovery_only": "",
        "github.event.inputs.operator_results_only": "",
        "github.event.inputs.capacity_only": "",
        "github.event.inputs.prepared_operations_only": "",
        "github.event.inputs.coordinated_update_only": "",
        "github.event.inputs.private_edit_self_test_only": "",
        "github.event.inputs.provider_ca_only": "",
        "github.event.inputs.native_preparation_only": "",
        "github.event.inputs.linked_worktrees_only": "",
        "github.event.inputs.project_presets_only": "",
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
    def test_linked_worktree_dispatch_is_separate_from_full_qualification(self):
        context = {"github.event_name": "workflow_dispatch",
                   "github.event.inputs.linked_worktrees_only": "true",
                   "github.event.inputs.native_preparation_only": "true"}
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                for title in (FULL, AUDIT,
                              "Qualify the installed guided pilot front door through the original host",
                              "Qualify the guided first-use entry point through the original host",
                              "Qualify exact prepared selection through enforcing daemon and original servers",
                              "Run the first-use demo through the prepared original host",
                              "Qualify terminal Ask inbox through the original Claude host",
                              "Qualify reused bounded audit engine restart and fail-safe retention"):
                    self.assertFalse(enabled(step(text, title), **context))
                    self.assertTrue(enabled(step(text, title)))
                body = step(text, "Qualify installed linked worktrees through original servers")
                self.assertTrue(enabled(body, **context))
                self.assertFalse(enabled(body))
                for missing in ("linked_worktrees_only", "native_preparation_only"):
                    self.assertFalse(enabled(body, **{
                        **context, "github.event.inputs." + missing: "",
                    }))
                self.assertFalse(enabled(body, **{**context, "github.event_name": "pull_request"}))
                self.assertIn("--linked-worktrees-only", body)

    def test_project_presets_dispatch_is_separate_from_full_qualification(self):
        context = {"github.event_name": "workflow_dispatch",
                   "github.event.inputs.project_presets_only": "true",
                   "github.event.inputs.native_preparation_only": "true"}
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                for title in (FULL, AUDIT,
                              "Qualify the installed guided pilot front door through the original host",
                              "Qualify the guided first-use entry point through the original host",
                              "Qualify exact prepared selection through enforcing daemon and original servers",
                              "Run the first-use demo through the prepared original host",
                              "Qualify terminal Ask inbox through the original Claude host",
                              "Qualify reused bounded audit engine restart and fail-safe retention"):
                    self.assertFalse(enabled(step(text, title), **context))
                    self.assertTrue(enabled(step(text, title)))
                body = step(text, "Qualify installed project presets through two owned projects")
                self.assertTrue(enabled(body, **context))
                self.assertFalse(enabled(body))
                for missing in ("project_presets_only", "native_preparation_only"):
                    self.assertFalse(enabled(body, **{
                        **context, "github.event.inputs." + missing: "",
                    }))
                self.assertFalse(enabled(body, **{**context, "github.event_name": "pull_request"}))
                self.assertIn("--project-presets-only", body)

    def test_provider_ca_dispatch_is_separate_from_full_qualification(self):
        context = {"github.event_name": "workflow_dispatch",
                   "github.event.inputs.provider_ca_only": "true",
                   "github.event.inputs.native_preparation_only": "true"}
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                for title in (FULL, AUDIT,
                              "Qualify the installed guided pilot front door through the original host",
                              "Qualify the guided first-use entry point through the original host",
                              "Qualify exact prepared selection through enforcing daemon and original servers",
                              "Run the first-use demo through the prepared original host",
                              "Qualify terminal Ask inbox through the original Claude host",
                              "Qualify reused bounded audit engine restart and fail-safe retention"):
                    self.assertFalse(enabled(step(text, title), **context))
                    self.assertTrue(enabled(step(text, title)))
                body = step(text, "Qualify installed provider CA custody through owned HTTPS")
                self.assertTrue(enabled(body, **context))
                self.assertFalse(enabled(body))
                for missing in ("provider_ca_only", "native_preparation_only"):
                    self.assertFalse(enabled(body, **{
                        **context, "github.event.inputs." + missing: "",
                    }))
                self.assertFalse(enabled(body, **{**context, "github.event_name": "pull_request"}))
                self.assertIn("--provider-ca-only", body)

    def test_update_dispatch_is_targeted_and_does_not_replace_existing_qualification(self):
        context = {"github.event_name": "workflow_dispatch",
                   "github.event.inputs.coordinated_update_only": "true"}
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                for title in (FULL, AUDIT,
                              "Qualify the installed guided pilot front door through the original host"):
                    self.assertFalse(enabled(step(text, title), **context))
                    self.assertTrue(enabled(step(text, title)))
                body = step(text, "Qualify coordinated installed update and rollback")
                self.assertTrue(enabled(body, **context))
                self.assertFalse(enabled(body))
                self.assertIn("scripts/prepare-pilot-update-fixture.py", body)
                self.assertIn("scripts/qualify-pilot-update.py", body)
                self.assertIn("${{ runner.temp }}/sou164-update/qualification/qualification.json", text)

    def workflows(self):
        for name in ("mcp-real-filesystem.yml", "ci-components.yml"):
            yield name, (ROOT / ".github/workflows" / name).read_text()

    def test_installed_front_door_qualifies_ordinary_pr_but_not_focused_capacity_or_operations(self):
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                body = step(text, "Qualify the installed guided pilot front door through the original host")
                self.assertTrue(enabled(body))
                self.assertIn("cargo test --locked -p agentfw --lib pilot_component", body)
                self.assertIn("scripts/qualify-installed-front-door.py --run", body)
                for focus in ("capacity_only", "prepared_operations_only"):
                    self.assertFalse(enabled(body, **{
                        "github.event_name": "workflow_dispatch",
                        "github.event.inputs." + focus: "true",
                    }))

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
                                 "github.event.inputs.ask_series",
                                 "github.event.inputs.storage_recovery_only",
                                 "github.event.inputs.operator_results_only",
                                 "github.event.inputs.prepared_operations_only"):
                    context = {"github.event_name": "workflow_dispatch", selected: "true"}
                    self.assertFalse(enabled(full, **context))
                    self.assertFalse(enabled(audit, **context))

    def test_operations_dispatch_has_separate_evidence_and_never_replaces_pr_gates(self):
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                body = step(text, OPERATIONS)
                self.assertFalse(enabled(body))
                self.assertTrue(enabled(body, **{
                    "github.event_name": "workflow_dispatch",
                    "github.event.inputs.prepared_operations_only": "true",
                }))
                for selected in ("audit_retention_only", "storage_recovery_only", "operator_results_only"):
                    self.assertFalse(enabled(body, **{
                        "github.event_name": "workflow_dispatch",
                        "github.event.inputs." + selected: "true",
                    }))
                self.assertIn("scripts/qualify-prepared-run-operations.py", body)
                self.assertIn('$RUNNER_TEMP/prepared-run-operations', body)
                self.assertIn('${{ runner.temp }}/prepared-run-operations/qualification/report.json', text)

    def test_unknown_input_still_requires_review(self):
        with self.assertRaisesRegex(AssertionError, "Unreviewed qualification condition"):
            enabled("if: github.event.inputs.unreviewed_input == 'true'")

    def test_private_edit_self_test_dispatch_does_not_claim_full_pilot_qualification(self):
        context = {"github.event_name": "workflow_dispatch",
                   "github.event.inputs.private_edit_self_test_only": "true"}
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                for title in (FULL, AUDIT, OPERATIONS,
                              "Qualify the installed guided pilot front door through the original host",
                              "Qualify the guided first-use entry point through the original host",
                              "Qualify bounded storage faults and fresh-authority recovery"):
                    self.assertFalse(enabled(step(text, title), **context))
                private = step(text, "Verify installed private-edit self-test outside the checkout")
                self.assertTrue(enabled(private, **context))
                self.assertTrue(enabled(private))
                self.assertIn("scripts/qualify-private-edit-self-test.py", private)

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

    def test_capacity_dispatch_cannot_claim_host_or_audit_qualification(self):
        context = {"github.event_name": "workflow_dispatch", "github.event.inputs.capacity_only": "true"}
        for name, text in self.workflows():
            with self.subTest(workflow=name):
                self.assertFalse(enabled(step(text, FULL), **context))
                self.assertFalse(enabled(step(text, AUDIT), **context))
                preparation = step(text, "Verify guarded preparation outcomes")
                self.assertTrue(enabled(preparation, **context))
                self.assertFalse(enabled(preparation))
                self.assertIn("--prepared-records", preparation)
                front_door = step(text, "Qualify the guided first-use entry point through the original host")
                self.assertFalse(enabled(front_door, **context))
                self.assertTrue(enabled(front_door))


if __name__ == "__main__":
    unittest.main()
