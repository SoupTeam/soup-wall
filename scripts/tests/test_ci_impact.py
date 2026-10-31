"""Adversarial selection and exact-source admission checks for SOU-91."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_impact import WORKFLOW_JOBS, plan, scheduled_plan  # noqa: E402
from ci_activation import ACTIVATION_VALUE, selective_enabled  # noqa: E402
from ci_admission import assess_codeql, assess_job_names, inspect, required_names  # noqa: E402
from sou91_ruleset_patch import admission_is_required, prepare as prepare_ruleset  # noqa: E402


class ImpactTests(unittest.TestCase):
    def selected(self, paths):
        result = plan(paths)
        return {name: set(jobs) for name, jobs in result["workflows"].items()}

    def test_plain_docs_only_keeps_executable_work_off(self):
        jobs = self.selected(["README.md", "docs/README.md"])
        self.assertEqual(jobs["ci.yml"], {"documentation"})
        self.assertFalse(jobs["mcp-real-filesystem.yml"])
        self.assertFalse(jobs["supply-chain.yml"])

    def test_agent_native_selects_all_platform_and_original_server_controls(self):
        jobs = self.selected(["crates/agentfw/src/native.rs"])
        self.assertTrue({"test", "native-macos-resilience", "agent-windows-security"} <= jobs["ci.yml"])
        for workflow in ("mcp-real-filesystem.yml", "mcp-real-git.yml", "mcp-https-post.yml",
                         "mcp-windows-read.yml", "agent-windows-onboarding.yml", "sou79-resource-budgets.yml",
                         "sou86-crash-supervision.yml", "provenance-memory.yml",
                         "supply-chain.yml", "license-policy.yml"):
            self.assertEqual(jobs[workflow], set(WORKFLOW_JOBS[workflow]))
        self.assertNotIn("postgres-integration", jobs["ci.yml"])

    def test_gateway_selects_identity_storage_tls_and_release_targets(self):
        jobs = self.selected(["crates/proxy/src/main.rs"])
        for ci_job in ("test", "saml-release-targets", "redis-integration",
                       "postgres-integration", "docker-build"):
            self.assertIn(ci_job, jobs["ci.yml"])
        for workflow in ("keycloak-oidc.yml", "keycloak-saml.yml",
                         "scim-directory.yml", "managed-policy-postgres.yml",
                         "tls-lifecycle.yml", "monitoring.yml", "gateway-sdk.yml"):
            self.assertEqual(jobs[workflow], set(WORKFLOW_JOBS[workflow]))

    def test_python_only_has_real_eval_without_rust_build(self):
        jobs = self.selected(["eval/eval_runner.py"])
        self.assertEqual(jobs["ci.yml"], {"documentation", "python-classifier"})
        self.assertEqual(jobs["benchmark.yml"], set(WORKFLOW_JOBS["benchmark.yml"]))

    def test_critical_and_unknown_paths_force_complete_qualification(self):
        for path in ("Cargo.lock", "rust-toolchain.toml", "crates/core/src/lib.rs",
                     ".github/workflows/ci.yml", ".github/actions/setup/action.yml",
                     ".github/dependabot.yml", "docs/operations/NATIVE_MCP_STDERR.md",
                     "docs/benchmarks/sou13/ACCEPTANCE.md",
                     "scripts/fixtures/scenario.json", "unexpected/new-component.txt",
                     "LICENSE", "../outside"):
            with self.subTest(path=path):
                result = plan([path])
                self.assertEqual(result["mode"], "full")
                self.assertEqual(result["workflows"],
                                 {name: list(jobs) for name, jobs in WORKFLOW_JOBS.items()})

    def test_mixed_change_or_empty_source_cannot_narrow(self):
        self.assertEqual(plan(["README.md", "Cargo.lock"])["mode"], "full")
        self.assertEqual(plan([])["mode"], "full")
        self.assertEqual(plan(["README.md"], force_full=True)["mode"], "full")

    def test_bootstrap_and_unverified_activation_keep_full_qualification(self):
        full = {name: list(jobs) for name, jobs in WORKFLOW_JOBS.items()}
        for event, verified in (("pull_request", False), ("workflow_dispatch", True),
                                ("push", True)):
            with self.subTest(event=event, verified=verified):
                result = scheduled_plan(["README.md"], event, verified)
                self.assertEqual(result["mode"], "full")
                self.assertEqual(result["workflows"], full)
        self.assertEqual(scheduled_plan(["README.md"], "pull_request", True)
                         ["workflows"]["ci.yml"], ["documentation"])

    def test_registered_workflows_have_explicit_plan_dependencies(self):
        actual = {path.name for path in (ROOT / ".github/workflows").glob("*.yml")}
        self.assertEqual(actual - {"release.yml", "ci-impact-plan.yml", "ci-admission.yml", "vps-ci.yml", "ci-components.yml"},
                         set(WORKFLOW_JOBS))
        for filename, jobs in WORKFLOW_JOBS.items():
            text = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            registered = set(re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\s*$",
                                        text.split("jobs:\n", 1)[1]))
            auxiliary = {"draft-checks", "main-smoke", "components"} if filename == "ci.yml" else set()
            if filename == "mcp-real-filesystem.yml":
                auxiliary.update({"manual-long-session", "manual-native-result-profile"})
            if filename == "mcp-real-git.yml":
                auxiliary.update({"manual-installed-git-profiles", "sou182-raw-boundary"})
            if filename == "mcp-create-file.yml":
                auxiliary.update({"reuse-plan", "reuse-qualification"})
            self.assertEqual(registered, set(jobs) | {"impact"} | auxiliary, filename)
            for job in jobs:
                body = re.split(r"\n  [a-z][a-z0-9-]*:\s*\n",
                                text.split(f"  {job}:\n", 1)[1], maxsplit=1)[0]
                self.assertIn("needs: impact", body, (filename, job))
                self.assertIn("needs.impact.outputs.jobs", body, (filename, job))

    def test_sou182_raw_boundary_is_manual_and_does_not_replace_required_git(self):
        text = (ROOT / ".github/workflows/mcp-real-git.yml").read_text()
        body = text.split("  sou182-raw-boundary:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.raw_boundary_only", body)
        self.assertNotIn("needs: impact", body)
        required = re.split(r"\n  [a-z][a-z0-9-]*:\s*\n",
                            text.split("  required-linux-git:\n", 1)[1], maxsplit=1)[0]
        impact = text.split("  impact:\n", 1)[1].split("  required-linux-git:\n", 1)[0]
        self.assertIn("if: ${{ !inputs.raw_boundary_only }}", impact)
        self.assertIn("needs: impact", required)
        self.assertNotIn("sou182-raw-boundary", WORKFLOW_JOBS["mcp-real-git.yml"])

    def test_native_result_profile_remains_explicit_manual_only(self):
        text = (ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text()
        body = text.split("  manual-native-result-profile:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", body)
        self.assertIn("github.event.inputs.native_result_profile_only == 'true'", body)
        self.assertNotIn("manual-native-result-profile", WORKFLOW_JOBS["mcp-real-filesystem.yml"])
        central = (ROOT / ".github/workflows/ci-components.yml").read_text()
        self.assertNotIn("manual-native-result-profile", central)

    def test_provider_ca_qualification_requires_explicit_native_dispatch(self):
        source = (ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text()
        shared = (ROOT / ".github/workflows/ci-components.yml").read_text()
        self.assertIn("      provider_ca_only:\n", source)
        self.assertIn("inputs.get('native_preparation_only') == 'true'", source)
        self.assertIn("github.event_name == 'workflow_dispatch' && github.event.inputs.provider_ca_only == 'true'", source)
        self.assertIn("scripts/qualify-installed-front-door.py --run --provider-ca-only", source)
        self.assertIn("installed-provider-ca/report.json", source)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && github.event.inputs.provider_ca_only == 'true'", shared)
        for workflow in (source, shared):
            for name in (
                "Qualify exact prepared selection through enforcing daemon and original servers",
                "Run the first-use demo through the prepared original host",
                "Qualify the guided first-use entry point through the original host",
                "Qualify the installed guided pilot front door through the original host",
                "Qualify terminal Ask inbox through the original Claude host",
                "Qualify owned prepared-selection launch and failures with the original host",
                "Qualify prepared-run audit rotation and failed-store continuation",
                "Qualify reused bounded audit engine restart and fail-safe retention",
                "Targeted existing-project read-only pilot with actual host and independent effects",
            ):
                step = workflow.split("      - name: " + name + "\n", 1)[1]
                condition = next(line for line in step.splitlines() if line.startswith("        if: "))
                self.assertIn("github.event.inputs.provider_ca_only != 'true'", condition, name)

    def test_build_producer_is_selected_only_with_compatible_consumers(self):
        for path, selected in (("README.md", False), ("eval/probe.py", False), ("crates/proxy/src/main.rs", False),
                               ("crates/agentfw/src/main.rs", True), ("Cargo.lock", True),
                               (".github/workflows/ci-builds.yml", True)):
            with self.subTest(path=path):
                result = plan([path])["workflows"]
                self.assertEqual(bool(result["ci-builds.yml"]), selected)

    def test_supplemental_vps_is_outside_pr_admission_only_while_main_only(self):
        text = (ROOT / '.github/workflows/vps-ci.yml').read_text(encoding='utf-8')
        self.assertNotRegex(text, r'(?m)^  pull_request(?:_target)?:')
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("github.repository == 'SoupTeam/soup-wall'", text)
        self.assertIn("vars.SOUP_VPS_CI_ENABLED == 'true'", text)
        self.assertIn("github.event_name == 'workflow_dispatch'", text)


class AdmissionTests(unittest.TestCase):
    SHA = "a" * 40
    HEAD = "b" * 40

    def job(self, name, conclusion="success", status="completed", head=None):
        return {"name": name, "conclusion": conclusion, "status": status,
                "head_sha": head or self.HEAD}

    def test_required_matrix_and_candidate_source(self):
        names = required_names("ci.yml", ["saml-release-targets"])
        self.assertEqual(len(names), 4)
        jobs = [self.job("impact / Candidate " + self.SHA)] + [self.job(name) for name in names]
        self.assertEqual(assess_job_names(jobs, names, self.SHA).state, "success")
        for incomplete in (jobs[1:], jobs[:-1]):
            self.assertEqual(assess_job_names(incomplete, names, self.SHA).state, "pending")
        for bad in (jobs + [jobs[-1]],
                    [dict(jobs[0], conclusion="skipped")] + jobs[1:],
                    [self.job("impact / Candidate " + "c" * 40)] + jobs[1:]):
            self.assertEqual(assess_job_names(bad, names, self.SHA).state, "failure")
        for bad_state in ("failure", "cancelled", "timed_out", "neutral", "skipped", None):
            altered = [dict(jobs[0])] + [dict(item) for item in jobs[1:]]
            altered[1]["conclusion"] = bad_state
            expected = "pending" if bad_state is None else "failure"
            self.assertEqual(assess_job_names(altered, names, self.SHA).state, expected)

    def test_codeql_missing_neutral_stale_or_wrong_source_fails_closed(self):
        expected = plan(["README.md"])["codeql"]
        run = {"head_sha": self.HEAD, "event": "dynamic",
               "path": "dynamic/github-code-scanning/codeql", "status": "completed",
               "conclusion": "success"}
        jobs = [self.job(name) for name in expected]
        self.assertEqual(assess_codeql(run, jobs, expected, self.HEAD).state, "success")
        self.assertEqual(assess_codeql(None, None, expected, self.HEAD).state, "pending")
        self.assertEqual(assess_codeql(run, jobs[:-1], expected, self.HEAD).state, "pending")
        for conclusion in ("neutral", "skipped", "failure", "cancelled", "timed_out"):
            altered = [dict(item) for item in jobs]
            altered[0]["conclusion"] = conclusion
            self.assertEqual(assess_codeql(run, altered, expected, self.HEAD).state, "failure")
        stale = [dict(item) for item in jobs]
        stale[0]["head_sha"] = self.SHA
        self.assertEqual(assess_codeql(run, stale, expected, self.HEAD).state, "failure")

    def test_live_api_shape_binds_merge_and_head_without_pr_execution(self):
        class Fake:
            def __init__(self, outer):
                self.outer = outer
                self.pr = {"state": "open", "base": {"sha": outer.SHA},
                           "head": {"sha": outer.HEAD}, "merge_commit_sha": "c" * 40,
                           "changed_files": 1}
                self.parents = [outer.SHA, outer.HEAD]
                self.runs = [{"id": 1, "path": ".github/workflows/ci.yml",
                              "head_sha": outer.HEAD, "event": "pull_request",
                              "created_at": "2026-10-18T00:00:00Z", "run_attempt": 1,
                              "status": "completed", "conclusion": "success"}]
                self.codeql = [{"id": 2, "path": "dynamic/github-code-scanning/codeql",
                                "head_sha": outer.HEAD, "event": "dynamic",
                                "created_at": "2026-10-18T00:00:00Z", "run_attempt": 1,
                                "status": "completed", "conclusion": "success"}]
                self.jobs = {
                    1: [outer.job("impact / Candidate " + "c" * 40),
                        outer.job("Documentation links")],
                    2: [outer.job(name) for name in plan(["README.md"])["codeql"]],
                }
                for run_id, entries in self.jobs.items():
                    for index, entry in enumerate(entries):
                        entry.update(id=run_id * 100 + index, run_id=run_id, run_attempt=1)
                self.ruleset = prepare_ruleset(RulesetTests().fixture())
                self.ruleset.update({"id": 24846282, "source_type": "Repository",
                                     "source": "SoupTeam/soup-wall"})

            def get(self, suffix):
                if suffix == "/pulls/1":
                    return self.pr
                if suffix == "/git/commits/" + "c" * 40:
                    return {"parents": [{"sha": sha} for sha in self.parents]}
                if suffix == "/rulesets/24846282":
                    return self.ruleset
                if suffix.startswith("/actions/runs/"):
                    return next(run for run in self.runs + self.codeql
                                if run["id"] == int(suffix.rsplit("/", 1)[1]))
                if suffix.startswith("/actions/jobs/"):
                    job_id = int(suffix.rsplit("/", 1)[1])
                    return next(entry for entries in self.jobs.values() for entry in entries
                                if entry["id"] == job_id)
                raise AssertionError(suffix)

            def pages(self, suffix, key):
                if suffix.startswith("/pulls/1/files"):
                    return [{"filename": "README.md"}]
                if suffix.startswith("/actions/runs?"):
                    return self.codeql if "event=dynamic" in suffix else self.runs
                if suffix.startswith("/actions/runs/"):
                    return self.jobs[int(suffix.split("/")[3])]
                raise AssertionError(suffix)

        api = Fake(self)
        self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "pending")
        with patch.dict("os.environ", {"SOU91_SELECTIVE_CI": ACTIVATION_VALUE}):
            installed = api.ruleset
            api.ruleset = RulesetTests().fixture()
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "pending")
            api.ruleset = installed
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "success")
            original_jobs = list(api.jobs[1])
            api.jobs[1] = original_jobs[:1]
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "pending")
            api.jobs[1] = original_jobs
            api.jobs[1][1]["conclusion"] = "failure"
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "failure")
            api.jobs[1][1]["conclusion"] = "skipped"
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "failure")
            api.jobs[1][1]["conclusion"] = "success"
            api.codeql = []
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "pending")
            api.codeql = Fake(self).codeql
            api.pr["head"]["sha"] = "d" * 40
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "failure")
            api.pr["head"]["sha"] = self.HEAD
            api.parents[0] = "d" * 40
            self.assertEqual(inspect(api, 1, self.SHA, self.HEAD)[1].state, "failure")


class RulesetTests(unittest.TestCase):
    def fixture(self):
        return {
            "name": "main", "target": "branch", "enforcement": "active",
            "bypass_actors": [], "conditions": {"ref_name": {
                "include": ["refs/heads/main"], "exclude": []}},
            "rules": [
                {"type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": name, "integration_id": 15368}
                        for name in ("Documentation links", "test", "all-features",
                                     "agent-windows-security")]}},
                {"type": "pull_request", "parameters": {"required_approving_review_count": 1}},
                {"type": "code_scanning", "parameters": {"code_scanning_tools": [
                    {"tool": "CodeQL", "alerts_threshold": "errors",
                     "security_alerts_threshold": "high_or_higher"}]}},
                {"type": "non_fast_forward"},
            ],
        }

    def test_additive_idempotent_patch_keeps_review_and_codeql(self):
        baseline = self.fixture()
        result = prepare_ruleset(baseline)
        checks = result["rules"][0]["parameters"]["required_status_checks"]
        self.assertEqual(len(checks), 5)
        self.assertIn({"context": "SOU-91 candidate admission", "integration_id": 15368}, checks)
        self.assertEqual(len(prepare_ruleset(result)["rules"][0]["parameters"]["required_status_checks"]), 5)
        self.assertEqual(result["rules"][2]["parameters"]["code_scanning_tools"][0]["security_alerts_threshold"],
                         "high_or_higher")

    def test_refuses_weakened_or_ambiguous_rulesets(self):
        for mutation in ("missing_review", "lowered_codeql", "non_strict", "wrong_ref", "wrong_app"):
            with self.subTest(mutation=mutation):
                value = self.fixture()
                if mutation == "missing_review":
                    value["rules"][1]["parameters"]["required_approving_review_count"] = 0
                elif mutation == "lowered_codeql":
                    value["rules"][2]["parameters"]["code_scanning_tools"][0]["security_alerts_threshold"] = "none"
                elif mutation == "non_strict":
                    value["rules"][0]["parameters"]["strict_required_status_checks_policy"] = False
                elif mutation == "wrong_ref":
                    value["conditions"]["ref_name"]["include"] = ["refs/heads/develop"]
                else:
                    value["rules"][0]["parameters"]["required_status_checks"][0]["integration_id"] = 99
                with self.assertRaises(ValueError):
                    prepare_ruleset(value)

    def test_activation_requires_switch_and_verified_live_context(self):
        current = self.fixture()
        current.update({"id": 24846282, "source_type": "Repository",
                        "source": "SoupTeam/soup-wall"})
        self.assertFalse(admission_is_required(current))
        self.assertFalse(selective_enabled(None, lambda: self.fail("unexpected API read")))
        self.assertFalse(selective_enabled(ACTIVATION_VALUE, lambda: current))
        installed = prepare_ruleset(current)
        installed.update({"id": 24846282, "source_type": "Repository",
                          "source": "SoupTeam/soup-wall"})
        self.assertTrue(admission_is_required(installed))
        self.assertTrue(selective_enabled(ACTIVATION_VALUE, lambda: installed))
        self.assertFalse(selective_enabled(ACTIVATION_VALUE,
                                           lambda: (_ for _ in ()).throw(OSError("API down"))))
        for mutation in ("wrong_id", "inactive", "missing_old", "lower_codeql", "missing_review"):
            with self.subTest(mutation=mutation):
                value = self.fixture()
                value.update({"id": 24846282, "source_type": "Repository",
                              "source": "SoupTeam/soup-wall"})
                value = prepare_ruleset(value)
                value.update({"id": 24846282, "source_type": "Repository",
                              "source": "SoupTeam/soup-wall"})
                if mutation == "wrong_id":
                    value["id"] = 1
                elif mutation == "inactive":
                    value["enforcement"] = "evaluate"
                elif mutation == "missing_old":
                    value["rules"][0]["parameters"]["required_status_checks"].pop(0)
                elif mutation == "lower_codeql":
                    value["rules"][2]["parameters"]["code_scanning_tools"][0][
                        "security_alerts_threshold"] = "medium_or_higher"
                else:
                    value["rules"][1]["parameters"]["required_approving_review_count"] = 0
                self.assertFalse(selective_enabled(ACTIVATION_VALUE, lambda: value))


if __name__ == "__main__":
    unittest.main()
