"""SOU-239: independent scheduling keeps complete exact-source admission."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_components import blocks  # noqa: E402
from ci_impact import plan, WORKFLOW_JOBS, BUILD_CONSUMERS, BUILD_PRODUCER  # noqa: E402
from ci_admission import assess_job_names, component_names, required_names  # noqa: E402


SOURCE = blocks((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
MIRROR = blocks((ROOT / ".github/workflows/ci-components.yml").read_text(encoding="utf-8"))
INDEPENDENT = ("components", "agent-lifecycle-macos", "all-features",
               "saml-release-targets", "redis-integration", "postgres-integration",
               "docker-build")
BASE_CHECKS = ("test", "native-macos-resilience", "agent-windows-security")


def condition(job: str) -> str:
    """Read the checked-in Actions expression; refuse unexpected graph syntax."""
    body = SOURCE[job]
    if re.findall(r"(?m)^    needs: (.+)$", body) != ["impact"]:
        raise AssertionError(f"{job}: only the trusted impact plan may precede independent work")
    match = re.search(r"(?m)^    if: >-\n((?: {6,}[^\n]*\n)+)", body)
    if not match:
        raise AssertionError(f"{job}: missing explicit scheduling expression")
    expression = " ".join(match[1].split())
    if any(f"needs.{name}.result" in expression for name in BASE_CHECKS):
        raise AssertionError(f"{job}: unrelated platform check is still a prerequisite")
    return expression


def scheduled(job: str, selected: set[str], impact: str = "success", *,
              event: str = "pull_request", draft: bool = False,
              cancelled: bool = False, smoke_only: bool = False) -> bool:
    """Evaluate the finite literal Actions subset used by these seven jobs."""
    expression = condition(job)
    expression = re.sub(
        r"contains\(fromJSON\(needs\.impact\.outputs\.jobs \|\| '\[\]'\), '([a-z-]+)'\)",
        lambda match: repr(match[1] in selected), expression)
    expression = expression.replace("needs.impact.result", repr(impact))
    expression = expression.replace("github.event_name", repr(event))
    expression = expression.replace("github.event.pull_request.draft", repr(draft))
    expression = expression.replace("inputs.smoke_only", repr(smoke_only))
    expression = expression.replace("cancelled()", repr(cancelled))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", " not ", expression)
    try:
        return bool(eval(expression, {"__builtins__": {}}, {}))
    except (NameError, SyntaxError) as error:
        raise AssertionError(f"{job}: unsupported scheduling expression: {expression}") from error


class IndependentComponents(unittest.TestCase):
    def setUp(self):
        self.full_plan = plan([".github/workflows/ci.yml"])
        self.full = set(self.full_plan["workflows"]["ci.yml"])

    def test_ready_jobs_depend_only_on_trusted_plan(self):
        for job in INDEPENDENT:
            with self.subTest(job=job):
                self.assertTrue(scheduled(job, self.full))
                self.assertIn("!cancelled()", condition(job))
                self.assertIn("needs.impact.result == 'success'", condition(job))
        for name in BASE_CHECKS:
            self.assertIn("    needs: impact\n", SOURCE[name])
        self.assertEqual(len(self.full_plan["codeql"]), 5)
        self.assertEqual(len(MIRROR), sum(len(ids) for wf, ids in WORKFLOW_JOBS.items()
                                          if wf != "ci.yml"))

    def test_runner_allocation_and_ordinary_failure_leave_other_jobs_runnable(self):
        for failed in BASE_CHECKS:
            for job in INDEPENDENT:
                with self.subTest(failed=failed, independent=job):
                    self.assertNotIn("needs." + failed + ".result", condition(job))
                    self.assertTrue(scheduled(job, self.full), job)

    def test_cancellation_failed_plan_draft_and_selective_scope(self):
        for job in INDEPENDENT:
            self.assertFalse(scheduled(job, self.full, cancelled=True), job)
            self.assertFalse(scheduled(job, self.full, impact="failure"), job)
            self.assertFalse(scheduled(job, self.full, draft=True), job)
        self.assertFalse(scheduled("components", self.full, event="workflow_dispatch",
                                   smoke_only=True))
        docs = set(plan(["README.md"])["workflows"]["ci.yml"])
        self.assertEqual(docs, {"documentation"})
        self.assertTrue(scheduled("components", docs))
        for job in INDEPENDENT[1:]:
            self.assertFalse(scheduled(job, docs), job)
        gateway = set(plan(["crates/proxy/src/lib.rs"])["workflows"]["ci.yml"])
        self.assertFalse(scheduled("agent-lifecycle-macos", gateway))
        for job in ("all-features", "saml-release-targets", "redis-integration",
                    "postgres-integration", "docker-build"):
            self.assertTrue(scheduled(job, gateway), job)
        self.assertEqual(plan(["README.md", "unknown/new-file"])["mode"], "full")

    def test_selected_failure_missing_job_or_stale_head_still_blocks_admission(self):
        expected = list(required_names("ci.yml", self.full_plan["workflows"]["ci.yml"]))
        for workflow, ids in self.full_plan["workflows"].items():
            if workflow != "ci.yml":
                expected.extend(component_names(workflow, ids))
        merge, head = "c" * 40, "b" * 40
        run = {"id": 7, "run_attempt": 1}

        def job(name):
            return {"name": name, "status": "completed", "conclusion": "success",
                    "run_id": 7, "run_attempt": 1, "head_sha": head}

        jobs = [job("impact / Candidate " + merge), *(job(name) for name in expected)]
        self.assertEqual(assess_job_names(jobs, tuple(expected), merge, run, head).state, "success")
        for name in ("Native macOS admission resilience", "test", "agent-windows-security",
                     component_names("mcp-real-filesystem.yml", ["native-ubuntu-2404"])[0]):
            for result in ("failure", "cancelled", "skipped", "timed_out"):
                with self.subTest(required=name, result=result):
                    target = next(item for item in jobs if item["name"] == name)
                    target["conclusion"] = result
                    self.assertEqual(assess_job_names(jobs, tuple(expected), merge, run, head).state,
                                     "failure")
                    target["conclusion"] = "success"
            with self.subTest(required=name, result="absent"):
                target = next(item for item in jobs if item["name"] == name)
                jobs.remove(target)
                self.assertEqual(assess_job_names(jobs, tuple(expected), merge, run, head).state,
                                 "pending")
                jobs.append(target)
        jobs[-1]["head_sha"] = "d" * 40
        self.assertEqual(assess_job_names(jobs, tuple(expected), merge, run, head).state, "failure")

    def test_real_build_edges_and_producer_refusal_survive_generation(self):
        producer = BUILD_PRODUCER[0].removesuffix(".yml") + "--" + BUILD_PRODUCER[1]
        for workflow, ids in BUILD_CONSUMERS.items():
            for job in ids:
                body = MIRROR[workflow.removesuffix(".yml") + "--" + job]
                with self.subTest(workflow=workflow, job=job):
                    self.assertIn("    needs: " + producer + "\n", body)
                    self.assertIn("!cancelled()", body)
                    self.assertIn("ci_qualification_build.py guard", body)
                    self.assertIn("${{ needs." + producer + ".result }}", body)


if __name__ == "__main__":
    unittest.main()
