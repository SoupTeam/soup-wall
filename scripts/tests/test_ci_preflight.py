"""Exercise the actual Ready workflow job expressions with selected CI plans."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_components import blocks
from ci_impact import plan


BARRIERS = ("test", "native-macos-resilience", "agent-windows-security")
DEFERRED = ("components", "agent-lifecycle-macos", "all-features",
            "saml-release-targets", "redis-integration", "postgres-integration",
            "docker-build")
SOURCE = blocks((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
MIRROR = blocks((ROOT / ".github/workflows/ci-components.yml").read_text(encoding="utf-8"))


def condition(job: str) -> str:
    body = SOURCE[job]
    expected = "    needs: [impact, " + ", ".join(BARRIERS) + "]"
    if expected not in body:
        raise AssertionError(f"{job}: a required preflight edge is missing")
    match = re.search(r"(?m)^    if: >-\n((?: {6,}[^\n]*\n)+)", body)
    if not match:
        raise AssertionError(f"{job}: missing explicit fail-closed expression")
    return " ".join(match[1].split())


def scheduled(job: str, selected: set[str], results: dict[str, str], *,
              event: str = "pull_request", draft: bool = False,
              cancelled: bool = False, smoke_only: bool = False) -> bool:
    """Evaluate the checked-in expression's small, literal Actions subset.

    This refuses unknown syntax instead of a separate hand-written gate model.
    The test is an offline contract, not a claim to run GitHub's scheduler.
    """
    expression = condition(job)
    for name in BARRIERS:
        needle = f"(!contains(fromJSON(needs.impact.outputs.jobs || '[]'), '{name}') || needs.{name}.result == 'success')"
        if expression.count(needle) != 1:
            raise AssertionError(f"{job}: {name} must be selected-or-success exactly once")
    expression = re.sub(
        r"contains\(fromJSON\(needs\.impact\.outputs\.jobs \|\| '\[\]'\), '([a-z-]+)'\)",
        lambda match: repr(match[1] in selected), expression)
    expression = re.sub(
        r"needs\.([a-z-]+)\.result",
        lambda match: repr(results.get(match[1], "")), expression)
    expression = expression.replace("github.event_name", repr(event))
    expression = expression.replace("github.event.pull_request.draft", repr(draft))
    expression = expression.replace("inputs.smoke_only", repr(smoke_only))
    expression = expression.replace("cancelled()", repr(cancelled))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", " not ", expression)
    try:
        return bool(eval(expression, {"__builtins__": {}}, {}))
    except (NameError, SyntaxError) as error:
        raise AssertionError(f"{job}: unsupported gate syntax: {expression}") from error


class ReadyPreflight(unittest.TestCase):
    def setUp(self):
        self.full = set(plan([".github/workflows/ci.yml"])["workflows"]["ci.yml"])
        self.healthy = {"impact": "success", **dict.fromkeys(BARRIERS, "success")}

    def test_healthy_ready_keeps_every_expensive_lane_and_existing_barriers(self):
        for job in DEFERRED:
            with self.subTest(job=job):
                self.assertTrue(scheduled(job, self.full, self.healthy))
        for job in BARRIERS:
            self.assertIn("    needs: impact\n", SOURCE[job])
            self.assertNotIn("needs: [impact,", SOURCE[job])
        self.assertEqual(len(plan([".github/workflows/ci.yml"])["codeql"]), 5)

    def test_failed_missing_stale_or_skipped_barrier_withholds_expensive_jobs(self):
        for barrier in BARRIERS:
            for result in ("failure", "cancelled", "skipped", "", "neutral", "timed_out"):
                with self.subTest(barrier=barrier, result=result):
                    results = {**self.healthy, barrier: result}
                    for job in DEFERRED:
                        self.assertFalse(scheduled(job, self.full, results), job)

    def test_cancelled_or_superseded_attempt_never_starts_deferred_work(self):
        for job in DEFERRED:
            self.assertFalse(scheduled(job, self.full, self.healthy, cancelled=True), job)
            self.assertFalse(scheduled(job, self.full, {**self.healthy, "impact": "failure"}), job)

    def test_draft_is_preparation_not_expensive_qualification(self):
        for job in DEFERRED:
            self.assertFalse(scheduled(job, self.full, self.healthy, draft=True), job)

    def test_docs_and_gateway_scope_do_not_require_unselected_platform_jobs(self):
        docs = set(plan(["README.md"])["workflows"]["ci.yml"])
        skipped = {"impact": "success", **dict.fromkeys(BARRIERS, "skipped")}
        self.assertEqual(docs, {"documentation"})
        self.assertTrue(scheduled("components", docs, skipped))
        for job in DEFERRED[1:]:
            self.assertFalse(scheduled(job, docs, skipped), job)
        gateway = set(plan(["crates/proxy/src/lib.rs"])["workflows"]["ci.yml"])
        self.assertTrue(scheduled("components", gateway, {**skipped, "test": "success"}))
        for job in ("all-features", "saml-release-targets", "redis-integration",
                    "postgres-integration", "docker-build"):
            self.assertTrue(scheduled(job, gateway, {**skipped, "test": "success"}), job)
        self.assertFalse(scheduled("agent-lifecycle-macos", gateway, skipped))

    def test_cancelled_shared_consumer_cannot_restart_after_producer(self):
        for job in ("mcp-create-file--linux-create-file",
                    "mcp-create-file--linux-installed-edit"):
            body = MIRROR[job]
            self.assertIn("    if: >-\n      !cancelled() && contains(", body)
            self.assertIn("ci_qualification_build.py guard", body)
            self.assertIn("        if: always()", body)


if __name__ == "__main__":
    unittest.main()
