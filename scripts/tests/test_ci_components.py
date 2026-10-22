"""One planner must retain every original component's executable acceptance."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_components import blocks, generated, TARGET
from ci_impact import WORKFLOW_JOBS


class SharedComponents(unittest.TestCase):
    def test_committed_workflow_matches_all_registered_source_jobs(self):
        self.assertEqual(TARGET.read_text(), generated())
        actual = blocks(TARGET.read_text())
        expected = {f"{wf.removesuffix('.yml')}--{job}" for wf, jobs in WORKFLOW_JOBS.items()
                    if wf != "ci.yml" for job in jobs}
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), 43)
        self.assertIn("gateway-sdk--official-sdk", actual)
        self.assertIn("mcp-https-post--linux-https-post", actual)
        self.assertIn("mcp-real-filesystem--native-ubuntu-2404", actual)

    def test_existing_filesystem_lane_keeps_its_qualified_runner(self):
        source = blocks((ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text())
        self.assertIn("runs-on: ubuntu-22.04", source["required-linux-sandbox-and-real-host"])
        self.assertIn("runs-on: ubuntu-24.04", source["native-ubuntu-2404"])

    def test_runtime_steps_and_platform_controls_are_not_replaced_by_summaries(self):
        central = blocks(TARGET.read_text())
        for wf, ids in WORKFLOW_JOBS.items():
            if wf == "ci.yml":
                continue
            source = blocks((ROOT / ".github/workflows" / wf).read_text(encoding="utf-8-sig"))
            for job_id in ids:
                with self.subTest(workflow=wf, job=job_id):
                    old, new = source[job_id], central[f"{wf.removesuffix('.yml')}--{job_id}"]
                    self.assertEqual(old.split("    steps:", 1)[1].rstrip(),
                                     new.split("    steps:", 1)[1].rstrip())
                    for field in ("runs-on", "timeout-minutes", "strategy", "services", "container"):
                        pattern = rf"(?m)^    {field}:.*(?:\n(?!    [a-z-]+:|  [a-z-]+:).*)*"
                        self.assertEqual(re.findall(pattern, old), re.findall(pattern, new))
                    self.assertNotIn("needs.impact", new)
                    self.assertIn("fromJSON(inputs.plan).workflows['" + wf + "']", new)

    def test_shared_workflow_cannot_be_triggered_independently_or_allocate_planners(self):
        text = TARGET.read_text()
        self.assertIn("  workflow_call:", text)
        self.assertNotRegex(text, r"(?m)^  (pull_request|pull_request_target|push|workflow_run):")
        self.assertNotIn("uses: ./.github/workflows/ci-impact-plan.yml", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertIn("  contents: read", text)

    def test_full_plan_is_passed_without_a_second_api_planner(self):
        root = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(root.count("uses: ./.github/workflows/ci-impact-plan.yml"), 1)
        self.assertIn("plan: ${{ needs.impact.outputs.plan }}", root)
        planner = (ROOT / ".github/workflows/ci-impact-plan.yml").read_text()
        self.assertIn("plan: ${{ steps.plan.outputs.plan }}", planner)
        self.assertIn("value: ${{ jobs.compute.outputs.plan }}", planner)

    def test_implicit_matrix_names_keep_each_required_platform_and_backend(self):
        text = TARGET.read_text()
        self.assertIn('native-mcp-stderr / native-platform-launch (${{ matrix.os }})', text)
        self.assertIn('scim-directory / interoperability (${{ matrix.backend }})', text)
