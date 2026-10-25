"""One planner must retain every original component's executable acceptance."""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_components import blocks, generated, TARGET
import ci_components
from ci_impact import WORKFLOW_JOBS
from ci_admission import component_names


class SharedComponents(unittest.TestCase):
    def test_generator_writes_stable_lf_output_on_every_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "components.yml"
            with patch.object(ci_components, "TARGET", target), patch.object(sys, "argv", ["ci_components.py"]):
                self.assertEqual(ci_components.main(), 0)
            self.assertEqual(target.read_bytes(), generated().encode("utf-8"))

    def test_committed_workflow_matches_all_registered_source_jobs(self):
        self.assertEqual(TARGET.read_text(), generated())
        actual = blocks(TARGET.read_text())
        expected = {f"{wf.removesuffix('.yml')}--{job}" for wf, jobs in WORKFLOW_JOBS.items()
                    if wf != "ci.yml" for job in jobs}
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), 44)
        self.assertIn("gateway-sdk--official-sdk", actual)
        self.assertIn("mcp-https-post--linux-https-post", actual)
        self.assertIn("mcp-real-filesystem--native-ubuntu-2404", actual)

    def test_existing_filesystem_lane_keeps_its_qualified_runner(self):
        source = blocks((ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text())
        self.assertIn("runs-on: ubuntu-22.04", source["required-linux-sandbox-and-real-host"])
        self.assertIn("runs-on: ubuntu-24.04", source["native-ubuntu-2404"])

    def test_ubuntu_preparation_name_matches_trusted_admission(self):
        workflow = "mcp-real-filesystem.yml"
        job = "native-ubuntu-2404"
        central = blocks(TARGET.read_text())["mcp-real-filesystem--" + job]
        name = re.search(r"(?m)^    name: (.+)$", central)
        self.assertIsNotNone(name)
        self.assertEqual(("Components / " + json.loads(name[1]),),
                         component_names(workflow, [job]))

    @unittest.skipUnless(shutil.which("bash"), "Bash is required for native CI preparation")
    def test_native_source_build_failure_preserves_record_and_reports_reason(self):
        job = blocks((ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text())["native-ubuntu-2404"]
        helper = re.search(r"(?ms)^          source_build\(\) \{\n.*?^          \}", job)
        self.assertIsNotNone(helper, "native source failures must be visible without downloading an artifact")
        helper = textwrap.dedent(helper[0])
        for code in (0, 2):
            with self.subTest(exit_code=code), tempfile.TemporaryDirectory() as temporary:
                record = Path(temporary) / "result.json"
                row = {"status": "built-not-qualified" if code == 0 else "failed",
                       "reason": None if code == 0 else "missing_inputs: fixture"}
                script = ("set -euo pipefail\npython3() { printf '%s\\n' \"$FIXTURE\"; return \"$CODE\"; }\n"
                          + helper + '\nsource_build "$RECORD" --build\n')
                result = subprocess.run([shutil.which("bash"), "-c", script],
                                        env={**os.environ, "FIXTURE": json.dumps(row),
                                             "CODE": str(code), "RECORD": str(record)},
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(json.loads(record.read_text()), row)
                self.assertEqual(result.stdout, "" if code == 0 else json.dumps(row) + "\n")

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
