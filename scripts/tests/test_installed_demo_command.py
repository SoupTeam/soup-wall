import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile
import unittest


PILOT = Path(__file__).resolve().parents[1] / "pilot.py"


class InstalledDemoCommand(unittest.TestCase):
    def test_packaged_report_matches_source_without_checkout(self):
        source = PILOT.parents[1]
        spec = importlib.util.spec_from_file_location(
            "installed_tools_builder", source / "scripts/build-pilot-front-door.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            component = base / "component"
            for name in builder.paths():
                target = component / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target)
            evidence = base / "evidence"
            evidence.mkdir()
            for root, command, output in (
                (source, [sys.executable, str(source / "scripts/roadmap_support.py")], base / "source-report"),
                (component, [sys.executable, str(component / "scripts/pilot.py"), "roadmap-support"], base / "installed-report"),
            ):
                result = subprocess.run(
                    [*command, "--source", "a" * 40, "--evidence-dir", str(evidence),
                     *([] if root == component else [
                         "--index", str(root / "docs/operations/roadmap-support-index.json"),
                         "--roadmap", str(root / "docs/ROADMAP.md")]),
                     "--output", str(output)],
                    cwd=base, capture_output=True, text=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)
            for name in ("report.json", "index.html"):
                self.assertEqual(
                    (base / "source-report" / name).read_bytes(),
                    (base / "installed-report" / name).read_bytes(),
                )

    def test_help_registers_both_commands_and_their_options(self):
        result = subprocess.run(
            [sys.executable, "-B", str(PILOT), "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("roadmap-support", result.stdout)
        self.assertIn("demo", result.stdout)
        for command, flag in (("demo", "--selection"), ("roadmap-support", "--evidence-dir")):
            result = subprocess.run(
                [sys.executable, "-B", str(PILOT), command, "--help"],
                capture_output=True, text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn(flag, result.stdout)

    def test_demo_plan_works_outside_checkout_without_creating_files(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-B", str(PILOT), "demo"],
                cwd=directory,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual("sw-pilot-demo/1", report["format"])
            self.assertFalse(report["executed"])
            self.assertEqual([], list(Path(directory).iterdir()))
