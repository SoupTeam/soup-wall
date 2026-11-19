# SPDX-License-Identifier: Apache-2.0
"""Review inputs must be bounded regular files before inventory hashes them."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import runtime_reviews


def inventory_probe(option, review_path, fixture):
    # Exercise main's actual review-input hash/read path. Preparation and scans
    # are unrelated to this file-type contract and use finite public fixtures.
    from types import SimpleNamespace
    from unittest.mock import Mock, patch
    import generate_inventory as inventory
    fixture = Path(fixture)
    fixture.mkdir()
    selection = fixture / "selection.json"
    selection.write_text(json.dumps({"prepared_profiles": {}, "source": {}, "files": {}}))
    cargo = fixture / "Cargo.lock"
    cargo.write_text('version = 3\n[[package]]\nname = "fixture"\nversion = "1.0"\n')
    requirements = fixture / "requirements.lock"
    requirements.write_text("fixture==1.0\n")
    graphs = {str(cargo): {("crates.io", "fixture", "1.0")},
              str(requirements): {("PyPI", "fixture", "1.0")}}
    prep = SimpleNamespace(verify_generation=Mock())
    spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
    output = fixture / "report.json"
    audit = {"database": {"advisory-count": 1},
             "lockfile": {"dependency-count": 1},
             "vulnerabilities": {"found": False, "list": []}, "warnings": {}}
    def scan(command, **kwargs):
        return {"status": "passed", "exit_code": 0, "command": command,
                "stdout": json.dumps(audit), "stderr": ""}
    with patch.object(inventory, "ROOT", fixture), \
            patch.object(inventory.importlib.util, "spec_from_file_location", return_value=spec), \
            patch.object(inventory.importlib.util, "module_from_spec", return_value=prep), \
            patch.object(inventory, "lock_graphs", return_value=graphs), \
            patch.object(inventory, "installed_graphs", return_value=([], {("PyPI", "fixture", "1.0")}, [])), \
            patch.object(inventory, "osv_observation", return_value={"coverage": {}, "findings": []}), \
            patch.object(inventory, "run_cmd", side_effect=scan):
        code = inventory.main(["--selection", str(selection), "--expected-commit", "a" * 40,
                               option, review_path, "--output", str(output)])
    report = json.loads(output.read_text())
    assert code == 1 and report["status"] == "incomplete"
    assert any("evidence_file_invalid" in error or "runtime_reviews_symlink" in error for error in report["errors"]), report["errors"]
    print(json.dumps({"refused": True, "status": report["status"], "option": option}))


class ReviewInputTests(unittest.TestCase):
    def assert_prompt_refusal(self, option, path, root):
        # An unwritten FIFO blocks open(), not read_json's byte limit. A child
        # timeout turns that regression into a bounded failure and reaps it.
        result = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--review-input-probe",
             option, str(path), str(root / "fixture")],
            capture_output=True, text=True, timeout=3, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout.splitlines()[-1])["refused"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires a real POSIX FIFO")
    def test_unwritten_fifo_is_refused_before_review_hash(self):
        for option in ("--runtime-reviews", "--native-reviews"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                fifo = root / "review.json"
                os.mkfifo(fifo)
                self.assert_prompt_refusal(option, fifo, root)

    def test_nonregular_and_oversized_review_inputs_are_refused(self):
        for option in ("--runtime-reviews", "--native-reviews"):
            for kind in ("directory", "symlink", "oversized"):
                with self.subTest(option=option, kind=kind), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    review = root / "review.json"
                    if kind == "directory":
                        review.mkdir()
                    elif kind == "symlink":
                        target = root / "regular.json"
                        target.write_text("{}")
                        try:
                            review.symlink_to(target)
                        except OSError:
                            self.skipTest("symlink creation unavailable")
                    else:
                        with review.open("wb") as stream:
                            stream.truncate(runtime_reviews.MAX_FILE + 1)
                    self.assert_prompt_refusal(option, review, root)

    def test_regular_review_digest_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            review = Path(temp) / "review.json"
            data = b'{"format":"scoped-public-test"}\n'
            review.write_bytes(data)
            self.assertEqual(runtime_reviews.file_sha(review), hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--review-input-probe":
        inventory_probe(*sys.argv[2:])
    else:
        unittest.main()
