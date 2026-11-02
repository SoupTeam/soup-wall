# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_inventory as inventory


class RuntimeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.graphs = {str(Path("Cargo.lock").resolve()): {("crates.io", "rust", "1.0")},
                       str(Path("requirements.lock").resolve()): {("PyPI", "python-lib", "2.0")},
                       str(Path("package-lock.json").resolve()): {("npm", "node-lib", "3.0")}}
        self.report = {"results": [{"source": {"type": "lockfile", "path": path},
            "packages": [{"package": dict(zip(("ecosystem", "name", "version"), item))} for item in graph]}
            for path, graph in self.graphs.items()]}

    def test_exact_identity_coverage_passes(self):
        self.assertEqual(set(inventory.verify_osv(self.report, self.graphs).values()), {1})

    def test_unrelated_names_and_versions_with_identical_counts_fail(self):
        for field in ("name", "version", "ecosystem"):
            report = copy.deepcopy(self.report)
            report["results"][0]["packages"][0]["package"][field] = "unrelated"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "exact_graph_mismatch"):
                inventory.verify_osv(report, self.graphs)

    def test_swapped_ecosystems_with_same_counts_fail(self):
        report = copy.deepcopy(self.report)
        a = report["results"][0]["packages"][0]["package"]
        b = report["results"][1]["packages"][0]["package"]
        a["ecosystem"], b["ecosystem"] = b["ecosystem"], a["ecosystem"]
        with self.assertRaisesRegex(ValueError, "exact_graph_mismatch"):
            inventory.verify_osv(report, self.graphs)

    def test_findings_including_informational_remain_blocking(self):
        for finding in ({"id": "TEST-advisory"}, {"id": "TEST", "database_specific": {"informational": "unmaintained"}}):
            report = copy.deepcopy(self.report)
            report["results"][0]["packages"][0]["vulnerabilities"] = [finding]
            with self.assertRaisesRegex(ValueError, "unresolved_osv_findings"):
                inventory.verify_osv(report, self.graphs)

    def test_missing_empty_and_unrelated_sources_fail(self):
        for report in ({}, {"results": []}, {"results": self.report["results"][:-1]}):
            with self.assertRaises(ValueError):
                inventory.verify_osv(report, self.graphs)
        report = copy.deepcopy(self.report)
        report["results"][0]["source"]["path"] = "different/Cargo.lock"
        with self.assertRaisesRegex(ValueError, "unexpected_source"):
            inventory.verify_osv(report, self.graphs)

    def test_python_name_normalization_is_ecosystem_specific(self):
        report = copy.deepcopy(self.report)
        report["results"][1]["packages"][0]["package"]["name"] = "Python_Lib"
        inventory.verify_osv(report, self.graphs)

    def test_real_shipped_graphs_are_finite_and_include_both_original_servers(self):
        graph = set.union(*inventory.lock_graphs().values())
        self.assertIn(("PyPI", "mcp-server-git", "2026.10.10"), graph)
        self.assertIn(("npm", "@modelcontextprotocol/server-filesystem", "2026.8.31"), graph)
        self.assertGreater(len(graph), 100)

    def test_missing_scanner_is_incomplete(self):
        result = inventory.run_cmd(["a-scanner-that-does-not-exist"])
        self.assertEqual(result["status"], "incomplete")

    def test_scanner_nonzero_cannot_pass(self):
        result = inventory.run_cmd([sys.executable, "-c", "raise SystemExit(127)"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 127)

    def test_timeout_is_bounded(self):
        result = inventory.run_cmd([sys.executable, "-c", "import time; time.sleep(20)"], timeout=0.2)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("timeout", result["reason"])

    def test_source_identity_is_not_an_installed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            status = inventory.main(["--selection", str(inventory.ROOT / "profiles/mcp/git-readonly-v1/upstream-identity.json"),
                "--expected-commit", "a" * 40, "--native-reviews", str(Path(temp) / "missing.json"), "--output", str(output)])
            self.assertEqual(status, 1)
            data = json.loads(output.read_text())
            self.assertEqual(data["status"], "incomplete")
            self.assertIn("verified_installed_selection_required", data["errors"])


if __name__ == "__main__":
    unittest.main()
