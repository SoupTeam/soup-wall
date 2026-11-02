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

    def test_unknown_source_label_still_requires_exact_path_and_identity(self):
        report = copy.deepcopy(self.report)
        report["results"][1]["source"]["type"] = "unknown"
        inventory.verify_osv(report, self.graphs)
        report["results"][1]["packages"][0]["package"]["version"] = "unrelated"
        with self.assertRaisesRegex(ValueError, "exact_graph_mismatch"):
            inventory.verify_osv(report, self.graphs)

    def test_full_local_cargo_rows_are_correlated_without_losing_source_origins(self):
        graph = inventory.lock_graphs()[str((inventory.ROOT / "Cargo.lock").resolve())]
        self.assertIn(("crates.io", "agentfw", "0.3.0"), graph)
        self.assertIn(("crates.io", "kryptering", "0.6.0"), graph)

    def test_findings_are_retained_separately_from_exact_coverage(self):
        report = copy.deepcopy(self.report)
        advisory = {"id": "TEST-1", "affected": [{"ranges": [{"events": [{"fixed": "2.0"}]}]}]}
        report["results"][0]["packages"][0]["vulnerabilities"] = [advisory]
        observation = inventory.osv_observation(report, self.graphs)
        self.assertEqual(len(observation["coverage"]), 3)
        self.assertEqual(observation["findings"][0]["advisory"], advisory)
        self.assertEqual(observation["findings"][0]["reachability"], "not_established")
        with self.assertRaisesRegex(ValueError, "unresolved_osv_findings"):
            inventory.verify_osv(report, self.graphs)

    def test_rust_license_report_is_scoped_to_source_even_for_external_inventory_output(self):
        path = inventory.ROOT / "target/runtime-inventory-license-test/report.json"
        command = inventory.rust_license_command(path)
        self.assertEqual(command[-2:], ["--report", str(path)])
        with self.assertRaisesRegex(ValueError, "outside_source"):
            inventory.rust_license_command(inventory.ROOT.parent / "report.json")

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
        result = inventory.run_cmd([sys.executable, "-c", "import time; print('entered',flush=True); time.sleep(20)"], timeout=0.2)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("timeout", result["reason"])
        self.assertIn("entered", result["stdout"])

    def test_source_identity_is_not_an_installed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            status = inventory.main(["--selection", str(inventory.ROOT / "profiles/mcp/git-readonly-v1/upstream-identity.json"),
                "--expected-commit", "a" * 40, "--native-reviews", str(Path(temp) / "missing.json"), "--output", str(output)])
            self.assertEqual(status, 1)
            data = json.loads(output.read_text())
            self.assertEqual(data["status"], "incomplete")
            self.assertIn("verified_installed_selection_required", data["errors"])

    def installed_fixture(self, root, *, extra="pip", license="MIT"):
        npm = root / "npm-package"
        dep = npm / "node_modules/node-lib"
        dep.mkdir(parents=True)
        (dep / "package.json").write_text(json.dumps({"name": "node-lib", "version": "3.0", "license": "MIT"}))
        (dep / "LICENSE").write_text("existing npm license")
        (npm / "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/node-lib": {"version": "3.0"}}}))
        python = root / "python-package"
        site = python / "python/lib/python3.11/site-packages"
        for name, version in [("python-lib", "2.0"), (extra, "1.0")]:
            dist = site / (name + ".dist-info")
            dist.mkdir(parents=True)
            (dist / "METADATA").write_text(f"Name: {name}\nVersion: {version}\nLicense-Expression: {license}\n")
            (dist / "LICENSE").write_text("existing Python license")
        for kind, package in [("filesystem", npm), ("git", python)]:
            directory = root / (kind + "-profile")
            directory.mkdir()
            (directory / "profile.json").write_text(json.dumps({"packageRoot": str(package)}))

    def test_bundled_bootstrap_package_is_included_in_scan_graph(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root)
            notices, graph, errors = inventory.installed_graphs(root, self.graphs)
            self.assertIn(("PyPI", "pip", "1.0"), graph)
            self.assertFalse(errors)
            self.assertEqual(len(notices), 3)

    def test_unrelated_installed_distribution_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root, extra="unrelated-package")
            with self.assertRaisesRegex(ValueError, "unexpected_python_distribution"):
                inventory.installed_graphs(root, self.graphs)

    def test_installed_version_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root)
            metadata = root / "npm-package/node_modules/node-lib/package.json"
            metadata.write_text(json.dumps({"name": "node-lib", "version": "different", "license": "MIT"}))
            with self.assertRaisesRegex(ValueError, "installed_npm_version_mismatch"):
                inventory.installed_graphs(root, self.graphs)

    def test_unreviewed_license_retains_inventory_and_blocking_reasons(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root, license="Unreviewed-License")
            notices, graph, errors = inventory.installed_graphs(root, self.graphs)
            self.assertEqual(len(notices), 3)
            self.assertEqual(len(errors), 2)
            self.assertTrue(all("runtime_license_review_required" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
