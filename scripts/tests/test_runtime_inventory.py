# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

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

    def test_unresolved_virtual_dependencies_are_not_installed_coverage(self):
        report = copy.deepcopy(self.report)
        report["results"][1]["source"]["type"] = "unknown"
        with self.assertRaisesRegex(ValueError, "source_type"):
            inventory.verify_osv(report, self.graphs)

    def test_numeric_python_release_zero_padding_is_equivalent_but_other_versions_are_not(self):
        report = copy.deepcopy(self.report)
        report["results"][1]["packages"][0]["package"]["version"] = "2.0.0"
        inventory.verify_osv(report, self.graphs)
        for version in ("2.0.1", "2.0rc1", "2.0.post1", "20.0"):
            report["results"][1]["packages"][0]["package"]["version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "exact_graph_mismatch"):
                inventory.verify_osv(report, self.graphs)

    def test_original_server_notice_must_match_the_shipped_source_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "profiles/mcp/filesystem-readonly-v1"
            source.mkdir(parents=True)
            generation = root / "generation"
            notice = generation / "filesystem-profile/upstream-notices/server-LICENSE"
            notice.parent.mkdir(parents=True)
            notice.write_text("Original upstream license text")
            identity = {"package": {"name": "original-server", "version": "1.0"}, "upstreamNotices": [{
                "component": "server", "path": "upstream-notices/server-LICENSE", "sha256": inventory.sha(notice)}]}
            (source / "upstream-identity.json").write_text(json.dumps(identity))
            with patch.object(inventory, "ROOT", root):
                self.assertEqual(inventory.original_server_notices(generation, {"name": "original-server", "version": "1.0"}), [notice])
                self.assertEqual(inventory.original_server_notices(generation, {"name": "unrelated", "version": "1.0"}), [])
                notice.write_text("Replaced")
                with self.assertRaisesRegex(ValueError, "notice_changed"):
                    inventory.original_server_notices(generation, {"name": "original-server", "version": "1.0"})

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

    def test_prefetched_rustsec_requires_exact_clean_official_source(self):
        with tempfile.TemporaryDirectory() as temp:
            replies = [{"status": "passed", "stdout": "a" * 40},
                       {"status": "passed", "stdout": "https://github.com/RustSec/advisory-db.git"},
                       {"status": "passed", "stdout": ""}]
            with patch.object(inventory, "run_cmd", side_effect=copy.deepcopy(replies)):
                self.assertEqual(inventory.rustsec_identity(temp, "a" * 40)["commit"], "a" * 40)
            for index, value in [(0, "b" * 40), (1, "https://example.invalid/database"), (2, " M changed.toml")]:
                changed = copy.deepcopy(replies)
                changed[index]["stdout"] = value
                with patch.object(inventory, "run_cmd", side_effect=changed), self.assertRaises(ValueError):
                    inventory.rustsec_identity(temp, "a" * 40)
            with self.assertRaisesRegex(ValueError, "expected_rustsec_commit_required"):
                inventory.rustsec_identity(temp, None)

    def test_cargo_audit_cannot_clear_an_empty_database_or_informational_findings(self):
        report = {"database": {"advisory-count": 1}, "lockfile": {"dependency-count": 1},
                  "vulnerabilities": {"found": False, "list": []}, "warnings": {}}
        inventory.verify_cargo_audit(report)
        empty = copy.deepcopy(report)
        empty["database"]["advisory-count"] = 0
        with self.assertRaisesRegex(ValueError, "incomplete_or_findings"):
            inventory.verify_cargo_audit(empty)
        warning = copy.deepcopy(report)
        warning["warnings"] = {"unmaintained": [{"package": "example"}]}
        with self.assertRaisesRegex(ValueError, "incomplete_or_findings"):
            inventory.verify_cargo_audit(warning)

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

    def provenance_fixture(self, root, *, name="python-lib", expression="BSD-3-Clause", owner=None):
        site = root / "python-package/python/lib/python3.11/site-packages"
        notices, graph = inventory.installed_python(site, self.graphs[next(
            path for path in self.graphs if path.endswith("requirements.lock"))])
        notice = next(row for row in notices if row["name"] == name and row["origin"]["owner"] == owner)
        def relative_map(files):
            return {Path(path).relative_to(site).as_posix(): digest for path, digest in files.items()}
        source = root / "profiles/mcp/git-readonly-v1"
        source.mkdir(parents=True)
        relative = "upstream-notices/runtime-licenses/provenance.json"
        supplement = "upstream-notices/runtime-licenses/original-NOTICE"
        text = source / supplement
        text.parent.mkdir(parents=True)
        text.write_text("Exact original upstream attribution\n")
        row = {"ecosystem": "PyPI", "name": name, "version": notice["version"],
               "origin": {**notice["origin"], "path": Path(notice["origin"]["path"]).relative_to(site).as_posix()},
               "original_declared_license": notice["license"],
               "original_license_declarations": notice.get("license_declarations"),
               "observed_identity_files": relative_map(notice["identity_files"]),
               "installed_notices": relative_map(notice["files"]),
               "source": {"archive_url": "https://files.pythonhosted.org/packages/exact.whl",
                          "archive_sha256": "a" * 64, "metadata_sha256": "b" * 64,
                          "notices": [{"sha256": digest} for digest in notice["files"].values()]
                                     + [{"sha256": inventory.sha(text)}]},
               "evidenced_spdx_expression": expression, "obligations": ["Retain attribution"],
               "supplemental_notices": [{"path": supplement, "sha256": inventory.sha(text)}]}
        if owner:
            parent = next(item for item in notices if item["name"] == owner
                          and item["origin"]["kind"] == "installed_distribution")
            row["parent_distribution"] = {"name": owner, "version": parent["version"],
                                           "identity_files": relative_map(parent["identity_files"])}
        provenance = source / relative
        provenance.write_text(json.dumps({"format": "sw-python-runtime-license-provenance/1", "components": [row]}))
        binding = {"path": relative, "sha256": inventory.sha(provenance)}
        (source / "upstream-identity.json").write_text(json.dumps({"runtime_license_provenance": binding}))
        installed = root / "git-profile"
        shutil.copytree(source / "upstream-notices", installed / "upstream-notices")
        (installed / "installation.json").write_text(json.dumps({"upstream_identity": {"runtime_license_provenance": binding}}))
        policy = root / "policy/license-policy.toml"
        policy.parent.mkdir()
        shutil.copyfile(inventory.ROOT / "policy/license-policy.toml", policy)
        return site, source, installed, row

    def test_exact_provenance_resolves_legacy_metadata_and_preserves_raw_declarations(self):
        for raw, expression in (("BSD License", "BSD-3-Clause"), (None, "MIT")):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                metadata = root / "python-package/python/lib/python3.11/site-packages/python-lib.dist-info/METADATA"
                metadata.write_text("Name: python-lib\nVersion: 2.0\n" + (f"License: {raw}\n" if raw else ""))
                self.provenance_fixture(root, expression=expression)
                with patch.object(inventory, "ROOT", root):
                    notices, graph, errors = inventory.installed_graphs(root, self.graphs)
                self.assertFalse(errors)
                notice = next(row for row in notices if row["name"] == "python-lib")
                self.assertEqual(notice["license"], raw)
                self.assertEqual(notice["original_declared_license"], raw)
                self.assertEqual(notice["license_declarations"]["License"], [raw] if raw else [])
                self.assertEqual(notice["effective_license"], expression)
                self.assertEqual(notice["attribution"]["status"], "notice_verified")
                self.assertFalse(notice["policy_disposition_required"])
                self.assertEqual(graph, {("PyPI", "python-lib", "2.0"), ("PyPI", "pip", "1.0")})
                self.assertTrue(any(path.endswith("original-NOTICE") for path in notice["files"]))

    def test_verified_attribution_does_not_waive_disallowed_licenses(self):
        for expression in ("LGPL-3.0-or-later", "MPL-2.0", "PSF-2.0", "BlueOak-1.0.0"):
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                self.provenance_fixture(root, expression=expression)
                with patch.object(inventory, "ROOT", root):
                    notices, _, errors = inventory.installed_graphs(root, self.graphs)
                notice = next(row for row in notices if row["name"] == "python-lib")
                self.assertEqual(notice["attribution"]["status"], "notice_verified")
                self.assertTrue(notice["policy_disposition_required"])
                self.assertEqual(notice["policy"]["status"], "disallowed")
                self.assertIn("runtime_license_review_required:python-lib", errors)

    def test_provenance_source_and_installed_bindings_cannot_fall_back(self):
        for change in ("source_hash", "source_missing", "installed_missing", "installed_changed",
                       "supplement_missing", "supplement_changed", "source_supplement_changed", "receipt_binding"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                _, source, installed, row = self.provenance_fixture(root)
                source_path = source / "upstream-notices/runtime-licenses/provenance.json"
                installed_path = installed / "upstream-notices/runtime-licenses/provenance.json"
                supplemental = installed / row["supplemental_notices"][0]["path"]
                if change == "source_hash": source_path.write_text(source_path.read_text() + " ")
                elif change == "source_missing": source_path.unlink()
                elif change == "installed_missing": installed_path.unlink()
                elif change == "installed_changed": installed_path.write_text("{}")
                elif change == "supplement_missing": supplemental.unlink()
                elif change == "supplement_changed": supplemental.write_text("Replaced")
                elif change == "source_supplement_changed": (source / row["supplemental_notices"][0]["path"]).write_text("Replaced")
                else: (installed / "installation.json").write_text('{"upstream_identity":{}}')
                with patch.object(inventory, "ROOT", root):
                    notices, graph, errors = inventory.installed_graphs(root, self.graphs)
                self.assertTrue(any(error.startswith("runtime_license_provenance:") for error in errors))
                self.assertEqual(len(notices), 3)
                self.assertEqual(len(graph), 2)
                notice = next(row for row in notices if row["name"] == "python-lib")
                self.assertEqual(notice["attribution"]["status"], "rejected")
                self.assertEqual(notice["license"], "MIT")
                self.assertIsNone(notice["effective_license"])

    def test_provenance_rejects_changed_identity_notice_and_parent(self):
        for change in ("metadata", "notice", "parent"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                self.vendor_fixture(root)
                site, _, _, _ = self.provenance_fixture(root, name="urllib3", expression="MIT", owner="pip")
                path = {"metadata": site / "pip/_vendor/vendor.txt", "notice": site / "pip/_vendor/urllib3.LICENSE",
                        "parent": site / "pip.dist-info/METADATA"}[change]
                path.write_text(path.read_text() + ("# changed\n" if change == "metadata" else "\nChanged evidence\n"))
                with patch.object(inventory, "ROOT", root):
                    notices, _, errors = inventory.installed_graphs(root, self.graphs)
                notice = next(row for row in notices if row["name"] == "urllib3")
                self.assertIsNone(notice["effective_license"])
                self.assertEqual(notice["attribution"]["status"], "rejected")
                self.assertTrue(any("runtime_license_provenance_mismatch:urllib3" in error for error in errors))

    def test_unknown_version_origin_and_source_only_assets_never_supply_a_mapping(self):
        for change in ("version", "owner", "kind", "source_only"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                self.vendor_fixture(root)
                site, _, installed, _ = self.provenance_fixture(root, name="urllib3", expression="MIT", owner="pip")
                with patch.object(inventory, "ROOT", root):
                    provenance = inventory.runtime_license_provenance(root)
                    notices, before = inventory.installed_python(site, self.graphs[next(
                        path for path in self.graphs if path.endswith("requirements.lock"))])
                    target = next(row for row in notices if row["name"] == "urllib3")
                    if change == "version": target["version"] = "2.0"
                    elif change == "owner": target["origin"]["owner"] = "setuptools"
                    elif change == "kind": target["origin"]["kind"] = "installed_distribution"
                    else:
                        (installed / "installation.json").unlink()
                        shutil.rmtree(installed / "upstream-notices")
                        provenance = inventory.runtime_license_provenance(root)
                        self.assertIsNone(provenance)
                    inventory.apply_runtime_license_provenance(notices, site, root, provenance)
                self.assertIsNone(target["effective_license"])
                self.assertNotIn("attribution", target)
                self.assertIn(("PyPI", "urllib3", "1.0"), before)

    def test_authors_and_declared_notices_are_collected_without_sibling_sweeps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dist = root / "example.dist-info"
            dist.mkdir()
            files = [dist / "AUTHORS", dist / "CREDITS", root / "other.dist-info/LICENSE"]
            for path in files:
                path.parent.mkdir(exist_ok=True)
                path.write_text("Original text")
            observed = inventory.python_notice_files(files, dist, ["CREDITS"])
            self.assertEqual(set(observed), {str(dist / "AUTHORS"), str(dist / "CREDITS")})
            for unsafe in ("../LICENSE", "/LICENSE", "C:/LICENSE", "sub\\LICENSE"):
                with self.subTest(unsafe=unsafe), self.assertRaisesRegex(ValueError, "unsafe_path"):
                    inventory.python_notice_files(files, dist, [unsafe])

    def test_bound_notices_reject_path_escapes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "LICENSE"
            path.write_text("Original")
            for unsafe in ("../LICENSE", "/LICENSE", "nested/../LICENSE", "C:/LICENSE", "sub\\LICENSE"):
                with self.subTest(unsafe=unsafe), self.assertRaisesRegex(ValueError, "unsafe_path"):
                    inventory.bound_file(root, unsafe, inventory.sha(path))
            link = root / "linked"
            try:
                link.symlink_to(path)
            except OSError:
                pass  # Windows accounts may lack symbolic-link creation privileges.
            else:
                with self.assertRaisesRegex(ValueError, "unsafe_path"):
                    inventory.bound_file(root, "linked", inventory.sha(path))

    def test_shipped_provenance_has_exact_bounded_rows_and_installed_assets(self):
        source = inventory.ROOT / "profiles/mcp/git-readonly-v1"
        identity = inventory.read_json(source / "upstream-identity.json")
        with tempfile.TemporaryDirectory() as temp:
            generation = Path(temp)
            installed = generation / "git-profile"
            installed.mkdir()
            shutil.copytree(source / "upstream-notices/runtime-licenses", installed / "upstream-notices/runtime-licenses")
            (installed / "installation.json").write_text(json.dumps({"upstream_identity": identity}))
            evidence = inventory.runtime_license_provenance(generation)
            self.assertIsNotNone(evidence)
            self.assertEqual(len(evidence["components"]), 23)
            supplemental = []
            for row in evidence["components"]:
                self.assertNotIn("approved", row)
                self.assertNotIn("selected_license", row)
                self.assertIn("original_declared_license", row)
                if row["origin"]["owner"]:
                    self.assertEqual(row["parent_distribution"]["name"], row["origin"]["owner"])
                supplemental.extend(item["path"] for item in row["supplemental_notices"])
            self.assertEqual({Path(path).name for path in supplemental},
                         {"gitdb-4.0.12-AUTHORS", "pygments-2.21.0-AUTHORS", "requests-2.34.2-NOTICE"})

    def vendor_fixture(self, root, *, name="urllib3", version="1.0", owner="pip", metadata=False):
        site = root / "python-package/python/lib/python3.11/site-packages"
        vendor = site / owner / "_vendor"
        vendor.mkdir(parents=True, exist_ok=True)
        module = "pkg_resources" if name == "setuptools" else name.replace("-", "_")
        code = vendor / (module + ".py")
        code.write_text("# Selected vendored component; never executed by inventory.\n")
        if owner == "pip":
            (vendor / "vendor.txt").write_text(f"{name}=={version}\n")
            (vendor / (module + ".LICENSE")).write_text("Actual component notice")
        if metadata:
            dist = vendor / (name + "-" + version + ".dist-info")
            dist.mkdir()
            (dist / "METADATA").write_text(f"Name: {name}\nVersion: {version}\nLicense-Expression: MIT\n")
            (dist / "LICENSE").write_text("Actual nested distribution notice")
            (dist / "RECORD").write_text(f"{code.name},,\n")
        return vendor

    def test_vendored_vulnerable_pin_is_in_exact_scanner_graph_and_retains_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root)
            vendor = self.vendor_fixture(root)
            notices, graph, errors = inventory.installed_graphs(root, self.graphs)
            identity = ("PyPI", "urllib3", "1.0")
            self.assertIn(identity, graph)
            row = next(row for row in notices if row["name"] == "urllib3")
            self.assertEqual(row["origin"]["owner"], "pip")
            self.assertEqual(row["identity_files"], {str(vendor / "vendor.txt"): inventory.sha(vendor / "vendor.txt")})
            self.assertEqual(row["files"], {str(vendor / "urllib3.LICENSE"): inventory.sha(vendor / "urllib3.LICENSE")})
            self.assertIn("runtime_license_notice_incomplete:urllib3", errors)
            path = str((root / "installed-requirements.txt").resolve())
            report = {"results": [{"source": {"type": "lockfile", "path": path}, "packages": [
                {"package": dict(zip(("ecosystem", "name", "version"), item)),
                 "vulnerabilities": [{"id": "VENDORED-ADVISORY"}] if item == identity else []}
                for item in graph]}]}
            observation = inventory.osv_observation(report, {path: graph})
            self.assertEqual(observation["findings"][0]["package"]["name"], "urllib3")
            with self.assertRaisesRegex(ValueError, "unresolved_osv_findings"):
                inventory.verify_osv(report, {path: graph})
            report["results"][0]["packages"] = [row for row in report["results"][0]["packages"]
                                                      if row["package"]["name"] != "urllib3"]
            with self.assertRaisesRegex(ValueError, "exact_graph_mismatch"):
                inventory.osv_observation(report, {path: graph})

    def test_parallel_vendored_versions_and_origins_are_not_dropped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root, extra="setuptools")
            self.vendor_fixture(root, name="python-lib", version="1.0", owner="setuptools", metadata=True)
            notices, graph, errors = inventory.installed_graphs(root, self.graphs)
            self.assertTrue({("PyPI", "python-lib", "1.0"), ("PyPI", "python-lib", "2.0")} <= graph)
            rows = [row for row in notices if row["name"] == "python-lib"]
            self.assertEqual(len(rows), 2)
            self.assertEqual({row["origin"]["kind"] for row in rows}, {"installed_distribution", "vendored_distribution"})
            self.assertFalse(errors)

    def test_vendor_metadata_cannot_satisfy_missing_top_level_lock_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root, extra="setuptools")
            self.vendor_fixture(root, name="python-lib", version="2.0", owner="setuptools", metadata=True)
            site = root / "python-package/python/lib/python3.11/site-packages"
            (site / "python-lib.dist-info/METADATA").write_text("Name: other\nVersion: 2.0\nLicense: MIT\n")
            with self.assertRaisesRegex(ValueError, "installed_python_graph_mismatch"):
                inventory.installed_graphs(root, self.graphs)

    def test_unpinned_ambiguous_and_wrong_vendor_versions_are_rejected(self):
        for text, reason in [("urllib3>=1.0", "unpinned"), ("urllib3==1.0\nurllib3==2.0", "duplicate"),
                             ("urllib3==2.0", "version_mismatch"), ("urllib3==1.0;evil", "invalid")]:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                vendor = self.vendor_fixture(root, metadata=True)
                (vendor / "vendor.txt").write_text(text)
                with self.assertRaisesRegex(ValueError, reason):
                    inventory.installed_graphs(root, self.graphs)

    def test_missing_vendor_material_and_manifest_and_unpinned_code_are_rejected(self):
        for change, reason in [("code", "material_missing"), ("manifest", "manifest_missing"), ("extra", "unpinned_material")]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root)
                vendor = self.vendor_fixture(root)
                if change == "code":
                    (vendor / "urllib3.py").unlink()
                elif change == "manifest":
                    (vendor / "vendor.txt").unlink()
                else:
                    (vendor / "unidentified.py").write_text("# Not pinned")
                with self.assertRaisesRegex(ValueError, reason):
                    inventory.installed_graphs(root, self.graphs)

    def test_nested_metadata_needs_real_record_material_and_safe_paths(self):
        for record, reason in [(None, "record_missing"), ("absent.py,,\n", "material_missing"),
                               ("../escape.py,,\n", "unsafe_path"), ("/escape.py,,\n", "unsafe_path")]:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root, extra="setuptools")
                vendor = self.vendor_fixture(root, owner="setuptools", metadata=True)
                path = vendor / "urllib3-1.0.dist-info/RECORD"
                if record is None:
                    path.unlink()
                else:
                    path.write_text(record)
                with self.assertRaisesRegex(ValueError, reason):
                    inventory.installed_graphs(root, self.graphs)

    def test_wrong_or_absent_nested_identity_cannot_hide_vendor_code(self):
        for change, reason in [("wrong_version", "metadata_identity_mismatch"),
                               ("duplicate_header", "metadata_ambiguous"),
                               ("extra_code", "unattributed_material"),
                               ("unpinned_pip_metadata", "unpinned_metadata")]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                owner = "pip" if change == "unpinned_pip_metadata" else "setuptools"
                self.installed_fixture(root, extra=owner)
                vendor = self.vendor_fixture(root, owner=owner, metadata=True)
                metadata = vendor / "urllib3-1.0.dist-info/METADATA"
                if change == "wrong_version":
                    metadata.write_text("Name: urllib3\nVersion: 2.0\nLicense: MIT\n")
                elif change == "duplicate_header":
                    metadata.write_text("Name: urllib3\nVersion: 1.0\nVersion: 2.0\nLicense: MIT\n")
                elif change == "extra_code":
                    (vendor / "hidden.py").write_text("# Missing distribution metadata")
                else:
                    (vendor / "vendor.txt").write_text("requests==1.0\n")
                with self.assertRaisesRegex(ValueError, reason):
                    inventory.installed_graphs(root, self.graphs)

    def test_nested_opaque_license_or_missing_notice_remains_blocking(self):
        for missing in ("license", "notice"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.installed_fixture(root, extra="setuptools")
                vendor = self.vendor_fixture(root, owner="setuptools", metadata=True)
                dist = vendor / "urllib3-1.0.dist-info"
                if missing == "license":
                    (dist / "METADATA").write_text("Name: urllib3\nVersion: 1.0\nLicense: Opaque-License\n")
                else:
                    (dist / "LICENSE").unlink()
                notices, graph, errors = inventory.installed_graphs(root, self.graphs)
                self.assertIn(("PyPI", "urllib3", "1.0"), graph)
                self.assertEqual(len([error for error in errors if "urllib3" in error]), 1)

    def main_scan_fixture(self, native_error=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.installed_fixture(root)
            self.vendor_fixture(root, name="setuptools", version="70.3.0")
            selection = root / "selection.json"
            selection.write_text(json.dumps({"prepared_profiles": {}, "source": {}, "files": {}}))
            graphs = {}
            for basename, graph in zip(("Cargo.lock", "requirements.lock", "package-lock.json"), self.graphs.values()):
                path = root / basename
                path.write_text("selected scan input")
                graphs[str(path.resolve())] = graph
            prep = SimpleNamespace(verify_generation=Mock())
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
            output = root / "fresh-report.json"
            def scan(command, **kwargs):
                if command[0] == "osv-scanner":
                    path = root / "fresh-report-installed-requirements.txt"
                    packages = [inventory.python_identity(*line.split("==")) for line in path.read_text().splitlines()]
                    observed = {**graphs}
                    observed.pop(str((root / "requirements.lock").resolve()))
                    observed[str(path.resolve())] = set(packages)
                    data = {"results": [{"source": {"type": "lockfile", "path": source}, "packages": [
                        {"package": dict(zip(("ecosystem", "name", "version"), item))} for item in graph]}
                        for source, graph in observed.items()]}
                else:
                    data = {"database": {"advisory-count": 1}, "lockfile": {"dependency-count": 1},
                            "vulnerabilities": {"found": False, "list": []}, "warnings": {}}
                return {"status": "passed", "exit_code": 0, "command": command, "stdout": json.dumps(data), "stderr": ""}
            with patch.object(inventory.importlib.util, "spec_from_file_location", return_value=spec), \
                    patch.object(inventory.importlib.util, "module_from_spec", return_value=prep), \
                    patch.object(inventory, "lock_graphs", return_value=copy.deepcopy(graphs)), \
                    patch.object(inventory, "verify_native_reviews", return_value={}, side_effect=native_error), \
                    patch.object(inventory, "run_cmd", side_effect=scan):
                self.assertEqual(inventory.main(["--selection", str(selection), "--expected-commit", "a" * 40,
                                                 "--output", str(output)]), 1)
            self.assertEqual(prep.verify_generation.call_count, 2)
            prep.verify_generation.assert_called_with(root, "a" * 40, probe_native=False)
            report = json.loads(output.read_text())
            self.assertIn(["PyPI", "setuptools", "70.3.0"], report["python_graphs"]["vendored"])
            self.assertNotIn(["PyPI", "setuptools", "70.3.0"], report["python_graphs"]["top_level"])
            self.assertIn("setuptools==70.3.0", (root / "fresh-report-installed-requirements.txt").read_text())
            self.assertIn("osv_coverage", report)
            return report

    def test_main_scans_union_and_rechecks_selected_tree_contract(self):
        self.main_scan_fixture()

    def test_native_process_failure_retains_scans_and_refuses_clearance(self):
        for error in (subprocess.TimeoutExpired(["python", "--version"], 5),
                      subprocess.CalledProcessError(1, ["python", "--version"]),
                      AttributeError("invalid native review component field")):
            with self.subTest(error=type(error).__name__):
                report = self.main_scan_fixture(error)
                self.assertEqual(report["status"], "incomplete")
                self.assertTrue(any(row.startswith("native_reviews:") for row in report["errors"]))
                self.assertEqual(set(report["checks"]), {"cargo_audit", "rust_licenses", "osv"})


if __name__ == "__main__":
    unittest.main()
