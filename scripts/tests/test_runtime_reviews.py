# SPDX-License-Identifier: Apache-2.0
"""Scope, custody and negative controls for explicit maintainer review inputs."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_inventory as inventory
import runtime_reviews as reviews


class RuntimeReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.generation = self.root / "generation"
        self.generation.mkdir()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.notice = self.generation / "LICENSE"
        self.notice.write_text("Exact original license notice")
        self.copy = self.bundle / "LICENSE"
        self.copy.write_bytes(self.notice.read_bytes())
        self.note = {"ecosystem": "npm", "name": "reviewed", "version": "1.0",
            "origin": {"kind": "installed_package", "owner": None, "path": "node_modules/reviewed"},
            "license": "BlueOak-1.0.0", "effective_license": "BlueOak-1.0.0",
            "files": {str(self.notice): inventory.sha(self.notice)},
            "policy": {"status": "review_required", "selected": None, "reason": "not_allowed"},
            "policy_disposition_required": True}
        self.report = {"source": {"commit": "a"*40, "tree": "b"*40, "dirty": False},
            "selection_sha256": "c"*64, "binaries": {}, "lock_sha256": {},
            "notices": [self.note], "packages": {"input": [["npm", "reviewed", "1.0"]]},
            "scan_input_sha256": {"input": "d"*64}, "scan_input_labels": {"input": "package-lock.json"}}
        self.requirement = {"id": "notice", "kind": "notice",
            "files": {"LICENSE": inventory.sha(self.copy)}, "installed_files": {},
            "explanation": "Give every recipient the retained notice.",
            "sources": ["https://blueoakcouncil.org/license/1.0.0"]}
        self.data = {"format": reviews.FORMAT, "binding": reviews.context(self.report),
            "decision": {"authority": "user-delegated-project-maintainer", "recorded_by": "Codex",
                "method": "AI-assisted project-maintainer disposition",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "rationale": "Exact selected private runtime license decision."},
            "scope": {"platform": "linux-x86_64",
                "profiles": ["filesystem-readonly-v1", "git-readonly-v1"],
                "distribution": "private-handoff", "constraints": ["Supply this compliance bundle."]},
            "requirements": [self.requirement],
            "licenses": [{"component": reviews.component(self.note), "material_sha256": reviews.digest(self.note),
                "expression": self.note["effective_license"], "disposition": "accepted_with_conditions",
                "requirements": ["notice"], "rationale": "Exact material; preserve license and recipient rights."}],
            "advisories": []}
        self.path = self.bundle / "runtime-reviews.json"

    def check(self, data=None, report=None, findings=()):
        review = reviews.Review(data or self.data, self.path, report or self.report, "a"*40, self.generation)
        review.licenses((report or self.report)["notices"])
        review.advisories(findings)
        return review.finish()

    def test_exact_review_preserves_original_policy_and_material(self):
        before = copy.deepcopy(self.report)
        self.assertEqual(len(self.check()["license_dispositions"]), 1)
        self.assertEqual(before, self.report)
        self.assertTrue(self.note["policy_disposition_required"])

    def test_source_selection_identity_notice_and_graph_drift_reject(self):
        for mutate in (lambda r: r["source"].update(commit="e"*40),
                       lambda r: r["source"].update(tree="e"*40),
                       lambda r: r["source"].update(dirty=True),
                       lambda r: r.update(selection_sha256="e"*64),
                       lambda r: r["notices"][0].update(version="2.0"),
                       lambda r: r["notices"][0]["origin"].update(owner="other"),
                       lambda r: r["notices"][0]["files"].update(changed="e"*64),
                       lambda r: r["packages"]["input"].append(["npm", "extra", "1.0"]),
                       lambda r: r["scan_input_sha256"].update(input="e"*64)):
            changed = copy.deepcopy(self.report)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.check(report=changed)

    def test_absent_default_unknown_fields_duplicates_and_unused_rows_reject(self):
        variants = []
        for path in ((), ("binding",), ("decision",), ("scope",), ("requirements", 0), ("licenses", 0)):
            data = copy.deepcopy(self.data)
            target = data
            for part in path:
                target = target[part]
            target["unknown"] = "not accepted"
            variants.append(data)
        for field in ("licenses", "requirements"):
            data = copy.deepcopy(self.data)
            data[field].append(copy.deepcopy(data[field][0]))
            variants.append(data)
        data = copy.deepcopy(self.data)
        data["licenses"] = []
        variants.append(data)
        data = copy.deepcopy(self.data)
        data["requirements"].append({**self.requirement, "id": "unused"})
        variants.append(data)
        for data in variants:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check(data)

    def test_missing_changed_and_symlinked_compliance_notices_reject(self):
        self.copy.unlink()
        with self.assertRaises(ValueError):
            self.check()
        self.copy.write_text("Changed")
        with self.assertRaises(ValueError):
            self.check()
        self.copy.unlink()
        try:
            self.copy.symlink_to(self.notice)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.check()

    def test_source_and_recombination_conditions_cannot_be_omitted(self):
        for expression in ("PSF-2.0", "MPL-2.0", "LGPL-3.0-or-later", "SEE LICENSE IN LICENSE"):
            report = copy.deepcopy(self.report)
            report["notices"][0]["effective_license"] = expression
            data = copy.deepcopy(self.data)
            data["binding"] = reviews.context(report)
            data["licenses"][0].update(expression=expression,
                material_sha256=reviews.digest(report["notices"][0]))
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, "conditions_missing"):
                self.check(data, report)

    def test_source_copy_must_match_actual_selected_file_and_be_inside_generation(self):
        code = self.generation / "library.py"
        code.write_text("# Editable library source")
        (self.bundle / "library.py").write_bytes(code.read_bytes())
        source = {**self.requirement, "id": "source", "kind": "source",
            "files": {"library.py": inventory.sha(code)}, "installed_files": {str(code): inventory.sha(code)}}
        data = copy.deepcopy(self.data)
        data["requirements"].append(source)
        data["licenses"][0]["requirements"].append("source")
        self.check(data)
        for mutate in (lambda r: r.update(installed_files={}),
                       lambda r: r.update(installed_files={str(self.copy): inventory.sha(self.copy)}),
                       lambda r: r["installed_files"].update({str(code): "f"*64})):
            changed = copy.deepcopy(data)
            mutate(changed["requirements"][1])
            with self.assertRaises(ValueError):
                self.check(changed)
        code.write_text("changed selected library")
        with self.assertRaises(ValueError):
            self.check(data)

    def advisory_fixture(self, scanner="osv", informational=None):
        advisory = {"id": "TEST-1", "aliases": ["ALIAS-1"], "summary": "Exact upstream finding"}
        if informational:
            advisory["affected"] = [{"package": {"ecosystem": "crates.io", "name": "reviewed"},
                "database_specific": {"informational": informational}}]
        finding = {"scanner": scanner, "package": {"ecosystem": "crates.io" if informational else "PyPI",
            "name": "reviewed", "version": "1.0"}, "source": "Cargo.lock" if informational else "installed-python",
            "advisory": advisory}
        data = copy.deepcopy(self.data)
        evidence = {**self.requirement, "id": "applicability", "kind": "advisory_evidence"}
        data["requirements"].append(evidence)
        data["advisories"] = [{"finding": reviews.finding_identity(finding),
            "disposition": "accepted_maintenance_risk" if informational else "not_applicable",
            "requirements": ["applicability"], "rationale": "Affected sink absent; exact source evidence."}]
        return data, finding

    def test_exact_advisory_record_aliases_origin_and_evidence_are_bound(self):
        data, finding = self.advisory_fixture()
        self.check(data, findings=[finding])
        for mutate in (lambda f: f["advisory"].update(id="TEST-2"),
                       lambda f: f["advisory"]["aliases"].append("NEW-ALIAS"),
                       lambda f: f["advisory"].update(summary="Updated upstream finding"),
                       lambda f: f["package"].update(version="2.0"),
                       lambda f: f.update(source="other-source")):
            changed = copy.deepcopy(finding)
            mutate(changed)
            with self.assertRaises(ValueError):
                self.check(data, findings=[changed])
        with self.assertRaises(ValueError):
            self.check(data, findings=[finding, finding])
        with self.assertRaises(ValueError):
            self.check(data, findings=[])
        with self.assertRaises(ValueError):
            self.check(findings=[finding])

    def test_maintenance_acceptance_is_not_a_vulnerability_override(self):
        data, finding = self.advisory_fixture(informational="unmaintained")
        self.check(data, findings=[finding])
        changed = copy.deepcopy(finding)
        changed["advisory"]["affected"][0]["database_specific"]["informational"] = "unsound"
        data["advisories"][0]["finding"] = reviews.finding_identity(changed)
        with self.assertRaisesRegex(ValueError, "disposition_invalid"):
            self.check(data, findings=[changed])

    def test_cargo_vulnerabilities_unknown_warnings_and_incomplete_scan_always_reject(self):
        valid = {"database": {"advisory-count": 100}, "lockfile": {"dependency-count": 10},
            "vulnerabilities": {"found": False, "list": []}, "warnings": {}}
        self.assertEqual(reviews.cargo_findings(valid), [])
        for mutate in (lambda d: d["database"].update({"advisory-count": 0}),
                       lambda d: d["vulnerabilities"].update(found=True, list=[{"id": "TEST"}]),
                       lambda d: d["warnings"].update(unsound=[{}]),
                       lambda d: d["warnings"].update(unmaintained=[{"package": "bad-schema"}])):
            changed = copy.deepcopy(valid)
            mutate(changed)
            with self.assertRaises(ValueError):
                reviews.cargo_findings(changed)

    def test_cargo_exact_unmaintained_warning_normalizes_without_erasing_raw_row(self):
        data = {"database": {"advisory-count": 100}, "lockfile": {"dependency-count": 10},
            "vulnerabilities": {"found": False, "list": []}, "warnings": {"unmaintained": [{
                "package": {"name": "paste", "version": "1.0.15"},
                "advisory": {"id": "RUSTSEC-2024-0436", "informational": "unmaintained"}}]}}
        before = copy.deepcopy(data)
        self.assertEqual(reviews.cargo_findings(data)[0]["package"]["version"], "1.0.15")
        self.assertEqual(data, before)

    def test_new_inventory_output_name_does_not_change_material_binding(self):
        report = copy.deepcopy(self.report)
        report["packages"] = {"other-output": report["packages"]["input"]}
        report["scan_input_sha256"] = {"other-output": report["scan_input_sha256"]["input"]}
        report["scan_input_labels"] = {"other-output": "package-lock.json"}
        self.assertEqual(reviews.context(report), reviews.context(self.report))


    def test_cli_default_blocks_exact_review_admits_and_native_failure_still_blocks(self):
        selection = self.generation / "selection.json"
        selection.write_text(json.dumps({"prepared_profiles": {}, "source": self.report["source"], "files": {}}))
        graphs = {}
        for name, graph in (("Cargo.lock", {("crates.io", "rust", "1.0")}),
                ("requirements.lock", {("PyPI", "python-lib", "2.0")}),
                ("package-lock.json", {("npm", "reviewed", "1.0")})):
            path = self.root / name
            path.write_text('version = 3\n[[package]]\nname = "rust"\nversion = "1.0"\n' if name == "Cargo.lock" else "exact selected lock")
            graphs[str(path)] = graph
        advisory = {"id": "TEST-1", "aliases": ["ALIAS-1"], "summary": "Affected code absent"}
        def scanner(command, **kwargs):
            failed = command[0] == "osv-scanner"
            if failed:
                results = []
                for argument in command:
                    if not argument.startswith("--lockfile="):
                        continue
                    source = argument.split("=", 1)[1].removeprefix("requirements.txt:")
                    packages = {("PyPI", "python-lib", "2.0")} if source.endswith("requirements.txt") else graphs[source]
                    rows = []
                    for package in packages:
                        row = {"package": dict(zip(("ecosystem", "name", "version"), package))}
                        if package[0] == "PyPI":
                            row["vulnerabilities"] = [advisory]
                        rows.append(row)
                    results.append({"source": {"type": "lockfile", "path": source}, "packages": rows})
                data = {"results": results}
            else:
                data = {"database": {"advisory-count": 100}, "lockfile": {"dependency-count": 10},
                    "vulnerabilities": {"found": False, "list": []}, "warnings": {}}
            return {"status": "failed" if failed else "passed", "exit_code": 1 if failed else 0,
                    "command": command, "stdout": json.dumps(data), "stderr": ""}
        prep = SimpleNamespace(verify_generation=Mock())
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        def run(name, accepted=False, native_error=False):
            path = self.root / name
            native_input = self.root / "native-reviews.json"
            native_input.write_text("{}")
            arguments = ["--native-reviews", str(native_input), "--selection", str(selection), "--expected-commit", "a"*40,
                         "--output", str(path)]
            if accepted:
                arguments += ["--runtime-reviews", str(self.path)]
            with patch.object(inventory, "ROOT", self.root), \
                    patch.object(inventory.importlib.util, "spec_from_file_location", return_value=spec), \
                    patch.object(inventory.importlib.util, "module_from_spec", return_value=prep), \
                    patch.object(inventory, "lock_graphs", return_value=copy.deepcopy(graphs)), \
                    patch.object(inventory, "installed_graphs", return_value=([copy.deepcopy(self.note)],
                        {("PyPI", "python-lib", "2.0")}, ["runtime_license_review_required:reviewed"])), \
                    patch.object(inventory, "verify_native_reviews",
                        side_effect=ValueError("node_preannouncement_unresolved") if native_error else None,
                        return_value={}), \
                    patch.object(inventory, "run_cmd", side_effect=scanner):
                result = inventory.main(arguments)
            return result, json.loads(path.read_text())
        code, baseline = run("default.json")
        self.assertEqual(code, 1)
        self.assertEqual(len(baseline["findings"]), 1)
        data = copy.deepcopy(self.data)
        data["binding"] = baseline["runtime_reviews_expected_binding"]
        data["requirements"].append({**self.requirement, "id": "applicability", "kind": "advisory_evidence"})
        finding = reviews.osv_findings(baseline["findings"], self.root,
            self.root / "default-installed-requirements.txt")[0]
        data["advisories"] = [{"finding": reviews.finding_identity(finding),
            "disposition": "not_applicable", "requirements": ["applicability"], "rationale": "Absent sink proof."}]
        self.path.write_text(json.dumps(data))
        code, accepted = run("accepted.json", accepted=True)
        self.assertEqual(code, 0, accepted["errors"])
        self.assertEqual(accepted["checks"]["osv"]["exit_code"], 1)
        self.assertEqual(accepted["findings"][0]["advisory"], advisory)
        self.assertTrue(accepted["notices"][0]["policy_disposition_required"])
        self.assertEqual(accepted["license_errors"], ["runtime_license_review_required:reviewed"])
        code, native = run("native-blocked.json", accepted=True, native_error=True)
        self.assertEqual(code, 1)
        self.assertTrue(any("node_preannouncement" in error for error in native["errors"]))
        data["advisories"] = []
        self.path.write_text(json.dumps(data))
        code, uncovered = run("uncovered.json", accepted=True)
        self.assertEqual(code, 1)
        self.assertTrue(any("unreviewed_advisory" in error for error in uncovered["errors"]))

if __name__ == "__main__":
    unittest.main()
