"""SOU-27 isolated, network-free license/provenance regressions."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "license_policy.py"
spec = importlib.util.spec_from_file_location("license_policy", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mod)

POLICY = {
    "allowed_licenses": ["MIT", "Apache-2.0", "BSD-2-Clause", "ISC"],
    "allowed_with_exceptions": ["GPL-2.0-only WITH Classpath-exception-2.0"],
    "workspace": {"expected_member_count": 1, "vendored_package": "kryptering",
                  "vendored_version": "0.6.0", "vendored_manifest": "vendor/kryptering/Cargo.toml",
                  "vendored_license": "BSD-2-Clause"},
    "package_exceptions": [],
}


def pkg(name, version, license, source, member=False, root=None):
    ident = f"path+{name}#{version}" if source is None else f"{source}#{name}@{version}"
    if root:
        manifest = root / ("vendor/kryptering/Cargo.toml" if name == "kryptering" else f"crates/{name}/Cargo.toml")
    else:
        manifest = pathlib.Path("/synthetic") / name / "Cargo.toml"
    return {"id": ident, "name": name, "version": version, "source": source,
            "license": license, "manifest_path": str(manifest), "license_file": None}


class SPDXTests(unittest.TestCase):
    def check(self, expr):
        return mod.judge_spdx(expr, POLICY)

    def test_or_selects_reviewed_alternative(self):
        self.assertEqual(self.check("GPL-3.0-only OR MIT")[0:2], ("approved", ["MIT"]))

    def test_and_requires_every_conjunct(self):
        self.assertEqual(self.check("MIT AND GPL-3.0-only")[0], "disallowed")
        self.assertEqual(self.check("MIT AND ISC")[0:2], ("approved", ["MIT", "ISC"]))

    def test_operator_precedence_and_parentheses(self):
        self.assertEqual(self.check("GPL-3.0-only OR MIT AND ISC")[0], "approved")
        self.assertEqual(self.check("(GPL-3.0-only OR MIT) AND ISC")[0], "approved")
        self.assertEqual(self.check("MIT AND (GPL-3.0-only OR ISC)")[0], "approved")
        self.assertEqual(self.check("(GPL-3.0-only OR AGPL-3.0-only) AND ISC")[0], "disallowed")

    def test_none_and_noassertion_cannot_hide_in_or(self):
        self.assertEqual(self.check("NONE OR MIT")[0], "unknown")
        self.assertEqual(self.check("MIT OR NOASSERTION")[0], "unknown")
        self.assertEqual(self.check("(MIT AND NOASSERTION) OR ISC")[0], "unknown")
        self.assertEqual(self.check("NONE WITH Classpath-exception-2.0")[0], "unknown")

    def test_with_needs_exact_reviewed_exception(self):
        self.assertEqual(self.check("GPL-2.0-only WITH Classpath-exception-2.0")[0], "approved")
        self.assertEqual(self.check("MIT WITH LLVM-exception")[0], "disallowed")
        self.assertEqual(self.check("(MIT OR ISC) WITH LLVM-exception")[0], "unknown")

    def test_unknown_does_not_become_approved(self):
        for expr in [None, "", "NOASSERTION", "NONE", "LicenseRef-Unreviewed", "GPL-3.0-only", "MIT+"]:
            with self.subTest(expr=expr):
                self.assertNotEqual(self.check(expr)[0], "approved")

    def test_malformed_is_unknown(self):
        for expr in ["MIT OR", "(MIT", "MIT AND )", "MIT * GPL", "MIT OR OR ISC", "MIT && ISC", "(MIT) WITH LLVM-exception"]:
            with self.subTest(expr=expr):
                self.assertEqual(self.check(expr)[0], "unknown")

    def test_unapproved_or_branch_does_not_hide_and_obligation(self):
        self.assertEqual(self.check("(MIT AND GPL-3.0-only) OR (ISC AND Apache-2.0)")[0:2],
                         ("approved", ["ISC", "Apache-2.0"]))
        self.assertEqual(self.check("MIT AND (ISC OR GPL-3.0-only)")[0:2], ("approved", ["MIT", "ISC"]))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        for f in ("Cargo.toml", "Cargo.lock", "vendor/kryptering/Cargo.toml", "vendor/kryptering/LICENSE", "vendor/kryptering/PATCH.md", "LICENSE", "NOTICE"):
            p = self.root / f
            p.parent.mkdir(exist_ok=True, parents=True)
            p.write_text("mock synthetic review evidence\n", encoding="utf8")
        self.registry = "registry+https://github.com/rust-lang/crates.io-index"
        self.workspace = pkg("app", "0.1.0", "MIT", None, root=self.root)
        self.vendor = pkg("kryptering", "0.6.0", "BSD-2-Clause", None, root=self.root)
        self.registry_pkg = pkg("remote", "1.2.3", "MIT OR GPL-3.0-only", self.registry, root=self.root)
        self.packages = [self.workspace, self.vendor, self.registry_pkg]
        self.policy = POLICY.copy()
        self.policy["workspace"] = POLICY["workspace"].copy()
        self.assets = {"asset": [
            {"name": "bundled vendor license", "kind": "bundled_vendor", "path": "vendor/kryptering/LICENSE",
             "mandatory": True, "decision": "reviewed", "license": "BSD-2-Clause",
             "origin": "mock-source", "version": "0.6.0", "notice_path": "vendor/kryptering/PATCH.md",
             "reviewed_git_blob_sha1": mod.git_blob_sha1(self.root / "vendor/kryptering/LICENSE")},
            {"name": "optional model", "kind": "external_optional", "path": "models/never-downloaded.bin",
             "mandatory": False, "decision": "unresolved"},
        ]}

    def write_lock(self):
        records = []
        for p in self.packages:
            section = '[[package]]\nname = "' + p["name"] + '"\nversion = "' + p["version"] + '"\n'
            if p.get("source"):
                section += 'source = "' + p["source"] + '"\n'
                section += 'checksum = "' + ("a" * 64) + '"\n'
            records.append(section)
        (self.root / "Cargo.lock").write_text("version = 4\n\n" + "\n".join(records), encoding="utf8")

    def metadata(self):
        return {"packages": self.packages, "workspace_members": [self.workspace["id"]]}

    def report(self):
        self.write_lock()
        # These TOML fixtures are minimal: read through build_report by writing
        # the equivalent policy structure (production sources are TOML too).
        policy_toml = """
allowed_licenses = ["MIT", "Apache-2.0", "BSD-2-Clause", "ISC"]
allowed_with_exceptions = []
[workspace]
expected_member_count = 1
vendored_package = "kryptering"
vendored_version = "0.6.0"
vendored_manifest = "vendor/kryptering/Cargo.toml"
vendored_license = "BSD-2-Clause"
"""
        asset_toml = """
[[asset]]
name = "bundled vendor license"
kind = "bundled_vendor"
path = "vendor/kryptering/LICENSE"
mandatory = true
decision = "reviewed"
license = "BSD-2-Clause"
origin = "mock-source"
version = "0.6.0"
notice_path = "vendor/kryptering/PATCH.md"
reviewed_git_blob_sha1 = "{BLOB}"
[[asset]]
name = "optional model"
kind = "external_optional_model"
path = "models/injection/model.safetensors"
mandatory = false
decision = "unresolved"
[[asset]]
name = "secondary model"
kind = "external_optional_model"
path = "models/moderation/model.safetensors"
mandatory = false
decision = "unresolved"
[[asset]]
name = "python support"
kind = "optional_support_requirements"
path = "scripts/benchmarks/agentdojo-live.requirements.txt"
mandatory = false
decision = "unresolved"
[[asset]]
name = "sou13 python validation"
kind = "optional_support_requirements"
path = "eval/sou13/requirements-cp2.txt"
mandatory = false
decision = "unresolved"
[[asset]]
name = "deepset"
kind = "external_optional_dataset"
path = "datasets/deepset_injection.jsonl"
mandatory = false
decision = "unresolved"
[[asset]]
name = "jackhhao"
kind = "external_optional_dataset"
path = "datasets/jailbreak_classification.jsonl"
mandatory = false
decision = "unresolved"
[[asset]]
name = "safe guard"
kind = "external_optional_dataset"
path = "datasets/safe_guard.jsonl"
mandatory = false
decision = "unresolved"
[[asset]]
name = "JBB"
kind = "external_optional_dataset"
path = "datasets/jailbreakbench.jsonl"
mandatory = false
decision = "unresolved"
"""
        (self.root / "policy.toml").write_text(policy_toml, encoding="utf8")
        asset_toml = asset_toml.replace("{BLOB}", mod.git_blob_sha1(self.root / "vendor/kryptering/LICENSE") if (self.root / "vendor/kryptering/LICENSE").is_file() else "0" * 40)
        (self.root / "assets.toml").write_text(asset_toml, encoding="utf8")
        return mod.build_report(self.root, self.root / "policy.toml", self.root / "assets.toml", self.metadata(), None)

    def test_sou13_pins_are_inventoried_without_granting_license_approval(self):
        path = self.root / "eval/sou13/requirements-cp2.txt"
        path.parent.mkdir(parents=True)
        for version in ("4.25.1", "4.25.2"):
            path.write_text("jsonschema==" + version + "\n", encoding="utf8")
            report = self.report()
            row = next(a for a in report["assets"] if a["path"] == "eval/sou13/requirements-cp2.txt")
            self.assertEqual(row["sha256"], mod.sha256(path))
            self.assertEqual(row["pinned_packages"][0]["version"], version)
            self.assertEqual(row["pinned_packages"][0]["decision"], "unresolved")
            self.assertFalse(report["summary"]["approved_for_release"])

    def test_sou13_requirement_record_cannot_be_removed(self):
        self.report()
        manifest = self.root / "assets.toml"
        contents = manifest.read_text().replace('''[[asset]]
name = "sou13 python validation"
kind = "optional_support_requirements"
path = "eval/sou13/requirements-cp2.txt"
mandatory = false
decision = "unresolved"
''', "", 1)
        manifest.write_text(contents)
        report = mod.build_report(self.root, self.root / "policy.toml", manifest, self.metadata(), None)
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertTrue(any("eval/sou13/requirements-cp2.txt" in e for e in report["errors"]))

    def test_additional_reviewed_path_requires_exact_manifest_notice_and_identity(self):
        manifest = self.root / "vendor/extra/Cargo.toml"
        notice = self.root / "vendor/extra/LICENSE"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("original manifest")
        notice.write_text("original notice")
        extra = pkg("extra", "1.0.0", "Apache-2.0", None, root=self.root)
        extra["manifest_path"] = str(manifest)
        self.packages.append(extra)
        self.write_lock()
        lock = tomllib.loads((self.root / "Cargo.lock").read_text())
        record = {"name": "extra", "version": "1.0.0", "manifest": "vendor/extra/Cargo.toml",
                  "manifest_sha256": mod.sha256(manifest), "notice": "vendor/extra/LICENSE",
                  "notice_sha256": mod.sha256(notice), "license": "Apache-2.0"}
        self.policy["reviewed_paths"] = [record]
        def errors():
            return mod.inventory_rust(self.metadata(), lock, self.policy, self.root)[1]
        self.assertEqual(errors(), [])
        for field, replacement in [("version", "2.0.0"), ("manifest", "../outside"),
                                   ("manifest_sha256", "0" * 64), ("notice_sha256", "0" * 64),
                                   ("license", "MIT")]:
            self.policy["reviewed_paths"] = [dict(record, **{field: replacement})]
            self.assertTrue(errors(), field)
        self.policy["reviewed_paths"] = [record, record]
        self.assertTrue(errors(), "duplicate records must not admit a path")
        self.policy["reviewed_paths"] = []
        self.assertTrue(errors(), "unknown paths remain rejected")

    def test_valid_lock_vendored_and_optional_asset_distinct(self):
        report = self.report()
        self.assertTrue(report["summary"]["license_gate_pass"], report["errors"])
        self.assertFalse(report["summary"]["approved_for_release"])
        self.assertEqual(report["summary"]["rust_count"], 3)
        self.assertEqual(len(report["summary"]["unreviewed_optional_assets"]), 8)
        self.assertTrue(report["inputs"]["cargo_lock_sha256"])
        self.assertTrue(report["inputs"]["checker_sha256"])

    def test_required_optional_provenance_cannot_disappear(self):
        report = self.report()
        self.assertTrue(report["summary"]["license_gate_pass"], report["errors"])
        manifest = self.root / "assets.toml"
        contents = manifest.read_text()
        # Delete one entire mandatory-to-inventory optional record.
        contents = contents.replace('''[[asset]]
name = "secondary model"
kind = "external_optional_model"
path = "models/moderation/model.safetensors"
mandatory = false
decision = "unresolved"
''', "", 1)
        manifest.write_text(contents)
        report = mod.build_report(self.root, self.root / "policy.toml", manifest, self.metadata(), None)
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertFalse(report["summary"]["approved_for_release"])
        self.assertTrue(any("required provenance record" in error for error in report["errors"]))

    def test_required_optional_provenance_cannot_be_duplicated(self):
        self.report()
        manifest = self.root / "assets.toml"
        manifest.write_text(manifest.read_text() + '''
[[asset]]
name = "shadow"
kind = "external_optional_model"
path = "models/injection/model.safetensors"
mandatory = false
decision = "unresolved"
''')
        report = mod.build_report(self.root, self.root / "policy.toml", manifest, self.metadata(), None)
        self.assertFalse(report["summary"]["license_gate_pass"])

    def test_manifest_absence_can_never_authorize_release(self):
        self.report()
        manifest = self.root / "assets.toml"
        content = manifest.read_text()
        manifest.write_text(content[:content.index('[[asset]]', content.index('[[asset]]') + 1)])
        report = mod.build_report(self.root, self.root / "policy.toml", manifest, self.metadata(), None)
        self.assertFalse(report["summary"]["approved_for_release"])

    def test_unknown_dependency_denied(self):
        self.registry_pkg["license"] = None
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertEqual(report["summary"]["rust"]["unknown"], 1)

    def test_disallowed_dependency_denied(self):
        self.registry_pkg["license"] = "AGPL-3.0-only"
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertEqual(report["summary"]["rust"]["disallowed"], 1)

    def test_lock_metadata_mismatch_detected(self):
        self.packages.append(pkg("extra", "1.0.0", "MIT", self.registry, root=self.root))
        self.write_lock()
        self.packages.pop()
        rows, errs = mod.inventory_rust(self.metadata(), tomllib.loads((self.root / "Cargo.lock").read_text()), self.policy, self.root)
        self.assertTrue(any("coverage mismatch" in s for s in errs))

    def test_unreviewed_path_dependency_detected(self):
        self.packages.append(pkg("mystery-local", "0.2.0", "MIT", None, root=self.root))
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertTrue(any("unreviewed path dependency" in s for s in report["errors"]))

    def test_unreviewed_git_dependency_source_detected(self):
        self.registry_pkg["source"] = "git+https://example.test/unreviewed#deadbeef"
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertTrue(any("unreviewed non-default dependency source" in s for s in report["errors"]))

    def test_optional_python_requirement_pins_are_recorded_unapproved(self):
        path = self.root / "scripts/benchmarks/agentdojo-live.requirements.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("requests==2.34.2\nhttpx==0.28.1\n", encoding="utf8")
        records, errors = mod.inventory_assets(self.root, {"asset": [{
            "name": "benchmark requirements", "kind": "optional_support_requirements",
            "path": "scripts/benchmarks/agentdojo-live.requirements.txt", "mandatory": False,
            "decision": "unresolved"}]})
        self.assertEqual(errors, [])
        self.assertEqual(len(records[0]["pinned_packages"]), 2)
        self.assertTrue(all(p["decision"] == "unresolved" for p in records[0]["pinned_packages"]))

    def test_vendor_path_spoofing_detected(self):
        self.vendor["manifest_path"] = str(self.root / "somewhere/Cargo.toml")
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertTrue(any("vendored kryptering resolved outside" in x for x in report["errors"]))

    def test_vendor_license_change_detected(self):
        self.vendor["license"] = "MIT"
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])

    def test_missing_vendor_notice_is_blocking(self):
        report = self.report()
        self.assertTrue(report["summary"]["license_gate_pass"])
        (self.root / "vendor/kryptering/PATCH.md").unlink()
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertTrue(any("asset falsely marked reviewed" in x for x in report["errors"]))

    def test_tampered_reviewed_vendor_license_is_blocked(self):
        self.report()
        path = self.root / "vendor/kryptering/LICENSE"
        original_manifest = self.root / "assets.toml"
        saved = original_manifest.read_text()
        path.write_text("wrong new license without review\n")
        assets = tomllib.loads(saved)
        records, errors = mod.inventory_assets(self.root, assets)
        self.assertTrue(any("do not match pinned Git blob" in e for e in errors))

    def test_missing_mandatory_vendor_file_denied(self):
        self.report()
        (self.root / "vendor/kryptering/LICENSE").unlink()
        report = self.report()
        self.assertFalse(report["summary"]["license_gate_pass"])
        self.assertTrue(any("missing mandatory provenance asset" in x for x in report["errors"]))

    def test_specific_exception_requires_reviewed_notice(self):
        self.registry_pkg["license"] = "LicenseRef-Example"
        exception = {"name": "remote", "version": "1.2.3", "source": self.registry,
                     "license": "LicenseRef-Example", "selected_license": "MIT",
                     "cargo_lock_checksum": "a" * 64,
                     "reason": "Explicit reviewed rights for this version and MIT grant in the notice",
                     "notice_path": "vendor/kryptering/LICENSE",
                     "notice_sha256": mod.sha256(self.root / "vendor/kryptering/LICENSE")}
        self.policy["package_exceptions"] = [exception]
        self.write_lock()
        rows, errs = mod.inventory_rust(self.metadata(), tomllib.loads((self.root / "Cargo.lock").read_text()), self.policy, self.root)
        self.assertFalse(errs)
        self.assertEqual([p for p in rows if p["name"] == "remote"][0]["decision"], "exception")
        exception["notice_path"] = "nonexistent/LICENSE"
        rows, _ = mod.inventory_rust(self.metadata(), tomllib.loads((self.root / "Cargo.lock").read_text()), self.policy, self.root)
        self.assertEqual([p for p in rows if p["name"] == "remote"][0]["decision"], "disallowed")


    def test_exception_rejects_wrong_or_missing_lock_checksum(self):
        self.registry_pkg["license"] = "LicenseRef-Example"
        self.write_lock()
        lock = tomllib.loads((self.root / "Cargo.lock").read_text())
        e = {"name": "remote", "version": "1.2.3", "source": self.registry,
             "license": "LicenseRef-Example", "selected_license": "MIT",
             "cargo_lock_checksum": "b" * 64,
             "reason": "Pinned local MIT notice from immutable upstream original",
             "notice_path": "vendor/kryptering/LICENSE",
             "notice_sha256": mod.sha256(self.root / "vendor/kryptering/LICENSE")}
        self.policy["package_exceptions"] = [e]
        rows, _ = mod.inventory_rust(self.metadata(), lock, self.policy, self.root)
        self.assertNotEqual(rows[-1]["decision"], "exception")
        e["cargo_lock_checksum"] = "a" * 64
        rows, _ = mod.inventory_rust(self.metadata(), lock, self.policy, self.root)
        self.assertEqual(rows[-1]["decision"], "exception")
        e.pop("cargo_lock_checksum")
        rows, _ = mod.inventory_rust(self.metadata(), lock, self.policy, self.root)
        self.assertNotEqual(rows[-1]["decision"], "exception")

    def test_exception_rejects_modified_or_missing_supplemental_notices(self):
        self.registry_pkg["license"] = "LicenseRef-Example"
        self.write_lock()
        lock = tomllib.loads((self.root / "Cargo.lock").read_text())
        extra = self.root / "copyright.txt"
        extra.write_text("copyright notice", encoding="utf-8")
        e = {"name": "remote", "version": "1.2.3", "source": self.registry,
             "license": "LicenseRef-Example", "selected_license": "MIT",
             "cargo_lock_checksum": "a" * 64,
             "reason": "Pinned local MIT notice with upstream copyright attribution",
             "notice_path": "vendor/kryptering/LICENSE",
             "notice_sha256": mod.sha256(self.root / "vendor/kryptering/LICENSE"),
             "supplemental_notices": [{"path": "copyright.txt", "sha256": mod.sha256(extra)}]}
        self.policy["package_exceptions"] = [e]
        rows, _ = mod.inventory_rust(self.metadata(), lock, self.policy, self.root)
        self.assertEqual(rows[-1]["decision"], "exception")
        extra.write_text("TAMPERED", encoding="utf-8")
        rows, _ = mod.inventory_rust(self.metadata(), lock, self.policy, self.root)
        self.assertNotEqual(rows[-1]["decision"], "exception")
        extra.unlink()
        rows, _ = mod.inventory_rust(self.metadata(), lock, self.policy, self.root)
        self.assertNotEqual(rows[-1]["decision"], "exception")

    def test_data_license_exception_stays_exactly_pinned_after_tls_update(self):
        for name, version, allowed in [("webpki-roots", "1.0.10", True),
                                       ("webpki-roots", "1.0.9", False),
                                       ("webpki-roots", "1.0.11", False),
                                       ("unreviewed-roots", "1.0.10", False)]:
            with self.subTest(name=name, version=version):
                package = pkg(name, version, "CDLA-Permissive-2.0", self.registry, root=self.root)
                self.packages = [self.workspace, self.vendor, package]
                self.policy["package_exceptions"] = [{
                    "name": name, "version": version, "source": self.registry,
                    "license": "CDLA-Permissive-2.0", "selected_license": "CDLA-Permissive-2.0",
                    "cargo_lock_checksum": "a" * 64,
                    "reason": "Exact reviewed data license notice for a pinned registry archive",
                    "notice_path": "vendor/kryptering/LICENSE",
                    "notice_sha256": mod.sha256(self.root / "vendor/kryptering/LICENSE")}]
                self.write_lock()
                rows, _ = mod.inventory_rust(self.metadata(),
                    tomllib.loads((self.root / "Cargo.lock").read_text()), self.policy, self.root)
                selected = next(row for row in rows if row["name"] == name)
                self.assertEqual(selected["decision"] == "exception", allowed)

    def test_exceptions_not_global_slash_or_data_license_allowlist(self):
        self.assertEqual(mod.judge_spdx("MIT/Apache-2.0", self.policy)[0], "unknown")
        self.assertEqual(mod.judge_spdx("CDLA-Permissive-2.0", self.policy)[0], "disallowed")

    def test_path_escape_rejected(self):
        with self.assertRaises(ValueError):
            mod.within(self.root, "../outside")

    def test_metadata_failure_produces_report(self):
        report = self.report()
        self.assertTrue(report["summary"]["license_gate_pass"])
        failed = mod.build_report(self.root, self.root / "policy.toml", self.root / "assets.toml", None, "cargo metadata failed")
        self.assertFalse(failed["summary"]["license_gate_pass"])
        self.assertTrue(any("cargo metadata failed" in s for s in failed["errors"]))

    def test_malformed_policy_still_writes_error_report(self):
        self.report()
        (self.root / "policy.toml").write_text("malformed = [", encoding="utf8")
        failed = mod.build_report(self.root, self.root / "policy.toml", self.root / "assets.toml", self.metadata(), None)
        self.assertFalse(failed["summary"]["license_gate_pass"])
        self.assertFalse(failed["summary"]["approved_for_release"])
        self.assertTrue(any("cannot load license/asset policy" in error for error in failed["errors"]))

    def test_malformed_assets_still_writes_error_report(self):
        self.report()
        (self.root / "assets.toml").write_text("[[asset]", encoding="utf8")
        failed = mod.build_report(self.root, self.root / "policy.toml", self.root / "assets.toml", self.metadata(), None)
        self.assertFalse(failed["summary"]["license_gate_pass"])
        self.assertTrue(any("cannot load license/asset policy" in error for error in failed["errors"]))

    def test_cli_nonzero_writes_machine_readable_evidence(self):
        self.registry_pkg["license"] = "GPL-3.0-only"
        self.report()
        metadata_path = self.root / "metadata.json"
        metadata_path.write_text(json.dumps(self.metadata()), encoding="utf8")
        cmd = [sys.executable, str(SCRIPT), "--root", str(self.root), "--policy", "policy.toml",
               "--assets", "assets.toml", "--metadata-json", str(metadata_path), "--report", "report.json"]
        cp = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(cp.returncode, 1)
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(report["summary"]["rust"]["disallowed"], 1)
        self.registry_pkg["license"] = "MIT"
        metadata_path.write_text(json.dumps(self.metadata()), encoding="utf8")
        cp = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)


if __name__ == "__main__":
    unittest.main()
