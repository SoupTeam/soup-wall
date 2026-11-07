# SPDX-License-Identifier: Apache-2.0
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime_reviews as reviews

SPEC = importlib.util.spec_from_file_location("runtime_compliance", Path(__file__).resolve().parents[1] /
                                              "build-runtime-compliance.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class RuntimeComplianceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.generation = self.root / "generation"
        profile = self.generation / "git-profile"
        profile.mkdir(parents=True)
        self.package = self.generation / "package"
        self.site = self.package / "python/lib/python3.11/site-packages"
        self.site.mkdir(parents=True)
        (profile / "profile.json").write_text(json.dumps({"packageRoot": str(self.package)}))
        self.notices = []
        for name, version, owner, expression in (("certifi", "2026.10.19", None, "MPL-2.0"),
                ("certifi", "2026.10.23", "pip", "MPL-2.0"),
                ("autocommand", "2.2.2", "setuptools", "LGPL-3.0-or-later"),
                ("node-lib", "1.0", None, "BlueOak-1.0.0")):
            path = self.site / (owner + "/_vendor/" + name if owner else name)
            path.mkdir(parents=True)
            (path / "__init__.py").write_bytes(b"")
            (path / "core.py").write_text("# Exact editable source\n")
            if name == "certifi":
                (path / "cacert.pem").write_text("Exact selected CA data")
            notice = path / "LICENSE"
            notice.write_text(name + " " + version + " original license/copyright")
            self.notices.append({"ecosystem": "npm" if name == "node-lib" else "PyPI",
                "name": name, "version": version,
                "origin": {"kind": "vendored_distribution" if owner else "installed_distribution",
                           "owner": owner, "path": str(path)},
                "license": expression, "effective_license": expression,
                "files": {str(notice): reviews.file_sha(notice)}, "policy_disposition_required": True})
        application = self.site / "setuptools/__init__.py"
        application.write_text("# Containing application source")
        self.report = {"source": {"commit": "a"*40, "tree": "b"*40, "dirty": False},
            "selection_sha256": "c"*64, "binaries": {}, "lock_sha256": {}, "notices": self.notices,
            "packages": {"input": []}, "scan_input_sha256": {"input": "d"*64},
            "scan_input_labels": {"input": "installed-python"}}
        self.output = self.root / "compliance"

    def admitted(self):
        data = json.loads((self.output / "runtime-reviews-proposal.json").read_text())
        data["decision"] = {"authority": "user-delegated-project-maintainer", "recorded_by": "Codex",
            "method": "AI-assisted project-maintainer disposition",
            "checked_at": datetime.now(timezone.utc).isoformat(), "rationale": "Controlled fixture decision."}
        for row in data["licenses"]:
            row.update(disposition="accepted_with_conditions", rationale="Exact fixture review.")
        review = reviews.Review(data, self.output / "runtime-reviews.json", self.report,
                                "a"*40, self.generation)
        review.licenses(self.notices)
        review.advisories([])
        return review.finish()

    def test_actual_notice_source_and_pem_copies_satisfy_conditions_after_explicit_decision(self):
        receipt = builder.build(self.report, self.generation, self.output)
        self.assertEqual(len(self.admitted()["license_dispositions"]), 4)
        self.assertIn("python-source/certifi/cacert.pem", receipt["files"])
        self.assertIn("python-source/pip/_vendor/certifi/cacert.pem", receipt["files"])
        self.assertIn("python-source/setuptools/_vendor/autocommand/__init__.py", receipt["files"])
        self.assertIn("python-source/setuptools/__init__.py", receipt["files"])
        self.assertEqual((self.output / "python-source/certifi/__init__.py").stat().st_size, 0)
        for relative, digest in receipt["files"].items():
            self.assertEqual(reviews.file_sha(self.output / relative), digest)

    def test_generated_proposal_is_not_approval(self):
        builder.build(self.report, self.generation, self.output)
        data = json.loads((self.output / "runtime-reviews-proposal.json").read_text())
        self.assertTrue(all(row["disposition"] == "UNREVIEWED" for row in data["licenses"]))
        with self.assertRaisesRegex(ValueError, "decision_invalid"):
            reviews.Review(data, self.output / "runtime-reviews.json", self.report, "a"*40, self.generation)

    def test_missing_gpl_text_and_changed_covered_source_reject(self):
        builder.build(self.report, self.generation, self.output)
        gpl = self.output / "licenses/GPL-3.0.txt"
        saved = gpl.read_bytes()
        gpl.unlink()
        with self.assertRaises(ValueError):
            self.admitted()
        gpl.write_bytes(saved)
        (self.site / "setuptools/_vendor/autocommand/core.py").write_text("changed source")
        with self.assertRaises(ValueError):
            self.admitted()

    def test_existing_output_and_unknown_source_layout_refuse(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "fresh_output"):
            builder.build(self.report, self.generation, self.output)
        self.output.rmdir()
        changed = copy.deepcopy(self.report)
        changed["notices"][2]["name"] = "different-lgpl-component"
        with self.assertRaisesRegex(ValueError, "source_layout"):
            builder.build(changed, self.generation, self.output)

    def test_source_symlink_and_changed_original_notice_refuse(self):
        target = self.site / "certifi/outside.py"
        try:
            target.symlink_to(self.root / "outside.py")
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ValueError, "source_file"):
            builder.build(self.report, self.generation, self.output)
        target.unlink()
        source = Path(next(iter(self.notices[0]["files"])))
        source.write_text("changed notice")
        with self.assertRaises(ValueError):
            builder.build(self.report, self.generation, self.root / "new-compliance")


    def test_removing_gpl_obligation_from_input_cannot_bypass_full_license_copy(self):
        builder.build(self.report, self.generation, self.output)
        data = json.loads((self.output / "runtime-reviews-proposal.json").read_text())
        data["decision"] = {"authority": "user-delegated-project-maintainer", "recorded_by": "Codex",
            "method": "AI-assisted project-maintainer disposition",
            "checked_at": datetime.now(timezone.utc).isoformat(), "rationale": "Controlled fixture decision."}
        for row in data["licenses"]:
            row.update(disposition="accepted_with_conditions", rationale="Exact fixture review.")
        for condition in data["requirements"]:
            condition["files"].pop("licenses/GPL-3.0.txt", None)
        review = reviews.Review(data, self.output / "runtime-reviews.json", self.report, "a"*40, self.generation)
        with self.assertRaisesRegex(ValueError, "full_license_text_missing"):
            review.licenses(self.notices)

    def test_original_mcp_readme_is_copied_with_documentation_attribution(self):
        package = self.generation / "filesystem-package"
        relative = "node_modules/@modelcontextprotocol/server-filesystem"
        server = package / relative
        server.mkdir(parents=True)
        (server / "README.md").write_text("# Filesystem Server\nOriginal attributed documentation.")
        (server / "LICENSE").write_text("Exact original MIT/Apache transition notice")
        profile = self.generation / "filesystem-profile"
        profile.mkdir()
        (profile / "profile.json").write_text(json.dumps({"packageRoot": str(package)}))
        notice = {"ecosystem": "npm", "name": "@modelcontextprotocol/server-filesystem",
            "version": "2026.8.31", "origin": {"kind": "installed_package", "owner": None, "path": relative},
            "license": "SEE LICENSE IN LICENSE", "effective_license": "SEE LICENSE IN LICENSE",
            "files": {str(server / "LICENSE"): reviews.file_sha(server / "LICENSE")},
            "policy_disposition_required": True}
        self.report["notices"].append(notice)
        builder.build(self.report, self.generation, self.output)
        proposal = json.loads((self.output / "runtime-reviews-proposal.json").read_text())
        requirements = [r for r in proposal["requirements"] if r["kind"] == "documentation_attribution"]
        self.assertEqual(len(requirements), 1)
        key = "documentation/filesystem-server-README.md"
        self.assertEqual(requirements[0]["files"][key], reviews.file_sha(server / "README.md"))
        self.assertEqual((self.output / key).read_bytes(), (server / "README.md").read_bytes())

if __name__ == "__main__":
    unittest.main()
