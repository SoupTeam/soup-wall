# SPDX-License-Identifier: Apache-2.0
"""Synthetic consumer controls, never product evidence or operator approval."""
from __future__ import annotations

import copy
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import publication_readiness as p
import pilot_dossier as d
import roadmap_support as support
import test_pilot_runtime_identity as scoped_fixture


class ForwardSlashPath(type(Path())):
    """Serialize the synthetic Linux profile paths consistently on Windows."""

    def __str__(self):
        return super().__str__().replace("\\", "/")


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True) + "\n").encode()


def ref(path, raw):
    return {"path": path, "sha256": p.sha(raw), "member": None, "member_sha256": None}


class PublicationReadinessTests(unittest.TestCase):
    def setUp(self):
        # These are Linux runtime *data* fixtures, not Windows runtime claims.
        # Existing fixture generation concatenates '/package' onto paths; use
        # one consistent serialized spelling when exercising it on Windows.
        if os.name == "nt":
            for module in (scoped_fixture.legacy, p.RUNTIME):
                change = patch.object(module, "Path", ForwardSlashPath)
                change.start()
                self.addCleanup(change.stop)
        self.fixture = scoped_fixture.ScopedDossierTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.fixture()
        self.root = self.fixture.root
        self.external = tempfile.TemporaryDirectory()
        self.addCleanup(self.external.cleanup)
        self.approval_path = Path(self.external.name) / "approval.json"
        self.manifest_path = Path(self.external.name) / "candidate-manifest.json"
        self.tag = "v0.0.0-synthetic-control"
        name = "soup-wall-" + self.tag + "-x86_64-unknown-linux-gnu.tar.gz"
        archive = self.root / name
        self.binary = self.fixture.paths["agentfw"].read_bytes()
        self.make_archive(archive, [(name[:-7] + "/agentfw", self.binary)])
        self.manifest = {"tag": self.tag, "checksums": [p.sha(archive.read_bytes()) + "  " + name]}
        self.manifest_path.write_bytes(encoded(self.manifest))
        self.manifest_sha = p.sha(self.manifest_path.read_bytes())
        self.prepare_roadmap()
        self.selection_ref = self.fixture.put("selection.json", self.fixture.m)
        self.index = {"format": p.VERSION, "candidate": self.fixture.m["candidate"],
                      "scope": p.SCOPE, "candidate_manifest_sha256": self.manifest_sha,
                      "selection": self.selection_ref,
                      "dossier": self.fixture.put("dossier.json", self.fixture.result()),
                      "stages": [{"id": row["stage"], "report": row["file"]}
                                 for row in self.fixture.m["evidence"]]}
        self.index_path = self.root / "readiness-index.json"
        self.approval = {"format": p.APPROVAL_VERSION, "candidate": self.index["candidate"],
                         "scope": p.SCOPE, "candidate_manifest_sha256": self.manifest_sha,
                         "index_sha256": None, "decision": "approved", "operator": "synthetic-operator",
                         "roadmap_decisions": self.decisions}
        self.save()

    @staticmethod
    def make_archive(path, files):
        with tarfile.open(path, "w:gz") as archive:
            for name, raw in files:
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))

    def prepare_roadmap(self):
        """All synthetic reports are labelled controls by this test module.

        Original dossier and scoped runtime validators execute unchanged. Only
        Git object access is the existing fixture's in-memory synthetic source.
        """
        index = self.fixture.index
        index["roadmap_sha256"] = p.sha((ROOT / "docs/ROADMAP.md").read_bytes())
        index["profile_inputs"] = []
        index["evidence"] = []
        ids = {name: "a" * 64 for name in support.IDENTITY_FIELDS}
        for cap in index["capabilities"]:
            cap.update(support="supported", identity=ids.copy())
            report = {"version": support.EVIDENCE_VERSION, "source": self.fixture.m["candidate"]["commit"],
                      **{key: cap[key] for key in ("platform", "architecture", "host", "transport", "server", "profile")},
                      "identity": ids.copy(), "execution": "live-model", "outcome": "passed",
                      "counts": {"passed": 1, "failed": 0, "skipped": 0, "expected": 1}}
            path = "synthetic-roadmap-" + cap["id"] + ".json"
            reference = self.fixture.put(path, report)
            index["evidence"].append({"id": cap["id"] + "-control", "capability": cap["id"],
                                      "path": path, "sha256": reference["sha256"],
                                      "format": support.EVIDENCE_VERSION, "kind": "integrated-candidate",
                                      "source": report["source"], "identity": ids.copy(),
                                      **{key: cap[key] for key in ("platform", "architecture", "host", "transport", "server", "profile")}})
        default = index["capabilities"][0]["id"]
        for criterion in index["criteria"]:
            if not criterion["capabilities"]:
                criterion["capabilities"] = [default]
        self.decisions = {"version": support.DECISION_VERSION,
                          "source": self.fixture.m["candidate"]["commit"], "decisions": []}
        number = 0
        for criterion in index["criteria"]:
            if criterion["phase"] == "Phase 7":
                continue
            for cap in criterion["capabilities"]:
                number += 1
                evidence = next(item for item in index["evidence"] if item["capability"] == cap)
                self.decisions["decisions"].append({"decision_id": "synthetic-" + str(number),
                    "criterion_id": criterion["id"], "evidence_id": evidence["id"],
                    "evidence_sha256": evidence["sha256"], "decision": "accepted"})
        self.fixture.m["support_index"] = self.fixture.put("index.json", index)

    def save(self, update_approval=True):
        self.index_path.write_bytes(encoded(self.index))
        if update_approval:
            self.approval["index_sha256"] = p.sha(self.index_path.read_bytes())
        self.approval_path.write_bytes(encoded(self.approval))

    def refresh_dossier(self):
        self.fixture.refresh()
        self.index["selection"] = self.fixture.put("selection.json", self.fixture.m)
        self.index["dossier"] = self.fixture.put("dossier.json", self.fixture.result())
        self.index["stages"] = [{"id": row["stage"], "report": row["file"]}
                                for row in self.fixture.m["evidence"]]
        self.save()

    def verify(self):
        return p.verify(self.index_path, self.root, ROOT, self.index["candidate"]["commit"],
                        self.manifest_sha, self.approval_path, self.root, self.manifest_path)

    def assert_blocked(self, *codes):
        result = self.verify()
        self.assertEqual(result["status"], "blocked", result)
        if codes:
            self.assertTrue(set(codes).intersection(result["blockers"]), result)
        return result

    def test_complete_synthetic_verifier_control(self):
        result = self.verify()
        self.assertEqual(result["status"], "admitted", result)
        self.assertEqual(result["roadmap"], {"required": 34, "accepted": 34})
        self.assertTrue(all(row["status"] == "verified" for row in result["stages"]))

    def test_duplicate_json_keys_unknown_version_and_unknown_fields(self):
        self.index_path.write_bytes(encoded(self.index)[:-2] + b',"scope":"full-product"}\n')
        self.assert_blocked("invalid_json")
        self.index["format"] = "sw-publication-readiness/99"
        self.save()
        self.assert_blocked("unsupported_index_version")
        self.index["format"] = p.VERSION
        self.index["copied_passed_flag"] = True
        self.save()
        self.assert_blocked("index_fields")

    def test_missing_duplicated_and_reordered_stages(self):
        rows = copy.deepcopy(self.index["stages"])
        for change in (lambda v: v.pop(), lambda v: v.__setitem__(1, v[0]), lambda v: v.reverse()):
            self.index["stages"] = copy.deepcopy(rows)
            change(self.index["stages"])
            self.save()
            self.assert_blocked("required_stage_inventory")

    def test_unsafe_references_do_not_open_arbitrary_paths(self):
        for name in ("../outside.json", "/outside.json", "C:/outside.json", "a\\b.json", "a//b.json"):
            self.index["selection"]["path"] = name
            self.save()
            self.assert_blocked("unsafe_evidence_reference")

    def test_oversized_index_and_aggregate_budget(self):
        self.index_path.write_bytes(b" " * (p.MAX_INDEX + 1))
        self.assert_blocked("unsafe_or_oversized_input")
        self.save()
        with patch.object(p, "MAX_BUNDLE", 20):
            self.assert_blocked("unsafe_missing_or_oversized_evidence")

    def test_index_changed_after_external_review(self):
        self.index_path.write_bytes(self.index_path.read_bytes() + b" ")
        self.assert_blocked("approval_index_mismatch")

    def test_approval_cannot_be_supplied_by_bundle(self):
        path = self.root / "self-minted-approval.json"
        path.write_bytes(encoded(self.approval))
        self.approval_path = path
        self.assert_blocked("approval_must_be_external_to_bundle")

    def test_missing_external_approval_and_rejected_decision(self):
        self.approval_path.unlink()
        self.assert_blocked("unsafe_or_oversized_input")
        self.approval["decision"] = "rejected"
        self.save()
        self.assert_blocked("external_operator_approval_required")

    def test_approval_source_and_manifest_are_exact(self):
        self.approval["candidate"] = {"commit": "f" * 40, "tree": "e" * 40}
        self.save()
        self.assert_blocked("approval_candidate_mismatch")
        self.approval["candidate"] = self.index["candidate"]
        self.approval["candidate_manifest_sha256"] = "f" * 64
        self.save()
        self.assert_blocked("approval_manifest_mismatch")

    def test_private_edit_or_live_only_scope_cannot_substitute(self):
        for scope in (d.SCOPE, "private-edit", "live-model", "windows"):
            self.index["scope"] = scope
            self.save()
            self.assert_blocked("unsupported_publication_scope")

    def test_tampered_original_report_bytes(self):
        path = self.root / self.index["stages"][0]["report"]["path"]
        path.write_bytes(path.read_bytes() + b" ")
        self.assert_blocked("evidence_digest_mismatch")

    def test_fake_dossier_ready_label_does_not_hide_failed_case(self):
        report = self.fixture.reports["docs-code"]
        report["cases"][4].update(status="failed", reason="synthetic-refusal")
        report["status"] = "failed"
        self.refresh_dossier()
        stored = json.loads((self.root / "dossier.json").read_bytes())
        stored["status"] = "READY"
        self.index["dossier"] = self.fixture.put("dossier.json", stored)
        self.save()
        result = self.assert_blocked("dossier_recomputed_verdict_mismatch")
        self.assertEqual(result["dossier_status"], "NOT_READY")

    def test_failed_case_with_valid_scoped_identities_remains_not_ready(self):
        self.fixture.reports["docs-code"]["cases"][4].update(status="failed", reason="synthetic-refusal")
        self.fixture.reports["docs-code"]["status"] = "failed"
        self.refresh_dossier()
        result = self.assert_blocked("dossier_not_ready")
        self.assertEqual(result["dossier_status"], "NOT_READY")

    def test_wrong_binary_profile_policy_and_classifier_bytes_refuse(self):
        original = copy.deepcopy(self.fixture.witnesses["installed"])
        for role in ("agentfw", "policy", "classifier", "profile"):
            self.fixture.witnesses["installed"] = copy.deepcopy(original)
            inputs = self.fixture.witnesses["installed"]["observations"][0]["inputs"]
            if role == "agentfw":
                inputs["binaries"]["agentfw"] = "f" * 64
            elif role == "policy":
                inputs["policy"]["sha256"] = "f" * 64
            elif role == "classifier":
                inputs["classifiers"]["filesystem"] = "f" * 64
            else:
                inputs["profiles"]["filesystem"]["profile"]["sha256"] = "f" * 64
            self.refresh_dossier()
            self.assert_blocked("dossier_not_ready")

    def test_changed_candidate_binary_after_review(self):
        name = self.manifest["checksums"][0][66:]
        archive = self.root / name
        self.make_archive(archive, [(name[:-7] + "/agentfw", b"different binary")])
        self.assert_blocked("candidate_archive_changed")

    def test_other_runtime_binary_cannot_claim_this_manifest(self):
        name = self.manifest["checksums"][0][66:]
        archive = self.root / name
        self.make_archive(archive, [(name[:-7] + "/agentfw", b"different binary")])
        self.manifest["checksums"][0] = p.sha(archive.read_bytes()) + "  " + name
        self.manifest_path.write_bytes(encoded(self.manifest))
        self.manifest_sha = p.sha(self.manifest_path.read_bytes())
        self.index["candidate_manifest_sha256"] = self.manifest_sha
        self.approval["candidate_manifest_sha256"] = self.manifest_sha
        self.save()
        self.assert_blocked("candidate_runtime_binary_mismatch")

    def test_stage_attachment_cannot_point_at_another_report(self):
        self.index["stages"][0]["report"] = self.index["stages"][1]["report"]
        self.save()
        self.assert_blocked("stage_report_binding_mismatch")

    def test_all_criteria_and_every_linked_capability_require_acceptance(self):
        self.approval["roadmap_decisions"]["decisions"].pop(0)
        self.save()
        self.assert_blocked("roadmap_capability_review_incomplete", "roadmap_acceptance_incomplete")

    def test_scripted_provider_cannot_close_phase4_live_model_acceptance(self):
        evidence = self.fixture.index["evidence"][0]
        path = self.root / evidence["path"]
        report = json.loads(path.read_bytes())
        report["execution"] = "scripted-host"
        evidence["sha256"] = self.fixture.put(evidence["path"], report)["sha256"]
        for row in self.approval["roadmap_decisions"]["decisions"]:
            if row["evidence_id"] == evidence["id"]:
                row["evidence_sha256"] = evidence["sha256"]
        self.fixture.m["support_index"] = self.fixture.put("index.json", self.fixture.index)
        self.refresh_dossier()
        self.assert_blocked("live_model_acceptance_missing")

    def test_report_output_omits_untrusted_payload_and_private_paths(self):
        self.index["selection"]["path"] = "../private-marker-untrusted"
        self.save()
        rendered = json.dumps(self.assert_blocked())
        self.assertNotIn("private-marker-untrusted", rendered)
        self.assertNotIn(str(self.root), rendered)


class RealRetainedDossierTests(unittest.TestCase):
    def test_real_historical_not_ready_dossier_is_independently_refused(self):
        selection_path = ROOT / "docs/operations/evidence/sou129/selection.json"
        selection = json.loads(selection_path.read_bytes())
        stored_path = ROOT / "docs/operations/evidence/sou129/current-dossier/dossier.json"
        stored = json.loads(stored_path.read_bytes())
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            # Restore exact public selected bytes from their retained source;
            # no synthetic runtime outcomes or substituted failure labels.
            refs = [selection["support_index"], selection["workload"]]
            refs += [entry["file"] for entry in selection["evidence"]]
            for reference in refs:
                raw = d.git_bytes(ROOT, selection["candidate"]["commit"], reference["path"])
                self.assertEqual(p.sha(raw), reference["sha256"])
                path = root / reference["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            selection_ref = ref("selection.json", selection_path.read_bytes())
            (root / "selection.json").write_bytes(selection_path.read_bytes())
            dossier_ref = ref("dossier.json", stored_path.read_bytes())
            (root / "dossier.json").write_bytes(stored_path.read_bytes())
            index = {"format": p.VERSION, "candidate": selection["candidate"], "scope": p.SCOPE,
                     "candidate_manifest_sha256": "a" * 64, "selection": selection_ref,
                     "dossier": dossier_ref,
                     "stages": [{"id": stage, "report": selection["evidence"][0]["file"]}
                                for stage in p.RUNTIME.STAGES]}
            index_path = root / "readiness-index.json"
            index_path.write_bytes(encoded(index))
            approval = {"format": p.APPROVAL_VERSION, "candidate": index["candidate"],
                        "scope": p.SCOPE, "candidate_manifest_sha256": "a" * 64,
                        "index_sha256": p.sha(index_path.read_bytes()), "decision": "approved",
                        "operator": "synthetic-verifier-control",
                        "roadmap_decisions": {"version": support.DECISION_VERSION,
                            "source": index["candidate"]["commit"], "decisions": []}}
            approval_path = Path(external) / "approval.json"
            approval_path.write_bytes(encoded(approval))
            result = p.verify(index_path, root, ROOT, index["candidate"]["commit"], "a" * 64,
                              approval_path)
            self.assertEqual(stored["status"], "NOT_READY")
            self.assertEqual(result["dossier_status"], "NOT_READY", result)
            self.assertEqual(result["status"], "blocked")
            self.assertTrue(set(result["blockers"]) & {"dossier_not_ready", "dossier_recomputed_verdict_mismatch"})


class ArchiveBoundsTests(unittest.TestCase):
    def test_pax_extension_is_refused_before_large_body_read(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT,
                          pax_headers={"comment": "x" * (1024 * 1024)}) as archive:
            info = tarfile.TarInfo("candidate/agentfw")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with gzip.GzipFile(fileobj=io.BytesIO(output.getvalue())) as stream:
            with patch.object(p, "MAX_ARCHIVE_EXPANSION", 16384):
                with self.assertRaisesRegex(p.Blocked, "unsupported_candidate_archive_extension_or_link"):
                    p.tar_binary(stream, "candidate/agentfw")
                self.assertEqual(stream.tell(), 512)

    def test_gnu_longname_is_refused_before_extension_body(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
            info = tarfile.TarInfo("a" * 150)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with gzip.GzipFile(fileobj=io.BytesIO(output.getvalue())) as stream:
            with self.assertRaisesRegex(p.Blocked, "unsupported_candidate_archive_extension_or_link"):
                p.tar_binary(stream, "candidate/agentfw")
            self.assertEqual(stream.tell(), 512)

    def test_decoded_zero_padding_is_charged_to_shared_budget(self):
        raw = gzip.compress(b"\0" * (1024 * 1024))
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            with patch.object(p, "MAX_ARCHIVE_EXPANSION", 16384):
                with self.assertRaisesRegex(p.Blocked, "candidate_archive_expansion_limit"):
                    p.tar_binary(stream, "candidate/agentfw")

    def test_duplicate_member_cannot_select_last_binary(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for _ in range(2):
                info = tarfile.TarInfo("candidate/agentfw")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
        with gzip.GzipFile(fileobj=io.BytesIO(output.getvalue())) as stream:
            with self.assertRaisesRegex(p.Blocked, "candidate_archive_duplicate_member"):
                p.tar_binary(stream, "candidate/agentfw")

    def test_zip_entry_count_is_rejected_before_existing_member_parser(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as target:
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                for number in range(p.MAX_ARCHIVE_ENTRIES + 1):
                    archive.writestr(str(number) + ".json", b"{}")
            raw = output.getvalue()
            (Path(root) / "many.zip").write_bytes(raw)
            selected = {"path": "many.zip", "sha256": p.sha(raw), "member": "0.json",
                        "member_sha256": p.sha(b"{}")}
            with patch.object(d, "selected_bytes") as original_parser:
                with self.assertRaisesRegex(p.Blocked, "invalid_selected_evidence"):
                    p.Snapshot(root, target).add(selected)
                original_parser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
