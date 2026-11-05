"""SOU-228 installed front-door, Linux-v1 scope and clean-user lifecycle evidence controls.

The committed fixtures are sanitized derivatives of the original GitHub artifact
reports (see fixtures/sou228/provenance.json). The reviewed index pins the
immutable original report hashes; tests rebind only those rows to fixture hashes.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
SPEC = importlib.util.spec_from_file_location("roadmap_support", REPO / "scripts/roadmap_support.py")
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)
INDEX = REPO / "docs/operations/roadmap-support-index.json"
FIXTURES = REPO / "scripts/tests/fixtures/sou228"
PROVENANCE = json.loads((FIXTURES / "provenance.json").read_bytes())["files"]
SCOPE_DOCUMENT = REPO / "profiles/pilot/linux-v1/scope.json"
TESTED = "b4d3e7d67abe7cfc2a0e0877dbd21d1d0c8e232f"
# Tree-identical merge commit of the tested source: never executed by these runs.
MERGE = "5dd30c878d0c786d4ec6c623a33ce4b554469683"
# Hard-coded `accepted_baseline` constant of the clean-user driver: not the tested product.
PRODUCER_BASELINE = "9a3c5b38e56ebc6ebbeedfda98805f6a327cb371"
FRONT, SCOPE = "sou228-front-door-41818201020", "sou228-linux-v1-scope-41818201020"
CLEAN_A, CLEAN_B = "sou228-clean-user-41818211366", "sou228-clean-user-41818225908"
ORIGINAL_REPORTS = {
    "sou-228/41818201020/sou215-pilot-scope/report.json":
        "c360bb3f2e03141969f0ed700134cf1477bc05b887b16bc35be2968ed349c084",
    "sou-228/41818211366/sou216-clean-user/report.json":
        "5ae594e027b9b03354504898e89d1bf85b523d8e3da095a1de6b26b9299c9515",
    "sou-228/41818225908/sou216-clean-user/report.json":
        "55a53e973c8190408f8631ef75e02d5e20ad0580b3b7859b055dfad14986a51e",
}
ARTIFACT_ZIPS = {
    "864669ba33cb5df823e44d1c52c408948bcd342754bef38a3feab3d60ba44f1b",
    "ffa3b7a3f30f6707acdd1f5a2ac62128eab4557b1d4dca12ab8a032379faa1b1",
    "8daccd83d0f88d49bbc5152bcedd2fdbaa32e51c49c03bace5fc15db5c95d6a3",
}
PRIVATE_MARKERS = ("<redacted>", "/home/", "/tmp/", "_temp", '"uid"', '"gid"', '"pid"', "user_namespace",
                   "boot_identity", "private_provenance", "demo_selection")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class InstalledEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.index = copy.deepcopy(support.validate_index(support.load_json(INDEX, support.MAX_INDEX)[0]))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "evidence"
        shutil.copytree(FIXTURES / "sou-228", self.root / "sou-228")
        fixture = {row["path"]: row["fixture_sha256"] for row in PROVENANCE}
        for row in self.rows():
            row["sha256"] = fixture[row["path"]]
            for companion in row["companions"]:
                companion["sha256"] = fixture[companion["path"]]

    def rows(self):
        return [row for row in self.index["evidence"] if row["format"] in support.PER_RUN_FORMATS]

    def row(self, evidence_id):
        return next(row for row in self.index["evidence"] if row["id"] == evidence_id)

    def path(self, evidence_id, role=None):
        row = self.row(evidence_id)
        return row["path"] if role is None else next(c["path"] for c in row["companions"] if c["role"] == role)

    def evaluate(self, evidence_id, target=TESTED):
        row = self.row(evidence_id)
        cap = next(c for c in self.index["capabilities"] if c["id"] == row["capability"])
        return support.evaluate(row, self.root, target, cap)

    def load(self, relative):
        return json.loads((self.root / relative).read_bytes())

    def write(self, relative, obj):
        """Replace a fixture and rebind every index reference, as a forger with index access could."""
        raw = json.dumps(obj).encode()
        (self.root / relative).write_bytes(raw)
        for row in self.rows():
            if row["path"] == relative:
                row["sha256"] = sha(raw)
            for companion in row["companions"]:
                if companion["path"] == relative:
                    companion["sha256"] = sha(raw)

    def mutate(self, evidence_id, change, role=None):
        relative = self.path(evidence_id, role)
        obj = self.load(relative)
        change(obj)
        self.write(relative, obj)

    def assertInvalid(self, evidence_id, message):
        result = self.evaluate(evidence_id)
        self.assertEqual(result["status"], "invalid", result["reason"])
        self.assertIn(message, result["reason"])

    @staticmethod
    def clean_rows(obj):
        return {row["id"]: row for row in obj["clean_user"]["cases"]}

    # Provenance and actual dispositions.

    def test_fixture_hashes_are_distinct_from_original_and_artifact_hashes(self):
        real = support.validate_index(support.load_json(INDEX, support.MAX_INDEX)[0])
        pinned = {row["path"]: row["sha256"] for row in real["evidence"]}
        pinned.update({c["path"]: c["sha256"] for row in real["evidence"] for c in row.get("companions", [])})
        for path, original in ORIGINAL_REPORTS.items():
            self.assertEqual(pinned[path], original)
        self.assertEqual(len(PROVENANCE), 13)
        for entry in PROVENANCE:
            raw = (FIXTURES / entry["path"]).read_bytes()
            self.assertEqual(sha(raw), entry["fixture_sha256"])
            self.assertNotIn(b"\r", raw)
            self.assertEqual(pinned[entry["path"]], entry["original_sha256"])
            self.assertNotEqual(entry["fixture_sha256"], entry["original_sha256"])
            self.assertIn(entry["artifact_zip_sha256"], ARTIFACT_ZIPS)
            self.assertNotIn(entry["artifact_zip_sha256"], (entry["original_sha256"], entry["fixture_sha256"]))

    def test_actual_dispositions_stay_unbound_with_named_proof_gaps(self):
        runtimes = set()
        for evidence_id, total in ((FRONT, 40), (SCOPE, 40), (CLEAN_A, 15), (CLEAN_B, 15)):
            result = self.evaluate(evidence_id)
            observed = result["observed"]
            self.assertEqual(result["status"], "unbound", result["reason"])
            self.assertEqual(observed["counts"], {"passed": total, "failed": 0, "skipped": 0,
                                                  "expected": total, "complete": True})
            self.assertEqual((observed["source"], observed["tree"]),
                             (TESTED, "6b0afad2456b53a5e394ed04a08606bd5f39c187"))
            self.assertIn(support.UNVERIFIED_WITNESS, observed["unverified"])
            runtimes.add(observed["identity"]["runtime"])
        self.assertEqual(len(runtimes), 3, "each native run keeps its own runtime digest")
        self.assertIn(support.UNVERIFIED_RECEIPT_ABSENT, self.evaluate(SCOPE)["reason"])
        self.assertIn(support.UNVERIFIED_GENERATION, self.evaluate(SCOPE)["reason"])
        clean = self.evaluate(CLEAN_A)["observed"]
        self.assertIn(support.UNVERIFIED_RECEIPT_BYTES, clean["unverified"])
        self.assertIn(support.UNVERIFIED_SEALED, clean["unverified"])
        self.assertEqual(clean["refusals"], 2)
        self.assertEqual(clean["driver_source"], TESTED)
        self.assertEqual(clean["scope"]["selected"], False)
        scope = self.evaluate(SCOPE)["observed"]["scope"]
        self.assertEqual((scope["selected"], scope["state"]), (True, "conforming"))
        self.assertNotIn("scope", self.evaluate(FRONT)["observed"])
        report = support.build(self.index, self.root, TESTED, [])
        statuses = {cap["id"]: cap["status"] for cap in report["capabilities"]}
        self.assertEqual([statuses[c] for c in ("installed-front-door-linux", "linux-v1-scope",
                                                 "clean-user-lifecycle-linux")], ["unbound"] * 3)
        self.assertTrue(all(c["status"] == "open" for c in report["criteria"]))

    def test_stale_or_tree_identical_sources_are_historical_and_unapprovable(self):
        for target in (MERGE, PRODUCER_BASELINE):
            for evidence_id in (FRONT, SCOPE, CLEAN_A, CLEAN_B):
                self.assertEqual(self.evaluate(evidence_id, target)["status"], "historical")
        for target in (TESTED, MERGE):
            decision = {"version": support.DECISION_VERSION, "source": target, "decisions": [{
                "decision_id": "forged-acceptance", "criterion_id": "phase-5.1", "evidence_id": CLEAN_A,
                "evidence_sha256": self.row(CLEAN_A)["sha256"], "decision": "accepted"}]}
            rows = support.validate_decisions(decision, target, self.index)
            with self.assertRaisesRegex(support.Invalid, "does not bind"):
                support.build(self.index, self.root, target, rows)

    # Variant separation and scope.selected semantics.

    def test_variants_are_selected_by_the_index_and_not_interchangeable(self):
        clean, scope = self.row(CLEAN_A), self.row(SCOPE)
        clean_format, scope_format = clean["format"], scope["format"]
        clean["format"] = support.SCOPE_FORMAT
        self.assertInvalid(CLEAN_A, "clean-user report is not front-door evidence")
        clean["format"] = clean_format
        scope["format"] = support.CLEAN_USER_FORMAT
        self.assertInvalid(SCOPE, "Linux-v1 scope report is not clean-user evidence")
        scope["format"] = scope_format
        broken = copy.deepcopy(self.index)
        next(r for r in broken["evidence"] if r["id"] == SCOPE)["companions"] = copy.deepcopy(clean["companions"][:2])
        with self.assertRaisesRegex(support.Invalid, "unknown or duplicate companion role"):
            support.validate_index(broken)

    def test_selected_scope_in_a_clean_user_report_is_refused(self):
        def select(obj):
            obj["cases"][0]["live_status"]["scope"].update(selected=True, state="conforming")
        self.mutate(CLEAN_A, select)
        self.assertInvalid(CLEAN_A, "recorded a selected scope")

    def test_unselected_scope_never_becomes_linux_v1_qualification(self):
        def unselect(obj):
            for row in obj["cases"]:
                if row["case"] in ("useful", "cancel"):
                    row["live_status"]["scope"].update(selected=False, state="unselected")
        self.mutate(SCOPE, unselect)
        self.assertInvalid(SCOPE, "not selected and conforming")
        # The standard front-door view of the same report claims no scope and stays unbound.
        self.assertEqual(self.evaluate(FRONT)["status"], "unbound")

    def test_scope_identity_and_control_facts_must_match(self):
        def other_document(obj):
            for row in obj["cases"]:
                if row["case"] in ("useful", "cancel"):
                    row["live_status"]["scope"]["document_sha256"] = "0" * 64
        self.mutate(SCOPE, other_document)
        self.assertInvalid(SCOPE, "facts do not match")
        self.setUp()

        def readiness(obj):
            for row in obj["cases"]:
                if row["case"] == "useful":
                    row["live_status"]["scope"]["qualification"] = "unqualified READY"
        self.mutate(SCOPE, readiness)
        self.assertInvalid(SCOPE, "claims qualification")
        self.setUp()

        def started(obj):
            rows = {row["id"]: row for row in obj["pilot_scope_qualification"]["cases"]}
            rows["excluded-capability-refused"]["selected_started"] = 1
        self.mutate(SCOPE, started)
        self.assertInvalid(SCOPE, "excluded-capability-refused")
        self.setUp()
        self.row(SCOPE)["profile"] = "linux-v1@" + "1" * 64
        self.cap(self.index, "linux-v1-scope")["profile"] = self.row(SCOPE)["profile"]
        self.assertInvalid(SCOPE, "profile identity mismatch")

    # Inventories, totals and contradictions.

    def test_clean_user_inventory_tampering_is_invalid(self):
        changes = {
            "removed": lambda obj: obj["clean_user"]["cases"].pop(3),
            "reordered": lambda obj: obj["clean_user"]["cases"].reverse(),
            "duplicated": lambda obj: obj["clean_user"]["cases"].append(obj["clean_user"]["cases"][0]),
            "shortened": lambda obj: (obj["clean_user"]["required"].pop(), obj["clean_user"]["cases"].pop()),
        }
        for label, change in changes.items():
            with self.subTest(label):
                self.setUp()
                self.mutate(CLEAN_A, change)
                self.assertEqual(self.evaluate(CLEAN_A)["status"], "invalid")

    def test_front_door_and_companion_inventory_tampering_is_invalid(self):
        self.mutate(SCOPE, lambda obj: obj["cases"].pop())
        self.assertInvalid(SCOPE, "lacks required cases")
        self.setUp()
        self.mutate(SCOPE, lambda obj: obj["cases"].insert(9, obj["cases"][8]))
        self.assertInvalid(SCOPE, "front-door case inventory mismatch")
        self.setUp()
        self.mutate(FRONT, lambda obj: obj["counts"].update(passed=11, failed=1), "installed-pilot")
        self.assertInvalid(FRONT, "counts disagree")
        self.setUp()
        self.mutate(FRONT, lambda obj: obj["cases"].pop(), "demo")
        self.assertInvalid(FRONT, "demo: case inventory mismatch")

    def test_contradictory_outcomes_are_invalid(self):
        def failed_row_in_passed_report(obj):
            self.clean_rows(obj)["update-rollback"]["status"] = "failed"
        self.mutate(CLEAN_A, failed_row_in_passed_report)
        self.assertInvalid(CLEAN_A, "report status contradicts case outcomes")
        self.setUp()

        def go_with_incomplete(obj):
            self.clean_rows(obj)["remove-preserves-user-data"]["status"] = "incomplete"
            obj.update(status="failed", remaining_blockers=["remove-preserves-user-data"])
            obj["clean_user"]["status"] = "failed"
        self.mutate(CLEAN_A, go_with_incomplete)
        self.assertInvalid(CLEAN_A, "decision text contradicts")
        self.setUp()
        self.mutate(CLEAN_A, lambda obj: obj.update(remaining_blockers=["ask-once-replay"]))
        self.assertInvalid(CLEAN_A, "remaining blockers contradict")
        self.setUp()
        self.mutate(FRONT, lambda obj: obj.update(error="late_failure"))
        self.assertInvalid(FRONT, "status contradicts its error")
        self.setUp()
        self.mutate(CLEAN_A, lambda obj: obj["run_archival"].update(completed_runs_archived=12))
        self.assertInvalid(CLEAN_A, "run archival totals disagree")
        self.setUp()

        def witness(obj):
            self.clean_rows(obj)["catalog-service:denied-calls"]["forbidden_network_connections"] = 1
        self.mutate(CLEAN_A, witness)
        self.assertInvalid(CLEAN_A, "denied-call witnesses")

    def test_honest_failures_are_incomplete_not_invalid(self):
        def late_failure(obj):
            row = self.clean_rows(obj)["remove-preserves-user-data"]
            row.update(status="failed", reason="removal_preview_refused")
            obj.update(status="failed", decision="NO-GO: inspect failed and incomplete observations",
                       remaining_blockers=["remove-preserves-user-data"])
            obj["clean_user"]["status"] = "failed"
        self.mutate(CLEAN_A, late_failure)
        result = self.evaluate(CLEAN_A)
        self.assertEqual(result["status"], "incomplete", result["reason"])
        self.assertEqual(result["observed"]["counts"]["failed"], 1)
        early = {"format": support.INSTALLED_REPORT, "status": "failed", "cases": [], "skipped": 0,
                 "provider": "owned-scripted-loopback", "decision": "NO-GO",
                 "error": "ordinary_native_linux_user_required", "remaining_blockers": []}
        self.write(self.path(CLEAN_B), early)
        self.assertEqual(self.evaluate(CLEAN_B)["status"], "incomplete")

        def scope_failure(obj):
            del obj["cases"][8:]
            obj.update(status="failed", error="scope_excluded_capability_not_refused")
            nested = obj["pilot_scope_qualification"]
            nested["status"] = "incomplete"
            for row in nested["cases"][3:]:
                row.update(status="incomplete")
        self.mutate(SCOPE, scope_failure)
        for evidence_id in (FRONT, SCOPE):
            result = self.evaluate(evidence_id)
            self.assertEqual(result["status"], "incomplete", result["reason"])
        self.write(self.path(SCOPE), {"format": support.INSTALLED_REPORT, "status": "failed", "cases": [],
                                      "skipped": 0, "provider": "owned-scripted-loopback",
                                      "live_model_effectiveness": "not_tested",
                                      "error": "new_output_outside_checkout_required"})
        for evidence_id in (FRONT, SCOPE):
            self.assertEqual(self.evaluate(evidence_id)["status"], "incomplete")
        self.mutate(SCOPE, lambda obj: obj.update(status="passed", error=None))
        self.assertEqual(self.evaluate(SCOPE)["status"], "invalid")

    def test_skipped_positives_tampered_reports_and_missing_witnesses(self):
        for evidence_id, change in ((CLEAN_A, lambda obj: obj.update(skipped=1)),
                                    (FRONT, lambda obj: obj.update(skipped=1)),
                                    (CLEAN_A, lambda obj: self.clean_rows(obj)["ask-once-replay"].update(status="skipped")),
                                    (FRONT, lambda obj: obj["cases"][5].update(passed=False))):
            with self.subTest(evidence_id):
                self.setUp()
                self.mutate(evidence_id, change)
                self.assertEqual(self.evaluate(evidence_id)["status"], "invalid")
        self.setUp()

        def unsupported(obj):
            obj["cases"][4]["status"] = "unsupported"
            obj.update(status="failed", counts={"passed": 11, "failed": 0, "incomplete": 0, "unsupported": 1},
                       remaining_blockers=[{"case": obj["cases"][4]["id"], "status": "unsupported"}])
        self.mutate(FRONT, unsupported, "installed-pilot")
        result = self.evaluate(FRONT)
        self.assertEqual(result["status"], "incomplete", result["reason"])
        self.assertEqual(result["observed"]["counts"]["failed"], 1)
        self.setUp()
        report = self.root / self.path(CLEAN_A)
        report.write_bytes(report.read_bytes().replace(b'"passed"', b'"passed" ', 1))
        self.assertInvalid(CLEAN_A, "SHA-256 mismatch")
        self.setUp()
        row = self.row(CLEAN_A)
        row["companions"] = [c for c in row["companions"] if c["role"] != "user-session"]
        self.assertInvalid(CLEAN_A, "index omits the user-session companion")

    # Expected maintenance refusals.

    def test_expected_maintenance_refusals_are_preserved(self):
        def drop(obj):
            obj["cases"] = [row for row in obj["cases"] if row["case"] != "entered-updated-b"]
        self.mutate(CLEAN_A, drop)
        self.assertInvalid(CLEAN_A, "maintenance refusals are missing or relabelled")
        self.setUp()

        def relabel(obj):
            for row in obj["cases"]:
                if row["case"] == "entered-rolled-back-a":
                    row.update(status="completed", exit=0, reason=None)
        self.mutate(CLEAN_A, relabel)
        self.assertEqual(self.evaluate(CLEAN_A)["status"], "invalid")
        self.setUp()

        def unexpected(obj):
            for row in obj["cases"]:
                if row["case"] == "installed-a":
                    row.update(status="failed", exit=1, reason="pilot_failed")
        self.mutate(CLEAN_A, unexpected)
        self.assertInvalid(CLEAN_A, "unexpected failed run")

    # Companions, custody and claims.

    def test_tampered_or_missing_companions_are_refused(self):
        self.mutate(CLEAN_A, lambda obj: obj.update(elapsed_seconds=1), "walkthrough")
        self.assertInvalid(CLEAN_A, "walkthrough companion hash differs")
        self.setUp()
        companion = self.root / self.path(CLEAN_A, "ask")
        companion.write_bytes(companion.read_bytes() + b" ")
        self.assertInvalid(CLEAN_A, "companion ask SHA-256 mismatch")
        self.setUp()
        (self.root / self.path(CLEAN_A, "ask")).unlink()
        self.assertEqual(self.evaluate(CLEAN_A)["status"], "missing")
        self.setUp()
        row = self.row(CLEAN_A)
        row["companions"] = [c for c in row["companions"] if c["role"] != "ask"]
        self.assertInvalid(CLEAN_A, "index omits the Ask companion")
        self.setUp()
        self.mutate(CLEAN_A, lambda obj: obj.update(status="already-visible"), "user-session")
        self.assertInvalid(CLEAN_A, "user-session companion differs")
        self.setUp()
        self.mutate(FRONT, lambda obj: obj["selected_sha256"].update(agentfw="0" * 64), "demo")
        self.assertInvalid(FRONT, "demo: generation differs")
        self.setUp()
        row = self.row(FRONT)
        row["companions"] = row["companions"][:1]
        self.assertInvalid(FRONT, "omits a companion report")

    def test_source_and_product_custody(self):
        other = "1" * 40

        def driver(obj):
            obj["driver_source"]["commit"] = other
        self.mutate(CLEAN_A, driver)
        for role in ("user-session", "user-session-after-cleanup"):
            self.mutate(CLEAN_A, driver, role)
        self.mutate(CLEAN_A, lambda obj: obj["ci_user_session"].update(
            observation=self.load(self.path(CLEAN_A, "user-session")),
            report_sha256=self.row(CLEAN_A)["companions"][2]["sha256"]))
        result = self.evaluate(CLEAN_A)
        self.assertEqual(result["status"], "unbound", result["reason"])
        self.assertIn(support.UNVERIFIED_DRIVER, result["reason"])
        self.assertEqual(result["observed"]["driver_source"], other)
        cases = {
            "dirty": lambda obj: obj["source_before"].update(dirty=True),
            "after": lambda obj: obj["source_after"].update(commit=other),
            "build tree": lambda obj: obj["build_source"].update(tree=other),
            "component": lambda obj: obj["component"].update(commit=other),
            "baseline as runtime": lambda obj: obj.update(runtime_source=PRODUCER_BASELINE),
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.setUp()
                self.mutate(CLEAN_A, change)
                self.assertEqual(self.evaluate(CLEAN_A)["status"], "invalid")
        self.setUp()
        self.mutate(FRONT, lambda obj: obj["source_after"].update(tree=other))
        self.assertInvalid(FRONT, "source identity mismatch")

    def test_forged_review_and_claim_fields(self):
        self.mutate(CLEAN_A, lambda obj: obj.update(full_product_acceptance="established"))
        self.assertInvalid(CLEAN_A, "forged claim field: full_product_acceptance")
        self.setUp()
        self.mutate(FRONT, lambda obj: obj.update(pilot_readiness="certified"), "installed-pilot")
        self.assertInvalid(FRONT, "installed-pilot: version or claim field mismatch")
        self.setUp()
        self.mutate(CLEAN_A, lambda obj: obj.update(physical_human_presence_proven=True), "ask")
        self.assertInvalid(CLEAN_A, "Ask companion hash differs")
        ask = next(c["sha256"] for c in self.row(CLEAN_A)["companions"] if c["role"] == "ask")
        self.mutate(CLEAN_A, lambda obj: self.clean_rows(obj)["ask-once-replay"].update(original_report_sha256=ask))
        self.assertInvalid(CLEAN_A, "Ask companion version or claim field mismatch")
        self.setUp()
        self.mutate(CLEAN_A, lambda obj: obj.update(approval={"reviewer": "FORGED_REVIEWER", "decision": "accepted"},
                                                    review_status="FORGED_ACCEPTED"))
        report = support.build(self.index, self.root, TESTED, [])
        self.assertEqual(self.evaluate(CLEAN_A)["status"], "unbound")
        self.assertNotIn("FORGED", json.dumps(report))
        self.assertTrue(all(c["status"] == "open" for c in report["criteria"]))

    # Index identity contract.

    def test_per_run_runtime_identity_is_strict(self):
        a, b = self.row(CLEAN_A), self.row(CLEAN_B)
        a["identity"]["runtime"], b["identity"]["runtime"] = b["identity"]["runtime"], a["identity"]["runtime"]
        self.assertInvalid(CLEAN_A, "runtime identity mismatch")
        index = support.validate_index(support.load_json(INDEX, support.MAX_INDEX)[0])
        for label, change, message in (
                ("row runtime absent", lambda i: self.find(i, CLEAN_A)["identity"].update(runtime=None),
                 "pinned on the evidence row only"),
                ("capability runtime pinned", lambda i: self.cap(i, "clean-user-lifecycle-linux")["identity"].update(
                    runtime="0" * 64), "pinned on the evidence row only"),
                ("policy drift", lambda i: self.find(i, CLEAN_A)["identity"].update(policy="0" * 64),
                 "evidence/identity mismatch"),
                ("legacy drift", lambda i: self.find(i, "https-get-run")["identity"].update(runtime="0" * 64),
                 "evidence/identity mismatch"),
                ("legacy companions", lambda i: self.find(i, "https-get-run").update(companions=[]),
                 "unexpected or missing fields"),
                ("component kind", lambda i: self.find(i, CLEAN_A).update(kind="component"),
                 "integrated and source-bound"),
                ("duplicate role", lambda i: self.find(i, CLEAN_A)["companions"][1].update(role="walkthrough"),
                 "unknown or duplicate companion role")):
            with self.subTest(label):
                broken = copy.deepcopy(index)
                change(broken)
                with self.assertRaisesRegex(support.Invalid, message):
                    support.validate_index(broken)

    @staticmethod
    def find(index, evidence_id):
        return next(row for row in index["evidence"] if row["id"] == evidence_id)

    @staticmethod
    def cap(index, cap_id):
        return next(row for row in index["capabilities"] if row["id"] == cap_id)

    # CRLF checkouts and projection privacy.

    def test_crlf_checkout_does_not_change_the_pinned_scope_identity(self):
        checkout = SCOPE_DOCUMENT.read_bytes()
        committed = checkout.replace(b"\r\n", b"\n")
        crlf = committed.replace(b"\n", b"\r\n")
        digest_value = self.cap(self.index, "linux-v1-scope")["profile"].split("@", 1)[1]
        self.assertEqual(sha(committed), digest_value)
        self.assertNotEqual(sha(crlf), digest_value)
        # A raw-byte profile input converted to CRLF fails closed instead of matching.
        entry = self.index["profile_inputs"][0]
        isolated = Path(self.tmp.name) / "crlf-source"
        target = isolated / entry["path"]
        target.parent.mkdir(parents=True)
        target.write_bytes((REPO / entry["path"]).read_bytes().replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(support.Invalid, "profile input changed"):
            support.validate_profile_inputs({"profile_inputs": [entry]}, isolated)
        try:
            attribute = subprocess.run(["git", "check-attr", "eol", "--", "scripts/tests/fixtures/sou228/provenance.json"],
                                       cwd=REPO, capture_output=True, text=True, timeout=15)
        except OSError:
            self.skipTest("git unavailable")
        self.assertTrue(attribute.stdout.strip().endswith("eol: lf"), attribute.stdout)

    def test_projection_is_allowlisted_and_private_fields_never_render(self):
        report = support.build(self.index, self.root, TESTED, [])
        assets = REPO / "scripts/roadmap_support_assets"
        page = support.render(report, (assets / "report.css").read_text(), (assets / "report.js").read_text())
        payload = json.dumps(report)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, payload)
            self.assertNotIn(marker, page)
        allowed = {"sha256", "source", "platform", "architecture", "counts", "execution", "version", "identity",
                   "tree", "driver_source", "unverified", "refusals", "scope", "companions"}
        for cap in report["capabilities"]:
            for item in cap["evidence"]:
                if item["observed"]:
                    self.assertLessEqual(set(item["observed"]), allowed)
        self.assertIn(support.UNVERIFIED_SEALED, page.replace("\\u003c", "<"))

    def test_publication_readiness_snapshots_companions(self):
        import publication_readiness
        refs = publication_readiness.evidence_references(self.index)
        paths = {ref["path"] for ref in refs}
        for row in self.rows():
            self.assertIn(row["path"], paths)
            for companion in row["companions"]:
                self.assertIn({"path": companion["path"], "sha256": companion["sha256"],
                               "member": None, "member_sha256": None}, refs)
        legacy = [row for row in self.index["evidence"] if row["format"] not in support.PER_RUN_FORMATS]
        self.assertEqual(len(refs), len(self.index["evidence"]) +
                         sum(len(row["companions"]) for row in self.rows()))
        self.assertTrue(all({"path": row["path"], "sha256": row["sha256"], "member": None,
                             "member_sha256": None} in refs for row in legacy))

    @unittest.skipUnless(os.environ.get("SOU228_ORIGINAL_EVIDENCE"), "original reports are in private custody")
    def test_original_reports_when_supplied(self):
        index = support.validate_index(support.load_json(INDEX, support.MAX_INDEX)[0])
        root = Path(os.environ["SOU228_ORIGINAL_EVIDENCE"]).absolute()
        report = support.build(index, root, TESTED, [])
        evidence = {item["id"]: item for cap in report["capabilities"] for item in cap["evidence"]}
        for evidence_id in (FRONT, SCOPE, CLEAN_A, CLEAN_B):
            self.assertEqual(evidence[evidence_id]["status"], "unbound", evidence[evidence_id]["reason"])
            self.assertTrue(evidence[evidence_id]["observed"]["counts"]["complete"])
        payload = json.dumps(report)
        for marker in PRIVATE_MARKERS[1:]:
            self.assertNotIn(marker, payload)


if __name__ == "__main__":
    unittest.main()
