"""Custody controls with generated inputs and the existing SOU-228 case inventories."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_evidence_custody as custody
import roadmap_support as support

FIXTURE = ROOT / "scripts/tests/fixtures/sou228/sou-228/41818201020"
D = "a" * 64


class CustodyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.read("sou215-pilot-scope")
        self.pilot = self.read("sou215-installed-pilot")
        self.demo = self.read("sou215-pilot-demo")
        self.source = self.parent["source_before"]
        inputs = self.parent["inputs_sha256"]
        tools = {name: {"path": "/usr/bin/" + name, "sha256": D} for name in custody.TOOL_ROLES}
        build_source = dict(self.source, cargo_lock_sha256=D, rust_toolchain_sha256=D, files_sha256=D)
        receipt = {"format": "sw-native-pilot-agent-source-build/1", "status": "built-not-qualified",
                   "toolchain": "1.94.1", "source": build_source, "tools": tools,
                   "commands": custody.BUILD_COMMANDS, "environment": {
                       **custody.BUILD_ENV, "RUSTUP_TOOLCHAIN": "1.94.1",
                       **{key: tools[role]["path"] for key, role in custody.TOOL_ENV.items()}},
                   "binaries": {role: {"path": "/build/bin/" + role, "sha256": inputs[role], "size": 123}
                                for role in custody.BUILD_ROLES}, "build_seconds": 5, "generation_tree_sha256": D}
        receipt_raw = b"\n" + json.dumps(receipt, indent=3).encode() + b"\n"
        receipt_path = self.root / "original.json"
        receipt_path.write_bytes(receipt_raw)
        actual, ref = custody.capture_receipt(self.root, receipt_path, self.source, inputs)
        self.assertEqual(actual, receipt)
        self.assertEqual((self.root / "custody" / ref["file"]).read_bytes(), receipt_raw)
        bindings = self.parent["custody"] = {
            "format": "sw-installed-pilot-custody/1", "receipt": ref, "selections": {}, "observers": {},
            "observer_sources": custody.capture_observer_sources(self.root, ROOT, ("procfs", "receiver")),
        }
        self.parent.update(source_build_receipt_sha256=ref["sha256"], build_source=build_source,
                           compiler_inputs=tools)
        selected_source = {**self.source, "files_sha256": D}
        files = {role: {"path": "/selected/" + role, "sha256": self.pilot["selected_sha256"][role]}
                 for role in custody.SELECTION_ROLES}
        profiles = {role: {"registry_sha256": D, "package_tree_sha256": D} for role in ("filesystem", "git")}
        selection = {"format": "sw-installed-pilot-selection/3", "source": selected_source,
                     "files": files, "prepared_profiles": profiles}
        for name, value in (("primary", {**selection, "prepared_workspaces": {}}), ("demo", selection)):
            path = self.root / (name + ".json")
            path.write_text(json.dumps(value), encoding="utf-8")
            bindings["selections"][name] = custody.capture_selection(self.root, name, path, self.source,
                                                                      inputs, build_source)
        self.parent["selection_sha256"] = bindings["selections"]["primary"]["sha256"]
        self.parent["demo_selection_sha256"] = bindings["selections"]["demo"]["sha256"]
        for name in ("useful", "cancel"):
            next(row for row in self.parent["cases"] if row["case"] == name)["process_cleanup"] = {
                "all_stopped": True, "descendants": 1,
            }
        cleanup = {"all_stopped": True, "descendant_count": 1, "remaining": [], "observed": [
            {"pid": 1, "start_time_ticks": 123, "parent_process": True},
            {"pid": 2, "start_time_ticks": 321, "parent_process": False},
        ]}
        bindings["observers"]["front-door"] = custody.capture_front_door(
            self.root, self.parent, 1, 0, cleanup, cleanup, True)
        for row in self.pilot["cases"]:
            row["evidence"] = {
                "witness-calibration": {"receiver_positive_observed": True, "original_write_observed": True,
                                        "git_original_opens": 1, "fifo": {"forbidden.fifo": {"reader_seen": True}}},
                "untrusted-input-refusal": {"fifo": {"reader_seen": False, "bytes_written": 0},
                                            "opens_during_refused_mutator": 0, "receiver_deliveries": 0,
                                            "host": {"process_cleanup": cleanup}},
                "final-cleanup": {"all_owned_processes_stopped": True, "private_installation_removed": True,
                                  "source_and_inputs_unchanged": True, "forced_cleanup": False},
            }.get(row["id"], {})
        next(row for row in self.demo["cases"] if row["case"] == "useful-refusal").update(
            dispatch_counts=[1, 1, 0], exact_once_kernel_read=True, process_cleanup=cleanup)
        selected_identities = custody.selected_identities(selection)
        self.identity = {
            "implementation": self.parent["component"]["archive_sha256"], "runtime": inputs["agentfw"],
            "policy": self.pilot["selected_sha256"]["policy"],
            **custody.combine_identities([selected_identities, selected_identities]),
        }

    @staticmethod
    def read(name):
        return json.loads((FIXTURE / name / "report.json").read_bytes())

    def write(self, name, value):
        raw = json.dumps(value).encode()
        (self.root / name).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def evaluate(self, *, child_parent=None, child_selection=None, child_source=None):
        parent_sha = self.write("parent.json", self.parent)
        companions = []
        for role, child in (("installed-pilot", self.pilot), ("demo", self.demo)):
            child["parent_report_sha256"] = child_parent or parent_sha
            child["selection_sha256"] = child_selection or self.parent["demo_selection_sha256"]
            if child_source:
                child["source_before"]["commit"] = child_source
            name = role + ".json"
            companions.append({"role": role, "path": name, "sha256": self.write(name, child)})
        descriptor = {"id": "control", "path": "parent.json", "sha256": parent_sha, "format": support.SCOPE_FORMAT,
                      "kind": "integrated-candidate", "source": self.source["commit"],
                      "platform": "linux", "architecture": "x86_64",
                      "host": "unit-test", "server": "unit-test", "transport": "stdio",
                      "profile": "linux-v1@" + self.parent["cases"][5]["live_status"]["scope"]["document_sha256"],
                      "identity": self.identity, "companions": companions}
        cap = {"platform": "linux", "architecture": "x86_64"}
        return support.evaluate(descriptor, self.root, self.source["commit"], cap)

    def test_complete_goes_to_pending_review(self):
        evidence = self.evaluate()
        self.assertEqual(evidence["status"], "pending-review", evidence)
        self.assertEqual(evidence["observed"]["custody"]["receipt_sha256"], self.parent["source_build_receipt_sha256"])
        self.assertNotIn("/build", json.dumps(evidence))

    def test_changed_receipt(self):
        path = self.root / "custody/source-build-receipt.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertIn("custody bytes changed", self.evaluate()["reason"])

    def test_changed_child_selection(self):
        self.assertIn("different generation", self.evaluate(child_selection=D)["reason"])

    def test_foreign_child_parent(self):
        self.assertIn("different parent", self.evaluate(child_parent=D)["reason"])

    def test_wrong_source(self):
        self.assertIn("source identity mismatch", self.evaluate(child_source="a" * 40)["reason"])

    def test_duplicate_case(self):
        self.pilot["cases"][1] = self.pilot["cases"][0]
        self.assertIn("case inventory mismatch", self.evaluate()["reason"])

    def test_missing_cleanup(self):
        self.pilot["cases"][-1]["evidence"].pop("all_owned_processes_stopped")
        self.assertEqual(self.evaluate()["status"], "invalid")

    def test_missing_calibration(self):
        self.pilot["cases"][2]["evidence"]["receiver_positive_observed"] = False
        self.assertIn("calibration missing", self.evaluate()["reason"])

    def test_limited_input_before_parse(self):
        path = self.root / "custody/source-build-receipt.json"
        path.write_bytes(b"{" + b"x" * custody.RECEIPT_LIMIT)
        self.assertIn("byte limit", self.evaluate()["reason"])

    def test_duplicate_key_and_number_overflow(self):
        for raw in (b'{"source":{},"source":{}}', b'{"source":1e400}'):
            (self.root / "custody/source-build-receipt.json").write_bytes(raw)
            self.parent["custody"]["receipt"]["sha256"] = custody.sha(raw)
            self.assertEqual(self.evaluate()["status"], "invalid")
