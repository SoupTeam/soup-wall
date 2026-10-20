"""SOU-97: candidate-mode replay and driver selection logic (no real server; not runtime evidence)."""
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPLAY = load("sou97_replay_tests", "scripts/sou97_runtime_replay.py")
GATE = load("sou97_gate_for_replay_tests", "eval/tools/check_pilot_gate.py")
MANIFEST = json.loads((ROOT / "eval/pilot/sou97_gate_manifest_v1.json").read_bytes())
CANDIDATE = ROOT / MANIFEST["candidate"]["path"]


def withheld(identifier, phase, reasons):
    return {"jsonrpc": "2.0", "id": identifier, "result": {"isError": True, "content": [
        {"type": "text", "text": f"Soup Wall withheld MCP {phase} ({reasons})"}]}}


class ClassifierSelection(unittest.TestCase):
    def test_exact_identity_and_revision(self):
        identity = REPLAY.classifier_identity(CANDIDATE, MANIFEST["candidate"]["sha256"])
        self.assertEqual((identity["sha256"], identity["revision"], identity["mode"]),
                         (MANIFEST["candidate"]["sha256"], "pilot_readonly_v1.1", "candidate"))

    def test_mismatch_or_malformed_digest_refuses(self):
        for digest in ("0" * 64, "", "ABC", MANIFEST["candidate"]["sha256"].upper()):
            with self.subTest(digest=digest), self.assertRaises(REPLAY.ReplayError):
                REPLAY.classifier_identity(CANDIDATE, digest)

    def test_drivers_require_both_selection_arguments(self):
        for driver in ("scripts/verify-sou62-real-mcp.py", "scripts/verify-sou68-real-mcp.py"):
            common = ["--agentfw", "a", "--sandbox-test-binary", "b", "--output", "o", "--expected-commit", "c"]
            extra = (["--node", "n", "--bwrap", "w", "--claude", "x"] if "sou62" in driver
                     else ["--git", "g", "--bwrap", "w", "--git-launcher", "l", "--git-sha256", "0" * 64])
            done = subprocess.run([sys.executable, "-B", str(ROOT / driver), *common, *extra,
                                   "--classifier-script", str(CANDIDATE)], capture_output=True, text=True, timeout=120)
            self.assertEqual(done.returncode, 2, driver)
            self.assertIn("must be given together", done.stderr)
            done = subprocess.run([sys.executable, "-B", str(ROOT / driver), *common, *extra,
                                   "--classifier-script", str(CANDIDATE), "--classifier-sha256", MANIFEST["candidate"]["sha256"]],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["status"], "plan")  # nothing runs without --run


class MatrixAndSeed(unittest.TestCase):
    def test_runtime_reachable_cases_are_partitioned_without_unreachable_ones(self):
        for profile, benign in (("filesystem", 46), ("git", 20)):
            digest, cases = REPLAY.matrix_cases(profile)
            self.assertEqual(digest, MANIFEST["inputs"]["eval/fixtures/soup_pilot_readonly_matrix_v0.1.json"])
            self.assertEqual(sum(c["expectation"] == "benign" for c in cases), benign)
            self.assertTrue(all(c["expectation"] in ("benign", "refusal") for c in cases))
            self.assertFalse({"PMX-E01", "PMX-E02", "PMF-M02", "PMF-S01", "PMG-S01"} & {c["id"] for c in cases})
        ids = {c["id"] for c in REPLAY.matrix_cases("filesystem")[1] if c["expectation"] == "refusal"}
        self.assertIn("PMF-A01", ids)  # undeclared field: must be refused before dispatch

    def test_seed_creates_every_benign_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "notes.txt").write_text("x", encoding="utf-8")
            seeded = REPLAY.seed_filesystem_workspace(workspace)
            self.assertIn("remove/", seeded)
            self.assertEqual(len(list((workspace / "src").iterdir())), 256)

    def test_original_error_list_is_the_manifest_list(self):
        self.assertEqual(REPLAY.original_error_expected(), MANIFEST["runtime"]["original_error_expected"])
        self.assertEqual(sorted(REPLAY.original_error_expected()), ["PMG-B07", "PMG-B08", "PMG-B19", "PMG-B20"])


class ResponseClassification(unittest.TestCase):
    def test_kinds(self):
        ok = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "x"}]}}
        upstream = {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": "bad revision"}]}}
        error = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "MCP tool is unsupported by selected profile"}}
        cases = [
            (ok, True, ("original_result", "allow")), (upstream, True, ("original_error", "allow")),
            (withheld(1, "invocation", "classifier_ask"), False, ("native_withheld_invocation", "ask")),
            (withheld(1, "invocation", "filesystem-profile-deny-write"), False, ("native_withheld_invocation", "deny")),
            (withheld(1, "result", "injection"), True, ("native_withheld_result", "allow_result_withheld")),
            (error, False, ("native_error", "refused")), (None, False, ("no_response", "refused")),
        ]
        for response, dispatched, (kind, verdict) in cases:
            with self.subTest(kind=kind):
                got = REPLAY.classify_response(response, dispatched)
                self.assertEqual((got["result_kind"], got["native_verdict"]), (kind, verdict))

    def record(self, **changes):
        base = {"case_id": "PMF-B01", "expectation": "benign", "result_kind": "original_result", "native_verdict": "allow",
                "refusal_code": None, "dispatched": True, "dispatch_witness": {"observed": True, "inotify_opens": 2},
                "effect_witness": {"workspace_unchanged": True, "egress_bodies": 0}}
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return base

    def test_expectations(self):
        allowed = REPLAY.original_error_expected()
        self.assertEqual(REPLAY.expectation_failures(self.record(), allowed), [])
        self.assertTrue(REPLAY.expectation_failures(self.record(result_kind="original_error"), allowed))
        self.assertEqual(REPLAY.expectation_failures(self.record(case_id="PMG-B07", result_kind="original_error"), allowed), [])
        self.assertTrue(REPLAY.expectation_failures(self.record(case_id="PMG-B07"), allowed))
        refusal = dict(expectation="refusal", case_id="PMF-A01", result_kind="native_error", native_verdict="refused",
                       refusal_code="jsonrpc:-32602:x", dispatched=False, dispatch_witness={"observed": False, "inotify_opens": 0},
                       continuation_ok=True)
        self.assertEqual(REPLAY.expectation_failures(self.record(**refusal), allowed), [])
        for bad in ({"dispatched": True}, {"dispatch_witness": {"inotify_opens": 1}},
                    {"result_kind": "native_withheld_result", "native_verdict": "allow_result_withheld"},
                    {"effect_witness": {"workspace_unchanged": False}}, {"effect_witness": {"egress_bodies": 1}},
                    {"continuation_ok": False}, {"refusal_code": None}):
            with self.subTest(bad=bad):
                self.assertTrue(REPLAY.expectation_failures(self.record(**{**refusal, **bad}), allowed))


class FakeSession:
    """Bookkeeping harness only: it replaces the transport, never the outcome rules or the gate."""

    def __init__(self, log, outcome, terminate_on=()):
        self.log, self.outcome, self.terminate_on, self.closed = log, outcome, set(terminate_on), False

    def exchange(self, frame):
        identifier, name = frame["id"], frame["params"]["name"]
        if name in self.terminate_on:
            raise ValueError("fake closed before correlated response")
        response, dispatched = self.outcome(frame)
        self.log.append({"host_call_id": identifier, "execution_dispatched": dispatched, "arguments_sha256": "x"})
        return response, json.dumps(response).encode()

    def close(self):
        self.closed = True


class ReplayBookkeeping(unittest.TestCase):
    def test_terminated_session_is_restarted_and_recorded_not_passed(self):
        log, sessions = [], []

        def outcome(frame):
            return {"jsonrpc": "2.0", "id": frame["id"], "error": {"code": -32602, "message": "refused"}}, False

        def open_session(index):
            session = FakeSession(log, outcome, terminate_on={""})
            sessions.append(session)
            return session, "log"

        class Witness:
            def __init__(self, root):
                pass

            def drain(self):
                return 0

            def close(self):
                pass

        receiver = type("Receiver", (), {"bodies": []})()
        with tempfile.TemporaryDirectory() as tmp:
            result, failures = REPLAY.replay("filesystem", open_session=open_session, events=lambda _: log, snapshot=lambda _: {},
                                             workspace=Path(tmp), witness_cls=Witness, receiver=receiver,
                                             continuation=lambda session, identifier: True,
                                             responses_path=Path(tmp, "responses.jsonl"))
            sidecar = Path(tmp, "responses.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(result["cases"]), len(sidecar))
        terminated = [c for c in result["cases"] if c["session_terminated"]]
        self.assertEqual([c["case_id"] for c in terminated], ["PMF-V04"])  # empty tool name in this fake transport
        self.assertEqual(terminated[0]["result_kind"], "no_response")
        self.assertEqual(result["sessions"], 2)
        benign = [c for c in result["cases"] if c["expectation"] == "benign"]
        self.assertTrue(benign and all(c["case_id"] in {f["case"] for f in failures} for c in benign))  # refused benign = failure
        self.assertTrue(all(s.closed for s in sessions))


class EvidenceFormat(unittest.TestCase):
    """Driver evidence must be the exact format the gate validates (compatibility, not qualification)."""

    def build(self, mutate=None):
        head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        classifier = REPLAY.classifier_identity(CANDIDATE, MANIFEST["candidate"]["sha256"])
        allowed = REPLAY.original_error_expected()
        files = {}
        for profile in ("filesystem", "git"):
            digest, cases = REPLAY.matrix_cases(profile)
            records = []
            for case in cases:
                benign = case["expectation"] == "benign"
                kind = ("original_error" if case["id"] in allowed else "original_result") if benign else "native_error"
                records.append({"case_id": case["id"], "arguments_sha256": {"sent": REPLAY.canonical_sha(case["arguments"])},
                                "result_kind": kind, "native_verdict": "allow" if benign else "refused",
                                "refusal_code": None if benign else "jsonrpc:-32602:x", "dispatched": benign,
                                "dispatch_witness": {"observed": benign, "inotify_opens": 1 if benign else 0},
                                "useful_result": kind == "original_result",
                                "effect_witness": {"workspace_unchanged": True, "egress_bodies": 0}})
            ev = REPLAY.evidence(profile, status="pass", source={"commit": head, "tree": None, "dirty": False},
                                 classifier=classifier, replay_result={"matrix_sha256": digest, "cases": records, "sessions": 1},
                                 failures=[], calibration={"dispatch_witness_calibrated": True, "effect_witness_calibrated": True},
                                 identities={"agent_binary_sha256": "a" * 64, "driver_sha256": "b" * 64},
                                 runtime={"bwrap": "c" * 64},
                                 witnesses={"daemon_stopped": True, "workspace_unchanged": True, "egress_bodies": 0})
            ev["platform"] = "Linux-format-compatibility-test"  # this is a format test, not a Linux run
            if mutate:
                mutate(profile, ev)
            files[profile] = ev
        with tempfile.TemporaryDirectory() as tmp:
            args = []
            for profile, ev in files.items():
                path = Path(tmp, profile + ".json")
                path.write_text(json.dumps(ev), encoding="utf-8")
                args += ["--runtime-evidence", str(path)]
            subprocess.run([sys.executable, "-B", str(ROOT / "eval/tools/check_pilot_gate.py"), "--mode", "runtime",
                            "--manifest-file", str(ROOT / "eval/pilot/sou97_gate_manifest_v1.json"), *args,
                            "--out", str(Path(tmp, "g.json"))], capture_output=True, text=True, timeout=300)
            return json.loads(Path(tmp, "g.json").read_bytes())

    def test_driver_evidence_shape_matches_the_gate(self):
        self.assertEqual(self.build()["failures"], [])

    def test_gate_rejects_bound_or_outcome_changes_in_driver_evidence(self):
        def case(ev, cid):
            return next(c for c in ev["cases"] if c["case_id"] == cid)
        mutations = {
            "runtime_arguments_mismatch": lambda p, ev: p == "filesystem" and case(ev, "PMF-B27")["arguments_sha256"].update(sent="0" * 64),
            "runtime_benign_failed": lambda p, ev: p == "git" and case(ev, "PMG-B07").update(result_kind="original_result", useful_result=True),
            "runtime_refusal_failed": lambda p, ev: p == "filesystem" and case(ev, "PMF-A01").update(
                dispatched=True, dispatch_witness={"observed": True, "inotify_opens": 3}),
            "runtime_case_malformed": lambda p, ev: p == "git" and ev.update(cases={"not": "a list"}),
            "runtime_malformed": lambda p, ev: p == "git" and ev.update(identities="not an object"),
            "runtime_platform": lambda p, ev: p == "git" and ev.update(platform=__import__("platform").platform()
                                                                        if not sys.platform.startswith("linux") else "Windows"),
        }
        for code, mutate in mutations.items():
            with self.subTest(code=code):
                result = self.build(mutate)
                self.assertEqual(result["verdict"], "FAIL")
                self.assertIn(code, {f["code"] for f in result["failures"]})
        unlisted = self.build(lambda p, ev: p == "git" and case(ev, "PMG-B01").update(result_kind="original_error", useful_result=False))
        self.assertIn("runtime_benign_failed", {f["code"] for f in unlisted["failures"]})


class DriverGrade(unittest.TestCase):
    """The SOU-62 grade(): default mode keeps the Ask requirement; candidate mode needs the admitted read."""

    @classmethod
    def setUpClass(cls):
        cls.tests = load("sou97_sou62_tests", "scripts/tests/test_sou62_real_mcp.py")
        cls.verify = cls.tests.VERIFY

    def test_default_mode_still_requires_the_directory_tree_ask(self):
        report = self.tests.complete_report()
        self.verify.grade(report)
        report.pop("directory_tree_classifier_refusal")
        with self.assertRaises(KeyError):
            self.verify.grade(report)

    def test_candidate_mode_requires_admitted_read_and_clean_replay(self):
        report = self.tests.complete_report()
        report.pop("directory_tree_classifier_refusal")
        report["classifier"] = {"mode": "candidate"}
        tree = json.dumps([{"name": "notes.txt", "type": "file"}])
        report["directory_tree_candidate_read"] = {"passed": True, "response": {
            "jsonrpc": "2.0", "id": 38, "result": {"content": [{"type": "text", "text": tree}], "structuredContent": {"content": tree}}}}
        report["sou97_replay"] = {"cases": 74, "failures": []}
        self.verify.grade(report)
        report["sou97_replay"]["failures"] = [{"case": "PMF-A01"}]
        with self.assertRaises(ValueError):
            self.verify.grade(report)
        report["sou97_replay"]["failures"] = []
        report["directory_tree_candidate_read"]["response"] = withheld(38, "invocation", "classifier_ask")
        with self.assertRaises(ValueError):
            self.verify.grade(report)


if __name__ == "__main__":
    unittest.main()
