"""SOU-97: candidate-mode replay and driver selection logic (no real server; not runtime evidence)."""
import hashlib
import importlib.util
import json
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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

    def test_every_benign_case_has_targets_and_refusals_have_none(self):
        _, cases = REPLAY.matrix_cases("filesystem")
        for case in cases:
            with self.subTest(case=case["id"]):
                targets = REPLAY.case_targets(case)
                self.assertEqual(targets == [], case["expectation"] == "refusal" or case["id"] in NO_TARGET_CASES)

    def test_original_error_list_is_the_manifest_list(self):
        self.assertEqual(REPLAY.original_error_expected(), MANIFEST["runtime"]["original_error_expected"])
        self.assertEqual(sorted(REPLAY.original_error_expected()), ["PMG-B07", "PMG-B08", "PMG-B19", "PMG-B20"])


NO_TARGET_CASES = {"PMF-B21", "PMF-B24", "PMF-B25", "PMF-B26", "PMF-B27", "PMF-B29", "PMF-B30", "PMF-B31", "PMF-B32",
                   "PMF-B33", "PMF-B34", "PMF-B35", "PMF-B36", "PMF-B37", "PMF-B38", "PMF-B39", "PMF-B40", "PMF-B41",
                   "PMF-B42", "PMF-B46"}  # /workspace itself or no path: nothing to seed
BASE_FILES = ["notes.txt"] + [f"pending-{i}.fifo" for i in range(8)]  # the SOU-62 driver's own layout (FIFOs as names)
OUTPUT_BOUND = 16 * 1024  # input.rs DEFAULT_STRING_BYTES applies to the {content: string} output schema


def base_workspace(root: Path) -> Path:
    for name in BASE_FILES:
        (root / name).write_text("synthetic original text\n", encoding="utf-8")
    return root


def tree_snapshot(root: Path) -> dict:
    return {str(p.relative_to(root)): (p.is_dir(), p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


def upstream_tree(path: Path) -> str:
    """JSON.stringify(buildTree(path), null, 2) of @modelcontextprotocol/server-filesystem 2026.8.31 (dist/index.js)."""
    def build(directory):
        out = []
        for entry in sorted(directory.iterdir()):
            item = {"name": entry.name, "type": "directory" if entry.is_dir() else "file"}
            if entry.is_dir():
                item["children"] = build(entry)
            out.append(item)
        return out
    return json.dumps(build(path), indent=2, ensure_ascii=False)


def upstream_multiple(paths: list, root: Path) -> str:
    """read_multiple_files: `${filePath}:\\n${content}\\n` joined by `\\n---\\n` (dist/index.js)."""
    return "\n---\n".join(f"{p}:\n{(root / p[len('/workspace/'):]).read_text(encoding='utf-8')}\n" for p in paths)


def upper_bound_listing(directory: Path) -> int:
    """Generous bound for list/list_with_sizes/search/info: every entry name plus 96 bytes of formatting."""
    return sum(len(p.name.encode()) + 96 for p in directory.rglob("*")) + 512


def original_output_size(case: dict, root: Path) -> int:
    tool, args = case["tool"], case["arguments"]
    if tool == "directory_tree":
        return len(upstream_tree(root / args["path"][len("/workspace"):].lstrip("/")).encode())
    if tool == "read_multiple_files":
        return len(upstream_multiple(args["paths"], root).encode())
    if tool in ("read_file", "read_text_file"):
        return len((root / args["path"][len("/workspace/"):]).read_bytes())
    return upper_bound_listing(root)


class PerCaseSeeding(unittest.TestCase):
    def test_each_case_is_seeded_exactly_and_the_workspace_is_restored(self):
        _, cases = REPLAY.matrix_cases("filesystem")
        with tempfile.TemporaryDirectory() as tmp:
            root = base_workspace(Path(tmp))
            initial = tree_snapshot(root)
            for case in cases:
                with self.subTest(case=case["id"]):
                    created = REPLAY.seed_case(root, case)
                    for rel, kind in REPLAY.case_targets(case):
                        self.assertEqual((root / rel).is_dir(), kind == "directory", rel)
                    self.assertEqual((root / "notes.txt").read_text(encoding="utf-8"), "synthetic original text\n")
                    REPLAY.unseed_case(created)
                    self.assertEqual(tree_snapshot(root), initial)

    def test_preexisting_fixtures_are_never_created_replaced_or_removed(self):
        case = next(c for c in REPLAY.matrix_cases("filesystem")[1] if c["id"] == "PMF-B01")  # read_file notes.txt
        with tempfile.TemporaryDirectory() as tmp:
            root = base_workspace(Path(tmp))
            self.assertEqual(REPLAY.seed_case(root, case), [])
            REPLAY.unseed_case([])
            self.assertTrue((root / "notes.txt").exists())

    def test_unseed_refuses_to_remove_unexpected_content(self):
        case = next(c for c in REPLAY.matrix_cases("filesystem")[1] if c["id"] == "PMF-B22")  # docs/guide
        with tempfile.TemporaryDirectory() as tmp:
            root = base_workspace(Path(tmp))
            created = REPLAY.seed_case(root, case)
            (root / "docs/guide/unexpected.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(OSError):
                REPLAY.unseed_case(created)


class OutputBound(unittest.TestCase):
    """Every benign filesystem original result must fit the selected output profile, or native validation withholds it."""

    def test_every_benign_case_fits_with_per_case_seeding(self):
        _, cases = REPLAY.matrix_cases("filesystem")
        sizes = {}
        with tempfile.TemporaryDirectory() as tmp:
            root = base_workspace(Path(tmp))
            for case in cases:
                if case["expectation"] != "benign":
                    continue
                created = REPLAY.seed_case(root, case)
                try:
                    sizes[case["id"]] = original_output_size(case, root)
                finally:
                    REPLAY.unseed_case(created)
        self.assertEqual(len(sizes), 46)
        too_large = {cid: size for cid, size in sizes.items() if size > OUTPUT_BOUND}
        self.assertEqual(too_large, {})
        self.assertLess(sizes["PMF-B19"], OUTPUT_BOUND)  # 256 seeded files
        self.assertLess(sizes["PMF-B27"], 1024)  # /workspace tree of the driver's own layout

    def test_the_first_runs_global_seeding_exceeded_the_bound(self):
        # Regression record: seeding every target at once produced the withheld id 38 tree.
        _, cases = REPLAY.matrix_cases("filesystem")
        with tempfile.TemporaryDirectory() as tmp:
            root = base_workspace(Path(tmp))
            for case in cases:
                REPLAY.seed_case(root, case)
            self.assertGreater(len(upstream_tree(root).encode()), OUTPUT_BOUND)


class WitnessCoverage(unittest.TestCase):
    def test_witness_is_installed_after_seeding_and_watches_every_seeded_directory(self):
        _, cases = REPLAY.matrix_cases("filesystem")
        expected = {c["id"]: c for c in cases}
        installs = []

        class RecordingWitness:
            def __init__(self, root):
                installs.append({p.relative_to(root).as_posix() for p in [root, *root.rglob("*")] if p.is_dir()})

            def drain(self):
                return 0

            def close(self):
                pass

        log = []

        def outcome(frame):
            return {"jsonrpc": "2.0", "id": frame["id"], "result": {"content": [{"type": "text", "text": "x"}]}}, True

        receiver = type("Receiver", (), {"bodies": []})()
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            root = base_workspace(Path(tmp))
            initial = tree_snapshot(root)
            result, _ = REPLAY.replay("filesystem", open_session=lambda i: (FakeSession(log, outcome), "log"),
                                      events=lambda _: log, snapshot=tree_snapshot, workspace=root, witness_cls=RecordingWitness,
                                      receiver=receiver, continuation=lambda session, identifier: True,
                                      responses_path=Path(out, "responses.jsonl"),
                                      prepare=lambda case: REPLAY.seed_case(root, case), restore=REPLAY.unseed_case)
            self.assertEqual(tree_snapshot(root), initial)
        self.assertEqual(len(installs), len(result["cases"]))
        for watched, record in zip(installs, result["cases"]):
            with self.subTest(case=record["case_id"]):
                self.assertTrue(record["workspace_restored"])
                for rel, kind in REPLAY.case_targets(expected[record["case_id"]]):
                    directory = rel if kind == "directory" else str(Path(rel).parent.as_posix())
                    self.assertIn("." if directory in ("", ".") else directory, watched)


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

    def test_native_output_profile_withholding_is_never_an_original_error_or_allow(self):
        withheld_output = {"jsonrpc": "2.0", "id": 38, "error": {"code": -32603,
                           "message": "Unsupported MCP result withheld by the selected output profile"}}
        got = REPLAY.classify_response(withheld_output, True)
        self.assertEqual((got["result_kind"], got["native_verdict"]), ("native_withheld_result", "allow_result_withheld"))
        self.assertNotEqual(got["native_verdict"], "allow")
        timeout = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32001,
                   "message": "MCP call timed out; dispatched execution may have occurred"}}
        self.assertEqual(REPLAY.classify_response(timeout, True)["result_kind"], "native_error_after_dispatch")
        budget = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": (
            "MCP result withheld: a result text exceeds the 262144-byte per-result budget; the original call may have executed")}}
        got_budget = REPLAY.classify_response(budget, True)
        self.assertEqual((got_budget["result_kind"], got_budget["native_verdict"]),
                         ("native_error_after_dispatch", "allow_result_withheld"))
        original ={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "upstream failure text"}}
        self.assertEqual(REPLAY.classify_response(original, True)["result_kind"], "original_error_jsonrpc")
        unknown = REPLAY.classify_response(original, False)
        self.assertEqual((unknown["native_verdict"], unknown.get("unrecognised_native_message")), ("refused", True))
        allowed = REPLAY.original_error_expected()
        for expectation, cid in (("benign", "PMF-B27"), ("refusal", "PMF-A01")):
            record = {"case_id": cid, "expectation": expectation, **got, "dispatched": True,
                      "dispatch_witness": {"observed": True, "inotify_opens": 1},
                      "effect_witness": {"workspace_unchanged": True, "egress_bodies": 0}}
            with self.subTest(expectation=expectation):
                self.assertTrue(REPLAY.expectation_failures(record, allowed))

    def test_native_message_list_matches_the_rust_source(self):
        source = (ROOT / "crates/agentfw/src/mcp/admission/real_server.rs").read_text(encoding="utf-8")
        found = set(re.findall(r'error\(\s*&?[\w.]+,\s*-?\d+,\s*"([^"]+)"\s*,?\s*\)', source))
        # Fixed messages that reach error() through a constant or a selecting expression.
        found |= set(re.findall(r'const \w+_MESSAGE: &str =\s*"([^"]+)";', source))
        routed = {"MCP arguments violate the selected input profile",
                  "Unsupported MCP result withheld by the selected output profile"}
        for message in routed:
            self.assertIn(f'"{message}"', source)
        found |= routed
        admission = (ROOT / "crates/agentfw/src/mcp/admission.rs").read_text(encoding="utf-8")
        self.assertIn("error(&call.id, -32603, limit.message())", source)
        limit = admission[admission.index("impl DaemonSizeLimit"):]
        limit = limit[limit.index("fn message(self)"):limit.index("impl std::fmt::Display for DaemonSizeLimit")]
        found |= set(re.findall(r'=> "([^"]+)"', limit))
        self.assertEqual(found, set(REPLAY.NATIVE_ERROR_MESSAGES))
        self.assertIn('"Soup Wall could not classify the MCP invocation ({failure}); policy not reached"', admission)

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


def synthetic_replay(profile: str) -> dict:
    """SYNTHETIC per-case outcomes in the driver record shape (format tests only; never a Linux run)."""
    allowed = REPLAY.original_error_expected()
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
    return {"matrix_sha256": digest, "cases": records, "sessions": 1}


def throwaway(test_class, prefix: str):
    """The eval gate tests' Throwaway repository, plus the runtime drivers and replay module at their paths."""
    test_class.tests = load("sou97_gate_tests_for_replay", "eval/test_pilot_gate.py")
    test_class.tmp = tempfile.mkdtemp(prefix=prefix)
    test_class.addClassCleanup(test_class.tests.remove_tree, test_class.tmp)  # also runs if setup fails below
    test_class.tw = test_class.tests.Throwaway(Path(test_class.tmp),
                                               extra=(*GATE.RUNTIME_DRIVERS.values(), GATE.RUNTIME_REPLAY_MODULE))


def run_gate_runtime(tw, ref: str, files: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        args = []
        for profile, ev in files.items():
            path = Path(tmp, profile + ".json")
            path.write_text(json.dumps(ev), encoding="utf-8")
            args += ["--runtime-evidence", str(path)]
        subprocess.run([sys.executable, "-B", str(ROOT / "eval/tools/check_pilot_gate.py"), "--mode", "runtime",
                        "--manifest-file", str(tw.path), "--repo", str(tw.repo), "--ref", ref, *args,
                        "--out", str(Path(tmp, "g.json"))], capture_output=True, text=True, timeout=300)
        return json.loads(Path(tmp, "g.json").read_bytes())


class EvidenceFormat(unittest.TestCase):
    """Driver evidence must be the exact format the gate validates (compatibility, not qualification).

    The gate runs against a throwaway repository with its own recorded-evidence history (the eval gate
    tests' Throwaway), so this format check does not depend on how much history the checkout has.
    """

    @classmethod
    def setUpClass(cls):
        throwaway(cls, "sou97-evidence-format-")

    def build(self, mutate=None):
        def git(*args, binary=False):
            out = subprocess.run(["git", "-C", str(self.tw.repo), *args], capture_output=True, check=True).stdout
            return out if binary else out.decode().strip()
        head = self.tw.recorded
        tree = git("rev-parse", f"{head}^{{tree}}")
        # The committed bytes a Linux checkout of that commit runs (a Windows autocrlf working copy may differ).
        committed = {rel: hashlib.sha256(git("cat-file", "blob", f"{head}:{rel}", binary=True)).hexdigest()
                     for rel in (*GATE.RUNTIME_DRIVERS.values(), GATE.RUNTIME_REPLAY_MODULE)}
        classifier = REPLAY.classifier_identity(CANDIDATE, MANIFEST["candidate"]["sha256"])
        files = {}
        for profile in ("filesystem", "git"):
            ev = REPLAY.evidence(profile, status="pass", source={"commit": head, "tree": tree, "dirty": False},
                                 classifier=classifier, replay_result=synthetic_replay(profile),
                                 failures=[], calibration={"dispatch_witness_calibrated": True, "effect_witness_calibrated": True},
                                 identities={"agent_binary_sha256": "a" * 64,
                                             "driver_sha256": committed[GATE.RUNTIME_DRIVERS[profile]],
                                             "replay_module_sha256": committed[GATE.RUNTIME_REPLAY_MODULE]},
                                 runtime={"bwrap": "c" * 64},
                                 witnesses={"daemon_stopped": True, "workspace_unchanged": True, "egress_bodies": 0})
            ev["platform"] = "Linux-format-compatibility-test"  # this is a format test, not a Linux run
            if mutate:
                mutate(profile, ev)
            files[profile] = ev
        return run_gate_runtime(self.tw, head, files)

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


class DriverEvidenceProducers(unittest.TestCase):
    """The real SOU-62/SOU-68 source() and write_sou97_evidence() must emit what gate_version 2 binds.

    The unmodified producer functions run against a byte-exact checkout of the committed files (the
    Throwaway repository), as a Linux checkout of that commit would. Only the per-case outcomes and the
    build/install digests are synthetic stand-ins: no server runs and no Linux runtime result is claimed.
    """

    STUB = "d" * 64  # build/install products the gate records but cannot prove from source

    @classmethod
    def setUpClass(cls):
        throwaway(cls, "sou97-evidence-producers-")
        cls.drivers = {"filesystem": load("sou97_producer_sou62", "scripts/verify-sou62-real-mcp.py"),
                       "git": load("sou97_producer_sou68", "scripts/verify-sou68-real-mcp.py")}

    def blob_sha(self, rel: str) -> str:
        return hashlib.sha256(subprocess.run(["git", "-C", str(self.tw.repo), "cat-file", "blob", f"{self.tw.recorded}:{rel}"],
                                             capture_output=True, check=True).stdout).hexdigest()

    def produce(self, profile: str) -> dict:
        module = self.drivers[profile]
        source_module = module if profile == "filesystem" else module.BASE  # SOU-68 records BASE.source()
        out = Path(tempfile.mkdtemp(prefix="sou97-producer-out-"))
        self.addCleanup(self.tests.remove_tree, out)
        with mock.patch.object(module, "ROOT", self.tw.repo), mock.patch.object(source_module, "ROOT", self.tw.repo):
            report = {"status": "pass", "source_before": source_module.source(), "binary_sha256": self.STUB,
                      # run() records sha(Path(__file__)): the driver file of a checkout of that commit
                      "driver_sha256": module.sha(self.tw.repo / GATE.RUNTIME_DRIVERS[profile]), "error": None}
            stack = SimpleNamespace(root=out, receiver=SimpleNamespace(bodies=[]), daemon_stopped=True,
                                    classifier=module.REPLAY.classifier_identity(CANDIDATE, MANIFEST["candidate"]["sha256"]),
                                    sou97={"result": synthetic_replay(profile), "failures": [], "calibration": {
                                        "dispatch_witness_calibrated": True, "effect_witness_calibrated": True}})
            args = None
            if profile == "filesystem":
                report.update(installed_profile={"policy_sha256": self.STUB, "profile": {
                                  "runtimeSha256": self.STUB, "bwrapSha256": self.STUB, "packageTreeSha256": self.STUB}},
                              sandbox_test_binary_sha256=self.STUB, claude_sha256=self.STUB,
                              daemon_stopped=True, workspace_unchanged=True)
            else:
                stand_ins = {}
                for name in ("bwrap", "git_launcher", "sandbox_test_binary"):
                    stand_ins[name] = out / f"stand-in-{name}"
                    stand_ins[name].write_bytes(b"synthetic stand-in, never executed\n")
                args = SimpleNamespace(git_sha256=self.STUB, **stand_ins)
                report.update(installation={"profile": {"packageTreeSha256": self.STUB}}, repository_unchanged=True)
            module.write_sou97_evidence(stack, report, args)
        return json.loads((out / "sou97-runtime-evidence.json").read_bytes())

    def test_real_producers_emit_the_bound_source_and_identities(self):
        tree = subprocess.run(["git", "-C", str(self.tw.repo), "rev-parse", f"{self.tw.recorded}^{{tree}}"],
                              capture_output=True, text=True, check=True).stdout.strip()
        files = {}
        for profile in ("filesystem", "git"):
            with self.subTest(profile=profile):
                ev = self.produce(profile)
                self.assertEqual(ev["source"], {"commit": self.tw.recorded, "tree": tree, "dirty": False})
                ids = ev["identities"]
                self.assertEqual(ids["driver_sha256"], self.blob_sha(GATE.RUNTIME_DRIVERS[profile]))
                self.assertEqual(ids["replay_module_sha256"], self.blob_sha(GATE.RUNTIME_REPLAY_MODULE))
                self.assertEqual(ids["agent_binary_sha256"], self.STUB)
                self.assertTrue(ids["runtime"] and all(v == self.STUB or len(v) == 64 for v in ids["runtime"].values()))
                self.assertEqual(ev["platform"], platform.platform())  # the producer records the host it ran on
                ev["platform"] = "Linux-producer-compatibility-test"   # this host is not the Linux run
                files[profile] = ev
        result = run_gate_runtime(self.tw, self.tw.recorded, files)
        self.assertEqual(result["failures"], [])

    def test_a_dirty_checkout_is_recorded_and_refused(self):
        stray = self.tw.repo / "sou97-producer-stray.txt"
        stray.write_text("untracked\n", encoding="utf-8")
        self.addCleanup(stray.unlink, missing_ok=True)
        ev = self.produce("filesystem")
        self.assertIs(ev["source"]["dirty"], True)
        ev["platform"] = "Linux-producer-compatibility-test"
        stray.unlink()  # the Git evidence comes from the clean checkout: only the filesystem source is dirty
        git_ev = self.produce("git")
        git_ev["platform"] = "Linux-producer-compatibility-test"
        result = run_gate_runtime(self.tw, self.tw.recorded, {"filesystem": ev, "git": git_ev})
        self.assertIn("runtime_source", {f["code"] for f in result["failures"]})


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
