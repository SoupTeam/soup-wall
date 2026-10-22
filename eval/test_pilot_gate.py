"""SOU-97: the deterministic acceptance gate and its broken-candidate negative controls."""
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "eval/tools/check_pilot_gate.py"
MANIFEST = ROOT / "eval/pilot/sou97_gate_manifest_v1.json"
REAL = json.loads(MANIFEST.read_bytes())
MATRIX = "eval/fixtures/soup_pilot_readonly_matrix_v0.1.json"
CANDIDATE = REAL["candidate"]["path"]
# Everything a throwaway checkout needs to produce a pilot report (all committed and pinned).
TREE = sorted({*REAL["inputs"], CANDIDATE, *(b["path"] for b in REAL["baselines"].values())})


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def env():
    # Isolated from user/system git configuration (autocrlf, hooks, signing).
    keep = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR")}
    return {**keep, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(*args, cwd):
    return subprocess.run(["git", "-c", "user.name=sou97-test", "-c", "user.email=sou97-test@example.test", *args],
                          cwd=cwd, env=env(), capture_output=True, check=True).stdout


def committed(rel: str) -> bytes:
    return subprocess.run(["git", "-C", str(ROOT), "cat-file", "blob", f"HEAD:{rel}"], capture_output=True, check=True).stdout


def remove_tree(path):
    def writable(func, target, _):
        os.chmod(target, stat.S_IWRITE)
        func(target)
    if Path(path).exists():
        shutil.rmtree(path, onerror=writable)


def run_gate(*args, cwd=ROOT):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp, "gate.json")
        done = subprocess.run([sys.executable, "-B", str(GATE), *map(str, args), "--out", str(out)], cwd=cwd, env=env(),
                              capture_output=True, text=True, encoding="utf-8", timeout=900)
        result = json.loads(out.read_bytes()) if out.exists() else None
        raw = out.read_bytes() if out.exists() else None
    return done, result, raw


def codes(result):
    return {f["code"] for f in result["failures"]}


class Throwaway:
    """A git repository from committed bytes, optionally with a broken candidate, plus recorded reports."""

    def __init__(self, base: Path, candidate: bytes | None = None, calls=3, spawns=1, matrix_edit=None, report_edit=None,
                 extra=()):
        self.repo = base / "repo"
        for rel in (*TREE, *extra):
            target = self.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(committed(rel))
        if candidate is not None:
            (self.repo / CANDIDATE).write_bytes(candidate)
        git("init", "-q", cwd=self.repo)
        git("config", "core.autocrlf", "false", cwd=self.repo)
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "source", cwd=self.repo)
        self.source = git("rev-parse", "HEAD", cwd=self.repo).decode().strip()
        self.runs = {}
        outside = base / "reports"  # written outside the checkout, as the real evidence was, then recorded
        for run in ("run1", "run2"):
            rel = f"eval/evidence/ctl/{run}/pilot_report.json"
            done = subprocess.run([sys.executable, "-B", "eval/eval_runner.py", MATRIX, "--pilot-report",
                                   "--pilot-candidate", CANDIDATE,
                                   "--pilot-baseline", f"filesystem={REAL['baselines']['filesystem']['path']}",
                                   "--pilot-baseline", f"git={REAL['baselines']['git']['path']}",
                                   "--latency-calls", str(calls), "--latency-spawns", str(spawns),
                                   "--out-dir", str(outside / run)],
                                  cwd=self.repo, env=env(), capture_output=True, text=True, encoding="utf-8", timeout=900)
            assert done.returncode == 0, done.stderr
        for run in ("run1", "run2"):
            rel = f"eval/evidence/ctl/{run}/pilot_report.json"
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            data = (outside / run / "pilot_report.json").read_bytes()
            if report_edit is not None:
                report = json.loads(data)
                report_edit(report)
                data = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
            (self.repo / rel).write_bytes(data)
            self.runs[rel] = sha((self.repo / rel).read_bytes())
        if matrix_edit is not None:
            matrix_edit(self.repo / MATRIX)
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "evidence", cwd=self.repo)
        self.recorded = git("rev-parse", "HEAD", cwd=self.repo).decode().strip()
        cand = (self.repo / CANDIDATE).read_bytes()
        self.manifest = copy.deepcopy(REAL)
        self.manifest["candidate"]["sha256"] = sha(cand)
        self.manifest["superseded_candidates"] = {}
        self.manifest["evidence"] = {"source_commit": self.source, "recorded_in": self.recorded,
                                     "reports": [{"fixture": MATRIX, "runs": self.runs}]}
        self.manifest["measurement"].update(latency_calls=calls, latency_spawns=spawns)
        self.path = base / "manifest.json"
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")

    def gate(self, mode="offline", *extra):
        return run_gate("--mode", mode, "--manifest-file", self.path, "--repo", self.repo, "--ref", self.recorded, *extra)


def broken(transform) -> bytes:
    source = committed(CANDIDATE).decode("utf-8")
    out = transform(source)
    assert out != source
    return out.encode("utf-8")


def schema_bypass(source: str) -> str:
    # The exact-schema requirement is removed: a drifted schema is proven read like the original.
    old = ("    if not isinstance(declared, dict) or hashlib.sha256(_canon(declared).encode()).hexdigest() != FS_READ_SCHEMAS[name]:\n"
           "        return False\n    if pinned is not None and _canon(pinned) != _canon(declared):\n        return False\n")
    assert source.count(old) == 1
    return source.replace(old, "")


def drop_write(source: str) -> str:
    # A new risky miss: write is silently replaced by read.
    hook = 'if __name__ == "__main__":'
    patch = ("_sound_classify = classify\n\n\ndef classify(event):\n    result = _sound_classify(event)\n"
             "    if 'write' in result.get('actions', []):\n"
             "        result['actions'] = [a for a in result['actions'] if a != 'write'] or ['read']\n"
             "    return result\n\n\n")
    assert source.count(hook) == 1
    return source.replace(hook, patch + hook)


class RecordedEvidence(unittest.TestCase):
    """The committed manifest and evidence, read as committed blobs of HEAD."""

    def test_offline_qualifies_but_is_never_acceptance_and_is_deterministic(self):
        first, result, raw1 = run_gate("--mode", "offline", "--manifest-file", MANIFEST, "--repo", ROOT, "--ref", "HEAD")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(result["verdict"], "OFFLINE_QUALIFIED")
        self.assertIs(result["pilot_acceptance"], False)
        self.assertIn("not pilot acceptance", result["statement"])
        self.assertEqual(result["failures"], [])
        fs = result["observed"]["offline_evidence"][MATRIX]["classification"]["filesystem"]
        self.assertEqual(fs["inherited"]["known_risk_misses"], ["PMF-U05"])
        self.assertEqual(fs["inherited"]["expected_d06_not_met"], ["PMF-V01", "PMF-V02", "PMF-V03"])
        self.assertEqual(fs["inherited"]["pending_safety_violations"], ["PMF-A01"])
        self.assertEqual(fs["denominators"]["supported_benign"], 46)
        git_profile = result["observed"]["offline_evidence"][MATRIX]["classification"]["git"]
        self.assertEqual(git_profile["inherited"]["known_risk_misses"], ["PMG-U03", "PMG-U04"])
        _, _, raw2 = run_gate("--mode", "offline", "--manifest-file", MANIFEST, "--repo", ROOT, "--ref", "HEAD")
        self.assertEqual(raw1, raw2)

    def test_runtime_mode_fails_without_runtime_evidence(self):
        done, result, _ = run_gate("--mode", "runtime", "--manifest-file", MANIFEST, "--repo", ROOT, "--ref", "HEAD")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(sorted(f["detail"] for f in result["failures"] if f["code"] == "runtime_evidence_missing"),
                         ["filesystem", "git"])

    def test_wrong_or_stale_candidate_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            for digest, expected in ((REAL["superseded_candidates"] and next(iter(REAL["superseded_candidates"])),
                                      {"stale_candidate", "input_modified", "report_classifier_identity"}),
                                     ("0" * 64, {"input_modified", "report_classifier_identity"})):
                manifest = copy.deepcopy(REAL)
                manifest["candidate"]["sha256"] = digest
                path = Path(tmp, "m.json")
                path.write_text(json.dumps(manifest), encoding="utf-8")
                done, result, _ = run_gate("--mode", "offline", "--manifest-file", path, "--repo", ROOT, "--ref", "HEAD")
                self.assertEqual(done.returncode, 1)
                self.assertTrue(expected <= codes(result), codes(result))

    def test_unacknowledged_inherited_limitation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = copy.deepcopy(REAL)
            del manifest["acknowledged_inherited"]["known_risk_misses"]["PMF-U05"]
            path = Path(tmp, "m.json")
            path.write_text(json.dumps(manifest), encoding="utf-8")
            done, result, _ = run_gate("--mode", "offline", "--manifest-file", path, "--repo", ROOT, "--ref", "HEAD")
            self.assertEqual(done.returncode, 1)
            self.assertEqual(codes(result), {"unacknowledged_inherited"})

    def test_modified_inputs_and_evidence_in_a_directory_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = TREE + [r for e in REAL["evidence"]["reports"] for r in e["runs"]] + ["eval/pilot/sou97_gate_manifest_v1.json"]
            for rel in files:
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(committed(rel) if rel != "eval/pilot/sou97_gate_manifest_v1.json" else MANIFEST.read_bytes())
            matrix = root / MATRIX
            matrix.write_bytes(matrix.read_bytes().replace(b'"move_file"', b'"move_filf"', 1))
            report = root / next(iter(REAL["evidence"]["reports"][1]["runs"]))
            report.write_bytes(report.read_bytes() + b"\n")
            done, result, _ = run_gate("--mode", "offline", "--manifest-file", MANIFEST, "--root", root)
            self.assertEqual(done.returncode, 1)
            found = codes(result)
            self.assertTrue({"input_modified", "fixture_modified", "evidence_modified", "lineage_unverified"} <= found, found)
            self.assertIn(MATRIX, json.dumps([f for f in result["failures"] if f["code"] == "input_modified"]))


class BrokenCandidates(unittest.TestCase):
    """Each control is a self-consistent throwaway repository: only the planted defect may fail the gate."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        remove_tree(self.tmp)

    def test_control_baseline_qualifies(self):
        # The harness itself is sound: the real candidate in a throwaway repository qualifies offline.
        done, result, _ = Throwaway(self.tmp).gate()
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertEqual(result["failures"], [])

    def test_schema_bypass_candidate_is_rejected(self):
        done, result, _ = Throwaway(self.tmp, broken(schema_bypass)).gate()
        self.assertEqual(done.returncode, 1)
        self.assertEqual(codes(result), {"new_pending_safety_violation"})
        detail = [f["detail"] for f in result["failures"]][0]
        # PMF-S01 (drifted title) is now proven read. PMF-S02 also carries an undeclared argument, which the
        # still-intact exact-keys check refuses, so it keeps its baseline result.
        self.assertEqual(detail["cases"], ["PMF-S01"])

    def test_new_risky_miss_candidate_is_rejected(self):
        done, result, _ = Throwaway(self.tmp, broken(drop_write)).gate()
        self.assertEqual(done.returncode, 1)
        found = codes(result)
        self.assertIn("new_known_risk_miss", found)
        self.assertIn("new_classification_failure", found)
        missed = {c for f in result["failures"] if f["code"] == "new_known_risk_miss" for c in f["detail"]["cases"]}
        self.assertTrue({"PMF-U01", "PMF-U03", "PMG-U02"} <= missed, missed)

    def test_failed_supported_benign_candidate_is_rejected(self):
        # The frozen baseline as "candidate": no regression against itself, but supported reads still fail.
        done, result, _ = Throwaway(self.tmp, committed(REAL["baselines"]["filesystem"]["path"])).gate()
        self.assertEqual(done.returncode, 1)
        found = codes(result)
        self.assertIn("failed_supported_benign", found)
        self.assertNotIn("new_known_risk_miss", found)

    def test_missing_measurements_are_rejected(self):
        ctl = Throwaway(self.tmp, calls=0, spawns=0)
        ctl.manifest["measurement"].update(latency_calls=3, latency_spawns=1)
        ctl.write()
        done, result, _ = ctl.gate()
        self.assertEqual(done.returncode, 1)
        self.assertEqual(codes(result), {"measurement_parameters", "measurement_missing"})

    def test_malformed_measurements_fail_in_a_controlled_way(self):
        def lat(report):
            return report["profiles"]["filesystem"]["after"]["latency"]
        edits = {
            "measurement_malformed": lambda r: lat(r)["warm_process_round_trip"].update(attempts="3"),
            "measurement_deadline": lambda r: lat(r)["cold_process_per_call"].update(p95_ms="fast"),
            "measurement_missing": lambda r: r["profiles"]["git"]["before"].update(latency=["not", "a", "mapping"]),
            "report_malformed": lambda r: r["profiles"]["filesystem"]["after"].update(cases="not a list"),
        }
        for code, edit in edits.items():
            with self.subTest(code=code):
                base = self.tmp / code
                base.mkdir()
                done, result, _ = Throwaway(base, report_edit=edit).gate()
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertIsNotNone(result, "the gate must write a FAIL result, not crash")
                self.assertNotIn("Traceback", done.stderr)
                self.assertEqual(result["verdict"], "FAIL")
                self.assertIn(code, codes(result))
        whole = self.tmp / "profiles"
        whole.mkdir()
        done, result, _ = Throwaway(whole, report_edit=lambda r: r.update(profiles=[])).gate()
        self.assertEqual((done.returncode, result["verdict"]), (1, "FAIL"))
        self.assertNotIn("Traceback", done.stderr)

    def test_matrix_changed_after_evidence_is_rejected(self):
        def relabel(path):
            data = json.loads(path.read_bytes())
            data["cases"][0]["expected"]["actions"] = ["write"]
            path.write_bytes((json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        done, result, _ = Throwaway(self.tmp, matrix_edit=relabel).gate()
        self.assertEqual(done.returncode, 1)
        found = codes(result)
        self.assertTrue({"input_modified", "fixture_modified", "report_expectation_mismatch"} <= found, found)


RUNTIME_DRIVERS = {"filesystem": "scripts/verify-sou62-real-mcp.py", "git": "scripts/verify-sou68-real-mcp.py"}


def rev(spec: str, repo=ROOT) -> str:
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", spec], capture_output=True, text=True,
                          check=True).stdout.strip()


def blob_sha(commit: str, rel: str, repo=ROOT) -> str:
    return sha(subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{commit}:{rel}"], capture_output=True,
                              check=True).stdout)


def runtime_evidence(profile: str, commit: str, mutate=None, repo=ROOT) -> dict:
    """SYNTHETIC TEST INPUT for the validator only; it is not evidence and is never committed."""
    pins = {**REAL["inputs"]}
    prof_dir = "filesystem-readonly-v1" if profile == "filesystem" else "git-readonly-v1"
    matrix = json.loads(committed(MATRIX))
    cases = []
    for c in matrix["cases"]:
        eo = c["evaluator_only"]
        if eo["profile"] != profile or eo["profile_admission"] == "not_runtime_reachable":
            continue
        allowed = eo["profile_admission"] == "admit" and eo["expected_native"] == "allow"
        original_error = c["id"] in REAL["runtime"].get("original_error_expected", {})
        if allowed or eo["expected_native"] == "profile_refusal":
            cases.append({"case_id": c["id"], "native_verdict": "allow" if allowed else "refused",
                          "refusal_code": None if allowed else "profile_refusal", "dispatched": allowed,
                          "arguments_sha256": {"sent": hashlib.sha256(json.dumps(c["input"]["raw_arguments"], sort_keys=True,
                                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()},
                          "result_kind": ("original_error" if original_error else "original_result") if allowed else "native_error",
                          "dispatch_witness": {"kind": "synthetic", "observed": allowed},
                          "useful_result": (allowed and not original_error) if allowed else None,
                          "effect_witness": {"kind": "synthetic", "workspace_unchanged": True, "egress_bodies": 0}})
    ev = {"format": "sou97-runtime-evidence/1", "profile": profile, "status": "pass", "platform": "Linux-synthetic",
          "source": {"commit": commit, "tree": rev(f"{commit}^{{tree}}", repo), "dirty": False}, "matrix_sha256": pins[MATRIX],
          "identities": {"classifier_sha256": REAL["candidate"]["sha256"], "classifier_revision": REAL["candidate"]["revision"],
                         "policy_sha256": pins[f"profiles/mcp/{prof_dir}/policy.yaml"],
                         "tools_list_sha256": pins[f"profiles/mcp/{prof_dir}/upstream-tools-list.json"],
                         "upstream_identity_sha256": pins[f"profiles/mcp/{prof_dir}/upstream-identity.json"],
                         "agent_binary_sha256": "a" * 64,
                         "driver_sha256": blob_sha(commit, RUNTIME_DRIVERS[profile], repo),
                         "replay_module_sha256": blob_sha(commit, "scripts/sou97_runtime_replay.py", repo),
                         "runtime": {"bwrap": "c" * 64}},
          "witnesses": {"dispatch_witness_calibrated": True, "effect_witness_calibrated": True, "daemon_stopped": True,
                        "workspace_unchanged": True, "egress_bodies": 0},
          "cases": cases}
    if mutate:
        mutate(ev)
    return ev


class RuntimeValidator(unittest.TestCase):
    """Validator logic only, on synthetic inputs; no runtime evidence exists for SOU-97 yet."""

    def gate(self, fs_mutate=None, git_mutate=None, profiles=("filesystem", "git")):
        head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        with tempfile.TemporaryDirectory() as tmp:
            args = []
            for profile, mutate in (("filesystem", fs_mutate), ("git", git_mutate)):
                if profile in profiles:
                    path = Path(tmp, f"{profile}.json")
                    path.write_text(json.dumps(runtime_evidence(profile, head, mutate)), encoding="utf-8")
                    args += ["--runtime-evidence", path]
            return run_gate("--mode", "runtime", "--manifest-file", MANIFEST, "--repo", ROOT, "--ref", "HEAD", *args)

    def test_complete_synthetic_evidence_satisfies_the_validator(self):
        done, result, _ = self.gate()
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertEqual(result["verdict"], "RUNTIME_QUALIFIED")
        self.assertEqual(result["observed"]["runtime"]["filesystem"]["supported_benign"], 46)

    def test_failed_expected_refusal_is_rejected(self):
        def dispatched(ev):
            case = next(c for c in ev["cases"] if c["case_id"] == "PMF-U01")
            case.update(dispatched=True, dispatch_witness={"kind": "synthetic", "observed": True})
        done, result, _ = self.gate(fs_mutate=dispatched)
        self.assertEqual(done.returncode, 1)
        self.assertEqual(codes(result), {"runtime_refusal_failed"})

    def test_missing_or_wrong_runtime_evidence_is_rejected(self):
        cases = {
            "runtime_evidence_missing": dict(profiles=("filesystem",)),
            "runtime_benign_missing": dict(fs_mutate=lambda ev: ev["cases"].pop(0)),
            "runtime_benign_failed": dict(git_mutate=lambda ev: ev["cases"][0].update(native_verdict="ask")),
            "runtime_identity": dict(fs_mutate=lambda ev: ev["identities"].update(classifier_sha256="0" * 64)),
            "runtime_platform": dict(git_mutate=lambda ev: ev.update(platform="Windows-11")),
            "runtime_witness": dict(fs_mutate=lambda ev: ev["witnesses"].update(egress_bodies=1)),
            "runtime_not_passed": dict(fs_mutate=lambda ev: ev.update(status="skipped")),
            "runtime_source_input": dict(fs_mutate=lambda ev: ev["source"].update(commit="77a3b611ba537f8ae33b7a0a981a59248503ba36")),
        }
        for code, kwargs in cases.items():
            with self.subTest(code=code):
                done, result, _ = self.gate(**kwargs)
                self.assertEqual(done.returncode, 1)
                self.assertIn(code, codes(result))


class RuntimeSourceBinding(unittest.TestCase):
    """D1: runtime evidence must share one verified source identity, and it must be the evaluated commit.

    Runs in a throwaway repository built from committed public bytes (Throwaway), so that commits can be
    added after the "evidence" without touching this checkout or any other repository.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sou97-binding-")
        cls.tw = Throwaway(Path(cls.tmp), extra=(*RUNTIME_DRIVERS.values(), "scripts/sou97_runtime_replay.py"))
        cls.head = cls.tw.recorded
        repo = cls.tw.repo
        cls.runtime_change = cls.commit_file("crates/agentfw/src/sou97_binding_control.rs", b"// changed after evidence\n")
        git("reset", "-q", "--hard", cls.head, cwd=repo)
        cls.docs_change = cls.commit_file("docs/sou97-binding-control.md", b"documentation only\n")
        git("reset", "-q", "--hard", cls.head, cwd=repo)
        cls.driver_change = cls.commit_file(RUNTIME_DRIVERS["git"], committed(RUNTIME_DRIVERS["git"]) + b"# changed\n")
        git("reset", "-q", "--hard", cls.head, cwd=repo)
        # Same tree as the evaluated commit but no shared history: not this source, whatever its bytes.
        cls.unrelated = git("commit-tree", cls.head + "^{tree}", "-m", "unrelated", cwd=repo).decode().strip()

    @classmethod
    def tearDownClass(cls):
        remove_tree(cls.tmp)

    @classmethod
    def commit_file(cls, rel: str, data: bytes) -> str:
        target = cls.tw.repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        git("add", "-A", cwd=cls.tw.repo)
        git("commit", "-q", "-m", "after evidence: " + rel, cwd=cls.tw.repo)
        return git("rev-parse", "HEAD", cwd=cls.tw.repo).decode().strip()

    def gate(self, fs=None, git_=None, ref=None, fs_mutate=None, git_mutate=None):
        with tempfile.TemporaryDirectory() as tmp:
            args = []
            for profile, commit, mutate in (("filesystem", fs or self.head, fs_mutate), ("git", git_ or self.head, git_mutate)):
                path = Path(tmp, f"{profile}.json")
                path.write_text(json.dumps(runtime_evidence(profile, commit, mutate, repo=self.tw.repo)), encoding="utf-8")
                args += ["--runtime-evidence", path]
            return run_gate("--mode", "runtime", "--manifest-file", self.tw.path, "--repo", self.tw.repo,
                            "--ref", ref or self.head, *args)

    def assertRejected(self, result, *expected):
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(set(expected) <= codes(result), codes(result))

    def test_control_exact_head_evidence_qualifies(self):
        for evaluated in (self.head, self.runtime_change):
            with self.subTest(evaluated=evaluated):
                done, result, _ = self.gate(fs=evaluated, git_=evaluated, ref=evaluated)
                self.assertEqual((done.returncode, result["verdict"]), (0, "RUNTIME_QUALIFIED"), result["failures"])

    def test_profiles_from_different_commits_are_rejected(self):
        done, result, _ = self.gate(git_=self.tw.source)
        self.assertEqual(done.returncode, 1)
        self.assertRejected(result, "runtime_source_mismatch", "runtime_source_not_evaluated")
        mismatch = next(f["detail"] for f in result["failures"] if f["code"] == "runtime_source_mismatch")
        self.assertEqual(mismatch, {"filesystem": self.head, "git": self.tw.source})

    def test_stale_or_unrelated_commit_is_rejected(self):
        # Stale: the previous gate accepted an ancestor holding the same pinned inputs.
        done, result, _ = self.gate(fs=self.tw.source, git_=self.tw.source)
        self.assertEqual(done.returncode, 1)
        self.assertRejected(result, "runtime_source_not_evaluated", "runtime_driver_identity")
        self.assertNotIn("runtime_source_mismatch", codes(result))
        _, result, _ = self.gate(fs=self.unrelated, git_=self.unrelated)
        self.assertRejected(result, "runtime_source_not_evaluated", "runtime_source_lineage")
        _, result, _ = self.gate(fs_mutate=lambda ev: ev["source"].update(commit="0123456789abcdef0123456789abcdef01234567"))
        self.assertRejected(result, "runtime_source_unknown", "runtime_source_mismatch", "runtime_driver_identity")

    def test_source_changed_after_evidence_is_rejected(self):
        # Exact head: a runtime change, a driver change and even a documentation-only successor all need new runs.
        for evaluated in (self.runtime_change, self.driver_change, self.docs_change):
            with self.subTest(evaluated=evaluated):
                done, result, _ = self.gate(ref=evaluated)
                self.assertEqual(done.returncode, 1)
                self.assertRejected(result, "runtime_source_not_evaluated", "runtime_driver_identity")

    def test_driver_identities_must_be_the_committed_bytes(self):
        mutations = {
            "placeholder driver digest": lambda ev: ev["identities"].update(driver_sha256="b" * 64),
            "other profile's driver": lambda ev: ev["identities"].update(
                driver_sha256=blob_sha(self.head, RUNTIME_DRIVERS["git"], self.tw.repo)),
            "placeholder replay module": lambda ev: ev["identities"].update(replay_module_sha256="c" * 64),
            "missing replay module": lambda ev: ev["identities"].pop("replay_module_sha256"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label):
                done, result, _ = self.gate(fs_mutate=mutate)
                self.assertEqual(done.returncode, 1)
                self.assertEqual(codes(result), {"runtime_driver_identity"})
        # A driver changed after the run: evidence of the old bytes against the new commit.
        _, result, _ = self.gate(ref=self.driver_change, fs=self.driver_change, git_=self.driver_change,
                                 git_mutate=lambda ev: ev["identities"].update(
                                     driver_sha256=blob_sha(self.head, RUNTIME_DRIVERS["git"], self.tw.repo)))
        self.assertEqual(codes(result), {"runtime_driver_identity"})

    def test_missing_or_invalid_provenance_is_rejected(self):
        other_tree = rev(self.tw.source + "^{tree}", self.tw.repo)
        mutations = {
            "runtime_source": [lambda ev: ev.pop("source"), lambda ev: ev.update(source="HEAD"),
                               lambda ev: ev["source"].pop("tree"), lambda ev: ev["source"].update(dirty=True),
                               lambda ev: ev["source"].pop("dirty"), lambda ev: ev["source"].update(commit="77a3b61")],
            "runtime_source_tree": [lambda ev: ev["source"].update(tree=other_tree)],
        }
        for code, variants in mutations.items():
            for index, mutate in enumerate(variants):
                with self.subTest(code=code, variant=index):
                    done, result, _ = self.gate(git_mutate=mutate)
                    self.assertEqual(done.returncode, 1)
                    self.assertRejected(result, code)


if __name__ == "__main__":
    unittest.main()
