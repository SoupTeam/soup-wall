"""SOU-97: the additive --pilot-report mode of eval_runner.py (the default mode must stay unchanged)."""
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
RUNNER = ROOT / "eval" / "eval_runner.py"
MATRIX = ROOT / "eval/fixtures/soup_pilot_readonly_matrix_v0.1.json"
CANDIDATE = ROOT / "rule_baseline/pilot_readonly_v1/rule_baseline.py"
FROZEN = ROOT / "rule_baseline/rule_baseline.py"
GIT_V1 = ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"
CANDIDATE_SHA256 = "ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30"


def run(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-B", str(RUNNER), *map(str, args)], cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", timeout=600)


def pilot(out, candidate=CANDIDATE, *extra, calls=3, spawns=1):
    return run(MATRIX, "--pilot-report", "--pilot-candidate", candidate, "--pilot-baseline", f"filesystem={FROZEN}",
               "--pilot-baseline", f"git={GIT_V1}", "--latency-calls", calls, "--latency-spawns", spawns,
               "--out-dir", out, *extra)


class DefaultModeUnchanged(unittest.TestCase):
    def test_scoring_matches_the_increment_1_evidence(self):
        # The evidence was produced by the previous runner; identical cases and summary prove the default
        # scoring contract is unchanged (meta differs only by the runner's own digest).
        with tempfile.TemporaryDirectory() as tmp:
            done = run("eval/fixtures/soup_task1_evaluation_cases_v0.4.json", "--classifier-path", "rule_baseline",
                       "--out-dir", tmp)
            self.assertEqual(done.returncode, 0, done.stderr)
            new = json.loads(Path(tmp, "results.json").read_text(encoding="utf-8"))
        old = json.loads((ROOT / "eval/evidence/sou97/baseline/frozen/public_v0.4/results.json").read_text(encoding="utf-8"))
        self.assertEqual(new["cases"], old["cases"])
        self.assertEqual(new["summary"], old["summary"])
        self.assertEqual(sorted(new["meta"]), sorted(old["meta"]))


class PilotReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.done = pilot(cls.tmp)
        path = Path(cls.tmp, "pilot_report.json")
        cls.rep = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_report_is_written_with_identities_and_no_runtime_claims(self):
        self.assertEqual(self.done.returncode, 0, self.done.stderr)
        rep = self.rep
        self.assertEqual(rep["classifiers"]["candidate"]["sha256"], CANDIDATE_SHA256)
        self.assertEqual(rep["classifiers"]["candidate"]["revision"], "pilot_readonly_v1.2")
        self.assertEqual(rep["native_policy"]["status"], "not_measured")
        self.assertEqual(rep["execution_effects"]["status"], "not_measured")
        self.assertTrue(rep["drift_check"].startswith("passed"))
        self.assertEqual(len(rep["identities"]), 8)
        self.assertTrue(Path(self.tmp, "pilot_report.md").read_text(encoding="utf-8").startswith("# SOU-97 pilot"))

    def test_metrics_and_retained_known_issues(self):
        fs, git = self.rep["profiles"]["filesystem"], self.rep["profiles"]["git"]
        for entry in (fs, git):
            self.assertEqual(entry["comparison"]["new_known_risk_misses"], [])
            self.assertEqual(entry["comparison"]["new_unexpected_technical_failures"], [])
            self.assertEqual(entry["comparison"]["new_supported_benign_false_interruptions"], [])
            self.assertEqual(entry["comparison"]["newly_failing"], [])
        self.assertEqual([x["id"] for x in fs["after"]["metrics"]["known_risk_misses"]], ["PMF-U05"])
        self.assertEqual([x["id"] for x in git["after"]["metrics"]["known_risk_misses"]], ["PMG-U03", "PMG-U04"])
        self.assertEqual(len(fs["before"]["metrics"]["supported_benign"]["false_interruptions"]), 12)
        self.assertEqual(fs["after"]["metrics"]["supported_benign"]["false_interruptions"], [])
        d06 = [x["id"] for x in fs["after"]["metrics"]["technical_failures"]["expected_d06"] if x["outcome"] != "pass"]
        self.assertEqual(d06, ["PMF-V01", "PMF-V02", "PMF-V03"])
        read = fs["after"]["metrics"]["per_action"]["read"]
        self.assertEqual(read["tp"] + read["fn"], read["known_positive"])
        self.assertEqual(fs["after"]["metrics"]["mixed_action"]["cases"], 1)

    def test_latency_keeps_attempts_failures_and_timeouts(self):
        for profile in ("filesystem", "git"):
            for role in ("before", "after"):
                lat = self.rep["profiles"][profile][role]["latency"]
                for mode, attempts in (("in_process_call", 3), ("warm_process_round_trip", 3), ("cold_process_per_call", 1)):
                    self.assertEqual(lat[mode]["attempts"], attempts)
                    self.assertEqual(lat[mode]["valid"] + lat[mode]["failed"] + lat[mode]["timed_out"], attempts)
        self.assertEqual(self.rep["latency_parameters"]["bridge_inner_timeout_ms"], 1500)


class FailClosed(unittest.TestCase):
    def test_expected_digest_mismatch_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = pilot(tmp, CANDIDATE, "--pilot-expect", "candidate=" + "0" * 64, calls=0, spawns=0)
            self.assertEqual(done.returncode, 4, done.stderr)
            self.assertIn("differs from expected", done.stderr)
            self.assertFalse(Path(tmp, "pilot_report.json").exists())

    def test_source_drift_during_the_run_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            drifting = Path(tmp, "drifting.py")
            # Executing the snapshot rewrites the file on disk: the run must refuse, not report.
            drifting.write_bytes(CANDIDATE.read_bytes() + b"\nopen(__file__, 'ab').write(b'# drift')\n")
            out = Path(tmp, "out")
            done = pilot(out, drifting, calls=0, spawns=0)
            self.assertEqual(done.returncode, 4, done.stderr)
            self.assertIn("changed while it was being measured", done.stderr)
            self.assertFalse(Path(out, "pilot_report.json").exists())

    def test_missing_classifier_and_usage_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(pilot(tmp, Path(tmp, "absent.py"), calls=0, spawns=0).returncode, 4)
            self.assertEqual(run(MATRIX, "--pilot-report", "--pilot-candidate", CANDIDATE, "--out-dir", tmp).returncode, 3)
            self.assertEqual(pilot(tmp, CANDIDATE, "--pilot-expect", "candidate=xyz", calls=0, spawns=0).returncode, 3)
            v04 = ROOT / "eval/fixtures/soup_task1_evaluation_cases_v0.4.json"
            done = run(v04, "--pilot-report", "--pilot-candidate", CANDIDATE, "--pilot-baseline", f"filesystem={FROZEN}",
                       "--pilot-baseline", f"git={GIT_V1}", "--out-dir", tmp)
            self.assertEqual(done.returncode, 3)
            self.assertIn("evaluator_only.profile", done.stderr)


PROVENANCE_INPUTS = ("eval/eval_runner.py", "rule_baseline/evaluate_dev.py", "rule_baseline/rule_baseline.py",
                     "rule_baseline/git_readonly_v1/rule_baseline.py", "rule_baseline/pilot_readonly_v1/rule_baseline.py",
                     "eval/fixtures/soup_pilot_readonly_matrix_v0.1.json",
                     "profiles/mcp/filesystem-readonly-v1/policy.yaml",
                     "profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json",
                     "profiles/mcp/filesystem-readonly-v1/upstream-identity.json",
                     "profiles/mcp/git-readonly-v1/policy.yaml",
                     "profiles/mcp/git-readonly-v1/upstream-tools-list.json",
                     "profiles/mcp/git-readonly-v1/upstream-identity.json")


def remove_tree(path):
    """Remove a test directory, including Git's read-only object files on Windows; never fail silently."""
    def writable(func, target, _):
        os.chmod(target, stat.S_IWRITE)
        func(target)
    if Path(path).exists():
        shutil.rmtree(path, onerror=writable)


def isolated_git(*args, cwd):
    # No user/system configuration: no autocrlf, hooks or signing settings leak into the throwaway repository.
    env = {**{k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP")},
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", "-c", "user.name=sou97-test", "-c", "user.email=sou97-test@example.test",
                           "-c", "core.autocrlf=false", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True)


class Provenance(unittest.TestCase):
    """A throwaway repository built from the current source bytes: checkout and verified-export modes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.repo = Path(cls.tmp, "repo")
        for rel in PROVENANCE_INPUTS:
            target = cls.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / rel).read_bytes())  # this throwaway commit owns whatever bytes it gets
        isolated_git("init", "-q", cwd=cls.repo)
        isolated_git("add", "-A", cwd=cls.repo)
        isolated_git("commit", "-q", "-m", "fixture", cwd=cls.repo)
        cls.commit = isolated_git("rev-parse", "HEAD", cwd=cls.repo).stdout.strip()

    @classmethod
    def tearDownClass(cls):
        remove_tree(cls.tmp)

    def report(self, root, out, *extra):
        done = subprocess.run([sys.executable, "-B", str(root / "eval/eval_runner.py"), "eval/fixtures/soup_pilot_readonly_matrix_v0.1.json",
                               "--pilot-report", "--pilot-candidate", "rule_baseline/pilot_readonly_v1/rule_baseline.py",
                               "--pilot-baseline", "filesystem=rule_baseline/rule_baseline.py",
                               "--pilot-baseline", "git=rule_baseline/git_readonly_v1/rule_baseline.py",
                               "--latency-calls", "0", "--latency-spawns", "0", "--out-dir", str(out), *extra],
                              cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=600)
        path = Path(out, "pilot_report.json")
        return done, (json.loads(path.read_text(encoding="utf-8")) if path.exists() else None)

    def test_clean_checkout_records_the_real_commit(self):
        done, rep = self.report(self.repo, Path(self.tmp, "clean"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(rep["git"], {"head": self.commit, "tracked_changes": False, "untracked_files": False})
        prov = rep["provenance"]
        self.assertEqual((prov["mode"], prov["source_commit"], prov["all_match"]), ("checkout", self.commit, True))
        self.assertEqual(set(prov["files"]), set(PROVENANCE_INPUTS))

    def test_dirty_checkout_is_recorded_not_normalized(self):
        policy = self.repo / "profiles/mcp/git-readonly-v1/policy.yaml"
        original = policy.read_bytes()
        try:
            policy.write_bytes(original + b"# local edit\n")
            done, rep = self.report(self.repo, Path(self.tmp, "dirty"))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue(rep["git"]["tracked_changes"])
            row = rep["provenance"]["files"]["profiles/mcp/git-readonly-v1/policy.yaml"]
            self.assertFalse(row["matches_commit"])
            self.assertNotEqual(row["sha256"], row["committed_sha256"])
            self.assertFalse(rep["provenance"]["all_match"])
        finally:
            policy.write_bytes(original)

    def export(self, name):
        root = Path(self.tmp, name)
        for rel in PROVENANCE_INPUTS:
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subprocess.run(["git", "-C", str(self.repo), "cat-file", "blob", f"{self.commit}:{rel}"],
                                              capture_output=True, check=True).stdout)
        return root

    def test_verified_export_keeps_head_null(self):
        root = self.export("export-ok")
        done, rep = self.report(root, Path(self.tmp, "export-ok-out"), "--source-commit", self.commit, "--source-repo", str(self.repo))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIsNone(rep["git"]["head"])
        self.assertEqual((rep["provenance"]["mode"], rep["provenance"]["source_commit"], rep["provenance"]["all_match"]),
                         ("exported_bytes_verified_against_commit", self.commit, True))
        done, rep = self.report(root, Path(self.tmp, "export-unverified-out"))
        self.assertEqual((rep["provenance"]["mode"], rep["provenance"]["source_commit"]), ("unverified", None))

    def test_tampered_export_or_unknown_commit_writes_nothing(self):
        root = self.export("export-bad")
        candidate = root / "rule_baseline/pilot_readonly_v1/rule_baseline.py"
        candidate.write_bytes(candidate.read_bytes() + b"\n# tampered\n")
        out = Path(self.tmp, "export-bad-out")
        done, rep = self.report(root, out, "--source-commit", self.commit, "--source-repo", str(self.repo))
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIn("rule_baseline/pilot_readonly_v1/rule_baseline.py", done.stderr)
        self.assertIsNone(rep)
        done, rep = self.report(self.export("export-commit"), out, "--source-commit", "f" * 40, "--source-repo", str(self.repo))
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIsNone(rep)
        done, _ = self.report(root, out, "--source-commit", self.commit)
        self.assertEqual(done.returncode, 3)


if __name__ == "__main__":
    unittest.main()
