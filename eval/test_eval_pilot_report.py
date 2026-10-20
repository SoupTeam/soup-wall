"""SOU-97: the additive --pilot-report mode of eval_runner.py (the default mode must stay unchanged)."""
import json
import shutil
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
CANDIDATE_SHA256 = "82a41dded79cf560cefc5ab6894e9f247d31fec2992b2b7b6d0fcad02c0494f4"


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
        self.assertEqual(rep["classifiers"]["candidate"]["revision"], "pilot_readonly_v1")
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


if __name__ == "__main__":
    unittest.main()
