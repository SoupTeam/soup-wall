"""SOU-128: the metamorphic gate, its broken-classifier negative controls and boundary probes."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "eval/metamorphic_runner.py"
BUILDER = ROOT / "eval/tools/make_sou128_corpus.py"
CORPUS = ROOT / "eval/fixtures/sou128_metamorphic_dev_v0.4.json"
RELATIONS = ROOT / "eval/fixtures/sou128_relations_v0.4.json"
BASELINE = ROOT / "rule_baseline/rule_baseline.py"
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "eval/tools"))
sys.dont_write_bytecode = True
import metamorphic_runner as MR  # noqa: E402
import sou128_controls as CONTROLS  # noqa: E402
import sou128_relation_review as REVIEW  # noqa: E402

GENERIC_ORDER = {f"ORDER-{n}" for n in ("READ", "SIZES", "SEARCH", "DEL", "MIX", "SHELL", "UNKNOWN")}
GENERIC_META = {f"META-{n}" for n in ("READ", "SIZES", "SEARCH", "DEL", "MIX", "SHELL", "UNKNOWN")}
# D01 extra-argument relations (PR #246 TL review, 2026-10-29). The accepted baselines genuinely fail all three.
EXTRA_ARG = {"EXTRA-ARG-CE1", "EXTRA-ARG-CE2", "EXTRA-ARG-CE3"}
BASELINE_D01_FAILURES = {("preserve_actions_mark_unknown", r) for r in EXTRA_ARG}
# The explicitly selected SOU-97 candidate: Draft PR #213, never merged into or imported by this branch.
SOU97_COMMIT = "7d7f974776c1312ce425f98734281891815b6943"
SOU97_PATH = "rule_baseline/pilot_readonly_v1/rule_baseline.py"
SOU97_SHA256 = "ffeb367ffbd8d73d84369111b96fd61026d34b77511149e3c86b07fc133ada30"  # pilot_readonly_v1.2
# Network is never used by the tests. A reviewer fetches the object first (eval/sou128/README.md, "SOU-97 candidate"):
#   git fetch origin 7d7f974776c1312ce425f98734281891815b6943
# Set SOU128_REQUIRE_SOU97_CANDIDATE=1 to make a missing candidate an error instead of a skip.
REQUIRE_SOU97 = os.environ.get("SOU128_REQUIRE_SOU97_CANDIDATE") == "1"


def gate(*args, timeout=900, keep=None):
    with tempfile.TemporaryDirectory() as tmp:
        done = subprocess.run([sys.executable, "-B", str(GATE), "--out-dir", tmp, *map(str, args)],
                              capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        out = {name: Path(tmp, name).read_bytes() for name in ("report.json", "latency.json") if Path(tmp, name).exists()}
    report = json.loads(out["report.json"]) if "report.json" in out else None
    return (done, report, out) if keep else (done, report)


def failing(report, mode, section=None):
    modes = (section or report)["modes"]
    return {(x["kind"], x["id"]) for x in modes[mode]["relations"] if x["verdict"] == "fail"}


def beyond_baseline(test, report, mode):
    """Failures of a baseline-wrapped control besides the inherited baseline D01 failures, which must still be there."""
    found = failing(report, mode)
    test.assertTrue(BASELINE_D01_FAILURES <= found, (mode, sorted(found)))
    return found - BASELINE_D01_FAILURES


def sou97_candidate(directory: Path) -> Path | None:
    """The pinned SOU-97 v1.2 classifier from its exact #213 commit, or None where that object is not fetched."""
    done = subprocess.run(["git", "-C", str(ROOT), "cat-file", "blob", f"{SOU97_COMMIT}:{SOU97_PATH}"], capture_output=True)
    if done.returncode != 0:
        return None
    if MR.sha256(done.stdout) != SOU97_SHA256:
        raise AssertionError("SOU-97 candidate blob does not match its pinned sha256")
    path = Path(directory) / "rule_baseline.py"
    path.write_bytes(done.stdout)
    return path


class AcceptedBaseline(unittest.TestCase):
    """The accepted baselines satisfy every source-backed relation except the three D01 extra-argument relations,
    which they genuinely fail in both modes. The gate reports FAIL for that; nothing is relabelled or observed away."""

    @classmethod
    def setUpClass(cls):
        cls.done, cls.report = gate()

    def test_fails_exactly_the_d01_relations_in_direct_and_worker_mode_with_parity(self):
        self.assertEqual(self.done.returncode, 1, self.done.stdout + self.done.stderr)
        self.assertEqual(self.report["verdict"], "FAIL")
        self.assertEqual(self.report["verdict_by_side"], {"baseline": "FAIL", "candidate": "not_run"})
        total = len(json.loads(RELATIONS.read_bytes())["relations"])
        for mode in ("direct", "worker"):
            tally = self.report["modes"][mode]["tally"]
            self.assertEqual((tally["fail"], tally["pass"], tally["observed"], tally["fail"] + tally["pass"] + tally["observed"]),
                             (3, 38, 17, total))
            self.assertEqual(failing(self.report, mode), BASELINE_D01_FAILURES)
            self.assertEqual(self.report["modes"][mode]["unexpected_technical_errors"], [])
        self.assertEqual(self.report["mode_parity"]["divergent_cases"], [])

    def test_baseline_d01_failures_are_the_reproduced_ones(self):
        # Observed before the relations existed (PHASE3_REVIEW.md sections 10.3 and 11): CE-1 loses the Git read,
        # CE-2 and CE-3 keep their action but suppress the uncertainty. Real classifications, not technical failures.
        expected = {
            "EXTRA-ARG-CE1": ("proven actions lost: ['read']", ["classification", "ok", ["read"], False],
                              ["classification", "unknown", [], True]),
            "EXTRA-ARG-CE2": ("unmodelled argument added but unknown is false", ["classification", "ok", ["read"], False],
                              ["classification", "ok", ["read"], False]),
            "EXTRA-ARG-CE3": ("unmodelled argument added but unknown is false", ["classification", "ok", ["write"], False],
                              ["classification", "ok", ["write"], False]),
        }
        for mode in ("direct", "worker"):
            rels = {x["id"]: x for x in self.report["modes"][mode]["relations"]}
            for rid, (detail, source, variant) in expected.items():
                self.assertEqual((rels[rid]["verdict"], rels[rid]["detail"]), ("fail", detail), (mode, rid))
                self.assertEqual([o for _, o in rels[rid]["members"]], [source, variant], (mode, rid))
                self.assertTrue(rels[rid]["informative"])

    def test_identities_and_scope_are_recorded(self):
        ids = self.report["identities"]
        self.assertEqual(ids["classifiers"]["generic"]["sha256"], MR.sha256(BASELINE.read_bytes()))
        self.assertEqual(ids["corpus"]["sha256"], MR.sha256(CORPUS.read_bytes()))
        self.assertEqual(ids["worker_deadlines_ms"], {"REQUEST_DEADLINE": 1400, "START_DEADLINE": 1400})
        self.assertIn("candidate classifier (SOU-97 #213 is not merged)", self.report["not_claimed"])
        self.assertEqual(self.report["candidate"]["status"], "not_run")
        self.assertIn("#213", self.report["candidate"]["blocker"])

    def test_vacuous_equalities_are_counted_not_hidden(self):
        vacuous = {x["id"] for x in self.report["modes"]["direct"]["relations"] if x["verdict"] == "pass" and not x["informative"]}
        self.assertEqual(vacuous, {"ORDER-UNKNOWN", "META-UNKNOWN", "DEFAULT-DTREE"})
        self.assertEqual(self.report["modes"]["direct"]["tally"]["pass_vacuous"], 3)

    def test_accounting_has_exact_denominators_and_no_label_claims(self):
        for mode in ("direct", "worker"):
            acc = self.report["modes"][mode]["accounting"]
            cases = acc["cases"]
            self.assertEqual(acc["labels"], {"scored": 0, "pending": 89,
                                             "note": "no label is reviewed ground truth; label-relative misses are not computed"})
            self.assertEqual(cases["total"], 89)
            self.assertEqual(cases["classified"] + cases["technical_failure"], 89)
            self.assertEqual(cases["certain_actions"] + cases["proven_noop"] + cases["partial_unknown"] + cases["abstention"],
                             cases["classified"])
            self.assertEqual(cases["technical_failure_by_channel"], {"expected:classifier_invalid": 7})
            self.assertEqual((acc["protocol_errors"], acc["timeouts"]), (0, 0))
            pairs = acc["relation_pairs"]
            self.assertEqual(pairs["known_action_losses_without_uncertainty"], [])
            self.assertEqual({(l["relation"], tuple(l["lost"]), l["verdict"]) for l in pairs["known_action_losses"]},
                             {("BOUND-DEPTH-4-5", ("delete",), "pass"), ("BOUND-DEPTH-4-20", ("delete",), "pass"),
                              ("BOUND-GITLOG-20-21", ("read",), "pass"), ("EXTRA-ARG-CE1", ("read",), "fail")})
            self.assertEqual({l["relation"] for l in pairs["risky_action_losses"]}, {"BOUND-DEPTH-4-5", "BOUND-DEPTH-4-20"})
            self.assertTrue(all(l["variant_unknown"] for l in pairs["risky_action_losses"]))

    def test_boundary_probes(self):
        probes = {p["id"]: p for p in self.report["boundary_probes"]}
        for pid in ("TRUNCATED", "TRAILING-COMMA", "INVALID-UTF8", "OVERSIZE", "FRAME-DUPLICATE-MEMBER", "FRAME-INPUT-SHA-MISMATCH"):
            self.assertEqual(probes[pid]["verdict"], "pass", probes[pid])
        self.assertEqual(probes["FRAME-DUPLICATE-MEMBER"]["detail"], {"replies": 0, "exit_code": 3})
        # Enforced only by Rust MCP admission: reported as blocked, and the Python gap stays visible.
        for pid in ("DUPLICATE-ARGUMENT", "DUPLICATE-TOOL-NAME", "NAN", "LONE-SURROGATE"):
            self.assertEqual(probes[pid]["verdict"], "blocked")
            self.assertIn("single_shot", probes[pid]["detail"]["known_gap"])


class NegativeControls(unittest.TestCase):
    """A deliberately broken classifier must FAIL the actual gate, for the reason it is broken."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sou128-broken-")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)

    def run_broken(self, name, modes="direct", profile="generic"):
        path = CONTROLS.write_control(name, Path(self.tmp), profile)
        return gate("--modes", modes, "--classifier", f"{profile}={path}")

    def test_order_sensitive_classifier_fails(self):
        done, report = self.run_broken("order_sensitive")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(beyond_baseline(self, report, "direct"), {("equal_outcome", r) for r in GENERIC_ORDER})
        done, report = self.run_broken("order_sensitive", profile="git")
        self.assertEqual(beyond_baseline(self, report, "direct"), {("equal_outcome", "ORDER-GITLOG")})

    def test_metadata_obedient_classifier_fails_in_both_modes(self):
        done, report = self.run_broken("metadata_obedient", "direct,worker")
        self.assertEqual(done.returncode, 1)
        for mode in ("direct", "worker"):
            self.assertEqual(beyond_baseline(self, report, mode), {("metadata_invariant", r) for r in GENERIC_META})

    def test_default_sensitive_classifier_fails(self):
        done, report = self.run_broken("default_sensitive")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(beyond_baseline(self, report, "direct"),
                         {("equal_outcome", f"DEFAULT-{n}") for n in ("DTREE", "SEARCH", "SIZES", "EDIT")})
        done, report = self.run_broken("default_sensitive", profile="git")
        self.assertEqual(beyond_baseline(self, report, "direct"), {("equal_outcome", "DEFAULT-GITDIFF"), ("equal_outcome", "DEFAULT-GITLOG")})

    def test_known_risk_loss_fails(self):
        done, report = self.run_broken("risk_loss")
        self.assertEqual(done.returncode, 1)
        lost = {i for k, i in failing(report, "direct") if k == "preserve_risk_mark_unknown"}
        self.assertEqual(lost, {"MIXED-SHELL-MIX", "MIXED-SHELL-SEND", "MIXED-WF-DELETE", "MIXED-WF-PERM"})

    def test_masked_technical_error_fails(self):
        done, report = self.run_broken("masked_error")
        self.assertEqual(done.returncode, 1)
        masked = [x for x in report["modes"]["direct"]["relations"]
                  if x["kind"] == "technical_failure_channel" and not x["id"].startswith("GIT-")]
        self.assertTrue(masked and all(x["verdict"] == "fail" and "masked" in x["detail"] for x in masked))
        done, report = self.run_broken("masked_error", profile="git")
        self.assertEqual(beyond_baseline(self, report, "direct"), {("technical_failure_channel", "GIT-NAME-01"),
                                                     ("technical_failure_channel", "GIT-NAME-02")})

    def test_certainty_past_a_bound_fails(self):
        done, report = self.run_broken("certain_noop")
        self.assertEqual(done.returncode, 1)
        broken = {i for k, i in failing(report, "direct") if k == "no_silent_loss_past_bound"}
        self.assertEqual(broken, {"BOUND-DEPTH-4-5", "BOUND-DEPTH-4-20", "BOUND-ARRAY-200-201", "BOUND-ARRAY-200-256"})
        losses = report["modes"]["direct"]["accounting"]["relation_pairs"]["known_action_losses_without_uncertainty"]
        self.assertTrue(losses)
        done, report = self.run_broken("certain_noop", profile="git")
        self.assertEqual(beyond_baseline(self, report, "direct"), {("no_silent_loss_past_bound", "BOUND-GITLOG-20-21")})

    def test_fake_success_is_a_technical_error(self):
        done, report = self.run_broken("fake_success")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(report["verdict"], "TECHNICAL_ERROR")
        self.assertTrue(report["modes"]["direct"]["unexpected_technical_errors"])

    def test_worker_deadline_is_a_timeout_channel_not_a_classification(self):
        done, report = self.run_broken("slow", "worker")
        self.assertEqual(done.returncode, 2)
        worker = report["modes"]["worker"]
        self.assertGreater(worker["worker_stats"]["generic"]["timeouts"], 0)
        self.assertGreater(worker["accounting"]["timeouts"], 0)
        errors = {e["id"]: e["error"] for e in worker["unexpected_technical_errors"]}
        self.assertTrue(all(i.startswith(("S128-ORDER-SEARCH", "S128-META-SEARCH", "S128-DEFAULT-SEARCH", "S128-UNICODE",
                                          "S128-LITERAL-RM")) for i in errors), sorted(errors))
        self.assertEqual({k for k in worker["accounting"]["cases"]["technical_failure_by_channel"] if k.startswith("unexpected")},
                         {"unexpected:classifier_timeout"})
        # A relation over a timed-out case fails (or is only observed); it never passes as a classification.
        timed_out = [x for x in worker["relations"] if any(m in errors for m, _ in x["members"])]
        self.assertTrue(timed_out and all(x["verdict"] in ("fail", "observed") for x in timed_out))


class RelationReview(unittest.TestCase):
    """Every asserted relation is broken by at least one targeted control (sensitivity)."""

    def test_every_asserted_relation_is_sensitive(self):
        with tempfile.TemporaryDirectory(prefix="sou128-review-") as tmp:
            result = REVIEW.review(Path(tmp))
        # The baseline's own D01 failures are reported, never credited to a control.
        self.assertEqual((result["baseline"]["exit_code"], result["baseline"]["verdict"]), (1, "FAIL"))
        self.assertEqual(result["failing_on_baseline"], sorted(EXTRA_ARG))
        self.assertTrue(all(not set(c["relations_broken"]) & EXTRA_ARG for c in result["controls"].values()))
        self.assertEqual(result["relations"], {"total": 58, "asserted": 41, "observe_only": 17})
        self.assertEqual(result["unbroken_asserted"], [])
        self.assertEqual(result["broken_only_by_untargeted"], [])
        self.assertEqual(result["vacuous_on_baseline"], ["DEFAULT-DTREE", "META-UNKNOWN", "ORDER-UNKNOWN"])
        # Coverage gaps are reported: no Git case has a risky action with an unknown component, and the
        # slow control delays only search_files. v0.4 closed certain_noop/git and masked_error/git.
        self.assertEqual(result["controls_without_effect"], ["risk_loss/git", "slow/git"])


class CandidateComparison(unittest.TestCase):
    """The comparison path works for an explicitly selected file (a broken control here, never the SOU-97 candidate)."""

    def test_explicit_candidate_is_compared_with_the_baseline(self):
        with tempfile.TemporaryDirectory(prefix="sou128-candidate-") as tmp:
            path = CONTROLS.write_control("risk_loss", Path(tmp))
            expected_sha = MR.sha256(path.read_bytes())
            done, report = gate("--modes", "direct", "--candidate", f"generic={path}")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(failing(report, "direct"), BASELINE_D01_FAILURES)  # the baseline's own failures, unchanged
        cand = report["candidate"]
        self.assertEqual(report["verdict_by_side"], {"baseline": "FAIL", "candidate": "FAIL"})
        self.assertEqual(cand["status"], "run")
        self.assertEqual(cand["classifiers"]["generic"]["sha256"], expected_sha)
        self.assertEqual(cand["classifiers"]["git"]["sha256"], report["identities"]["classifiers"]["git"]["sha256"])
        cmp_ = cand["comparison"]["direct"]
        self.assertEqual({r["relation"] for r in cmp_["relation_regressions"]},
                         {"MIXED-SHELL-MIX", "MIXED-SHELL-SEND", "MIXED-WF-DELETE", "MIXED-WF-PERM"})
        self.assertTrue(cmp_["risky_losses"] and all(c["risky_lost"] for c in cmp_["risky_losses"]))

    def test_candidate_boundaries_are_probed_and_a_masked_parse_failure_fails(self):
        # Unchanged baseline classify(); only the single-shot main() answers unparseable input with an
        # ordinary read classification. No in-process relation can see this, so only probing fails it.
        masking = ("import io, json, sys\n"
                   "_ns = {'__name__': 'sou128_wrapped_baseline', '__file__': 'rule_baseline.py'}\n"
                   "exec(compile(open(@BASELINE@, 'rb').read(), 'rule_baseline.py', 'exec'), _ns)\n"
                   "classify, _error = _ns['classify'], _ns['_error']\n"
                   "if __name__ == '__main__':\n"
                   "    raw = sys.stdin.buffer.read()\n"
                   "    try:\n"
                   "        json.loads(raw)\n"
                   "    except ValueError:\n"
                   "        print(json.dumps(classify({'tool_name': 'read_text_file', 'raw_arguments': {'path': '/workspace/a'}})))\n"
                   "        raise SystemExit(0)\n"
                   "    sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding='utf-8')\n"
                   "    raise SystemExit(_ns['main']())\n").replace("@BASELINE@", repr(str(BASELINE)))
        with tempfile.TemporaryDirectory(prefix="sou128-candidate-") as tmp:
            path = Path(tmp, "masks_invalid_input.py")
            path.write_text(masking, encoding="utf-8")
            done, report = gate("--modes", "direct", "--candidate", f"generic={path}")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        cand = report["candidate"]
        # Relations show nothing beyond the inherited baseline D01 failures; only probing fails it.
        self.assertEqual(failing(report, "direct", cand), BASELINE_D01_FAILURES)
        self.assertEqual(cand["comparison"]["direct"]["relation_regressions"], [])
        self.assertEqual(cand["boundary_probes_classifier"], cand["classifiers"]["generic"])
        probes = {p["id"]: p for p in cand["boundary_probes"]}
        for pid in ("TRUNCATED", "TRAILING-COMMA"):
            self.assertEqual((probes[pid]["verdict"], probes[pid]["detail"]["single_shot"]), ("fail", "classification"))
        self.assertEqual({p["id"] for p in report["boundary_probes"] if p["verdict"] == "fail"}, set())  # baseline unchanged
        self.assertEqual({p["id"] for p in cand["boundary_probes"] if p["verdict"] == "blocked"},
                         {"DUPLICATE-ARGUMENT", "DUPLICATE-TOOL-NAME", "NAN", "LONE-SURROGATE"})

    def test_git_candidate_boundaries_are_probed_too(self):
        # A Git-only candidate: the unchanged Git baseline plus a main() that masks unparseable input.
        git_baseline = ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"
        masking = ("import io, json, sys\n"
                   "_ns = {'__name__': 'sou128_wrapped_baseline', '__file__': 'rule_baseline.py'}\n"
                   "exec(compile(open(@BASELINE@, 'rb').read(), 'rule_baseline.py', 'exec'), _ns)\n"
                   "classify, _error = _ns['classify'], _ns['_error']\n"
                   "if __name__ == '__main__':\n"
                   "    raw = sys.stdin.buffer.read()\n"
                   "    try:\n"
                   "        json.loads(raw)\n"
                   "    except ValueError:\n"
                   "        print(json.dumps(classify({'tool_name': 'git_status', 'raw_arguments': {'repo_path': '/workspace'}})))\n"
                   "        raise SystemExit(0)\n"
                   "    sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding='utf-8')\n"
                   "    raise SystemExit(_ns['main']())\n").replace("@BASELINE@", repr(str(git_baseline)))
        with tempfile.TemporaryDirectory(prefix="sou128-candidate-") as tmp:
            path = Path(tmp, "git_masks_invalid_input.py")
            path.write_text(masking, encoding="utf-8")
            done, report = gate("--modes", "direct", "--candidate", f"git={path}")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        cand = report["candidate"]
        self.assertEqual(failing(report, "direct", cand), BASELINE_D01_FAILURES)  # inherited only; probing fails it
        self.assertEqual(cand["comparison"]["direct"]["relation_regressions"], [])
        self.assertEqual(cand["boundary_probes_git_classifier"], cand["classifiers"]["git"])
        git_probes = {p["id"]: p for p in cand["boundary_probes_git"]}
        for pid in ("TRUNCATED", "TRAILING-COMMA"):
            self.assertEqual((git_probes[pid]["verdict"], git_probes[pid]["detail"]["single_shot"]), ("fail", "classification"))
        self.assertEqual({p["id"] for p in cand["boundary_probes"] if p["verdict"] == "fail"}, set())  # generic is the baseline
        # The baseline Git classifier's own boundaries are probed as well, and hold.
        self.assertEqual(report["boundary_probes_git_classifier"], report["identities"]["classifiers"]["git"])
        self.assertEqual({p["id"] for p in report["boundary_probes_git"] if p["verdict"] == "fail"}, set())


class Reproducibility(unittest.TestCase):
    def test_report_is_byte_identical_across_runs_and_latency_is_separate(self):
        first = gate("--modes", "direct,worker", keep=True)[2]
        second = gate("--modes", "direct,worker", "--latency", "--latency-repeats", "1", "--latency-cold", "1", keep=True)[2]
        self.assertEqual(first["report.json"], second["report.json"])
        self.assertNotIn("latency.json", first)
        latency = json.loads(second["latency.json"])
        self.assertEqual(latency["method"]["batch_size"], 1)
        self.assertEqual(latency["method"]["deadlines_ms"], {"REQUEST_DEADLINE": 1400, "START_DEADLINE": 1400})
        for profile, rows in latency["profiles"].items():
            self.assertEqual(rows["direct_warm_in_process"]["n"], rows["cases"])
            self.assertEqual(rows["worker_warm_round_trip"]["n"], rows["cases"])
            for key in ("direct_cold_process_per_call", "worker_cold_start_to_ready", "worker_cold_first_reply"):
                self.assertEqual(rows[key]["n"], 1)
            self.assertEqual(rows["worker_warm_round_trip"]["timeouts"], 0)

    def test_candidate_latency_is_separate_and_leaves_the_report_unchanged(self):
        # A pass-through candidate: the unchanged generic baseline under another file identity.
        source = (CONTROLS.PREAMBLE.replace("@BASELINE@", repr(str(BASELINE)))
                  + "def classify(event):\n    return _base(event)\n" + CONTROLS.POSTAMBLE)
        with tempfile.TemporaryDirectory(prefix="sou128-candidate-") as tmp:
            path = Path(tmp, "passthrough.py")
            path.write_text(source, encoding="utf-8")
            cand_sha = MR.sha256(path.read_bytes())
            plain = gate("--modes", "direct,worker", "--candidate", f"generic={path}", keep=True)
            timed = gate("--modes", "direct,worker", "--candidate", f"generic={path}", "--latency",
                         "--latency-repeats", "1", "--latency-cold", "1", keep=True)
        # Exit 1 on both runs only through the baseline D01 failures, which a pass-through inherits.
        self.assertEqual((plain[0].returncode, timed[0].returncode), (1, 1), timed[0].stdout + timed[0].stderr)
        self.assertEqual(failing(timed[1], "worker", timed[1]["candidate"]), BASELINE_D01_FAILURES)
        self.assertEqual(plain[2]["report.json"], timed[2]["report.json"])
        latency = json.loads(timed[2]["latency.json"])
        baseline_ids = timed[1]["identities"]["classifiers"]
        self.assertEqual(latency["classifiers"], baseline_ids)
        self.assertEqual({k: v["classifier_sha256"] for k, v in latency["profiles"].items()},
                         {k: v["sha256"] for k, v in baseline_ids.items()})
        cand = latency["candidate"]
        self.assertEqual(cand["classifiers"], {"generic": {"path": "passthrough.py", "sha256": cand_sha}})
        self.assertEqual(set(cand["profiles"]), {"generic"})  # only the replaced profile is timed again
        rows = cand["profiles"]["generic"]
        self.assertEqual(rows["classifier_sha256"], cand_sha)
        self.assertEqual(rows["cases"], latency["profiles"]["generic"]["cases"])
        self.assertEqual(rows["direct_warm_in_process"]["n"], rows["cases"])
        self.assertEqual(rows["worker_warm_round_trip"]["n"], rows["cases"])
        for key in ("direct_cold_process_per_call", "worker_cold_start_to_ready", "worker_cold_first_reply"):
            self.assertEqual(rows[key]["n"], 1)
        self.assertEqual(rows["worker_warm_round_trip"]["timeouts"], 0)
        self.assertEqual(latency["method"]["deadlines_ms"], {"REQUEST_DEADLINE": 1400, "START_DEADLINE": 1400})


class InputIntegrity(unittest.TestCase):
    def mutated(self, corpus_edit=None, relations_edit=None):
        corpus, rels = json.loads(CORPUS.read_bytes()), json.loads(RELATIONS.read_bytes())
        if corpus_edit:
            corpus_edit(corpus)
        if relations_edit:
            relations_edit(rels)
        tmp = Path(tempfile.mkdtemp(prefix="sou128-mutated-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "c.json").write_text(json.dumps(corpus), encoding="utf-8")
        (tmp / "r.json").write_text(json.dumps(rels), encoding="utf-8")
        return gate("--modes", "direct", "--corpus", tmp / "c.json", "--relations", tmp / "r.json")

    def test_cited_source_drift_is_refused(self):
        def drift(rels):
            rels["relations"][0]["sources"][1]["sha256"] = "0" * 64
        done, report = self.mutated(relations_edit=drift)
        self.assertEqual(done.returncode, 3)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertTrue(any("contract/updated_contract2.md" in e for e in report["validation_errors"]))

    def test_label_promotion_is_refused(self):
        def promote(corpus):
            case = corpus["cases"][0]
            case["expectation_status"] = "provisional"
            case["expected"] = {"actions": ["read"], "unknown": False, "status": None}
        done, report = self.mutated(corpus_edit=promote)
        self.assertEqual(done.returncode, 3)
        self.assertTrue(any("must stay pending" in e for e in report["validation_errors"]))

    def test_unsourced_assertion_and_cross_classifier_relation_are_refused(self):
        def edit(rels):
            rels["relations"][0]["sources"] = []
            rels["relations"][1]["members"] = ["S128-ORDER-READ-A", "S128-ORDER-GITLOG-A"]
        done, report = self.mutated(relations_edit=edit)
        self.assertEqual(done.returncode, 3)
        joined = " ".join(report["validation_errors"])
        self.assertIn("needs a source", joined)
        self.assertIn("different classifiers", joined)

    def test_corpus_is_the_deterministic_build(self):
        done = subprocess.run([sys.executable, "-B", str(BUILDER), "--check"], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_v04_keeps_the_frozen_v03_corpus_as_an_exact_prefix(self):
        import make_sou128_corpus as BUILD
        corpus, rels = json.loads(CORPUS.read_bytes()), json.loads(RELATIONS.read_bytes())
        frozen = json.loads(BUILD.FROZEN_FIXTURE.read_bytes())
        self.assertEqual(frozen["fixture_version"], "sou128-metamorphic-dev-v0.3")
        self.assertEqual(MR.sha256(BUILD.FROZEN_FIXTURE.read_bytes()),
                         "4d71bcd33b38db213600b95b179506177bd1d61c1e728010c64c153497f31cd7")
        self.assertEqual(BUILD.frozen_prefix_errors(corpus, rels), [])
        added = corpus["cases"][len(frozen["cases"]):]
        self.assertEqual([c["id"] for c in added],
                         ["S128-GIT-BOUND-LOG-20", "S128-GIT-BOUND-LOG-21", "S128-GIT-NAME-01", "S128-GIT-NAME-02"]
                         + [f"S128-EXTRA-ARG-CE{i}-{side}" for i in (1, 2, 3) for side in ("SOURCE", "VARIANT")])
        self.assertEqual([c["origin"] for c in added], [BUILD.ORIGIN_V04] * 4 + [BUILD.ORIGIN_V04_D01] * 6)
        reordered = json.loads(json.dumps(corpus))
        reordered["cases"][-1]["origin"] = BUILD.ORIGIN_V04
        reordered["cases"][len(frozen["cases"])]["origin"] = BUILD.ORIGIN_V04_D01
        self.assertTrue(any("in that order" in e for e in BUILD.frozen_prefix_errors(reordered, rels)))
        self.assertTrue(all(c["expectation_status"] == "pending" and c["expected"] == {"actions": None, "unknown": None, "status": None}
                            for c in added))
        edited = json.loads(json.dumps(corpus))
        edited["cases"][0]["input"]["raw_arguments"]["head"] = 11
        self.assertIn("v0.4 cases do not start with the frozen v0.3 cases", BUILD.frozen_prefix_errors(edited, rels))
        # A re-cited source hash keeps the frozen prefix; a changed cited rule or basis does not.
        recited = json.loads(json.dumps(rels))
        recited["relations"][0]["sources"][1]["sha256"] = "0" * 64
        recited["boundary_probes"][0]["sources"][0]["sha256"] = "0" * 64
        self.assertEqual(BUILD.frozen_prefix_errors(corpus, recited), [])
        for edit in (lambda r: r["relations"][0]["sources"][1].update(rule="changed"),
                     lambda r: r["relations"][0].update(basis="changed")):
            changed = json.loads(json.dumps(rels))
            edit(changed)
            self.assertIn("v0.4 relations do not start with the frozen v0.3 relations", BUILD.frozen_prefix_errors(corpus, changed))


class Judge(unittest.TestCase):
    @staticmethod
    def rec(actions=None, unknown=None, status="ok", error=None, channel=None):
        return {"technical_error": error, "failure_channel": channel, "predicted_status": status,
                "predicted_actions": actions, "predicted_unknown": unknown}

    def test_relation_rules(self):
        j = MR.judge
        ok_del, unk = self.rec(["delete"], False), self.rec(["delete"], True)
        self.assertEqual(j({"kind": "preserve_risk_mark_unknown"}, [ok_del, unk])[0], "pass")
        self.assertEqual(j({"kind": "preserve_risk_mark_unknown"}, [ok_del, self.rec(["delete"], False)])[0], "fail")
        self.assertEqual(j({"kind": "preserve_risk_mark_unknown"}, [self.rec(["read"], False), self.rec(["read"], True)])[0], "fail")
        self.assertEqual(j({"kind": "no_silent_loss_past_bound"}, [ok_del, self.rec([], True, "unknown")])[0], "pass")
        self.assertEqual(j({"kind": "no_silent_loss_past_bound"}, [ok_del, self.rec([], False)])[0], "fail")
        tech = self.rec(error="classifier_reported_error: x", channel="unestablished")
        self.assertEqual(j({"kind": "technical_failure_channel"}, [tech])[0], "fail")
        self.assertEqual(j({"kind": "equal_outcome"}, [tech, tech])[0], "fail")

    def test_preserve_actions_mark_unknown(self):
        k = {"kind": "preserve_actions_mark_unknown"}
        j = lambda a, b: MR.judge(k, [a, b])  # noqa: E731
        read = self.rec(["read"], False)
        # Any proven action, of any risk, kept with unknown = true: the only passing shape.
        self.assertEqual(j(read, self.rec(["read"], True)), ("pass", "actions kept, unknown set"))
        self.assertEqual(j(self.rec(["write"], False), self.rec(["delete", "write"], True))[0], "pass")
        # Action loss, also with uncertainty set.
        self.assertEqual(j(read, self.rec([], True, "unknown")), ("fail", "proven actions lost: ['read']"))
        self.assertEqual(j(self.rec(["read", "write"], False), self.rec(["read"], True))[0], "fail")
        # Suppressed uncertainty.
        self.assertEqual(j(read, read), ("fail", "unmodelled argument added but unknown is false"))
        # A technical failure, even through an established D06 channel, is never a valid classification.
        invalid = self.rec(error="classifier_reported_error: classifier_invalid", channel="classifier_invalid")
        self.assertEqual(j(read, invalid)[0], "fail")
        self.assertIn("technical failure", j(read, invalid)[1])
        self.assertEqual(j(invalid, self.rec(["read"], True))[0], "fail")
        # A source that proves nothing (abstention, or uncertain) cannot make the relation pass vacuously.
        for source in (self.rec([], True, "unknown"), self.rec([], False), self.rec(["read"], True)):
            verdict, detail = j(source, self.rec(["read"], True))
            self.assertEqual(verdict, "fail")
            self.assertIn("inconclusive", detail)
        # The risk-only relation keeps its semantics: a read source is inconclusive there.
        self.assertEqual(MR.judge({"kind": "preserve_risk_mark_unknown"}, [read, self.rec(["read"], True)])[0], "fail")

    def test_nearest_rank_percentile(self):
        self.assertEqual(MR.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(MR.percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(MR.percentile([7], 95), 7)
        self.assertIsNone(MR.percentile([], 50))


class D01ExtraArgument(unittest.TestCase):
    """CE-1/2/3: corpus provenance, source drift and the closed-schema boundary (no candidate needed)."""

    def test_cases_and_relations_are_pending_source_backed_and_schema_permitted(self):
        corpus, rels = json.loads(CORPUS.read_bytes()), json.loads(RELATIONS.read_bytes())
        cases = {c["id"]: c for c in corpus["cases"]}
        extra = {r["id"]: r for r in rels["relations"] if r["id"] in EXTRA_ARG}
        self.assertEqual(set(extra), EXTRA_ARG)
        added = {"EXTRA-ARG-CE1": ("git_log", "author", "x", "git"), "EXTRA-ARG-CE2": ("read_text_file", "mode", "raw", "generic"),
                 "EXTRA-ARG-CE3": ("edit_file", "backup", True, "generic")}
        for rid, (tool, key, value, cls) in added.items():
            r = extra[rid]
            self.assertEqual((r["kind"], r["review_status"]), ("preserve_actions_mark_unknown", "source_backed"))
            source, variant = (cases[m] for m in r["members"])
            for c in (source, variant):
                self.assertEqual((c["expectation_status"], c["evaluator_only"]["classifier"], c["input"]["tool_name"]),
                                 ("pending", cls, tool))
                self.assertEqual(c["expected"], {"actions": None, "unknown": None, "status": None})
            schema = variant["input"]["tool_schema"]
            self.assertEqual(schema, source["input"]["tool_schema"])
            self.assertNotIn(key, schema["properties"])
            self.assertNotIn("additionalProperties", schema)  # open: the argument is permitted, not a D06 violation
            self.assertTrue(set(source["input"]["raw_arguments"]) <= set(schema["properties"]))
            self.assertEqual(variant["input"]["raw_arguments"], {**source["input"]["raw_arguments"], key: value})
            cited = {s["path"] for s in r["sources"]}
            self.assertIn("contract/updated_contract2.md", cited)
            self.assertTrue({s["rule"].split(" /")[0] for s in r["sources"] if s["path"] == "contract/updated_contract2.md"}
                            >= {"D01", "D06"})
            self.assertTrue(cited & {"profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json",
                                     "profiles/mcp/git-readonly-v1/upstream-tools-list.json"})

    def test_a_closed_schema_is_not_built_as_a_d01_case(self):
        # An explicitly closed schema would make the argument a D06 violation; the builder refuses to emit it.
        import make_sou128_corpus as BUILD
        original = BUILD.FS["read_text_file"]
        BUILD.FS["read_text_file"] = {**original, "additionalProperties": False}
        try:
            with self.assertRaises(AssertionError):
                BUILD.build()
        finally:
            BUILD.FS["read_text_file"] = original

    def test_candidate_pin_matches_the_runner(self):
        # Offline: the identity this suite verifies is the one the runner publishes, at the same commit.
        for pin in (SOU97_SHA256, SOU97_COMMIT[:8], SOU97_PATH, "pilot_readonly_v1.2", "unmerged Draft PR #213"):
            self.assertIn(pin, MR.CANDIDATE_BLOCKER)

    def test_schema_citation_drift_is_refused(self):
        rels = json.loads(RELATIONS.read_bytes())
        for r in rels["relations"]:
            if r["id"] == "EXTRA-ARG-CE2":
                next(s for s in r["sources"] if s["path"].startswith("profiles/"))["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory(prefix="sou128-drift-") as tmp:
            path = Path(tmp, "r.json")
            path.write_text(json.dumps(rels), encoding="utf-8")
            done, report = gate("--modes", "direct", "--relations", path)
        self.assertEqual((done.returncode, report["verdict"]), (3, "INVALID"))
        self.assertTrue(any(e.startswith("profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json") for e in report["validation_errors"]))


class SOU97CandidateD01(unittest.TestCase):
    """The explicitly selected SOU-97 v1.2 candidate satisfies CE-1/2/3 while the baselines still fail them, and
    D01 defects wrapped around that candidate are caught in both modes.

    Where #213's commit object is absent (any clone that has not fetched it) both tests are SKIPPED with a
    "CANDIDATE NOT AVAILABLE" reason: the candidate is then not tested, which is not a pass. With
    SOU128_REQUIRE_SOU97_CANDIDATE=1 the absence is an error instead."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="sou128-sou97-"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.candidate = sou97_candidate(cls.tmp)
        if cls.candidate is None:
            why = (f"CANDIDATE NOT AVAILABLE, NOT TESTED: SOU-97 #213 commit {SOU97_COMMIT} is not in this clone; "
                   f"fetch it with 'git fetch origin {SOU97_COMMIT}' (see eval/sou128/README.md)")
            if REQUIRE_SOU97:
                raise AssertionError(why + "; required by SOU128_REQUIRE_SOU97_CANDIDATE=1")
            raise unittest.SkipTest(why)

    def run_candidate(self, generic, git):
        return gate("--modes", "direct,worker", "--candidate", f"generic={generic}", "--candidate", f"git={git}")

    def test_candidate_passes_d01_and_baseline_failures_remain(self):
        done, report = self.run_candidate(self.candidate, self.candidate)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)  # the baseline side still fails D01
        self.assertEqual(report["verdict_by_side"], {"baseline": "FAIL", "candidate": "PASS"})
        cand = report["candidate"]
        self.assertEqual({v["sha256"] for v in cand["classifiers"].values()}, {SOU97_SHA256})
        for mode in ("direct", "worker"):
            self.assertEqual(failing(report, mode), BASELINE_D01_FAILURES)
            self.assertEqual(failing(report, mode, cand), set())
            rels = {x["id"]: x for x in cand["modes"][mode]["relations"]}
            for rid in EXTRA_ARG:
                self.assertEqual((rels[rid]["verdict"], rels[rid]["informative"]), ("pass", True))
                (_, source), (_, variant) = rels[rid]["members"]
                self.assertEqual((source[0], source[3], variant[0], variant[3]), ("classification", False, "classification", True))
                self.assertTrue(source[2] and set(source[2]) <= set(variant[2]))
            cmp_ = cand["comparison"][mode]
            self.assertEqual({m["relation"] for m in cmp_["relation_fixes"]}, EXTRA_ARG)
            self.assertEqual((cmp_["relation_regressions"], cmp_["risky_losses"]), ([], []))
        self.assertEqual(cand["mode_parity"]["divergent_cases"], [])
        self.assertEqual(report["mode_parity"]["divergent_cases"], [])

    def test_d01_defects_around_the_candidate_fail_in_both_modes(self):
        expected = {
            "extra_arg_action_loss": (1, "FAIL", "proven actions lost"),
            "extra_arg_unknown_suppressed": (1, "FAIL", "unmodelled argument added but unknown is false"),
            "extra_arg_technical_failure": (2, "TECHNICAL_ERROR", "technical failure on a case that must classify"),
            "vacuous_source": (1, "FAIL", "inconclusive: the source proves no action"),
        }
        for name, (code, side, detail) in expected.items():
            with self.subTest(control=name):
                generic = CONTROLS.write_control(name, self.tmp, "generic", base=self.candidate)
                git = CONTROLS.write_control(name, self.tmp, "git", base=self.candidate)
                done, report = self.run_candidate(generic, git)
                self.assertEqual(done.returncode, code, done.stdout + done.stderr)
                self.assertEqual(report["verdict_by_side"], {"baseline": "FAIL", "candidate": side})
                cand = report["candidate"]
                for mode in ("direct", "worker"):
                    rels = {x["id"]: x for x in cand["modes"][mode]["relations"]}
                    for rid in EXTRA_ARG:
                        self.assertEqual(rels[rid]["verdict"], "fail", (mode, rid))
                        self.assertTrue(rels[rid]["detail"].startswith(detail), (mode, rid, rels[rid]["detail"]))
                    others = {i for _, i in failing(report, mode, cand)} - EXTRA_ARG
                    self.assertEqual(others, {"MIXED-SHELL-MIX", "MIXED-SHELL-SEND", "MIXED-WF-DELETE", "MIXED-WF-PERM"}
                                     if name == "vacuous_source" else set())
                self.assertEqual(cand["mode_parity"]["divergent_cases"], [])


if __name__ == "__main__":
    unittest.main()
