"""SOU-128: the metamorphic gate, its broken-classifier negative controls and boundary probes."""
import json
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


class AcceptedBaseline(unittest.TestCase):
    """Positive control: the accepted baselines satisfy every source-backed relation in both modes."""

    @classmethod
    def setUpClass(cls):
        cls.done, cls.report = gate()

    def test_passes_in_direct_and_worker_mode_with_parity(self):
        self.assertEqual(self.done.returncode, 0, self.done.stdout + self.done.stderr)
        self.assertEqual(self.report["verdict"], "PASS")
        total = len(json.loads(RELATIONS.read_bytes())["relations"])
        for mode in ("direct", "worker"):
            tally = self.report["modes"][mode]["tally"]
            self.assertEqual((tally["fail"], tally["pass"], tally["observed"], tally["pass"] + tally["observed"]), (0, 38, 17, total))
        self.assertEqual(self.report["mode_parity"]["divergent_cases"], [])

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
            self.assertEqual(acc["labels"], {"scored": 0, "pending": 83,
                                             "note": "no label is reviewed ground truth; label-relative misses are not computed"})
            self.assertEqual(cases["total"], 83)
            self.assertEqual(cases["classified"] + cases["technical_failure"], 83)
            self.assertEqual(cases["certain_actions"] + cases["proven_noop"] + cases["partial_unknown"] + cases["abstention"],
                             cases["classified"])
            self.assertEqual(cases["technical_failure_by_channel"], {"expected:classifier_invalid": 7})
            self.assertEqual((acc["protocol_errors"], acc["timeouts"]), (0, 0))
            pairs = acc["relation_pairs"]
            self.assertEqual(pairs["known_action_losses_without_uncertainty"], [])
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
        self.assertEqual(failing(report, "direct"), {("equal_outcome", r) for r in GENERIC_ORDER})
        done, report = self.run_broken("order_sensitive", profile="git")
        self.assertEqual(failing(report, "direct"), {("equal_outcome", "ORDER-GITLOG")})

    def test_metadata_obedient_classifier_fails_in_both_modes(self):
        done, report = self.run_broken("metadata_obedient", "direct,worker")
        self.assertEqual(done.returncode, 1)
        for mode in ("direct", "worker"):
            self.assertEqual(failing(report, mode), {("metadata_invariant", r) for r in GENERIC_META})

    def test_default_sensitive_classifier_fails(self):
        done, report = self.run_broken("default_sensitive")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(failing(report, "direct"),
                         {("equal_outcome", f"DEFAULT-{n}") for n in ("DTREE", "SEARCH", "SIZES", "EDIT")})
        done, report = self.run_broken("default_sensitive", profile="git")
        self.assertEqual(failing(report, "direct"), {("equal_outcome", "DEFAULT-GITDIFF"), ("equal_outcome", "DEFAULT-GITLOG")})

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
        self.assertEqual(failing(report, "direct"), {("technical_failure_channel", "GIT-NAME-01"),
                                                     ("technical_failure_channel", "GIT-NAME-02")})

    def test_certainty_past_a_bound_fails(self):
        done, report = self.run_broken("certain_noop")
        self.assertEqual(done.returncode, 1)
        broken = {i for k, i in failing(report, "direct") if k == "no_silent_loss_past_bound"}
        self.assertEqual(broken, {"BOUND-DEPTH-4-5", "BOUND-DEPTH-4-20", "BOUND-ARRAY-200-201", "BOUND-ARRAY-200-256"})
        losses = report["modes"]["direct"]["accounting"]["relation_pairs"]["known_action_losses_without_uncertainty"]
        self.assertTrue(losses)
        done, report = self.run_broken("certain_noop", profile="git")
        self.assertEqual(failing(report, "direct"), {("no_silent_loss_past_bound", "BOUND-GITLOG-20-21")})

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
        self.assertEqual(result["baseline"]["exit_code"], 0)
        self.assertEqual(result["relations"], {"total": 55, "asserted": 38, "observe_only": 17})
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
        self.assertEqual(report["modes"]["direct"]["tally"]["fail"], 0)  # the baseline itself still passes
        cand = report["candidate"]
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
        self.assertEqual(cand["modes"]["direct"]["tally"]["fail"], 0)  # relations alone would pass this candidate
        self.assertEqual(cand["comparison"]["direct"]["relation_regressions"], [])
        self.assertEqual(cand["boundary_probes_classifier"], cand["classifiers"]["generic"])
        probes = {p["id"]: p for p in cand["boundary_probes"]}
        for pid in ("TRUNCATED", "TRAILING-COMMA"):
            self.assertEqual((probes[pid]["verdict"], probes[pid]["detail"]["single_shot"]), ("fail", "classification"))
        self.assertEqual({p["id"] for p in report["boundary_probes"] if p["verdict"] == "fail"}, set())  # baseline unchanged
        self.assertEqual({p["id"] for p in cand["boundary_probes"] if p["verdict"] == "blocked"},
                         {"DUPLICATE-ARGUMENT", "DUPLICATE-TOOL-NAME", "NAN", "LONE-SURROGATE"})


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
        self.assertEqual((plain[0].returncode, timed[0].returncode), (0, 0), timed[0].stdout + timed[0].stderr)
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
                         ["S128-GIT-BOUND-LOG-20", "S128-GIT-BOUND-LOG-21", "S128-GIT-NAME-01", "S128-GIT-NAME-02"])
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

    def test_nearest_rank_percentile(self):
        self.assertEqual(MR.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(MR.percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(MR.percentile([7], 95), 7)
        self.assertIsNone(MR.percentile([], 50))


if __name__ == "__main__":
    unittest.main()
