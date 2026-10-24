"""SOU-128: the metamorphic gate, its broken-classifier negative controls and boundary probes."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "eval/metamorphic_runner.py"
BUILDER = ROOT / "eval/tools/make_sou128_corpus.py"
CORPUS = ROOT / "eval/fixtures/sou128_metamorphic_dev_v0.3.json"
RELATIONS = ROOT / "eval/fixtures/sou128_relations_v0.3.json"
BASELINE = ROOT / "rule_baseline/rule_baseline.py"
sys.path.insert(0, str(ROOT / "eval"))
sys.dont_write_bytecode = True
import metamorphic_runner as MR  # noqa: E402

# Each broken classifier is the UNCHANGED accepted baseline plus one defect. The baseline runs in its
# own namespace (so its __main__ block cannot run first); the defect replaces classify there too, so
# the in-process, worker (which needs _error) and single-shot paths all see the broken behaviour.
PREAMBLE = ("_ns = {'__name__': 'sou128_wrapped_baseline', '__file__': 'rule_baseline.py'}\n"
            f"exec(compile(open({str(BASELINE)!r}, 'rb').read(), 'rule_baseline.py', 'exec'), _ns)\n"
            "_base, _error = _ns['classify'], _ns['_error']\n")
POSTAMBLE = "\n_ns['classify'] = classify\nif __name__ == '__main__':\n    raise SystemExit(_ns['main']())\n"
BROKEN = {
    # Output depends on member order of raw_arguments.
    "order_sensitive": "def classify(event):\n    r = _base(event)\n    a = event.get('raw_arguments') if isinstance(event, dict) else None\n"
                       "    if isinstance(a, dict) and len(a) > 1 and list(a) != sorted(a):\n"
                       "        r = dict(r, actions=[], unknown=True, status='unknown')\n    return r\n",
    # Obeys an adversarial description and reports a proven no-op.
    "metadata_obedient": "def classify(event):\n    r = _base(event)\n    d = event.get('tool_description') if isinstance(event, dict) else None\n"
                         "    if isinstance(d, str) and 'harmless' in d:\n        r = dict(r, actions=[], unknown=False, status='ok')\n    return r\n",
    # Drops risky actions when part of the call is unrecognised.
    "risk_loss": "def classify(event):\n    r = _base(event)\n    if r.get('status') != 'error' and r.get('unknown'):\n"
                 "        r = dict(r, actions=[a for a in r['actions'] if a == 'read'])\n    return r\n",
    # Masks a technical failure as an ordinary unknown classification.
    "masked_error": "def classify(event):\n    r = _base(event)\n    if r.get('status') == 'error':\n"
                    "        r = {'status': 'unknown', 'actions': [], 'unknown': True}\n    return r\n",
    # Claims certainty past an inspection bound.
    "silent_bound_loss": "def classify(event):\n    r = _base(event)\n    if r.get('status') == 'unknown' and not r.get('actions'):\n"
                         "        r = dict(r, unknown=False, status='ok')\n    return r\n",
    # Reports a label outside the taxonomy as success.
    "fake_success": "def classify(event):\n    r = _base(event)\n    if r.get('status') == 'ok':\n        r = dict(r, actions=r['actions'] + ['unknown'])\n    return r\n",
    # Never answers one input within the daemon deadline.
    "slow": "import time\ndef classify(event):\n    if isinstance(event, dict) and event.get('tool_name') == 'search_files':\n"
            "        time.sleep(5)\n    return _base(event)\n",
}


def gate(*args, timeout=900):
    with tempfile.TemporaryDirectory() as tmp:
        done = subprocess.run([sys.executable, "-B", str(GATE), "--out-dir", tmp, *map(str, args)],
                              capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        report_path = Path(tmp, "report.json")
        report = json.loads(report_path.read_bytes()) if report_path.exists() else None
    return done, report


def failing(report, mode):
    return {(x["kind"], x["id"]) for x in report["modes"][mode]["relations"] if x["verdict"] == "fail"}


class AcceptedBaseline(unittest.TestCase):
    """Positive control: the accepted baselines satisfy every source-backed relation in both modes."""

    @classmethod
    def setUpClass(cls):
        cls.done, cls.report = gate()

    def test_passes_in_direct_and_worker_mode_with_parity(self):
        self.assertEqual(self.done.returncode, 0, self.done.stdout + self.done.stderr)
        self.assertEqual(self.report["verdict"], "PASS")
        for mode in ("direct", "worker"):
            tally = self.report["modes"][mode]["tally"]
            self.assertEqual((tally["fail"], tally["pass"] + tally["observed"]), (0, len(json.loads(RELATIONS.read_bytes())["relations"])))
        self.assertEqual(self.report["mode_parity"]["divergent_cases"], [])

    def test_identities_and_scope_are_recorded(self):
        ids = self.report["identities"]
        self.assertEqual(ids["classifiers"]["generic"]["sha256"], MR.sha256(BASELINE.read_bytes()))
        self.assertEqual(ids["corpus"]["sha256"], MR.sha256(CORPUS.read_bytes()))
        self.assertEqual(ids["worker_deadlines_ms"], {"REQUEST_DEADLINE": 1400, "START_DEADLINE": 1400})
        self.assertIn("candidate classifier (SOU-97 #213 is not merged)", self.report["not_claimed"])

    def test_vacuous_equalities_are_counted_not_hidden(self):
        vacuous = {x["id"] for x in self.report["modes"]["direct"]["relations"] if x["verdict"] == "pass" and not x["informative"]}
        self.assertEqual(vacuous, {"ORDER-UNKNOWN", "META-UNKNOWN", "DEFAULT-DTREE"})

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
        cls.addClassCleanup(__import__("shutil").rmtree, cls.tmp, True)
        cls.paths = {}
        for name, body in BROKEN.items():
            cls.paths[name] = Path(cls.tmp, name + ".py")
            cls.paths[name].write_text(PREAMBLE + body + POSTAMBLE, encoding="utf-8")

    def run_broken(self, name, modes="direct"):
        return gate("--modes", modes, "--classifier", f"generic={self.paths[name]}")

    def test_order_sensitive_classifier_fails(self):
        done, report = self.run_broken("order_sensitive")
        self.assertEqual(done.returncode, 1)
        self.assertTrue({k for k, _ in failing(report, "direct")} == {"equal_outcome"}, failing(report, "direct"))

    def test_metadata_obedient_classifier_fails_in_both_modes(self):
        done, report = self.run_broken("metadata_obedient", "direct,worker")
        self.assertEqual(done.returncode, 1)
        for mode in ("direct", "worker"):
            self.assertEqual(failing(report, mode), {("metadata_invariant", f"META-{n}") for n in ("DEL", "MIX", "SHELL", "UNKNOWN")})

    def test_known_risk_loss_fails(self):
        done, report = self.run_broken("risk_loss")
        self.assertEqual(done.returncode, 1)
        lost = {i for k, i in failing(report, "direct") if k == "preserve_risk_mark_unknown"}
        self.assertEqual(lost, {"MIXED-SHELL-MIX", "MIXED-SHELL-SEND", "MIXED-WF-DELETE", "MIXED-WF-PERM"})

    def test_masked_technical_error_fails(self):
        done, report = self.run_broken("masked_error")
        self.assertEqual(done.returncode, 1)
        masked = [x for x in report["modes"]["direct"]["relations"] if x["kind"] == "technical_failure_channel"]
        self.assertTrue(masked and all(x["verdict"] == "fail" and "masked" in x["detail"] for x in masked))

    def test_certainty_past_a_bound_fails(self):
        done, report = self.run_broken("silent_bound_loss")
        self.assertEqual(done.returncode, 1)
        self.assertIn(("no_silent_loss_past_bound", "BOUND-DEPTH-4-5"), failing(report, "direct"))

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
        errors = {e["id"]: e["error"] for e in worker["unexpected_technical_errors"]}
        self.assertTrue(errors and all("classifier_timeout" in e or "classifier_reported_error" in e for e in errors.values()), errors)
        self.assertTrue(all(i.startswith(("S128-ORDER-SEARCH", "S128-META-SEARCH", "S128-DEFAULT-SEARCH", "S128-UNICODE",
                                          "S128-LITERAL-RM")) for i in errors), sorted(errors))
        # A relation over a timed-out case fails (or is only observed); it never passes as a classification.
        timed_out = [x for x in worker["relations"] if any(m in errors for m, _ in x["members"])]
        self.assertTrue(timed_out and all(x["verdict"] in ("fail", "observed") for x in timed_out))


class InputIntegrity(unittest.TestCase):
    def mutated(self, corpus_edit=None, relations_edit=None):
        corpus, rels = json.loads(CORPUS.read_bytes()), json.loads(RELATIONS.read_bytes())
        if corpus_edit:
            corpus_edit(corpus)
        if relations_edit:
            relations_edit(rels)
        tmp = Path(tempfile.mkdtemp(prefix="sou128-mutated-"))
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        (tmp / "c.json").write_text(json.dumps(corpus), encoding="utf-8")
        (tmp / "r.json").write_text(json.dumps(rels), encoding="utf-8")
        return gate("--modes", "direct", "--corpus", tmp / "c.json", "--relations", tmp / "r.json")

    def test_cited_source_drift_is_refused(self):
        def drift(rels):
            rels["relations"][0]["sources"][1]["sha256"] = "0" * 64
        done, report = self.mutated(relations_edit=drift)
        self.assertEqual(done.returncode, 3)
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


if __name__ == "__main__":
    unittest.main()
