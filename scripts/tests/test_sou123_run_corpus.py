# SPDX-License-Identifier: Apache-2.0
"""The SOU-123 reporter must not turn missing or wrong results into a green report."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou123_run_corpus", ROOT / "eval/sou123/run_corpus.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


def case(pair, side, label, klass="semantic", surface="git_show", category="code_comment_directive",
         language="en", position="middle"):
    return {"case_id": f"{pair}-{side}", "pair_id": pair, "label": label, "class": klass, "surface": surface,
            "category": category, "language": language, "position": position, "size_bytes": 10}


def manifest(*cases):
    return {"format": "sw-result-inspection-corpus/1", "cases": list(cases)}


def result(case_id, verdict, status="inspected", rule="r", micros=5):
    return {"case_id": case_id, "status": status, "verdict": verdict, "rule": rule, "latency_micros": micros}


class Classification(unittest.TestCase):
    def test_a_missed_attack_and_a_false_refusal_are_named_not_hidden(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"))
        report = RUN.build_report(pairs, [result("p1-a", "Deny"), result("p1-b", "Allow")], {})
        self.assertEqual(report["acceptance"], "fail")
        self.assertEqual(report["totals"]["missed_instructions"], 1)
        self.assertEqual(report["totals"]["false_refusals"], 1)
        self.assertEqual(report["pair_outcomes"]["both_wrong"], 1)

    def test_a_deny_on_the_attack_alone_is_not_acceptance_while_its_benign_twin_is_refused(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"))
        report = RUN.build_report(pairs, [result("p1-a", "Escalate"), result("p1-b", "Deny")], {})
        self.assertEqual(report["acceptance"], "fail")
        self.assertEqual(report["pair_outcomes"]["false_refusal_only"], 1)
        self.assertEqual(report["totals"]["missed_instructions"], 0)

    def test_acceptance_needs_every_attack_caught_and_every_benign_allowed(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"))
        report = RUN.build_report(pairs, [result("p1-a", "Allow"), result("p1-b", "Deny")], {})
        self.assertEqual(report["acceptance"], "pass")
        self.assertEqual(report["pair_outcomes"]["both_correct"], 1)

    def test_a_missing_result_is_unknown_and_never_counted_as_caught_or_allowed(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"))
        report = RUN.build_report(pairs, [result("p1-a", "Allow")], {})
        self.assertEqual(report["acceptance"], "fail")
        self.assertEqual(report["totals"]["unknown_or_technical_errors"], 1)
        self.assertEqual(report["totals"]["caught_instructions"], 0)
        self.assertEqual(report["pair_outcomes"]["incomplete"], 1)

    def test_a_not_inspected_result_is_unknown_even_when_it_carries_a_deny_verdict(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"))
        rows = [result("p1-a", "Allow"), result("p1-b", "Deny", status="over_budget_not_inspected")]
        report = RUN.build_report(pairs, rows, {})
        self.assertEqual(report["acceptance"], "fail")
        self.assertEqual(report["totals"]["caught_instructions"], 0)

    def test_an_empty_manifest_never_passes(self):
        self.assertEqual(RUN.build_report(manifest(), [], {})["acceptance"], "fail")

    def test_technical_cases_are_reported_separately_and_do_not_change_the_semantic_counts(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"),
                         case("t1", "a", "technical", klass="technical"))
        rows = [result("p1-a", "Allow"), result("p1-b", "Deny"),
                result("t1-a", None, status="over_budget_not_inspected")]
        report = RUN.build_report(pairs, rows, {})
        self.assertEqual(report["denominators"]["technical_reported_separately"], 1)
        self.assertEqual(report["denominators"]["semantic_cases"], 2)
        self.assertEqual(report["acceptance"], "pass")

    def test_the_report_states_it_is_a_development_corpus_and_a_deny_is_not_prevention(self):
        report = RUN.build_report(manifest(case("p1", "a", "benign")), [result("p1-a", "Allow")], {"x": "y"})
        self.assertTrue(report["development_only"])
        self.assertIn("not proof of prevention", report["claim"])
        self.assertEqual(report["identities"], {"x": "y"})

    def test_breakdowns_count_by_surface_category_language_and_position(self):
        pairs = manifest(case("p1", "a", "benign", language="kk"), case("p1", "b", "attack", language="kk"))
        report = RUN.build_report(pairs, [result("p1-a", "Deny"), result("p1-b", "Allow")], {})
        self.assertEqual(report["by_language"]["kk"], {"attack": 1, "caught": 0, "benign": 1, "false_refusals": 1})

    def test_latency_percentiles_use_only_reported_values(self):
        pairs = manifest(case("p1", "a", "benign"), case("p1", "b", "attack"))
        rows = [result("p1-a", "Allow", micros=10), result("p1-b", "Deny", micros=None)]
        stats = RUN.build_report(pairs, rows, {})["latency_micros"]
        self.assertEqual((stats["count"], stats["max"]), (1, 10))


class Inputs(unittest.TestCase):
    def test_payloads_that_differ_from_the_frozen_digest_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "p1-a.txt").write_bytes(b"changed")
            entry = dict(case("p1", "a", "benign"), sha256=RUN.sha(b"original"))
            self.assertIn("differs from the frozen manifest", RUN.verify_payloads(manifest(entry), tmp)[0])

    def test_a_missing_payload_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry = dict(case("p1", "a", "benign"), sha256=RUN.sha(b"x"))
            self.assertIn("payload missing", RUN.verify_payloads(manifest(entry), tmp)[0])

    def test_an_unknown_manifest_format_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "m.json")
            path.write_text(json.dumps({"format": "other", "cases": []}))
            with self.assertRaises(SystemExit):
                RUN.load_manifest(path)

    def test_the_committed_manifest_matches_its_payloads(self):
        base = ROOT / "eval/sou123"
        loaded = RUN.load_manifest(base / "manifest.json")
        self.assertEqual(RUN.verify_payloads(loaded, base / "payloads"), [])
        pairs = {c["pair_id"] for c in loaded["cases"] if c["class"] == "semantic"}
        self.assertEqual(len(pairs), 24)
        for pair in pairs:
            labels = sorted(c["label"] for c in loaded["cases"] if c["pair_id"] == pair)
            self.assertEqual(labels, ["attack", "benign"])

    @unittest.skipUnless(os.name == "posix", "the fake adapter is a shell script")
    def test_the_guide_states_the_digests_of_the_frozen_artifacts(self):
        guide = (ROOT / "docs/operations/RESULT_INSPECTION_CORPUS.md").read_text(encoding="utf-8")
        for name in ("manifest.json", "baseline-main-4828cf35.json", "baseline-main-adefce2a.json",
                     "effect-controls-main-adefce2a.json"):
            digest = RUN.sha((ROOT / "eval/sou123" / name).read_bytes())
            self.assertIn(digest, guide, name + " digest in the guide is stale")

    def test_retained_baselines_use_the_committed_manifest_and_stay_non_passing(self):
        manifest_digest = RUN.sha((ROOT / "eval/sou123/manifest.json").read_bytes())
        for name in ("baseline-main-4828cf35.json", "baseline-main-adefce2a.json"):
            report = json.loads((ROOT / "eval/sou123" / name).read_text(encoding="utf-8"))
            self.assertEqual(report["format"], RUN.FORMAT)
            self.assertEqual(report["identities"]["manifest_sha256"], manifest_digest)
            self.assertEqual(report["acceptance"], "fail")  # real failures stay visible until the detector changes
            self.assertEqual(len(report["cases"]), 51)

    def test_the_main_entry_point_returns_two_for_a_refusal_and_one_for_a_failing_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "payloads").mkdir()
            (tmp / "payloads/p1-a.txt").write_bytes(b"x")
            entry = dict(case("p1", "a", "benign"), sha256=RUN.sha(b"x"))
            (tmp / "m.json").write_text(json.dumps(manifest(entry)))
            adapter = tmp / "adapter.sh"
            adapter.write_text('#!/bin/sh\necho \'{"results":[{"case_id":"p1-a","status":"inspected","verdict":"Deny","rule":"r","latency_micros":3}]}\'\n')
            adapter.chmod(0o755)
            (tmp / "policy.yaml").write_text("x: y\n")
            args = ["--manifest", str(tmp / "m.json"), "--payload-dir", str(tmp / "payloads"),
                    "--adapter", str(adapter), "--policy", str(tmp / "policy.yaml"), "--output", str(tmp / "r.json")]
            self.assertEqual(RUN.main(args), 1)
            self.assertEqual(json.loads((tmp / "r.json").read_text())["totals"]["false_refusals"], 1)
            (tmp / "payloads/p1-a.txt").write_bytes(b"changed")
            self.assertEqual(RUN.main(args), 2)


if __name__ == "__main__":
    unittest.main()
