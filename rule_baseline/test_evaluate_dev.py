# SPDX-License-Identifier: Apache-2.0
"""Tests for evaluate_dev.py (SOU-14, PR 3). They use a few synthetic cases, not the SOU-13 package.

The regressions cover the four defects found in the review of PR #81: tri-state labels, output
validation and technical failures, validated latency samples, and one captured source.
"""
import json
import os
import sys
import tempfile
import unittest

import evaluate_dev as ev

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSIFIER = os.path.join(HERE, "rule_baseline.py")


def targets(true=(), unknown=()):
    return {a: (True if a in true else None if a in unknown else False) for a in ev.ACTIONS}


def rec(i, true=(), actions=(), unknown=False, expected_unknown=False, unlabelled=(), error=None, family="fam.x"):
    return {"id": i, "family": family, "targets": targets(true, unlabelled), "expected_unknown": expected_unknown,
            "technical_error": error, "actions": list(actions), "unknown": unknown}


class Score(unittest.TestCase):
    def test_actions_with_unknown_targets_are_not_false_positives(self):
        # review finding 1: all targets null, mask 0, contract_view {actions: [], unknown: true}
        recs = [rec(str(i), unlabelled=ev.ACTIONS, actions=["read"], unknown=True, expected_unknown=True) for i in range(3)]
        s = ev.score(recs)
        read = s["per_label"]["read"]
        self.assertEqual((read["fp"], read["tp"], read["known_true"], read["known_false"]), (0, 0, 0, 0))
        self.assertIsNone(read["precision"])
        self.assertEqual((read["unlabelled"], read["reported_on_unlabelled"]), (3, 3))

    def test_known_false_counts_as_false_positive_and_known_true_as_found_or_missed(self):
        s = ev.score([
            rec("a", true=["read"], actions=["read"]),
            rec("b", true=["write"], actions=["write", "read"]),     # extra read on a known-false target
            rec("c", true=["delete"], actions=[], unknown=True),     # missed, flagged unknown
        ])
        self.assertEqual(s["exact"], 1)
        r = s["per_label"]["read"]
        self.assertEqual((r["known_true"], r["tp"], r["fp"], r["tn"]), (1, 1, 1, 1))
        self.assertEqual((s["per_label"]["delete"]["fn"], s["per_label"]["write"]["tp"]), (1, 1))

    def test_fully_annotated_exact_is_separate_from_partial_label_matching(self):
        s = ev.score([
            rec("full_ok", true=["read"], actions=["read"]),
            rec("full_bad", true=["read"], actions=["write"]),
            rec("part_ok", true=["read"], unlabelled=["write"], actions=["read", "write"], unknown=True, expected_unknown=True),
            rec("part_bad", true=["read"], unlabelled=["write"], actions=["send_data"], unknown=True, expected_unknown=True),
        ])
        a = s["annotation"]
        self.assertEqual((a["fully_annotated"], a["fully_annotated_exact"]), (2, 1))
        self.assertEqual((a["partial"], a["partial_known_labels_ok"], a["partial_contract_exact"]), (2, 1, 0))

    def test_silent_miss_needs_a_known_true_risky_label_and_unknown_false(self):
        s = ev.score([
            rec("silent", true=["write", "delete"], actions=["write"]),
            rec("flagged", true=["write", "delete"], actions=["write"], unknown=True),
            rec("read_only_miss", true=["read"], actions=[]),
            rec("unlabelled_risky", true=["read"], unlabelled=["delete"], actions=["read"]),
        ])
        c = s["critical"]
        self.assertEqual((c["silent_risky_miss_cases"], c["silent_risky_miss_pairs"], c["risky_miss_flagged_unknown_pairs"]), (1, 1, 1))
        self.assertEqual(c["silent_pairs"], [("silent", "delete")])

    def test_mixed_cases_are_counted_apart(self):
        s = ev.score([
            rec("m1", true=["write", "send_data"], actions=["write", "send_data"]),
            rec("m2", true=["write", "send_data"], actions=["write"]),
            rec("m3", true=["write", "send_data"], actions=["write"], unknown=True),
            rec("s1", true=["read"], actions=["read", "send_data"]),
        ])
        m = s["mixed"]
        self.assertEqual((m["cases"], m["exact_set"], m["all_found"], m["silent_miss"], m["flagged_miss"]), (3, 1, 1, 1, 1))
        self.assertEqual(m["single_expected_but_several_reported"], 1)

    def test_abstention_and_coverage_use_all_cases_as_denominator(self):
        s = ev.score([
            rec("u1", unknown=True, expected_unknown=True),                       # right abstention
            rec("u2", true=["read"], unknown=True),                               # coverage lost
            rec("u3", expected_unknown=True),                                     # confident on an unknown case
            rec("k1", true=["read"], actions=["read"]),
        ])
        a = s["abstention"]
        self.assertEqual((a["expected_unknown"], a["reported_unknown"], a["full_abstain"]), (2, 2, 2))
        self.assertEqual((a["unknown_when_expected_unknown"], a["unknown_when_expected_known"], a["confident_when_expected_unknown"]), (1, 1, 1))
        self.assertEqual((a["answered"], s["coverage"]), (2, 0.5))
        self.assertEqual(s["exact_on_answered"], 0.5)

    def test_technical_failures_count_against_the_case_total_and_are_never_exact(self):
        s = ev.score([rec("ok", true=["read"], actions=["read"]), rec("err", true=["read"], error="invalid_output: x")])
        self.assertEqual((s["cases"], s["scored"], s["technical_failures"], s["exact"], s["coverage"]), (2, 1, 1, 1, 0.5))
        self.assertEqual(s["per_label"]["read"]["known_true"], 1)  # the failed case is not scored per label

    def test_blanket_refusal_scores_only_the_unknown_cases_and_is_never_a_silent_miss(self):
        cases = {"s": [
            {"id": "1", "family": "f", "input": {}, "targets": targets(["delete"]), "expected_unknown": False},
            {"id": "2", "family": "f", "input": {}, "targets": targets(unknown=ev.ACTIONS), "expected_unknown": True},
        ]}
        s = ev.score(ev.reference(cases, [], True)["s"])
        self.assertEqual((s["exact"], s["critical"]["silent_risky_miss_cases"], s["coverage"]), (1, 0, 0.0))

    def test_empty_input_does_not_divide_by_zero(self):
        s = ev.score([])
        self.assertEqual((s["scored"], s["coverage"], s["exact_on_answered"]), (0, None, None))


def label(cid="c", true=(), unknown=(), view=None, mask=None):
    t = targets(true, unknown)
    m = mask or {a: 0 if t[a] is None else 1 for a in ev.ACTIONS}
    return {"id": cid, "per_action_targets": t, "known_mask": m,
            "contract_view": view or {"actions": sorted(true), "unknown": bool(unknown)}}


class LabelValidation(unittest.TestCase):
    def test_a_consistent_label_returns_its_tri_state_targets(self):
        t = ev.validate_label(label(true=["read"], unknown=["write"]))
        self.assertEqual((t["read"], t["write"], t["delete"]), (True, None, False))

    def test_mask_and_target_must_agree(self):
        m = {a: 1 for a in ev.ACTIONS}
        with self.assertRaises(ev.DataError):
            ev.validate_label(label(unknown=["write"], mask=m))

    def test_contract_view_must_match_the_true_targets(self):
        with self.assertRaises(ev.DataError):
            ev.validate_label(label(true=["read"], view={"actions": ["write"], "unknown": False}))

    def test_missing_fields_and_bad_values_are_refused(self):
        bad = label(true=["read"])
        del bad["known_mask"]
        with self.assertRaises(ev.DataError):
            ev.validate_label(bad)
        bad = label(true=["read"])
        bad["per_action_targets"]["read"] = "yes"
        with self.assertRaises(ev.DataError):
            ev.validate_label(bad)


def fake_classifier(body):
    return {"classify": body}


class RunClassifier(unittest.TestCase):
    CASES = {"s": [{"id": "1", "family": "f", "input": {"tool_name": "x"}, "targets": targets(["read"]), "expected_unknown": False}]}

    def run_with(self, fn):
        recs = ev.run_classifier(fn, self.CASES)["s"]
        return recs[0], ev.score(recs)

    def test_empty_object_is_a_technical_failure_not_a_no_op(self):
        r, s = self.run_with(lambda e: {})
        self.assertIn("invalid_output", r["technical_error"])
        self.assertEqual((s["technical_failures"], s["exact"]), (1, 0))

    def test_malformed_outputs_are_technical_failures(self):
        bad = [
            None, [], "ok",
            {"status": "weird", "actions": [], "unknown": False},
            {"actions": "read", "unknown": False},
            {"actions": ["read", "read"], "unknown": False},
            {"actions": ["unknown"], "unknown": True},
            {"actions": [], "unknown": "no"},
            {"actions": [], "unknown": 0},
            {"actions": ["read"], "unknown": False, "confidence": True},
            {"actions": ["read"], "unknown": False, "confidence": 2},
            {"actions": ["read"], "unknown": False, "uncertainty": float("nan")},
        ]
        for out in bad:
            with self.subTest(out=out):
                r, s = self.run_with(lambda e, o=out: o)
                self.assertIsNotNone(r["technical_error"])
                self.assertEqual(s["exact"], 0)

    def test_status_error_is_a_technical_failure(self):
        r, _ = self.run_with(lambda e: {"status": "error", "actions": [], "unknown": True, "reason": "x"})
        self.assertIn("classifier_reported_error", r["technical_error"])

    def test_an_exception_is_a_technical_failure_and_does_not_abort_the_run(self):
        def boom(e):
            raise RuntimeError("secret detail")
        r, s = self.run_with(boom)
        self.assertEqual(r["technical_error"], "exception: RuntimeError")  # the message is not copied
        self.assertEqual((s["technical_failures"], s["exact"]), (1, 0))

    def test_a_valid_answer_is_scored(self):
        r, s = self.run_with(lambda e: {"status": "ok", "actions": ["read"], "unknown": False})
        self.assertIsNone(r["technical_error"])
        self.assertEqual(s["exact"], 1)

    def test_the_classifier_cannot_change_the_case_through_its_input(self):
        def mutate(e):
            e["tool_name"] = "changed"
            return {"actions": ["read"], "unknown": False}
        ev.run_classifier(mutate, self.CASES)
        self.assertEqual(self.CASES["s"][0]["input"]["tool_name"], "x")

    def test_check_output_matches_the_reviewed_runner_when_the_repository_is_present(self):
        path = os.path.join(HERE, "..", "eval", "eval_runner.py")
        if not os.path.exists(path):
            self.skipTest("eval/eval_runner.py not found")
        import importlib.util
        spec = importlib.util.spec_from_file_location("reviewed_eval_runner", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        samples = [None, {}, [], "x", {"actions": [], "unknown": False}, {"status": "ok", "actions": ["read"], "unknown": False},
                   {"status": "error", "actions": [], "unknown": True}, {"status": "x", "actions": [], "unknown": False},
                   {"actions": ["read", "read"], "unknown": False}, {"actions": ["nope"], "unknown": False},
                   {"actions": [], "unknown": "no"}, {"actions": [], "unknown": False, "confidence": 1.5},
                   {"actions": [], "unknown": False, "confidence": True}, {"actions": [], "unknown": False, "uncertainty": 0.5}]
        for out in samples:
            with self.subTest(out=out):
                self.assertEqual(ev.check_output(out) is None, mod.check_output(out) is None)


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


SAME_SIZE_A = 'def classify(e):\n    return {"actions": ["read"], "unknown": False}\n'
SAME_SIZE_B = 'def classify(e):\n    return {"actions": ["read"], "unknown": True }\n'
GOOD_LOOP = (
    "import json, sys\n"
    "def classify(e):\n    return {'status': 'ok', 'actions': [], 'unknown': False}\n"
    "def main():\n"
    "    for line in sys.stdin:\n"
    "        print(json.dumps(classify(json.loads(line))), flush=True)\n"
    "if __name__ == '__main__':\n    main()\n"
)


class CapturedSource(unittest.TestCase):
    def test_same_size_rewrite_with_the_same_mtime_runs_the_new_bytes_and_records_their_digest(self):
        # review finding 4: a timestamp-based cached .pyc used to run the old code under the new digest
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.py")
            write(path, SAME_SIZE_A)
            st = os.stat(path)
            first = ev.Snapshot(path, "x")
            self.assertEqual(first.classify({})["unknown"], False)
            first.close()
            write(path, SAME_SIZE_B)
            self.assertEqual(os.path.getsize(path), len(SAME_SIZE_A))
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
            second = ev.Snapshot(path, "x")
            self.addCleanup(second.close)
            self.assertEqual(second.classify({})["unknown"], True)
            self.assertEqual(second.sha256, ev.sha256_file(path))
            self.assertNotEqual(first.sha256, second.sha256)

    def test_drift_after_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.py")
            write(path, SAME_SIZE_A)
            snap = ev.Snapshot(path, "x")
            self.addCleanup(snap.close)
            snap.verify_unchanged()
            write(path, SAME_SIZE_B)
            with self.assertRaises(ev.SourceDrift):
                snap.verify_unchanged()

    def test_process_measurements_run_the_snapshot_not_the_file_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.py")
            write(path, GOOD_LOOP)
            snap = ev.Snapshot(path, "x")
            self.addCleanup(snap.close)
            write(path, "raise SystemExit(5)\n")  # drift on disk must not reach the measured processes
            cases = {"s": [{"input": {"tool_name": "x"}}]}
            lat = ev.latency(snap, cases, calls=3, spawns=2, timeout=5)
            self.assertEqual((lat["warm_process_round_trip"]["valid"], lat["cold_process_per_call"]["valid"]), (3, 2))
            with self.assertRaises(ev.SourceDrift):
                snap.verify_unchanged()

    def test_a_snapshot_with_a_wrong_digest_does_not_start(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.py")
            write(path, GOOD_LOOP)
            snap = ev.Snapshot(path, "x")
            self.addCleanup(snap.close)
            argv = snap.argv()[:-1] + ["0" * 64]
            done = subprocess.run(argv, input="{}\n", capture_output=True, text=True, timeout=10)
            self.assertEqual((done.returncode, done.stdout), (97, ""))


class LatencySamples(unittest.TestCase):
    CASES = {"s": [{"input": {"tool_name": "x"}}]}

    def measure(self, source, calls=2, spawns=1, timeout=0.5):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.py")
            write(path, source)
            snap = ev.Snapshot(path, "x")
            try:
                return ev.latency(snap, self.CASES, calls, spawns, timeout)
            finally:
                snap.close()

    def test_a_valid_classifier_gives_a_timed_sample_for_every_attempt(self):
        lat = self.measure(GOOD_LOOP, calls=4, spawns=2, timeout=5)
        for key, n in (("in_process_call", 4), ("warm_process_round_trip", 4), ("cold_process_per_call", 2)):
            s = lat[key]
            self.assertEqual((s["attempts"], s["valid"], s["failed"], s["timed_out"]), (n, n, 0, 0))
            self.assertIn("p50_ms", s)

    def test_invalid_replies_are_failures_not_timing_samples(self):
        # review finding 3: {} in process and "not-json" on stdout used to be timed as successes
        src = ("import sys\n"
               "def classify(e):\n    return {}\n"
               "def main():\n    for line in sys.stdin:\n        print('not-json', flush=True)\n"
               "if __name__ == '__main__':\n    main()\n")
        lat = self.measure(src, calls=3, spawns=2, timeout=5)
        for key, n in (("in_process_call", 3), ("warm_process_round_trip", 3), ("cold_process_per_call", 2)):
            s = lat[key]
            self.assertEqual((s["attempts"], s["valid"], s["failed"]), (n, 0, n))
            self.assertNotIn("p50_ms", s)

    def test_a_valid_looking_line_that_is_not_a_classification_is_a_failure(self):
        src = ("import sys\n"
               "def classify(e):\n    return {'actions': [], 'unknown': False}\n"
               "def main():\n    for line in sys.stdin:\n        print('{\"actions\": \"read\"}', flush=True)\n"
               "if __name__ == '__main__':\n    main()\n")
        lat = self.measure(src, calls=2, spawns=1, timeout=5)
        self.assertEqual((lat["warm_process_round_trip"]["valid"], lat["warm_process_round_trip"]["failed"]), (0, 2))

    def test_nonzero_exit_status_is_a_failure_even_with_a_valid_line(self):
        src = ("import sys\n"
               "def classify(e):\n    return {'actions': [], 'unknown': False}\n"
               "def main():\n    print('{\"actions\": [], \"unknown\": false}')\n    sys.exit(3)\n"
               "if __name__ == '__main__':\n    main()\n")
        lat = self.measure(src, calls=1, spawns=2, timeout=5)
        self.assertEqual((lat["cold_process_per_call"]["valid"], lat["cold_process_per_call"]["failed"]), (0, 2))

    def test_a_hung_process_times_out_without_blocking_and_is_counted(self):
        src = ("import sys, time\n"
               "def classify(e):\n    return {'actions': [], 'unknown': False}\n"
               "def main():\n    sys.stdin.readline()\n    time.sleep(60)\n"
               "if __name__ == '__main__':\n    main()\n")
        lat = self.measure(src, calls=2, spawns=1, timeout=0.4)
        self.assertEqual((lat["warm_process_round_trip"]["attempts"], lat["warm_process_round_trip"]["timed_out"],
                          lat["warm_process_round_trip"]["valid"]), (2, 2, 0))
        self.assertEqual((lat["cold_process_per_call"]["timed_out"], lat["cold_process_per_call"]["valid"]), (1, 0))

    def test_an_exception_in_process_is_a_failed_attempt(self):
        src = "def classify(e):\n    raise ValueError('x')\n"
        lat = self.measure(src, calls=3, spawns=0, timeout=0.4)
        self.assertEqual((lat["in_process_call"]["failed"], lat["in_process_call"]["valid"]), (3, 0))

    def test_percentile_is_the_nearest_rank_of_sorted_values(self):
        self.assertEqual(ev.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(ev.percentile([1], 95), 1)


def write_export(root, rows, tamper=False):
    """rows: list of (id, tool_name, arguments, true actions, unknown actions)."""
    os.makedirs(os.path.join(root, "model_inputs"))
    os.makedirs(os.path.join(root, "labels"))
    hashes = {}
    for sp in ("train", "validation", "calibration"):
        ins, labs = [], []
        for cid, name, args, true, unk in rows:
            ins.append({"id": f"{sp}-{cid}", "input": {"tool_name": name, "raw_arguments": args, "tool_description": "",
                                                          "tool_schema": {}, "server_id": "s"}})
            lab = label(f"{sp}-{cid}", true=true, unknown=unk)
            lab.update(family_id=f"fam.{name}", label_status="provisional")
            labs.append(lab)
        for kind, items in (("model_inputs", ins), ("labels", labs)):
            path = os.path.join(root, kind, f"{sp}.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(x) + "\n" for x in items))
            hashes[f"{kind}/{sp}.jsonl"] = ev.sha256_file(path)
    if tamper:
        hashes["labels/train.jsonl"] = "0" * 64
    with open(os.path.join(root, "EXPORT_MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump({"status": "DRAFT", "cp2_version": "test", "files_sha256": hashes}, f)


ROWS = [
    ("1", "read_file", {"path": "a.txt"}, ["read"], []),
    ("2", "delete_file", {"path": "a.txt"}, ["delete"], []),
    ("3", "send_email", {"to": "a@example.test", "body": "hi"}, ["send_data"], []),
]


class LoadAndRun(unittest.TestCase):
    def test_load_cases_keeps_tri_state_targets_and_checks_the_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            write_export(d, ROWS + [("4", "mystery", {"x": 1}, [], list(ev.ACTIONS))])
            cases, prov = ev.load_cases(d)
            self.assertEqual({k: len(v) for k, v in cases.items()}, {"train": 4, "validation": 4, "calibration": 4})
            self.assertEqual((prov["manifest_check"], prov["label_status"]), ("ok", {"provisional": 12}))
            self.assertEqual(cases["train"][1]["targets"]["delete"], True)
            self.assertIsNone(cases["train"][3]["targets"]["read"])
            self.assertTrue(cases["train"][3]["expected_unknown"])

    def test_an_inconsistent_label_stops_the_load(self):
        with tempfile.TemporaryDirectory() as d:
            write_export(d, ROWS)
            path = os.path.join(d, "labels", "train.jsonl")
            with open(path, encoding="utf-8") as fh:
                rows = [json.loads(x) for x in fh]
            rows[0]["known_mask"]["read"] = 0
            write(path, "".join(json.dumps(x) + "\n" for x in rows))
            with self.assertRaises(ev.DataError):
                ev.load_cases(d)

    def test_a_changed_export_file_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            write_export(d, ROWS, tamper=True)
            self.assertIn("MISMATCH", ev.load_cases(d)[1]["manifest_check"])

    def test_end_to_end_writes_json_and_markdown_with_the_caveats(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write_export(d, ROWS + [("4", "mystery", {"x": 1}, [], list(ev.ACTIONS))])
            code = ev.main(["--exports", d, "--classifier", CLASSIFIER, "--baseline", CLASSIFIER, "--baseline-label", "same",
                            "--out-dir", out, "--latency-calls", "5", "--latency-spawns", "2"])
            self.assertEqual(code, 0)
            with open(os.path.join(out, "evaluation.json"), encoding="utf-8") as f:
                res = json.load(f)
            cand = res["classifiers"]["candidate"]
            self.assertEqual((cand["all"]["cases"], cand["all"]["technical_failures"]), (12, 0))
            self.assertEqual(cand["all"]["exact"], 12)
            self.assertEqual(cand["all"]["per_label"]["read"]["unlabelled"], 3)
            self.assertEqual(cand["latency"]["warm_process_round_trip"]["valid"], 5)
            self.assertEqual(cand["latency"]["cold_process_per_call"]["valid"], 2)
            self.assertEqual(cand["sha256"], ev.sha256_file(CLASSIFIER))
            with open(os.path.join(out, "EVALUATION.md"), encoding="utf-8") as f:
                md = f.read()
            self.assertIn("Development numbers, not a held-out result", md)
            self.assertIn("Provisional labels", md)
            self.assertIn("always abstain", md)
            self.assertNotIn("upper bound", md.replace("not a bound", ""))


if __name__ == "__main__":
    unittest.main()