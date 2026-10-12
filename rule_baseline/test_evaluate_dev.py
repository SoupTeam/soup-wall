# SPDX-License-Identifier: Apache-2.0
"""Tests for evaluate_dev.py (SOU-14, PR 3). They use a few synthetic cases, not the SOU-13 package."""
import json
import os
import tempfile
import unittest

import evaluate_dev as ev

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSIFIER = os.path.join(HERE, "rule_baseline.py")


def rec(i, expected, actions, unknown=False, expected_unknown=False, status=None, family="fam.x"):
    return {"id": i, "family": family, "expected": expected, "expected_unknown": expected_unknown,
            "actions": actions, "unknown": unknown, "status": status or ("unknown" if unknown else "ok")}


class Score(unittest.TestCase):
    def test_exact_and_per_label_counts(self):
        s = ev.score([
            rec("a", ["read"], ["read"]),
            rec("b", ["write"], ["write", "read"]),      # one extra read
            rec("c", ["delete"], [], unknown=True),      # missed but flagged
        ])
        self.assertEqual((s["scored"], s["exact"]), (3, 1))
        self.assertEqual(s["per_label"]["read"], {"support": 1, "tp": 1, "fp": 1, "fn": 0, "precision": 0.5, "recall": 1.0})
        self.assertEqual(s["per_label"]["delete"]["fn"], 1)

    def test_silent_miss_is_only_a_miss_with_unknown_false(self):
        s = ev.score([
            rec("silent", ["write", "delete"], ["write"]),
            rec("flagged", ["write", "delete"], ["write"], unknown=True),
            rec("read_only_miss", ["read"], []),         # read is not a risky label
        ])
        c = s["critical"]
        self.assertEqual((c["silent_risky_miss_cases"], c["silent_risky_miss_pairs"], c["risky_miss_flagged_unknown_pairs"]), (1, 1, 1))
        self.assertEqual(c["silent_pairs"], [("silent", "delete")])

    def test_mixed_cases_are_counted_apart(self):
        s = ev.score([
            rec("m1", ["write", "send_data"], ["write", "send_data"]),
            rec("m2", ["write", "send_data"], ["write"]),
            rec("m3", ["write", "send_data"], ["write"], unknown=True),
            rec("s1", ["read"], ["read", "send_data"]),
        ])
        m = s["mixed"]
        self.assertEqual((m["cases"], m["exact_set"], m["all_found"], m["silent_miss"], m["flagged_miss"]), (3, 1, 1, 1, 1))
        self.assertEqual(m["single_expected_but_several_reported"], 1)

    def test_abstention_and_coverage_denominators(self):
        s = ev.score([
            rec("u1", [], [], unknown=True, expected_unknown=True),       # right abstention
            rec("u2", ["read"], [], unknown=True),                         # coverage lost
            rec("u3", [], [], expected_unknown=True),                      # confident on an unknown case
            rec("k1", ["read"], ["read"]),
        ])
        a = s["abstention"]
        self.assertEqual((a["expected_unknown"], a["reported_unknown"], a["full_abstain"]), (2, 2, 2))
        self.assertEqual((a["unknown_when_expected_unknown"], a["unknown_when_expected_known"], a["confident_when_expected_unknown"]), (1, 1, 1))
        self.assertEqual((a["answered"], s["coverage"]), (2, 0.5))
        self.assertEqual(s["exact_on_answered"], 0.5)

    def test_technical_failures_are_not_scored_as_answers(self):
        s = ev.score([rec("ok", ["read"], ["read"]), rec("err", ["read"], [], status="error")])
        self.assertEqual((s["cases"], s["scored"], s["technical_failures"], s["exact"]), (2, 1, 1, 1))

    def test_blanket_refusal_scores_only_the_unknown_cases_and_is_never_a_silent_miss(self):
        cases = {"s": [
            {"id": "1", "family": "f", "input": {}, "expected": ["delete"], "expected_unknown": False},
            {"id": "2", "family": "f", "input": {}, "expected": [], "expected_unknown": True},
        ]}
        s = ev.score(ev.always_abstain(cases)["s"])
        self.assertEqual((s["exact"], s["critical"]["silent_risky_miss_cases"], s["coverage"]), (1, 0, 0.0))

    def test_empty_input_does_not_divide_by_zero(self):
        s = ev.score([])
        self.assertEqual((s["scored"], s["coverage"], s["exact_on_answered"]), (0, None, None))


def write_export(root, rows, tamper=False):
    """rows: list of (id, tool_name, arguments, actions, unknown)."""
    os.makedirs(os.path.join(root, "model_inputs"))
    os.makedirs(os.path.join(root, "labels"))
    hashes = {}
    for sp in ("train", "validation", "calibration"):
        ins, labs = [], []
        for i, (cid, name, args, actions, unknown) in enumerate(rows):
            ins.append({"id": f"{sp}-{cid}", "input": {"tool_name": name, "raw_arguments": args, "tool_description": "",
                                                          "tool_schema": {}, "server_id": "s"}})
            labs.append({"id": f"{sp}-{cid}", "family_id": f"fam.{name}", "label_status": "provisional",
                         "contract_view": {"actions": actions, "unknown": unknown}})
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
    ("1", "read_file", {"path": "a.txt"}, ["read"], False),
    ("2", "delete_file", {"path": "a.txt"}, ["delete"], False),
    ("3", "send_email", {"to": "a@example.test", "body": "hi"}, ["send_data"], False),
]


class LoadAndRun(unittest.TestCase):
    def test_load_cases_joins_inputs_and_labels_and_checks_the_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            write_export(d, ROWS)
            cases, prov = ev.load_cases(d)
            self.assertEqual({k: len(v) for k, v in cases.items()}, {"train": 3, "validation": 3, "calibration": 3})
            self.assertEqual((prov["manifest_check"], prov["label_status"]), ("ok", {"provisional": 9}))
            self.assertEqual(cases["train"][1]["expected"], ["delete"])

    def test_a_changed_export_file_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            write_export(d, ROWS, tamper=True)
            self.assertIn("MISMATCH", ev.load_cases(d)[1]["manifest_check"])

    def test_end_to_end_writes_json_and_markdown_with_the_caveats(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            write_export(d, ROWS)
            code = ev.main(["--exports", d, "--classifier", CLASSIFIER, "--baseline", CLASSIFIER, "--baseline-label", "same",
                            "--out-dir", out, "--latency-calls", "5", "--latency-spawns", "1"])
            self.assertEqual(code, 0)
            with open(os.path.join(out, "evaluation.json"), encoding="utf-8") as f:
                res = json.load(f)
            cand = res["classifiers"]["candidate"]
            self.assertEqual((cand["all"]["scored"], cand["all"]["technical_failures"]), (9, 0))
            self.assertEqual(cand["all"]["exact"], 9)
            self.assertEqual(cand["latency"]["warm_process_round_trip"]["n"], 5)
            self.assertEqual(cand["latency"]["cold_process_per_call"]["n"], 1)
            self.assertEqual(cand["sha256"], ev.sha256_file(CLASSIFIER))
            with open(os.path.join(out, "EVALUATION.md"), encoding="utf-8") as f:
                md = f.read()
            self.assertIn("Development numbers, not a held-out result", md)
            self.assertIn("Provisional labels", md)
            self.assertIn("always abstain", md)

    def test_percentile_is_the_nearest_rank_of_sorted_values(self):
        self.assertEqual(ev.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(ev.percentile([1], 95), 1)


if __name__ == "__main__":
    unittest.main()
