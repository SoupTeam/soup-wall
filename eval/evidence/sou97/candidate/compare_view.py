# SPDX-License-Identifier: Apache-2.0
"""SOU-97: before/after view of eval_runner results (stdlib; reads only; classification only).

usage: compare_view.py MATRIX.json BEFORE_FROZEN.json BEFORE_GIT_READONLY_V1.json AFTER_CANDIDATE.json
Before = the classifier each profile selects today (filesystem: frozen, Git: git_readonly_v1).
"New" lists are cases the candidate gets worse than that selected baseline; they must be empty.
"""
import json
import sys

RISKY = ("write", "delete", "send_data", "change_permissions")
fixture, frozen, gitv1, after = sys.argv[1:5]
meta = {c["id"]: c["evaluator_only"] for c in json.load(open(fixture, encoding="utf-8"))["cases"]}
load = lambda p: {r["id"]: r for r in json.load(open(p, encoding="utf-8"))["cases"]}
runs = {"frozen": load(frozen), "git_readonly_v1": load(gitv1), "candidate": load(after)}
SELECTED = {"filesystem": "frozen", "git": "git_readonly_v1"}


def risky_miss(r):
    return r["outcome"] in ("pass", "fail") and r["expected_technical_failure"] is None and bool(set(r["missing"]) & set(RISKY))


def interruption(r):
    return (meta[r["id"]]["profile_admission"] == "admit" and r["outcome"] in ("pass", "fail")
            and (r["predicted_unknown"] or bool(set(r["predicted_actions"] or []) & set(RISKY))))


def technical(r):
    return r["outcome"] == "technical_error" or (r["technical_error"] and r["expected_technical_failure"] is None)


out = {}
for prof, name in SELECTED.items():
    ids = sorted(i for i in meta if meta[i]["profile"] == prof)
    before, cand = runs[name], runs["candidate"]
    sets = {}
    for label, run in (("before", before), ("after", cand)):
        scored = [run[i] for i in ids if run[i]["outcome"] != "unscored"]
        sets[label] = {
            "scored": len(scored), "pass": sum(r["outcome"] == "pass" for r in scored),
            "fail": sorted(r["id"] for r in scored if r["outcome"] == "fail"),
            "technical": sorted(r["id"] for r in scored if technical(r)),
            "risky_misses": sorted(r["id"] for r in scored if risky_miss(r)),
            "admitted_benign_false_interruptions": sorted(r["id"] for r in scored if interruption(r)),
            "expected_technical_failure_not_met": sorted(r["id"] for r in scored
                                                        if r["expected_technical_failure"] and r["outcome"] != "pass"),
        }
    b, a = sets["before"], sets["after"]
    out[prof] = {
        "before_classifier": name, **{f"before_{k}": v for k, v in b.items()}, **{f"after_{k}": v for k, v in a.items()},
        "newly_failing": sorted(set(a["fail"]) - set(b["fail"])),
        "newly_passing": sorted(set(b["fail"]) - set(a["fail"])),
        "new_risky_misses": sorted(set(a["risky_misses"]) - set(b["risky_misses"])),
        "new_technical_failures": sorted(set(a["technical"]) - set(b["technical"])),
        "new_benign_false_interruptions": sorted(set(a["admitted_benign_false_interruptions"])
                                                 - set(b["admitted_benign_false_interruptions"])),
        "core_changed": sorted(i for i in ids if (before[i]["predicted_actions"], before[i]["predicted_unknown"],
                                                   before[i]["failure_channel"]) != (cand[i]["predicted_actions"],
                                                   cand[i]["predicted_unknown"], cand[i]["failure_channel"])),
        "unscored_core_changed": sorted(i for i in ids if before[i]["outcome"] == "unscored" and
                                        (before[i]["predicted_actions"], before[i]["predicted_unknown"]) !=
                                        (cand[i]["predicted_actions"], cand[i]["predicted_unknown"])),
    }
out["candidate_classifier_sha256"] = json.load(open(after, encoding="utf-8"))["meta"]["classifier"]["module_sha256"]
print(json.dumps(out, indent=2, sort_keys=True))
