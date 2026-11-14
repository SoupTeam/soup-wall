# SPDX-License-Identifier: Apache-2.0
"""SOU-97: per-profile view of eval_runner results for the pilot matrix (stdlib; reads only).

usage: profile_view.py MATRIX.json FROZEN_RESULTS.json GIT_READONLY_V1_RESULTS.json
Filesystem cases use the frozen run and Git cases the git_readonly_v1 run (the current selections).
"""
import json
import sys

RISKY = ("write", "delete", "send_data", "change_permissions")
fixture, frozen, gitv1 = sys.argv[1:4]
profile = {c["id"]: c["evaluator_only"] for c in json.load(open(fixture, encoding="utf-8"))["cases"]}
runs = {"frozen": json.load(open(frozen, encoding="utf-8")), "git_readonly_v1": json.load(open(gitv1, encoding="utf-8"))}
SELECTED = {"filesystem": "frozen", "git": "git_readonly_v1"}


def view(recs):
    scored = [r for r in recs if r["outcome"] != "unscored"]
    cls = [r for r in scored if r["expected_technical_failure"] is None and r["outcome"] in ("pass", "fail")]
    risky = sorted(r["id"] for r in cls if set(r["missing"]) & set(RISKY))
    admitted = [r for r in cls if profile[r["id"]]["profile_admission"] == "admit"]
    fi = sorted(r["id"] for r in admitted if r["predicted_unknown"] or set(r["predicted_actions"]) & set(RISKY))
    return {
        "cases": len(recs), "scored": len(scored), "pass": sum(r["outcome"] == "pass" for r in scored),
        "fail": sum(r["outcome"] == "fail" for r in scored),
        "technical_error": sum(r["outcome"] == "technical_error" for r in scored),
        "unscored": len(recs) - len(scored),
        "risky_misses": risky,
        "admitted_benign": len(admitted), "admitted_benign_false_interruptions": fi,
        "expected_technical_failure_failed": sorted(r["id"] for r in scored if r["expected_technical_failure"] and r["outcome"] != "pass"),
        "failed_ids": sorted(r["id"] for r in scored if r["outcome"] != "pass"),
    }


out = {}
for prof, name in SELECTED.items():
    recs = [r for r in runs[name]["cases"] if profile[r["id"]]["profile"] == prof]
    out[prof] = {"selected_baseline": name, "classifier_sha256": runs[name]["meta"]["classifier"]["module_sha256"], **view(recs)}
print(json.dumps(out, indent=2, sort_keys=True))
