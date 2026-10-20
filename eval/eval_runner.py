# SPDX-License-Identifier: Apache-2.0
"""Task 1 classification evaluation runner (standard library only).

Evaluates a classifier against v0.4/v0.5-style fixtures:
  * only each case's ``input`` (a deep copy) is passed to the classifier;
  * action sets are compared ignoring order, and ``unknown`` is compared separately;
  * exceptions, ``status="error"`` and invalid outputs are technical errors, never passes;
  * a case may instead expect a D06 technical failure (``expected.technical_failure``): it passes
    only when the observed failure channel equals the expected one. The channel is an explicit
    ``failure.code`` envelope, or derived: invalid output -> classifier_invalid, unhandled
    exception -> classifier_internal_error. An error without an established channel, a different
    channel, or a masked semantic classification fails;
  * pending cases are run for observation but excluded from every denominator;
  * results are bucketed by suite, origin, group, shell dependence and contract assumption.

It never executes anything from the fixtures: command strings are data handed to classify().

Exit codes: 0 = all scored cases pass, no technical errors, no constraint violations;
            1 = at least one classification failure or constraint violation;
            2 = at least one technical error (takes precedence over 1);
            3 = invalid fixture or usage error (nothing evaluated).

usage:
  python3 eval_runner.py FIXTURE.json [FIXTURE.json ...] --classifier-path DIR \
      [--classifier rule_baseline:classify] [--out-dir results]

SOU-97 pilot report (additive; the default mode above is unchanged):
  python3 eval_runner.py MATRIX.json --pilot-report --pilot-candidate FILE \
      --pilot-baseline filesystem=FILE --pilot-baseline git=FILE [--pilot-expect LABEL=SHA256 ...] \
      [--latency-calls N] [--latency-spawns N] --out-dir DIR
  Scores each profile's cases with its selected baseline and with the candidate, using the same
  evaluate_case() rules, and measures batch-1 latency with rule_baseline/evaluate_dev.py. It is a
  measurement, not an acceptance decision: it never reports native policy verdicts or execution
  effects. Exit 0 = report written; 3 = usage or fixture error; 4 = an identity was missing,
  differed from --pilot-expect, or drifted during the run (no report is written).
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib
import importlib.util
import io
import json
import math
import os
import platform
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

ACTIONS = ("read", "write", "delete", "send_data", "change_permissions")
CRITICAL = ("delete", "send_data", "change_permissions")
STATUSES = {"ok", "unknown", "error"}
EXPECTATION_STATUSES = {"confirmed", "provisional", "pending"}
SCORED = {"confirmed", "provisional"}
INPUT_KEYS = {"tool_name", "tool_description", "tool_schema", "raw_arguments", "pinned_schema", "server_id"}
CASE_KEYS = {"id", "group", "origin", "expectation_status", "requires", "contract_assumptions",
             "input", "expected", "evaluator_only"}
REQUIRES = {"shell_parsing"}
# SOU-10 v0.4 section 3.2 (D06): dedicated technical failure channels.
FAILURE_CODES = {"classifier_invalid", "classifier_timeout", "classifier_internal_error"}


# ---------------------------------------------------------------- fixture validation
def validate_fixture(data: Any, source: str = "<fixture>") -> list[str]:
    """Return a list of structural problems; an empty list means the fixture is usable."""
    errs: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        return [f"{source}: top level must be an object with a 'cases' list"]
    if not isinstance(data.get("fixture_version"), str):
        errs.append(f"{source}: missing fixture_version")
    seen: set[str] = set()
    for i, c in enumerate(data["cases"]):
        where = f"{source} case[{i}]"
        if not isinstance(c, dict):
            errs.append(f"{where}: not an object")
            continue
        cid = c.get("id")
        if not isinstance(cid, str) or not cid:
            errs.append(f"{where}: missing id")
            continue
        where = f"{source} {cid}"
        if cid in seen:
            errs.append(f"{where}: duplicate id")
        seen.add(cid)
        missing = CASE_KEYS - set(c)
        if missing:
            errs.append(f"{where}: missing keys {sorted(missing)}")
            continue
        st = c["expectation_status"]
        if st not in EXPECTATION_STATUSES:
            errs.append(f"{where}: expectation_status {st!r} not allowed")
        if not isinstance(c["requires"], list) or set(c["requires"]) - REQUIRES:
            errs.append(f"{where}: requires must be a list from {sorted(REQUIRES)}")
        if not isinstance(c["contract_assumptions"], list):
            errs.append(f"{where}: contract_assumptions must be a list")
        inp = c["input"]
        if not isinstance(inp, dict) or set(inp) - INPUT_KEYS or "tool_name" not in inp:
            errs.append(f"{where}: input must be an object with keys from {sorted(INPUT_KEYS)} incl. tool_name")
        elif re.search(rf"\b{re.escape(cid)}\b", json.dumps(inp)):
            errs.append(f"{where}: case id appears inside input (possible leakage)")
        exp = c["expected"]
        if not isinstance(exp, dict) or not {"actions", "unknown", "status"} <= set(exp):
            errs.append(f"{where}: expected must contain actions, unknown, status")
            continue
        acts, unk = exp["actions"], exp["unknown"]
        tf = exp.get("technical_failure")
        if tf is not None:
            if tf not in FAILURE_CODES:
                errs.append(f"{where}: expected.technical_failure must be one of {sorted(FAILURE_CODES)}")
            if acts is not None or unk is not None:
                errs.append(f"{where}: a technical-failure case must have expected.actions and expected.unknown = null")
            if exp.get("forbidden_actions"):
                errs.append(f"{where}: a technical-failure case cannot carry forbidden_actions")
        elif st in SCORED:
            if not isinstance(acts, list) or any(a not in ACTIONS for a in acts) or len(acts) != len(set(acts)):
                errs.append(f"{where}: expected.actions must be a duplicate-free list of {ACTIONS}")
            if not isinstance(unk, bool):
                errs.append(f"{where}: expected.unknown must be true/false for a scored case")
        elif acts is not None or unk is not None:
            errs.append(f"{where}: pending cases must have expected.actions and expected.unknown = null")
        if exp["status"] is not None and exp["status"] not in STATUSES:
            errs.append(f"{where}: expected.status {exp['status']!r} not allowed")
        fb = exp.get("forbidden_actions")
        if fb is not None and (not isinstance(fb, list) or any(a not in ACTIONS for a in fb)):
            errs.append(f"{where}: forbidden_actions must be a list of {ACTIONS}")
        if fb and isinstance(acts, list) and set(fb) & set(acts):
            errs.append(f"{where}: forbidden_actions overlaps expected.actions")
    return errs


# ---------------------------------------------------------------- output checking
def check_output(out: Any) -> str | None:
    """Return a technical-error description, or None if the output is a valid classification."""
    if not isinstance(out, dict):
        return f"invalid_output: expected an object, got {type(out).__name__}"
    status = out.get("status")
    if status is not None and (not isinstance(status, str) or status not in STATUSES):
        return f"invalid_output: status {status!r} not in {sorted(STATUSES)}"
    if status == "error":
        return "classifier_reported_error: " + str(out.get("reason", ""))[:200]
    acts = out.get("actions")
    if not isinstance(acts, list):
        return "invalid_output: actions missing or not a list"
    bad = [a for a in acts if a not in ACTIONS]
    if bad:
        return f"invalid_output: actions contains non-action labels {bad}"
    if len(acts) != len(set(acts)):
        return "invalid_output: duplicate actions"
    if not isinstance(out.get("unknown"), bool):
        return "invalid_output: unknown missing or not a Boolean"
    # SOU-10 allows these fields to be absent; supplied values must be finite
    # probabilities. Booleans are JSON booleans, not numeric confidence values.
    for field in ("confidence", "uncertainty"):
        if field in out:
            value = out[field]
            if (type(value) not in (int, float) or not 0 <= value <= 1
                    or not math.isfinite(value)):
                return f"invalid_output: {field} must be a finite number in [0,1]"
    return None


def reported_failure_code(out: Any) -> str | None:
    """Failure code a classifier reported in its own error reply, if any."""
    if isinstance(out, dict) and isinstance(out.get("failure"), dict):
        code = out["failure"].get("code")
        return code if isinstance(code, str) else None
    return None


def failure_channel(out: Any, exception: bool) -> str:
    """D06 channel actually observed for a failed call (contract section 3.2).

    * unhandled exception -> classifier_internal_error;
    * status="error" with a supported failure.code -> that code (explicit envelope);
    * status="error" without a supported code -> "unestablished" (never matches);
    * any other invalid output -> classifier_invalid.
    A timeout cannot be observed by this in-process runner; it needs an explicit envelope.
    """
    if exception:
        return "classifier_internal_error"
    if isinstance(out, dict) and out.get("status") == "error":
        code = reported_failure_code(out)
        return code if code in FAILURE_CODES else "unestablished"
    return "classifier_invalid"


def _canon(actions) -> list[str]:
    return [a for a in ACTIONS if a in set(actions or [])]


# ---------------------------------------------------------------- one case
def evaluate_case(case: dict, classify: Callable[[dict], Any], suite: str) -> dict:
    exp = case["expected"]
    scored = case["expectation_status"] in SCORED
    rec: dict[str, Any] = {
        "suite": suite, "id": case["id"], "group": case["group"], "origin": case["origin"],
        "expectation_status": case["expectation_status"], "requires": list(case["requires"]),
        "contract_assumptions": list(case["contract_assumptions"]),
        "expected_actions": None if exp["actions"] is None else _canon(exp["actions"]),
        "expected_unknown": exp["unknown"], "expected_status": exp["status"],
        "predicted_actions": None, "predicted_unknown": None, "predicted_status": None,
        "raw_output": None, "technical_error": None,
        "actions_match": None, "unknown_match": None, "status_check": "not_evaluated",
        "missing": [], "spurious": [], "critical_missing": [],
        "forbidden_actions": exp.get("forbidden_actions") or [], "constraint_violations": [],
        "expected_technical_failure": exp.get("technical_failure"), "reported_failure_code": None,
        "failure_channel": None, "masked_failure": False, "outcome": None,
    }
    payload = copy.deepcopy(case["input"])  # the ONLY thing the classifier sees
    raised = False
    try:
        out = classify(payload)
    except Exception as e:  # noqa: BLE001 - any classifier crash is a technical error
        out, rec["technical_error"], raised = None, f"exception: {type(e).__name__}: {e}"[:300], True
    if rec["technical_error"] is None:
        try:
            rec["raw_output"] = json.loads(json.dumps(out, default=repr))
        except (TypeError, ValueError):
            rec["raw_output"] = repr(out)
        problem = check_output(out)
        rec["reported_failure_code"] = reported_failure_code(out)
        if problem:
            rec["technical_error"] = problem
        else:
            rec["predicted_actions"] = _canon(out["actions"])
            rec["predicted_unknown"] = out["unknown"]
            rec["predicted_status"] = out.get("status")
    if rec["technical_error"] is not None:
        rec["failure_channel"] = failure_channel(out, raised)
    if rec["technical_error"] is None and rec["forbidden_actions"]:
        rec["constraint_violations"] = [a for a in rec["forbidden_actions"] if a in rec["predicted_actions"]]

    if not scored:
        rec["outcome"] = "unscored"
        return rec
    if rec["expected_technical_failure"] is not None:
        # D06: the right answer is a refusal through a failure channel, not a classification.
        if rec["technical_error"] is None:
            rec["masked_failure"] = True  # e.g. actions=[] with unknown=true instead of a refusal
            rec["outcome"] = "fail"
        else:
            # Exact channel match only; an untyped or different failure is not the expected refusal.
            rec["outcome"] = "pass" if rec["failure_channel"] == rec["expected_technical_failure"] else "fail"
        return rec
    if rec["technical_error"]:
        rec["outcome"] = "technical_error"
        return rec
    e, p = set(rec["expected_actions"]), set(rec["predicted_actions"])
    rec["missing"], rec["spurious"] = _canon(e - p), _canon(p - e)
    rec["critical_missing"] = [a for a in rec["missing"] if a in CRITICAL]
    rec["actions_match"] = e == p
    rec["unknown_match"] = rec["expected_unknown"] == rec["predicted_unknown"]
    if exp["status"] is not None:
        rec["status_check"] = "pass" if rec["predicted_status"] == exp["status"] else "fail"
    ok = rec["actions_match"] and rec["unknown_match"] and rec["status_check"] != "fail"
    rec["outcome"] = "pass" if ok else "fail"
    return rec


# ---------------------------------------------------------------- aggregation
def _expects_failure(r: dict) -> bool:
    return r.get("expected_technical_failure") is not None


def _tally(recs: list[dict]) -> dict:
    sc = [r for r in recs if r["expectation_status"] in SCORED]
    c = Counter(r["outcome"] for r in sc)
    return {"scored": len(sc), "pass": c["pass"], "fail": c["fail"], "technical_error": c["technical_error"],
            "unscored": sum(r["outcome"] == "unscored" for r in recs)}


def summarize(recs: list[dict]) -> dict:
    scored_cls = [r for r in recs if r["outcome"] in ("pass", "fail") and not _expects_failure(r)]
    buckets: dict[str, dict[str, dict]] = {}
    for name, key in (("suite", lambda r: [r["suite"]]), ("origin", lambda r: [r["origin"]]),
                      ("group", lambda r: [f"{r['suite']} / {r['group']}"]),
                      ("shell_dependent", lambda r: [f"{r['suite']} / " + ("requires shell_parsing" if "shell_parsing" in r["requires"] else "no shell parsing")]),
                      ("assumption", lambda r: r["contract_assumptions"])):
        groups: dict[str, list] = defaultdict(list)
        for r in recs:
            for k in key(r):
                groups[k].append(r)
        buckets[name] = {k: _tally(v) for k, v in sorted(groups.items())}
    per_label = {a: {"missing": sum(a in r["missing"] for r in scored_cls),
                     "spurious": sum(a in r["spurious"] for r in scored_cls),
                     "expected_present": sum(a in r["expected_actions"] for r in scored_cls)} for a in ACTIONS}
    unknown = {
        "expected_true_predicted_false": [r["id"] for r in scored_cls if r["expected_unknown"] and not r["predicted_unknown"]],
        "expected_false_predicted_true": [r["id"] for r in scored_cls if not r["expected_unknown"] and r["predicted_unknown"]],
        "actions_right_but_unknown_wrong": [r["id"] for r in scored_cls if r["actions_match"] and not r["unknown_match"]],
    }
    return {
        "overall": _tally(recs),
        "buckets": buckets,
        "per_label": per_label,
        "critical_misses": [{"id": r["id"], "suite": r["suite"], "missing": r["critical_missing"]}
                            for r in scored_cls if r["critical_missing"]],
        "unknown_mismatches": unknown,
        "technical_errors": [{"id": r["id"], "suite": r["suite"], "scored": r["expectation_status"] in SCORED,
                              "error": r["technical_error"]} for r in recs
                             if r["technical_error"] and not _expects_failure(r)],
        "expected_technical_failures": [{"id": r["id"], "suite": r["suite"], "expected": r["expected_technical_failure"],
                                         "observed": r["technical_error"], "observed_channel": r["failure_channel"],
                                         "reported_code": r["reported_failure_code"],
                                         "masked_as_classification": r["masked_failure"], "outcome": r["outcome"]}
                                        for r in recs if _expects_failure(r)],
        "constraint_violations": [{"id": r["id"], "suite": r["suite"], "violated": r["constraint_violations"]}
                                  for r in recs if r["constraint_violations"]],
        "constraint_checked": [r["id"] for r in recs if r["forbidden_actions"] and not r["technical_error"]],
        "status_field": "not evaluated (expected.status is null in every case)" if all(
            r["expected_status"] is None for r in recs) else "evaluated where expected.status is set",
    }


def exit_code(summary: dict) -> int:
    if summary["technical_errors"]:
        return 2
    if summary["overall"]["fail"] or summary["constraint_violations"]:
        return 1
    return 0


# ---------------------------------------------------------------- reporting
def _fmt(acts, unk) -> str:
    if acts is None:
        return "—"
    return f"[{', '.join(acts)}] unk={'T' if unk else 'F'}"


def render_markdown(summary: dict, recs: list[dict], meta: dict) -> str:
    o = summary["overall"]
    L = ["# Task 1 classification evaluation — results", "",
         "Generated by `eval_runner.py`. Pass = action set AND unknown both match. "
         "Pending cases are run for observation only and excluded from every denominator.", "",
         f"**Overall (scored):** {o['pass']}/{o['scored']} pass, {o['fail']} fail, "
         f"{o['technical_error']} technical error(s); {o['unscored']} unscored.", "",
         f"**status field:** {summary['status_field']}.", "", "## Results by bucket", ""]
    for name in ("suite", "origin", "group", "shell_dependent", "assumption"):
        L += [f"### by {name}", "", "| bucket | pass | fail | technical | scored | unscored |", "|---|---|---|---|---|---|"]
        for k, t in summary["buckets"][name].items():
            L.append(f"| {k} | {t['pass']} | {t['fail']} | {t['technical_error']} | {t['scored']} | {t['unscored']} |")
        L.append("")
    L += ["## Per-label errors (scored, non-technical cases)", "",
          "| label | expected present | missing (FN) | spurious (FP) |", "|---|---|---|---|"]
    for a, v in summary["per_label"].items():
        crit = " **critical**" if a in CRITICAL else ""
        L.append(f"| {a}{crit} | {v['expected_present']} | {v['missing']} | {v['spurious']} |")
    L += ["", "## Critical misses (missing delete / send_data / change_permissions)", ""]
    L += [f"- {c['suite']} {c['id']}: missing {', '.join(c['missing'])}" for c in summary["critical_misses"]] or ["- none"]
    u = summary["unknown_mismatches"]
    L += ["", "## unknown mismatches", "",
          f"- expected unknown=true, predicted false: {', '.join(u['expected_true_predicted_false']) or 'none'}",
          f"- expected unknown=false, predicted true: {', '.join(u['expected_false_predicted_true']) or 'none'}",
          f"- actions correct but unknown wrong: {', '.join(u['actions_right_but_unknown_wrong']) or 'none'}",
          "", "## Technical errors (not classification results)", ""]
    L += [f"- {t['suite']} {t['id']} ({'scored' if t['scored'] else 'unscored'}): {t['error']}"
          for t in summary["technical_errors"]] or ["- none"]
    L += ["", "## Expected technical failures (D06)", ""]
    L += [f"- {t['suite']} {t['id']}: expected {t['expected']}; " + (
          f"masked as a classification ({'FAIL'})" if t["masked_as_classification"] else
          f"failed via {t['observed_channel']} ({t['observed']}) ({t['outcome'].upper()})")
          for t in summary.get("expected_technical_failures", [])] or ["- none"]
    L += ["", "## Constraint checks (forbidden_actions)", "",
          f"- checked: {', '.join(summary['constraint_checked']) or 'none'}"]
    L += [f"- VIOLATED {c['suite']} {c['id']}: {', '.join(c['violated'])}" for c in summary["constraint_violations"]] or ["- no violations"]
    L += ["", "## Failing cases", "", "| suite | id | group | shell | expected | predicted | missing | spurious |",
          "|---|---|---|---|---|---|---|---|"]
    for r in recs:
        if r["outcome"] == "fail" and _expects_failure(r):
            L.append(f"| {r['suite']} | {r['id']} | {r['group']} | no | technical_failure={r['expected_technical_failure']} | "
                     f"{_fmt(r['predicted_actions'], r['predicted_unknown']) if r['masked_failure'] else r['technical_error']} | n/a | n/a |")
        elif r["outcome"] == "fail":
            L.append(f"| {r['suite']} | {r['id']} | {r['group']} | {'yes' if 'shell_parsing' in r['requires'] else 'no'} | "
                     f"{_fmt(r['expected_actions'], r['expected_unknown'])} | {_fmt(r['predicted_actions'], r['predicted_unknown'])} | "
                     f"{', '.join(r['missing']) or '—'} | {', '.join(r['spurious']) or '—'} |")
    L += ["", "## Unscored (pending) cases — observation only", "", "| suite | id | group | predicted | note |", "|---|---|---|---|---|"]
    for r in recs:
        if r["outcome"] == "unscored":
            pred = r["technical_error"] or _fmt(r["predicted_actions"], r["predicted_unknown"]) + (
                f" status={r['predicted_status']}" if r["predicted_status"] else "")
            L.append(f"| {r['suite']} | {r['id']} | {r['group']} | {pred} | not in any denominator |")
    L += ["", "## Run metadata", "", "```json", json.dumps(meta, indent=2), "```", ""]
    return "\n".join(L)


CSV_FIELDS = ["suite", "id", "group", "origin", "expectation_status", "shell_dependent", "contract_assumptions", "outcome",
              "expected_actions", "expected_unknown", "predicted_actions", "predicted_unknown", "predicted_status",
              "missing", "spurious", "critical_missing", "constraint_violations", "technical_error",
              "expected_technical_failure", "failure_channel", "reported_failure_code"]


def render_csv(recs: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    j = lambda v: "" if v is None else ("|".join(v) if isinstance(v, list) else v)  # noqa: E731
    for r in recs:
        row = {k: j(r.get(k)) for k in CSV_FIELDS if k != "shell_dependent"}
        row["shell_dependent"] = "shell_parsing" in r["requires"]
        w.writerow(row)
    return buf.getvalue()


# ---------------------------------------------------------------- SOU-97 pilot report (additive)
RISKY = ("write", "delete", "send_data", "change_permissions")
PILOT_PROFILES = ("filesystem", "git")
REPO = Path(__file__).resolve().parents[1]
# Profile and policy identities recorded with every pilot report (raw bytes, never normalized).
PILOT_IDENTITY_FILES = (
    "profiles/mcp/filesystem-readonly-v1/policy.yaml",
    "profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json",
    "profiles/mcp/filesystem-readonly-v1/upstream-identity.json",
    "profiles/mcp/git-readonly-v1/policy.yaml",
    "profiles/mcp/git-readonly-v1/upstream-tools-list.json",
    "profiles/mcp/git-readonly-v1/upstream-identity.json",
)
NOT_MEASURED = {"status": "not_measured",
                "note": "offline classification only; native policy verdicts and execution effects come only "
                        "from real runtime runs and are never derived from classifier predictions"}
SAFETY_NOT_PROVEN_READ = "must_not_be_classified_read_with_unknown_false"


class IdentityError(RuntimeError):
    """A required identity is missing, differs from the expected digest, or drifted during the run."""


def _load_evaluate_dev():
    """The existing SOU-14 snapshot/latency machinery, loaded from its source file (no bytecode cache)."""
    path = REPO / "rule_baseline" / "evaluate_dev.py"
    if not path.is_file():
        raise IdentityError("missing rule_baseline/evaluate_dev.py")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("evaluate_dev_for_pilot_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def _git_state() -> dict:
    try:
        head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=10, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True, timeout=30, check=True).stdout.strip()
        return {"head": head, "tracked_changes": bool(dirty)}
    except (OSError, subprocess.SubprocessError):
        return {"head": None, "tracked_changes": None, "note": "not a usable git checkout"}


def _environment() -> dict:
    return {"python": platform.python_version(), "implementation": platform.python_implementation(),
            "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "cpu_count": os.cpu_count(), "executable": Path(sys.executable).name}


def _ratio4(a: int, b: int):
    return round(a / b, 4) if b else None


def _uncertainty(r: dict):
    out = r.get("raw_output")
    return out.get("uncertainty") if isinstance(out, dict) else None


def _benign_supported(r: dict, meta: dict) -> bool:
    return (meta["profile_admission"] == "admit" and r["expected_technical_failure"] is None
            and not set(r["expected_actions"] or []) & set(RISKY) and r["expected_unknown"] is False)


def _interrupted(r: dict) -> list[str]:
    """Classification signals the native mapping does not allow (admission.rs); a signal, not a verdict."""
    if r["technical_error"]:
        return ["technical_error"]
    reasons = []
    if r["predicted_unknown"]:
        reasons.append("unknown")
    u = _uncertainty(r)
    if isinstance(u, (int, float)) and u >= 0.8:
        reasons.append("uncertainty>=0.8")
    risky = [a for a in RISKY if a in r["predicted_actions"]]
    if risky:
        reasons.append("risky_action:" + "+".join(risky))
    return reasons


def pilot_metrics(recs: list[dict], meta: dict[str, dict]) -> dict:
    """Classification metrics for one profile and one classifier (scored cases; pending observed only)."""
    scored = [r for r in recs if r["expectation_status"] in SCORED]
    cls = [r for r in scored if r["expected_technical_failure"] is None]
    valid = [r for r in cls if r["technical_error"] is None]
    per_action = {}
    for a in ACTIONS:
        tp = sum(a in r["expected_actions"] and a in r["predicted_actions"] for r in valid)
        fp = sum(a not in r["expected_actions"] and a in r["predicted_actions"] for r in valid)
        fn = sum(a in r["expected_actions"] and a not in r["predicted_actions"] for r in valid)
        per_action[a] = {"known_labels": len(valid), "known_positive": tp + fn, "predicted_positive": tp + fp,
                         "tp": tp, "fp": fp, "fn": fn, "precision": _ratio4(tp, tp + fp), "recall": _ratio4(tp, tp + fn)}
    known_effect = [r for r in valid if r["expected_unknown"] is False]
    expected_unknown = [r for r in valid if r["expected_unknown"] is True]
    abstained = [r for r in known_effect if r["predicted_unknown"]]
    mixed = [r for r in valid if len(r["expected_actions"]) > 1]
    benign = [r for r in valid if _benign_supported(r, meta[r["id"]])]
    pending = [r for r in recs if r["outcome"] == "unscored"]
    return {
        "cases": len(recs), "scored": len(scored), "unscored": len(pending),
        "pass": sum(r["outcome"] == "pass" for r in scored), "fail": sum(r["outcome"] == "fail" for r in scored),
        "technical_error": sum(r["outcome"] == "technical_error" for r in scored),
        "failed_ids": sorted(r["id"] for r in scored if r["outcome"] != "pass"),
        "per_action": per_action,
        "known_risk_misses": [{"id": r["id"], "missing": [a for a in RISKY if a in r["missing"]],
                               "predicted_actions": r["predicted_actions"], "predicted_unknown": r["predicted_unknown"]}
                              for r in valid if set(r["missing"]) & set(RISKY)],
        "mixed_action": {"cases": len(mixed), "exact": sum(bool(r["actions_match"] and r["unknown_match"]) for r in mixed),
                         "actions_exact": sum(bool(r["actions_match"]) for r in mixed),
                         "failed_ids": sorted(r["id"] for r in mixed if not (r["actions_match"] and r["unknown_match"]))},
        "abstention": {
            "known_effect_cases": len(known_effect), "abstained": len(abstained),
            "partial_unknown": sorted(r["id"] for r in abstained if r["predicted_actions"]),
            "full_unknown": sorted(r["id"] for r in abstained if not r["predicted_actions"]),
            "expected_unknown_cases": len(expected_unknown),
            "expected_unknown_covered": sum(bool(r["predicted_unknown"]) for r in expected_unknown),
            "expected_unknown_missed": sorted(r["id"] for r in expected_unknown if not r["predicted_unknown"]),
        },
        "technical_failures": {
            "unexpected": [{"id": r["id"], "error": r["technical_error"]} for r in cls if r["technical_error"]],
            "expected_d06": [{"id": r["id"], "expected": r["expected_technical_failure"],
                              "observed_channel": r["failure_channel"], "masked_as_classification": r["masked_failure"],
                              "predicted_actions": r["predicted_actions"], "predicted_unknown": r["predicted_unknown"],
                              "outcome": r["outcome"]} for r in scored if r["expected_technical_failure"]],
        },
        "supported_benign": {"cases": len(benign),
                             "false_interruptions": [{"id": r["id"], "reasons": _interrupted(r)}
                                                     for r in benign if _interrupted(r)]},
        "pending_observed": [{"id": r["id"], "predicted_actions": r["predicted_actions"],
                              "predicted_unknown": r["predicted_unknown"], "technical_error": r["technical_error"],
                              "safety_expectation": meta[r["id"]].get("safety_expectation"),
                              "safety_expectation_violated": bool(
                                  meta[r["id"]].get("safety_expectation") == SAFETY_NOT_PROVEN_READ
                                  and r["technical_error"] is None and r["predicted_actions"] == ["read"]
                                  and r["predicted_unknown"] is False)} for r in pending],
    }


def pilot_compare(before: dict, after: dict) -> dict:
    def ids(metrics, *path):
        node = metrics
        for key in path:
            node = node[key]
        return {x["id"] for x in node}
    return {
        "newly_failing": sorted(set(after["failed_ids"]) - set(before["failed_ids"])),
        "newly_passing": sorted(set(before["failed_ids"]) - set(after["failed_ids"])),
        "new_known_risk_misses": sorted(ids(after, "known_risk_misses") - ids(before, "known_risk_misses")),
        "new_unexpected_technical_failures": sorted(ids(after, "technical_failures", "unexpected")
                                                    - ids(before, "technical_failures", "unexpected")),
        "new_expected_d06_mismatches": sorted({x["id"] for x in after["technical_failures"]["expected_d06"] if x["outcome"] != "pass"}
                                              - {x["id"] for x in before["technical_failures"]["expected_d06"] if x["outcome"] != "pass"}),
        "new_supported_benign_false_interruptions": sorted(ids(after, "supported_benign", "false_interruptions")
                                                           - ids(before, "supported_benign", "false_interruptions")),
        "new_pending_safety_violations": sorted({x["id"] for x in after["pending_observed"] if x["safety_expectation_violated"]}
                                                - {x["id"] for x in before["pending_observed"] if x["safety_expectation_violated"]}),
    }


def _sha_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as e:
        raise IdentityError(f"missing identity input {path.name}: {e.strerror}") from e


CASE_FIELDS = ("id", "group", "outcome", "expected_actions", "expected_unknown", "predicted_actions", "predicted_unknown",
               "missing", "spurious", "technical_error", "expected_technical_failure", "failure_channel", "masked_failure")


def run_pilot(fixture_paths: list[str], candidate: str, baselines: dict[str, str], expect: dict[str, str],
              calls: int, spawns: int) -> dict:
    dev, dev_path = _load_evaluate_dev()
    identities = {"eval/eval_runner.py": _sha_file(Path(__file__)), "rule_baseline/evaluate_dev.py": _sha_file(dev_path)}
    for rel in PILOT_IDENTITY_FILES:
        identities[rel] = _sha_file(REPO / rel)
    fixtures, cases = [], []
    for p in fixture_paths:
        raw = Path(p).read_bytes()
        data = json.loads(raw.decode("utf-8"))
        errs = validate_fixture(data, Path(p).name)
        bad = [c.get("id") if isinstance(c, dict) else None for c in data.get("cases", [])
               if not isinstance(c, dict) or not isinstance(c.get("evaluator_only"), dict)
               or c["evaluator_only"].get("profile") not in PILOT_PROFILES or "profile_admission" not in c["evaluator_only"]]
        if bad:
            errs.append(f"{Path(p).name}: pilot cases need evaluator_only.profile and profile_admission: {bad[:5]}")
        if errs:
            raise ValueError("; ".join(errs))
        fixtures.append({"file": Path(p).name, "path": p, "fixture_version": data["fixture_version"],
                         "sha256": hashlib.sha256(raw).hexdigest()})
        cases += [(data["fixture_version"], c) for c in data["cases"]]
    ids = [c["id"] for _, c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids across pilot fixtures")
    meta = {c["id"]: c["evaluator_only"] for _, c in cases}

    subjects = {"candidate": candidate, **{f"baseline_{k}": baselines[k] for k in PILOT_PROFILES}}
    snaps = {}
    try:
        for label, path in subjects.items():
            try:
                snaps[label] = dev.Snapshot(path, label)
            except OSError as e:
                raise IdentityError(f"{label}: cannot read {path}: {e.strerror}") from e
            want = expect.get(label)
            if want is not None and snaps[label].sha256 != want:
                raise IdentityError(f"{label}: {Path(path).name} sha256 {snaps[label].sha256} differs from expected {want}")
        report = {
            "kind": "sou97-pilot-report", "report_version": 1, "environment": _environment(), "git": _git_state(),
            "identities": identities,
            "fixtures": [{k: v for k, v in f.items() if k != "path"} for f in fixtures],
            "classifiers": {label: {"file": Path(path).name, "sha256": snaps[label].sha256,
                                    "expected_sha256": expect.get(label),
                                    "revision": snaps[label].classify.__globals__.get("REVISION")}
                            for label, path in subjects.items()},
            "native_policy": NOT_MEASURED, "execution_effects": NOT_MEASURED,
            "latency_parameters": {"calls": calls, "spawns": spawns, "batch_size": 1,
                                   "request_timeout_s": dev.REQUEST_TIMEOUT_S,
                                   "bridge_inner_timeout_ms": dev.BRIDGE_INNER_TIMEOUT_MS,
                                   "workload": "the profile's admitted cases (profile_admission=admit), cycled in order",
                                   "source": "rule_baseline/evaluate_dev.py latency()"},
            "profiles": {},
        }
        for profile in PILOT_PROFILES:
            prof_cases = [(v, c) for v, c in cases if meta[c["id"]]["profile"] == profile]
            admitted = [{"input": c["input"]} for _, c in prof_cases if meta[c["id"]]["profile_admission"] == "admit"]
            entry = {"selected_baseline": f"baseline_{profile}", "cases": len(prof_cases),
                     "latency_workload": {"cases": len(admitted), "sha256": hashlib.sha256(json.dumps(
                         [x["input"] for x in admitted], sort_keys=True, ensure_ascii=False).encode()).hexdigest()}}
            for role, label in (("before", f"baseline_{profile}"), ("after", "candidate")):
                recs = [evaluate_case(c, snaps[label].classify, v) for v, c in prof_cases]
                entry[role] = {"classifier": label, "metrics": pilot_metrics(recs, meta),
                               "cases": [{**{k: r[k] for k in CASE_FIELDS}, "uncertainty": _uncertainty(r)} for r in recs],
                               "latency": (dev.latency(snaps[label], {"admitted": admitted}, calls, spawns)
                                           if admitted and (calls > 0 or spawns > 0) else {"status": "not_measured"})}
            entry["comparison"] = pilot_compare(entry["before"]["metrics"], entry["after"]["metrics"])
            report["profiles"][profile] = entry
        # Fail closed on drift: classifiers (on disk and as executed), fixtures, evaluators and identities.
        for snap in snaps.values():
            try:
                snap.verify_unchanged()
            except dev.SourceDrift as e:
                raise IdentityError(str(e)) from e
        for f in fixtures:
            if _sha_file(Path(f["path"])) != f["sha256"]:
                raise IdentityError(f"{f['file']} changed during the run")
        if (_sha_file(Path(__file__)) != identities["eval/eval_runner.py"]
                or _sha_file(dev_path) != identities["rule_baseline/evaluate_dev.py"]):
            raise IdentityError("evaluator source changed during the run")
        for rel in PILOT_IDENTITY_FILES:
            if _sha_file(REPO / rel) != identities[rel]:
                raise IdentityError(f"{rel} changed during the run")
        report["drift_check"] = "passed: classifier, executed snapshot, fixture, evaluator and profile/policy bytes unchanged"
        return report
    finally:
        for snap in snaps.values():
            snap.close()


def _pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _lat(entry: dict, mode: str) -> str:
    m = entry["latency"].get(mode)
    if not m:
        return "not measured"
    vals = f"p50 {m['p50_ms']} ms, p95 {m['p95_ms']} ms" if "p50_ms" in m else "no valid sample"
    return f"{vals} ({m['valid']}/{m['attempts']} valid, {m['failed']} failed, {m['timed_out']} timed out)"


def _ids(items) -> str:
    return ", ".join(x if isinstance(x, str) else x["id"] for x in items) or "none"


def render_pilot_markdown(rep: dict) -> str:
    env, g = rep["environment"], rep["git"]
    L = ["# SOU-97 pilot classifier report", "",
         "Offline classification measurement on development data. This is **not** an acceptance decision and "
         "**not** a runtime result: native policy verdicts and execution effects were not measured and are never "
         "derived from these predictions. Latency depends on the host.", "",
         "## Identities", "", "| item | sha256 |", "|---|---|"]
    for label, c in rep["classifiers"].items():
        L.append(f"| {label}: `{c['file']}`, revision {c['revision'] or 'none'} | `{c['sha256']}` |")
    for f in rep["fixtures"]:
        L.append(f"| fixture `{f['file']}` ({f['fixture_version']}) | `{f['sha256']}` |")
    for rel, digest in rep["identities"].items():
        L.append(f"| `{rel}` | `{digest}` |")
    L += ["", f"Git HEAD `{g.get('head')}`, tracked changes: {g.get('tracked_changes')}. Host: {env['platform']}, "
          f"Python {env['python']} ({env['implementation']}), {env['cpu_count']} CPUs. Drift check {rep['drift_check']}.",
          "", f"Latency: batch size 1, {rep['latency_parameters']['calls']} in-process and warm calls, "
          f"{rep['latency_parameters']['spawns']} cold spawns per classifier and profile; request timeout "
          f"{rep['latency_parameters']['request_timeout_s']} s; the bridge's inner timeout is "
          f"{rep['latency_parameters']['bridge_inner_timeout_ms']} ms. Only valid completed exchanges are timed; "
          "failed and timed-out attempts are counted.", ""]
    for profile, e in rep["profiles"].items():
        b, a = e["before"]["metrics"], e["after"]["metrics"]
        d06 = lambda m: sum(x["outcome"] != "pass" for x in m["technical_failures"]["expected_d06"])  # noqa: E731
        L += [f"## Profile: {profile}", "",
              f"Before: `{e['before']['classifier']}`. After: `candidate`. {e['cases']} cases, {b['scored']} scored, "
              f"{b['unscored']} pending (observed only). Latency workload: {e['latency_workload']['cases']} admitted cases.", "",
              "| measure | before | after |", "|---|---|---|",
              f"| scored pass | {b['pass']}/{b['scored']} | {a['pass']}/{a['scored']} |",
              f"| known-risk misses | {_ids(b['known_risk_misses'])} | {_ids(a['known_risk_misses'])} |",
              f"| mixed-action exact | {b['mixed_action']['exact']}/{b['mixed_action']['cases']} | "
              f"{a['mixed_action']['exact']}/{a['mixed_action']['cases']} |",
              f"| abstained on known-effect cases | {b['abstention']['abstained']}/{b['abstention']['known_effect_cases']} | "
              f"{a['abstention']['abstained']}/{a['abstention']['known_effect_cases']} |",
              f"| of which partial unknown | {len(b['abstention']['partial_unknown'])} | {len(a['abstention']['partial_unknown'])} |",
              f"| expected-unknown cases covered | {b['abstention']['expected_unknown_covered']}/{b['abstention']['expected_unknown_cases']} | "
              f"{a['abstention']['expected_unknown_covered']}/{a['abstention']['expected_unknown_cases']} |",
              f"| unexpected technical failures | {len(b['technical_failures']['unexpected'])} | {len(a['technical_failures']['unexpected'])} |",
              f"| expected D06 failures not met | {d06(b)}/{len(b['technical_failures']['expected_d06'])} | "
              f"{d06(a)}/{len(a['technical_failures']['expected_d06'])} |",
              f"| supported benign false interruptions | {len(b['supported_benign']['false_interruptions'])}/{b['supported_benign']['cases']} | "
              f"{len(a['supported_benign']['false_interruptions'])}/{a['supported_benign']['cases']} |",
              f"| warm batch-1 round trip | {_lat(e['before'], 'warm_process_round_trip')} | {_lat(e['after'], 'warm_process_round_trip')} |",
              f"| cold process per call | {_lat(e['before'], 'cold_process_per_call')} | {_lat(e['after'], 'cold_process_per_call')} |",
              f"| in-process call | {_lat(e['before'], 'in_process_call')} | {_lat(e['after'], 'in_process_call')} |",
              "", "Per-action precision and recall on known labels. Each cell gives P, R, then (TP, FP, FN; known labels).", "",
              "| action | before | after |", "|---|---|---|"]
        for act in ACTIONS:
            fmt = lambda p: f"P {_pct(p['precision'])}, R {_pct(p['recall'])} ({p['tp']}, {p['fp']}, {p['fn']}; {p['known_labels']})"  # noqa: E731
            L.append(f"| {act} | {fmt(b['per_action'][act])} | {fmt(a['per_action'][act])} |")
        c = e["comparison"]
        L += ["", "Changes against the selected baseline:", ""]
        L += [f"- {k.replace('_', ' ')}: {_ids(v)}" for k, v in c.items()]
        L += ["", "Retained as they are, not relabelled:", "",
              "- known-risk misses after: " + ("; ".join(
                  f"{x['id']} misses {'+'.join(x['missing'])} (predicted {x['predicted_actions']}, unknown={x['predicted_unknown']})"
                  for x in a["known_risk_misses"]) or "none"),
              "- expected D06 failures not met after: " + ("; ".join(
                  f"{x['id']} " + ("masked as a classification" if x["masked_as_classification"] else f"via {x['observed_channel']}")
                  for x in a["technical_failures"]["expected_d06"] if x["outcome"] != "pass") or "none"),
              "- supported benign false interruptions after: " + ("; ".join(
                  f"{x['id']} ({', '.join(x['reasons'])})" for x in a["supported_benign"]["false_interruptions"]) or "none"),
              ""]
    L += ["## Not measured", "", "- Native policy verdicts: not measured.", "- Execution effects: not measured.", ""]
    return "\n".join(L)


def pilot_main(a) -> int:
    baselines = {}
    for item in a.pilot_baseline or []:
        profile, _, path = item.partition("=")
        if profile not in PILOT_PROFILES or not path or profile in baselines:
            print(f"usage error: --pilot-baseline must be PROFILE=FILE once per profile {PILOT_PROFILES}", file=sys.stderr)
            return 3
        baselines[profile] = path
    if set(baselines) != set(PILOT_PROFILES) or not a.pilot_candidate:
        print("usage error: --pilot-report needs --pilot-candidate and one --pilot-baseline per profile", file=sys.stderr)
        return 3
    expect = {}
    for item in a.pilot_expect or []:
        label, _, digest = item.partition("=")
        if label not in ("candidate", "baseline_filesystem", "baseline_git") or not re.fullmatch(r"[0-9a-f]{64}", digest):
            print("usage error: --pilot-expect must be candidate|baseline_filesystem|baseline_git=<sha256>", file=sys.stderr)
            return 3
        expect[label] = digest
    if a.latency_calls < 0 or a.latency_spawns < 0:
        print("usage error: latency counts must be non-negative", file=sys.stderr)
        return 3
    try:
        rep = run_pilot(a.fixtures, a.pilot_candidate, baselines, expect, a.latency_calls, a.latency_spawns)
    except IdentityError as e:
        print(f"identity error: {e}", file=sys.stderr)
        return 4
    except (ValueError, OSError) as e:
        print(f"usage error: {e}", file=sys.stderr)
        return 3
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "pilot_report.json").write_bytes(
        (json.dumps(rep, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
    (out / "pilot_report.md").write_bytes(render_pilot_markdown(rep).encode("utf-8"))
    for profile, e in rep["profiles"].items():
        b, n = e["before"]["metrics"], e["after"]["metrics"]
        print(f"{profile}: before {b['pass']}/{b['scored']}, after {n['pass']}/{n['scored']}; "
              + "; ".join(f"{k}={v}" for k, v in e["comparison"].items() if k != "newly_passing"))
    print(f"wrote {out / 'pilot_report.json'}, {out / 'pilot_report.md'}")
    return 0


# ---------------------------------------------------------------- driver
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_classifier(spec: str, path: str | None) -> tuple[Callable, dict]:
    mod_name, _, func = spec.partition(":")
    if path:
        sys.path.insert(0, str(Path(path).resolve()))
    sys.dont_write_bytecode = True  # do not leave __pycache__ next to the classifier under test
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, func or "classify")
    info = {"spec": spec, "module_file": Path(mod.__file__).name}
    try:
        info["module_sha256"] = _sha256(Path(mod.__file__))
    except OSError:
        pass
    return fn, info


def run(fixture_paths: list[str], classify: Callable, classifier_info: dict) -> tuple[list[dict], dict, dict, list[str]]:
    recs: list[dict] = []
    errors: list[str] = []
    meta = {"runner": "eval_runner.py", "runner_sha256": _sha256(Path(__file__)), "python": platform.python_version(),
            "classifier": classifier_info, "fixtures": []}
    loaded = []
    all_ids: set[str] = set()
    for p in fixture_paths:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
        errors += validate_fixture(data, Path(p).name)
        ids = {c.get("id") for c in data.get("cases", []) if isinstance(c, dict)}
        dup = all_ids & ids
        if dup:
            errors.append(f"{Path(p).name}: ids also used in another fixture: {sorted(dup)}")
        all_ids |= ids
        meta["fixtures"].append({"file": Path(p).name, "fixture_version": data.get("fixture_version"), "sha256": _sha256(Path(p))})
        loaded.append(data)
    if errors:
        return [], {}, meta, errors
    for data in loaded:
        for case in data["cases"]:
            recs.append(evaluate_case(case, classify, data["fixture_version"]))
    return recs, summarize(recs), meta, []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("fixtures", nargs="+")
    ap.add_argument("--classifier", default="rule_baseline:classify", help="module:function")
    ap.add_argument("--classifier-path", default=None, help="directory containing the classifier module")
    ap.add_argument("--out-dir", default="results")
    ap.add_argument("--pilot-report", action="store_true", help="SOU-97 before/after report (see module docstring)")
    ap.add_argument("--pilot-candidate", help="candidate classifier source file")
    ap.add_argument("--pilot-baseline", action="append", help="PROFILE=FILE, selected baseline per profile")
    ap.add_argument("--pilot-expect", action="append", help="LABEL=SHA256 that the raw source bytes must have")
    ap.add_argument("--latency-calls", type=int, default=200)
    ap.add_argument("--latency-spawns", type=int, default=20)
    a = ap.parse_args(argv)
    if a.pilot_report:
        return pilot_main(a)
    try:
        classify, info = load_classifier(a.classifier, a.classifier_path)
    except (ImportError, AttributeError) as e:
        print(f"usage error: cannot load classifier {a.classifier}: {e}", file=sys.stderr)
        return 3
    recs, summary, meta, errors = run(a.fixtures, classify, info)
    if errors:
        print("fixture validation failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 3
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps({"meta": meta, "summary": summary, "cases": recs}, indent=2,
                                                 ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "results.csv").write_text(render_csv(recs), encoding="utf-8")
    (out / "summary.md").write_text(render_markdown(summary, recs, meta), encoding="utf-8")
    o = summary["overall"]
    print(f"scored: {o['pass']}/{o['scored']} pass, {o['fail']} fail, {o['technical_error']} technical; "
          f"unscored: {o['unscored']}; critical misses: {len(summary['critical_misses'])}; "
          f"constraint violations: {len(summary['constraint_violations'])}")
    for name, t in summary["buckets"]["suite"].items():
        print(f"  {name}: {t['pass']}/{t['scored']} pass, {t['fail']} fail, {t['technical_error']} technical, {t['unscored']} unscored")
    print(f"wrote {out/'results.json'}, {out/'results.csv'}, {out/'summary.md'}")
    return exit_code(summary)


if __name__ == "__main__":
    raise SystemExit(main())
