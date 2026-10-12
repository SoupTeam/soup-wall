# SPDX-License-Identifier: Apache-2.0
"""Measure a classifier on the SOU-13 development splits (SOU-14, PR 3).

Standard library only. The measured data are the label-separated exports of the SOU-13 development
package (``exports/model_inputs/<split>.jsonl`` and ``exports/labels/<split>.jsonl``). The labels are
provisional and the splits were visible while the classifier was developed, so every number written
here is a development number. It is not a held-out result: the closed test stays with its custodian.

    python evaluate_dev.py --exports <package>/exports --classifier rule_baseline.py \
        [--baseline old_rule_baseline.py --baseline-label 900cc3a] --out-dir out/

Writes ``evaluation.json`` (all counts) and ``EVALUATION.md``.

What the scoring rules are (the first version of this script got the first two wrong):

* Labels are tri-state. Each case has, per action, a target that is true, false or unknown (null, with
  ``known_mask`` 0). Only known targets are scored. An action that is absent from ``contract_view`` is
  not a known false unless its target is false.
* An output is a classification only if it passes ``check_output`` (a copy of the reviewed check in
  ``eval/eval_runner.py``). A missing or malformed output, ``status="error"`` and an exception are technical
  failures (D06). They are counted against the case total and never become answers or exact matches.
* Every measured latency sample is a valid completed exchange. Failed and timed-out attempts are counted
  apart, with the number of attempts.
* The classifier source is captured once. The same bytes are hashed, compiled, and written to the snapshot
  that the process measurements run, so the recorded digest is the code that ran. Source drift aborts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import queue
import subprocess
import sys
import tempfile
import threading
import time
import types
from collections import Counter, defaultdict

ACTIONS = ("read", "write", "delete", "send_data", "change_permissions")
RISKY = ("write", "delete", "send_data", "change_permissions")
STATUSES = {"ok", "unknown", "error"}
SPLITS = ("train", "validation", "calibration")
BRIDGE_INNER_TIMEOUT_MS = 1500  # the daemon's inner classifier timeout
REQUEST_TIMEOUT_S = 5.0  # bound for one measured exchange
CLEANUP_TIMEOUT_S = 1.0  # bound for closing a measured process before it is killed
MAX_SOURCE_BYTES = 1024 * 1024

CAVEATS = """\
- **Development numbers, not a held-out result.** The train, validation and calibration splits were all
  visible while the rules were written, so none of them is held out from the classifier. The closed test
  (54 cases) is held by its custodian and was not used here.
- **Provisional labels.** Every case carries `label_status: provisional`, and the exports measured here
  predate the final dev-export and gold addendum. A "miss" can also be a label question.
- **Partial labels.** Some cases have actions whose truth is not established (target null, `known_mask` 0).
  Those actions are not scored as right or wrong; the tables below say how many known labels each number rests on.
- **Synthetic data.** All cases come from the SOU-13 synthetic generator (`example.test` domains only);
  they say little about the frequency of real tools.
- **Denominators are cases, not tools.** Several cases share a template or family, so counts are not
  independent samples.
"""

BOOTSTRAP = (
    "import hashlib, sys\n"
    "p, d = sys.argv[1], sys.argv[2]\n"
    "s = open(p, 'rb').read()\n"
    "if hashlib.sha256(s).hexdigest() != d:\n"
    "    sys.exit(97)\n"
    "g = {'__name__': '__main__', '__file__': p}\n"
    "exec(compile(s, p, 'exec'), g)\n"
)


class DataError(ValueError):
    """The exported labels are not internally consistent."""


class SourceDrift(RuntimeError):
    """The classifier source changed while it was being measured."""


# ----------------------------------------------------------------------------- output check


def check_output(out) -> str | None:
    """Technical-error description, or None for a valid classification.

    Copy of ``check_output`` in ``eval/eval_runner.py`` (the reviewed one); a parity test compares the
    two when the repository layout is available.
    """
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
    for field in ("confidence", "uncertainty"):
        if field in out:
            value = out[field]
            if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
                return f"invalid_output: {field} must be a finite number in [0,1]"
    return None


# ----------------------------------------------------------------------------- scoring


def _ratio(a: int, b: int):
    return round(a / b, 4) if b else None


def score(records: list[dict]) -> dict:
    """Pure function over per-case records.

    A record has ``targets`` (action -> True/False/None), ``expected_unknown`` (bool), ``technical_error``
    (None or text), ``actions`` (list), ``unknown`` (bool) and ``family`` (str). A record with a technical
    error is counted against the case total and nowhere else.
    """
    out: dict = {"cases": len(records)}
    scored = [r for r in records if r.get("technical_error") is None]
    out["technical_failures"] = len(records) - len(scored)
    out["scored"] = len(scored)
    exact = 0
    c = {a: Counter() for a in ACTIONS}
    full = Counter()
    silent_pairs, silent_cases, flagged_pairs = [], 0, 0
    mixed = Counter()
    ab = Counter()
    errors = []
    for r in scored:
        t = r["targets"]
        exp = {a for a in ACTIONS if t[a] is True}
        got = set(r["actions"])
        eu, gu = bool(r["expected_unknown"]), bool(r["unknown"])
        ok = exp == got and eu == gu
        exact += ok
        for a in ACTIONS:
            if t[a] is None:
                c[a]["unlabelled"] += 1
                c[a]["reported_on_unlabelled"] += a in got
                continue
            c[a]["known_true" if t[a] else "known_false"] += 1
            if t[a]:
                c[a]["tp" if a in got else "fn"] += 1
            else:
                c[a]["fp" if a in got else "tn"] += 1
        fully = all(t[a] is not None for a in ACTIONS)
        known_ok = all(a in got for a in ACTIONS if t[a] is True) and not any(a in got for a in ACTIONS if t[a] is False)
        if fully:
            full["fully_annotated"] += 1
            full["fully_annotated_exact"] += ok
        else:
            full["partial"] += 1
            full["partial_known_labels_ok"] += known_ok
            full["partial_contract_exact"] += ok
        missed = [a for a in RISKY if t[a] is True and a not in got]
        if missed and not gu:
            silent_cases += 1
            silent_pairs += [(r["id"], a) for a in missed]
        elif missed:
            flagged_pairs += len(missed)
        if len(exp) >= 2:
            mixed["cases"] += 1
            mixed["exact_set"] += exp == got
            mixed["all_found"] += exp <= got
            mixed["silent_miss"] += bool(missed) and not gu
            mixed["flagged_miss"] += bool(missed) and gu
        elif len(got) >= 2 and not any(t[a] is None for a in ACTIONS):
            mixed["single_expected_but_several_reported"] += 1
        ab["expected_unknown"] += eu
        ab["reported_unknown"] += gu
        ab["full_abstain"] += gu and not got
        ab["unknown_when_expected_unknown"] += gu and eu
        ab["unknown_when_expected_known"] += gu and not eu
        ab["confident_when_expected_unknown"] += eu and not gu
        ab["answered"] += not gu
        ab["exact_on_answered"] += ok and not gu
        if not ok:
            errors.append({"id": r["id"], "family": r["family"], "expected": sorted(exp), "expected_unknown": eu,
                           "got": sorted(got), "unknown": gu, "known_labels_ok": known_ok})
    out["exact"] = exact
    out["per_label"] = {
        a: {"known_true": c[a]["known_true"], "known_false": c[a]["known_false"], "unlabelled": c[a]["unlabelled"],
            "tp": c[a]["tp"], "fn": c[a]["fn"], "fp": c[a]["fp"], "tn": c[a]["tn"],
            "reported_on_unlabelled": c[a]["reported_on_unlabelled"],
            "precision": _ratio(c[a]["tp"], c[a]["tp"] + c[a]["fp"]),
            "recall": _ratio(c[a]["tp"], c[a]["tp"] + c[a]["fn"])}
        for a in ACTIONS
    }
    out["annotation"] = dict(full)
    out["critical"] = {
        "silent_risky_miss_cases": silent_cases,
        "silent_risky_miss_pairs": len(silent_pairs),
        "silent_pairs": silent_pairs,
        "risky_miss_flagged_unknown_pairs": flagged_pairs,
        "definition": "a known-true write/delete/send_data/change_permissions is missing and unknown=false",
    }
    out["mixed"] = dict(mixed)
    out["abstention"] = dict(ab)
    out["coverage"] = _ratio(ab["answered"], len(records))
    out["exact_on_answered"] = _ratio(ab["exact_on_answered"], ab["answered"])
    out["errors"] = errors
    return out


# ----------------------------------------------------------------------------- data


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def validate_label(lab: dict) -> dict:
    """Check the tri-state targets and mask against contract_view and return the targets."""
    cid = lab.get("id", "?")
    t, m, view = lab.get("per_action_targets"), lab.get("known_mask"), lab.get("contract_view")
    if not isinstance(t, dict) or not isinstance(m, dict) or not isinstance(view, dict):
        raise DataError(f"{cid}: per_action_targets, known_mask and contract_view are required")
    if set(t) != set(ACTIONS) or set(m) != set(ACTIONS):
        raise DataError(f"{cid}: per_action_targets and known_mask must cover exactly {ACTIONS}")
    for a in ACTIONS:
        if t[a] not in (True, False, None) or m[a] not in (0, 1) or isinstance(m[a], bool):
            raise DataError(f"{cid}: bad target or mask for {a}")
        if (m[a] == 1) != (t[a] is not None):
            raise DataError(f"{cid}: known_mask and target disagree for {a}")
    if not isinstance(view.get("actions"), list) or not isinstance(view.get("unknown"), bool):
        raise DataError(f"{cid}: contract_view needs actions and unknown")
    if sorted(view["actions"]) != sorted(a for a in ACTIONS if t[a] is True):
        raise DataError(f"{cid}: contract_view actions differ from the true targets")
    return {a: t[a] for a in ACTIONS}


def load_cases(exports: str, splits=SPLITS) -> tuple[dict[str, list[dict]], dict]:
    """Join model inputs with labels by id. Returns cases per split and the data provenance."""
    cases: dict[str, list[dict]] = {}
    prov = {"files_sha256": {}, "label_status": Counter(), "manifest_check": "no EXPORT_MANIFEST.json"}
    manifest = None
    mpath = os.path.join(exports, "EXPORT_MANIFEST.json")
    if os.path.exists(mpath):
        with open(mpath, encoding="utf-8") as f:
            manifest = json.load(f)
        prov["manifest_check"] = "ok"
        prov["export_status"] = manifest.get("status")
        prov["cp2_version"] = manifest.get("cp2_version")
    for sp in splits:
        ins = read_jsonl(os.path.join(exports, "model_inputs", f"{sp}.jsonl"))
        labs = {r["id"]: r for r in read_jsonl(os.path.join(exports, "labels", f"{sp}.jsonl"))}
        rows = []
        for r in ins:
            lab = labs[r["id"]]
            targets = validate_label(lab)
            prov["label_status"][lab.get("label_status", "?")] += 1
            rows.append({"id": r["id"], "family": lab.get("family_id", "?"), "input": r["input"], "targets": targets,
                         "expected_unknown": bool(lab["contract_view"]["unknown"])})
        cases[sp] = rows
        for kind in ("model_inputs", "labels"):
            rel = f"{kind}/{sp}.jsonl"
            digest = sha256_file(os.path.join(exports, rel))
            prov["files_sha256"][rel] = digest
            if manifest is not None and manifest.get("files_sha256", {}).get(rel) != digest:
                prov["manifest_check"] = f"MISMATCH on {rel}"
    prov["label_status"] = dict(prov["label_status"])
    return cases, prov


# ----------------------------------------------------------------------------- captured source


class Snapshot:
    """One captured classifier source: its bytes, digest and the classify() compiled from those bytes."""

    def __init__(self, path: str, label: str):
        with open(path, "rb") as f:
            data = f.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("classifier source exceeds the byte limit")
        self.path, self.label, self.data = path, label, data
        self.sha256 = hashlib.sha256(data).hexdigest()
        module = types.ModuleType("classifier_snapshot_" + self.sha256[:8])
        module.__file__ = path
        exec(compile(data, path, "exec"), module.__dict__)  # never a cached .pyc: the bytes above are what runs
        if not callable(getattr(module, "classify", None)):
            raise ValueError("classifier must export a callable classify")
        self.classify = module.classify
        self._dir = tempfile.mkdtemp(prefix="sou14_snapshot_")
        self.file = os.path.join(self._dir, "classifier_snapshot.py")
        with open(self.file, "wb") as f:
            f.write(data)

    def verify_unchanged(self) -> None:
        """Reject drift of the source on disk and of the snapshot the processes ran."""
        for p in (self.path, self.file):
            with open(p, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != self.sha256:
                    raise SourceDrift(f"{p} changed while it was being measured")

    def close(self) -> None:
        try:
            os.remove(self.file)
            os.rmdir(self._dir)
        except OSError:
            pass

    def argv(self) -> list[str]:
        return [sys.executable, "-I", "-u", "-c", BOOTSTRAP, self.file, self.sha256]


def _child_env() -> dict:
    return {k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "LANG", "LC_ALL")}


# ----------------------------------------------------------------------------- running


def run_classifier(classify, cases: dict[str, list[dict]]) -> dict[str, list[dict]]:
    out = {}
    for sp, rows in cases.items():
        recs = []
        for c in rows:
            rec = {"id": c["id"], "family": c["family"], "targets": c["targets"], "expected_unknown": c["expected_unknown"],
                   "technical_error": None, "actions": [], "unknown": False}
            try:
                res = classify(json.loads(json.dumps(c["input"])))
                problem = check_output(res)
            except Exception as e:  # noqa: BLE001 - any classifier crash is a technical failure (D06)
                problem, res = f"exception: {type(e).__name__}", None
            if problem:
                rec["technical_error"] = problem
            else:
                rec["actions"], rec["unknown"] = list(res["actions"]), res["unknown"]
            recs.append(rec)
        out[sp] = recs
    return out


def reference(cases, actions, unknown):
    return {sp: [{"id": c["id"], "family": c["family"], "targets": c["targets"], "expected_unknown": c["expected_unknown"],
                  "technical_error": None, "actions": list(actions), "unknown": unknown} for c in rows]
            for sp, rows in cases.items()}


def percentile(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def _valid_reply(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) != 1:
        return False
    try:
        return check_output(json.loads(lines[0])) is None
    except ValueError:
        return False


class _Warm:
    """One long-lived classifier process, spoken to one line at a time with a bounded wait."""

    def __init__(self, snap: Snapshot):
        self.p = subprocess.Popen(snap.argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, encoding="utf-8", env=_child_env())
        self.q: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        try:
            for line in self.p.stdout:
                self.q.put(line)
        except (OSError, ValueError):
            pass
        self.q.put(None)

    def exchange(self, line: str, timeout: float) -> str | None:
        """Reply text, or None on timeout; raises OSError if the process is gone."""
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        for stream in (self.p.stdin,):
            try:
                stream.close()
            except OSError:
                pass
        try:
            self.p.wait(timeout=CLEANUP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        try:
            self.p.stdout.close()
        except OSError:
            pass


def _summ(ms: list[float], attempts: int, failed: int, timed_out: int) -> dict:
    out = {"attempts": attempts, "valid": len(ms), "failed": failed, "timed_out": timed_out}
    if ms:
        out.update(p50_ms=round(percentile(ms, 50), 3), p95_ms=round(percentile(ms, 95), 3), max_ms=round(max(ms), 3),
                   over_inner_timeout=sum(m >= BRIDGE_INNER_TIMEOUT_MS for m in ms))
    return out


def latency(snap: Snapshot, cases: dict[str, list[dict]], calls: int, spawns: int, timeout: float = REQUEST_TIMEOUT_S) -> dict:
    """Batch size 1: one request at a time. Only valid completed exchanges are timed."""
    lines = [json.dumps(c["input"], ensure_ascii=False) for rows in cases.values() for c in rows]
    inproc, bad = [], 0
    for i in range(calls):
        payload = json.loads(lines[i % len(lines)])
        t = time.perf_counter()
        try:
            res = snap.classify(payload)
            dt = (time.perf_counter() - t) * 1000
            problem = check_output(res)
        except Exception:  # noqa: BLE001
            problem, dt = "exception", 0.0
        if problem:
            bad += 1
        else:
            inproc.append(dt)
    result = {"in_process_call": _summ(inproc, calls, bad, 0)}

    warm, failed, timed_out = [], 0, 0
    proc = _Warm(snap)
    try:
        for i in range(calls):
            t = time.perf_counter()
            try:
                reply = proc.exchange(lines[i % len(lines)], timeout)
            except OSError:
                reply = ""
            dt = (time.perf_counter() - t) * 1000
            if reply is None:
                timed_out += 1
            elif not _valid_reply(reply):
                failed += 1
            else:
                warm.append(dt)
            if reply is None or reply == "" or proc.p.poll() is not None:
                proc.close()  # a hung or dead process is replaced; later attempts still count
                proc = _Warm(snap)
    finally:
        proc.close()
    result["warm_process_round_trip"] = _summ(warm, calls, failed, timed_out)

    cold, failed, timed_out = [], 0, 0
    for i in range(spawns):
        t = time.perf_counter()
        try:
            done = subprocess.run(snap.argv(), input=lines[i % len(lines)] + "\n", capture_output=True, text=True,
                                  encoding="utf-8", timeout=timeout, env=_child_env(), check=False)
        except subprocess.TimeoutExpired:
            timed_out += 1
            continue
        dt = (time.perf_counter() - t) * 1000
        if done.returncode != 0 or not _valid_reply(done.stdout):
            failed += 1
        else:
            cold.append(dt)
    result["cold_process_per_call"] = _summ(cold, spawns, failed, timed_out)
    return result


def evaluate(exports: str, classifier: str, baseline: str | None, baseline_label: str, calls: int, spawns: int) -> dict:
    cases, prov = load_cases(exports)
    subjects = {"candidate": (classifier, "candidate")}
    if baseline:
        subjects["baseline"] = (baseline, baseline_label)
    result = {
        "kind": "sou14-dev-evaluation",
        "scoring_version": 2,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "data": {"exports": os.path.basename(os.path.abspath(exports)), "provenance": prov,
                 "cases": {sp: len(rows) for sp, rows in cases.items()}},
        "caveats": CAVEATS,
        "classifiers": {},
        "references": {},
    }
    for name, (path, label) in subjects.items():
        snap = Snapshot(path, label)
        try:
            recs = run_classifier(snap.classify, cases)
            entry = {"label": label, "file": os.path.basename(path), "sha256": snap.sha256}
            entry["splits"] = {sp: score(r) for sp, r in recs.items()}
            entry["all"] = score([x for r in recs.values() for x in r])
            entry["latency"] = latency(snap, cases, calls, spawns)
            snap.verify_unchanged()
        finally:
            snap.close()
        result["classifiers"][name] = entry
    for name, (acts, unk) in (("always_abstain", ([], True)), ("always_no_effect", ([], False))):
        recs = reference(cases, acts, unk)
        result["references"][name] = {"all": score([x for r in recs.values() for x in r])}
    return result


# ----------------------------------------------------------------------------- report


def pct(x):
    return "n/a" if x is None else f"{x * 100:.0f}%"


def render(res: dict) -> str:
    L: list[str] = []
    w = L.append
    w("# SOU-14 development evaluation of the generic classifier\n")
    w("Generated by `evaluate_dev.py` (scoring version 2). Re-run it after any change to the classifier; the hashes below say "
      "what was measured.\n")
    w("## Read this first\n")
    w(res["caveats"])
    d = res["data"]
    w("## What was measured\n")
    w(f"- Data: SOU-13 development exports (cp2 version `{d['provenance'].get('cp2_version')}`), label status "
      f"{d['provenance']['label_status']}, export status `{d['provenance'].get('export_status')}`, manifest hash check: "
      f"{d['provenance']['manifest_check']}.")
    w("- Cases: " + ", ".join(f"{sp} {n}" for sp, n in d["cases"].items()) + f" (total {sum(d['cases'].values())}).")
    w(f"- Python {res['environment']['python']}, {res['environment']['platform']}.")
    for name, c in res["classifiers"].items():
        w(f"- {name}{'' if c['label'] == name else ' (' + c['label'] + ')'}: `{c['file']}`, sha256 `{c['sha256']}`. "
          "The same captured bytes were compiled, run in process and run in the process snapshots.")
    w("- Exported file hashes: " + ", ".join(f"`{k}` `{v[:12]}`" for k, v in d["provenance"]["files_sha256"].items()) + ".\n")

    names = list(res["classifiers"])
    w("## Contract match (actions equal the true targets and unknown equals the label)\n")
    w("Cases that fail the output check count as failures here. Counts are out of all cases in the split.\n")
    w("| Split | " + " | ".join(names) + " | always abstain | always no-effect |")
    w("|---|" + "---|" * (len(names) + 2))
    for sp in list(d["cases"]) + ["all"]:
        row = [sp]
        for n in names:
            s = res["classifiers"][n]["splits"][sp] if sp != "all" else res["classifiers"][n]["all"]
            row.append(f"{s['exact']}/{s['cases']} ({pct(s['exact'] / s['cases'])})")
        for ref in ("always_abstain", "always_no_effect"):
            if sp == "all":
                s = res["references"][ref]["all"]
                row.append(f"{s['exact']}/{s['cases']} ({pct(s['exact'] / s['cases'])})")
            else:
                row.append("")
        w("| " + " | ".join(row) + " |")
    w("\nA blanket refusal scores the share of cases labelled unknown and nothing else; compare it with the candidate row.\n")

    for n in names:
        c = res["classifiers"][n]
        a = c["all"]
        title = n if c["label"] == n else f"{n} ({c['label']})"
        w(f"## {title} on all {a['cases']} development cases\n")
        w(f"Technical failures (missing or malformed output, explicit error, exception): {a['technical_failures']} of {a['cases']}.\n")
        an = a["annotation"]
        w(f"**Annotation.** {an.get('fully_annotated', 0)} cases have all five targets known: contract match "
          f"{an.get('fully_annotated_exact', 0)}/{an.get('fully_annotated', 0)}. {an.get('partial', 0)} cases have some targets "
          f"unknown: the known labels are all respected (known-true reported, known-false not reported) in "
          f"{an.get('partial_known_labels_ok', 0)}/{an.get('partial', 0)}; strict contract match "
          f"{an.get('partial_contract_exact', 0)}/{an.get('partial', 0)}.\n")
        w("**Per label** (known labels only; an action whose target is unknown is not scored)\n")
        w("| Label | Known true | Known false | Unknown target | Found (tp) | Missed (fn) | Extra (fp) | Precision | Recall | Reported on unknown target |")
        w("|---|---|---|---|---|---|---|---|---|---|")
        for lab, s in a["per_label"].items():
            w(f"| {lab} | {s['known_true']} | {s['known_false']} | {s['unlabelled']} | {s['tp']} | {s['fn']} | {s['fp']} | "
              f"{pct(s['precision'])} | {pct(s['recall'])} | {s['reported_on_unlabelled']} |")
        cr = a["critical"]
        w(f"\n**Critical misses** ({cr['definition']}): {cr['silent_risky_miss_cases']} cases, "
          f"{cr['silent_risky_miss_pairs']} label misses, of {a['scored']} scored cases. Risky known labels missed but flagged "
          f"`unknown=true`: {cr['risky_miss_flagged_unknown_pairs']}.")
        by = Counter(sp for sp, s in c["splits"].items() for _ in range(s["critical"]["silent_risky_miss_cases"]))
        if by:
            w("Silent misses by split: " + ", ".join(f"{sp} {k}" for sp, k in by.items()) + ".")
            fam_of = {e["id"]: e["family"] for e in a["errors"]}
            fams = Counter((fam_of.get(i, "?"), lab) for i, lab in cr["silent_pairs"])
            w("Silent misses by family and missed label: " + ", ".join(f"`{f}` {lab} x{k}" for (f, lab), k in sorted(fams.items())) + ".")
        m = a["mixed"]
        mc = m.get("cases", 0)
        w(f"\n**Mixed actions** (cases with two or more known-true actions): {mc} cases; exact set {m.get('exact_set', 0)}/{mc}; "
          f"all expected actions found {m.get('all_found', 0)}/{mc}; silent miss {m.get('silent_miss', 0)}; "
          f"missed but flagged unknown {m.get('flagged_miss', 0)}. Several actions reported where one is expected "
          f"(fully annotated cases): {m.get('single_expected_but_several_reported', 0)}.")
        ab = a["abstention"]
        w(f"\n**Abstention and coverage:** {ab.get('expected_unknown', 0)} cases are labelled unknown; the classifier reports unknown on "
          f"{ab.get('reported_unknown', 0)} ({ab.get('full_abstain', 0)} with no action at all). Of its unknown replies, "
          f"{ab.get('unknown_when_expected_unknown', 0)} are on cases labelled unknown and {ab.get('unknown_when_expected_known', 0)} are on "
          f"cases labelled known (coverage lost). Cases labelled unknown that it answers with confidence: "
          f"{ab.get('confident_when_expected_unknown', 0)}. Coverage (answered without unknown): {ab.get('answered', 0)}/{a['cases']} "
          f"({pct(a['coverage'])}); contract match among answered: {ab.get('exact_on_answered', 0)}/{ab.get('answered', 0)} "
          f"({pct(a['exact_on_answered'])}).\n")
        lat = c["latency"]
        w("**Latency, batch size 1** (one request at a time; milliseconds). Only valid completed exchanges are timed; failed and "
          "timed-out attempts are counted apart.\n")
        w("| Path | Attempts | Valid | Failed | Timed out | p50 | p95 | max | Valid calls over 1500 ms |")
        w("|---|---|---|---|---|---|---|---|---|")
        for key, title2 in (("in_process_call", "`classify()` in the process"),
                            ("warm_process_round_trip", "warm snapshot process, one line in, one line out"),
                            ("cold_process_per_call", "new snapshot process per call")):
            s = lat[key]
            w(f"| {title2} | {s['attempts']} | {s['valid']} | {s['failed']} | {s['timed_out']} | {s.get('p50_ms', 'n/a')} | "
              f"{s.get('p95_ms', 'n/a')} | {s.get('max_ms', 'n/a')} | {s.get('over_inner_timeout', 'n/a')} |")
        w("\nThe snapshot processes start from the captured classifier bytes through a small bootstrap that checks the digest, "
          "shaped like the daemon's snapshot start but not the daemon's own code or admission path. These numbers are not a bound "
          "on daemon latency; they were measured in one environment (see above).\n")

    if len(names) == 2:
        b, c = res["classifiers"]["baseline"]["all"], res["classifiers"]["candidate"]["all"]
        w("## Candidate against baseline, same cases\n")
        w("| Measure | baseline | candidate |")
        w("|---|---|---|")
        w(f"| contract match | {b['exact']}/{b['cases']} | {c['exact']}/{c['cases']} |")
        w(f"| silent risky-label misses (cases) | {b['critical']['silent_risky_miss_cases']} | {c['critical']['silent_risky_miss_cases']} |")
        w(f"| coverage | {pct(b['coverage'])} | {pct(c['coverage'])} |")
        w(f"| full abstentions | {b['abstention'].get('full_abstain', 0)} | {c['abstention'].get('full_abstain', 0)} |")
        w(f"| mixed cases with all actions found | {b['mixed'].get('all_found', 0)}/{b['mixed'].get('cases', 0)} | "
          f"{c['mixed'].get('all_found', 0)}/{c['mixed'].get('cases', 0)} |")
        w("")

    cand = res["classifiers"]["candidate"]["all"]
    w("## Remaining contract mismatches of the candidate\n")
    fam = defaultdict(list)
    for e in cand["errors"]:
        fam[e["family"]].append(e)
    only_unlabelled = sum(e["known_labels_ok"] for e in cand["errors"])
    w(f"{len(cand['errors'])} of {cand['cases']} cases differ from the contract label, in {len(fam)} families; in "
      f"{only_unlabelled} of them every known label is respected and the difference is in the unknown flag or in actions "
      "whose truth is not established. First case of each family shown; expected -> got; `?` = unknown:\n")
    w("| Family | Cases | Known labels respected | Expected | Got |")
    w("|---|---|---|---|---|")
    for f, es in sorted(fam.items(), key=lambda kv: -len(kv[1])):
        e = es[0]
        ex = "+".join(e["expected"]) or "no effect"
        ex += " ?" if e["expected_unknown"] else ""
        go = "+".join(e["got"]) or "no action"
        go += " ?" if e["unknown"] else ""
        w(f"| `{f}` | {len(es)} | {sum(x['known_labels_ok'] for x in es)}/{len(es)} | {ex} | {go} |")
    w("")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exports", required=True)
    ap.add_argument("--classifier", required=True)
    ap.add_argument("--baseline")
    ap.add_argument("--baseline-label", default="baseline")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--latency-calls", type=int, default=500)
    ap.add_argument("--latency-spawns", type=int, default=30)
    a = ap.parse_args(argv)
    res = evaluate(a.exports, a.classifier, a.baseline, a.baseline_label, a.latency_calls, a.latency_spawns)
    os.makedirs(a.out_dir, exist_ok=True)
    with open(os.path.join(a.out_dir, "evaluation.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, sort_keys=True, ensure_ascii=False)
    with open(os.path.join(a.out_dir, "EVALUATION.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(render(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())