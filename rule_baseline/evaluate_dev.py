# SPDX-License-Identifier: Apache-2.0
"""Measure a classifier on the SOU-13 development splits (SOU-14, PR 3).

Standard library only. The measured data are the label-separated exports of the SOU-13 development
package (``exports/model_inputs/<split>.jsonl`` and ``exports/labels/<split>.jsonl``). The labels are
provisional and the splits were visible while the classifier was developed, so every number written
here is a development number. It is not a held-out result: the closed test stays with its custodian.

    python evaluate_dev.py --exports <package>/exports --classifier rule_baseline.py \
        [--baseline old_rule_baseline.py --baseline-label 900cc3a] --out-dir out/

Writes ``evaluation.json`` (all counts and the per-case outcome) and ``EVALUATION.md``.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
from collections import Counter, defaultdict

ACTIONS = ("read", "write", "delete", "send_data", "change_permissions")
RISKY = ("write", "delete", "send_data", "change_permissions")
SPLITS = ("train", "validation", "calibration")
BRIDGE_INNER_TIMEOUT_MS = 1500  # the daemon's inner classifier timeout

CAVEATS = """\
- **Development numbers, not a held-out result.** The train, validation and calibration splits were all
  visible while the rules were written, so none of them is held out from the classifier. The closed test
  (54 cases) is held by its custodian and was not used here.
- **Provisional labels.** Every case carries `label_status: provisional`. The owner review of the labels
  has no independent gold sign-off yet, so a "miss" can also be a label question.
- **Synthetic data.** All cases come from the SOU-13 synthetic generator (`example.test` domains only);
  they say little about the frequency of real tools.
- **Denominators are cases, not tools.** Several cases share a template or family, so counts are not
  independent samples.
"""


# ----------------------------------------------------------------------------- scoring


def score(records: list[dict]) -> dict:
    """Pure function over per-case records.

    A record has ``expected`` (list), ``expected_unknown`` (bool), ``actions`` (list), ``unknown`` (bool),
    ``status`` ("ok"/"unknown"/"error"), ``family`` (str). Technical failures are counted apart and are
    not scored as answers.
    """
    scored = [r for r in records if r["status"] != "error"]
    n = len(scored)
    out: dict = {"cases": len(records), "technical_failures": len(records) - n, "scored": n}
    exact = 0
    tp, fp, fn = Counter(), Counter(), Counter()
    support = Counter()
    silent_pairs, silent_cases, flagged_pairs = [], 0, 0
    mixed = Counter()
    ab = Counter()
    errors = []
    for r in scored:
        exp, got = set(r["expected"]), set(r["actions"])
        eu, gu = bool(r["expected_unknown"]), bool(r["unknown"])
        ok = exp == got and eu == gu
        exact += ok
        for a in ACTIONS:
            support[a] += a in exp
            tp[a] += a in exp and a in got
            fp[a] += a not in exp and a in got
            fn[a] += a in exp and a not in got
        missed = [a for a in RISKY if a in exp and a not in got]
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
        elif len(got) >= 2:
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
                           "got": sorted(got), "unknown": gu})
    out["exact"] = exact
    out["per_label"] = {
        a: {"support": support[a], "tp": tp[a], "fp": fp[a], "fn": fn[a],
            "precision": _ratio(tp[a], tp[a] + fp[a]), "recall": _ratio(tp[a], tp[a] + fn[a])}
        for a in ACTIONS
    }
    out["critical"] = {
        "silent_risky_miss_cases": silent_cases,
        "silent_risky_miss_pairs": len(silent_pairs),
        "silent_pairs": silent_pairs,
        "risky_miss_flagged_unknown_pairs": flagged_pairs,
        "definition": "an expected write/delete/send_data/change_permissions is missing and unknown=false",
    }
    out["mixed"] = dict(mixed)
    out["abstention"] = dict(ab)
    out["coverage"] = _ratio(ab["answered"], n)
    out["exact_on_answered"] = _ratio(ab["exact_on_answered"], ab["answered"])
    out["errors"] = errors
    return out


def _ratio(a: int, b: int):
    return round(a / b, 4) if b else None


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
            view = lab["contract_view"]
            prov["label_status"][lab.get("label_status", "?")] += 1
            rows.append({"id": r["id"], "family": lab.get("family_id", "?"), "input": r["input"],
                         "expected": list(view["actions"]), "expected_unknown": bool(view["unknown"])})
        cases[sp] = rows
        for kind in ("model_inputs", "labels"):
            rel = f"{kind}/{sp}.jsonl"
            digest = sha256_file(os.path.join(exports, rel))
            prov["files_sha256"][rel] = digest
            if manifest is not None and manifest.get("files_sha256", {}).get(rel) != digest:
                prov["manifest_check"] = f"MISMATCH on {rel}"
    prov["label_status"] = dict(prov["label_status"])
    return cases, prov


# ----------------------------------------------------------------------------- running


def load_classify(path: str):
    spec = importlib.util.spec_from_file_location("classifier_under_test_" + hashlib.sha1(path.encode()).hexdigest()[:8], path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.classify


def run_classifier(classify, cases: dict[str, list[dict]]) -> dict[str, list[dict]]:
    out = {}
    for sp, rows in cases.items():
        recs = []
        for c in rows:
            res = classify(c["input"])
            recs.append({"id": c["id"], "family": c["family"], "expected": c["expected"],
                         "expected_unknown": c["expected_unknown"], "status": res.get("status", "ok"),
                         "actions": list(res.get("actions") or []), "unknown": bool(res.get("unknown"))})
        out[sp] = recs
    return out


def always_abstain(cases):
    return {sp: [{"id": c["id"], "family": c["family"], "expected": c["expected"], "expected_unknown": c["expected_unknown"],
                  "status": "unknown", "actions": [], "unknown": True} for c in rows] for sp, rows in cases.items()}


def always_no_effect(cases):
    return {sp: [{"id": c["id"], "family": c["family"], "expected": c["expected"], "expected_unknown": c["expected_unknown"],
                  "status": "ok", "actions": [], "unknown": False} for c in rows] for sp, rows in cases.items()}


def percentile(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def _summ(ms: list[float]) -> dict:
    return {"n": len(ms), "p50_ms": round(percentile(ms, 50), 3), "p95_ms": round(percentile(ms, 95), 3),
            "max_ms": round(max(ms), 3), "over_inner_timeout": sum(m >= BRIDGE_INNER_TIMEOUT_MS for m in ms)}


def latency(path: str, cases: dict[str, list[dict]], calls: int, spawns: int) -> dict:
    """Batch size 1: one request at a time, never a batch of several."""
    lines = [json.dumps(c["input"], ensure_ascii=False) for rows in cases.values() for c in rows]
    classify = load_classify(path)
    inproc = []
    for i in range(calls):
        payload = json.loads(lines[i % len(lines)])
        t = time.perf_counter()
        classify(payload)
        inproc.append((time.perf_counter() - t) * 1000)
    warm = []
    proc = subprocess.Popen([sys.executable, "-I", "-u", path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                            encoding="utf-8")
    try:
        for i in range(calls):
            t = time.perf_counter()
            proc.stdin.write(lines[i % len(lines)] + "\n")
            proc.stdin.flush()
            proc.stdout.readline()
            warm.append((time.perf_counter() - t) * 1000)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    cold = []
    for i in range(spawns):
        t = time.perf_counter()
        subprocess.run([sys.executable, "-I", "-u", path], input=lines[i % len(lines)] + "\n", capture_output=True,
                       text=True, encoding="utf-8", check=False)
        cold.append((time.perf_counter() - t) * 1000)
    return {"in_process_call": _summ(inproc), "warm_process_round_trip": _summ(warm),
            "cold_process_per_call": _summ(cold)}


def describe(path: str, label: str) -> dict:
    return {"label": label, "file": os.path.basename(path), "sha256": sha256_file(path)}


def evaluate(exports: str, classifier: str, baseline: str | None, baseline_label: str, calls: int, spawns: int) -> dict:
    cases, prov = load_cases(exports)
    subjects = {"candidate": classifier}
    if baseline:
        subjects["baseline"] = baseline
    result = {
        "kind": "sou14-dev-evaluation",
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "data": {"exports": os.path.basename(os.path.abspath(exports)), "provenance": prov,
                 "cases": {sp: len(rows) for sp, rows in cases.items()}},
        "caveats": CAVEATS,
        "classifiers": {},
        "references": {},
    }
    for name, path in subjects.items():
        recs = run_classifier(load_classify(path), cases)
        entry = describe(path, baseline_label if name == "baseline" else "candidate")
        entry["splits"] = {sp: score(r) for sp, r in recs.items()}
        entry["all"] = score([x for r in recs.values() for x in r])
        entry["latency"] = latency(path, cases, calls, spawns)
        result["classifiers"][name] = entry
    for name, fn in (("always_abstain", always_abstain), ("always_no_effect", always_no_effect)):
        recs = fn(cases)
        result["references"][name] = {"all": score([x for r in recs.values() for x in r])}
    return result


# ----------------------------------------------------------------------------- report


def pct(x):
    return "n/a" if x is None else f"{x * 100:.0f}%"


def render(res: dict) -> str:
    L: list[str] = []
    w = L.append
    w("# SOU-14 development evaluation of the generic classifier\n")
    w("Generated by `evaluate_dev.py`. Re-run it after any change to the classifier; the hashes below say what was measured.\n")
    w("## Read this first\n")
    w(res["caveats"])
    d = res["data"]
    w("## What was measured\n")
    w(f"- Data: SOU-13 development exports (cp2 version `{d['provenance'].get('cp2_version')}`), label status {d['provenance']['label_status']}, "
      f"export status `{d['provenance'].get('export_status')}`, manifest hash check: {d['provenance']['manifest_check']}.")
    w("- Cases: " + ", ".join(f"{sp} {n}" for sp, n in d["cases"].items()) + f" (total {sum(d['cases'].values())}).")
    w(f"- Python {res['environment']['python']}, {res['environment']['platform']}.")
    for name, c in res["classifiers"].items():
        w(f"- {name}{'' if c['label'] == name else ' (' + c['label'] + ')'}: `{c['file']}`, sha256 `{c['sha256']}`.")
    w("- Exported file hashes: " + ", ".join(f"`{k}` `{v[:12]}`" for k, v in d["provenance"]["files_sha256"].items()) + ".\n")

    names = list(res["classifiers"])
    w("## Exact match (actions and unknown both equal the provisional label)\n")
    w("| Split | " + " | ".join(names) + " | always abstain | always no-effect |")
    w("|---|" + "---|" * (len(names) + 2))
    for sp in list(d["cases"]) + ["all"]:
        row = [sp]
        for n in names:
            s = res["classifiers"][n]["splits"][sp] if sp != "all" else res["classifiers"][n]["all"]
            row.append(f"{s['exact']}/{s['scored']} ({pct(s['exact'] / s['scored'])})")
        for ref in ("always_abstain", "always_no_effect"):
            if sp == "all":
                s = res["references"][ref]["all"]
                row.append(f"{s['exact']}/{s['scored']} ({pct(s['exact'] / s['scored'])})")
            else:
                row.append("")
        w("| " + " | ".join(row) + " |")
    w("\nA blanket refusal scores the share of cases labelled unknown and nothing else; compare it with the candidate row.\n")

    for n in names:
        c = res["classifiers"][n]
        a = c["all"]
        title = n if c["label"] == n else f"{n} ({c['label']})"
        w(f"## {title} on all {a['scored']} development cases\n")
        w(f"Technical failures: {a['technical_failures']} of {a['cases']}.\n")
        w("**Per label** (counts are cases; precision and recall use the denominators shown)\n")
        w("| Label | Expected | Found (tp) | Extra (fp) | Missed (fn) | Precision | Recall |")
        w("|---|---|---|---|---|---|---|")
        for lab, s in a["per_label"].items():
            w(f"| {lab} | {s['support']} | {s['tp']} | {s['fp']} | {s['fn']} | {pct(s['precision'])} | {pct(s['recall'])} |")
        cr = a["critical"]
        w(f"\n**Critical misses** ({cr['definition']}): {cr['silent_risky_miss_cases']} cases, "
          f"{cr['silent_risky_miss_pairs']} label misses, of {a['scored']} cases. Risky labels missed but flagged "
          f"`unknown=true`: {cr['risky_miss_flagged_unknown_pairs']}.")
        by = Counter(sp for sp, s in c["splits"].items() for _ in range(s["critical"]["silent_risky_miss_cases"]))
        if by:
            w("Silent misses by split: " + ", ".join(f"{sp} {k}" for sp, k in by.items()) + ".")
            fam_of = {e["id"]: e["family"] for e in a["errors"]}
            fams = Counter((fam_of.get(i, "?"), lab) for i, lab in cr["silent_pairs"])
            w("Silent misses by family and missed label: " + ", ".join(f"`{f}` {lab} x{k}" for (f, lab), k in sorted(fams.items())) + ".")
        m = a["mixed"]
        mc = m.get("cases", 0)
        w(f"\n**Mixed actions** (cases whose label has two or more actions): {mc} cases; exact set {m.get('exact_set', 0)}/{mc}; "
          f"all expected actions found {m.get('all_found', 0)}/{mc}; silent miss {m.get('silent_miss', 0)}; "
          f"missed but flagged unknown {m.get('flagged_miss', 0)}. Several actions reported where one is expected: "
          f"{m.get('single_expected_but_several_reported', 0)}.")
        ab = a["abstention"]
        w(f"\n**Abstention and coverage:** {ab['expected_unknown']} cases are labelled unknown; the classifier reports unknown on "
          f"{ab['reported_unknown']} ({ab['full_abstain']} with no action at all). Of its unknown replies, "
          f"{ab['unknown_when_expected_unknown']} are on cases labelled unknown and {ab['unknown_when_expected_known']} are on cases "
          f"labelled known (coverage lost). Cases labelled unknown that it answers with confidence: {ab['confident_when_expected_unknown']}. "
          f"Coverage (answered without unknown): {ab['answered']}/{a['scored']} ({pct(a['coverage'])}); exact among answered: "
          f"{ab['exact_on_answered']}/{ab['answered']} ({pct(a['exact_on_answered'])}).\n")
        lat = c["latency"]
        w("**Latency, batch size 1** (one request at a time; milliseconds; `n` is the number of calls)\n")
        w("| Path | n | p50 | p95 | max | calls over 1500 ms |")
        w("|---|---|---|---|---|---|")
        for key, title in (("in_process_call", "classify() in the process"), ("warm_process_round_trip", "warm process, one line in, one line out"),
                           ("cold_process_per_call", "new `python -I -u` process per call")):
            s = lat[key]
            w(f"| {title} | {s['n']} | {s['p50_ms']} | {s['p95_ms']} | {s['max_ms']} | {s['over_inner_timeout']} |")
        w("\nThe daemon starts one isolated Python process per snapshot and applies a 1.5 s inner timeout; the cold row includes interpreter "
          "start-up and is the upper bound.\n")

    if len(names) == 2:
        b, c = res["classifiers"]["baseline"]["all"], res["classifiers"]["candidate"]["all"]
        w("## Candidate against baseline, same cases\n")
        w("| Measure | baseline | candidate |")
        w("|---|---|---|")
        w(f"| exact | {b['exact']}/{b['scored']} | {c['exact']}/{c['scored']} |")
        w(f"| silent risky-label misses (cases) | {b['critical']['silent_risky_miss_cases']} | {c['critical']['silent_risky_miss_cases']} |")
        w(f"| coverage | {pct(b['coverage'])} | {pct(c['coverage'])} |")
        w(f"| full abstentions | {b['abstention']['full_abstain']} | {c['abstention']['full_abstain']} |")
        w(f"| mixed cases with all actions found | {b['mixed'].get('all_found', 0)}/{b['mixed'].get('cases', 0)} | {c['mixed'].get('all_found', 0)}/{c['mixed'].get('cases', 0)} |")
        w("")

    cand = res["classifiers"]["candidate"]["all"]
    w("## Remaining errors of the candidate\n")
    fam = defaultdict(list)
    for e in cand["errors"]:
        fam[e["family"]].append(e)
    w(f"{len(cand['errors'])} of {cand['scored']} cases differ from the provisional label, in {len(fam)} families "
      "(first case of each family shown; expected -> got; `?` = unknown):\n")
    w("| Family | Cases | Expected | Got |")
    w("|---|---|---|---|")
    for f, es in sorted(fam.items(), key=lambda kv: -len(kv[1])):
        e = es[0]
        ex = "+".join(e["expected"]) or "no effect"
        ex += " ?" if e["expected_unknown"] else ""
        go = "+".join(e["got"]) or "no action"
        go += " ?" if e["unknown"] else ""
        w(f"| `{f}` | {len(es)} | {ex} | {go} |")
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
