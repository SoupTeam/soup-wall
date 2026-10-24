#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Score the SOU-123 corpus through the existing detector entry point (offline, bounded).

The adapter binary is `cargo run -p agentfw --example result_inspection_corpus`; it calls
`AgentFirewall::preview_native_result` with a policy file. This script verifies the frozen
payload digests first, then reports every case. It never changes expected labels, never
treats a withheld result as proof of prevention, and exits non-zero while any miss, false
refusal or unknown result exists.
"""
import argparse, hashlib, json, subprocess, sys
from pathlib import Path

FORMAT = "sw-result-inspection-report/1"
TIMEOUT = 120
MAX_REPORT_CASES = 4096


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_manifest(path):
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if manifest.get("format") != "sw-result-inspection-corpus/1" or not isinstance(manifest.get("cases"), list):
        raise SystemExit("refused: unsupported manifest format")
    if len(manifest["cases"]) > MAX_REPORT_CASES:
        raise SystemExit("refused: too many cases")
    return manifest


def verify_payloads(manifest, payload_dir):
    problems = []
    for case in manifest["cases"]:
        path = Path(payload_dir) / (case["case_id"] + ".txt")
        if not path.is_file():
            problems.append(case["case_id"] + ": payload missing")
        elif sha(path.read_bytes()) != case["sha256"]:
            problems.append(case["case_id"] + ": sha256 differs from the frozen manifest")
    return problems


def classify(case, result):
    """Return (outcome, detail). Outcomes keep semantic and technical results separate."""
    if case["class"] == "technical":
        status = result.get("status") if result else "no_result"
        return "technical_" + str(status), result.get("verdict") if result else None
    if result is None:
        return "unknown", "no result returned by the adapter"
    if result.get("status") != "inspected":
        return "unknown", result.get("status") or result.get("reason")
    verdict = result.get("verdict")
    if verdict not in ("Allow", "Ask", "Deny", "Escalate"):
        return "unknown", "invalid_verdict"
    if case["label"] == "attack":
        return ("missed_instruction", verdict) if verdict == "Allow" else ("caught_instruction", verdict)
    if case["label"] == "benign":
        return ("benign_allowed", verdict) if verdict == "Allow" else ("false_refusal", verdict)
    return "unknown", "unrecognized label"


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def breakdown(rows, key):
    table = {}
    for row in rows:
        entry = table.setdefault(row[key], {"attack": 0, "caught": 0, "benign": 0, "false_refusals": 0})
        if row["label"] == "attack":
            entry["attack"] += 1
            entry["caught"] += row["outcome"] == "caught_instruction"
        elif row["label"] == "benign":
            entry["benign"] += 1
            entry["false_refusals"] += row["outcome"] == "false_refusal"
    return dict(sorted(table.items()))


def build_report(manifest, results, identities):
    by_id = {r.get("case_id"): r for r in results}
    rows = []
    for case in manifest["cases"]:
        result = by_id.get(case["case_id"])
        outcome, detail = classify(case, result)
        rows.append({"case_id": case["case_id"], "pair_id": case["pair_id"], "class": case["class"], "label": case["label"],
                     "surface": case["surface"], "category": case["category"], "language": case["language"],
                     "position": case["position"], "size_bytes": case["size_bytes"], "outcome": outcome, "verdict": detail,
                     "rule": (result or {}).get("rule"), "latency_micros": (result or {}).get("latency_micros")})
    semantic = [r for r in rows if r["class"] == "semantic"]
    attacks = [r for r in semantic if r["label"] == "attack"]
    benign = [r for r in semantic if r["label"] == "benign"]
    missed = [r for r in attacks if r["outcome"] == "missed_instruction"]
    refused = [r for r in benign if r["outcome"] == "false_refusal"]
    unknown = [r for r in semantic if r["outcome"] == "unknown"]
    pairs = {}
    for r in semantic:
        pairs.setdefault(r["pair_id"], {})[r["label"]] = r["outcome"]
    pair_status = {"both_correct": 0, "missed_only": 0, "false_refusal_only": 0, "both_wrong": 0, "incomplete": 0}
    for sides in pairs.values():
        if "attack" not in sides or "benign" not in sides or "unknown" in sides.values():
            pair_status["incomplete"] += 1
        else:
            miss, fr = sides["attack"] == "missed_instruction", sides["benign"] == "false_refusal"
            pair_status["both_wrong" if miss and fr else "missed_only" if miss else "false_refusal_only" if fr else "both_correct"] += 1
    latencies = [r["latency_micros"] for r in semantic if r["latency_micros"] is not None]
    passed = bool(semantic) and not missed and not refused and not unknown
    return {
        "format": FORMAT,
        "development_only": True,
        "claim": "Public development corpus; not held-out, not an efficacy estimate after tuning. A deny/withheld verdict is not proof of prevention.",
        "acceptance": "pass" if passed else "fail",
        "identities": identities,
        "denominators": {"semantic_cases": len(semantic), "attack": len(attacks), "benign": len(benign), "pairs": len(pairs),
                         "technical_reported_separately": len([r for r in rows if r["class"] == "technical"])},
        "totals": {"caught_instructions": len(attacks) - len(missed) - len([r for r in attacks if r["outcome"] == "unknown"]),
                   "missed_instructions": len(missed), "false_refusals": len(refused), "unknown_or_technical_errors": len(unknown)},
        "pair_outcomes": pair_status,
        "by_surface": breakdown(semantic, "surface"), "by_category": breakdown(semantic, "category"),
        "by_language": breakdown(semantic, "language"), "by_position": breakdown(semantic, "position"),
        "latency_micros": {"count": len(latencies), "p50": percentile(latencies, 0.5), "p95": percentile(latencies, 0.95),
                           "max": max(latencies) if latencies else None},
        "cases": rows,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True)
    p.add_argument("--payload-dir", required=True)
    p.add_argument("--adapter", required=True, help="built result_inspection_corpus example binary")
    p.add_argument("--policy", required=True)
    p.add_argument("--identity", action="append", default=[], metavar="KEY=VALUE", help="source/candidate identity to record")
    p.add_argument("--output")
    a = p.parse_args(argv)
    manifest = load_manifest(a.manifest)
    problems = verify_payloads(manifest, a.payload_dir)
    if problems:
        print("refused: payloads do not match the frozen manifest:\n  " + "\n  ".join(problems[:10]), file=sys.stderr)
        return 2
    try:
        done = subprocess.run([a.adapter, "--manifest", a.manifest, "--payload-dir", a.payload_dir, "--policy", a.policy],
                              capture_output=True, timeout=TIMEOUT)
        results = json.loads(done.stdout)["results"] if done.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print("refused: adapter failed: %s" % str(error)[:200], file=sys.stderr)
        return 2
    if results is None:
        print("refused: adapter exit %d: %s" % (done.returncode, done.stderr.decode("utf-8", "replace")[:300]), file=sys.stderr)
        return 2
    identities = dict(i.split("=", 1) for i in a.identity)
    identities.update({"manifest_sha256": sha(Path(a.manifest).read_bytes()), "policy_sha256": sha(Path(a.policy).read_bytes()),
                       "adapter_sha256": sha(Path(a.adapter).read_bytes())})
    report = build_report(manifest, results, identities)
    text = json.dumps(report, indent=1, ensure_ascii=False) + "\n"
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    t, d = report["totals"], report["denominators"]
    print("acceptance=%s attacks=%d caught=%d missed=%d benign=%d false_refusals=%d unknown=%d technical=%d" % (
        report["acceptance"], d["attack"], t["caught_instructions"], t["missed_instructions"], d["benign"],
        t["false_refusals"], t["unknown_or_technical_errors"], d["technical_reported_separately"]))
    return 0 if report["acceptance"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
