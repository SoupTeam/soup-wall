#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-191 negative controls: mutated COPIES of the retained genuine runs, never the originals.

Each control copies the evidence run directories to a temporary directory, applies one named
mutation and runs the comparison. Where a control targets a check deeper than custody, it re-seals
the recorded digests so that the deeper check, not a digest mismatch, must refuse it. Results are
written to ``controls.json``; a control fails when the observed exit code or error code differs.

    python scripts/benchmarks/result_inspection_controls.py \
      --evidence docs/benchmarks/evidence/sou191 --out docs/benchmarks/evidence/sou191/controls.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import result_inspection_compare as ric  # noqa: E402

CORPUS_FILES = ("eval/sou123/manifest.json", "eval/sou123/payloads", "profiles/pilot/linux-readonly-v1/policy.yaml")


def measured(role_dir: Path) -> Path:
    for path in ric.attempts(role_dir):
        if json.loads((path / "run.json").read_bytes())["status"] in ("executed", "integrity_failed"):
            return path
    raise SystemExit(f"{role_dir}: no executed attempt to derive controls from")


def load(run_dir):
    return json.loads((run_dir / "run.json").read_bytes())


def save(run_dir, run):
    (run_dir / "run.json").write_bytes((json.dumps(run, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))


def reseal_stdout(run_dir, run, raw):
    (run_dir / "adapter-stdout.json").write_bytes(raw)
    digest = ric._sha(raw)
    run["execution"]["stdout"].update(raw_sha256=digest, raw_bytes=len(raw), retained_sha256=digest,
                                      retained_bytes=len(raw))


def reseal_report(run_dir, run, report):
    raw = (json.dumps(report, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    (run_dir / "report.json").write_bytes(raw)
    run["report"]["sha256"] = ric._sha(raw)


def rebuild_report(run_dir, run, results, git, manifest):
    """Re-derive the report with the revision's own scorer so that only the targeted check can refuse."""
    report = json.loads((run_dir / "report.json").read_bytes())
    runner = ric.load_runner(git, run["revision"]["commit"])
    reseal_report(run_dir, run, runner.build_report(manifest, results, report["identities"]))


def results_of(run_dir):
    return json.loads((run_dir / "adapter-stdout.json").read_bytes())["results"]


def mutate_results(edit, resealed_report=True):
    def apply(ctx):
        run_dir = ctx["cand"]
        run = load(run_dir)
        results = results_of(run_dir)
        edit(results, ctx)
        reseal_stdout(run_dir, run, json.dumps({"results": results}).encode())
        if resealed_report:
            rebuild_report(run_dir, run, results, ctx["git"], ctx["manifest"])
        save(run_dir, run)
    return apply


def edit_payload(ctx):
    path = ctx["corpus"] / "eval/sou123/payloads/g01-a.txt"
    path.write_bytes(path.read_bytes() + b" ")


def edit_policy(ctx):
    path = ctx["corpus"] / "profiles/pilot/linux-readonly-v1/policy.yaml"
    path.write_bytes(path.read_bytes() + b"\n# drift\n")


def fake_success(ctx):
    run_dir = ctx["cand"]
    run = load(run_dir)
    report = json.loads((run_dir / "report.json").read_bytes())
    report["acceptance"] = "pass"
    report["totals"].update(missed_instructions=0, false_refusals=0)
    reseal_report(run_dir, run, report)
    save(run_dir, run)


def raw_edit_without_reseal(ctx):
    path = ctx["cand"] / "adapter-stdout.json"
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b'"Allow"', b'"Deny"', 1) if b'"Allow"' in raw else raw.replace(b'"Deny"', b'"Allow"', 1))


def claim_other_adapter_source(ctx):
    run_dir = ctx["cand"]
    run = load(run_dir)
    other = ric.Git(ctx["repo"]).blob_id(ctx["pre"]["revisions"]["baseline"]["commit"],
                                         "crates/agentfw/examples/result_inspection_corpus.rs")
    run["checkout"]["inputs"]["crates/agentfw/examples/result_inspection_corpus.rs"]["blob"] = other
    save(run_dir, run)


def executed_other_artifact(ctx):
    run_dir = ctx["cand"]
    run = load(run_dir)
    run["execution"]["artifact_sha256_before"] = load(ctx["base"])["build"]["artifact"]["sha256"]
    save(run_dir, run)


def timed_out(ctx):
    run_dir = ctx["cand"]
    run = load(run_dir)
    raw = (run_dir / "adapter-stdout.json").read_bytes()
    reseal_stdout(run_dir, run, raw[: len(raw) // 3])
    run["execution"].update(exit_code=None, timed_out=True)
    run["report"] = None
    (run_dir / "report.json").unlink()
    save(run_dir, run)


def unknown_and_technical(results, ctx):
    labels = {c["case_id"]: c for c in ctx["manifest"]["cases"]}
    attack = [r for r in results if labels[r["case_id"]]["class"] == "semantic"
              and labels[r["case_id"]]["label"] == "attack" and r["status"] == "inspected"]
    attack[0]["verdict"] = "Maybe"
    case_id = attack[1]["case_id"]
    attack[1].clear()
    attack[1].update(case_id=case_id, status="technical_error", reason="payload_not_utf8")
    attack[2]["status"] = "evidence_budget_not_inspected"


CONTROLS = [
    ("missing_case", "drop one planned case from the raw output (digests and report resealed)",
     mutate_results(lambda r, _: r.pop()), ric.EXIT_INVALID, "missing_case"),
    ("fabricated_case", "add a case ID absent from the frozen manifest (resealed)",
     mutate_results(lambda r, _: r.append(dict(r[0], case_id="z99-a")), resealed_report=False), ric.EXIT_INVALID,
     "fabricated_case"),
    ("duplicate_case", "repeat one case (resealed)",
     mutate_results(lambda r, _: r.append(dict(r[0])), resealed_report=False), ric.EXIT_INVALID, "duplicate_case"),
    ("altered_payload", "append one byte to payload g01-a in the compared corpus", edit_payload, ric.EXIT_INVALID,
     "payload_altered"),
    ("altered_policy", "append a comment to the compared policy", edit_policy, ric.EXIT_INVALID, "policy_or_corpus_drift"),
    ("fake_aggregate_success", "set acceptance=pass and zero totals in the report, digest resealed", fake_success,
     ric.EXIT_INVALID, "report_not_derivable"),
    ("raw_output_edited", "flip one verdict in the raw output without updating the record", raw_edit_without_reseal,
     ric.EXIT_INVALID, "custody_mismatch"),
    ("source_claim_mismatch", "candidate record claims the baseline adapter blob; checked against Git objects",
     claim_other_adapter_source, ric.EXIT_INVALID, "source_mismatch"),
    ("artifact_mismatch", "candidate execution records the baseline artifact hash", executed_other_artifact,
     ric.EXIT_INVALID, "artifact_integrity"),
    ("incomplete_run", "candidate run recorded as timed out with a third of its output", timed_out,
     ric.EXIT_COMPARABLE, None),
    ("unknown_and_technical", "one invalid verdict, one technical error, one budget refusal (resealed)",
     mutate_results(unknown_and_technical), ric.EXIT_COMPARABLE, None),
]


def run_controls(evidence: Path, repo: Path):
    pre_path = evidence / "predeclaration.json"
    pre = json.loads(pre_path.read_bytes())
    corpus = ric.load_corpus(repo)
    rows = []
    for name, mutation, apply, expected_code, expected_error in CONTROLS:
        with tempfile.TemporaryDirectory(prefix=f"sou191-{name}-") as tmp:
            tmp = Path(tmp)
            dirs = {}
            for role in ric.ROLES:
                source = measured(evidence / "runs" / role)
                dirs[role] = tmp / role / source.name
                shutil.copytree(source, dirs[role])
            root = tmp / "corpus"
            for rel in CORPUS_FILES:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (shutil.copytree if (repo / rel).is_dir() else shutil.copyfile)(repo / rel, root / rel)
            ctx = {"base": dirs["baseline"], "cand": dirs["candidate"], "corpus": root, "repo": repo, "pre": pre,
                   "git": ric.Git(repo), "manifest": corpus["manifest"]}
            apply(ctx)
            result, code = ric.compare(pre_path, tmp / "baseline", tmp / "candidate", repo, root)
            error = result["errors"][0]["code"] if result["errors"] else None
            row = {"control": name, "synthetic_mutation": mutation, "expected_exit": expected_code,
                   "observed_exit": code, "expected_error": expected_error, "observed_error": error,
                   "passed": code == expected_code and error == expected_error}
            if name == "incomplete_run" and code == ric.EXIT_COMPARABLE:
                d = result["denominators"]["candidate"]["attack"]
                row["candidate_attack_denominators"] = d
                row["passed"] = row["passed"] and d["attempted"] is None and d["unobserved"] == d["planned"]
            if name == "unknown_and_technical" and code == ric.EXIT_COMPARABLE:
                d = result["denominators"]["candidate"]["attack"]
                row["candidate_attack_denominators"] = d
                row["passed"] = row["passed"] and (d["unknown"], d["error"]) == (1, 1) and d["incomplete"] >= 1
            rows.append(row)
    return {"schema": "soup-wall-result-inspection-controls/1",
            "note": "Every control is a synthetic mutation of a temporary copy of the retained genuine runs; none "
                    "is evidence about a revision.", "controls": rows, "all_passed": all(r["passed"] for r in rows)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = run_controls(Path(args.evidence), Path(args.repo).resolve())
    Path(args.out).write_bytes((json.dumps(result, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    for row in result["controls"]:
        print(f"{'PASS' if row['passed'] else 'FAIL'} {row['control']}: exit {row['observed_exit']} {row['observed_error']}")
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
