# SPDX-License-Identifier: Apache-2.0
"""SOU-128 relation review: which asserted relations does each negative control break?

Runs eval/metamorphic_runner.py once with the accepted baselines and once per broken classifier in
eval/sou128_controls.py (direct mode; the "slow" control needs the worker deadline, so it runs in worker
mode). An asserted relation that no control can break is not shown to be sensitive; an equality
between abstentions (pass_vacuous) is listed separately. Observation-only relations are never scored.

usage: python3 eval/tools/sou128_relation_review.py --out-dir DIR
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval"))
sys.dont_write_bytecode = True
import sou128_controls  # noqa: E402

GATE = ROOT / "eval/metamorphic_runner.py"
UNTARGETED = ("fake_success/",)


def gate(out: Path, *args) -> tuple[int, dict]:
    done = subprocess.run([sys.executable, "-B", str(GATE), "--out-dir", str(out), *map(str, args)],
                          capture_output=True, text=True, encoding="utf-8", timeout=900)
    return done.returncode, json.loads((out / "report.json").read_bytes())


def review(work: Path) -> dict:
    code, base = gate(work / "baseline", "--modes", "direct")
    relations = base["modes"]["direct"]["relations"]
    asserted = [x for x in relations if x["kind"] != "observe"]
    killed_by = {x["id"]: [] for x in asserted}
    controls = {}
    for name in sorted(sou128_controls.CONTROLS):
        for profile in ("generic", "git"):
            path = sou128_controls.write_control(name, work, profile)
            mode = "worker" if name == "slow" else "direct"
            label = f"{name}/{profile}"
            exit_code, rep = gate(work / f"{name}-{profile}", "--modes", mode, "--classifier", f"{profile}={path}")
            broken = sorted(x["id"] for x in rep["modes"][mode]["relations"] if x["verdict"] == "fail")
            for rid in broken:
                killed_by[rid].append(label)
            controls[label] = {"mode": mode, "exit_code": exit_code, "verdict": rep["verdict"], "relations_broken": broken,
                               "unexpected_technical_errors": len(rep["modes"][mode]["unexpected_technical_errors"])}
    vacuous = sorted(x["id"] for x in asserted if not x["informative"])
    return {
        "baseline": {"exit_code": code, "verdict": base["verdict"], "identities": base["identities"]},
        "relations": {"total": len(relations), "asserted": len(asserted), "observe_only": len(relations) - len(asserted)},
        "controls": controls,
        "killed_by": killed_by,
        "unbroken_asserted": sorted(r for r, k in killed_by.items() if not k),
        # fake_success breaks nearly everything through the evaluator's output check; it proves nothing
        # about a specific relation, so a relation must also be broken by a targeted control.
        "broken_only_by_untargeted": sorted(r for r, k in killed_by.items() if k and all(c.startswith(UNTARGETED) for c in k)),
        "vacuous_on_baseline": vacuous,
        "controls_without_effect": sorted(n for n, c in controls.items() if c["exit_code"] == 0),
    }


def markdown(r: dict) -> str:
    lines = ["# SOU-128 relation review (generated)", "",
             f"Baseline verdict {r['baseline']['verdict']}; relations {r['relations']}.", "",
             "| control | mode | exit | verdict | relations broken |", "|---|---|---|---|---|"]
    lines += [f"| {n} | {c['mode']} | {c['exit_code']} | {c['verdict']} | {len(c['relations_broken'])} |" for n, c in r["controls"].items()]
    lines += ["", f"Asserted relations no control breaks: {r['unbroken_asserted'] or 'none'}",
              f"Broken only by the untargeted fake_success control: {r['broken_only_by_untargeted'] or 'none'}",
              f"Vacuous on the baseline (equal abstentions): {r['vacuous_on_baseline'] or 'none'}",
              f"Control/profile pairs with no effect (no corpus case exercises that defect there): "
              f"{r['controls_without_effect'] or 'none'}", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-dir", type=Path, required=True)
    a = ap.parse_args(argv)
    a.out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sou128-review-") as tmp:
        result = review(Path(tmp))
    (a.out_dir / "relation_review.json").write_bytes((json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    (a.out_dir / "relation_review.md").write_bytes(markdown(result).encode("utf-8"))
    print(markdown(result))
    # Sensitivity is judged per relation; a control with no effect on a profile is reported, not hidden.
    return 0 if (result["baseline"]["exit_code"] == 0 and not result["unbroken_asserted"]
                 and not result["broken_only_by_untargeted"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
