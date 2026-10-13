# SPDX-License-Identifier: Apache-2.0
"""SOU-31: check the public Task 1 fixtures against the frozen versions and the accepted contract.

Checks, all without running a classifier:
  1. frozen fixture files are byte-identical to their recorded digests;
  2. make_v05.py regenerates the committed v0.5/v0.2 fixtures byte for byte;
  3. every fixture passes the runner's structural validation;
  4. v0.5/v0.2 follow the accepted SOU-10 v0.4 rules used for this version:
     decision IDs only, D07 for every expected no-op, D06 for every expected
     technical failure, D04 on every misleading-metadata case that has a description.

Exit 0 when every check passes, 1 otherwise.
usage: python3 eval/tools/check_fixtures.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "eval" / "fixtures"
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "eval" / "tools"))
sys.dont_write_bytecode = True

import eval_runner  # noqa: E402
import make_v05  # noqa: E402

FROZEN = {
    "soup_task1_evaluation_cases_v0.4.json": "047d522c8fcaaa61aa479f12a9e34eb7c6bd47dcd4c7005909e6837afea91044",
    "soup_task1_challenge_cases_v0.1.json": "48a445b5d53dd2cc77a999616f7042eff1962eaf8291ee099e6e88b5fe621a69",
    "soup_task1_mixed_actions_urtisto_v0.1.json": "9cab289f9fda0c6ac3b6cca0ad74e1e19adff0f7898d67807f4219b6bdf0701a",
    "soup_task1_benign_comparison_urtisto_v0.1.json": "636d31cd5248502ab8a07716671c5885827e47941748e121be9efa04e483f195",
}
GENERATED = ("soup_task1_evaluation_cases_v0.5.json", "soup_task1_challenge_cases_v0.2.json")
DECISION_IDS = {f"D{n:02d}" for n in range(1, 11)}


def sha256(path: Path) -> str:
    # Fixtures are LF text; a CRLF working copy (Windows autocrlf) hashes the same as the committed bytes.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def contract_problems(data: dict, name: str) -> list[str]:
    errs = []
    for c in data["cases"]:
        cid, exp, tags = c["id"], c["expected"], set(c["contract_assumptions"])
        if tags - DECISION_IDS:
            errs.append(f"{name} {cid}: non-decision tags {sorted(tags - DECISION_IDS)}")
        if exp.get("technical_failure") is not None:
            if "D06" not in tags or c["group"] != "input_validation" or c["expectation_status"] == "pending":
                errs.append(f"{name} {cid}: technical-failure case must be scored, input_validation and cite D06")
        elif exp["actions"] == [] and exp["unknown"] is False and "D07" not in tags:
            errs.append(f"{name} {cid}: expected no-op must cite D07")
        # Cases with a misleading name but no description (M05, CM06) are controls, not D04 cases.
        if c["group"] == "misleading_metadata" and c["input"].get("tool_description") and "D04" not in tags:
            errs.append(f"{name} {cid}: misleading-metadata case with a description must cite D04")
    return errs


def counts(data: dict) -> dict:
    cs = data["cases"]
    return {"cases": len(cs),
            "scored": sum(c["expectation_status"] != "pending" for c in cs),
            "pending": sum(c["expectation_status"] == "pending" for c in cs),
            "expected_no_op": sum(c["expected"]["actions"] == [] and c["expected"]["unknown"] is False for c in cs),
            "expected_technical_failure": sum(c["expected"].get("technical_failure") is not None for c in cs)}


def main() -> int:
    errs: list[str] = []
    for name, digest in FROZEN.items():
        if sha256(FIXTURES / name) != digest:
            errs.append(f"{name}: frozen fixture changed")
    with tempfile.TemporaryDirectory() as tmp:
        make_v05.main(["--out-dir", tmp])
        for name in GENERATED:
            if sha256(Path(tmp) / name) != sha256(FIXTURES / name):
                errs.append(f"{name}: does not match a fresh make_v05.py run")
    for name in list(FROZEN) + list(GENERATED):
        data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        errs += eval_runner.validate_fixture(data, name)
        if name in GENERATED:
            errs += contract_problems(data, name)
        print(f"{name}: sha256 {sha256(FIXTURES / name)} {json.dumps(counts(data))}")
    if errs:
        print("FAILED:\n  " + "\n  ".join(errs))
        return 1
    print("all fixture checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
