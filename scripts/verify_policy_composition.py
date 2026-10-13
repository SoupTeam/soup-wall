# SPDX-License-Identifier: Apache-2.0
"""Offline production decision matrix, existing mock judge and unchanged corpus."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MATRIX = "crates/agentfw/tests/fixtures/policy_matrix_v1.json"
POLICY = "crates/agent/policies/agent-default.yaml"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture(*args):
    return subprocess.check_output(args, cwd=ROOT).decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "target/policy-composition")
    args = parser.parse_args()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    # Never reuse a matrix result from an earlier failed build.
    (out / "matrix.json").unlink(missing_ok=True)
    tracked = capture("git", "ls-files", "-z").split("\0")
    prefixes = ("crates/agent/", "crates/agentfw/", "crates/core/", "crates/adapter/", "crates/bench/")
    source = {p: sha((ROOT / p).read_bytes()) for p in sorted(tracked) if p and (
        p.startswith(prefixes) or p in ("Cargo.lock", "Cargo.toml", POLICY, MATRIX,
                                       "scripts/verify_policy_composition.py", ".github/workflows/ci.yml"))}
    report = {
        "version": 1,
        "head": capture("git", "rev-parse", "HEAD"),
        "tree": capture("git", "rev-parse", "HEAD^{tree}"),
        "dirty": bool(capture("git", "status", "--porcelain", "--untracked-files=no")),
        "source_sha256": sha(json.dumps(source, sort_keys=True).encode()),
        "source_files": source,
        "policy_sha256": sha((ROOT / POLICY).read_bytes()),
        "input_sha256": sha((ROOT / MATRIX).read_bytes()),
        "commands": [],
        "scope": "Controlled component inputs and loopback mocks; no real provider or live effectiveness claim.",
    }
    commands = [
        ["rustc", "--version"],
        ["cargo", "run", "--locked", "-p", "agentfw", "--example", "policy_matrix", "--", MATRIX, str(out / "matrix.json")],
        ["cargo", "test", "--locked", "-p", "soup-wall-agent"],
        ["cargo", "test", "--locked", "-p", "agentfw", "--lib"],
        ["cargo", "test", "--locked", "-p", "agentfw", "--test", "judge_endpoint"],
        ["cargo", "test", "--locked", "-p", "agentfw", "--test", "native_endpoint"],
        ["cargo", "run", "--locked", "-p", "soup-wall-bench", "--", "--agent", "crates/bench/corpora/agent_sessions.jsonl", "--policy", POLICY],
    ]
    for index, command in enumerate(commands):
        log = out / f"{index:02d}.log"
        print("Running:", " ".join(command), flush=True)
        try:
            with log.open("wb") as stream:
                code = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=False).returncode
        except OSError as exc:
            log.write_text(str(exc), encoding="utf-8")
            code = 127
        report["commands"].append({"argv": command, "exit_code": code, "log": log.name, "log_sha256": sha(log.read_bytes())})
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    matrix = out / "matrix.json"
    if matrix.exists():
        report["matrix"] = json.loads(matrix.read_text(encoding="utf-8"))
    report["passed"] = all(c["exit_code"] == 0 for c in report["commands"]) and bool(report.get("matrix"))
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(
        f"# Policy composition evidence\n\nSource: `{report['head']}`; dirty: `{report['dirty']}`.\n\n"
        f"Source digest: `{report['source_sha256']}`.\n\nPolicy: `{report['policy_sha256']}`.\n\n"
        f"Inputs: `{report['input_sha256']}`.\n\nPassed: `{report['passed']}`.\n\n"
        + "\n".join(f"- `{c['log']}`: exit {c['exit_code']}" for c in report["commands"])
        + "\n\nSee report.json for all expected/actual rows and exact commands.\n", encoding="utf-8")
    print(f"Evidence: {out}; passed={report['passed']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
