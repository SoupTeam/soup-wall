#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-204 source-bound demonstration of `agentfw mcp-schema-upgrade`.

Runs the already-built analyzer on the accepted filesystem/Git snapshots and the
labelled synthetic fixtures, twice per scenario (reproducibility), with an
isolated empty HOME/USERPROFILE and working directory. Records exit codes,
output digests, the binary digest, the source state (base revision plus the
line-ending-normalized git blob id of every changed file, excluding this
evidence directory) and digests of
protected files before and after. It starts no MCP server, installs nothing and
changes no configuration; `git` is used read-only for provenance.

Usage: python scripts/schema-upgrade-demo.py --agentfw target/debug/agentfw[.exe]
           --out docs/operations/evidence/sou-204-schema-upgrade-2026-11-03
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = "crates/agentfw/tests/fixtures/schema_upgrade"
FS = "profiles/mcp/filesystem-readonly-v1"
GIT = "profiles/mcp/git-readonly-v1"
# Historical: the accepted main SOU-204 started from.
ORIGINAL_BASE = "b385e7506ab26896637f348e3180e52d1fc6d423"
# The pinned main revision merged into the branch. SOU-204's own changes are
# measured against it, and unchanged dependencies are anchored to it.
INTEGRATION_BASE = "7f973f0b82480090e3de51111a90f550ea6a0d57"
KEEP_REPORTS = {
    "fs-identical", "git-identical", "fs-metadata-inert", "fs-malicious-metadata",
    "fs-required-default-type-enum", "fs-destination-controls-declared", "fs-unsupported",
    "git-semantic", "git-recursive-ref", "operator-authoring-declarations", "snapshot-only-git-semantic",
    "declaration-only-drift", "extreme-bound-before-snapshot-only",
}
# Inputs the analyzer, fixtures or demo depend on but SOU-204 does not change.
# Each must be byte-identical to its blob at INTEGRATION_BASE; upstream changes
# since ORIGINAL_BASE are recorded per file rather than hidden.
ACCEPTED_DEPENDENCIES = [
    "profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json",
    "profiles/mcp/filesystem-readonly-v1/upstream-identity.json",
    "profiles/mcp/filesystem-readonly-v1/upstream-notices/node-v22.22.0-LICENSE",
    "profiles/mcp/filesystem-readonly-v1/upstream-notices/servers-a40bc270-LICENSE",
    "profiles/mcp/filesystem-readonly-v1/upstream-notices/typescript-sdk-ff07b001-LICENSE",
    "profiles/mcp/git-readonly-v1/upstream-tools-list.json",
    "profiles/mcp/git-readonly-v1/upstream-identity.json",
    "profiles/mcp/git-readonly-v1/upstream-initialize.json",
    "profiles/mcp/git-readonly-v1/requirements.lock",
    "profiles/mcp/operator-authoring-v1/discovery.json",
    "profiles/mcp/operator-authoring-v1/declarations.json",
    "profiles/pilot/linux-readonly-v1/manifest.json",
    "scripts/install-sou62-filesystem-profile.py",
    "scripts/install-sou68-git-profile.py",
    "scripts/pilot_provider.py",
    "scripts/pilot_filesystem_roots.py",
    "crates/agentfw/src/mcp/input.rs",
    "crates/agentfw/src/mcp/admission.rs",
    "crates/agentfw/src/mcp/server_profile.rs",
    "crates/agentfw/src/mcp/manifest.rs",
    "crates/agentfw/src/native.rs",
    "crates/agentfw/src/config.rs",
    "crates/agentfw/Cargo.toml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
]
PROTECTED = [
    "profiles/mcp", "profiles/pilot", "policies/default.yaml", "firewall.yaml",
    "crates/agentfw/tests/fixtures/schema_upgrade",
]


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def tree_digest(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    if path.is_file():
        return {"exists": True, "sha256": sha_file(path)}
    entries = sorted(p for p in path.rglob("*") if p.is_file())
    rows = [f"{p.relative_to(path).as_posix()}\0{sha_file(p)}" for p in entries]
    return {"exists": True, "files": len(rows), "sha256": sha_bytes("\n".join(rows).encode())}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True,
                          text=True, timeout=60).stdout


def accepted_dependencies() -> dict:
    rows, ok = {}, True
    for path in ACCEPTED_DEPENDENCIES:
        integration_blob = git("rev-parse", f"{INTEGRATION_BASE}:{path}").strip()
        working_blob = git("hash-object", f"--path={path}", path).strip()
        unchanged = integration_blob == working_blob and \
            subprocess.run(["git", "diff", "--quiet", INTEGRATION_BASE, "--", path], cwd=ROOT).returncode == 0
        original = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ORIGINAL_BASE}:{path}"],
                                  cwd=ROOT, capture_output=True, text=True).stdout.strip() or None
        ok = ok and unchanged
        rows[path] = {"integration_baseline_blob": integration_blob, "working_tree_blob": working_blob,
                      "unchanged_vs_integration_baseline": unchanged, "original_base_blob": original,
                      "upstream_change_since_original_base": original != integration_blob}
    manifest = json.loads((ROOT / "crates/agentfw/tests/fixtures/schema_upgrade/MANIFEST.json").read_text(encoding="utf-8"))
    registry_checks = []
    for entry in manifest["fixtures"]:
        if entry["kind"] != "reproduced_installer_registry":
            continue
        installer_blob = git("rev-parse", f"{INTEGRATION_BASE}:{entry['installer']}").strip()
        imports_ok = all(git("rev-parse", f"{INTEGRATION_BASE}:{path}").strip() == blob
                         for path, blob in entry["installer_imports"].items())
        good = (entry["integration_baseline"] == INTEGRATION_BASE
                and entry["original_task_base"] == ORIGINAL_BASE
                and installer_blob == entry["installer_git_blob"] and imports_ok)
        ok = ok and good
        registry_checks.append({"fixture": entry["fixture"], "installer": entry["installer"],
                                "parameters": entry["parameters"],
                                "installer_git_blob": entry["installer_git_blob"],
                                "installer_imports": entry["installer_imports"],
                                "installer_and_imports_match_integration_baseline": good,
                                "provenance_status": entry["provenance_status"]})
    upstream = sorted(p for p, r in rows.items() if r["upstream_change_since_original_base"])
    return {"anchored_by": INTEGRATION_BASE, "original_task_base": ORIGINAL_BASE, "all_unchanged": ok,
            "upstream_changes_since_original_base": upstream, "files": rows,
            "reproduced_registry_provenance": registry_checks}


def source_state(evidence: Path) -> dict:
    head = git("rev-parse", "HEAD").strip()
    changed = set(git("diff", "--name-only", INTEGRATION_BASE).split())
    changed |= set(git("ls-files", "--others", "--exclude-standard").split())
    excluded = evidence.resolve().relative_to(ROOT.resolve()).as_posix()
    blobs, raw = {}, {}
    for name in sorted(changed):
        if name.startswith(excluded + "/") or not (ROOT / name).is_file():
            continue
        # Git blob id after the repository's own clean filters (line endings):
        # platform-independent and equal to `git rev-parse <commit>:<path>`
        # once committed. Computed without writing objects.
        blobs[name] = git("hash-object", f"--path={name}", name).strip()
        raw[name] = sha_file(ROOT / name)
    combined = sha_bytes("".join(f"{k}\0{v}\n" for k, v in blobs.items()).encode())
    contains = subprocess.run(["git", "merge-base", "--is-ancestor", INTEGRATION_BASE, "HEAD"],
                              cwd=ROOT).returncode == 0
    return {"original_task_base": ORIGINAL_BASE, "integration_baseline": INTEGRATION_BASE,
            "changes_measured_against": INTEGRATION_BASE, "head": head,
            "head_contains_integration_baseline": contains,
            "working_tree": "uncommitted changes on top of head" if blobs else "clean",
            "binding": "changed_files_git_blob is authoritative; working_tree_sha256 depends on "
                       "checkout line endings (core.autocrlf) and is informational",
            "changed_files_git_blob": blobs, "changed_files_manifest_sha256": combined,
            "working_tree_sha256": raw,
            "excluded_from_binding": excluded + "/ (this evidence; avoids circular self-hash)"}


def scenarios(tmp: Path) -> list[dict]:
    manifest = json.loads((ROOT / FIX / "MANIFEST.json").read_text(encoding="utf-8"))
    out = [
        {"id": "fs-identical", "label": "accepted filesystem snapshot vs itself",
         "args": ["--before", f"{FS}/upstream-tools-list.json", "--after", f"{FS}/upstream-tools-list.json",
                  "--before-identity", f"{FS}/upstream-identity.json",
                  "--registry", f"{FIX}/filesystem-readonly-v1.registry.json"], "expect_exit": 0},
        {"id": "git-identical", "label": "accepted Git snapshot vs itself",
         "args": ["--before", f"{GIT}/upstream-tools-list.json", "--after", f"{GIT}/upstream-tools-list.json",
                  "--before-identity", f"{GIT}/upstream-identity.json",
                  "--registry", f"{FIX}/git-readonly-v1.registry.json"], "expect_exit": 0},
    ]
    for entry in manifest["fixtures"]:
        if entry["kind"] not in ("mutated_upgrade_snapshot", "invalid_input"):
            continue
        base = FS if "filesystem" in entry["baseline"] else GIT
        registry = "filesystem-readonly-v1" if base == FS else "git-readonly-v1"
        out.append({"id": entry["fixture"][:-5], "label": "SYNTHETIC: " + entry["mutation"],
                    "args": ["--before", f"{base}/upstream-tools-list.json", "--after", f"{FIX}/{entry['fixture']}",
                             "--before-identity", f"{base}/upstream-identity.json",
                             "--registry", f"{FIX}/{registry}.registry.json",
                             "--before-label", f"{base}/upstream-tools-list.json@{INTEGRATION_BASE[:12]}",
                             "--after-label", f"SYNTHETIC {entry['fixture']}"],
                    "expect_exit": entry["expect"]["exit"],
                    "expect": entry["expect"]})
    out += [
        {"id": "fs-destination-controls-declared", "label": "SYNTHETIC control declarations: declared "
         "destination on move_file; proposed draft registry",
         "args": ["--before", f"{FS}/upstream-tools-list.json", "--after", f"{FIX}/fs-destination-controls.json",
                  "--registry", f"{FIX}/fs-control-current.registry.json",
                  "--proposed-registry", f"{FIX}/fs-control-proposed.registry.json"], "expect_exit": 5},
        {"id": "operator-authoring-declarations", "label": "accepted SOU-65 owned discovery/declarations "
         "vs itself (sw-mcp/operator-declaration/1 binding)",
         "args": ["--before", "profiles/mcp/operator-authoring-v1/discovery.json",
                  "--after", "profiles/mcp/operator-authoring-v1/discovery.json",
                  "--declarations", "profiles/mcp/operator-authoring-v1/declarations.json"], "expect_exit": 0},
        {"id": "declaration-only-drift", "label": "accepted filesystem snapshot vs itself; SYNTHETIC "
         "proposed registry changes only an action class",
         "args": ["--before", f"{FS}/upstream-tools-list.json", "--after", f"{FS}/upstream-tools-list.json",
                  "--before-identity", f"{FS}/upstream-identity.json",
                  "--registry", f"{FIX}/filesystem-readonly-v1.registry.json",
                  "--proposed-registry", f"{FIX}/fs-proposed-action-only.registry.json"], "expect_exit": 5,
         "expect": {"classification": "review_required"}},
        {"id": "declaration-only-control", "label": "accepted filesystem snapshot vs itself; proposed "
         "registry identical to the current one",
         "args": ["--before", f"{FS}/upstream-tools-list.json", "--after", f"{FS}/upstream-tools-list.json",
                  "--registry", f"{FIX}/filesystem-readonly-v1.registry.json",
                  "--proposed-registry", f"{FIX}/filesystem-readonly-v1.registry.json"], "expect_exit": 0,
         "expect": {"classification": "byte_identical"}},
        {"id": "extreme-bound-before", "label": "SYNTHETIC before snapshot with maxLength = u64::MAX vs the "
         "accepted Git snapshot (previously an overflow panic)",
         "args": ["--before", f"{FIX}/git-extreme-bound-before.json", "--after", f"{GIT}/upstream-tools-list.json",
                  "--registry", f"{FIX}/git-readonly-v1.registry.json"], "expect_exit": 2,
         "expect": {"refusal": "declaration_binding_mismatch"}},
        {"id": "extreme-bound-before-snapshot-only", "label": "same SYNTHETIC before snapshot, explicit "
         "--snapshot-only (reaches example generation)",
         "args": ["--before", f"{FIX}/git-extreme-bound-before.json", "--after", f"{GIT}/upstream-tools-list.json",
                  "--snapshot-only"], "expect_exit": 5, "expect": {"classification": "review_required"}},
        {"id": "snapshot-only-git-semantic", "label": "SYNTHETIC Git upgrade compared WITHOUT declarations "
         "(explicit --snapshot-only: semantic review unavailable)",
         "args": ["--before", f"{GIT}/upstream-tools-list.json", "--after", f"{FIX}/git-semantic.json",
                  "--before-identity", f"{GIT}/upstream-identity.json", "--snapshot-only"], "expect_exit": 5,
         "expect": {"analysis_mode": "snapshot_only"}},
        {"id": "control-missing-declarations", "label": "SYNTHETIC Git upgrade without declarations and "
         "without --snapshot-only (refusal)",
         "args": ["--before", f"{GIT}/upstream-tools-list.json", "--after", f"{FIX}/git-semantic.json"],
         "expect_exit": 2, "expect": {"refusal": "missing_declarations"}},
        {"id": "control-identity-mismatch", "label": "SYNTHETIC before snapshot checked against the "
         "accepted Git identity (refusal)",
         "args": ["--before", f"{FIX}/git-metadata-inert.json", "--after", f"{GIT}/upstream-tools-list.json",
                  "--before-identity", f"{GIT}/upstream-identity.json", "--snapshot-only"], "expect_exit": 2,
         "expect": {"refusal": "identity_digest_mismatch"}},
        {"id": "control-stale-registry", "label": "accepted Git registry presented against a synthetic "
         "before snapshot (refusal)",
         "args": ["--before", f"{FIX}/git-semantic.json", "--after", f"{GIT}/upstream-tools-list.json",
                  "--registry", f"{FIX}/git-readonly-v1.registry.json"], "expect_exit": 2,
         "expect": {"refusal": "declaration_binding_mismatch"}},
    ]
    oversized = tmp / "oversized.json"
    raw = (ROOT / GIT / "upstream-tools-list.json").read_bytes()
    oversized.write_bytes(raw + b" " * (262_145 - len(raw)))
    out.append({"id": "control-oversized", "label": "SYNTHETIC accepted Git bytes padded past 262144 bytes",
                "args": ["--before", f"{GIT}/upstream-tools-list.json", "--after", str(oversized),
                         "--snapshot-only"],
                "expect_exit": 2, "expect": {"refusal": "input_too_large"}, "temp_input": True})
    return out


def run(binary: Path, scenario: dict, out: Path, home: Path, cwd: Path) -> dict:
    path_flags = {"--before", "--after", "--before-identity", "--registry", "--declarations",
                  "--proposed-registry"}
    args = list(scenario["args"])
    for i in range(1, len(args)):
        if args[i - 1] in path_flags and not Path(args[i]).is_absolute():
            args[i] = str(ROOT / args[i])
    env = {"HOME": str(home), "USERPROFILE": str(home)}
    for key in ("SYSTEMROOT", "SystemRoot", "PATH"):
        if key in os.environ:
            env[key] = os.environ[key]
    result = subprocess.run([str(binary), "mcp-schema-upgrade", *args, "--out", str(out)], cwd=cwd,
                            env=env, capture_output=True, text=True, timeout=120)
    files = {}
    if out.is_dir():
        files = {p.name: sha_file(p) for p in sorted(out.iterdir())}
    return {"exit": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr.strip(),
            "outputs": files}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    evidence = args.out if args.out.is_absolute() else ROOT / args.out
    if evidence.exists():
        raise SystemExit("evidence directory must be new")
    binary = args.agentfw.resolve()
    real_home = Path.home() / ".agentfw"
    protected_before = {p: tree_digest(ROOT / p) for p in PROTECTED}
    protected_before["~/.agentfw (real Agent home)"] = tree_digest(real_home)
    with tempfile.TemporaryDirectory() as temp:
        tmp = Path(temp)
        home, cwd, runs = tmp / "home", tmp / "cwd", tmp / "runs"
        for d in (home, cwd, runs):
            d.mkdir()
        results = []
        for scenario in scenarios(tmp):
            first = run(binary, scenario, runs / f"{scenario['id']}-1", home, cwd)
            second = run(binary, scenario, runs / f"{scenario['id']}-2", home, cwd)
            summary = None
            report_path = runs / f"{scenario['id']}-1" / "report.json"
            if report_path.exists():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                summary = report["summary"]
            ok = first["exit"] == scenario["expect_exit"] and first == second
            exp = scenario.get("expect", {})
            if "refusal" in exp:
                ok = ok and exp["refusal"] in first["stderr"]
            if "analysis_mode" in exp:
                ok = ok and summary is not None and summary["analysis_mode"] == exp["analysis_mode"]
            if "classification" in exp:
                ok = ok and summary is not None and summary["classification"] == exp["classification"]
            display_args = ["<temp>/" + Path(a).name if scenario.get("temp_input") and a.endswith("oversized.json")
                            else a for a in scenario["args"]]
            results.append({"id": scenario["id"], "label": scenario["label"],
                            "command": "agentfw mcp-schema-upgrade " + " ".join(display_args) + " --out <new dir>",
                            "expect_exit": scenario["expect_exit"], "expect": exp,
                            "exit": first["exit"], "reproducible": first == second,
                            "stdout": first["stdout"], "stderr": first["stderr"],
                            "output_sha256": first["outputs"], "summary": summary,
                            "result": "PASS" if ok else "FAIL"})
            if scenario["id"] in KEEP_REPORTS and (runs / f"{scenario['id']}-1").is_dir():
                shutil.copytree(runs / f"{scenario['id']}-1", tmp / "keep" / scenario["id"])
        home_written = any(home.rglob("*"))
        cwd_written = any(cwd.rglob("*"))
        protected_after = {p: tree_digest(ROOT / p) for p in PROTECTED}
        protected_after["~/.agentfw (real Agent home)"] = tree_digest(real_home)
        evidence.mkdir(parents=True)
        if (tmp / "keep").exists():
            shutil.copytree(tmp / "keep", evidence / "runs")
    record = {
        "format": "sw-evidence/sou204-schema-upgrade-demo/1",
        "observation_kind": "concrete local runs of the built analyzer (Windows host)",
        "source": source_state(evidence),
        "accepted_dependencies": accepted_dependencies(),
        "binary": {"path": "target/debug/" + binary.name, "sha256": sha_file(binary)},
        "isolation": {"HOME_and_USERPROFILE": "fresh empty temporary directory",
                      "cwd": "fresh empty temporary directory",
                      "home_written": home_written, "cwd_written": cwd_written},
        "protected_files": {"before": protected_before, "after": protected_after,
                            "unchanged": protected_before == protected_after},
        "scenarios": results,
        "totals": {"scenarios": len(results), "pass": sum(r["result"] == "PASS" for r in results),
                   "fail": sum(r["result"] != "PASS" for r in results)},
        "not_observed_here": [
            "network traffic: no packet capture was run; absence of network use rests on code inspection "
            "and the source test analyzer_source_has_no_process_network_or_install_path",
            "child processes: not traced at OS level; same code-inspection basis",
        ],
    }
    (evidence / "evidence.json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n",
                                           encoding="utf-8", newline="\n")
    print(json.dumps(record["totals"]))
    ok = record["totals"]["fail"] == 0 and record["protected_files"]["unchanged"] \
        and record["accepted_dependencies"]["all_unchanged"] \
        and not home_written and not cwd_written
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
