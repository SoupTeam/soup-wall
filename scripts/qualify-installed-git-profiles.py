#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused SOU-162 installed original-host qualification on native Ubuntu 24.04.

Uses only disposable owned projects, the pinned genuine Claude/Git MCP and the
existing scripted provider. Every command runs outside the checkout through
`agentfw pilot`. This is not a shared CI matrix or a candidate-kit builder.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_git_profiles as G


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSTALLED = load("git_profiles_installed", "qualify-installed-front-door.py")
QUAL, BASE = INSTALLED.QUAL, INSTALLED.BASE
require = BASE.require
VARIANTS = (G.DEFAULT, "git-readonly-file-revisions-v1", "git-tracked-symlinks-readonly-v1")


def checked(door, command, *extra, status=None, **options):
    code, value, _ = door.call(command, *extra, **options)
    if code != 0:
        door.args.stage_failures.append({"command": command, "exit": code, "report": value})
    require(code == 0 and (status is None or value.get("status") == status),
            command + "_failed:" + str(value.get("reason") or value.get("missing")))
    return value


def qualify(args, report):
    preparation = load("qualification_platform", "prepare-installed-pilot.py")
    audit = load("qualification_retained_audit", "pilot_audit.py")
    preparation.supported_platform()
    report["platform"] = {"system": platform.system(), "machine": platform.machine(),
                          "kernel": platform.release(), "os_release_sha256": BASE.sha(Path("/etc/os-release"))}
    before = preparation.PILOT.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "exact_clean_source_required")
    report["source_before"] = before
    normal_git = args.git
    home = args.output / "operator-home"
    home.mkdir(mode=0o700)
    QUAL.user_config(home)
    env = QUAL.qualification_environment(home)
    agent_home = args.output / "agent-home"
    agent_home.mkdir(mode=0o700)
    work = args.output / "outside-checkout"
    work.mkdir(mode=0o700)
    require(not work.is_relative_to(ROOT), "outside_checkout_required")
    args.work = work
    built = INSTALLED.build(ROOT, args.output / "component.tar", env)
    report["component"] = built
    INSTALLED.install_component(args, agent_home, args.output / "component.tar", built["archive_sha256"],
                                built["component"], env, report)
    receiver = QUAL.ISOLATION.Receiver()
    sentinel = args.output / "outside-sentinel.txt"
    sentinel.write_text("Owned outside sentinel; never selected by Git.\n")
    try:
        args.project = args.output / "project"
        args.repository = args.output / "repository"
        marker = QUAL.make_projects(args, env, receiver)
        args.other_prefix = args.output / "unused-other-prefix"
        baseline_home = QUAL.snapshot(home)
        for name in VARIANTS:
            args.git = args.static_git if name == "git-tracked-symlinks-readonly-v1" else normal_git
            args.prefix = args.output / name
            args.state_root = args.output / (name + "-runs")
            args.state_root.mkdir(mode=0o700)
            link = args.repository / "tracked-link.txt"
            if name == "git-tracked-symlinks-readonly-v1":
                link.symlink_to("tracked.txt")
                for words in (("add", "tracked-link.txt"), ("commit", "-qm", "Owned bounded tracked link")):
                    subprocess.run([str(args.git), "-C", str(args.repository), *words], env=env,
                                   check=True, capture_output=True, timeout=15)
            baseline = {"project": QUAL.snapshot(args.project), "repository": QUAL.snapshot(args.repository),
                        "sentinel": sentinel.read_bytes()}
            door = INSTALLED.InstalledDoor(args, env, work, agent_home)
            trace = args.output / (name + "-preview.trace.private")
            preview = checked(door, "preview", "--git-profile", name, trace=trace)
            observed = QUAL.executed(trace, {role: getattr(args, role) for role in QUAL.SELECTED_PROGRAMS
                                             if role != "agentfw" and getattr(args, role) is not None})
            require(preview["executed"] is False and not preview["missing"] and not args.prefix.exists()
                    and not observed["selected_started"] and observed["inet_connects"] == 0,
                    "preview_effect_or_missing_input")
            require(preview["git_selection"] == G.binding(name), "preview_selection_mismatch")
            trace.unlink()
            prepared = checked(door, "prepare", "--apply", "--git-profile", name, timeout=3600)
            selection_path = Path(prepared["selection"])
            selection = json.loads(selection_path.read_bytes())
            require(selection["format"] == G.SELECTION_V3 and G.from_selection(selection) == name,
                    "prepared_selection_mismatch")
            report["selections"][name] = {"selection_sha256": BASE.sha(selection_path),
                "source": selection["source"], "files": selection["files"],
                "prepared_profiles": selection["prepared_profiles"], "git_selection": selection["git_selection"]}
            require(checked(door, "prepare", "--apply", inputs=False)["status"] == "reused", "reuse_failed")
            status = checked(door, "status", "--state-root", str(args.state_root), inputs=False)
            require(status["protection"] == "configured-not-running"
                    and status["selection"]["git_selection"] == G.binding(name), "configured_status_mismatch")
            if name == "git-readonly-file-revisions-v1":
                head = subprocess.check_output([str(args.git), "-C", str(args.repository), "rev-parse", "HEAD"],
                                               env=env, timeout=15).decode().strip()
                proposals = [("mcp__git__git_show", {"repo_path": "/workspace", "revision": revision})
                             for revision in ("HEAD:tracked.txt", head + ":tracked.txt",
                                              "refs/heads/main:tracked.txt", "HEAD:tracked.txt")]
                refused_indices, useful_indices = (2,), (0, 1, 3)
            elif name == "git-tracked-symlinks-readonly-v1":
                proposals = [("mcp__git__" + tool, {"repo_path": "/workspace", **arguments}) for tool, arguments in (
                    ("git_status", {}), ("git_diff", {"target": "HEAD"}), ("git_diff_untracked", {}),
                    ("git_diff_staged", {}), ("git_log", {"max_count": 3}), ("git_show", {"revision": "HEAD"}))]
                proposals += [("mcp__git__git_status", {"repo_path": str(sentinel.parent)}),
                              ("mcp__git__git_status", {"repo_path": "/workspace"})]
                refused_indices, useful_indices = (6,), (0, 1, 2, 3, 4, 5, 7)
            else:
                proposals = [("mcp__git__git_show", {"repo_path": "/workspace", "revision": "HEAD"}),
                             ("mcp__git__git_show", {"repo_path": "/workspace", "revision": "HEAD:tracked.txt"}),
                             ("mcp__git__git_status", {"repo_path": "/workspace"})]
                refused_indices, useful_indices = (1,), (0, 2)
            label = name.replace("git-", "")
            row, results, outcome = QUAL.run_case(args, door, report, label, proposals)
            row["launch_outcome"] = outcome
            if outcome.get("audit", {}).get("directory"):
                row["audit_export"] = audit.export_run(Path(outcome["audit"]["directory"]),
                    args.output / (label + ".audit.json"), outcome["audit"]["run_id"])
            require(row["exit"] == 0 and row["process_cleanup"]["all_stopped"], "useful_run_or_cleanup_failed")
            require(row["live_status"]["protection"] == "observed-live", "live_status_not_verified")
            require(outcome["git_selection"] == G.binding(name), "run_selection_mismatch")
            require(len(results) == len(proposals), "correlated_results_missing")
            for index in useful_indices:
                require(results[f"toolu_front_{label}_{index}"]["is_error"] is False, "useful_original_call_refused")
            for index in refused_indices:
                require(results[f"toolu_front_{label}_{index}"]["is_error"] is True, "unsupported_call_released")
            require("Owned tracked content" in json.dumps(results[f"toolu_front_{label}_0"]["content"])
                    if name == "git-readonly-file-revisions-v1" else True, "per_file_bytes_missing")
            row.update(passed=True, git_selection=G.binding(name), successful_original_calls=len(useful_indices),
                       refused_calls=len(refused_indices), observed_identity=outcome["identity"],
                       selection_sha256=outcome["selection_sha256"], profiles=outcome["profiles"],
                       resource_budget=outcome["resource_budget"])
            # Preserve both failed and successful attempts; cancellation uses fresh
            # authority, and a separate successful run proves useful restart.
            if name != G.DEFAULT:
                cancelled, _, _ = QUAL.run_case(args, door, report, label + "-cancel", proposals[:1],
                                                hold=True, cancel=signal.SIGINT)
                require(cancelled["reason"] == "pilot_cancelled" and cancelled["process_cleanup"]["all_stopped"],
                        "cancellation_cleanup_failed")
                cancelled["passed"] = True
                resumed, resumed_results, _ = QUAL.run_case(args, door, report, label + "-restart", proposals[:1])
                require(resumed["exit"] == 0 and resumed["process_cleanup"]["all_stopped"]
                        and len(resumed_results) == 1 and not next(iter(resumed_results.values()))["is_error"],
                        "useful_restart_failed")
                resumed["passed"] = True
            # Alter manifests / profile bytes while retaining the published
            # selection digest. Neither may launch or silently rebind authority.
            original = selection_path.read_bytes()
            for fault in ("binding", "source"):
                altered = json.loads(original)
                altered["git_selection"]["registry_id"] = "unreviewed-union" if fault == "binding" else name
                if fault == "source":
                    altered["source"]["commit"] = "0" * 40
                selection_path.write_text(json.dumps(altered))
                code, value, _ = door.call("status", inputs=False)
                require(code == 0 and value["selection"]["state"] == "stale"
                        and value["protection"] == "unavailable", "altered_manifest_not_stale")
                selection_path.write_bytes(original)
            profile_path = Path(selection["prepared_profiles"]["git"]["profile"]["path"])
            original_profile = profile_path.read_bytes()
            profile_path.write_bytes(original_profile + b"\n ")
            code, value, _ = door.call("status", inputs=False)
            require(code == 0 and value["selection"]["state"] == "stale", "altered_profile_not_stale")
            profile_path.write_bytes(original_profile)
            code, value, _ = door.call("preview", "--git-profile", name + "+" + G.DEFAULT, inputs=False)
            require(code != 0 and value.get("executed") is not True, "unsupported_union_not_refused")
            require(QUAL.snapshot(args.project) == baseline["project"]
                    and QUAL.snapshot(args.repository) == baseline["repository"]
                    and sentinel.read_bytes() == baseline["sentinel"] and QUAL.snapshot(home) == baseline_home
                    and receiver.count == 0 and not marker.exists(), "workspace_index_head_or_outside_changed")
            if link.is_symlink():
                link.unlink()
                link.symlink_to("../outside-sentinel.txt")
                unsafe_baseline = QUAL.snapshot(args.repository)
                code, value, _ = door.call("prepare", "--apply", "--rebuild", "--git-profile", name, timeout=3600)
                require(code != 0 and value.get("reason") ==
                        "unsupported_existing_git_layout_use_supported_standalone_repository", "escaping_link_not_refused")
                require(QUAL.snapshot(args.repository) == unsafe_baseline and sentinel.read_bytes() == baseline["sentinel"],
                        "escaping_link_validation_effect")
                link.unlink()
                link.symlink_to("tracked.txt")
            report["cases"].append({"case": name + "-integrity-controls", "passed": True,
                "workspace_index_head_unchanged": True, "outside_sentinel_unchanged": True,
                "manifest_profile_source_tampering_refused": True, "unsupported_union_refused": True})
        require(preparation.PILOT.source() == before, "qualification_source_changed")
        report["source_after"] = before
    finally:
        receiver.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--component-python", type=Path, required=True)
    parser.add_argument("--static-git", type=Path, required=True,
                        help="separate pinned static Git input for the accepted tracked-link installer")
    parser.add_argument("--allow-download", action="store_true")
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    for name in INSTALLED.INPUT_NAMES:
        parser.add_argument("--" + name.replace("_", "-"), type=Path)
    args = parser.parse_args()
    args.agent_output = None
    args.output = args.output.resolve()
    report = {"format": "sw-installed-git-profiles-qualification/1", "status": "failed", "cases": [],
              "stage_failures": [], "selections": {}, "skipped": 0, "provider": "owned-scripted-loopback",
              "unqualified": ["WSL2", "macOS", "Windows"]}
    args.stage_failures = report["stage_failures"]
    try:
        require(not args.output.exists() and not args.output.is_relative_to(ROOT), "new_output_outside_checkout_required")
        args.output.mkdir(mode=0o700)
        report["inputs_sha256"] = {name: BASE.sha(getattr(args, name)) for name in (*INSTALLED.INPUT_NAMES, "static_git")
                                   if getattr(args, name) is not None and getattr(args, name).is_file()}
        qualify(args, report)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)[:500]
    finally:
        if args.output.exists():
            BASE.write(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
