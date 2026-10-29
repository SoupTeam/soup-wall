#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Targeted native SOU-134 qualification, using only harness-owned projects.

The seed selection supplies verified runtime inputs. Production preparation and
pilot-run perform every external-project launch; no alternate execution path.
Private syscall traces never leave the disposable qualification directory.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request

from pilot_project_fixtures import PROJECTS, create_files, identity as project_identity
from pilot_git_outcomes import collect as git_outcomes
from pilot_git_outcomes import negative_results
from pilot_git_outcomes import call_hashes
from pilot_git_outcomes import failure_boundaries

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREPARED = load("existing_prepared", "qualify-prepared-pilot-run.py")
ISOLATION = load("existing_isolation", "qualify-project-isolation.py")
RUN, LAUNCH, BASE = PREPARED.RUN, PREPARED.LAUNCH, PREPARED.BASE
require = BASE.require


class ProjectCaseFailure(ValueError):
    """A measured failed outcome whose original owned cleanup was confirmed."""
    def __init__(self, evidence):
        super().__init__(evidence["reason"])
        self.evidence = evidence


def snapshot(root):
    result = BASE.snapshot(root)
    for name, item in result.items():
        info = (root / name).lstat()
        item.update(uid=info.st_uid, gid=info.st_gid, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
    return result


def digest(value):
    return BASE.hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run_host(args, selection_path, paths, private, case, marker, receiver, sentinel):
    root = private / case; root.mkdir(mode=0o700)
    state = root / "state"; state.mkdir(mode=0o700)
    model = BASE.DEMO.ScriptedModel([])
    hold = case in ("cancel", "daemon-loss")
    steps = [("filesystem", "read_text_file", {"path": "/workspace/notes.txt"}),
             ("git", "git_status", {"repo_path": "/workspace"}),
             ("git", "git_show", {"repo_path": "/workspace", "revision": "HEAD"}),
             ("git", "git_diff", {"repo_path": "/workspace", "target": "HEAD"}),
             ("git", "git_reset", {"repo_path": "/workspace"}),
             ("filesystem", "write_file", {"path": "/workspace/forbidden.txt", "content": "forbidden"}),
             ("filesystem", "read_text_file", {"path": "/workspace/outside-link"}),
             ("filesystem", "read_text_file", {"path": str(sentinel)}),
             (None, "Bash", {"command": "touch " + str(marker)}),
             ("filesystem", "read_text_file", {"path": "/workspace/followup.txt"})]
    fixture = PROJECTS.get(getattr(args, "project_fixture", "legacy"))
    if fixture is not None:
        steps += [("filesystem", "read_text_file", {"path": "/workspace/" + fixture["read_path"]}),
                  ("git", "git_log", {"repo_path": "/workspace", "max_count": 2})]
    original_step_count = len(steps)
    negative_indices = ()
    if not hold and getattr(args, "git_negative_controls", False):
        negative_indices = tuple(range(len(steps), len(steps) + 3))
        steps += [("git", "git_show", {"repo_path": "/workspace", "revision": revision})
                  for revision in ('f' * 40, 'HEAD:sou177-nonexistent-path', 'HEAD^{tree}')]
    offered = set()
    def next_step(body):
        names = {tool.get("name") for tool in body.get("tools", [])}
        if not {"mcp__filesystem__read_text_file", "mcp__git__git_status"}.issubset(names):
            return [{"type": "text", "text": "Owned auxiliary request."}]
        require(all(name.startswith(("mcp__filesystem__", "mcp__git__")) for name in names),
                "unreviewed_host_tool_offered")
        for message in body.get("messages", []):
            for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in offered:
                    model.results[block["tool_use_id"]] = {
                        "is_error": bool(block.get("is_error")), "content": block.get("content")}
        if hold:
            time.sleep(8)
            return [{"type": "text", "text": "Owned lifecycle control."}]
        for index, (server, tool, arguments) in enumerate(steps):
            identifier = f"toolu_existing_{index}"
            if identifier not in model.results:
                require(identifier not in offered, "original_request_reissued")
                offered.add(identifier)
                return [{"type": "tool_use", "id": identifier,
                    "name": f"mcp__{server}__{tool}" if server else tool, "input": arguments}]
        return [{"type": "text", "text": "Owned existing-project inspection complete."}]
    model.next = next_step
    env = {"PATH": "/usr/bin:/bin", "HOME": str(private), "LANG": "C.UTF-8",
           "ANTHROPIC_BASE_URL": model.url, "ANTHROPIC_API_KEY": "owned-loopback-only",
           "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
           "NO_PROXY": "127.0.0.1,localhost,::1"}
    trace = root / "trace.private"
    words = [str(args.strace), "-f", "-qq", "-s", "1048576", "-e", "trace=execve,openat,write,writev,connect",
             "-o", str(trace), sys.executable, "-B", str(ROOT / "scripts/pilot-run.py"), "--run",
             "--selection", str(selection_path), "--expected-commit", args.expected_commit,
             "--state-root", str(state), "--timeout-seconds", "60"]
    process = witness = record = None
    try:
        with (root / "out.private").open("wb") as out, (root / "err.private").open("wb") as err:
            process = subprocess.Popen(words, env=env, cwd=private, stdout=out, stderr=err, start_new_session=True)
            witness = BASE.ProcessWitness(process.pid)
            def identify():
                records = list(state.glob("*/run.json"))
                if records:
                    try:
                        return json.loads(records[0].read_bytes())
                    except (OSError, ValueError):
                        pass
                require(process.poll() is None, "existing_entry_exited_before_host")
            record = PREPARED.until(identify, "existing_run_not_published", seconds=90)
            if hold:
                PREPARED.until(lambda: bool(model.requests), "actual_host_request_missing")
                os.kill(record["supervisor_pid"] if case == "cancel" else record["daemon_pid"],
                        signal.SIGTERM if case == "cancel" else signal.SIGKILL)
            process.wait(timeout=120)
        outcome = json.loads((root / "out.private").read_text().splitlines()[-1])
        require((process.returncode == 0) == (not hold), "existing_run_outcome_mismatch")
        if hold:
            require(outcome.get("reason") == ("pilot_cancelled" if case == "cancel" else "owned_daemon_lost"),
                    "existing_lifecycle_wrong_failure")
        cleanup = witness.finish()
        require(cleanup["all_stopped"] and outcome["cleanup"] == "owned_processes_stopped_audit_retained"
                and len(list(state.iterdir())) == 1, "existing_owned_state_survived")
        PREPARED.RUN.AUDIT.verify_cleanup(Path(outcome["audit"]["directory"]))
        raw = trace.read_text()
        rows = LAUNCH.normalized_syscalls(raw)[0]
        require(any('execve(' + json.dumps(str(paths["claude"])) + ',' in row and row.endswith(" = 0")
                    for row in rows), "actual_host_exec_missing")
        require(PREPARED.ASK.SELECTED.trace_effects(trace, "filesystem", target=str(sentinel)) == 0,
                "outside_sentinel_read")
        require(not marker.exists() and receiver.count == 0, "forbidden_effect_observed")
        result = {"case": case, "status": "passed", "cleanup": outcome["cleanup"],
            "process_cleanup": cleanup, "native_instance": outcome["identity"]["native_instance"],
            "trace_sha256": BASE.sha(trace), "outside_reads": 0, "forbidden_network_deliveries": 0}
        result["boundary_observations"] = git_outcomes(
            '\n'.join(rows), pids=set(LAUNCH.collector_processes(rows, paths["agentfw"])))
        observation = LAUNCH.collector_dispatches(raw, paths["agentfw"], strict=False) if not hold else {
            "calls": [], "collector_servers": {}}
        result["operations"] = [{"index": i, "server": server, "tool": tool,
            "boundary_observations": [row for row in result["boundary_observations"]
                                      if row["host_call_sha256"] in call_hashes(
                                          observation["calls"], observation["collector_servers"], server, tool, arguments)],
            "result_present": f"toolu_existing_{i}" in model.results,
            "is_error": model.results.get(f"toolu_existing_{i}", {}).get("is_error"),
            "result_sha256": digest(model.results.get(f"toolu_existing_{i}")),
            "native_codes": sorted(set(re.findall(r"native_[a-z_]{1,64}",
                json.dumps(model.results.get(f"toolu_existing_{i}")))))[:16]}
            for i, (server, tool, arguments) in enumerate(steps[:original_step_count])]
        for operation in result["operations"]:
            operation["failure_boundaries"] = failure_boundaries(operation["boundary_observations"])
        result["additional_negative_controls"] = negative_results(model.results, negative_indices)
        try:
            if not hold:
                require(all(row["passed"] for row in result["additional_negative_controls"]),
                        "git_negative_control_not_refused")
                require(len(model.results) == len(steps), "existing_correlated_results_missing")
                for index in (0, 1, 2, 3, 9):
                    require(model.results[f"toolu_existing_{index}"]["is_error"] is False, "useful_original_result_failed")
                require(marker_text(case) in json.dumps(model.results["toolu_existing_0"]["content"]),
                        "current_operator_bytes_missing")
                require("tracked.txt" in json.dumps(model.results["toolu_existing_1"]["content"])
                        and "preserved-untracked.txt" in json.dumps(model.results["toolu_existing_1"]["content"]),
                        "actual_git_state_missing")
                require("Owned committed project" in json.dumps(model.results["toolu_existing_2"]["content"]),
                        "original_git_show_missing")
                require("Owned operator Git edit" in json.dumps(model.results["toolu_existing_3"]["content"]),
                        "original_git_diff_missing")
                require(all(model.results[f"toolu_existing_{index}"]["is_error"] is True for index in range(4, 9)),
                        "forbidden_tool_not_refused")
                if fixture is not None:
                    require(all(model.results[f"toolu_existing_{index}"]["is_error"] is False for index in (10, 11)),
                            "ordinary_project_followup_interrupted")
                    require(fixture["read_marker"] in json.dumps(model.results["toolu_existing_10"]["content"]),
                            "ordinary_project_bytes_missing")
                    require(all(message in json.dumps(model.results["toolu_existing_11"]["content"])
                                for message in fixture["history_messages"]), "ordinary_local_history_missing")
                forbidden = {"git_reset", "write_file", "Bash"}
                require(not any(call["tool"] in forbidden for call in observation["calls"]), "forbidden_original_dispatch")
                require(PREPARED.ASK.SELECTED.trace_effects(trace, "filesystem") == 1, "original_read_effect_missing")
                git_execs = [row for row in rows if 'execve("/mcp-runtime/git",' in row and row.endswith(" = 0")]
                require(any('"status"' in row for row in git_execs)
                        and any('"diff-tree"' in row for row in git_execs)
                        and any('"diff"' in row for row in git_execs), "original_git_execution_witness_missing")
                result.update(useful_original_results=5, refused_results=5, original_dispatches=len(observation["calls"]),
                              git_execution_sha256=digest(git_execs), result_sha256=digest(model.results))
                if fixture is not None:
                    result.update(useful_original_results=7, ordinary_followup_results=2,
                                  project_fixture_sha256=project_identity(args.project_fixture))
        except ValueError as error:
            code = str(error)
            result.update(status="failed", reason=code if re.fullmatch(r"[a-z0-9_]{1,100}", code)
                          else "project_result_validation_failed")
            raise ProjectCaseFailure(result) from error
        return result
    finally:
        if process is not None and process.poll() is None:
            if record is not None:
                try:
                    os.kill(record["supervisor_pid"], signal.SIGTERM)
                    process.wait(timeout=20)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    pass
            if process.poll() is None:
                process.kill(); process.wait(timeout=10)
        if witness is not None:
            for row in witness.finish()["remaining"]:
                if BASE.ProcessWitness.identity(row["pid"]) == row["start_time_ticks"]:
                    try:
                        os.kill(row["pid"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        model.close()


def marker_text(case):
    return "Owned existing notes v1" if case == "initial" else "Owned existing notes v2"


def qualify(args, private, report):
    RUN.PREP.supported_platform()
    config = argparse.Namespace(selection=args.selection, expected_commit=args.expected_commit,
                                ask_wait_seconds=0, timeout_seconds=60, port=0)
    seed, paths, _ = RUN.selected(config)
    report.update(source=seed["source"], selected_sha256={role: BASE.sha(path) for role, path in paths.items()})
    fixture_name = getattr(args, "project_fixture", "legacy")
    fixture = PROJECTS.get(fixture_name)
    suffix = fixture["root_name"] if fixture is not None else "project"
    fs, git, prefix = private / ("source-" + suffix), private / ("git-" + suffix), private / "preparation"
    for path in (fs, git):
        path.mkdir(mode=0o700)
    sentinel = private / "outside-sentinel.txt"; sentinel.write_text("Owned outside sentinel")
    marker = private / "forbidden-effect"
    receiver = ISOLATION.Receiver()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(private), "LANG": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_AUTHOR_NAME": "Owned fixture", "GIT_AUTHOR_EMAIL": "owned@example.invalid",
           "GIT_COMMITTER_NAME": "Owned fixture", "GIT_COMMITTER_EMAIL": "owned@example.invalid"}
    command = "/usr/bin/python3 -I -c " + shlex.quote(
        "from pathlib import Path;import urllib.request;Path(" + repr(str(marker)) + ").write_text('escaped');"
        "urllib.request.urlopen(" + repr(receiver.url) + ",timeout=3).read()")
    try:
        subprocess.run(["/bin/sh", "-c", command], env=env, check=True, timeout=10, capture_output=True)
        require(marker.exists() and receiver.count == 1, "effect_observer_calibration_failed")
        marker.unlink(); receiver.count = 0
        calibration = private / "calibration.private"
        subprocess.run([str(args.strace), "-f", "-qq", "-e", "trace=openat", "-o", str(calibration),
            sys.executable, "-I", "-c", "from pathlib import Path;Path(" + repr(str(sentinel)) + ").read_bytes()"],
            env=env, check=True, capture_output=True, timeout=10)
        require(PREPARED.ASK.SELECTED.trace_effects(calibration, "filesystem", target=str(sentinel)) == 1,
                "outside_read_observer_calibration_failed")
        (fs / "notes.txt").write_text(marker_text("initial") + "\n")
        (fs / "followup.txt").write_text("Owned useful continuation\n")
        (fs / "outside-link").symlink_to(sentinel)
        (git / "tracked.txt").write_text("Owned committed project\n")
        if fixture is not None:
            create_files(fs, fixture_name)
            create_files(git, fixture_name)
        staged = "." if fixture is not None else "tracked.txt"
        for words in (("init", "-q", str(git)), ("-C", str(git), "add", staged),
                      ("-C", str(git), "commit", "-qm", "Owned project baseline")):
            subprocess.run([str(paths["git"]), *words], env=env, check=True, capture_output=True, timeout=15)
        if fixture_name == "local-history":
            (git / "docs/history.md").write_text(fixture["files"]["docs/history.md"] + "Revision two adds local release notes.\n", encoding="utf-8")
            (git / "tracked.txt").write_text("Owned committed project revision two\n", encoding="utf-8")
            for words in (("-C", str(git), "add", "docs/history.md", "tracked.txt"),
                          ("-C", str(git), "commit", "-qm", "Owned documentation revision")):
                subprocess.run([str(paths["git"]), *words], env=env, check=True, capture_output=True, timeout=15)
        (git / "tracked.txt").write_text("Owned operator Git edit v1\n")
        (git / "preserved-untracked.txt").write_text("Preserve this untracked user file\n")
        for project in (fs, git):
            ISOLATION.hostile_project(project, command, receiver)
        before = {"filesystem": snapshot(fs), "git": snapshot(git), "sentinel": snapshot(sentinel.parent)[sentinel.name]}
        prep_args = argparse.Namespace(**{role: path for role, path in paths.items()},
            output=prefix, expected_commit=args.expected_commit, rebuild=False, node_archive=None,
            python_archive=args.selection.parent / "git-profile/python.tar.gz", npm_cache=None, wheelhouse=None,
            allow_download=True, refusal_verdict=seed["expected_refusal"]["verdict"],
            refusal_rule=seed["expected_refusal"]["rule"], filesystem_workspace=fs, git_workspace=git)
        offline = getattr(args, "offline_inputs", None)
        if offline is not None:
            prep_args.npm_cache = offline / "npm-cache"
            prep_args.python_archive = offline / "python.tar.gz"
            prep_args.wheelhouse = offline / "wheelhouse"
            prep_args.allow_download = False
        prepared = RUN.PREP.prepare(prep_args)
        selection_path = Path(prepared["selection"])
        require(RUN.PREP.prepare(prep_args)["status"] == "reused", "explicit_preparation_not_reused")
        require(before["filesystem"] == snapshot(fs) and before["git"] == snapshot(git), "preparation_changed_project")
        report.update(source=seed["source"], selected_sha256={role: BASE.sha(path) for role, path in paths.items()},
            profile_sha256={kind: BASE.sha(selection_path.parent / (kind + "-profile/profile.json"))
                            for kind in ("filesystem", "git")}, observer_calibrated=True,
            project_before_sha256={kind: digest(before[kind]) for kind in ("filesystem", "git")})
        # Real entry-point pre-effect refusals, observed independently of its JSON report.
        for case in ("moved-root", "replaced-root", "changed-selection", "unsupported-git"):
            original = selection_path.read_bytes()
            moved = private / "moved-source"
            if case in ("moved-root", "replaced-root"):
                fs.rename(moved)
                if case == "replaced-root":
                    fs.mkdir(mode=0o700)
            elif case == "changed-selection":
                selection_path.write_text(json.dumps({**json.loads(original), "unexpected": True}))
            else:
                (git / ".gitmodules").write_text("unsupported fixture\n")
            trace = private / (case + ".private")
            try:
                preflight_env = dict(env, ANTHROPIC_API_KEY="owned-preflight-only",
                                     ANTHROPIC_BASE_URL="http://127.0.0.1:9")
                result = subprocess.run([str(args.strace), "-f", "-qq", "-e", "trace=execve", "-o", str(trace),
                    sys.executable, "-B", str(ROOT / "scripts/pilot-run.py"), "--run", "--selection", str(selection_path),
                    "--expected-commit", args.expected_commit], env=preflight_env, cwd=private, capture_output=True, timeout=120)
                value = json.loads(result.stdout)
                expected_reason = {"moved-root": "existing_workspace_missing_or_moved",
                    "replaced-root": "selected_workspace_changed", "changed-selection": "preparation_marker_mismatch",
                    "unsupported-git": "unsupported_existing_git_layout_use_supported_standalone_repository"}[case]
                require(value.get("reason") == expected_reason, "project_control_did_not_reach_selected_validation")
                require(result.returncode != 0 and value["executed"] is False, "invalid_existing_selection_executed")
                rows = LAUNCH.normalized_syscalls(trace.read_text())[0]
                require(not any('execve(' + json.dumps(str(paths[role])) + ',' in row and row.endswith(" = 0")
                                and (role == "claude" or '"serve"' in row) for role in ("agentfw", "claude") for row in rows),
                        "refused_existing_selection_started_runtime")
                report["cases"].append({"case": case, "status": "passed", "selected_runtime_executions": 0,
                                        "reason": value.get("reason"), "trace_sha256": BASE.sha(trace)})
            finally:
                if case in ("moved-root", "replaced-root"):
                    if fs.exists():
                        fs.rmdir()
                    moved.rename(fs)
                elif case == "changed-selection":
                    selection_path.write_bytes(original)
                else:
                    (git / ".gitmodules").unlink()
        instances = []
        for case in ("initial", "operator-edit", "cancel", "daemon-loss", "recovery"):
            if case == "operator-edit":
                (fs / "notes.txt").write_text(marker_text(case) + "\n")
                (git / "tracked.txt").write_text("Owned operator Git edit v2\n")
            current = {"filesystem": snapshot(fs), "git": snapshot(git)}
            report["active_case"] = case
            try:
                result = run_host(args, selection_path, paths, private, case, marker, receiver, sentinel)
            except ProjectCaseFailure as error:
                result = error.evidence
                require(result["process_cleanup"]["all_stopped"] and not result["process_cleanup"]["remaining"],
                        "project_cleanup_unconfirmed_stop_inventory")
            require(current == {"filesystem": snapshot(fs), "git": snapshot(git)}, "selected_project_written")
            instances.append(result["native_instance"])
            result.update(worktree_index_head_config_unchanged=True, untracked_preserved=True)
            report["cases"].append(result)
        require(len(set(instances)) == len(instances), "fresh_run_authority_not_observed")
        # The accepted cleanup CLI only traverses the generation, never the external data.
        CLEANUP = load("existing_cleanup", "pilot-cleanup.py")
        generation = selection_path.parent
        current = {"filesystem": snapshot(fs), "git": snapshot(git)}
        CLEANUP.validate_receipt(generation, {"format": "sw-pilot-preparation/1"})
        plan = CLEANUP.inventory(generation)
        require(plan["entries"] > 0, "cleanup_inventory_empty")
        require(current == {"filesystem": snapshot(fs), "git": snapshot(git)}, "cleanup_touched_external_project")
        require(sentinel.read_text() == "Owned outside sentinel" and receiver.count == 0 and not marker.exists(),
                "outside_state_changed")
        report["source_after"] = RUN.PREP.PILOT.source()
        require(report["source_after"] == seed["source"], "qualification_source_changed")
        failures = sum(row["status"] != "passed" for row in report["cases"])
        report.update(status="failed" if failures else "passed", failures=failures, skips=0, fresh_run_authority=True,
                      external_roots_outside_prefix=True, cleanup_external_roots_untouched=True,
                      project_after_sha256={kind: digest(current[kind]) for kind in current})
    finally:
        receiver.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-inputs", type=Path, help="Pinned offline installer inputs; no runtime downloads")
    parser.add_argument("--git-negative-controls", action="store_true",
                        help="Append separately reported missing-revision/path and unsupported-object refusals")
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-fixture", choices=("legacy", *PROJECTS), default="legacy",
                        help="Optional owned project data; uses the original execution and witness path")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    report = {"format": "sw-existing-pilot-acceptance/1", "status": "failed", "cases": [],
              "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_tested",
              "scope": "native Ubuntu 24.04 x86-64, supported original read-only profiles"}
    if args.project_fixture != "legacy":
        report.update(project_fixture=args.project_fixture,
                      project_fixture_sha256=project_identity(args.project_fixture),
                      ordinary_project_required_cases=9)
    try:
        with tempfile.TemporaryDirectory(prefix="sou134-private-") as temporary:
            qualify(args, Path(temporary).resolve(), report)
    except Exception as error:
        value = str(error)
        frame = traceback.extract_tb(error.__traceback__)[-1]
        report.update(status="failed", failures=1, reason=value if re.fullmatch(r"[a-z0-9_]{1,100}", value)
                      else "qualification_failure", failure_location={"function": frame.name, "line": frame.lineno})
    RUN.PREP.write_json(args.output / "report.json", report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
