#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify the installed first-parent Git profile with the pinned original server."""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile

import pilot_git_profiles as profiles
import pilot_policy
from pilot_git_outcomes import project

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sou244_original", ROOT / "scripts/verify-sou68-real-mcp.py")
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)
require, sha, write = original.require, original.sha, original.write
base = original.BASE

TARGET = {"target": "HEAD~1", "context_lines": 3}
INVALID_DIFFS = {
    "second_ancestor": "HEAD~2",
    "caret_parent": "HEAD^1",
    "reflog": "HEAD@{0}",
    "revision_path": "HEAD~1:notes.txt",
    "relative_path": "./HEAD~1",
}
PARENT_FAILURES = (
    "no_parent", "unavailable_parent", "malformed_parent", "wrong_kind_parent", "invalid_parent_commit_body",
)
POSITIVES = {"merge_first_parent", "fresh_session_restored"}
NEGATIVES = set(INVALID_DIFFS) | set(PARENT_FAILURES) | {
    "show_head_tilde_one", "literal_path_collision", "branch_replaced_and_restored", "parent_object_replaced_and_restored",
}


def fixture(repo, git, env):
    def command(*args, data=None):
        return subprocess.run([git, "-C", repo, *args], env=env, input=data, capture_output=True,
                              check=True, timeout=10).stdout.strip()

    def staged_tree(text):
        (repo / "notes.txt").write_text(text + "\n", encoding="utf-8")
        command("add", "notes.txt")
        return command("write-tree").decode()

    repo.mkdir(mode=0o700)
    command("init", "-q", "-b", "main", "--template=")
    for path in ("objects/info", "objects/pack", "info", "refs/heads"):
        (repo / ".git" / path).mkdir(parents=True, exist_ok=True)
    first = command("commit-tree", staged_tree("Owned first-parent text"), "-m", "first parent")
    second = command("commit-tree", staged_tree("Owned second-parent text"), "-m", "second parent")
    tree = staged_tree("Owned merge text")
    head = command("commit-tree", tree, "-m", "merge", "-p", first.decode(), "-p", second.decode())
    branch = repo / ".git/refs/heads/main"
    branch.write_bytes(head + b"\n")

    def loose_commit(payload):
        return command("hash-object", "-t", "commit", "-w", "--stdin", "--literally", data=payload)

    def invalid_parent(parent):
        identity = b"Owner <owner@example.invalid> 1 +0000"
        return loose_commit(b"tree " + tree.encode() + b"\nparent " + parent
                            + b"\nauthor " + identity + b"\ncommitter " + identity + b"\n\nOwned control\n")

    invalid_body = loose_commit(b"tree " + tree.encode() + b"\n")
    failures = (first, invalid_parent(b"1" * 40), invalid_parent(b"malformed"),
                invalid_parent(tree.encode()), invalid_parent(invalid_body))
    oid = first.decode()
    return branch, head, dict(zip(PARENT_FAILURES, failures, strict=True)), repo / ".git/objects" / oid[:2] / oid[2:]


def replace_and_restore(path):
    backup = path.with_name("owned-retained")
    path.rename(backup)
    backup.rename(path)


def reference(python, repo, env, output):
    with (output / "reference.log").open("xb") as log:
        client = original.Client([python, "-I", "-B", "-m", "mcp_server_git", "--repository", repo],
                                 env, repo, log, "first-parent independent reference")
        try:
            client.initialize()
            response, raw = client.exchange(original.call(10, "git_diff", TARGET, repo))
            text = original.text(response)
            require("-Owned first-parent text" in text and "+Owned merge text" in text
                    and "Owned second-parent text" not in text, "reference selected the wrong merge parent")
        finally:
            client.close()
    require(cleaned(client), "reference process cleanup unverified")
    return raw


def cleaned(client):
    return (not client.forced_cleanup and client.process.returncode == 0
            and client.process_witness.final["all_stopped"]
            and client.process_witness.final["descendant_count"] > 0)


def control(output, repo, command, env, row, *, expected=None, mutate=None, follow="useful"):
    witness = client = None
    path = output / (row["control"] + ".log")
    frame = original.call(10, row["tool"], row["arguments"])
    try:
        with path.open("xb") as log:
            client = original.Client(command, env, repo, log, "first-parent original collector")
            client.initialize()
            if mutate is not None:
                replace_and_restore(mutate)
            witness = original.RepositoryWitness(repo)
            response, raw = client.exchange(frame)
            request = sha256(client.sent[-1]).hexdigest()
            response_digest = sha256(raw).hexdigest()
            rows = [entry for name in ("mcp_call_outcome", "mcp_original_result_delivery_timing")
                    for line in base.events(path, name)
                    if (entry := project(line)) is not None and entry["request_sha256"] == request]
            stages = {entry["stage"]: entry for entry in rows}
            require(len(stages) == len(rows), "duplicate original call stage")
            reads = witness.drain()
            row.update(request_sha256=request, client_response_sha256=response_digest,
                       boundaries=stages, repository_open_events=reads)
            if expected is None:
                require(response.get("error", {}).get("code") == -32602 and not set(stages) - {"input_profile"}
                        and reads == 0, "expected correlated pre-dispatch refusal with no repository opens")
                row["dispatched"] = False
            else:
                require(raw == expected and not base.refused(response) and reads > 0,
                        "protected original bytes differ from independent reference")
                require(stages["call_admission"]["released"] and stages["profile_validation"]["accepted"]
                        and stages["result_inspection"]["released"] and stages["host_delivery"]["written"]
                        and all(stages[name]["response_sha256"] == response_digest
                                for name in ("original_response", "profile_validation",
                                             "result_inspection", "host_delivery")),
                        "original response, inspection and delivery evidence differ")
                row.update(dispatched=True, original_equals_reference=True)
            if follow == "useful":
                result, _ = client.exchange(original.call(11, "git_status", {}))
                require("On branch main" in original.text(result) and witness.drain() > 0, "git_status continuation lost")
                row["useful_continuation"] = True
            elif follow == "withdrawn":
                result, _ = client.exchange(original.call(11, "git_status", {}))
                require(result.get("error", {}).get("code") == -32602 and witness.drain() == 0,
                        "withdrawn session regained repository access")
                row["sticky_session_withdrawal"] = True
    finally:
        if witness is not None:
            witness.close()
        if client is not None:
            client.close()
            row["cleanup"] = cleaned(client)
    require(row.get("cleanup") is True, "collector process cleanup unverified")


def qualify(args, output, scratch, report):
    repo, home, installed = (scratch / name for name in ("repo", "home", "installed"))
    home.mkdir(mode=0o700)
    env = base.environment(home)
    env.update(PATH=f"{args.git.parent}:/usr/bin:/bin", LANG="C.UTF-8", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
               GIT_PYTHON_GIT_EXECUTABLE=str(args.git))
    for who in ("AUTHOR", "COMMITTER"):
        env.update({f"GIT_{who}_NAME": "Owned control", f"GIT_{who}_EMAIL": "control@example.invalid",
                    f"GIT_{who}_DATE": "2026-10-23T09:00:00+00:00"})
    branch, head, failures, parent_object = fixture(repo, args.git, env)
    with (output / "installer.log").open("xb") as log:
        profiles.install(profiles.FIRST_PARENT, installed, repo, args.git, args.git_sha256, args.bwrap,
                         args.git_launcher, python_archive=args.python_archive, wheelhouse=args.wheelhouse,
                         allow_download=args.allow_download, log=log)
    python = installed / "package/python/bin/python3.11"
    port = base.DEMO.free_port()
    config, selection = pilot_policy.prepare("git", installed, scratch / "selection", port, python,
                                             git_profile=profiles.FIRST_PARENT)
    report["selection"] = {key: value for key, value in selection.items() if key != "environment"}
    config["bind"] = "127.0.0.1"
    protected_env = dict(env, **selection["environment"])
    command = [args.agentfw, "mcp", "--native-admission", "--id", "sou244-controls", "--",
               python, "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
    subprocess.run([args.agentfw, "install"], env=protected_env, capture_output=True, check=True, timeout=30)
    write(home / ".agentfw/config.yaml", config)

    def run(name, tool="git_diff", arguments=TARGET, **options):
        row = {"control": name, "tool": tool, "arguments": arguments}
        report["cases"].append(row)
        try:
            control(output, repo, command, protected_env, row, **options)
        finally:
            write(output / "report.json", report)

    with (output / "daemon.log").open("xb") as log:
        daemon = subprocess.Popen([args.agentfw, "serve"], env=protected_env, stdout=log, stderr=log)
    try:
        require(base.DEMO.wait_healthy(port, daemon, startup_log=output / "daemon.log"), "owned daemon did not start")
        expected = reference(python, repo, env, output)
        run("merge_first_parent", expected=expected)
        for name, revision in INVALID_DIFFS.items():
            run(name, arguments={"target": revision})
        run("show_head_tilde_one", "git_show", {"revision": "HEAD~1"})
        for name, object_id in failures.items():
            branch.write_bytes(object_id + b"\n")
            # Git status may itself fail where the owned commit is malformed.
            run(name, follow="useful" if name in ("no_parent", "unavailable_parent") else None)
        branch.write_bytes(head + b"\n")
        collision = repo / "HEAD~1"
        collision.touch()
        run("literal_path_collision")
        collision.unlink()
        run("branch_replaced_and_restored", mutate=branch, follow="withdrawn")
        run("parent_object_replaced_and_restored", mutate=parent_object, follow="withdrawn")
        run("fresh_session_restored", expected=expected)
    finally:
        base.DEMO.stop(daemon)
        daemon.wait(timeout=10)
        report["daemon_stopped"] = daemon.poll() is not None


def full_inventory(rows):
    observed = {row["control"]: row.get("dispatched") for row in rows if row.get("cleanup") is True}
    expected = {name: True for name in POSITIVES} | {name: False for name in NEGATIVES}
    return len(rows) == len(expected) == 16 and observed == expected


def run(args):
    source = base.source()
    require(source["commit"] == args.expected_commit and not source["dirty"], "clean exact candidate required")
    output = args.output.resolve()
    require(not output.is_relative_to(ROOT), "output must be a new directory outside the checkout")
    roles = ("agentfw", "git_launcher", "git", "bwrap", "python_archive", "wheelhouse")
    for name in roles:
        path = getattr(args, name)
        if path is not None:
            setattr(args, name, path.resolve(strict=True))
    inputs = {key: sha(getattr(args, key)) for key in roles if key != "wheelhouse" and getattr(args, key)}
    require(inputs["git"] == args.git_sha256, "pinned Git digest mismatch")
    output.mkdir(mode=0o700)
    report = {"format": "sw-sou244-first-parent-controls/1", "status": "incomplete", "source": source,
              "sha256": inputs, "cases": []}
    try:
        with tempfile.TemporaryDirectory(prefix="sou244-first-parent-") as temporary:
            scratch = Path(temporary)
            qualify(args, output, scratch, report)
        report["private_removed"] = not scratch.exists()
        require(report["private_removed"] and report["daemon_stopped"] and full_inventory(report["cases"]),
                "all sixteen controls and verified cleanup are required")
        require(base.source() == source and all(sha(getattr(args, key)) == digest for key, digest in inputs.items()),
                "source or runtime input changed")
        report["status"] = "complete"
    finally:
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "controls": len(report["cases"])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--git-sha256", required=True)
    for name in ("output", "agentfw", "git-launcher", "git", "bwrap"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--python-archive", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--allow-download", action="store_true")
    args = parser.parse_args()
    if not args.allow_download and (args.python_archive is None or args.wheelhouse is None):
        parser.error("supply both pinned offline inputs or explicitly allow verified downloads")
    try:
        run(args)
    except (OSError, ValueError, KeyError, queue.Empty, subprocess.SubprocessError) as error:
        print(f"first-parent qualification incomplete ({type(error).__name__}): {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
