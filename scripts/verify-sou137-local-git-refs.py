#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in exact-source Linux acceptance of literal local Git reference reads."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
import importlib.util

SPEC = importlib.util.spec_from_file_location("sou137_original", ROOT / "scripts/verify-sou68-real-mcp.py")
GIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GIT)
BASE, INSTALL = GIT.BASE, GIT.INSTALL
require, sha, write = BASE.require, BASE.sha, BASE.write
CLASSIFIER = ROOT / "rule_baseline/git_readonly_local_refs_v1/rule_baseline.py"
REFS = ("refs/heads/feature/nested", "refs/heads/機能/読み取り", "refs/heads/café",
        "refs/tags/releases/light", "refs/tags/releases/annotated", "refs/tags/版/一")
INVALID = ("main", "--help", "-c core.pager=helper", "HEAD~1", "HEAD:file", "HEAD@{0}",
           "refs/remotes/origin/main", "refs/heads/a..b", "refs/heads/a^", "refs/heads/a~1",
           "refs/heads/a:b", "refs/heads/a@{0}", "refs/heads/a//b", "refs/heads/.hidden",
           "refs/heads/a.lock", "refs/heads/-option", "refs/heads/a ", "refs/heads/a\n",
           "refs/heads/a\\b", "refs/heads/a*", "refs/heads/a?", "refs/heads/a[b",
           "refs/heads/" + "a" * 245, "refs/heads/" + "/".join(["a"] * 9),
           "refs/heads/a\u202eb")


def prepare_repo(workspace, git, env):
    workspace.mkdir(mode=0o700)
    def command(*args, data=None):
        return subprocess.check_output([str(git), "-c", "user.name=SOU137 Synthetic",
            "-c", "user.email=sou137@example.invalid", *args], cwd=workspace, env=env,
            input=data, stderr=subprocess.PIPE, timeout=20).decode("utf-8").strip()
    command("init", "--initial-branch=main", "--template=")
    (workspace / "notes.txt").write_text("Synthetic reference baseline.\n")
    command("add", "notes.txt")
    command("commit", "-m", "Synthetic reference baseline")
    first = command("rev-parse", "HEAD")
    (workspace / "notes.txt").write_text("Synthetic reference second version.\n")
    command("add", "notes.txt")
    command("commit", "-m", "Synthetic reference second version")
    second = command("rev-parse", "HEAD")
    for ref in REFS[:3]:
        command("update-ref", ref, first)
    command("tag", "releases/light", first)
    command("tag", "-a", "releases/annotated", first, "-m", "Synthetic annotated reference")
    command("tag", "版/一", first)
    blob = command("hash-object", "-w", "--stdin", data=b"Synthetic blob target.\n")
    tree = command("rev-parse", "HEAD^{tree}")
    command("update-ref", "refs/tags/unsupported-blob", blob)
    command("update-ref", "refs/tags/unsupported-tree", tree)
    (workspace / "notes.txt").write_text("Synthetic reference staged version.\n")
    command("add", "notes.txt")
    (workspace / "notes.txt").write_text("Synthetic reference working version.\n")
    return first, second


def reads(first):
    return [(name, {key: ref}, ref) for ref in ("HEAD", first, *REFS)
            for name, key in (("git_show", "revision"), ("git_diff", "target"))]


def collector(stack, log, *, legacy=False):
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile), AGENTFW_CLASSIFIER="rule-baseline",
        AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py" if legacy else CLASSIFIER),
        AGENTFW_CLASSIFIER_PYTHON=sys.executable)
    return GIT.Client([str(stack.binary), "mcp", "--native-admission", "--id", "sou137-git", "--",
        str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
        env, stack.workspace, log, "protected local-reference original Git")


def exact_reads(stack, first, report):
    originals = {}
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git), GIT_OPTIONAL_LOCKS="0")
    with (stack.root / "original.log").open("wb") as log:
        client = GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
                            env, stack.workspace, log, "direct original Git")
        try:
            client.initialize()
            for identifier, (tool, args, ref) in enumerate(reads(first), 10):
                response, raw = client.exchange(GIT.call(identifier, tool, args, stack.workspace))
                GIT.text(response)
                originals[identifier] = raw
        finally:
            client.close()
            report["direct_client"] = client.transcript()
    before = BASE.snapshot(stack.workspace)
    witness = GIT.RepositoryWitness(stack.workspace)
    path = stack.root / "collector.log"
    with path.open("wb") as log:
        client = collector(stack, log)
        try:
            client.initialize()
            report["reads"], report["refusals"] = [], []
            for identifier, (tool, args, ref) in enumerate(reads(first), 10):
                witness.drain()
                response, raw = client.exchange(GIT.call(identifier, tool, args))
                GIT.text(response)
                require(raw == originals[identifier], "original response bytes changed: " + tool + " " + ref)
                require(witness.drain() > 0, "independent execution witness did not observe read")
                report["reads"].append({"id": identifier, "tool": tool, "reference": ref,
                    "response_sha256": hashlib.sha256(raw).hexdigest(), "original_bytes_equal": True})
            denials = [(tool, {key: ref}, "syntax") for ref in INVALID
                       for tool, key in (("git_show", "revision"), ("git_diff", "target"))]
            denials += [(tool, {key: ref}, "target") for ref in
                ("refs/heads/missing", "refs/tags/unsupported-blob", "refs/tags/unsupported-tree")
                for tool, key in (("git_show", "revision"), ("git_diff", "target"))]
            denials += [("git_checkout", {"branch_name": "main"}, "mutation"),
                       ("git_create_branch", {"branch_name": "forbidden"}, "mutation"),
                       ("git_add", {"files": ["notes.txt"]}, "mutation")]
            for identifier, (tool, args, category) in enumerate(denials, 100):
                witness.drain()
                response, _ = client.exchange(GIT.call(identifier, tool, args))
                require(BASE.refused(response), "unsupported original call was not refused")
                require(witness.drain() == 0, "refused call opened repository")
                require(not any(r.get("host_call_id") == identifier and r.get("state") == "inflight"
                                for r in BASE.events(path)), "refused call dispatched")
                if category == "target":
                    require(response.get("error", {}).get("code") == -32602 and
                            "local reference" in response["error"]["message"], "unattributable target refusal")
                report["refusals"].append({"id": identifier, "category": category,
                    "response": response, "repository_opens": 0, "execution_dispatched": False})
                followup, _ = client.exchange(GIT.call(identifier + 1000, "git_show", {"revision": REFS[0]}))
                GIT.text(followup)
            require(BASE.snapshot(stack.workspace) == before, "protected reads/refusals changed repository")
            report["repository_unchanged"] = True
        finally:
            client.close()
            witness.close()
            report["protected_client"] = client.transcript()
    require(client.process.returncode == 0 and not client.forced_cleanup and
            client.process_witness.final.get("all_stopped") is True, "protected process cleanup unverified")


def source_mutations(stack, first, second, report):
    ref = stack.workspace / REFS[0].replace("refs/", ".git/refs/", 1)
    original = ref.read_bytes()
    report["source_mutations"] = []
    for name in ("rewrite", "replace", "symlink"):
        path = stack.root / ("mutation-" + name + ".log")
        before = BASE.snapshot(stack.workspace)
        with path.open("wb") as log:
            client = collector(stack, log)
            witness = GIT.RepositoryWitness(stack.workspace)
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_show", {"revision": REFS[0]}))[0])
                if name == "rewrite":
                    ref.write_text(second + "\n")
                elif name == "replace":
                    temporary = ref.with_name("replacement")
                    temporary.write_text(second + "\n")
                    temporary.replace(ref)
                else:
                    ref.unlink()
                    ref.symlink_to(stack.workspace / ".git/refs/heads/main")
                witness.drain()
                response, _ = client.exchange(GIT.call(11, "git_show", {"revision": REFS[0]}))
                require(response.get("error", {}).get("code") == -32602, "source mutation was not refused")
                require(witness.drain() == 0, "withdrawn source was dispatched")
                if ref.is_symlink():
                    ref.unlink()
                ref.write_bytes(original)
                witness.drain()
                restored, _ = client.exchange(GIT.call(12))
                require(restored.get("error", {}).get("code") == -32602 and witness.drain() == 0,
                        "restoration revived withdrawn source")
                report["source_mutations"].append({"case": name, "refused": True,
                    "restoration_still_refused": True, "repository_opens": 0})
            finally:
                client.close()
                witness.close()
                if ref.is_symlink():
                    ref.unlink()
                ref.write_bytes(original)
        # Replacement intentionally changes inode; independently compare data and modes.
        after = BASE.snapshot(stack.workspace)
        for records in (before, after):
            for row in records.values():
                row.pop("inode", None)
        require(before == after, "mutation harness did not restore owned fixture")
        with (stack.root / ("fresh-" + name + ".log")).open("wb") as log:
            client = collector(stack, log)
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_show", {"revision": REFS[0]}))[0])
            finally:
                client.close()
        require(client.process.returncode == 0 and not client.forced_cleanup, "fresh collector failed")


def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 enforcing isolation required")
    before = BASE.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact candidate required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new evidence directory outside source required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou137-local-git-refs-acceptance/1", "status": "incomplete", "skipped": 0,
        "source_before": before, "driver_sha256": sha(__file__), "binary_sha256": sha(args.agentfw),
        "classifier_sha256": sha(CLASSIFIER)}
    daemon = None
    try:
        with tempfile.TemporaryDirectory(prefix="sou137-owned-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = BASE.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
            workspace, install = private / "workspace", private / "installed"
            first, second = prepare_repo(workspace, args.git, env)
            INSTALL.install(install, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher, local_references=True)
            report["installation"] = json.loads((install / "installation.json").read_text())
            subprocess.run([str(args.agentfw), "install"], env=env, capture_output=True, check=True, timeout=30)
            port = BASE.DEMO.free_port()
            config = {"port": port, "enforce": True, "max_record_bytes": 1048576,
                "policy": str(install / "policy.yaml"), "native": {"registry_path": str(install / "registry.json"),
                "registry_sha256": sha(install / "registry.json")}}
            write(home / ".agentfw/config.yaml", config)
            with (output / "daemon.log").open("wb") as log:
                daemon = subprocess.Popen([str(args.agentfw), "serve"], env=env, stdout=log, stderr=log)
                require(BASE.DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed to start")
                stack = SimpleNamespace(root=output, binary=args.agentfw, git=args.git, workspace=workspace,
                    install=install, profile=install / "profile.json", env=env, daemon=daemon)
                exact_reads(stack, first, report)
                source_mutations(stack, first, second, report)
            require(INSTALL.tree_sha(install / "package") == report["installation"]["profile"]["packageTreeSha256"],
                    "original package bytes changed")
        report["source_after"] = BASE.source()
        require(report["source_after"] == before, "candidate source changed")
        report["status"] = "pass"
    except Exception as error:
        report["status"], report["error"] = "fail", type(error).__name__ + ": " + str(error)
    finally:
        if daemon is not None:
            BASE.DEMO.stop(daemon)
        report["protected_diagnostics"] = GIT.protected_diagnostics(report, output)
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "error": report.get("error"), "report": str(output / "report.json"),
        "reads": len(report.get("reads", [])), "refusals": len(report.get("refusals", [])),
        "source_mutations": report.get("source_mutations", []), "protected_diagnostics": report["protected_diagnostics"]}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "git", "bwrap", "git-launcher", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False}))
        return 0
    try:
        return run(args)
    except Exception as error:
        print(json.dumps({"status": "fail", "error": str(error), "skipped": 0}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
