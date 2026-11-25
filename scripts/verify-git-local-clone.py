#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit Linux acceptance for the opt-in original Git local-clone profile."""
from __future__ import annotations

import argparse
import importlib.util
import json
import hashlib
import platform
import select
import threading
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V1 = load("sou107_transport", "verify-sou68-real-mcp.py")
INSTALL = load("sou107_install", "install-sou107-git-profile.py")
BASE = V1.BASE
require, sha, write = BASE.require, BASE.sha, BASE.write


class ContinuousRepositoryWitness(V1.RepositoryWitness):
    """Consume real kernel events during calls; never clear an overflow/error."""
    def __init__(self, root):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._count = 0
        self._failure = None
        super().__init__(root)
        self._thread = threading.Thread(target=self._collect, daemon=True)
        self._thread.start()

    def _collect(self):
        try:
            while not self._stop.is_set():
                ready, _, _ = select.select([self.fd], [], [], 0.01)
                if ready:
                    with self._lock:
                        self._count += super().drain()
        except Exception as error:
            with self._lock:
                self._failure = error
            self._stop.set()

    def drain(self):
        with self._lock:
            if self._failure is not None:
                raise ValueError("continuous repository witness failed") from self._failure
            try:
                self._count += super().drain()
            except Exception as error:
                self._failure = error
                raise
            count, self._count = self._count, 0
            return count

    def close(self):
        self._stop.set()
        try:
            if self._thread is not None:
                self._thread.join(timeout=2)
                require(not self._thread.is_alive(), "continuous repository witness did not stop")
        finally:
            super().close()
        if self._failure is not None:
            raise ValueError("continuous repository witness failed") from self._failure


def fixture(root, git, env):
    poison = V1.prepare_repo(root, git, env)

    def command(*args):
        subprocess.run([str(git), "-c", "user.name=SOU107 Synthetic", "-c",
                        "user.email=sou107@example.invalid", *args], cwd=root,
                       env=env, check=True, capture_output=True, timeout=20)

    (root / "notes.txt").write_text("synthetic original text\n")
    (root / ".gitattributes").write_text("*.txt text eol=lf\n*.bin binary\n")
    (root / "owned.bin").write_bytes(b"\0owned synthetic binary\xff\n")
    (root / "nested").mkdir()
    (root / "nested/.gitattributes").write_text("*.txt text=auto\n")
    (root / "nested/example.txt").write_text("owned nested text\n")
    command("add", ".")
    command("commit", "--amend", "--no-edit")
    command("update-ref", "refs/remotes/origin/main", "HEAD")
    config = root / ".git/config"
    config.write_bytes(config.read_bytes() + b'\n[user]\nname = Synthetic Owner\nemail = owner@example.invalid\n[remote "origin"]\nurl = https://example.invalid/owned/repo.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\nremote = origin\nmerge = refs/heads/main\n')
    (root / "notes.txt").write_text("synthetic staged text\n")
    command("add", "notes.txt")
    (root / "notes.txt").write_text("synthetic changed text\n")
    return poison


def late_changes(stack, report):
    """Mutate only our fixture after original-server initialization and a read."""
    profile = json.loads((stack.install / "profile.json").read_text())
    # One logical pinned server across both phases; a second ID would correctly
    # trigger the shared policy's duplicate-tool/server-shadow protection.
    command = [str(stack.binary), "mcp", "--native-admission", "--id", "sou68-git", "--",
               profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
    env = dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.install / "profile.json"),
               AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"),
               AGENTFW_CLASSIFIER_PYTHON=sys.executable)
    config, attrs, index = [stack.workspace / p for p in (".git/config", ".gitattributes", ".git/index")]
    originals = {p: p.read_bytes() for p in (config, attrs, index)}
    extra = stack.workspace / ".git/commondir"
    outside = stack.root / "owned-config-copy"
    outside.write_bytes(originals[config])
    report["late_changes"] = []
    original_env = dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git),
                        GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    with (stack.root / "multifile-unwrapped.log").open("wb") as log:
        source = V1.Client([profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git",
                            "--repository", str(stack.workspace)], original_env, stack.workspace, log,
                           "unwrapped multi-file original Git")
        try:
            source.initialize()
            original_response, original = source.exchange(V1.call(10, repo=stack.workspace))
            original_text = V1.text(original_response)
        finally:
            source.close()
            report["multifile_original_client"] = source.transcript()
    require(source.process_witness.final["all_stopped"], "multi-file baseline process cleanup incomplete")
    (stack.root / "multifile-original-response.json").write_bytes(original)
    (stack.root / "multifile-original-show.txt").write_text(original_text)
    with (stack.root / "late-changes.log").open("wb") as log:
        client = V1.Client(command, env, stack.workspace, log, "local clone late changes")
        try:
            client.initialize()
            # Retain the ordinary multi-file result-policy false positive. Do
            # not weaken policy, strip result bytes or silently discard this case.
            result, raw = client.exchange(V1.call(10))
            refused = BASE.refused(result)
            if refused:
                require("git-profile-refuse-result-injection" in json.dumps(result), "unexpected multi-file read refusal")
            else:
                require(raw == original, "multi-file original output changed")
            report["multifile_result_policy"] = {
                "known_false_block": refused, "original_sha256": hashlib.sha256(original).hexdigest(),
                "response": result, "policy_unchanged": True,
                "scope": "benign multi-file HEAD; retained separately from supported six-read qualification"}
            # Advance only the owned fixture to a conventional one-file HEAD.
            # Keep all attributes, origin/tracking metadata and staged/unstaged
            # notes. This is not a transformation applied to operator repositories.
            (stack.workspace / "checkpoint.txt").write_text("owned local clone checkpoint\n")
            for args in (("add", "checkpoint.txt"),
                         ("commit", "--only", "-m", "SOU-68 synthetic initial commit follow-up", "checkpoint.txt"),
                         ("update-ref", "refs/remotes/origin/main", "HEAD")):
                subprocess.run([str(stack.git), "-c", "user.name=SOU107 Synthetic", "-c",
                                "user.email=sou107@example.invalid", *args], cwd=stack.workspace,
                               env=stack.env, capture_output=True, check=True, timeout=20)
            result, _ = client.exchange(V1.call(11))
            require("SOU-68 synthetic" in V1.text(result), "initial useful read required")
            for n, case in enumerate(("include", "external-helper", "attributes", "config-symlink", "metadata", "index-attributes")):
                try:
                    if case == "include":
                        config.write_bytes(originals[config] + b'\n[include]\npath = /outside/config\n')
                    elif case == "external-helper":
                        config.write_bytes(originals[config] + b'\n[diff]\nexternal = /outside/helper\n')
                    elif case == "attributes":
                        attrs.write_bytes(b"*.txt filter=unsafe\n")
                    elif case == "config-symlink":
                        config.unlink()
                        config.symlink_to(outside)
                    elif case == "metadata":
                        extra.write_bytes(b"/outside\n")
                    else:
                        attrs.write_bytes(b"*.txt diff=unsafe\n")
                        subprocess.run([str(stack.git), "add", ".gitattributes"], cwd=stack.workspace,
                                       env=stack.env, capture_output=True, check=True, timeout=10)
                        attrs.write_bytes(originals[attrs])
                    before = BASE.snapshot(stack.workspace)
                    response, _ = client.exchange(V1.call(20 + n, "git_status", {}))
                    require(BASE.refused(response), "late unsupported repository accepted: " + case)
                    require(BASE.snapshot(stack.workspace) == before, "guard rewrote unsupported repository")
                    report["late_changes"].append({"case": case, "passed": True, "response": response})
                finally:
                    if config.is_symlink():
                        config.unlink()
                    for path, content in originals.items():
                        path.write_bytes(content)
                    extra.unlink(missing_ok=True)
                result, _ = client.exchange(V1.call(100 + n))
                require("SOU-68 synthetic" in V1.text(result), "late refusal broke useful continuation")
        finally:
            client.close()
            report["late_client"] = client.transcript()
    require(client.process_witness.final["all_stopped"], "late-change owned process cleanup incomplete")


def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    before = BASE.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact source required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new evidence directory outside source required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou107-local-clone-acceptance/1", "status": "incomplete", "source_before": before,
              "binary_sha256": sha(args.agentfw), "driver_sha256": sha(__file__), "skipped": 0}
    daemon = None
    try:
        with tempfile.TemporaryDirectory(prefix="sou107-owned-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = BASE.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
            workspace = private / "workspace"
            poison = fixture(workspace, args.git, env)
            install = private / "installed"
            INSTALL.install(install, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher)
            report["installation"] = json.loads((install / "installation.json").read_text())
            positive = subprocess.run([str(args.sandbox_test_binary),
                "selected_local_clone_denies_actual_helper_execution_and_network", "--ignored", "--nocapture"],
                env=dict(env, SOU107_TEST_PROFILE=str(install / "profile.json"), SOU86_TEST_AGENTFW=str(args.agentfw.resolve())),
                capture_output=True, timeout=100)
            (output / "sandbox-positive.log").write_bytes(positive.stdout + positive.stderr)
            require(positive.returncode == 0 and b"SOU107_HELPER_NETWORK_WITNESSES_PASSED" in positive.stdout
                    and b"1 passed; 0 failed" in positive.stdout, "independent helper/network OS proof failed")
            report["sandbox_positive"] = True
            subprocess.run([str(args.agentfw), "install"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, check=True, timeout=30)
            port = BASE.DEMO.free_port()
            config, report["pilot_selection"] = INSTALL.prepare(install, output / "selection", port)
            write(home / ".agentfw/config.yaml", config)
            with (output / "daemon.log").open("wb") as log:
                daemon = subprocess.Popen([str(args.agentfw), "serve"], env=env, stdout=log, stderr=log)
                require(BASE.DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed")
                stack = SimpleNamespace(root=output, binary=args.agentfw, git=args.git, workspace=workspace,
                                        poison=poison, install=install, env=env, daemon=daemon)
                late_changes(stack, report)
                V1.protected(stack, report, witness_type=ContinuousRepositoryWitness)
            require(INSTALL.V1.tree_sha(install / "package") == report["installation"]["profile"]["packageTreeSha256"], "package changed")
            require(sha(config["policy"]) == report["pilot_selection"]["policy_sha256"], "policy changed")
        report["source_after"] = BASE.source()
        require(report["source_after"] == before, "source changed during acceptance")
        report["status"] = "pass"
    except Exception as error:
        report["status"], report["error"] = "fail", type(error).__name__ + ": " + str(error)
    finally:
        if daemon is not None:
            BASE.DEMO.stop(daemon)
        report["protected_diagnostics"] = V1.protected_diagnostics(report, output)
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "error": report.get("error"), "report": str(output / "report.json")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "git", "bwrap", "git-launcher", "sandbox-test-binary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False})); return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
