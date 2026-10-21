#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Acceptance: `agentfw onboard` with the accepted original filesystem and Git profiles.

For each selected profile the runner creates owned roots outside the source checkout,
installs the profile with its accepted installer, copies the Agent and classifier to
installed locations, and drives preview -> apply -> useful read -> refusal ->
continuation -> undo through the actual installed original server. It also runs
negative controls: changed profile/runtime after preview, missing Linux sandbox
support, an occupied foreign port, operator configuration edits, interruption and
retry, and cleanup. Independent effects are calibrated: the same original server,
started unprotected on a scratch copy, performs the change that the protected
connection must refuse. No model, provider or private data is used. Failed,
incomplete and refused results are retained in the evidence directory.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parents[1]
FS_INSTALLER = REPO / "scripts/install-sou62-filesystem-profile.py"
GIT_INSTALLER = REPO / "scripts/install-sou68-git-profile.py"
CLASSIFIERS = {"filesystem": REPO / "rule_baseline/rule_baseline.py",
               "git": REPO / "rule_baseline/git_readonly_v1/rule_baseline.py"}
FS_ENTRY = "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha(Path(path).read_bytes())


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def snapshot(root: Path) -> dict:
    """Independent host-side witness: every entry, kind and content digest, no links followed."""
    result = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            result[rel] = "link:" + os.readlink(path)
        elif path.is_dir():
            result[rel] = "dir"
        elif path.is_file():
            result[rel] = sha_file(path)
        else:
            result[rel] = "other"
    return result


def wait_for(predicate, limit=300.0):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class ForeignListener:
    """An unrelated TCP listener that onboarding must never adopt."""

    def __init__(self, port):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.socket.listen(8)
        self.stop = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        self.socket.settimeout(0.2)
        while not self.stop:
            try:
                connection, _ = self.socket.accept()
                connection.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.thread.join(timeout=5)
        self.socket.close()


class Mcp:
    """A minimal line-delimited MCP client over a real process; cleared environment."""

    def __init__(self, command, args, env=None, limit=120):
        self.process = subprocess.Popen([command, *args], env=env or {}, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        self.deadline = time.monotonic() + limit
        self.next_id = 0

    def call(self, method, params):
        self.next_id += 1
        frame = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        try:
            self.process.stdin.write(json.dumps(frame).encode() + b"\n")
            self.process.stdin.flush()
        except OSError:  # the entry exited (for example it refused to start)
            return None
        while time.monotonic() < self.deadline:
            line = self.process.stdout.readline()
            if not line:
                return None
            value = json.loads(line)
            if value.get("id") == self.next_id:
                return value
        return None

    def notify(self, method):
        try:
            self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}).encode() + b"\n")
            self.process.stdin.flush()
        except OSError:
            pass

    def start(self):
        init = self.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                        "clientInfo": {"name": "profile-onboarding-acceptance", "version": "1"}})
        if not init or "result" not in init:
            return None
        self.notify("notifications/initialized")
        return self.call("tools/list", {})

    def tool(self, name, arguments):
        return self.call("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except OSError:
            pass
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        self.process.wait(timeout=10)


def refused(response):
    return response is None or "error" in response or response.get("result", {}).get("isError") is True


def text(response):
    return "".join(item.get("text", "") for item in response["result"]["content"])


def trusted_interpreter():
    """A Python the connection may persist: regular, single-link, owned by root or us and
    not group/other-writable. Hosted tool caches are often group-writable, so prefer the
    system interpreter and never relax the Agent's rule."""
    for candidate in ("/usr/bin/python3", sys.executable):
        path = Path(os.path.realpath(candidate))
        try:
            meta = path.lstat()
        except OSError:
            continue
        if (path.is_file() and meta.st_nlink == 1 and meta.st_mode & 0o022 == 0 and meta.st_mode & 0o111
                and meta.st_uid in (0, os.geteuid())):
            return path
    raise RuntimeError("no trusted Python interpreter (regular, single-link, not group/other-writable) is available")


def wrapper_environment(entry):
    """Variable names the wrapper sets before `--`, or None when the entry is not wrapped."""
    args = entry.get("args", [])
    if entry.get("command") != "/usr/bin/env" or "--" not in args:
        return None
    return [a.split("=", 1)[0] for a in args[:args.index("--")] if "=" in a]


def check(results, name, passed, **observed):
    results.append({"check": name, "passed": bool(passed), **observed})
    print(f"  {'PASS' if passed else 'FAIL'}  {name}")


class Root:
    """One owned profile installation and clean user home outside the checkout."""

    def __init__(self, base: Path, kind: str, options):
        self.kind = kind
        self.root = base / kind
        self.user = self.root / "user"
        self.out = self.root / "out"
        self.opt = self.root / "opt"
        for path in (self.user / ".claude", self.out, self.opt / "bin", self.opt / "classifier"):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.user, 0o700)
        os.chmod(self.user / ".claude", 0o700)
        self.agent = self.opt / "bin/agentfw"
        shutil.copyfile(options.agentfw, self.agent)
        os.chmod(self.agent, 0o755)
        self.classifier = self.opt / "classifier/rule_baseline.py"
        shutil.copyfile(CLASSIFIERS[kind], self.classifier)
        self.python = trusted_interpreter()
        self.git_env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LANG": "C.UTF-8"}
        self.options = options
        self.install = self.opt / f"{kind}-profile"
        if kind == "filesystem":
            self.workspace = self.user / "work"
            self.workspace.mkdir()
            (self.workspace / "inventory.txt").write_text("Inventory: 7 red widgets.\n")
            (self.workspace / "notes").mkdir()
            (self.workspace / "notes/plan.txt").write_text("Quarterly plan draft.\n")
            load(FS_INSTALLER, "profile_onboarding_fs").install(self.install, self.workspace, options.node, options.bwrap, options.npm)
            self.command = os.path.realpath(options.node)
            self.args = [str(self.install / "package" / FS_ENTRY), "/workspace"]
        else:
            self.workspace = self.user / "repo"
            self.workspace.mkdir(mode=0o700)
            self.git("init", "--initial-branch=main", "--template=")
            (self.workspace / "notes.txt").write_text("synthetic original text\n")
            self.git("add", "notes.txt")
            self.git("commit", "-m", "profile onboarding synthetic initial commit")
            (self.workspace / "notes.txt").write_text("synthetic changed text\n")
            load(GIT_INSTALLER, "profile_onboarding_git").install(self.install, self.workspace, options.git, options.git_sha256,
                                                       options.bwrap, options.git_launcher)
            self.command = str(self.install / "package/python/bin/python3.11")
            self.args = ["-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
        self.profile = self.install / "profile.json"
        self.entry = {"command": self.command, "args": self.args}
        self.sentinel_entry = {"command": "/bin/true", "args": ["sentinel-entry"]}
        self.host = self.user / ".claude/mcp.json"
        self.write_host({"theme": "dark", "mcpServers": {"selected": self.entry, "unrelated": self.sentinel_entry}})
        (self.user / "sentinel.txt").write_text("operator sentinel file\n")
        self.home = self.user / ".agentfw"
        self.state = self.user / ".soup-wall-onboarding"
        self.port = free_port()
        self.reports = 0

    def git(self, *args):
        subprocess.run([str(self.options.git), "-c", "user.name=Profile Onboarding Synthetic", "-c",
                        "user.email=profile-onboarding@example.invalid", *args], cwd=self.workspace, env=self.git_env,
                       check=True, capture_output=True, timeout=30)

    def write_host(self, value):
        self.host.write_text(json.dumps(value, indent=2), encoding="utf-8")
        os.chmod(self.host, 0o600)

    def host_value(self):
        return json.loads(self.host.read_text())

    def inputs(self, **overrides):
        values = {
            "--agent": str(self.agent), "--agent-sha256": sha_file(self.agent),
            "--classifier": "rule-baseline", "--classifier-script": str(self.classifier),
            "--classifier-sha256": sha_file(self.classifier), "--classifier-python": str(self.python),
            "--registry": str(self.install / "registry.json"),
            "--registry-sha256": sha_file(self.install / "registry.json"),
            "--policy": str(self.install / "policy.yaml"), "--policy-sha256": sha_file(self.install / "policy.yaml"),
            "--server-profile": str(self.profile), "--server-profile-sha256": sha_file(self.profile),
            "--workspace": str(self.workspace), "--agent-home": str(self.home),
            "--host-config": str(self.host), "--server": "selected", "--port": str(self.port),
        }
        values.update(overrides)
        return [item for key, value in values.items() if value is not None for item in (key, value)]

    def onboard(self, operation, args, label, popen=False, prefix=()):
        self.reports += 1
        report = self.out / f"{self.reports:02d}-{label}.json"
        command = [*prefix, str(self.agent), "onboard", operation, *args, "--report", str(report)]
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.user), "LANG": "C.UTF-8"}
        if popen:
            return subprocess.Popen(command, cwd=self.user, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT), report
        result = subprocess.run(command, cwd=self.user, env=env, capture_output=True, timeout=1200)
        (self.out / f"{self.reports:02d}-{label}.log").write_bytes(result.stdout + result.stderr)
        return result.returncode, json.loads(report.read_text()) if report.exists() else None

    def preview(self, label="preview", **overrides):
        code, report = self.onboard("preview", self.inputs(**overrides), label)
        return code, report, (report or {}).get("plan_sha256")

    def apply(self, digest, label="apply", **overrides):
        return self.onboard("apply", self.inputs(**overrides) + ["--plan-sha256", digest], label)

    def undo(self, label="undo", purge=False):
        args = ["--agent", str(self.agent), "--agent-home", str(self.home), "--host-config", str(self.host),
                "--server", "selected"]
        return self.onboard("undo", args + (["--purge-agent-home"] if purge else []), label)

    def inspect(self):
        result = subprocess.run([str(self.agent), "mcp-connection", "inspect", "--path", str(self.host),
                                 "--server", "selected", "--agent", str(self.agent), "--home", str(self.home)],
                                env={"PATH": "/usr/bin:/bin", "HOME": str(self.user)}, capture_output=True, timeout=300)
        try:
            return json.loads(result.stdout)["status"]
        except (ValueError, KeyError):
            return "error"

    def journal(self):
        try:
            return json.loads((self.state / "journal.json").read_text())
        except (OSError, ValueError):
            return None

    def owned_processes(self):
        needle, count = str(self.user), 0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                if needle in (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace"):
                    count += 1
            except OSError:
                pass
        return count

    def sentinels(self):
        value = self.host_value()
        return {"file": sha_file(self.user / "sentinel.txt"), "entry": value["mcpServers"].get("unrelated"),
                "theme": value.get("theme")}

    def clean(self):
        retained = [p.name for p in (self.user / ".claude").iterdir() if p.name != "mcp.json"]
        return (not self.home.exists() and not self.state.exists() and self.owned_processes() == 0
                and self.host_value()["mcpServers"]["selected"] == self.entry
                and all(name.startswith(".soup-wall-") for name in retained))

    # Witnesses ---------------------------------------------------------------------
    def useful_call(self):
        if self.kind == "git":
            return "git_status", {"repo_path": "/workspace"}
        return "read_text_file", {"path": "/workspace/inventory.txt"}

    def refused_call(self, nonce):
        if self.kind == "git":
            branch = f"profile-witness-{nonce}"
            return "git_create_branch", {"repo_path": "/workspace", "branch_name": branch}, \
                lambda ws: (ws / ".git/refs/heads" / branch).exists()
        name = f"profile-witness-{nonce}.txt"
        return "write_file", {"path": f"/workspace/{name}", "content": "calibrated change"}, \
            lambda ws: (ws / name).exists()

    def unprotected(self, workspace):
        """The same original server, unsandboxed, on a scratch copy (calibration only)."""
        if self.kind == "git":
            env = dict(self.git_env, PATH=f"{Path(self.options.git).parent}:/usr/bin:/bin")
            return Mcp(self.command, ["-I", "-B", "-m", "mcp_server_git", "--repository", str(workspace)], env)
        return Mcp(self.command, [self.args[0], str(workspace)])

    def calibrate(self):
        scratch = self.root / f"calibration-{self.reports}"
        shutil.copytree(self.workspace, scratch, symlinks=True)
        tool, args = self.useful_call()
        name, mutate, effect = self.refused_call("calibration")
        args = {key: (str(scratch) + value[len("/workspace"):] if isinstance(value, str) and value.startswith("/workspace") else value)
                for key, value in args.items()}
        mutate = {key: (str(scratch) + value[len("/workspace"):] if isinstance(value, str) and value.startswith("/workspace") else value)
                  for key, value in mutate.items()}
        client = self.unprotected(scratch)
        try:
            listed = client.start()
            useful = client.tool(tool, args)
            changed = client.tool(name, mutate)
        finally:
            client.close()
        result = {"discovery": bool(listed and "result" in listed), "useful": not refused(useful),
                  "useful_text_sha256": sha(text(useful).encode()) if not refused(useful) else None,
                  "change_executed": not refused(changed) and effect(scratch)}
        shutil.rmtree(scratch)
        return result, (text(useful) if not refused(useful) else None)

    def protected_session(self, nonce):
        entry = self.host_value()["mcpServers"]["selected"]
        if wrapper_environment(entry) is None:
            raise RuntimeError("refusing to drive an unwrapped entry (the original server would run unprotected)")
        client = Mcp(entry["command"], entry["args"])
        tool, args = self.useful_call()
        name, mutate, effect = self.refused_call(nonce)
        try:
            listed = client.start()
            first = client.tool(tool, args)
            before = snapshot(self.workspace)
            denied = client.tool(name, mutate)
            after = snapshot(self.workspace)
            second = client.tool(tool, args)
        finally:
            client.close()
        return {"listed": listed, "first": first, "denied": denied, "second": second,
                "unchanged": before == after and not effect(self.workspace)}


def scenario_full_cycle(root: Root):
    out = []
    before = root.sentinels()
    workspace_before = snapshot(root.workspace)
    calibration, original_text = root.calibrate()
    check(out, "calibration_original_server_reads_and_changes_unprotected",
          calibration["discovery"] and calibration["useful"] and calibration["change_executed"], **calibration)
    code, report, digest = root.preview()
    check(out, "preview_ready_and_read_only", code == 0 and report["result"] == "plan_ready"
          and not root.home.exists() and not root.state.exists()
          and root.host_value()["mcpServers"]["selected"] == root.entry,
          profile=report and report["inputs"].get("server_profile"))
    check(out, "preview_checks_profile_identities", report and all(
        any(c["id"] == name and c["status"] == "ok" for c in report["checks"])
        for name in ("server_profile", "profile_registry", "profile_runtime", "sandbox_support")))
    code, report = root.apply(digest)
    witness = (report or {}).get("profile_witness", {})
    check(out, "apply_verified_through_selected_profile", code == 0 and report["result"] == "verified"
          and report["host_probe"]["status"] == "verified_profile_witness", result=report and report["result"],
          exit_code=code, connection=report and report.get("connection"), witness=witness,
          steps=report and report.get("steps"))
    check(out, "configured_identity_separate", report and all(report["configured"]["checks"].values()))
    check(out, "agent_witness_original_discovery_refusal_continuation", witness.get("original_discovery") is True
          and witness.get("refusal", {}).get("refused") is True and witness.get("refusal", {}).get("workspace_unchanged") is True
          and witness.get("continuation", {}).get("ok") is True)
    entry = root.host_value()["mcpServers"]["selected"]
    variables = wrapper_environment(entry)
    check(out, "persisted_launch_settings_are_structured_and_narrow", variables == [
              "PATH", "HOME", "USERPROFILE", "AGENTFW_MCP_SERVER_PROFILE", "AGENTFW_WORKSPACE",
              "AGENTFW_CLASSIFIER", "AGENTFW_RULE_BASELINE", "AGENTFW_CLASSIFIER_PYTHON"]
          and "env" not in entry and entry["args"][entry["args"].index("--") + 1:] == [root.command, *root.args],
          variables=variables)
    if variables is None:
        # Never drive an unwrapped entry: it would run the original server unprotected.
        for name in ("independent_useful_original_result", "independent_refusal_witnessed",
                     "independent_useful_continuation"):
            check(out, name, False, reason="the selected entry is not wrapped; not driven")
        return out
    session = root.protected_session("protected")
    first, second = session["first"], session["second"]
    check(out, "independent_useful_original_result", not refused(first) and original_text is not None
          and text(first) == original_text, result_sha256=None if refused(first) else sha(text(first).encode()))
    check(out, "independent_refusal_witnessed", refused(session["denied"]) and session["unchanged"])
    check(out, "independent_useful_continuation", not refused(second) and text(second) == original_text)
    code, report = root.apply(digest, "apply-retry")
    check(out, "safe_retry_reverifies", code == 0 and report["result"] == "verified" and report["resumed"] is True)
    code, report = root.undo()
    check(out, "undo_restores_original_entry", code == 0 and report["result"] == "undone"
          and root.host_value()["mcpServers"]["selected"] == root.entry, result=report and report["result"])
    code, report = root.undo("undo-purge", purge=True)
    check(out, "purge_and_cleanup", code == 0 and root.clean(), processes=root.owned_processes())
    check(out, "workspace_and_sentinels_unchanged", snapshot(root.workspace) == workspace_before and root.sentinels() == before)
    return out


def scenario_changed_after_preview(root: Root):
    out = []
    _, _, digest = root.preview("preview")
    # A dependency file of the installed original server changes after review.
    target = sorted(p for p in (root.install / "package").rglob("*.json" if root.kind == "filesystem" else "*.py")
                    if p.is_file() and not p.is_symlink())[0]
    original = target.read_bytes()
    target.write_bytes(original + b"\n")
    code, report = root.apply(digest, "apply-changed-runtime")
    check(out, "changed_runtime_refused_before_change", code == 4 and report["result"] == "refused"
          and any(c["id"] == "profile_runtime" and c["status"] == "refused" for c in report["checks"])
          and not root.home.exists() and root.host_value()["mcpServers"]["selected"] == root.entry)
    target.write_bytes(original)
    # The profile file itself changes after review.
    profile = root.profile.read_bytes()
    root.profile.write_bytes(profile + b"\n")
    code, report = root.apply(digest, "apply-changed-profile", **{"--server-profile-sha256": sha(profile)})
    check(out, "changed_profile_refused_before_change", code == 4 and report["result"] == "refused"
          and any(c["id"] == "server_profile" and c["status"] == "refused" for c in report["checks"])
          and not root.home.exists())
    root.profile.write_bytes(profile)
    os.chmod(root.profile, 0o600)
    # The selected entry changes after review: the plan digest no longer matches.
    value = root.host_value()
    value["mcpServers"]["selected"]["args"] = [*root.args, "--extra"] if root.kind == "git" else [root.args[0], "/other"]
    root.write_host(value)
    code, report = root.apply(digest, "apply-changed-entry")
    check(out, "changed_entry_refused", code == 4 and report["result"] == "refused" and not root.home.exists())
    value["mcpServers"]["selected"] = root.entry
    root.write_host(value)
    # An interpreter writable by group (as in hosted tool caches) is refused at preview,
    # before it could be persisted in the connected entry.
    writable = root.opt / "bin/python3-group-writable"
    shutil.copyfile(root.python, writable)
    os.chmod(writable, 0o775)
    code, report, _ = root.preview("preview-writable-python", **{"--classifier-python": str(writable)})
    check(out, "group_writable_interpreter_refused", code == 4 and any(
        c["id"] == "classifier_python" and c["status"] == "refused" for c in report["checks"]))
    check(out, "nothing_changed", root.clean())
    return out


def scenario_missing_sandbox(root: Root):
    out = []
    unshare = shutil.which("unshare", path="/usr/bin:/bin")
    check(out, "unshare_available", unshare is not None)
    if unshare is None:
        return out
    # A private user namespace that forbids further namespaces: the profile sandbox cannot start.
    prefix = [unshare, "--user", "--map-root-user", "--fork", "/bin/sh", "-c",
              'echo 0 > /proc/sys/user/max_user_namespaces && exec "$@"', "profile-onboarding"]
    code, report = root.onboard("preview", root.inputs(), "preview-no-userns", prefix=prefix)
    check(out, "missing_sandbox_support_refused", code == 4 and report and any(
        c["id"] == "sandbox_support" and c["status"] == "refused" for c in report["checks"]),
          result=report and report.get("result"))
    check(out, "nothing_changed", root.clean())
    return out


def scenario_foreign_port(root: Root):
    out = []
    listener = ForeignListener(root.port)
    try:
        code, report, _ = root.preview("preview-port")
        check(out, "occupied_port_conflict", code == 4 and any(c["id"] == "port" and c["status"] == "conflict"
                                                              for c in report["checks"]))
    finally:
        listener.close()
    _, _, digest = root.preview("preview")
    listener = ForeignListener(root.port)
    try:
        code, report = root.apply(digest, "apply-after-listener")
        check(out, "listener_after_preview_refused", code == 4 and report["result"] == "refused" and not root.home.exists())
    finally:
        listener.close()
    check(out, "nothing_changed", root.clean())
    return out


def scenario_operator_edits(root: Root):
    out = []
    _, _, digest = root.preview()
    code, report = root.apply(digest)
    check(out, "apply_verified", code == 0 and report["result"] == "verified")
    # An unrelated operator edit is preserved by undo.
    value = root.host_value()
    value["editorSetting"] = "operator"
    value["mcpServers"]["later"] = {"command": "/bin/true", "args": ["later"]}
    root.write_host(value)
    # The installed runtime changes after apply: the entry is no longer reported
    # configured and the collector refuses to start the server, so the entry never
    # appears protected while bypassing its selected profile.
    target = sorted(p for p in (root.install / "package").rglob("*.json" if root.kind == "filesystem" else "*.py")
                    if p.is_file() and not p.is_symlink())[0]
    original = target.read_bytes()
    target.write_bytes(original + b"\n")
    status = root.inspect()
    session = root.protected_session("changed-runtime")
    check(out, "changed_runtime_not_configured_and_fails_closed", status == "unknown" and session["listed"] is None
          and refused(session["first"]) and session["unchanged"], inspect=status)
    target.write_bytes(original)
    # A changed profile file alone is also no longer attributed to this connection.
    profile = root.profile.read_bytes()
    root.profile.write_bytes(profile + b" ")
    changed_profile = root.inspect()
    root.profile.write_bytes(profile)
    os.chmod(root.profile, 0o600)
    check(out, "changed_profile_not_configured", changed_profile == "unknown", inspect=changed_profile)
    check(out, "restored_installation_configured", root.inspect() == "configured")
    # The operator edits the wrapped entry: undo must not overwrite it.
    value = root.host_value()
    value["mcpServers"]["selected"]["args"].append("--operator-edit")
    root.write_host(value)
    edited = root.host_value()["mcpServers"]["selected"]
    code, report = root.undo("undo-conflict")
    check(out, "edited_entry_blocks_undo", code == 4 and report["result"] == "incomplete"
          and root.host_value()["mcpServers"]["selected"] == edited and root.journal()["phase"] == "rollback_conflict")
    value["mcpServers"]["selected"]["args"].pop()
    root.write_host(value)
    code, report = root.undo("undo-purge", purge=True)
    final = root.host_value()
    check(out, "undo_after_resolution_preserves_operator_edits", code == 0 and final.get("editorSetting") == "operator"
          and final["mcpServers"].get("later") == {"command": "/bin/true", "args": ["later"]})
    del final["editorSetting"]
    del final["mcpServers"]["later"]
    root.write_host(final)
    check(out, "cleanup", root.clean())
    return out


def scenario_interrupted(root: Root):
    out = []
    workspace_before = snapshot(root.workspace)
    _, _, digest = root.preview()
    # Interrupted right after the connection was published, before it was verified.
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-interrupted", popen=True)
    reached = wait_for(lambda: (root.journal() or {}).get("steps", {}).get("connect_server") == "done")
    process.send_signal(signal.SIGINT)
    process.communicate(timeout=900)
    report = json.loads(report_path.read_text())
    status = root.inspect()
    check(out, "interrupt_after_publication_keeps_profile_launch", reached and process.returncode == 4
          and report["result"] == "incomplete" and root.journal()["phase"] == "interrupted" and status == "configured",
          inspect=status)
    code, report = root.apply(digest, "apply-resume")
    check(out, "rerun_resumes_to_verified", code == 0 and report["result"] == "verified" and report["resumed"] is True)
    # Killed during the real-server witness: the rerun verifies again.
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-killed", popen=True)
    wait_for(lambda: (root.journal() or {}).get("steps", {}).get("verify_server") == "started")
    process.kill()
    process.communicate(timeout=60)
    code, report = root.apply(digest, "apply-after-kill")
    check(out, "rerun_after_sigkill_verified", code == 0 and report["result"] == "verified")
    code, report = root.undo("undo-purge", purge=True)
    check(out, "undo_after_recovery_clean", code == 0 and root.clean())
    # Interrupted before the connection: undo reverses the partial setup only.
    _, _, digest = root.preview("preview-2")
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-interrupted-early", popen=True)
    wait_for(lambda: (root.journal() or {}).get("steps", {}).get("lifecycle_install") == "done")
    process.send_signal(signal.SIGINT)
    process.communicate(timeout=900)
    early = "connect_server" not in (root.journal() or {}).get("steps", {})
    code, report = root.undo("undo-partial", purge=True)
    check(out, "partial_setup_undone", early and code == 0 and root.clean())
    check(out, "workspace_unchanged", snapshot(root.workspace) == workspace_before)
    return out


SCENARIOS = [("full_cycle", scenario_full_cycle), ("changed_after_preview", scenario_changed_after_preview),
             ("missing_sandbox_support", scenario_missing_sandbox), ("occupied_foreign_port", scenario_foreign_port),
             ("operator_edits", scenario_operator_edits), ("interrupted_and_retry", scenario_interrupted)]


def source_identity():
    def git(*args):
        result = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() if result.returncode == 0 else None
    files = ["crates/agentfw/src/onboarding/linux.rs", "crates/agentfw/src/onboarding/mod.rs",
             "crates/agentfw/src/mcp/connection.rs", "crates/agentfw/src/mcp/server_sandbox.rs",
             "scripts/onboarding-profile-acceptance.py"]
    return {"commit": git("rev-parse", "HEAD"), "tree_clean": git("status", "--porcelain") == "",
            "files": {name: sha_file(REPO / name) for name in files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--npm", type=Path)
    parser.add_argument("--bwrap", type=Path, required=True)
    parser.add_argument("--git", type=Path)
    parser.add_argument("--git-sha256")
    parser.add_argument("--git-launcher", type=Path)
    parser.add_argument("--profiles", nargs="+", choices=["filesystem", "git"], default=["filesystem", "git"])
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--out", type=Path, required=True, help="fresh evidence directory")
    parser.add_argument("--work-parent", type=Path)
    parser.add_argument("--keep", action="store_true")
    options = parser.parse_args()
    if sys.platform != "linux":
        sys.exit("profile onboarding acceptance supports Linux only")
    if "filesystem" in options.profiles and not (options.node and options.npm):
        sys.exit("--node and --npm are required for the filesystem profile")
    if "git" in options.profiles and not (options.git and options.git_sha256 and options.git_launcher):
        sys.exit("--git, --git-sha256 and --git-launcher are required for the Git profile")
    options.out.mkdir(parents=False, exist_ok=False)
    base = Path(tempfile.mkdtemp(prefix="profile-onboarding-", dir=options.work_parent)).resolve()
    if base.is_relative_to(REPO):
        sys.exit("work parent must be outside the source checkout")
    summary = {"schema": "sw-onboarding-profile-acceptance/1", "source": source_identity(),
               "agentfw_sha256": sha_file(options.agentfw), "bwrap_sha256": sha_file(options.bwrap),
               "outside_source_checkout": True, "uid_is_root": os.geteuid() == 0, "profiles": []}
    started = time.monotonic()
    for kind in options.profiles:
        entry = {"profile": kind, "classifier_sha256": sha_file(CLASSIFIERS[kind]), "scenarios": []}
        for name, function in SCENARIOS:
            if options.only and name not in options.only:
                continue
            print(f"{kind}/{name}:")
            began = time.monotonic()
            root = None
            try:
                root = Root(base / name, kind, options)
                if not entry.get("installation"):
                    installation = json.loads((root.install / "installation.json").read_text())
                    entry["installation"] = {key: installation.get(key) for key in
                                             ("profile_sha256", "registry_sha256", "policy_sha256", "git_version", "bwrap_version")}
                    entry["installation"]["runtime_sha256"] = installation["profile"]["runtimeSha256"]
                    entry["installation"]["package_tree_sha256"] = installation["profile"]["packageTreeSha256"]
                checks = function(root)
            except Exception as error:  # a crashed scenario is a failed scenario, never skipped
                checks = [{"check": "scenario_completed", "passed": False, "error": f"{type(error).__name__}: {error}"[:500]}]
                print(f"  FAIL  scenario raised {type(error).__name__}: {error}")
            reports = []
            if root is not None:
                for report in sorted(root.out.glob("*.json")):
                    text_value = report.read_text().replace(str(root.root), "<root>")
                    (options.out / f"{kind}-{name}-{report.name}").write_text(text_value)
                    reports.append(report.name)
                leaked = [r for r in reports if str(root.root) in (options.out / f"{kind}-{name}-{r}").read_text()]
                checks.append({"check": "reports_contain_no_raw_paths", "passed": not leaked})
                if root.owned_processes():
                    checks.append({"check": "no_owned_processes_remain", "passed": False})
            entry["scenarios"].append({"scenario": name, "passed": all(c["passed"] for c in checks), "checks": checks,
                                       "reports": reports, "duration_s": round(time.monotonic() - began, 1)})
        summary["profiles"].append(entry)
    if not options.keep:
        shutil.rmtree(base, ignore_errors=True)
    summary["cleanup"] = {"owned_roots_removed": not options.keep and not base.exists()}
    summary["passed"] = all(s["passed"] for p in summary["profiles"] for s in p["scenarios"])
    summary["duration_s"] = round(time.monotonic() - started, 1)
    (options.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    total = [s for p in summary["profiles"] for s in p["scenarios"]]
    print(f"{'PASSED' if summary['passed'] else 'FAILED'}: {sum(s['passed'] for s in total)}/{len(total)} scenarios; "
          f"evidence {options.out}")
    sys.exit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
