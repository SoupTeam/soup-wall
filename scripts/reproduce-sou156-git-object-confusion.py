#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture unchanged original Git MCP replies for distinct commit/blob objects.

This is an owned synthetic ambiguity control, not a runtime attestation or an
OS-confinement qualification. Native Linux qualification remains separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WIRE_LIMIT = 1_048_576
TOTAL_LIMIT = 4 * WIRE_LIMIT
TIMEOUT = 15


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    with path.open("xb") as out:
        out.write(data)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def command(argv, env, cwd, data=None, *, timeout=TIMEOUT, limit=WIRE_LIMIT):
    """Drain finite buffers while running; enforce bytes/deadline before exit."""
    require(data is None or len(data) <= WIRE_LIMIT, "owned command input bound")
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True,
                               stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    remaining_input = memoryview(data or b"")
    try:
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if data:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "owned command deadline")
            events = selector.select(remaining)
            require(events, "owned command deadline")
            for key, _ in events:
                if key.data == "stdin":
                    try:
                        count = os.write(key.fd, remaining_input[:4096])
                    except BrokenPipeError:
                        count = len(remaining_input)
                    remaining_input = remaining_input[count:]
                    if not remaining_input:
                        selector.unregister(key.fileobj)
                        process.stdin.close()
                    continue
                buffer = buffers[key.data]
                chunk = os.read(key.fd, min(65_536, limit - len(buffer) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(buffer) + len(chunk) <= limit,
                        "owned command " + key.data + " byte bound")
                buffer.extend(chunk)
        remaining = deadline - time.monotonic()
        require(remaining > 0, "owned command deadline")
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise ValueError("owned command deadline") from error
        if code:
            raise subprocess.CalledProcessError(code, argv, bytes(buffers["stdout"]),
                                                bytes(buffers["stderr"]))
        return bytes(buffers["stdout"])
    finally:
        # This group was created by this invocation, never selected from caller
        # metadata. Kill remaining descendants even if the direct child exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def snapshot(root):
    rows = []
    for path in sorted(root.rglob("*")):
        require(len(rows) < 1024, "owned fixture inventory limit")
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "unexpected owned fixture entry")
        require(info.st_size <= WIRE_LIMIT, "owned fixture file limit")
        rows.append([str(path.relative_to(root)), stat.S_IMODE(info.st_mode),
                     digest(path.read_bytes()) if path.is_file() else "directory"])
    return digest(canonical(rows))


class Original:
    def __init__(self, python, git, repo, env, output):
        self.argv = [str(python), "-I", "-B", "-m", "mcp_server_git",
                     "--repository", str(repo)]
        self.output = output
        self.output.mkdir(mode=0o700)
        self.process = subprocess.Popen(self.argv, cwd=repo, env=env,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True)
        self.selector = selectors.DefaultSelector()
        for stream, label in ((self.process.stdout, "stdout"),
                              (self.process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.total = 0
        self.sent = 0
        self.received = 0

    def send(self, frame):
        raw = canonical(frame) + b"\n"
        require(len(raw) <= 65_536 and self.sent < 8, "request bound")
        save(self.output / f"request-{self.sent}.jsonl", raw)
        self.sent += 1
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def exchange(self, frame):
        self.send(frame)
        deadline = time.monotonic() + TIMEOUT
        while True:
            stdout = self.buffers["stdout"]
            if b"\n" in stdout:
                end = stdout.index(b"\n") + 1
                raw = bytes(stdout[:end])
                del stdout[:end]
                require(len(raw) <= WIRE_LIMIT, "response wire bound")
                value = json.loads(raw)
                save(self.output / f"response-{self.received}.jsonl", raw)
                self.received += 1
                if value.get("id") == frame["id"]:
                    return value, raw
                require("method" in value and "id" not in value,
                        "unexpected original response correlation")
            remaining = deadline - time.monotonic()
            require(remaining > 0, "original response timeout")
            events = self.selector.select(remaining)
            require(events, "original response timeout")
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65_536)
                require(chunk or key.data != "stdout", "original stdout closed")
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    continue
                self.total += len(chunk)
                require(self.total <= TOTAL_LIMIT, "original total output bound")
                self.buffers[key.data].extend(chunk)
                require(len(self.buffers[key.data]) <= WIRE_LIMIT,
                        "original buffered output bound")

    def initialize(self):
        value, _ = self.exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "sou156-owned-confusion", "version": "1"}}})
        pins = ROOT / "profiles/mcp/git-readonly-v1"
        require(value["result"] == json.loads((pins / "upstream-initialize.json").read_bytes())["result"],
                "original initialization differs from accepted pin")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        value, _ = self.exchange({"jsonrpc": "2.0", "id": 2,
                                  "method": "tools/list", "params": {}})
        require(value["result"] == json.loads((pins / "upstream-tools-list.json").read_bytes())["result"],
                "original discovery differs from accepted pin")

    def close(self):
        forced = False
        try:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                forced = True
        finally:
            # The original may create Git children; terminate the owned group
            # on every error path, including a parent that exited first.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=3)
            self.selector.close()
            for stream in (self.process.stdout, self.process.stderr):
                stream.close()
            save(self.output / "stderr-captured.bin", bytes(self.buffers["stderr"]))
        require(not forced and self.process.returncode == 0,
                "original server did not exit cleanly")


def show(python, git, repo, env, output, revision):
    client = Original(python, git, repo, env, output)
    try:
        client.initialize()
        return client.exchange({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "git_show", "arguments": {
                "repo_path": str(repo), "revision": revision}}})
    finally:
        client.close()


def run(args):
    require(os.name == "posix", "this owned process control requires POSIX")
    # Preserve the selected venv invocation path: resolving its interpreter
    # symlink would silently select the base interpreter and another closure.
    python = args.python.absolute()
    require(python.is_file(), "selected Python invocation is unavailable")
    git, wheel = [p.resolve(strict=True) for p in (args.git, args.server_wheel)]
    args.output.mkdir(mode=0o700, parents=False)
    output = args.output.resolve(strict=True)
    home, repo = output / "home", output / "repository"
    home.mkdir(mode=0o700)
    repo.mkdir(mode=0o700)
    env = {"HOME": str(home), "PATH": str(git.parent), "LANG": "C.UTF-8",
           "GIT_PYTHON_GIT_EXECUTABLE": str(git), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_DATE": "2026-10-26T00:00:00+0000",
           "GIT_COMMITTER_DATE": "2026-10-26T00:00:00+0000"}
    pins = ROOT / "profiles/mcp/git-readonly-v1"
    lock = (pins / "requirements.lock").read_bytes()
    line = next(s for s in lock.decode().splitlines() if s.startswith("mcp-server-git=="))
    require(wheel.stat().st_size <= WIRE_LIMIT, "server wheel bound")
    wheel_sha = digest(wheel.read_bytes())
    require(wheel_sha in re.findall(r"sha256:([0-9a-f]{64})", line), "wheel differs from accepted pin")
    probe = "import mcp_server_git,sys,json,importlib.metadata as m;print(json.dumps({'module':mcp_server_git.__file__,'python':sys.version,'packages':{d.metadata['Name']:d.version for d in m.distributions()}}))"
    runtime = json.loads(command([str(python), "-I", "-B", "-c", probe], env, output))
    expected = dict(s.split(" --hash=")[0].split("==", 1) for s in lock.decode().splitlines() if s)
    normalize = lambda s: re.sub(r"[-_.]+", "-", s).lower()
    installed = {normalize(k): v for k, v in runtime["packages"].items()}
    require(all(installed.get(normalize(k)) == v for k, v in expected.items()),
            "runtime dependency versions differ from accepted lock")
    source = Path(runtime["module"]).parent
    source_hashes = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith("mcp_server_git/") and not name.endswith("/"):
                data = archive.read(name)
                require(len(data) <= WIRE_LIMIT and (source / name.split("/", 1)[1]).read_bytes() == data,
                        "installed original server bytes differ from pinned wheel")
                source_hashes[name] = digest(data)

    def fixture(*argv, data=None):
        return command([str(git), "-c", "user.name=SOU156 Synthetic",
                        "-c", "user.email=sou156@example.invalid", *argv], env, repo, data)

    fixture("init", "--initial-branch=main", "--template=")
    (repo / "notes.txt").write_bytes(b"Owned synthetic object-kind fixture.\n")
    fixture("add", "notes.txt")
    fixture("commit", "-m", "Owned synthetic commit")
    commit = fixture("rev-parse", "HEAD").decode().strip()
    commit_reply, seed_raw = show(python, git, repo, env, output / "seed-commit", commit)
    require(not commit_reply.get("error") and commit_reply["result"].get("isError") is not True,
            "original commit call failed")
    content = commit_reply["result"]["content"]
    require(len(content) == 1 and content[0]["type"] == "text", "unexpected original content")
    text = content[0]["text"].encode("utf-8")
    blob = fixture("hash-object", "-w", "--stdin", data=text).decode().strip()
    plain_blob = fixture("hash-object", "-w", "--stdin", data=b"Owned raw blob.\n").decode().strip()
    tree = fixture("rev-parse", "HEAD^{tree}").decode().strip()
    tags = {}
    for name, target in (("commit", commit), ("blob", blob), ("tree", tree)):
        fixture("tag", "--annotate", "owned-" + name, target, "--message", "Owned tag")
        tags[name] = fixture("rev-parse", "refs/tags/owned-" + name).decode().strip()
    fixture("tag", "--annotate", "owned-nested", tags["commit"], "--message", "Owned nested tag")
    tags["nested"] = fixture("rev-parse", "refs/tags/owned-nested").decode().strip()
    before = snapshot(repo)
    commit_reply, commit_raw = show(python, git, repo, env, output / "commit", commit)
    blob_reply, blob_raw = show(python, git, repo, env, output / "commit-looking-blob", blob)
    plain_reply, plain_raw = show(python, git, repo, env, output / "raw-blob", plain_blob)
    missing_reply, missing_raw = show(python, git, repo, env, output / "missing", "0" * 40)
    tag_controls = {}
    for name in ("commit", "nested", "blob", "tree"):
        value, raw = show(python, git, repo, env, output / ("tag-" + name), tags[name])
        failed = bool(value.get("error")) or value.get("result", {}).get("isError") is True
        if name in ("commit", "nested"):
            require(not failed and raw == commit_raw, "original commit tag formatting changed")
        else:
            require(failed, "original tag-to-noncommit unexpectedly succeeded")
        tag_controls[name] = {"oid": tags[name], "original_is_error": failed,
                              "raw_response_sha256": digest(raw), "bytes": len(raw)}
    tree_reply, tree_raw = show(python, git, repo, env, output / "tree", tree)
    # Pinned GitPython's directly resolved root Tree lacks a path for this
    # nonempty fixture. Preserve its original error instead of substituting a
    # listing or claiming a successful tree formatter result.
    require(tree_reply.get("error") or tree_reply.get("result", {}).get("isError") is True,
            "pinned nonempty-root-tree error control changed")
    require(blob != commit and seed_raw == commit_raw == blob_raw and commit_reply == blob_reply,
            "byte-identical original commit/blob ambiguity did not reproduce")
    require(plain_reply["result"]["content"] == [{"type": "text", "text": "Owned raw blob.\n"}],
            "ordinary raw blob read failed")
    require(missing_reply.get("error") or missing_reply.get("result", {}).get("isError") is True,
            "missing-object control unexpectedly succeeded")
    require(snapshot(repo) == before, "read controls changed owned repository bytes or modes")
    save(output / "commit-looking-blob-payload.bin", text)
    report = {"format": "sou156/original-object-confusion/1", "status": "PASS",
        "scope": "original pinned package ambiguity only; no native confinement or production attestation",
        "source_commit": command([str(git), "rev-parse", "HEAD"], env, ROOT).decode().strip(),
        "source_status": command([str(git), "status", "--porcelain"], env, ROOT).decode(),
        "platform": platform.platform(), "python": str(python), "runtime": runtime,
        "python_executable_sha256": digest(python.read_bytes()),
        "driver_sha256": digest(Path(__file__).read_bytes()),
        "git": str(git), "git_version": fixture("--version").decode().strip(),
        "identity_sha256": digest((pins / "upstream-identity.json").read_bytes()),
        "requirements_sha256": digest(lock), "server_wheel_sha256": wheel_sha,
        "original_source_sha256": source_hashes,
        "commit_oid": commit, "forged_blob_oid": blob, "raw_blob_oid": plain_blob,
        "tree_oid": tree, "tree_original_is_error": True,
        "tree_response_sha256": digest(tree_raw), "tag_controls": tag_controls,
        "same_raw_mcp_response": True, "same_decoded_result": True,
        "response_sha256": digest(commit_raw), "response_bytes": len(commit_raw),
        "blob_payload_sha256": digest(text), "plain_response_sha256": digest(plain_raw),
        "missing_response_sha256": digest(missing_raw), "repository_snapshot_sha256": before,
        "repository_unchanged": True, "separate_sessions_same_request_id": True,
        "limits": {"response_bytes": WIRE_LIMIT, "total_bytes_per_session": TOTAL_LIMIT,
                   "response_seconds": TIMEOUT, "cleanup_seconds": 3},
        "native_linux_qualification": "NOT_RUN", "production_authentication": "DISABLED"}
    save(output / "report.json", json.dumps(report, indent=2).encode() + b"\n")
    return {k: report[k] for k in ("status", "scope", "commit_oid", "forged_blob_oid",
                                   "response_sha256", "response_bytes", "repository_unchanged")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--git", type=Path, required=True)
    parser.add_argument("--server-wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "scope": "owned original-package ambiguity control",
                          "production_authentication": "DISABLED"}))
        return
    print(json.dumps(run(args), indent=2))


if __name__ == "__main__":
    main()
