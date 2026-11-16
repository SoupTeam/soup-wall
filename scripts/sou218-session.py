#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Linux personal memory-only Gemini session; bounded jobs, never automatic retries."""
import argparse
import ctypes
import getpass
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import resource
import socket
import stat
import subprocess
import threading
import time
import tomllib
import uuid
import warnings

MODEL = "gemini-2.5-flash"
KEY_SHAPE = re.compile(r"[A-Za-z0-9_.-]{20,256}\Z")


def normalize_key(value):
    value = value.strip(" \t\r\n")
    if value.startswith("\x1b[200~") and value.endswith("\x1b[201~"):
        value = value[6:-6].strip(" \t\r\n")
    if not KEY_SHAPE.fullmatch(value):
        raise ValueError("key_shape")
    return value


def private_read(path, limit=4096):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise ValueError("private_file_required")
        data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file_limit")
        return data


def write_private(path, value):
    data = json.dumps(value, ensure_ascii=True).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


class Budget:
    def __init__(self, remaining, expires):
        if type(remaining) is not int or not 1 <= remaining <= 30:
            raise ValueError("budget_range")
        self.remaining, self.expires = remaining, expires
        self.jobs = []

    def reserve(self, amount, now):
        if now >= self.expires:
            raise ValueError("session_expired")
        if type(amount) is not int or not 1 <= amount <= self.remaining:
            raise ValueError("session_budget_exhausted")
        self.remaining -= amount  # No refunds, including crashes/uncertain results.


def validate_job(request, project, allowed_root, features, native_token):
    if set(request) != {"action", "config", "feature", "max_new_rows"}:
        raise ValueError("job_fields")
    feature = request["feature"]
    if feature not in features or not feature.startswith("sou218-gemini25-flash-"):
        raise ValueError("feature_scope")
    config_path = Path(request["config"])
    if config_path.is_symlink():
        raise ValueError("config_symlink")
    config_path = config_path.resolve(strict=True)
    if not config_path.is_relative_to(allowed_root):
        raise ValueError("config_scope")
    config = json.loads(private_read(config_path))
    if config.get("model") != MODEL or config.get("project") != project:
        raise ValueError("model_project_scope")
    if any(config.get(k) is not None for k in ("metadata_recovery_started_sha256", "resume_count_unknown", "parent_attempt")):
        raise ValueError("uncertain_recovery_not_automatic")
    ceiling = config.get("row_ceiling")
    if type(ceiling) is not int or not 1 <= ceiling <= 30:
        raise ValueError("row_ceiling")
    for name in ("ledger", "evidence_file"):
        path = Path(config[name])
        if not path.is_absolute() or path.is_symlink() or not path.resolve().is_relative_to(allowed_root):
            raise ValueError("path_scope")
    private_read(config["evidence_file"])
    # Inspect token metadata only; the existing Rust operator reads it privately.
    token_path = Path(config["native_token_file"])
    if token_path.is_symlink() or token_path.resolve(strict=True) != native_token:
        raise ValueError("token_scope")
    token = token_path.stat()
    if not stat.S_ISREG(token.st_mode) or token.st_uid != os.getuid() or token.st_mode & 0o077:
        raise ValueError("token_permissions")
    config["non_billed_free_tier"] = True
    config["quota_available"] = True
    return config, feature


def build(repo, feature, log):
    env = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0")
    result = subprocess.run(["cargo", "test", "--locked", "-p", "agentfw", "--lib", "--no-run",
                             "--message-format=json", "--features", feature], cwd=repo,
                            env=env, stdout=subprocess.PIPE, stderr=log, text=True, check=True, timeout=600)
    bins = [v["executable"] for line in result.stdout.splitlines() if (v := json.loads(line)).get("reason") == "compiler-artifact"
            and v.get("target", {}).get("name") == "agentfw" and v.get("profile", {}).get("test") and v.get("executable")]
    if len(bins) != 1:
        raise ValueError("binary_count")
    return bins[0]


class Supervisor:
    def __init__(self, root, repo, allowed_root, project, budget, key, native_token):
        self.root, self.repo, self.allowed_root, self.project = root, repo, allowed_root, project
        self.budget, self.key = budget, key
        self.native_token = native_token
        self.lock = threading.Lock()
        self.pending = queue.Queue(maxsize=1)
        self.busy = False
        self.stopping = False
        self.events = 0
        self.proc = None

    def event(self, value):
        self.events += 1
        write_private(self.root / ("event-%06d.json" % self.events), value)

    def dispatch(self, request):
        with self.lock:
            action = request.get("action")
            if action == "status":
                return {"busy": self.busy, "remaining_reserved_budget": self.budget.remaining,
                        "expires": self.budget.expires, "stopping": self.stopping, "jobs": self.budget.jobs}
            if action == "stop":
                self.stopping = True
                if self.proc is not None and self.proc.poll() is None:
                    self.proc.terminate()
                return {"stopping": True, "uncertain_attempts_remain_reserved": self.busy}
            if action != "submit" or self.busy or self.stopping or time.time() >= self.budget.expires:
                raise ValueError("session_not_available")
            features = tomllib.loads((self.repo / "crates/agentfw/Cargo.toml").read_text())["features"]
            config, feature = validate_job(request, self.project, self.allowed_root, features, self.native_token)
            n = request["max_new_rows"]
            if type(n) is not int or not 1 <= n <= min(30, self.budget.remaining):
                raise ValueError("session_budget_exhausted")
            self.busy = True
            job = {"id": uuid.uuid4().hex, "feature": feature, "reserved_rows": n, "status": "building"}
            self.budget.jobs.append(job)
            self.pending.put((job, config))
            return dict(job)

    def work(self):
        while True:
            try:
                job, config = self.pending.get(timeout=1)
            except queue.Empty:
                if self.stopping or time.time() >= self.budget.expires:
                    return
                continue
            try:
                folder = self.root / job["id"]
                folder.mkdir(mode=0o700)
                with open(folder / "build.log", "xb") as log:
                    os.chmod(log.name, 0o600)
                    binary = build(self.repo, job["feature"], log)
                with self.lock:
                    if self.stopping:
                        raise ValueError("session_stopped_before_key_use")
                    self.budget.reserve(job["reserved_rows"], time.time())
                    # Reservation is durably recorded BEFORE any key transfer or API access.
                    self.event({"event": "reserved", "job": job["id"], "rows": job["reserved_rows"],
                                "remaining": self.budget.remaining, "expires": self.budget.expires})
                ledger = Path(config["ledger"])
                ledger.mkdir(mode=0o700, exist_ok=True)
                reports_before = {p.name for p in ledger.glob("report-*.json")}
                cfgpath = folder / "operator.json"
                write_private(cfgpath, config)
                config_bytes = private_read(cfgpath)
                grant = {"key": self.key, "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
                         "project": self.project, "model": MODEL, "expires": self.budget.expires,
                         "max_new_rows": job["reserved_rows"], "parent_pid": os.getpid(), "job": job["id"]}
                read_fd, write_fd = os.pipe()
                try:
                    env = dict(os.environ, SOUP_WALL_GEMINI_MANUAL_CONFIG=str(cfgpath),
                               SOUP_WALL_GEMINI_SESSION_FD=str(read_fd))
                    with open(folder / "run.log", "xb") as log:
                        os.chmod(log.name, 0o600)
                        proc = subprocess.Popen([binary, "pilot-launch",
                            "native::consumer::gemini_fixture::controller::operator::manual_public_gemini_operator",
                            "--ignored", "--exact", "--nocapture", "--test-threads=1"], cwd=self.repo,
                            env=env, pass_fds=(read_fd,), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                        with self.lock:
                            self.proc = proc
                            if self.stopping:
                                proc.terminate()
                        os.close(read_fd); read_fd = -1
                        with os.fdopen(write_fd, "wb") as pipe:
                            write_fd = -1
                            pipe.write(json.dumps(grant).encode())
                        grant.clear()
                        with self.lock:
                            job["status"] = "running"
                            self.event({"event": "key_used", "job": job["id"], "max_new_rows": job["reserved_rows"], "time": int(time.time())})
                        try:
                            result = proc.wait(timeout=max(1, self.budget.expires - time.time()) + 70)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                            raise ValueError("expired_worker_unknown_outcome")
                        self.proc = None
                    with self.lock:
                        job["status"] = "finished" if result == 0 else "stopped"
                        job["exit_code"] = result
                        job["log"] = str(folder / "run.log")
                        self.event({"event": "finished", **job, "remaining": self.budget.remaining})
                        for report in ledger.glob("report-*.json"):
                            if report.name in reports_before:
                                continue
                            observed = json.loads(private_read(report, 131072))
                            if any(row.get("state") in ("quota_stop", "model_drift") for row in observed.get("rows", [])):
                                self.stopping = True
                                self.event({"event":"provider_quota_or_model_stop", "job":job["id"]})
                    # A new job is always explicit. There is no HTTP/unknown retry loop.
                finally:
                    grant.clear()
                    for fd in (read_fd, write_fd):
                        if fd >= 0:
                            os.close(fd)
            except Exception:
                with self.lock:
                    job["status"] = "stopped_inspect_logs"
                    self.event({"event": "stopped", "job": job["id"], "remaining": self.budget.remaining})
            finally:
                with self.lock:
                    self.busy = False
                self.pending.task_done()


def serve(args):
    if os.name != "posix" or "CI" in os.environ:
        raise ValueError("personal_linux_only")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Do not permit ordinary process dumps of the supervisor's credential memory.
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise ValueError("memory_dump_guard")
    os.umask(0o077)
    root = args.session.absolute()
    root.mkdir(mode=0o700, exist_ok=False)  # Never restart an existing session/budget.
    repo = args.repo.resolve(strict=True)
    allowed = args.allowed_root.resolve(strict=True)
    budget = Budget(args.rows, int(time.time()) + args.minutes * 60)
    with open("/dev/tty", "r") as tty_in, open("/dev/tty", "w") as tty:
        tty.write(f"Memory-only session for {args.project} / {MODEL}. Maximum {args.rows} NEW row attempts, USD0, {args.minutes} minutes. No refunds/retries or daily reset. Do not use this quota from other clients. Verify non-billed Free Tier and current remaining quota.\nType SESSION {args.project} {MODEL} {args.rows} USD0\n")
        tty.flush()
        if tty_in.readline().strip() != f"SESSION {args.project} {MODEL} {args.rows} USD0":
            raise ValueError("personal_confirmation")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            key = getpass.getpass("Gemini API key (hidden): ", stream=tty)
    key = normalize_key(key)
    template = json.loads(private_read(args.template_config.resolve(strict=True)))
    if template.get("project") != args.project or template.get("model") != MODEL:
        raise ValueError("template_scope")
    native_token = Path(template["native_token_file"]).resolve(strict=True)
    supervisor = Supervisor(root, repo, allowed, args.project, budget, key, native_token)
    key = None
    supervisor.event({"event": "armed", "project": args.project, "model": MODEL, "budget": args.rows,
                      "expires": budget.expires, "time": int(time.time())})
    worker = threading.Thread(target=supervisor.work)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(root / "control.sock")); os.chmod(root / "control.sock", 0o600)
    sock.listen(4); sock.settimeout(1)
    if args.initial_config:
        supervisor.dispatch({"action":"submit", "config":str(args.initial_config),
                             "feature":args.initial_feature, "max_new_rows":1})
    worker.start()
    print("Session armed. Keep this terminal open. Initial probe is queued when configured. Control socket:", root / "control.sock", flush=True)
    try:
        while worker.is_alive():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(3)
                try:
                    import struct
                    _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != os.getuid():
                        raise ValueError("peer_owner")
                    raw = bytearray()
                    while len(raw) <= 8192:
                        part = conn.recv(min(4096, 8193 - len(raw)))
                        if not part: break
                        raw.extend(part)
                    if len(raw) > 8192:
                        raise ValueError("request_limit")
                    reply = supervisor.dispatch(json.loads(raw))
                except Exception:
                    reply = {"error": "request_refused; inspect session status and scope"}
                conn.sendall(json.dumps(reply).encode())
    except KeyboardInterrupt:
        supervisor.dispatch({"action":"stop"})
        print("Stopping; preserve uncertain requests and reservations.", flush=True)
    finally:
        supervisor.stopping = True
        worker.join()
        supervisor.key = None
        sock.close()
        print("Session closed. A new session requires personal input.", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    start = sub.add_parser("serve")
    start.add_argument("--session", type=Path, required=True)
    start.add_argument("--repo", type=Path, required=True)
    start.add_argument("--allowed-root", type=Path, required=True)
    start.add_argument("--project", required=True)
    start.add_argument("--template-config", type=Path, required=True)
    start.add_argument("--rows", type=int, required=True)
    start.add_argument("--minutes", type=int, default=120)
    start.add_argument("--initial-config", type=Path)
    start.add_argument("--initial-feature")
    for cmd in ("status", "stop", "submit"):
        item = sub.add_parser(cmd); item.add_argument("--session", type=Path, required=True)
        if cmd == "submit":
            item.add_argument("--config", required=True); item.add_argument("--feature", required=True)
            item.add_argument("--max-new-rows", type=int, required=True)
    args = p.parse_args()
    if args.command == "serve":
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", args.project) or not 1 <= args.minutes <= 240:
            p.error("invalid project or session duration")
        if bool(args.initial_config) != bool(args.initial_feature):
            p.error("initial config and feature must be supplied together")
        serve(args)
    else:
        req = {"action": args.command}
        if args.command == "submit":
            req.update(config=args.config, feature=args.feature, max_new_rows=args.max_new_rows)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(10); client.connect(str(args.session / "control.sock"))
            client.sendall(json.dumps(req).encode()); client.shutdown(socket.SHUT_WR); print(client.recv(65536).decode())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Session stopped/refused. No automatic retry. Inspect non-secret logs; never send the key.") from None
