# SPDX-License-Identifier: Apache-2.0
"""Bounded, allowlisted evidence and owned lifecycle for genuine SSO drivers.

Never serialize an exception message, URL, header, body, environment or raw log.
The synthetic protocol drivers retain their real positive/refusal assertions.
"""
from contextlib import ExitStack
import hashlib
import importlib.metadata
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time
import urllib.parse
import uuid


NETWORK_ERRORS = frozenset("net::" + name for name in (
    "ERR_EMPTY_RESPONSE", "ERR_CONNECTION_CLOSED", "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_REFUSED", "ERR_CERT_AUTHORITY_INVALID", "ERR_CERT_COMMON_NAME_INVALID",
    "ERR_ABORTED", "ERR_FAILED", "ERR_BLOCKED_BY_CLIENT", "ERR_HTTP_RESPONSE_CODE_FAILURE",
    "ERR_HTTP2_PROTOCOL_ERROR", "ERR_TIMED_OUT", "ERR_INTERNET_DISCONNECTED",
    "ERR_NAME_NOT_RESOLVED", "ERR_NETWORK_CHANGED", "ERR_CONNECTION_TIMED_OUT", "ERR_CACHE_MISS"))
SERVER_ERRORS = (
    "oidc discovery failed", "oidc callback discovery failed", "oidc callback jwks fetch failed",
    "oidc authorization-code exchange failed", "oidc id token verification failed",
    "failed to consume oidc callback state", "failed to authorize verified oidc identity",
    "failed to create oidc browser session", "failed to authenticate oidc browser session",
    "saml login start failed", "failed to consume saml state", "saml response validation failed",
    "failed to authorize saml identity", "failed to issue saml browser session",
    "address already in use", "failed to start server", "permission denied")
VALIDATION_ERRORS = ("expired", "signature", "audience", "issuer", "destination", "recipient",
                     "request", "replay", "notbefore", "not yet valid")


def network_category(value):
    return value if value in NETWORK_ERRORS else "other"


def location(url, gateway, vendor):
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "other"
    origin = parsed.scheme + "://" + parsed.netloc
    if origin == gateway:
        return {"/auth/oidc/start": "gateway_start", "/auth/saml/start": "gateway_start",
                "/auth/oidc/callback": "gateway_callback", "/auth/saml/acs": "gateway_acs",
                "/customer": "gateway_console", "/customer/v1/session": "server_session"}.get(
                    parsed.path, "gateway_other")
    if origin == vendor:
        return "vendor"
    return "browser_error" if parsed.scheme in ("about", "chrome-error") else "other"


def same_endpoint(url, expected):
    try:
        actual, target = urllib.parse.urlsplit(url), urllib.parse.urlsplit(expected)
        return (actual.scheme, actual.netloc, actual.path) == (target.scheme, target.netloc, target.path)
    except ValueError:
        return False


def log_categories(path, offset=0):
    """Read at most 64 KiB, starting no earlier than this attempt's log offset."""
    try:
        with Path(path).open("rb") as source:
            source.seek(0, os.SEEK_END)
            end = source.tell()
            start = max(offset, end - 65536)
            source.seek(start)
            text = source.read(65536).decode(errors="replace").lower()
    except OSError:
        return {"available": False, "categories": [], "validation": []}
    validation = text.rsplit("saml response validation failed", 1)
    return {"available": True, "truncated": start > offset,
            "categories": [label for label in SERVER_ERRORS if label in text],
            "validation": [label for label in VALIDATION_ERRORS
                           if len(validation) == 2 and label in validation[-1]]}


class BrowserTransportFailure(RuntimeError):
    pass


def wait_for_browser(page, ready, observation, timeout_ms):
    """Pump real browser events; a failed navigation cannot become a blind timeout.

    No retry happens here. The caller alone applies the existing narrow rule.
    Check failures before readiness so a late failure is never hidden by stale UI.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        if observation.get("network_failures"):
            raise BrowserTransportFailure("navigation failed")
        if ready():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("browser phase budget exhausted")
        page.wait_for_timeout(min(100, remaining * 1000))


class RunCancelled(InterruptedError):
    pass


class RunBudgetExceeded(TimeoutError):
    pass


class Diagnostics:
    def __init__(self, report, output, root):
        self.report, self.output = report, output
        self.started = time.monotonic()
        self.report.update(outcome="incomplete", timeline=[], run_id=uuid.uuid4().hex,
                           budget_seconds=900)
        self.processes, self.containers, self.logs = [], [], []
        runtime = {"python": platform.python_version(), "os": platform.system(),
                   "architecture": platform.machine(), "kernel": platform.release()}
        for name in ("playwright", "requests", "cryptography", "psutil"):
            try:
                runtime[name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                runtime[name] = "unavailable"
        self.report["driver_runtime"] = runtime
        try:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, timeout=5,
                                             stderr=subprocess.DEVNULL, text=True).strip()
            diff = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=root, timeout=5,
                                           stderr=subprocess.DEVNULL)
            if re.fullmatch(r"[a-f0-9]{40}", commit):
                self.report["source_commit"] = commit
            self.report["tracked_source_dirty"] = bool(diff)
            self.report["tracked_diff_sha256"] = hashlib.sha256(diff).hexdigest()
        except (OSError, subprocess.SubprocessError):
            self.report["source_identity_available"] = False
        self.phase("prerequisites")

    def phase(self, name):
        now = time.monotonic()
        timeline = self.report["timeline"]
        if timeline:
            timeline[-1]["duration_ms"] = round((now - self.phase_started) * 1000)
        if len(timeline) >= 256:
            raise RuntimeError("phase evidence limit exceeded")
        self.phase_started = now
        self.report["phase"] = name
        timeline.append({"phase": name, "elapsed_ms": round((now - self.started) * 1000)})
        self.publish()

    def publish(self):
        self.report["elapsed_ms"] = round((time.monotonic() - self.started) * 1000)
        if self.report["timeline"]:
            self.report["timeline"][-1]["duration_ms"] = round((time.monotonic() - self.phase_started) * 1000)
        self.output.publish(self.report)

    def process(self, name, child):
        self.processes.append((name, child))

    def container(self, name, docker, identifier):
        self.containers.append((name, docker, identifier))

    def health(self):
        health = {"processes": [{"role": name, "running": child.poll() is None,
                                  "exit_code": child.poll()} for name, child in self.processes]}
        health["containers"] = []
        if self.containers:
            try:
                runtime = subprocess.run([self.containers[0][1], "version", "--format",
                    "{{.Client.Version}} {{.Server.Version}}"], capture_output=True, text=True,
                    timeout=5, check=True)
                if re.fullmatch(r"[0-9][0-9a-zA-Z.+-]{0,40} [0-9][0-9a-zA-Z.+-]{0,40}\s*", runtime.stdout):
                    client, server = runtime.stdout.split()
                    self.report["driver_runtime"].update(docker_client=client, docker_server=server)
            except (OSError, subprocess.SubprocessError):
                pass
        for name, docker, identifier in self.containers:
            item = {"role": name, "id": identifier, "inspect_available": False}
            try:
                result = subprocess.run([docker, "inspect", "--format",
                    "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}} {{.Image}}", identifier],
                    capture_output=True, text=True, timeout=5, check=True)
                match = re.fullmatch(r"(created|running|paused|restarting|removing|exited|dead) (-?\d+) (true|false) (sha256:[a-f0-9]{64})\s*", result.stdout)
                if match:
                    item.update(inspect_available=True, state=match[1], exit_code=int(match[2]),
                                oom_killed=match[3] == "true", image_id=match[4])
            except (OSError, subprocess.SubprocessError):
                pass
            health["containers"].append(item)
        health["server_errors"] = [{"role": name, **log_categories(path)} for name, path in self.logs]
        self.report["owned_health_before_cleanup"] = health
        self.publish()


class RunResources(ExitStack):
    """SIGTERM/timeout unwind the same owned cleanup as an assertion failure."""
    def __init__(self, diagnostics):
        super().__init__()
        self.diagnostics = diagnostics
        self.previous = {}

    def __enter__(self):
        super().__enter__()
        if os.name == "posix":
            def cancel(signum, _frame):
                if signum == signal.SIGALRM:
                    raise RunBudgetExceeded("acceptance budget exhausted")
                raise RunCancelled("acceptance cancelled")
            for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
                self.previous[number] = signal.signal(number, cancel)
            signal.alarm(self.diagnostics.report["budget_seconds"])
        return self

    def __exit__(self, kind, error, trace):
        diag = self.diagnostics
        # Give already bounded cleanup callbacks time to finish after cancellation.
        if self.previous:
            signal.alarm(0)
            for number in (signal.SIGTERM, signal.SIGINT):
                signal.signal(number, signal.SIG_IGN)
        try:
            try:
                diag.health()
            finally:
                super().__exit__(kind, error, trace)
            diag.report["cleanup_passed"] = True
        finally:
            for number, handler in self.previous.items():
                signal.signal(number, handler)
            diag.publish()
        return False


def owned_network(docker, resources):
    name = "soup-sso-" + uuid.uuid4().hex
    created = subprocess.run([docker, "network", "create", name], check=True,
                             capture_output=True, text=True, timeout=30)
    identifier = created.stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{64}", identifier):
        raise RuntimeError("Docker did not return an owned network ID")
    resources.callback(lambda: subprocess.run([docker, "network", "rm", identifier],
                        check=True, capture_output=True, timeout=30))
    return identifier
