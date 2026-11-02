# SPDX-License-Identifier: Apache-2.0
"""Bounded, non-inferential observation of one installed provider selection.

The parent reads the selected private profile. The worker receives only public
host/port and optional CA bytes, performs DNS/TCP/TLS, and sends no HTTP data.
"""
from __future__ import annotations

import ctypes
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

_ca_spec = importlib.util.spec_from_file_location(
    "provider_preflight_ca_boundary", Path(__file__).with_name("pilot_provider_ca.py"))
PROVIDER_CA = importlib.util.module_from_spec(_ca_spec)
_ca_spec.loader.exec_module(PROVIDER_CA)

FORMAT = "sw-pilot-provider-preflight/1"
MAX_CA = 2 * 1024 * 1024
MAX_WORKER_INPUT = MAX_CA * 2 + 8192  # JSON escapes PEM line breaks.
MAX_WORKER_OUTPUT = 2048
STAGES = frozenset(("local", "dns", "connect", "tls", "proxy_dns", "proxy_connect", "tunnel"))
OUTCOMES = frozenset(("transport-observed", "refused", "unavailable", "incomplete"))
REASONS = frozenset(("tcp_connected", "tls_verified", "dns_failed", "address_limit",
                     "connect_failed", "connect_timeout", "tls_invalid", "tls_failed",
                     "tls_timeout", "deadline", "worker_failed", "proxy_dns_failed",
                     "proxy_address_limit", "proxy_connect_failed", "proxy_connect_timeout",
                     "proxy_tunnel_refused", "proxy_auth_required", "proxy_redirect_refused",
                     "proxy_response_invalid", "proxy_response_oversized", "proxy_tunnel_timeout",
                     "proxy_tls_verified"))
MAX_PROXY_HEADER = 8192
MAX_CONNECT_REQUEST = 1024


def _host_valid(host):
    if type(host) is not str or not 0 < len(host) <= 253 or not host.isascii():
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                   for part in host.rstrip(".").split("."))
NEXT = {
    "configuration-valid": "Use --transport for a bounded connection observation, or start the host explicitly.",
    "transport-observed": "Start the host explicitly if credential and model behavior must be tested.",
    "refused": "Review the selected profile, CA and certificate; correct them explicitly, then check again.",
    "unavailable": "Check the exact endpoint or select a reachable profile, then check again.",
    "incomplete": "Repeat the explicit check after resolving the timeout or cancellation.",
}


def report(status, stage, reason, *, transport=False, network=False):
    return {"format": FORMAT, "command": "provider check", "status": status,
            "stage": stage, "reason": reason, "next_step": NEXT[status],
            "transport_requested": transport, "network_attempted": network,
            "provider_request_sent": False, "model_or_tool_executed": False,
            "credential_validity_verified": False, "model_availability_verified": False,
            "protected_task_execution_verified": False}


def human(value):
    return (f"Provider check: {value['status']} ({value['reason']}; stage {value['stage']}).\n"
            f"Next: {value['next_step']}\n"
            "Credential validity, model availability and protected task execution were NOT verified.")


def _same(left, right):
    return (left.st_dev, left.st_ino, left.st_mode, left.st_uid, left.st_nlink,
            left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
            right.st_dev, right.st_ino, right.st_mode, right.st_uid, right.st_nlink,
            right.st_size, right.st_mtime_ns, right.st_ctime_ns)


def _open_parent(path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("ca_unsafe")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parent.parts[1:]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=directory)
            os.close(directory)
            directory = next_directory
        return directory
    except BaseException:
        os.close(directory)
        raise


def _ca_bytes(path):
    """Read an accepted CA through no-follow parent and regular-file descriptors."""
    path = Path(path)
    try:
        parent = _open_parent(path)
        try:
            directory = os.fstat(parent)
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            try:
                opened = os.fstat(fd)
                if not (stat.S_ISREG(opened.st_mode) and opened.st_uid in (0, os.getuid())
                        and not opened.st_mode & 0o022 and opened.st_nlink == 1
                        and 0 < opened.st_size <= MAX_CA and _same(before, opened)):
                    raise ValueError("ca_unsafe")
                raw = b""
                while len(raw) <= MAX_CA:
                    block = os.read(fd, min(65536, MAX_CA + 1 - len(raw)))
                    if not block:
                        break
                    raw += block
                reopened = _open_parent(path)
                try:
                    if (len(raw) != opened.st_size or not _same(os.fstat(fd), opened)
                            or not _same(os.stat(path.name, dir_fd=parent, follow_symlinks=False), opened)
                            or not _same(os.fstat(reopened), directory)):
                        raise ValueError("ca_changed")
                finally:
                    os.close(reopened)
                return raw.decode("ascii")
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    except (OSError, UnicodeError):
        raise ValueError("ca_unsafe") from None


def _stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _stage(raw):
    if not raw:
        return "local"
    for line in reversed(raw[:MAX_WORKER_OUTPUT].splitlines()):
        try:
            stage = json.loads(line).get("stage")
        except (ValueError, AttributeError):
            continue
        if stage in STAGES:
            return stage
    return "local"


def _probe(payload, seconds):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_WORKER_INPUT:
        return report("refused", "local", "ca_unsafe", transport=True)
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        process = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   cwd="/", env=environment, start_new_session=True)
    except OSError:
        return report("unavailable", "local", "worker_failed", transport=True)
    try:
        try:
            output, _ = process.communicate(raw, timeout=seconds)
        except subprocess.TimeoutExpired as error:
            _stop(process)
            return report("incomplete", _stage(error.output), "deadline", transport=True, network=True)
        except KeyboardInterrupt:
            _stop(process)
            return report("incomplete", "local", "cancelled", transport=True, network=True)
        if process.returncode != 0 or len(output) > MAX_WORKER_OUTPUT:
            return report("unavailable", _stage(output), "worker_failed", transport=True, network=True)
        lines = output.splitlines()
        if not lines:
            return report("unavailable", "local", "worker_failed", transport=True, network=True)
        value = json.loads(lines[-1])
        if (type(value) is not dict or set(value) != {"status", "stage", "reason"}
                or value["status"] not in OUTCOMES or value["stage"] not in STAGES
                or value["reason"] not in REASONS):
            return report("unavailable", "local", "worker_failed", transport=True, network=True)
        return report(value["status"], value["stage"], value["reason"], transport=True, network=True)
    except (ValueError, TypeError):
        return report("unavailable", "local", "worker_failed", transport=True, network=True)
    finally:
        if process.poll() is None:
            _stop(process)


def check(home, profiles, *, transport=False, proxy_connect=False, seconds=5):
    """Read and revalidate exact selection; never return profile data."""
    if type(seconds) is not int or not 1 <= seconds <= 15:
        return report("refused", "local", "deadline_invalid", transport=transport)
    try:
        with profiles.Store(home) as store:
            selected = store.selected()
            if selected is None:
                return report("unavailable", "local", "profile_not_selected", transport=transport)
            profile, identity = store.profile(selected["name"], selected.get("version"))
            if identity != selected["profile_sha256"]:
                raise profiles.Refusal("provider_selection_stale")
            public = profile["public"]
            profiles.validate_public(public)
            if profiles.PROVIDER.selected(os.environ):
                raise profiles.Refusal("provider_source_conflict")
            token = (selected["version"] + ":" + identity if "version" in selected else identity)
            name = selected["name"]
        profiles.unchanged(home, name, token)
    except (OSError, ValueError, KeyError, TypeError):
        return report("refused", "local", "selection_invalid", transport=transport)
    ca_path = public.get("SSL_CERT_FILE")
    try:
        ca = _ca_bytes(ca_path) if ca_path else None
    except ValueError:
        return report("refused", "local", "ca_unsafe", transport=transport)
    if ca is not None:
        try:
            # Match the installed host's certificate-only and count bounds
            # before any CA bytes can reach the transport helper.
            PROVIDER_CA._validate(ca.encode("ascii"))
        except (ssl.SSLError, ValueError):
            return report("refused", "local", "ca_invalid", transport=transport)
    try:
        profiles.unchanged(home, name, token)
    except (OSError, ValueError, KeyError, TypeError):
        return report("refused", "local", "selection_changed", transport=transport)
    if not transport:
        if proxy_connect:
            return report("refused", "local", "proxy_opt_in_required")
        return report("configuration-valid", "local", "selection_valid", transport=False)
    # An implicit endpoint or configured proxy would make a direct observation
    # differ from the selected host route. Report unsupported, never bypass it.
    endpoint = public.get("ANTHROPIC_BASE_URL")
    if not endpoint:
        return report("unavailable", "local", "endpoint_not_explicit", transport=True)
    parsed = urlsplit(endpoint)
    proxy = public.get("HTTPS_PROXY")
    if proxy_connect:
        # The accepted profile parser already rejects URL credentials. Limit this
        # observation to a selected, unauthenticated HTTP CONNECT route for HTTPS.
        if (not proxy or public.get("HTTP_PROXY") or public.get("NO_PROXY")
                or parsed.scheme != "https"):
            return report("unavailable", "local", "proxy_route_unsupported", transport=True)
        proxy_url = urlsplit(proxy)
        if proxy_url.scheme != "http" or proxy_url.path not in ("", "/"):
            return report("unavailable", "local", "proxy_route_unsupported", transport=True)
        payload = {"host": parsed.hostname, "port": parsed.port or 443, "tls": True,
                   "ca": ca, "seconds": seconds, "proxy_host": proxy_url.hostname,
                   "proxy_port": proxy_url.port or 80}
    else:
        if public.get("HTTP_PROXY") or proxy:
            return report("unavailable", "local", "proxy_route_unsupported", transport=True)
        if ca_path and parsed.scheme != "https":
            return report("unavailable", "local", "ca_route_unsupported", transport=True)
        payload = {"host": parsed.hostname, "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                   "tls": parsed.scheme == "https", "ca": ca, "seconds": seconds}
    result = _probe(payload, seconds)
    try:
        profiles.unchanged(home, name, token)
        if ca_path and _ca_bytes(ca_path) != ca:
            raise ValueError("ca_changed")
    except (OSError, ValueError, KeyError, TypeError):
        return report("refused", "local", "selection_changed", transport=True,
                      network=result["network_attempted"])
    return result


def _proxy_response(connection, deadline):
    """Read one finite CONNECT header, never a response body or redirect target."""
    raw = bytearray()
    while not raw.endswith(b"\r\n\r\n"):
        if len(raw) >= MAX_PROXY_HEADER:
            return "proxy_response_oversized"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(min(remaining, 3))
        byte = connection.recv(1)
        if not byte:
            return "proxy_response_invalid"
        raw.extend(byte)
    lines = bytes(raw[:-4]).split(b"\r\n")
    if (not lines or not re.fullmatch(rb"HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e]{0,128})?", lines[0])
            or len(lines) > 65):
        return "proxy_response_invalid"
    for line in lines[1:]:
        if (not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+: ?[\x20-\x7e]*", line)
                or line.lower().startswith(b"transfer-encoding:")
                or line.lower().startswith(b"content-length:")
                and line.split(b":", 1)[1].strip() != b"0"):
            return "proxy_response_invalid"
    status = int(lines[0][9:12])
    if status == 200:
        return None
    if status == 407:
        return "proxy_auth_required"
    if 300 <= status < 400:
        return "proxy_redirect_refused"
    return "proxy_tunnel_refused"


def _proxy_probe(value, deadline, emit, finish):
    emit("proxy_dns")
    try:
        addresses = socket.getaddrinfo(value["proxy_host"], value["proxy_port"], type=socket.SOCK_STREAM)
    except socket.gaierror:
        return finish("unavailable", "proxy_dns", "proxy_dns_failed")
    if not 1 <= len(addresses) <= 16:
        return finish("unavailable", "proxy_dns", "proxy_address_limit")
    authority = value["host"]
    if ":" in authority:
        authority = f"[{authority}]"
    authority = f"{authority}:{value['port']}"
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii")
    if len(request) > MAX_CONNECT_REQUEST:
        return finish("refused", "tunnel", "proxy_response_invalid")
    for family, socktype, proto, _, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return finish("incomplete", "proxy_connect", "deadline")
        emit("proxy_connect")
        current_stage = "proxy_connect"
        try:
            with socket.socket(family, socktype, proto) as connection:
                connection.settimeout(min(remaining, 3))
                connection.connect(address)
                emit("tunnel")
                current_stage = "tunnel"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return finish("incomplete", "tunnel", "deadline")
                connection.settimeout(min(remaining, 3))
                connection.sendall(request)
                response = _proxy_response(connection, deadline)
                if response is not None:
                    return finish("refused", "tunnel", response)
                emit("tls")
                current_stage = "tls"
                context = ssl.create_default_context(cadata=value["ca"])
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return finish("incomplete", "tls", "deadline")
                connection.settimeout(min(remaining, 3))
                with context.wrap_socket(connection, server_hostname=value["host"]):
                    return finish("transport-observed", "tls", "proxy_tls_verified")
        except ssl.SSLCertVerificationError:
            return finish("refused", "tls", "tls_invalid")
        except (ssl.SSLError, ValueError):
            return finish("refused", "tls", "tls_failed")
        except (socket.timeout, TimeoutError):
            # The whole worker has one deadline; never try a direct route.
            return finish("incomplete", current_stage,
                          {"proxy_connect": "proxy_connect_timeout", "tunnel": "proxy_tunnel_timeout",
                           "tls": "tls_timeout"}[current_stage])
        except OSError:
            if current_stage == "proxy_connect":
                continue
            return finish("unavailable", current_stage,
                          "proxy_response_invalid" if current_stage == "tunnel" else "tls_failed")
    return finish("unavailable", "proxy_connect", "proxy_connect_failed")


def _worker():
    parent = os.getppid()
    if sys.platform.startswith("linux"):
        if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            return 2
    try:
        raw = sys.stdin.buffer.read(MAX_WORKER_INPUT + 1)
        if len(raw) > MAX_WORKER_INPUT:
            return 2
        value = json.loads(raw)
        if (type(value) is not dict or set(value) not in (
                {"host", "port", "tls", "ca", "seconds"},
                {"host", "port", "tls", "ca", "seconds", "proxy_host", "proxy_port"})
                or not _host_valid(value["host"])
                or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
                or type(value["tls"]) is not bool or type(value["seconds"]) is not int
                or not 1 <= value["seconds"] <= 15
                or value["ca"] is not None and (type(value["ca"]) is not str or len(value["ca"]) > MAX_CA)
                or "proxy_host" in value and (not _host_valid(value["proxy_host"]) or not value["tls"]
                    or type(value["proxy_port"]) is not int or not 1 <= value["proxy_port"] <= 65535)):
            return 2
        deadline = time.monotonic() + value["seconds"]
        def emit(stage):
            print(json.dumps({"stage": stage}), flush=True)
        def finish(status, stage, reason):
            print(json.dumps({"status": status, "stage": stage, "reason": reason}), flush=True)
            return 0
        if "proxy_host" in value:
            return _proxy_probe(value, deadline, emit, finish)
        emit("dns")
        try:
            addresses = socket.getaddrinfo(value["host"], value["port"], type=socket.SOCK_STREAM)
        except socket.gaierror:
            return finish("unavailable", "dns", "dns_failed")
        if not 1 <= len(addresses) <= 16:
            return finish("unavailable", "dns", "address_limit")
        emit("connect")
        timed_out = False
        timeout_stage = "connect"
        for family, socktype, proto, _, address in addresses:
            current_stage = "connect"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return finish("incomplete", "connect", "deadline")
            try:
                with socket.socket(family, socktype, proto) as connection:
                    connection.settimeout(min(remaining, 3))
                    connection.connect(address)
                    if not value["tls"]:
                        return finish("transport-observed", "connect", "tcp_connected")
                    emit("tls")
                    current_stage = "tls"
                    context = ssl.create_default_context(cadata=value["ca"])
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return finish("incomplete", "tls", "deadline")
                    connection.settimeout(min(remaining, 3))
                    with context.wrap_socket(connection, server_hostname=value["host"]):
                        return finish("transport-observed", "tls", "tls_verified")
            except ssl.SSLCertVerificationError:
                return finish("refused", "tls", "tls_invalid")
            except (ssl.SSLError, ValueError):
                return finish("refused", "tls", "tls_failed")
            except (socket.timeout, TimeoutError):
                timed_out = True
                timeout_stage = current_stage
            except OSError:
                pass
        return finish("incomplete" if timed_out else "unavailable",
                      timeout_stage if timed_out else "connect",
                      ("tls_timeout" if timeout_stage == "tls" else "connect_timeout")
                      if timed_out else "connect_failed")
    except (OSError, ValueError, TypeError, KeyError):
        return 2


if __name__ == "__main__":
    raise SystemExit(_worker() if sys.argv[1:] == ["--worker"] else 2)
