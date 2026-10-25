# SPDX-License-Identifier: Apache-2.0
"""Finite provider routing for the prepared pilot; no persisted credential carrier."""
import contextlib
import json
import os

KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")
MAX_BYTES = 16384


def selected(environment):
    values = {key: environment[key] for key in KEYS if key in environment}
    if any('\0' in value for value in values.values()):
        raise ValueError("provider_input_invalid")
    if len(json.dumps(values, ensure_ascii=True).encode()) > MAX_BYTES:
        raise ValueError("provider_input_invalid")
    return values


def require_access(values):
    if not any(values.get(key) for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")):
        raise ValueError("provider_unavailable")


@contextlib.contextmanager
def carrier(values):
    """Linux anonymous sealed memfd, passed only to the intended native launcher.

    No credential file, environment of the launcher, or secret argument. The
    receiver consumes/closes it before host exec; other subprocesses never inherit it.
    """
    import fcntl
    if not hasattr(os, "memfd_create"):
        raise ValueError("provider_input_unsupported")
    raw = json.dumps(values, ensure_ascii=True).encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("provider_input_invalid")
    descriptor = os.memfd_create("sw-provider-input", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(raw)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor
    finally:
        os.close(descriptor)


class Redactor:
    """Replace exact selected values before private logging, across pipe chunks.

    Only a bounded suffix is retained in memory. On EOF even a truncated secret
    prefix is hidden. Reports still use the existing finite failure-code boundary.
    """
    def __init__(self, values):
        patterns = set()
        for value in values.values():
            if value:
                patterns.add(value.encode())
                for ascii_only in (True, False):
                    patterns.add(json.dumps(value, ensure_ascii=ascii_only)[1:-1].encode())
        self.patterns = sorted(patterns, key=len, reverse=True)
        self.width = max(map(len, self.patterns), default=1)
        self.pending = b''

    def feed(self, raw, final=False):
        self.pending += raw
        output = bytearray()
        index = 0
        limit = len(self.pending) if final else max(0, len(self.pending) - self.width + 1)
        while index < limit:
            match = next((value for value in self.patterns if self.pending.startswith(value, index)), None)
            if match is not None:
                output.extend(b'[REDACTED]' if len(match) >= 10 else b'*' * len(match))
                index += len(match)
            elif final and any(value.startswith(self.pending[index:]) for value in self.patterns):
                length = len(self.pending) - index
                output.extend(b'[REDACTED]' if length >= 10 else b'*' * length)
                index = len(self.pending)
            else:
                output.append(self.pending[index])
                index += 1
        self.pending = self.pending[index:]
        return bytes(output)


def utility_environment(build=False):
    """Source/version probes need no provider, loader, project or proxy inputs."""
    result = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
              "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
              "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}
    if build:
        # Existing installed toolchain lookup only; never auto-install or borrow
        # provider transport. Actual compiler children already use private HOME.
        from pathlib import Path
        result.update(HOME=str(Path.home()), RUSTUP_AUTO_INSTALL="0")
        for name in ("CARGO_HOME", "RUSTUP_HOME"):
            if name in os.environ:
                result[name] = os.environ[name]
    return result
