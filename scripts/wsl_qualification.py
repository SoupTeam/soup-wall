# SPDX-License-Identifier: Apache-2.0
"""Additional opt-in WSL witnesses; no host settings or foreign processes adopted."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import subprocess


def host_settings():
    """Retain only presence and digests of fixed runtime-relevant settings."""
    result = {}
    for name in ("/etc/wsl.conf", "/proc/sys/kernel/unprivileged_userns_clone",
                 "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
                 "/proc/sys/user/max_user_namespaces"):
        try:
            result[name] = hashlib.sha256(Path(name).read_bytes()).hexdigest()
        except FileNotFoundError:
            result[name] = "absent"
    return result


def foreign_port(binary, python, env, private, port):
    """Prove bind refusal and survival of an independent, calibrated listener."""
    marker = b"owned-wsl-port-witness\n"
    owner = candidate = None
    owner_code = (
        "import socket,sys\n"
        "s=socket.socket(fileno=int(sys.argv[1]))\n"
        "while True:\n"
        " c,_=s.accept()\n"
        " c.sendall(b'owned-wsl-port-witness\\n'); c.close()\n"
    )
    result = {}
    try:
        with socket.socket() as reservation:
            reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            reservation.bind(("127.0.0.1", port))
            reservation.listen(4)
            owner = subprocess.Popen([str(python), "-I", "-c", owner_code, str(reservation.fileno())],
                pass_fds=(reservation.fileno(),), env=env, cwd=private,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def observe():
            if owner.poll() is not None:
                raise ValueError("foreign_port_owner_died")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                with connection.makefile("rb") as stream:
                    if stream.readline(64) != marker:
                        raise ValueError("foreign_port_witness_changed")

        observe()
        log = Path(private) / "foreign-port-startup.log"
        with log.open("xb") as output:
            candidate = subprocess.Popen([str(binary), "serve"], env=env, cwd=private,
                stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            code = candidate.wait(timeout=15)
        if code == 0:
            raise ValueError("foreign_port_candidate_accepted")
        # A generic setup error cannot substitute for the native bind refusal.
        if log.stat().st_size > 65536:
            raise ValueError("foreign_port_diagnostic_bound")
        raw = log.read_bytes()
        if b"Address already in use" not in raw or b"os error 98" not in raw:
            raise ValueError("foreign_port_wrong_refusal")
        observe()
        result = {"status": "passed", "candidate_exit": code, "bind_refusal": True,
                  "independent_listener_calibrated": True, "foreign_process_survived": True,
                  "diagnostic_sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        for process in (candidate, owner):
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    result["owned_fixture_removed"] = True
    return result
