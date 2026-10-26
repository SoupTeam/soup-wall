#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""List recorded prepared runs; --probe observes authenticated loopback state.

No daemon, host, helper or provider is started. Recorded state never proves
protection, model consumption, execution, or approval.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import socket
import threading

if sys.platform.startswith("linux"):
    import fcntl

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pilot_run_state as S

FORMAT = "sw-prepared-pilot-discovery/1"
MAX_OUTPUT = 256 * 1024


def deadline_check(deadline):
    S.require(time.monotonic() < deadline, "probe_time_limit")


def proc_read(pid, name, limit):
    S.require(type(pid) is int and 0 < pid < 2**31, "launcher_unverified")
    S.require(os.stat(f"/proc/{pid}").st_uid == os.getuid(), "foreign_process")
    with open(f"/proc/{pid}/{name}", "rb", buffering=0) as stream:
        value = stream.read(limit + 1)
    S.require(len(value) <= limit, "process_record_limit")
    return value


def process_start(pid):
    raw = proc_read(pid, "stat", 4096)
    # comm may contain spaces and parentheses; fields after the last ')' are fixed.
    fields = raw.rsplit(b")", 1)[1].split()
    S.require(fields[0] not in (b"Z", b"X"), "launcher_unavailable")
    return int(fields[19])


def sealed_launcher(raw, manifest, selected, deadline, pin=False):
    """Read the accepted launcher's sealed memfd, not PID/name liveness alone."""
    pid = manifest["launcher_pid"]
    S.require(type(manifest["launcher_start"]) is int
              and process_start(pid) == manifest["launcher_start"], "stale_launcher")
    args = proc_read(pid, "cmdline", 65536).split(b"\0")
    S.require(len(args) >= 2 and args[1] == b"pilot-launch", "launcher_unverified")
    descriptor = manifest["manifest_fd"]
    S.require(type(descriptor) is int and 3 <= descriptor <= 2**20, "launcher_unverified")
    # /proc/PID/fd deliberately references the sealed object, not a disk path.
    fd = os.open(f"/proc/{pid}/fd/{descriptor}", os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        S.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                  and info.st_size <= S.MAX_RECORD
                  and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & 15 == 15, "launcher_unverified")
        S.require(os.read(fd, S.MAX_RECORD + 1) == raw, "stale_or_edited_run")
    finally:
        os.close(fd)
    deadline_check(deadline)
    # Source/selection labels remain recorded. The running executable's hash is
    # independently compared with the selected prepared-run binary identity.
    with open(f"/proc/{pid}/exe", "rb", buffering=0) as executable:
        info = os.fstat(executable.fileno())
        S.require(stat.S_ISREG(info.st_mode) and info.st_size <= 512 * 1024 * 1024, "binary_unverified")
        digest, count = hashlib.sha256(), 0
        while True:
            deadline_check(deadline)
            block = executable.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            S.require(count <= 512 * 1024 * 1024, "binary_unverified")
            digest.update(block)
        S.require(digest.hexdigest() == selected["binary_sha256"], "binary_identity_mismatch")
        pinned = os.dup(executable.fileno()) if pin else None
    try:
        S.require(process_start(pid) == manifest["launcher_start"], "stale_launcher")
        return pinned
    except BaseException:
        if pinned is not None:
            os.close(pinned)
        raise


def diagnostic_projection(executable, config_raw, policy_raw, status, nonce, record, selected, deadline):
    """The pinned Agent validates its own accepted diagnostic contract offline.

    No token is passed to the child. Config and policy are verified held bytes,
    not mutable home paths. Only this owned diagnostic child may be terminated.
    """
    envelope = {"format": "sw-prepared-pilot-observation-input/1", "nonce": nonce,
                "daemon_pid": record["daemon_pid"], "binary_sha256": selected["binary_sha256"],
                "registry_sha256": selected["registry_sha256"], "config": config_raw.decode("utf-8"),
                "policy": policy_raw.decode("utf-8"), "snapshot": status}
    body = S.encoded(envelope)
    S.require(len(body) <= 256 * 1024, "diagnostic_input_limit")
    deadline_check(deadline)
    process = subprocess.Popen([f"/proc/self/fd/{executable}", "pilot-observation"],
        pass_fds=(executable,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    try:
        try:
            stdout, _ = process.communicate(body, timeout=min(5, max(.001, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise S.Refusal("diagnostic_validation_timeout") from None
        S.require(process.returncode == 0 and len(stdout) <= 16384, "diagnostic_validation_unavailable")
        value = S.strict(stdout)
        S.require(type(value) is dict and set(value) == {"format", "state", "reason", "mode", "policy_sha256",
                  "registry_sha256", "config_sha256", "binary_sha256", "protection", "execution_coverage", "paths"}
                  and value["format"] == "sw-prepared-pilot-observation/1"
                  and value["state"] == "authenticated_daemon_observed"
                  and value["reason"] == "current_instance_ready_not_execution"
                  and value["protection"] == value["execution_coverage"] == "unknown"
                  and value["mode"] in ("enforcing", "shadow")
                  and value["binary_sha256"] == selected["binary_sha256"]
                  and value["registry_sha256"] == selected["registry_sha256"]
                  and type(value["paths"]) is list and len(value["paths"]) == 7,
                  "diagnostic_projection_invalid")
        deadline_check(deadline)
        return value
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


def request(port, token, path, deadline, limit, nonce=None):
    deadline_check(deadline)
    # http.client does no proxy/environment routing, DNS lookup or redirects.
    connection = http.client.HTTPConnection("127.0.0.1", port,
                                            timeout=min(1.0, deadline - time.monotonic()))
    timer = None
    try:
        connection.connect()
        held_socket = connection.sock
        def expire():
            try:
                held_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(max(0, deadline - time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        headers = {"Authorization": "Bearer " + token, "Connection": "close"}
        if nonce:
            headers["x-agentfw-status-nonce"] = nonce
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        S.require(response.status == 200, "daemon_query_rejected")
        chunks, count = [], 0
        while count <= limit:
            deadline_check(deadline)
            connection.sock and connection.sock.settimeout(min(1.0, deadline - time.monotonic()))
            raw = response.read1(min(4096, limit + 1 - count))
            if not raw:
                break
            chunks.append(raw)
            count += len(raw)
        S.require(count <= limit, "daemon_response_limit")
        deadline_check(deadline)
        return S.strict(b"".join(chunks))
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def token(home, name):
    raw = home.read(name, 4096)[0]
    S.require(re.fullmatch(rb"[A-Za-z0-9_-]{16,1024}\s*", raw), "token_unavailable")
    return raw.decode("ascii").strip()


def probe(run, selected, record, deadline):
    S.require(set(record) == {"format", "home", "supervisor_pid", "launcher_pid", "daemon_pid", "port"}
              and record["format"] == "sw-prepared-pilot-run/1"
              and record["home"] == str(run.path / ".agentfw")
              and type(record["port"]) is int and 1 <= record["port"] <= 65535, "run_record_invalid")
    with run.child(".agentfw") as home:
        config_raw = home.read("config.yaml")[0]
        config = S.strict(config_raw)
        S.require(type(config) is dict and set(config) == {"bind", "port", "enforce", "policy", "native", "audit_retention"}
                  and config["bind"] == "127.0.0.1" and type(config["port"]) is int
                  and config["port"] == record["port"] and config["enforce"] is True,
                  "untrusted_endpoint")
        S.require(config["native"]["registry_sha256"] == selected["registry_sha256"]
                  and config["native"]["registry_path"] == str(home.path / "registry.json")
                  and S.sha(home.read("registry.json")[0]) == selected["registry_sha256"], "registry_identity_mismatch")
        with home.child("pilot-runs") as runs:
            names = runs.names(16)
            S.require(len(names) == 1 and re.fullmatch(r"[0-9a-f]{32}", names[0]), "ambiguous_launcher")
            with runs.child(names[0]) as native:
                S.require("stop.json" not in native.names(32), "retained_stop_state")
                raw = native.read("run.json")[0]
                manifest = S.strict(raw)
                S.require(type(manifest) is dict and manifest.get("contract") == "sw-pilot-run/1"
                          and manifest.get("run_id") == native.name and manifest.get("home") == str(home.path)
                          and manifest.get("launcher_pid") == record["launcher_pid"]
                          and manifest.get("registry_sha256") == selected["registry_sha256"]
                          and type(manifest.get("instance_id")) is str
                          and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", manifest["instance_id"])
                          and type(manifest.get("expires_at_ms")) is int
                          and manifest["expires_at_ms"] > int(time.time() * 1000), "stale_or_edited_run")
                files = manifest.get("files")
                S.require(type(files) is list and len(files) == 5
                          and files[0] == {"path": str(home.path / "config.yaml"), "sha256": S.sha(config_raw)},
                          "sealed_endpoint_selection_mismatch")
                S.require(type(config.get("policy")) is str, "selected_policy_unverified")
                policy_path = Path(config["policy"])
                with S.Directory(policy_path.parent) as policy_directory:
                    policy_raw, policy_identity = policy_directory.read(policy_path.name)
                    S.require(sum(row == {"path": str(policy_path), "sha256": S.sha(policy_raw)} for row in files) == 1
                              and S.sha(policy_raw) == selected["policy_sha256"], "selected_policy_unverified")
                    executable = sealed_launcher(raw, manifest, selected, deadline, pin=True)
                    try:
                        daemon_start = process_start(record["daemon_pid"])
                        daemon_exe = os.stat(f"/proc/{record['daemon_pid']}/exe")
                        S.require(S.same_object(daemon_exe)[:2] == S.same_object(os.fstat(executable))[:2],
                                  "foreign_daemon_process")
                        live = request(record["port"], token(home, "native-token"), "/native/v1/instance", deadline, 2 * 1024 * 1024)
                        S.require(type(live) is dict and live.get("instance_id") == manifest["instance_id"]
                                  and live.get("registry_sha256") == selected["registry_sha256"], "stale_daemon_instance")
                        nonce = secrets.token_urlsafe(24)
                        status = request(record["port"], token(home, "token"), "/diagnostics/v1/protection",
                                         deadline, 32768, nonce)
                        value = diagnostic_projection(executable, config_raw, policy_raw, status, nonce, record, selected, deadline)
                        S.require(home.read("config.yaml")[0] == config_raw and native.read("run.json")[0] == raw
                                  and policy_directory.read(policy_path.name) == (policy_raw, policy_identity)
                                  and process_start(record["daemon_pid"]) == daemon_start, "record_changed")
                        sealed_launcher(raw, manifest, selected, deadline)
                        return value
                    finally:
                        if executable is not None:
                            os.close(executable)


def inspect(parent, name, probing, deadline):
    result = {"run_id": S.run_id(name), "lifecycle": "unknown", "protection": "unknown",
              "observation": {"state": "not_probed", "reason": "explicit_probe_required"}}
    try:
        with parent.child(name) as run:
            selected = S.receipt(run)
            result["recorded"] = {key: selected[key] for key in ("source_commit", "selection_sha256", "policy_sha256",
                                  "registry_sha256", "binary_sha256")}
            result["recorded"]["trust"] = "local_owner_editable"
            names = run.names(64)
            if set(names) == {"audit", "audit-run.json", "audit-finished.json"}:
                S.completed_inventory(run)
                result.update(lifecycle="completed_audit_only", reason="recorded_completion")
                result["observation"] = {"state": "not_applicable", "reason": "no_live_authority_retained"}
            elif ".agentfw" in names:
                result.update(lifecycle="active_or_interrupted", reason="live_state_requires_probe")
                with run.child(".agentfw") as home:
                    with home.child("pilot-runs") as runs:
                        native_names = runs.names(16)
                        for native_name in native_names:
                            S.require(re.fullmatch(r"[0-9a-f]{32}", native_name), "invalid_native_run")
                            with runs.child(native_name) as native:
                                if "stop.json" in native.names(32):
                                    stop = native.json("stop.json")
                                    run_raw = native.read("run.json")[0]
                                    S.require(type(stop) is dict and set(stop) == {"contract", "run_sha256", "status", "signature"}
                                              and stop["contract"] == "sw-pilot-stop/1"
                                              and stop["run_sha256"] == S.sha(run_raw)
                                              and stop["status"] in ("requested", "revoked", "stopped")
                                              and type(stop["signature"]) is str
                                              and re.fullmatch(r"[A-Za-z0-9_-]{43}", stop["signature"]),
                                              "stop_record_invalid")
                                    result.update(lifecycle="retained_stop_state", reason="stop_authority_preserved")
                                    result["recorded_stop"] = {"status": stop["status"], "authentication": "not_checked"}
                if probing and result["lifecycle"] != "retained_stop_state":
                    before = run.read("run.json")[0]
                    result["observation"] = probe(run, selected, S.strict(before), deadline)
                    S.require(run.read("run.json")[0] == before and S.receipt(run) == selected, "record_changed")
            else:
                raise S.Refusal("incomplete_run_state")
    except S.Refusal as error:
        result.update(lifecycle="unknown", reason=str(error))
        result["observation"] = {"state": "unavailable", "reason": str(error)}
    except (OSError, ValueError, KeyError, TypeError, IndexError, OverflowError, http.client.HTTPException):
        result.update(lifecycle="unknown", reason="state_or_probe_unavailable")
        result["observation"] = {"state": "unavailable", "reason": "state_or_probe_unavailable"}
    return result


def discover(path, probing=False, scan_limit=512, candidate_limit=32, probe_seconds=10, selected_ids=None):
    S.require(type(scan_limit) is int and 1 <= scan_limit <= 4096
              and type(candidate_limit) is int and 1 <= candidate_limit <= 64
              and 1 <= probe_seconds <= 30, "invalid_limits")
    chosen = set(selected_ids or [])
    S.require(len(chosen) <= 64, "invalid_limits")
    for value in chosen:
        S.run_id("soup-wall-run-" + value)
    result = {"format": FORMAT, "complete": True, "probe_requested": probing, "runs": [],
              "excluded_entries": 0, "scanned_entries": 0, "reasons": []}
    deadline = time.monotonic() + probe_seconds
    with S.Directory(path, state_parent=True) as parent:
        with os.scandir(parent.fd) as entries:
            for entry in entries:
                if result["scanned_entries"] >= scan_limit:
                    result["complete"] = False
                    result["reasons"].append("enumeration_limit")
                    break
                result["scanned_entries"] += 1
                match = S.RUN_NAME.fullmatch(entry.name)
                if not match or chosen and match[1] not in chosen:
                    result["excluded_entries"] += 1
                    continue
                if len(result["runs"]) >= candidate_limit:
                    result["complete"] = False
                    result["reasons"].append("candidate_limit")
                    break
                row = inspect(parent, entry.name, probing, deadline)
                result["runs"].append(row)
                if row["lifecycle"] == "unknown":
                    result["complete"] = False
        parent.check()
    found = {row["run_id"] for row in result["runs"]}
    if chosen - found:
        result["complete"] = False
        result["reasons"].append("selected_run_unavailable")
    result["runs"].sort(key=lambda row: row["run_id"])
    S.require(len(S.encoded(result)) <= MAX_OUTPUT, "output_limit")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-parent", type=Path, required=True)
    parser.add_argument("--run-id", action="append")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--scan-limit", type=int, default=512)
    parser.add_argument("--candidate-limit", type=int, default=32)
    parser.add_argument("--probe-seconds", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        result = discover(args.state_parent, args.probe, args.scan_limit, args.candidate_limit,
                          args.probe_seconds, args.run_id)
        code = 0 if result["complete"] else 2
    except S.Refusal as error:
        result, code = {"format": FORMAT, "complete": False, "reason": str(error)}, 1
    except (OSError, ValueError, KeyError, TypeError):
        result, code = {"format": FORMAT, "complete": False, "reason": "state_unavailable"}, 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
