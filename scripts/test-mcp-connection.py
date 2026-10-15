#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable Linux connection tests and installed-client acceptance."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DEMO = load(ROOT / "scripts/mcp-admission-demo.py", "connection_demo")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_snapshot():
    paths = [ROOT / "Cargo.lock", ROOT / "Cargo.toml", ROOT / "rust-toolchain.toml",
             *sorted((ROOT / "crates").rglob("*.rs")), *sorted((ROOT / "crates").rglob("Cargo.toml")),
             Path(__file__), ROOT / "scripts/fixtures/connection_server.py",
             ROOT / "scripts/fixtures/connection_publication.c",
             ROOT / "scripts/mcp-admission-demo.py", ROOT / "scripts/windows-claude-host-acceptance.py",
             ROOT / "scripts/fixtures/mcp_admission_demo_server.py"]
    return {str(path.relative_to(ROOT)): sha(path) for path in paths}


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def inside(options):
    out = options.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    checks = []
    operations = []

    def check(name, condition):
        checks.append({"check": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError(name)

    with tempfile.TemporaryDirectory(prefix="sou50-connection-") as temporary:
        root = Path(temporary)
        binary = root / "agentfw"
        shutil.copyfile(options.agentfw, binary)
        binary.chmod(0o755)
        with DEMO.agent_stack(binary, root / "stack") as stack:
            home = stack.workspace / ".agentfw"
            for path in [home / "config.yaml", home / "token", home / "native-token"]:
                path.chmod(0o600)
            config = stack.workspace / "mcp config.json"
            env_ledger = stack.workspace / "environment.jsonl"
            original = {"type": "stdio", "command": str(Path(sys.executable).resolve()),
                        "args": ["-I", str(ROOT / "scripts/fixtures/connection_server.py"), str(env_ledger),
                                 "--notes", str(stack.notes), "--ledger", str(stack.ledger),
                                 "--recipient", stack.receiver.url]}
            initial = {"mcpServers": {"demo": original, "other": {"command": "untouched", "args": ["a b"],
                                                                 "env": {"TOKEN": "unrelated-fixture-secret"}}},
                       "settings": {"theme": "light"}}
            write(config, initial)
            with (stack.workspace / "control.log").open("wb") as log:
                control = DEMO.Harness([original["command"], *original["args"]], {"PATH": "/usr/bin:/bin"}, log)
                try:
                    _, response = control.call(1, "read_document", {"name": "inventory"})
                    check("unwrapped_read_control", response is not None and b"Inventory: 7 red widgets." in response)
                    _, response = control.call(2, "send_http", {"url": stack.receiver.url, "body": "owned receiver control"})
                    check("receiver_positive_control", response is not None and stack.receiver.bodies == ["owned receiver control"])
                finally:
                    control.close()
            stack.receiver.bodies.clear()
            stack.ledger.write_text("")
            stack.responses.write_text("")
            env_ledger.write_text("")

            def arguments(operation, extra=(), path=config):
                return [str(binary), "mcp-connection", operation, "--path", str(path),
                             "--server", "demo", "--agent", str(binary), "--home", str(home), *extra]

            def command(operation, extra=(), expected=0, path=config):
                env = dict(stack.env, ANTHROPIC_API_KEY="must-not-reach-child", GITHUB_TOKEN="must-not-reach-child")
                started = time.monotonic()
                result = subprocess.run(arguments(operation, extra, path), capture_output=True, text=True, env=env, timeout=20)
                check(f"{operation}_exit_{len(checks)}", (result.returncode == 0) == (expected == 0))
                check(f"{operation}_redacted_{len(checks)}",
                      all(s not in result.stdout + result.stderr for s in ["unrelated-fixture-secret", "must-not-reach-child"]))
                response = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {}
                operations.append({"operation": operation, "exit_code": result.returncode,
                                   "elapsed_ms": round((time.monotonic() - started) * 1000, 2), "report": response})
                return response

            def race(operation, change):
                snapshot = sha(config)
                started = time.monotonic()
                process = subprocess.Popen(arguments(operation), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, env=stack.env)
                paused = False
                try:
                    deadline = time.monotonic() + 8
                    while process.poll() is None and time.monotonic() < deadline:
                        for fd in Path(f"/proc/{process.pid}/fd").glob("*"):
                            try:
                                if os.readlink(fd) == str(binary):
                                    os.kill(process.pid, signal.SIGSTOP)
                                    paused = True
                                    break
                            except FileNotFoundError:
                                pass
                        if paused:
                            break
                        time.sleep(0.001)
                    check(f"{operation}_preflight_paused_{len(checks)}", paused)
                    change()
                    os.kill(process.pid, signal.SIGCONT)
                    paused = False
                    stdout, stderr = process.communicate(timeout=25)
                    check(f"{operation}_concurrent_change_refused_{len(checks)}", process.returncode != 0)
                    response = json.loads(stdout) if stdout.strip().startswith("{") else {}
                    check(f"{operation}_no_stale_success_{len(checks)}", response.get("status") not in {"configured", "verified_for_this_probe"})
                    if operation == "inspect":
                        check(f"inspect_snapshot_digest_{len(checks)}", response.get("status") == "unknown" and response.get("config_sha256") == snapshot and response.get("probe_result_sha256") is None)
                    check(f"{operation}_race_redacted_{len(checks)}", "unrelated-fixture-secret" not in stdout + stderr)
                    operations.append({"operation": operation, "scenario": "concurrent_change", "exit_code": process.returncode,
                                       "elapsed_ms": round((time.monotonic() - started) * 1000, 2), "report": response})
                finally:
                    if paused:
                        os.kill(process.pid, signal.SIGCONT)
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=10)

            library = root / "publication.so"
            subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                            str(ROOT / "scripts/fixtures/connection_publication.c"), "-ldl", "-o", str(library)],
                           check=True, capture_output=True, timeout=30)

            def publication_races():
                for operation in ["connect", "disconnect"]:
                    for mode in ["write-before", "replace-before", "held-write-after", "write-after",
                                 "crash-before", "crash-after"]:
                        case = root / (operation + "-" + mode)
                        case.mkdir(mode=0o700)
                        selected = case / "mcp.json"
                        write(selected, initial)
                        if operation == "disconnect":
                            command("connect", path=selected)
                        before = selected.read_bytes()
                        external = json.loads(before)
                        external["settings"]["theme"] = "external-" + mode
                        external["mcpServers"]["other"]["args"].append("external-argument")
                        payload = case / "external.json"
                        write(payload, external)
                        env = dict(stack.env, LD_PRELOAD=str(library), SW_PUBLICATION_MODE=mode,
                                   SW_PUBLICATION_EDIT=str(payload))
                        result = subprocess.run(arguments(operation, path=selected), env=env,
                                                capture_output=True, text=True, timeout=30)
                        label = operation + "_" + mode
                        check(label + "_nonzero", result.returncode != 0)
                        check(label + "_redacted", "unrelated-fixture-secret" not in result.stdout + result.stderr)
                        journals = list(case.glob(".soup-wall-publication-*.json"))
                        check(label + "_journal_retained", len(journals) == 1)
                        record = json.loads(journals[0].read_text())
                        archive = case / record["archive"]
                        check(label + "_snapshot_retained", (archive / "snapshot.json").read_bytes() == before)
                        proposed = (archive / "proposed.json").read_bytes()
                        displaced = (archive / "exchanged.json").read_bytes()
                        check(label + "_archive_private", archive.stat().st_mode & 0o077 == 0
                              and all(p.stat().st_mode & 0o077 == 0 for p in archive.iterdir()))
                        if mode.startswith("crash-"):
                            check(label + "_exact_crash", result.returncode == (86 if mode == "crash-before" else 87))
                            check(label + "_live_version", selected.read_bytes() == (before if mode == "crash-before" else proposed))
                            command("inspect", expected=1, path=selected)
                            command(operation, path=selected)
                            check(label + "_recovered", not journals[0].exists() and selected.read_bytes() == proposed)
                        else:
                            check(label + "_external_version_retained", payload.read_bytes() in [displaced, selected.read_bytes()])
                            check(label + "_conflict_reported", "publication conflict" in result.stderr)
                            live = selected.read_bytes()
                            command(operation, expected=1, path=selected)
                            check(label + "_retry_preserves_all_versions", selected.read_bytes() == live
                                  and (archive / "snapshot.json").read_bytes() == before
                                  and (archive / "proposed.json").read_bytes() == proposed
                                  and (archive / "exchanged.json").read_bytes() == displaced
                                  and journals[0].exists())
                            write(selected, external)
                            journals[0].unlink()
                            command(operation, path=selected)
                            reconciled = json.loads(selected.read_text())
                            check(label + "_reconciled_settings", reconciled["settings"] == external["settings"]
                                  and reconciled["mcpServers"]["other"] == external["mcpServers"]["other"])
                        check(label + "_versions_still_retained", archive.is_dir())

            publication_races()

            before = config.read_bytes()
            command("preview")
            check("preview_no_change", config.read_bytes() == before and not list(config.parent.glob(".soup-wall-*")))
            command("connect")
            connected = json.loads(config.read_text())
            command("connect")
            check("connect_idempotent", json.loads(config.read_text()) == connected)
            check("unrelated_preserved", connected["settings"] == initial["settings"] and connected["mcpServers"]["other"] == initial["mcpServers"]["other"])
            check("native_wrapper", "--native-admission" in connected["mcpServers"]["demo"]["args"])
            check("original_server_argv_preserved", connected["mcpServers"]["demo"]["args"][10:] == [original["command"], *original["args"]])
            inspected = command("inspect")
            check("configured_is_not_verified", inspected["status"] == "configured")
            state_path = next(config.parent.glob(".soup-wall-*.json"))
            state_before = state_path.read_bytes()
            race("connect", lambda: write(config, initial))
            check("repeated_connect_preserves_concurrent_edit", json.loads(config.read_text()) == initial)
            check("repeated_connect_preserves_ownership", state_path.read_bytes() == state_before)
            write(config, connected)
            race("inspect", lambda: command("disconnect"))
            check("inspect_disconnect_not_mixed", json.loads(config.read_text()) == initial)
            command("connect")
            state = json.loads(state_path.read_text())
            race("inspect", lambda: write(state_path, dict(state, phase="pending_disconnect")))
            write(state_path, state)
            limit_config = config.parent / "argument limit.json"
            limited = {"mcpServers": {"demo": {"command": str(Path("/usr/bin/env").resolve()), "args": ["x"] * 246}}}
            write(limit_config, limited)
            limit_before = limit_config.read_bytes()
            states_before = sorted(config.parent.glob(".soup-wall-*.json"))
            command("preview", expected=1, path=limit_config)
            command("connect", expected=1, path=limit_config)
            check("argument_overflow_no_mutation", limit_config.read_bytes() == limit_before and sorted(config.parent.glob(".soup-wall-*.json")) == states_before)
            limited["mcpServers"]["demo"]["args"].pop()
            write(limit_config, limited)
            command("preview", path=limit_config)
            command("connect", path=limit_config)
            check("wrapped_argument_boundary_accepted", len(json.loads(limit_config.read_text())["mcpServers"]["demo"]["args"]) == 256)
            command("inspect", path=limit_config)
            command("disconnect", path=limit_config)
            check("argument_boundary_restored", json.loads(limit_config.read_text()) == limited)
            limit_config.unlink()
            result = command("inspect", ["--probe-tool", "read_document", "--probe-args", '{"name":"inventory"}'])
            check("controlled_probe_verified", result["status"] == "verified_for_this_probe" and len(result["probe_result_sha256"]) == 64)
            check("probe_effect_once", len(DEMO.lines(stack.ledger)) == 1)
            check("probe_result_useful", "Inventory: 7 red widgets." in stack.responses.read_text())
            command("disconnect")
            command("disconnect")
            check("disconnect_exact_entry", json.loads(config.read_text()) == initial)
            command("connect")
            edited = json.loads(config.read_text())
            edited["mcpServers"]["demo"]["args"].append("user edit")
            write(config, edited)
            command("disconnect", expected=1)
            check("user_conflict_preserved", json.loads(config.read_text()) == edited)
            write(config, connected)
            state = json.loads(state_path.read_text())
            state["phase"] = "pending_connect"
            write(state_path, state)
            result = command("inspect", expected=1)
            check("partial_connect_unknown", result["status"] == "unknown")
            command("connect")
            check("partial_connect_recovered", json.loads(state_path.read_text())["phase"] == "connected")
            state = json.loads(state_path.read_text())
            state["phase"] = "pending_disconnect"
            write(state_path, state)
            check("partial_disconnect_unknown", command("inspect", expected=1)["status"] == "unknown")
            command("disconnect")
            command("connect")
            check("partial_disconnect_recovered", json.loads(state_path.read_text())["phase"] == "connected")
            write(config, dict(initial, settings={"theme": "dark"}))
            command("connect")
            command("disconnect")
            check("later_unrelated_edit_preserved", json.loads(config.read_text())["settings"] == {"theme": "dark"})
            command("connect")
            write(config, {"mcpServers": {"demo": {"command": str(binary), "args": [1]}}})
            command("preview", expected=1)
            config.write_text('{"mcpServers":{},"mcpServers":{}}')
            command("preview", expected=1)
            write(config, connected)

            stack.ledger.write_text("")
            if stack.responses.exists():
                stack.responses.write_text("")
            env_ledger.write_text("")
            write(out / "ready.json", {"config": str(config), "agent": str(binary), "home": str(home),
                                       "daemon_pid": stack.daemon.pid, "receiver_url": stack.receiver.url,
                                       "binary_sha256": sha(binary), "registry_sha256": stack.registry_sha256,
                                       "config_sha256": sha(config)})
            deadline = time.monotonic() + 600
            while not (out / "finish.json").exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("installed-client evidence was not supplied")
                time.sleep(0.1)
            actual = json.loads((out / "finish.json").read_text())
            check("actual_client_passed", actual["passed"])
            executions = [json.loads(line) for line in DEMO.lines(stack.ledger)]
            check("only_expected_reads_executed", len(executions) == 2 and all(row["params"]["name"] == "read_document" for row in executions))
            check("no_receiver_effect", not stack.receiver.bodies)
            environments = [json.loads(line) for line in DEMO.lines(env_ledger)]
            check("child_environment_cleared", environments and all(set(row["environment_keys"]) <= {"HOME", "USERPROFILE", "PATH", "LC_CTYPE"} for row in environments))
            check("unavailable_after_daemon_loss", command("inspect", expected=1)["status"] == "unavailable")
            command("disconnect")
            command("disconnect")
            check("disconnect_works_offline", json.loads(config.read_text())["mcpServers"]["demo"] == original)
            report = {"recorded_at": datetime.now(timezone.utc).isoformat(), "checks": checks, "passed": all(c["passed"] for c in checks),
                      "operations": operations, "runtime": {"system": os.uname().sysname, "release": os.uname().release,
                                                           "machine": os.uname().machine, "python": sys.version.split()[0]},
                      "binary_sha256": sha(binary), "registry_sha256": stack.registry_sha256,
                      "actual_client": actual, "executions": executions, "receiver_count": len(stack.receiver.bodies),
                      "child_environments": environments}
        report["daemon_stopped"] = stack.daemon.poll() is not None
    report["private_profile_removed"] = not root.exists()
    write(out / "report.json", report)


def relay(options):
    entry = json.loads(options.config.read_text())["mcpServers"][options.server]
    os.execve(entry["command"], [entry["command"], *entry.get("args", [])], {})


def bridge(options):
    arguments = [options.docker, "--host", options.engine, "exec", "-i", options.container, "python3",
                 "/workspace/scripts/test-mcp-connection.py", "--relay", "--config",
                 options.config, "--server", "demo"]
    raise SystemExit(subprocess.call(arguments))


def actual(options, container, out, ready):
    model_steps = [
        {"tool": "read_document", "args": {"name": "inventory"}},
        {"tool": "send_http", "args": {"url": ready["receiver_url"], "body": f"key={DEMO.SECRET}"}},
    ]
    host = load(ROOT / "scripts/windows-claude-host-acceptance.py", "connection_host")
    model = DEMO.ScriptedModel(model_steps)
    records = []
    with tempfile.TemporaryDirectory(prefix="sou50-claude-") as temporary:
        profile = Path(temporary)
        project = profile / "project"
        project.mkdir()
        config = project / "mcp.json"
        if os.name == "nt":
            entry = {"command": sys.executable,
                     "args": [str(Path(__file__).resolve()), "--bridge", "--docker", shutil.which("docker"),
                              "--engine", subprocess.check_output([shutil.which("docker"), "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], text=True).strip(),
                              "--container", container, "--config", ready["config"]]}
            environment = host.environment(profile, type("Proxy", (), {"url": "http://127.0.0.1:9"})(),
                                           Path("C:/Program Files/Git/bin/bash.exe"))
        else:
            entry = {"command": shutil.which("docker"), "args": ["exec", "-i", container, "python3",
                     "/workspace/scripts/test-mcp-connection.py", "--relay", "--config", ready["config"], "--server", "demo"]}
            environment = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG"}}
            environment.update(HOME=str(profile), USERPROFILE=str(profile), CLAUDE_CONFIG_DIR=str(profile / ".claude"),
                               ANTHROPIC_API_KEY=host.API_KEY, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                               DISABLE_UPDATES="1", HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
                               NO_PROXY="localhost,127.0.0.1")
        write(config, {"mcpServers": {"demo": entry}})
        environment["ANTHROPIC_BASE_URL"] = model.url
        environment["CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL"] = "1"
        with (out / "bridge-stderr.log").open("wb") as stderr:
            diagnostic = DEMO.Harness([entry["command"], *entry["args"]], environment, stderr)
            try:
                reply = diagnostic.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                                   "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                                              "clientInfo": {"name": "connection-diagnostic", "version": "1"}}}))
                if reply is None:
                    raise RuntimeError("Docker stdio bridge did not initialize; see bridge-stderr.log")
            finally:
                diagnostic.close()

        def invoke(name):
            command = [str(options.claude), "--restricted", "-p", "Run the local fixture maintenance steps.",
                       "--tools", "", "--allowedTools", "mcp__demo__read_document,mcp__demo__send_http",
                       "--strict-mcp-config", "--mcp-config", str(config), "--no-session-persistence",
                       "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk",
                       "--model", "claude-sonnet-4-20250514"]
            started = time.monotonic()
            result = subprocess.run(command, cwd=project, env=environment, capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=100)
            messages = []
            for line in result.stdout.splitlines():
                try:
                    messages.append(json.loads(line))
                except ValueError:
                    pass
            final = [m for m in messages if m.get("type") == "result"]
            write(out / f"{name}-host.json", {"messages": messages, "stderr": result.stderr})
            record = {"scenario": name, "exit_code": result.returncode, "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                      "completed": result.returncode == 0 and len(final) == 1 and not final[0].get("is_error"),
                      "tool_results": model.results.copy(), "output_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                      "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()}
            records.append(record)
            write(out / f"{name}.json", record)
            if not record["completed"]:
                raise RuntimeError(f"{name}: installed client did not complete: {result.stderr[-1000:]} {result.stdout[-1000:]}")

        try:
            invoke("useful_and_forbidden")
            first = model.results
            if not (not first.get("toolu_demo_0", {}).get("is_error", True)
                    and "Inventory: 7 red widgets." in first.get("toolu_demo_0", {}).get("text", "")
                    and first.get("toolu_demo_1", {}).get("is_error")):
                raise RuntimeError("installed client did not observe useful read and refused send")
            model.results = {}
            model.steps = [{"tool": "read_document", "args": {"name": "inventory"}},
                           {"tool": "read_document", "args": {"name": "inventory"}}]
            ordinary_next = model.next
            stopped = False

            def outage_next(body):
                nonlocal stopped
                content = ordinary_next(body)
                if model.results.get("toolu_demo_0") and not stopped:
                    subprocess.run([shutil.which("docker"), "exec", container, "kill", str(ready["daemon_pid"])],
                                   check=True, capture_output=True, timeout=10)
                    stopped = True
                return content

            model.next = outage_next
            invoke("daemon_loss")
            if not (stopped and not model.results.get("toolu_demo_0", {}).get("is_error", True)
                    and model.results.get("toolu_demo_1", {}).get("is_error")):
                raise RuntimeError("daemon loss did not refuse the subsequent protected request")
        finally:
            model.close()
    return {"passed": True, "host": str(options.claude), "host_sha256": sha(options.claude),
            "version": subprocess.check_output([str(options.claude), "--version"], text=True, timeout=10).strip(),
            "transport": "installed host to owned Linux collector through Docker stdio bridge",
            "records": records, "private_host_profile_removed": not profile.exists()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--claude", type=Path)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--relay", action="store_true")
    parser.add_argument("--bridge", action="store_true")
    parser.add_argument("--docker")
    parser.add_argument("--container")
    parser.add_argument("--engine")
    parser.add_argument("--config")
    parser.add_argument("--server", default="demo")
    options = parser.parse_args()
    if options.relay:
        options.config = Path(options.config)
        return relay(options)
    if options.bridge:
        return bridge(options)
    if options.inside:
        return inside(options)
    if not options.claude or not options.claude.is_file() or not options.agentfw or not options.agentfw.is_file():
        parser.error("--claude and --agentfw must identify existing executables")
    if not options.out or options.out.exists():
        parser.error("--out must be a new directory")
    out = options.out.resolve()
    out.mkdir(parents=True)
    source_before = source_snapshot()
    binary_before = sha(options.agentfw)
    container = "sou50-acceptance-" + os.urandom(6).hex()
    docker = shutil.which("docker")
    command = [docker, "run", "--rm", "--name", container, "--network", "none", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "-v", f"{ROOT}:/workspace:ro", "-v", f"{out}:/evidence",
               "-v", f"{options.agentfw.resolve()}:/selected-agentfw:ro", "-w", "/workspace",
               "rust:1.99-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6", "python3", "scripts/test-mcp-connection.py", "--inside",
               "--agentfw", "/selected-agentfw", "--out", "/evidence"]
    with (out / "driver.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 300
            while not (out / "ready.json").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Linux preparation failed; see driver.log")
                time.sleep(0.2)
            ready = json.loads((out / "ready.json").read_text())
            result = actual(options, container, out, ready)
            write(out / "finish.json", result)
            code = process.wait(timeout=40)
            if code != 0:
                raise RuntimeError("Linux acceptance failed; see driver.log")
        finally:
            subprocess.run([docker, "rm", "-f", container], capture_output=True, timeout=15)
            process.wait(timeout=15)
    report = json.loads((out / "report.json").read_text())
    source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    report["source_commit"] = source
    report["source_files"] = source_before
    report["source_unchanged"] = source_before == source_snapshot()
    report["selected_binary_unchanged"] = binary_before == sha(options.agentfw) == report["binary_sha256"]
    report["source_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True).strip())
    report["runtime_image"] = "rust:1.99-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6"
    report["container_removed"] = container not in subprocess.check_output([docker, "ps", "-a", "--format", "{{.Names}}"], text=True).splitlines()
    report["passed"] = all([report["passed"], report["source_unchanged"], report["selected_binary_unchanged"],
                            report["container_removed"], report["daemon_stopped"], report["private_profile_removed"]])
    write(out / "report.json", report)
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]), "report": str(out / "report.json")}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
