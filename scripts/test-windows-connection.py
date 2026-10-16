# SPDX-License-Identifier: Apache-2.0
"""Native Windows connection transactions and controlled Claude Code evidence."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
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

C = load(ROOT / "scripts/verify-sou60-windows-create.py", "connection_create")
R, H = C.R, C.H
D = load(ROOT / "scripts/mcp-admission-demo.py", "connection_model")
FIXTURE = ROOT / "scripts/fixtures/connection_windows_server.py"

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def require(value, message):
    if not value:
        raise RuntimeError(message)

def account():
    command = Path(os.environ["SystemRoot"]) / "System32/whoami.exe"
    user = subprocess.run([str(command), "/user", "/fo", "csv", "/nh"],
                          capture_output=True, check=True, timeout=10)
    sid = re.findall(rb"S-1-5-21-(?:[0-9]+-){3}[0-9]+", user.stdout)
    require(len(sid) == 1, "current account SID missing")
    groups = subprocess.run([str(command), "/groups", "/fo", "csv"],
                            capture_output=True, check=True, timeout=10).stdout
    return {"sid": sid[0].decode(), "administrator_group_present": b"S-1-5-32-544" in groups,
            "is_administrator": bool(__import__("ctypes").windll.shell32.IsUserAnAdmin())}

def secure(path, sid):
    suffix = "(OI)(CI)" if path.is_dir() else ""
    icacls = str(Path(os.environ["SystemRoot"]) / "System32/icacls.exe")
    result = subprocess.run([icacls, str(path), "/inheritance:r",
        "/remove:g", "*S-1-1-0", "*S-1-3-0", "*S-1-5-11", "*S-1-5-32-544",
        "*S-1-5-32-545", "*S-1-5-32-546",
        "/grant:r", "*" + sid + ":" + suffix + "F", "*S-1-5-18:" + suffix + "F"],
        capture_output=True, timeout=20)
    require(result.returncode == 0, "owned fixture ACL setup failed: " + result.stderr.decode("utf-8", errors="replace")[-1000:])

def write(path, value, sid):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    secure(path, sid)

def snapshot():
    result = {}
    for base in [ROOT / "crates", ROOT / "scripts"]:
        for path in sorted(base.rglob("*")):
            if path.suffix in {".rs", ".py", ".ps1"} and "__pycache__" not in path.parts:
                result[path.relative_to(ROOT).as_posix()] = digest(path)
    result["Cargo.lock"] = digest(ROOT / "Cargo.lock")
    return result

def private_python(root, sid):
    target = root / "python runtime"
    target.mkdir()
    secure(target, sid)
    base = Path(sys.base_prefix)
    for path in base.iterdir():
        if path.is_file() and path.suffix.lower() in {".exe", ".dll", ".zip", "._pth"}:
            shutil.copyfile(path, target / path.name)
    for name in ["Lib", "DLLs"]:
        if (base / name).is_dir():
            shutil.copytree(base / name, target / name,
                ignore=shutil.ignore_patterns("site-packages", "__pycache__", "test", "tests", "ensurepip", "idlelib", "tkinter"))
    executable = target / "python.exe"
    secure(executable, sid)
    return executable

NATIVE_TESTS = {
    "ancestor_junction_and_path_aliases_are_refused", "boundary_replacement_retains_external_inode",
    "boundary_write_retains_external_bytes_and_refuses_success", "concurrent_operations_are_refused_and_lock_releases",
    "crash_child", "failed_native_replacement_keeps_recovery_versions", "hardlink_and_nonregular_input_are_refused",
    "post_publication_edit_retains_journal_and_live_bytes", "process_interruption_recovers_only_exact_states",
    "selected_change_retains_other_entries_and_original_fields", "stale_snapshot_refuses_before_publication",
    "strict_entry_and_json_validation", "unsafe_acl_is_refused_without_repair", "writes_through_old_descriptor_survive_success",
}

def native_tests_passed(text, code):
    observed = re.findall(r"^test mcp::connection::windows::tests::([a-z_]+) \.\.\. ok$", text, re.MULTILINE)
    return code == 0 and set(observed) == NATIVE_TESTS and len(observed) == len(NATIVE_TESTS) and bool(
        re.search(r"test result: ok\. 14 passed; 0 failed; 0 ignored;", text))

def native_tests(binary, directory):
    output = subprocess.run([str(binary), "mcp::connection::windows::tests::", "--test-threads=1", "--nocapture"],
                            capture_output=True, timeout=300)
    text = (output.stdout + output.stderr).decode("utf-8", errors="replace")
    (directory / "native-tests.log").write_text(text, encoding="utf-8")
    require(native_tests_passed(text, output.returncode),
            "native Windows connection tests failed or did not execute\n" + text[-8192:])
    return {"sha256": digest(binary), "passed": int(re.search(r"test result: ok\. ([0-9]+) passed;", text)[1])}

def host_run(claude, config, workspace, profile, steps):
    model = D.ScriptedModel(steps)
    profile.mkdir()
    env = H.private_environment(profile)
    env.update(CLAUDE_CONFIG_DIR=str(profile / "claude"), ANTHROPIC_BASE_URL=model.url,
        ANTHROPIC_API_KEY="owned-local-fixture-key", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
        DISABLE_UPDATES="1", DISABLE_AUTOUPDATER="1", ENABLE_CLAUDEAI_MCP_SERVERS="false",
        CLAUDE_CODE_DISABLE_CLAUDE_MDS="1", CLAUDE_CODE_DISABLE_AUTO_MEMORY="1",
        CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL="1",
        API_TIMEOUT_MS="10000", CLAUDE_CODE_MAX_RETRIES="0",
        HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
        NO_PROXY="127.0.0.1,localhost,::1", SOUP_CONNECTION_SENTINEL="fixture-only")
    bash = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/bin/bash.exe"
    if bash.is_file():
        env["CLAUDE_CODE_GIT_BASH_PATH"] = str(bash)
    command = [str(claude), "--restricted", "-p", "Run the owned fixture steps.",
        "--tools", "", "--allowedTools", "mcp__demo__read_document,mcp__demo__create_file",
        "--strict-mcp-config", "--mcp-config", str(config), "--no-session-persistence",
        "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk",
        "--model", "claude-sonnet-4-20250514", "--system-prompt", "Execute the local fixture tool proposals."]
    try:
        output = subprocess.run(command, cwd=workspace, env=env, capture_output=True, timeout=150)
    finally:
        model.close()
    results = model.results
    raw = output.stdout.decode("utf-8", errors="replace")
    messages = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    final = [value for value in messages if value.get("type") == "result"]
    require(output.returncode == 0 and len(final) == 1 and not final[0].get("is_error"),
            "actual Claude Code run failed: " + output.stderr.decode("utf-8", errors="replace")[-2000:])
    require(len(results) == len(steps), "actual Claude Code did not complete every proposed invocation")
    return {"exit_code": output.returncode, "results": results,
            "stdout_sha256": hashlib.sha256(output.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(output.stderr).hexdigest()}

def run(options, report):
    require(os.name == "nt", "native Windows required")
    user = account()
    report["process_job"] = bool(R.ProcessJob().handle)
    report["standard_user"] = user
    if not options.diagnostic:
        require(not user["is_administrator"] and not user["administrator_group_present"],
                "a genuine standard-user account is required; --diagnostic records an incomplete local run")
    source = snapshot()
    report["source_hashes"] = source
    report["source_before"] = R.source_snapshot(ROOT)
    report["binary_sha256"] = digest(options.agentfw)
    report["native_test_binary_sha256"] = digest(options.native_test_binary)
    report["native_tests"] = native_tests(options.native_test_binary, options.out)
    sid = user["sid"]
    checks, operations = [], []
    report.update(checks=checks, operations=operations)
    def check(name, value):
        checks.append({"name": name, "passed": bool(value)})
        require(value, name)
    temporary = tempfile.TemporaryDirectory(prefix="soup-connection-")
    root = Path(temporary.name)
    report["fixture_removed"] = False
    daemon = None
    try:
        secure(root, sid)
        private = root / "owned profile"
        private.mkdir()
        secure(private, sid)
        home = private / ".agentfw"
        home.mkdir()
        secure(home, sid)
        workspace = root / ("workspace " + "\u65e5\u672c")
        workspace.mkdir()
        secure(workspace, sid)
        document = workspace / "inventory.txt"
        document.write_text("Owned useful document: seven red widgets.\n", encoding="utf-8")
        target = workspace / "created.txt"
        outside = root / "outside.txt"
        outside.write_bytes(b"outside must remain unchanged")
        agent_directory = root / "agent tools"
        agent_directory.mkdir()
        secure(agent_directory, sid)
        agent = agent_directory / "agentfw.exe"
        shutil.copyfile(options.agentfw, agent)
        secure(agent, sid)
        python = private_python(root, sid)
        script = root / "rule_baseline.py"
        shutil.copyfile(ROOT / "rule_baseline/rule_baseline.py", script)
        secure(script, sid)
        runtime = root / "runtime.json"
        write(runtime, {"workspace": str(workspace), "classifier_script": str(script),
                        "classifier_python": str(python)}, sid)
        config = root / "mcp config.json"
        ledger = workspace / "ledger \u65e5.jsonl"
        original = {"type": "stdio", "command": str(python),
            "args": ["-I", "-u", str(FIXTURE), "--ledger", str(ledger)]}
        initial = {"mcpServers": {"demo": original, "other": {"command": "untouched",
            "args": ["a b"], "env": {"TOKEN": "fixture-only-secret"}}}, "settings": {"theme": "light"}}
        write(config, initial, sid)
        server_id = "claude-" + hashlib.sha256((str(config) + "\0demo").encode()).hexdigest()[:24]
        registry = C.registry(workspace, target, digest(script))
        for tool in registry["tools"]:
            tool["resource_policy"]["profile"]["server_id"] = server_id
        registry_path = root / "registry.json"
        write(registry_path, registry, sid)
        policy = root / "policy.yaml"
        policy.write_text(C.policy_for("utf8-relative"), encoding="utf-8")
        secure(policy, sid)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        write(home / "config.yaml", {"port": port, "enforce": True, "policy": str(policy),
            "native": {"registry_path": str(registry_path), "registry_sha256": digest(registry_path)}}, sid)
        env = H.private_environment(private)
        def cli(operation, expected=0, extra=()):
            started = time.monotonic()
            output = subprocess.run([str(agent), "mcp-connection", operation,
                "--path", str(config), "--server", "demo", "--home", str(home),
                "--agent", str(agent), "--runtime", str(runtime), *extra],
                cwd=workspace, env=env, capture_output=True, timeout=35)
            stderr = output.stderr.decode("utf-8", errors="replace")
            value = json.loads(output.stdout) if output.stdout.startswith(b"{") else {}
            operations.append({"operation": operation, "exit_code": output.returncode,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3), "report": value})
            require((output.returncode == 0) == (expected == 0),
                operation + " unexpected result: " + stderr[-2000:])
            check(operation + " output redacted", b"fixture-only-secret" not in output.stdout + output.stderr)
            return value
        preview_bytes = config.read_bytes()
        check("preview has no effect", cli("preview")["status"] == "preview" and config.read_bytes() == preview_bytes)
        if options.claude:
            require(options.claude_sha256 and digest(options.claude) == options.claude_sha256,
                    "explicit Claude Code hash does not match")
            report["host"] = {"sha256": options.claude_sha256,
                "version": subprocess.run([str(options.claude), "--version"], capture_output=True,
                    timeout=25).stdout.decode("utf-8", errors="replace").strip()}
            report["host"]["control"] = host_run(options.claude, config, workspace, root / "control profile",
                [{"tool": "read_document", "args": {"path": str(document)}}])
            check("actual host control reads useful bytes", "seven red widgets" in report["host"]["control"]["results"]["toolu_demo_0"]["text"])
            ledger.unlink()
        with (root / "daemon.log").open("wb") as log:
            daemon = subprocess.Popen([str(agent), "serve"], env=env, cwd=workspace, stdout=log, stderr=log)
            require(H.healthy(port, daemon), "enforcing daemon did not become healthy")
            for token in ["token", "native-token"]:
                secure(home / token, sid)
            check("connect configures exact wrapper", cli("connect")["status"] == "configured")
            connected = json.loads(config.read_bytes())
            check("repeat connect does not wrap again", cli("connect")["status"] == "configured" and json.loads(config.read_bytes()) == connected)
            check("other entry is preserved", connected["mcpServers"]["other"] == initial["mcpServers"]["other"])
            wrapped = connected["mcpServers"]["demo"]
            with (root / "protocol.log").open("wb") as protocol_log:
                client = H.Collector([wrapped["command"], *wrapped["args"]],
                    dict(env, SOUP_CONNECTION_SENTINEL="fixture-only", ANTHROPIC_API_KEY="fixture-only"), workspace, protocol_log)
                try:
                    client.send({"jsonrpc": "2.0", "id": "initialize", "method": "initialize", "params": {
                        "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "connection-probe", "version": "1"}}})
                    client.send({"jsonrpc": "2.0", "method": "notifications/initialized"}, reply=False)
                    client.send({"jsonrpc": "2.0", "id": "listing", "method": "tools/list"})
                    request = H.frame("opaque \u65e5 007", "read_document", {"path": "inventory.txt"})
                    request["params"]["_meta"]["claudecode/toolUseId"] = "toolu_connection_read"
                    response = json.loads(client.send(request))
                    report["protocol_witness"] = {"request": request, "response": response}
                    check("opaque JSON-RPC identity and useful arguments survive", response["id"] == request["id"]
                        and "seven red widgets" in json.dumps(response["result"]) and not response["result"].get("isError"))
                finally:
                    closure = client.close()
                    report["protocol_closure"] = closure
                    protocol_log.flush()
                    report["protocol_log_sha256"] = digest(root / "protocol.log")
                    if closure["exit_code"] != 0:
                        report["protocol_diagnostics"] = (root / "protocol.log").read_text(encoding="utf-8", errors="replace")[-8192:]
                    check("protocol processes close cleanly", closure["exit_code"] == 0 and closure["reader_joined"] and not closure["forced_cleanup"])
            result = cli("inspect", extra=["--probe-tool", "read_document", "--probe-args",
                                          json.dumps({"path": "inventory.txt"})])
            check("controlled read is verified", result["status"] == "verified_for_this_probe")
            check("protected read is not forwarded", ledger.is_file() and ledger.read_bytes() == b"")
            cli("inspect", expected=1, extra=["--probe-tool", "create_file", "--probe-args",
                json.dumps({"path": str(outside), "content": "forbidden"})])
            check("outside bytes are unchanged", outside.read_bytes() == b"outside must remain unchanged")
            cli("inspect", extra=["--probe-tool", "create_file", "--probe-args",
                json.dumps({"path": "created.txt", "content": "Owned native creation.\n"})])
            check("admitted native create writes exact bytes", target.read_bytes() == b"Owned native creation.\n")
            target.unlink()
            if options.claude:
                report["host"]["protected"] = host_run(options.claude, config, workspace, root / "protected profile", [
                    {"tool": "read_document", "args": {"path": "inventory.txt"}},
                    {"tool": "create_file", "args": {"path": str(outside), "content": "forbidden"}},
                    {"tool": "create_file", "args": {"path": "created.txt", "content": "Owned host creation.\n"}}])
                results = report["host"]["protected"]["results"]
                check("actual protected host reads useful bytes", "seven red widgets" in results["toolu_demo_0"]["text"] and not results["toolu_demo_0"]["is_error"])
                check("actual host sees outside refusal", results["toolu_demo_1"]["is_error"])
                check("actual host creates exact admitted bytes", target.read_bytes() == b"Owned host creation.\n")
                check("actual host keeps outside unchanged", outside.read_bytes() == b"outside must remain unchanged")
            check("all protected calls remain outside server child", ledger.read_bytes() == b"")
            environment = json.loads(ledger.with_suffix(".environment").read_bytes())
            check("collector child receives no application secrets", not environment["provider_key_present"] and not environment["sentinel_present"])
            value = json.loads(config.read_bytes())
            value["settings"]["theme"] = "later"
            write(config, value, sid)
            cli("disconnect")
            cli("disconnect")
            restored = json.loads(config.read_bytes())
            check("disconnect restores exact entry and later settings", restored["mcpServers"]["demo"] == original and restored["settings"]["theme"] == "later")
            cli("connect")
            edited = json.loads(config.read_bytes())
            edited["mcpServers"]["demo"]["args"].append("operator-edit")
            write(config, edited, sid)
            conflict = config.read_bytes()
            cli("disconnect", expected=1)
            check("selected edit survives conflict", config.read_bytes() == conflict)
            write(config, connected | {"settings": {"theme": "later"}}, sid)
            H.stop_owned(daemon)
            daemon = None
            cli("inspect", expected=1, extra=["--probe-tool", "read_document", "--probe-args",
                                          json.dumps({"path": "inventory.txt"})])
            check("daemon loss has no new file effects", outside.read_bytes() == b"outside must remain unchanged" and ledger.read_bytes() == b"")
            cli("disconnect")
        check("source unchanged", source == snapshot())
        check("selected binary unchanged", digest(options.agentfw) == report["binary_sha256"])
        if options.claude:
            check("selected host binary unchanged", digest(options.claude) == report["host"]["sha256"])
        report["source_binary_stable"] = True
    finally:
        if daemon is not None:
            H.stop_owned(daemon)
        temporary.cleanup()
        report["fixture_removed"] = not root.exists()
    expected = 35 if options.claude else 29
    report["summary"] = {"expected": expected, "observed": len(checks), "failed": sum(not c["passed"] for c in checks), "skips": 0}
    require(len(checks) == expected, "acceptance did not execute every required control")
    report["transactions_passed"] = not options.diagnostic and report["fixture_removed"] and all(row["passed"] for row in checks)
    report["acceptance_passed"] = report["transactions_passed"] and bool(options.claude)
    report["status"] = "pass" if report["acceptance_passed"] else "incomplete"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--native-test-binary", type=Path, required=True)
    parser.add_argument("--claude", type=Path)
    parser.add_argument("--claude-sha256")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--transactions-only", action="store_true")
    args = parser.parse_args()
    args.agentfw = args.agentfw.resolve()
    args.native_test_binary = args.native_test_binary.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": "sou66-windows-connection/1", "status": "incomplete",
              "acceptance_passed": False, "observed_at": datetime.now(timezone.utc).isoformat(),
              "os": platform.platform(), "diagnostic": args.diagnostic}
    try:
        run(args, report)
    except Exception as error:
        report["error"] = str(error)
        report["status"] = "fail"
    (args.out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({key: report.get(key) for key in ["status", "acceptance_passed", "summary", "error"]}))
    if args.transactions_only and report.get("transactions_passed"):
        return 0
    return 0 if report["status"] == "pass" else 2 if report["status"] == "incomplete" else 1

if __name__ == "__main__":
    raise SystemExit(main())
