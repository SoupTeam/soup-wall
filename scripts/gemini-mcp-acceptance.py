#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gemini CLI 0.68.0 with native stdio admission and an owned loopback provider."""
from __future__ import annotations
import argparse
import hashlib
import http.server
import importlib.util
import json
import secrets
import shlex
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/mcp-admission-demo.py")
DEMO = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DEMO)


def identities(gemini):
    runtime = gemini.parents[3]
    files = {str(path.relative_to(runtime)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(runtime.rglob("*")) if path.is_file() and not path.is_symlink()}
    sources = [ROOT / "Cargo.lock", *sorted((ROOT / "crates/agentfw").rglob("*.rs")),
               *sorted((ROOT / "scripts").glob("gemini-*.py"))]
    return {"source_files_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
            "runtime_tree_sha256": hashlib.sha256(DEMO.canonical(files)).hexdigest(), "runtime_file_count": len(files)}


class Provider:
    def __init__(self, steps, before=None):
        self.requests, self.steps = [], steps
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(request)
                index = len(outer.requests) - 1
                if index < len(steps):
                    if before:
                        before(index)
                    name, args = steps[index]
                    parts = [{"functionCall": {"name": name, "args": args}}]
                else:
                    parts = [{"text": "Owned fixture finished."}]
                response = {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP", "index": 0}],
                            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
                            "modelVersion": "gemini-2.5-flash", "responseId": f"owned-{index}"}
                streaming = "streamGenerateContent" in self.path
                body = ("data: " + json.dumps(response) + "\n\n" if streaming else json.dumps(response)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream" if streaming else "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--gemini", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--hooks", action="store_true", help="also bind native MCP and Gemini callbacks to one authenticated session")
    args = parser.parse_args()
    binary, node, gemini = args.agentfw.resolve(), args.node.resolve(), args.gemini.resolve()
    checks, completed = [], False
    report = {"source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "gemini_version": subprocess.check_output([str(node), str(gemini), "--version"], text=True).strip(),
              "agentfw_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "gemini_entry_sha256": hashlib.sha256(gemini.read_bytes()).hexdigest(),
              "node_sha256": hashlib.sha256(node.read_bytes()).hexdigest(),
              "external_provider_requests": 0, "checks": checks,
              "coverage": {"selected_stdio_mcp": "tested_below", "builtin_tools": "not_enforced", "hooks": "not_installed"}}
    report.update(identities(gemini))

    def check(name, condition):
        checks.append({"check": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        check("pinned_host_version", report["gemini_version"] == "0.68.0")
        with tempfile.TemporaryDirectory(prefix="soup-gemini-", dir=ROOT / "target") as tmp:
            root = Path(tmp)
            installed = root / "agentfw"
            shutil.copyfile(binary, installed)
            installed.chmod(0o755)
            with DEMO.agent_stack(installed, root / "stack") as stack:
                home = stack.workspace / ".agentfw"
                for name in ["config.yaml", "token", "native-token"]:
                    (home / name).chmod(0o600)
                host_home = root / "host-home"
                (host_home / ".gemini").mkdir(parents=True, mode=0o700)
                config = host_home / ".gemini/settings.json"
                entry = {"command": str(Path("/usr/bin/python3").resolve()),
                         "args": ["-I", str(DEMO.FIXTURE), "--notes", str(stack.notes), "--ledger", str(stack.ledger),
                                  "--recipient", stack.receiver.url]}
                prefix = '{ /* owned */ "mcpServers": { "demo": '
                suffix = ', "other": {"command":"untouched", "env":{"TOKEN":"synthetic-secret"},},}, "theme":"light",}\n'
                original = prefix + json.dumps(entry) + suffix
                config.write_text(original)
                config.chmod(0o600)

                def connection(operation, extra=(), success=True):
                    result = subprocess.run([str(installed), "mcp-connection", operation, "--host", "gemini", "--path", str(config),
                                             "--server", "demo", "--home", str(home), "--agent", str(installed), *extra],
                                            capture_output=True, text=True, timeout=30)
                    check(f"{operation}_exit_{len(checks)}", (result.returncode == 0) == success)
                    check(f"{operation}_redacted_{len(checks)}", "synthetic-secret" not in result.stdout + result.stderr)
                    return json.loads(result.stdout) if result.stdout.startswith("{") else {}

                connection("preview")
                check("preview_no_write", config.read_text() == original)
                check("connect_configured", connection("connect")["status"] == "configured")
                connected = config.read_bytes()
                connection("connect")
                check("reconnect_idempotent", config.read_bytes() == connected)
                check("unrelated_bytes_preserved", config.read_text().startswith(prefix) and config.read_text().endswith(suffix))
                probe = connection("inspect", ["--probe-tool", "read_document", "--probe-args", '{"name":"inventory"}'])
                check("probe_verified", probe["status"] == "verified_for_this_probe" and probe["host"] == "gemini")
                connection("disconnect")
                restored = config.read_text()
                check("disconnect_restores_selected_entry", json.loads(restored[len(prefix):restored.index(', "other":')]) == entry)
                connection("connect")
                config.write_text(config.read_text().replace('"light"', '"external edit"'))
                connection("disconnect")
                check("unrelated_edit_survives", '"external edit"' in config.read_text())
                connection("connect")
                connected = config.read_bytes()
                config.write_text(config.read_text().replace("PATH=/usr/bin:/bin", "PATH=/changed"))
                conflict = config.read_bytes()
                connection("disconnect", success=False)
                check("selected_conflict_preserved", config.read_bytes() == conflict)
                config.write_bytes(connected)

                # Extract only the owned selected entry after the lifecycle tests. Host-only
                # authentication/approval settings belong to this disposable acceptance fixture.
                text = config.read_text()
                selected = json.loads(text[len(prefix):text.index(', "other":')])
                settings = {"mcpServers": {"demo": selected}, "security": {"auth": {"selectedType": "gemini-api-key"},
                            "folderTrust": {"enabled": False}}, "telemetry": {"enabled": False}, "general": {"disableAutoUpdate": True}}
                if args.hooks:
                    daemon_config = json.loads((home / "config.yaml").read_text())
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    request = urllib.request.Request(f'http://127.0.0.1:{daemon_config["port"]}/native/v1/instance',
                        headers={"Authorization": "Bearer " + (home / "native-token").read_text().strip()})
                    with opener.open(request, timeout=5) as response:
                        instance = json.load(response)
                    native_id = selected["args"][selected["args"].index("--id") + 1]
                    session = "gemini-owned-" + secrets.token_hex(12)
                    proof = subprocess.check_output([str(installed), "child-authority", "mint", "--session", session,
                        "--server", native_id, "--agent-id", "main", "--instance-id", instance["instance_id"],
                        "--tools", ",".join(tool["name"] for tool in stack.tools), "--resources", stack.receiver.url],
                        env=stack.env, text=True, timeout=10).strip()
                    binding = root / "binding.json"
                    binding.write_text(json.dumps({"contract_version": "sw-gemini-hook-binding/1", "host_session": session,
                        "host_server": "demo", "native_server": native_id, "child_authority": proof}))
                    binding.chmod(0o600)
                    binding_original = binding.read_bytes()
                    hook_token_original = (home / "token").read_bytes()
                    index = selected["args"].index(str(installed))
                    selected["args"][index:index] = ["AGENTFW_HOST_SESSION=" + session, "AGENTFW_CHILD_AUTHORITY=" + proof]
                    command = shlex.join([str(installed), "gemini-hook", "--home", str(home), "--binding", str(binding)])
                    settings["hooks"] = {event: [{"matcher": ".*", "hooks": [{"type": "command", "command": command, "timeout": 5000}]}]
                                         for event in ["BeforeTool", "AfterTool"]}
                    report["coverage"]["hooks"] = "one_signed_native_mcp_binding"
                    report["coverage"]["builtin_tools"] = "refused_when_callback_runs; callback_crash_timeout_remain_host_fail_open"
                config.write_text(json.dumps(settings))
                builtin_witness = root / "builtin.txt"
                steps = [("read_document", {"name": "inventory"}),
                         ("send_http", {"url": stack.receiver.url, "body": DEMO.BENIGN}),
                         ("send_http", {"url": stack.receiver.url, "body": "key=" + DEMO.SECRET}),
                         ("delete_note", {"name": "inventory"}),
                         ("send_http", {"url": stack.receiver.url, "body": "Contact alice@example.com"}),
                         ("read_document", {"name": "injected"}),
                         ("read_document", {"name": "inventory"}),
                         ("write_file", {"file_path": str(builtin_witness), "content": "owned builtin witness"}),
                         ("read_document", {"name": "inventory"})]
                steps = [("mcp_demo_" + name if name in {"read_document", "send_http", "delete_note"} else name, value)
                         for name, value in steps]
                if args.hooks:
                    steps[7:7] = [("mcp_demo_read_document", {"name": "inventory"})] * 3

                def before(index):
                    if args.hooks:
                        if index == 7:
                            (home / "token").write_text("owned-invalid-hook-token")
                        elif index == 8:
                            (home / "token").write_bytes(hook_token_original)
                            changed = json.loads(binding_original)
                            changed["child_authority"] = "owned-invalid-child-authority"
                            binding.write_text(json.dumps(changed))
                        elif index == 9:
                            binding.write_bytes(binding_original)
                    if index == len(steps) - 1:
                        DEMO.stop(stack.daemon)

                provider = Provider(steps, before)
                try:
                    stack.ledger.write_text("")
                    env = {"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(host_home), "CI": "true",
                           "GEMINI_CLI_NO_RELAUNCH": "true", "GEMINI_API_KEY": "owned-local-fixture-key",
                           "GOOGLE_GEMINI_BASE_URL": provider.url, "NO_PROXY": "127.0.0.1,localhost"}
                    result = subprocess.run([str(node), str(gemini), "--model", "gemini-2.5-flash", "--approval-mode", "yolo",
                                             "--output-format", "json", "--prompt", "Run the owned fixture tool sequence."],
                                            env=env, cwd=root, capture_output=True, text=True, timeout=90, umask=0o077)
                    args.out.with_suffix(".host.json").write_text(json.dumps({"stdout": result.stdout, "stderr": result.stderr,
                                                                            "requests": provider.requests}, indent=2))
                    check("real_host_exit", result.returncode == 0)
                    check("private_settings_after_host", config.stat().st_mode & 0o077 == 0)
                    check("real_host_completed_sequence", len(provider.requests) == len(steps) + 1)
                    witness = [json.loads(line)["params"] for line in DEMO.lines(stack.ledger)]
                    expected = ["read_document", "send_http", "read_document", "read_document"] + (["read_document"] if args.hooks else [])
                    check("exact_server_executions", [p["name"] for p in witness] == expected)
                    check("only_allowed_delivery", stack.receiver.bodies == [DEMO.BENIGN])
                    check("delete_denied", (stack.notes / "inventory.txt").exists())
                    received = json.dumps(provider.requests[1:])
                    check("useful_read", "Inventory: 7 red widgets." in received)
                    check("result_withheld", DEMO.MARKER not in received)
                    audit = (home / "audit.jsonl").read_text()
                    check("ask_withheld", "demo-pii-confirmation" in (audit if args.hooks else received))
                    check("builtin_coverage_boundary", not builtin_witness.exists() if args.hooks else builtin_witness.read_text() == "owned builtin witness")
                    responses = [request["contents"][-1]["parts"][0]["functionResponse"] for request in provider.requests[1:]]
                    check("host_result_correlations", [response["name"] for response in responses] == [name for name, _ in steps])
                    check("host_result_dispositions", ["error" in response["response"] for response in responses]
                          == [False, False, True, True, True, True, False] + ([True, True, False, True, True] if args.hooks else [False, True]))
                    check("outage_no_execution", len(witness) == len(expected) and ("callback is unavailable" if args.hooks else "Connection closed") in responses[-1]["response"]["error"])
                    if args.hooks:
                        rows = [json.loads(line) for line in audit.splitlines()]
                        native_bound = [row for row in rows if row.get("event") == "native_call" and row.get("host_session") == session]
                        hook_bound = [row for row in rows if row.get("event") in {"pre_tool_use", "post_tool_use"}
                                      and row.get("session") == session and row.get("agent_id") == "main"]
                        report["shared_identity_witness"] = {"native_calls": len(native_bound), "before_callbacks": sum(row["event"] == "pre_tool_use" for row in hook_bound),
                            "after_callbacks": sum(row["event"] == "post_tool_use" for row in hook_bound)}
                        check("shared_authenticated_session", report["shared_identity_witness"] == {"native_calls": 5, "before_callbacks": 8, "after_callbacks": 5}
                              and all(row.get("agent_id") == "main" for row in native_bound))
                        check("wrong_token_and_proof_no_execution_then_recovery", all("callback is unavailable" in responses[i]["response"]["error"] for i in [7, 8])
                              and "error" not in responses[9]["response"])
                        report["binding_sha256"] = hashlib.sha256(binding.read_bytes()).hexdigest()
                    report["server_witness_sha256"] = hashlib.sha256(stack.ledger.read_bytes()).hexdigest()
                    completed = True
                finally:
                    provider.close()
    finally:
        report["passed"] = completed and all(c["passed"] for c in checks)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
