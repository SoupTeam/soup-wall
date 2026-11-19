#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned Codex CLI + native MCP acceptance; loopback scripted Responses, USD0."""
from __future__ import annotations

import argparse
import hashlib
import http.server
import importlib.util
import json
import re
import shlex
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/mcp-admission-demo.py")
DEMO = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DEMO)


class Provider:
    def __init__(self, steps, before=None):
        self.steps, self.requests = steps, []
        self.before = before
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(request)
                index = len(outer.requests) - 1
                response_id = f"resp_fixture_{index}"
                if index < len(outer.steps):
                    if outer.before:
                        outer.before(index)
                    step = outer.steps[index]
                    name, args = step(request) if callable(step) else step
                    item = {"id": f"fc_{index}", "type": "function_call", "status": "completed",
                            "call_id": f"call_{index}", "name": name, "arguments": json.dumps(args)}
                    if name.startswith("mcp__"):
                        item["namespace"], item["name"] = name.rsplit("__", 1)
                else:
                    item = {"id": f"msg_{index}", "type": "message", "status": "completed", "role": "assistant",
                            "content": [{"type": "output_text", "text": "Owned fixture finished.", "annotations": []}]}
                response = {"id": response_id, "object": "response", "status": "completed", "output": [item],
                            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
                events = [{"type": "response.created", "response": dict(response, status="in_progress", output=[])},
                          {"type": "response.output_item.added", "output_index": 0, "item": item},
                          {"type": "response.output_item.done", "output_index": 0, "item": item},
                          {"type": "response.completed", "response": response}]
                body = "".join("event: " + e["type"] + "\ndata: " + json.dumps(e) + "\n\n" for e in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def host_identity(executable):
    binary = Path(shutil.which(executable) or executable).resolve(strict=True)
    return {
        "codex_version": subprocess.check_output([str(binary), "--version"], text=True, timeout=10).strip(),
        "codex_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--codex")
    mode.add_argument("--lifecycle-only", action="store_true", help="verify the TOML lifecycle without starting Codex")
    parser.add_argument("--out", type=Path, required=True)
    options = parser.parse_args()
    binary = options.agentfw.resolve()
    checks = []
    completed = False
    report = {"source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "mode": "lifecycle_only" if options.lifecycle_only else "actual_host",
              "external_provider_requests": 0, "live_model_evaluation": False, "checks": checks,
              "coverage": {"selected_stdio_mcp": "controlled_probe" if options.lifecycle_only else "tested_below", "builtin_shell_file_subagents": "not_enforced",
                           "authenticated_cross_tool_session": "not_implemented"}}

    def check(name, condition):
        checks.append({"check": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.touch(exist_ok=False)
    try:
        if not options.lifecycle_only:
            report.update(host_identity(options.codex))
            check("pinned_host_version", report["codex_version"] == "codex-cli 0.169.0-alpha.11.1")
        report["agentfw_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["source_files_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [ROOT / "Cargo.lock", ROOT / "scripts/fixtures/codex-0.169.0-call.json",
                      *sorted((ROOT / "crates/agentfw").rglob("*.rs")), Path(__file__)]}
        with tempfile.TemporaryDirectory(prefix="soup-codex-", dir=ROOT / "target") as tmp:
            root = Path(tmp)
            installed = root / "agentfw"
            shutil.copyfile(binary, installed)
            installed.chmod(0o755)
            binary = installed
            with DEMO.agent_stack(binary, root / "stack") as stack:
                home = stack.workspace / ".agentfw"
                for name in ["config.yaml", "token", "native-token"]:
                    (home / name).chmod(0o600)
                codex_home = root / "codex"
                codex_home.mkdir(mode=0o700)
                config = codex_home / "config.toml"
                original = {"command": str(Path("/usr/bin/python3").resolve()),
                            "args": ["-I", str(DEMO.FIXTURE), "--notes", str(stack.notes),
                                     "--ledger", str(stack.ledger), "--recipient", stack.receiver.url]}
                suffix = "\n[mcp_servers.unrelated]\ncommand = 'untouched'\nenv = { TOKEN = 'synthetic-secret' }\n"
                initial = ("# owned acceptance\nmodel = 'fixture' # keep\n[mcp_servers.demo]\n# selected command\ncommand = "
                           + json.dumps(original["command"]) + "\nargs = " + json.dumps(original["args"]) + "\n" + suffix)
                config.write_text(initial)
                config.chmod(0o600)

                def connection(operation, extra=(), success=True):
                    result = subprocess.run([str(binary), "mcp-connection", operation, "--host", "codex",
                                             "--path", str(config), "--server", "demo", "--home", str(home),
                                             "--agent", str(binary), *extra], capture_output=True, text=True, timeout=30)
                    if (result.returncode == 0) != success:
                        print(result.stdout, result.stderr)
                    check(f"{operation}_exit_{len(checks)}", (result.returncode == 0) == success)
                    check(f"{operation}_redacted_{len(checks)}", "synthetic-secret" not in result.stdout + result.stderr)
                    return json.loads(result.stdout) if result.stdout.startswith("{") else {}

                connection("preview")
                check("preview_no_write", config.read_text() == initial)
                check("connect_configured", connection("connect")["status"] == "configured")
                connected = config.read_bytes()
                check("wrapper_present", tomllib.loads(connected.decode())["mcp_servers"]["demo"]["command"] == "/usr/bin/env")
                connection("connect")
                check("reconnect_idempotent", config.read_bytes() == connected)
                check("unrelated_text_preserved", config.read_text().endswith(suffix))
                check("inspect_configured", connection("inspect")["status"] == "configured")
                native_token = home / "native-token"
                correct_token = native_token.read_bytes()
                try:
                    native_token.write_text("owned-invalid-native-token")
                    connection("inspect", ["--probe-tool", "read_document", "--probe-args", '{"name":"inventory"}'], success=False)
                    check("wrong_token_probe_no_execution", not DEMO.lines(stack.ledger))
                finally:
                    native_token.write_bytes(correct_token)
                probe = connection("inspect", ["--probe-tool", "read_document", "--probe-args", '{"name":"inventory"}'])
                check("probe_verified", probe["status"] == "verified_for_this_probe")
                check("probe_executed_once", len(DEMO.lines(stack.ledger)) == 1)
                connection("disconnect")
                check("disconnect_restores_semantics", tomllib.loads(config.read_text()) == tomllib.loads(initial))
                check("disconnect_preserves_selected_comment", "# selected command\ncommand" in config.read_text())
                connection("connect")
                connected = config.read_bytes()
                config.write_text(config.read_text().replace("# keep", "# concurrent edit"))
                connection("disconnect")
                check("unrelated_edit_survives", "# concurrent edit" in config.read_text())
                connection("connect")
                config.write_text(config.read_text().replace("PATH=/usr/bin:/bin", "PATH=/modified"))
                conflict = config.read_bytes()
                connection("disconnect", success=False)
                check("selected_conflict_preserved", config.read_bytes() == conflict)
                config.write_bytes(connected)
                if options.lifecycle_only:
                    connection("disconnect")
                    completed = True
                    return

                # Real host: only an isolated home, loopback provider and owned MCP server.
                # The unrelated fake server is disabled for this acceptance host run.
                config.write_text(config.read_text().replace(suffix, ""))
                shell_witness = root / "interactive.txt"
                shell_program = "import sys; from pathlib import Path; Path(" + repr(str(shell_witness)) + ").write_text(sys.stdin.readline())"
                def continue_shell(request):
                    outputs = [x["output"] for x in request["input"] if x.get("type") == "function_call_output"]
                    match = re.search(r"session ID (\d+)", str(outputs[-1]))
                    if not match:
                        raise RuntimeError("interactive session ID absent: " + str(outputs[-1]))
                    return "write_stdin", {"session_id": int(match[1]), "chars": "owned interactive witness\n", "yield_time_ms": 1000}
                steps = [("mcp__demo__read_document", {"name": "inventory"}),
                         ("mcp__demo__send_http", {"url": stack.receiver.url, "body": DEMO.BENIGN}),
                         ("mcp__demo__send_http", {"url": stack.receiver.url, "body": "key=" + DEMO.SECRET}),
                         ("mcp__demo__delete_note", {"name": "inventory"}),
                         ("mcp__demo__send_http", {"url": stack.receiver.url, "body": "Contact alice@example.com"}),
                         ("mcp__demo__read_document", {"name": "injected"}),
                         ("mcp__demo__read_document", {"name": "inventory"}),
                         ("exec_command", {"cmd": "/usr/bin/python3 -c " + shlex.quote(shell_program), "tty": True,
                                           "yield_time_ms": 250, "shell": "/bin/bash", "login": False}),
                         continue_shell,
                         ("mcp__demo__read_document", {"name": "inventory"})]
                def before(index):
                    if index == len(steps) - 1:
                        DEMO.stop(stack.daemon)
                provider = Provider(steps, before)
                try:
                    with config.open("a") as stream:
                        stream.write('\n[model_providers.owned]\nname = "Owned loopback"\nbase_url = '
                                     + json.dumps(provider.url) + '\nwire_api = "responses"\nrequires_openai_auth = false\n')
                    stack.ledger.write_text("")
                    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "CODEX_HOME": str(codex_home),
                           "USERPROFILE": str(root), "LANG": "C.UTF-8"}
                    result = subprocess.run([options.codex, "exec", "--skip-git-repo-check", "--ephemeral", "--json",
                                             "-C", str(root), "-s", "workspace-write", "-c", 'model_provider="owned"',
                                             "-c", 'model="fixture"', "-c", 'approval_policy="never"',
                                             "-c", 'mcp_servers.demo.default_tools_approval_mode="approve"',
                                             "Run the owned fixture tool sequence."], env=env, capture_output=True, text=True, timeout=90)
                    # All persisted diagnostic bytes belong to this synthetic fixture.
                    options.out.with_suffix(".host.json").write_text(json.dumps({"stdout": result.stdout, "stderr": result.stderr,
                                                                              "requests": provider.requests}, indent=2))
                    check("real_host_exit", result.returncode == 0)
                    check("real_host_completed_sequence", len(provider.requests) == len(steps) + 1)
                    witness = [json.loads(line)["params"] for line in DEMO.lines(stack.ledger)]
                    check("real_host_exact_executions", [p["name"] for p in witness] ==
                          ["read_document", "send_http", "read_document", "read_document"])
                    check("real_host_only_allowed_delivery", stack.receiver.bodies == [DEMO.BENIGN])
                    check("real_host_delete_denied", (stack.notes / "inventory.txt").exists())
                    received = json.dumps(provider.requests[1:])
                    check("real_host_useful_read", "Inventory: 7 red widgets." in received)
                    check("real_host_result_withheld", DEMO.MARKER not in received)
                    check("real_host_unconfirmed_ask_withheld", "demo-pii-confirmation" in received)
                    check("interactive_shell_outside_mcp_coverage", shell_witness.read_text() == "owned interactive witness\n")
                    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
                    calls = [e["item"] for e in events if e.get("type") == "item.completed"
                             and e.get("item", {}).get("type") == "mcp_tool_call"]
                    check("host_outcomes_correlate", [c["status"] for c in calls] ==
                          ["completed", "completed", "failed", "failed", "failed", "failed", "completed", "failed"])
                    check("daemon_outage_no_execution", len(witness) == 4
                          and "Transport closed" in calls[-1]["error"]["message"])
                    report["host_calls"] = [{"server": c["server"], "tool": c["tool"], "status": c["status"],
                                             "arguments_sha256": hashlib.sha256(DEMO.canonical(c["arguments"])).hexdigest()}
                                            for c in calls]
                    report["server_witness_sha256"] = hashlib.sha256(stack.ledger.read_bytes()).hexdigest()
                finally:
                    provider.close()
                completed = True
    finally:
        report["passed"] = completed and bool(checks) and all(c["passed"] for c in checks)
        options.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
