#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copilot CLI 1.0.112 with native stdio admission and an owned loopback provider."""
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


def identities(copilot):
    runtime = copilot.parents[2]
    files = {str(path.relative_to(runtime)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(runtime.rglob("*")) if path.is_file() and not path.is_symlink()}
    sources = [ROOT / "Cargo.lock", *sorted((ROOT / "crates/agentfw").rglob("*.rs")),
               *sorted((ROOT / "scripts").glob("copilot-*.py")), ROOT / "scripts/opencode-mcp-acceptance.py"]
    return {"source_files_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
            "runtime_tree_sha256": hashlib.sha256(DEMO.canonical(files)).hexdigest(), "runtime_file_count": len(files)}


spec = importlib.util.spec_from_file_location("owned_host", ROOT / "scripts/opencode-mcp-acceptance.py")
HOST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HOST)
Provider, run_host = HOST.Provider, HOST.run_host


def host_environment(home, provider):
    config = home / ".copilot/providers.json"
    config.write_text(json.dumps({"providers":[{"name":"owned","type":"openai","baseUrl":provider.url + "/v1","apiKey":"owned-synthetic"}],
                                 "models":[{"id":"fixture","provider":"owned"}]}))
    config.chmod(0o600)
    return {"PATH":"/usr/bin:/bin", "HOME":str(home), "COPILOT_HOME":str(home / ".copilot"),
            "COPILOT_PROVIDERS_CONFIG":str(config), "COPILOT_OFFLINE":"true", "NO_PROXY":"127.0.0.1,localhost"}


def host_command(binary):
    return [str(binary), "--model", "owned/fixture", "--disable-builtin-mcps", "--no-auto-update", "--no-custom-instructions",
            "--no-ask-user", "--trust-folder", "--allow-all", "--output-format", "json", "--stream", "on",
            "--prompt", "Run the owned fixture tool sequence."]


def completions(stdout):
    events = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    return [event["data"] for event in events if event.get("type") == "tool.execution_complete"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--copilot", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--hooks", action="store_true", help="also bind native MCP and Copilot callbacks to one authenticated session")
    args = parser.parse_args()
    binary, copilot = args.agentfw.resolve(), args.copilot.resolve()
    checks, completed = [], False
    report = {"source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "copilot_version": subprocess.check_output([str(copilot), "--version"], text=True).strip(),
              "agentfw_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "copilot_entry_sha256": hashlib.sha256(copilot.read_bytes()).hexdigest(),
              "external_provider_requests": 0, "checks": checks,
              "coverage": {"selected_stdio_mcp": "tested_below", "builtin_tools": "not_enforced", "hooks": "not_installed"}}
    report.update(identities(copilot))

    def check(name, condition):
        checks.append({"check": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        check("pinned_host_version", report["copilot_version"].splitlines()[0] == "GitHub Copilot CLI 1.0.112.")
        with tempfile.TemporaryDirectory(prefix="soup-copilot-", dir=ROOT / "target") as tmp:
            root = Path(tmp)
            installed = root / "agentfw"
            shutil.copyfile(binary, installed)
            installed.chmod(0o755)
            with DEMO.agent_stack(installed, root / "stack") as stack:
                home = stack.workspace / ".agentfw"
                for name in ["config.yaml", "token", "native-token"]:
                    (home / name).chmod(0o600)
                host_home = root / "host-home"
                (host_home / ".copilot").mkdir(parents=True, mode=0o700)
                config = host_home / ".copilot/mcp-config.json"
                entry = {"type":"local", "tools":["*"], "command": str(Path("/usr/bin/python3").resolve()),
                         "args": ["-I", str(DEMO.FIXTURE), "--notes", str(stack.notes), "--ledger", str(stack.ledger),
                                  "--recipient", stack.receiver.url]}
                prefix = '{ "mcpServers": { "demo": '
                suffix = ', "other": {"command":"untouched", "env":{"TOKEN":"synthetic-secret"}}}, "theme":"light"}\n'
                original = prefix + json.dumps(entry) + suffix
                config.write_text(original)
                config.chmod(0o600)

                def connection(operation, extra=(), success=True):
                    result = subprocess.run([str(installed), "mcp-connection", operation, "--host", "copilot", "--path", str(config),
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
                check("probe_verified", probe["status"] == "verified_for_this_probe" and probe["host"] == "copilot")
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
                settings = {}
                if args.hooks:
                    daemon_config = json.loads((home / "config.yaml").read_text())
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    request = urllib.request.Request(f'http://127.0.0.1:{daemon_config["port"]}/native/v1/instance',
                        headers={"Authorization": "Bearer " + (home / "native-token").read_text().strip()})
                    with opener.open(request, timeout=5) as response:
                        instance = json.load(response)
                    native_id = selected["args"][selected["args"].index("--id") + 1]
                    session = "copilot-owned-" + secrets.token_hex(12)
                    proof = subprocess.check_output([str(installed), "child-authority", "mint", "--session", session,
                        "--server", native_id, "--agent-id", "main", "--instance-id", instance["instance_id"],
                        "--tools", ",".join(tool["name"] for tool in stack.tools), "--resources", stack.receiver.url],
                        env=stack.env, text=True, timeout=10).strip()
                    binding = root / "binding.json"
                    binding.write_text(json.dumps({"contract_version": "sw-copilot-hook-binding/1", "host_session": session,
                        "host_server": "demo", "native_server": native_id, "child_authority": proof}))
                    binding.chmod(0o600)
                    binding_original = binding.read_bytes()
                    hook_token_original = (home / "token").read_bytes()
                    index = selected["args"].index(str(installed))
                    selected["args"][index:index] = ["AGENTFW_HOST_SESSION=" + session, "AGENTFW_CHILD_AUTHORITY=" + proof]
                    settings["hooks"] = {event: [{"type":"command", "command":shlex.join([str(installed), "copilot-hook", "--home", str(home),
                        "--binding", str(binding), "--phase", phase]), "timeoutSec":5}]
                        for event, phase in [("preToolUse", "before"), ("postToolUse", "after")]}
                    report["coverage"]["hooks"] = "one_signed_native_mcp_binding"
                    report["coverage"]["builtin_tools"] = "refused_when_callback_runs; host_timeout_malformed_output_and_post_crash_remain_fail_open"
                config.write_text(json.dumps({"mcpServers":{"demo":selected}}))
                (host_home / ".copilot/settings.json").write_text(json.dumps(settings))
                builtin_witness = root / "builtin.txt"
                steps = [("read_document", {"name": "inventory"}),
                         ("send_http", {"url": stack.receiver.url, "body": DEMO.BENIGN}),
                         ("send_http", {"url": stack.receiver.url, "body": "key=" + DEMO.SECRET}),
                         ("delete_note", {"name": "inventory"}),
                         ("send_http", {"url": stack.receiver.url, "body": "Contact alice@example.com"}),
                         ("read_document", {"name": "injected"}),
                         ("read_document", {"name": "inventory"}),
                         ("create", {"path": str(builtin_witness), "file_text": "owned builtin witness"}),
                         ("read_document", {"name": "inventory"})]
                steps = [("demo-" + name if name in {"read_document", "send_http", "delete_note"} else name, value)
                         for name, value in steps]
                if args.hooks:
                    steps[7:7] = [("demo-read_document", {"name": "inventory"})] * 3

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
                    result = run_host(host_command(copilot), env=host_environment(host_home, provider), cwd=root,
                                      stdin=subprocess.DEVNULL, text=True, timeout=90, umask=0o077)
                    report["host_timed_out"] = result.timed_out
                    args.out.with_suffix(".host.json").write_text(json.dumps({"stdout": result.stdout, "stderr": result.stderr,
                                                                            "requests": provider.requests}, indent=2))
                    check("real_host_exit", result.returncode == 0 and not result.timed_out)
                    check("private_settings_after_host", config.stat().st_mode & 0o077 == 0)
                    check("real_host_completed_sequence", len(provider.requests) == len(steps) + 1)
                    witness = [json.loads(line)["params"] for line in DEMO.lines(stack.ledger)]
                    args.out.with_suffix(".audit.jsonl").write_bytes((home / "audit.jsonl").read_bytes())
                    report["observed_server_executions"] = [p["name"] for p in witness]
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
                    responses = [request["messages"][-1] for request in provider.requests[1:]]
                    outcomes = completions(result.stdout)
                    check("host_result_correlations", [response["tool_call_id"] for response in responses] == [f"owned-{i}" for i in range(len(steps))])
                    check("host_result_dispositions", [outcome["success"] for outcome in outcomes]
                          == [True, True, False, False, False, False, True] + ([False, False, True, False, False] if args.hooks else [True, False]))
                    check("outage_no_execution", len(witness) == len(expected) and ("callback is unavailable" if args.hooks else "MCP transport closed") in responses[-1]["content"])
                    if args.hooks:
                        rows = [json.loads(line) for line in audit.splitlines()]
                        native_bound = [row for row in rows if row.get("event") == "native_call" and row.get("host_session") == session]
                        hook_bound = [row for row in rows if row.get("event") in {"pre_tool_use", "post_tool_use"}
                                      and row.get("session") == session and row.get("agent_id") == "main"]
                        report["shared_identity_witness"] = {"native_calls": len(native_bound), "before_callbacks": sum(row["event"] == "pre_tool_use" for row in hook_bound),
                            "after_callbacks": sum(row["event"] == "post_tool_use" for row in hook_bound)}
                        check("shared_authenticated_session", report["shared_identity_witness"] == {"native_calls": 5, "before_callbacks": 8, "after_callbacks": 4}
                              and all(row.get("agent_id") == "main" for row in native_bound))
                        check("wrong_token_and_proof_no_execution_then_recovery", all("callback is unavailable" in responses[i]["content"] for i in [7, 8])
                              and outcomes[9]["success"])
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
