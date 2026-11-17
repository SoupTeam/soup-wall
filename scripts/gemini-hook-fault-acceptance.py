#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Characterize the actual Gemini 0.68.0 callback boundary, including fail-open cases."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gemini_acceptance", ROOT / "scripts/gemini-mcp-acceptance.py")
HOST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HOST)

HOOK = '''import json,sys,time
d=json.load(sys.stdin)
mode=sys.argv[1]
if mode=='error':sys.exit(1)
if mode=='timeout':time.sleep(2)
if mode=='mcp_ask':
 print(json.dumps({'decision':'ask','reason':'owned MCP Ask'}));sys.exit(0)
block=d['hook_event_name']=='AfterTool' or d.get('tool_name')=='write_file'
if mode=='exit2' and block:
 print('owned exit2 refusal',file=sys.stderr);sys.exit(2)
print(json.dumps({'decision':'deny','reason':'owned refusal'} if block else {}))
'''


def run_case(node, gemini, parent, mode):
    with tempfile.TemporaryDirectory(prefix=mode + "-", dir=parent) as tmp:
        root = Path(tmp)
        home = root / "home"
        (home / ".gemini").mkdir(parents=True, mode=0o700)
        workspace = root / "workspace"
        workspace.mkdir()
        note = workspace / "note.txt"
        marker = "GEMINI_OWNED_RESULT_CANARY"
        note.write_text(marker)
        witness = workspace / "forbidden.txt"
        hook = root / "callback.py"
        hook.write_text(HOOK)
        command = "/usr/bin/python3 " + str(hook) + " " + mode
        settings = {"security": {"auth": {"selectedType": "gemini-api-key"}, "folderTrust": {"enabled": False}},
                    "telemetry": {"enabled": False}, "general": {"disableAutoUpdate": True},
                    "hooks": {event: [{"matcher": ".*", "hooks": [{"type": "command", "command": command,
                               "timeout": 100 if mode == "timeout" else 5000}]}] for event in ["BeforeTool", "AfterTool"]}}
        receiver = HOST.DEMO.Receiver()
        ledger = root / "executed.jsonl"
        if mode == "mcp_ask":
            settings["mcpServers"] = {"probe": {"command": "/usr/bin/python3", "args": ["-I", str(HOST.DEMO.FIXTURE),
                "--notes", str(workspace), "--ledger", str(ledger), "--recipient", receiver.url]}}
            steps = [("mcp_probe_send_http", {"url": receiver.url, "body": "owned MCP Ask witness"})]
        else:
            steps = [("read_file", {"file_path": str(note)}), ("write_file", {"file_path": str(witness), "content": "owned write witness"})]
        (home / ".gemini/settings.json").write_text(json.dumps(settings))
        provider = HOST.Provider(steps)
        env = {"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(home), "CI": "true", "GEMINI_CLI_NO_RELAUNCH": "true",
               "GEMINI_API_KEY": "owned-local-fixture-key", "GOOGLE_GEMINI_BASE_URL": provider.url, "NO_PROXY": "127.0.0.1,localhost"}
        process = subprocess.Popen([str(node), str(gemini), "--model", "gemini-2.5-flash", "--approval-mode", "yolo", "--output-format", "json",
            "--prompt", "Run the owned callback fixture."], env=env, cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, start_new_session=True, umask=0o077)
        timed_out = False
        try:
            try:
                stdout, stderr = process.communicate(timeout=8 if mode == "mcp_ask" else 30)
            except subprocess.TimeoutExpired:
                timed_out = True
                # The process group was created by this fixture, never selected by name.
                assert os.getpgid(process.pid) == process.pid
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    stdout, stderr = process.communicate(timeout=5)
            result = {"case": mode, "host_exit": process.returncode, "timed_out": timed_out,
                      "provider_requests": len(provider.requests), "file_written": witness.exists(),
                      "result_reached_provider": marker in json.dumps(provider.requests),
                      "mcp_executions": len(HOST.DEMO.lines(ledger)), "receiver_deliveries": len(receiver.bodies)}
            if mode == "mcp_ask":
                result["observed"] = "headless_MCP_Ask_did_not_continue"
                result["passed"] = timed_out and len(provider.requests) == 1 and not receiver.bodies and not HOST.DEMO.lines(ledger)
            else:
                fail_open = mode in {"error", "timeout"}
                result["observed"] = "callback_failure_is_fail_open" if fail_open else "callback_blocks_call_and_result"
                result["passed"] = (not timed_out and process.returncode == 0 and len(provider.requests) == 3
                                    and witness.exists() == fail_open and result["result_reached_provider"] == fail_open)
            # The transcripts contain only this owned fixture; no user credentials or files.
            (parent / (mode + ".host.json")).write_text(json.dumps({"stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"), "requests": provider.requests}, indent=2))
            return result
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
            provider.close()
            receiver.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ["node", "gemini", "out"]:
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    node, gemini = args.node.resolve(), args.gemini.resolve()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([str(node), str(gemini), "--version"], text=True).strip()
    assert version == "0.68.0", "unqualified Gemini version"
    report = {"kind": "host_contract_characterization_not_enforcement_qualification", "gemini_version": version,
              "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "external_provider_requests": 0,
              "cases": [], "passed": False}
    report.update(HOST.identities(gemini))
    report["node_sha256"] = hashlib.sha256(node.read_bytes()).hexdigest()
    report["gemini_entry_sha256"] = hashlib.sha256(gemini.read_bytes()).hexdigest()
    try:
        for mode in ["deny", "exit2", "error", "timeout", "mcp_ask"]:
            case = run_case(node, gemini, args.out.parent, mode)
            report["cases"].append(case)
            if not case["passed"]:
                raise AssertionError("unexpected actual host outcome: " + mode)
        report["passed"] = True
    finally:
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
