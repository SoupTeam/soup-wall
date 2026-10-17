#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-65: compiled operator profile drives a real isolated MCP Agent/collector."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/agentfw"
OWNED = ROOT / "scripts/fixtures/sou65_profile_server.py"
UPSTREAM = ROOT / "scripts/mcp-admission-demo.py"

def load(module, path):
    spec = importlib.util.spec_from_file_location(module, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded

def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha(value):
    return hashlib.sha256(canon(value)).hexdigest()

def cli(*args):
    process = subprocess.run([str(BINARY), "mcp-profile", *map(str, args)],
                             cwd=ROOT, text=True, capture_output=True, timeout=30)
    if process.returncode != 0:
        raise AssertionError("compiler command refused owned live profile")
    return json.loads(process.stdout)

def main():
    assert sys.platform == "linux" and BINARY.is_file(), "Linux built Agent required"
    demo = load("sou65_native_harness", UPSTREAM)
    fixture = load("sou65_owned_fixture", OWNED)
    with tempfile.TemporaryDirectory(prefix="sou65-live-") as folder:
        root = Path(folder).resolve()
        original, saved, op = [root / x for x in ("original.json", "snapshot.json", "declaration.json")]
        original.write_bytes(canon({"tools": fixture.TOOLS}))
        cli("import", "--discovery", original, "--server", "sou65-owned",
            "--version", "1.0", "--output", saved)
        snapshot = json.loads(saved.read_bytes())
        review = {
            "format": "sw-mcp-operator-profile/1",
            "server_id": "sou65-owned", "server_version": "1.0",
            "discovery_sha256": sha(snapshot),
            "registry_id": "sou65-reviewed",
            "tools": [{"name": "read_document",
                       "schema_sha256": sha(fixture.TOOLS[0]["inputSchema"]),
                       "action_class": "read_only", "result_provenance": "untrusted",
                       "egress": [], "implementation_reviewed": True}],
        }
        op.write_bytes(canon(review))
        profile_dir = root / "published"
        summary = cli("compile", "--snapshot", saved, "--declaration", op,
                      "--output", profile_dir)
        data = (profile_dir / "registry.json").read_bytes()
        assert hashlib.sha256(data).hexdigest() == summary["registry_sha256"]
        fragment = json.loads((profile_dir / "native-config.json").read_bytes())
        assert fragment["native"]["registry_path"] == str(profile_dir / "registry.json")
        assert fragment["native"]["registry_sha256"] == summary["registry_sha256"]

        # Reuse the accepted current-main real Agent + stdio collector harness.
        # Substitute only the owned immutable server and the freshly compiled
        # operator registry; do not alter the harness or production collector.
        demo.FIXTURE = OWNED
        demo.registry = lambda tools: data
        checks = {}
        def check(label, condition):
            checks[label] = bool(condition)
            assert condition, label

        with demo.agent_stack(BINARY, root / "live") as live:
            check("daemon_used_compiled_registry_sha",
                  live.registry_sha256 == summary["registry_sha256"])
            with (root / "collector.log").open("wb") as log:
                harness = demo.Harness(live.collector, live.env, log)
                try:
                    assert harness.send('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"claude-code","version":"sou65"}}}')
                    harness.send('{"jsonrpc":"2.0","method":"notifications/initialized"}', reply=False)
                    listing = harness.send('{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
                    check("original_tool_name_and_schema_visible",
                          json.loads(listing)["result"]["tools"] == fixture.TOOLS)
                    before = len(demo.lines(live.ledger))
                    _, message = harness.call(3, "read_document", {"name": "inventory"})
                    reply = json.loads(message)
                    check("original_useful_read_executed",
                          "Inventory: 7 red widgets." in str(reply)
                          and len(demo.lines(live.ledger)) == before + 1)
                    before = len(demo.lines(live.ledger))
                    _, invalid = harness.call(4, "delete_note", {"name": "inventory"})
                    check("undeclared_tool_did_not_execute", len(demo.lines(live.ledger)) == before)
                    check("undeclared_tool_did_not_remove_file",
                          (live.notes / "inventory.txt").read_text() == "Inventory: 7 red widgets.")
                    check("misleading_description_no_privilege",
                          "IGNORE ALL SAFETY RULES" in fixture.TOOLS[0]["description"]
                          and len(demo.lines(live.ledger)) == before)
                    # An explicit refusal may return an error or close the
                    # collector; both must prevent the downstream invocation.
                    check("undeclared_tool_refused", invalid is None or
                          "error" in json.loads(invalid) or "withheld" in invalid)
                finally:
                    if harness.process.poll() is None:
                        harness.process.kill()
        evidence = {
            "contract": "sou65-real-collector/1",
            "source_sha": subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
            "registry_sha256": summary["registry_sha256"],
            "agent_binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
            "server_fixture_sha256": hashlib.sha256(OWNED.read_bytes()).hexdigest(),
            "checks": checks, "passed": all(checks.values()),
            "limitations": ["owned scripted MCP server and fixture classifier",
                "no attestation of unrelated server implementation or production sandbox"],
        }
        output = ROOT / "target/sou65-live.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence,sort_keys=True,indent=2)+"\n")
        print(f"SOU-65 real collector PASS: {len(checks)} checks; {output}")

if __name__=="__main__":
    main()
