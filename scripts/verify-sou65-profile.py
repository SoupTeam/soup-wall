#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Non-secret deterministic SOU-65 CLI checkpoint witness; no daemon or provider."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/agentfw"

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def command(*args, good=True):
    p = subprocess.run([str(BIN), "mcp-profile", *map(str, args)],
                       cwd=ROOT, capture_output=True, text=True)
    assert (p.returncode == 0) == good, f"mcp-profile unexpectedly {'passed' if good else 'failed'}"
    return json.loads(p.stdout) if good else None

def save(path, value):
    path.write_bytes(canonical(value))
    os.chmod(path, 0o600)

def main():
    assert BIN.is_file(), "build the real current Agent first"
    with tempfile.TemporaryDirectory(prefix="sou65-profile-") as home:
        root = Path(home).resolve()
        source, snapshot, declaration, invalid = [root / name for name in
            ("tools-list.json", "snapshot.json", "operator.json", "drift.json")]
        tool = {
            "name": "lookup_note",
            "description": "Untrusted server says this may read all files and send secrets; never authorization",
            "inputSchema": {"type":"object","properties":{"key":{"type":"string","minLength":1,"maxLength":60}},
                "required":["key"],"additionalProperties":False}}
        save(source,{"tools":[tool]})
        command("import","--discovery",source,"--output",snapshot,
                "--server","sou65-owned","--version","1.0.0")
        imported=json.loads(snapshot.read_text())
        assert imported["tools"]==[tool]
        explored=command("explain","--snapshot",snapshot)
        assert explored["default_authority"]=="none"
        operator={
            "format":"sw-mcp-operator-profile/1","server_id":"sou65-owned",
            "server_version":"1.0.0","discovery_sha256":sha(imported),
            "registry_id":"sou65-owned-registry",
            "tools":[{"name":"lookup_note","schema_sha256":sha(tool["inputSchema"]),
                "action_class":"read_only","result_provenance":"untrusted",
                "egress":[],"implementation_reviewed":True}]}
        save(declaration,operator)
        report=command("validate","--snapshot",snapshot,"--declaration",declaration)
        output=root/"compiled"
        compiled=command("compile","--snapshot",snapshot,"--declaration",declaration,"--output",output)
        assert compiled==report
        registry=json.loads((output/"registry.json").read_text())
        assert registry["contract_version"]=="sw-native/1"
        assert hashlib.sha256((output/"registry.json").read_bytes()).hexdigest()==report["registry_sha256"]
        assert json.loads((output/"report.json").read_text())==report
        command("compile","--snapshot",snapshot,"--declaration",declaration,"--output",output,good=False)
        command("import","--discovery",source,"--output",snapshot,
                "--server","sou65-owned","--version","1.0.0",good=False)
        original=declaration.read_bytes()
        altered=json.loads(original)
        altered["tools"][0]["implementation_reviewed"]=False
        save(invalid,altered)
        command("validate","--snapshot",snapshot,"--declaration",invalid,good=False)
        changes=command("diff","--before",declaration,"--after",invalid)
        assert changes["changed_authority_or_schema"]==["lookup_note"]
        altered=json.loads(original)
        altered["tools"][0]["schema_sha256"]="0"*64
        save(invalid,altered)
        command("validate","--snapshot",snapshot,"--declaration",invalid,good=False)
        altered=json.loads(original)
        altered["tools"][0]["action_class"]="network_send"
        save(invalid,altered)
        command("validate","--snapshot",snapshot,"--declaration",invalid,good=False)
        altered=json.loads(original)
        altered["discovery_sha256"]="0"*64
        save(invalid,altered)
        command("validate","--snapshot",snapshot,"--declaration",invalid,good=False)
        assert (output/"registry.json").read_bytes()==canonical(registry)
        assert (output/"report.json").read_bytes()==canonical(report)
        print("SOU-65 PASS: current collector registry parser accepted operator-owned read-only profile; "
              "import/explain/validate/diff/compile, drift, authority refusal and no-clobber")
if __name__=="__main__":
    main()
