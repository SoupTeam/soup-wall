#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Characterize Copilot 1.0.112 command-hook failures on owned local fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("copilot_host", ROOT / "scripts/copilot-mcp-acceptance.py")
HOST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HOST)


def run_case(binary, parent, mode):
    with tempfile.TemporaryDirectory(prefix=mode + "-", dir=parent) as tmp:
        root = Path(tmp)
        home = root / "home"
        (home / ".copilot").mkdir(parents=True, mode=0o700)
        workspace = root / "workspace"
        workspace.mkdir()
        marker = "COPILOT_OWNED_RESULT_CANARY"
        (workspace / "inventory.txt").write_text(marker)
        ledger = root / "ledger.jsonl"
        events = root / "callbacks.jsonl"
        receiver = HOST.DEMO.Receiver()
        fake = root / "callback.py"
        # This characterizes host transport behavior; it never substitutes for native policy.
        fake.write_text("import json,sys,time\nframe=json.load(sys.stdin)\nphase=sys.argv[1]\nmode=" + repr(mode) + "\n"
                        "with open(" + repr(str(events)) + ", 'a') as f:f.write(json.dumps({'phase':phase,'value':frame})+'\\n')\n"
                        "if mode in ['exit1','exit2'] and phase=='before': sys.exit(int(mode[-1]))\n"
                        "if mode=='after_exit1' and phase=='after': sys.exit(1)\n"
                        "if mode=='timeout' and phase=='before': time.sleep(3)\n"
                        "if mode=='malformed' and phase=='before': print('invalid'); sys.exit(0)\n"
                        "if mode=='deny' and phase=='before': print(json.dumps({'permissionDecision':'deny','permissionDecisionReason':'Owned refusal'}))\n"
                        "elif mode=='after_deny' and phase=='after': print(json.dumps({'modifiedResult':{'resultType':'failure','textResultForLlm':'Owned result withheld'}}))\n"
                        "else: print('{}')\n")
        settings = {"hooks":{event:[{"type":"command","command":shlex.join(["/usr/bin/python3",str(fake),phase]),"timeoutSec":1}]
                             for event,phase in [("preToolUse","before"),("postToolUse","after")]}}
        (home / ".copilot/settings.json").write_text(json.dumps(settings))
        (home / ".copilot/mcp-config.json").write_text(json.dumps({"mcpServers":{"demo":{"type":"local","tools":["*"],"command":"/usr/bin/python3",
            "args":["-I",str(HOST.DEMO.FIXTURE),"--notes",str(workspace),"--ledger",str(ledger),"--recipient",receiver.url]}}}))
        provider = HOST.Provider([("demo-read_document",{"name":"inventory"}),
                                  ("demo-send_http",{"url":receiver.url,"body":"owned delivery witness"})])
        try:
            result = HOST.run_host(HOST.host_command(binary), env=HOST.host_environment(home,provider), cwd=workspace,
                                   stdin=subprocess.DEVNULL,text=True,timeout=60,umask=0o077)
            case = {"case":mode,"host_exit":result.returncode,"host_timed_out":result.timed_out,"provider_requests":len(provider.requests),
                    "executions":len(HOST.DEMO.lines(ledger)),"deliveries":len(receiver.bodies),"result_reached_provider":marker in json.dumps(provider.requests)}
            (parent/(mode+".host.json")).write_text(json.dumps({"stdout":result.stdout,"stderr":result.stderr,"requests":provider.requests},indent=2))
            if events.exists(): (parent/(mode+".callbacks.jsonl")).write_bytes(events.read_bytes())
            executed = mode not in {"deny","exit1","exit2"}
            released = executed and mode != "after_deny"
            case["expected_boundary"] = "host_fail_open" if mode in {"timeout","malformed","after_exit1"} else "transport_characterization"
            case["passed"] = (not result.timed_out and result.returncode==0 and len(provider.requests)==3 and case["executions"]==(2 if executed else 0)
                              and case["deliveries"]==(1 if executed else 0) and case["result_reached_provider"]==released)
            return case
        finally:
            provider.close()
            receiver.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--copilot",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args = parser.parse_args()
    binary = args.copilot.resolve()
    args.out.parent.mkdir(parents=True,exist_ok=True)
    version = subprocess.check_output([str(binary),"--version"],text=True).strip()
    assert version.splitlines()[0]=="GitHub Copilot CLI 1.0.112."
    report = {"kind":"host_hook_contract_characterization_not_native_enforcement_qualification","copilot_version":version,
              "source_sha":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
              "copilot_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"external_provider_requests":0,"cases":[],"passed":False}
    report.update(HOST.identities(binary))
    try:
        for mode in ["defer","deny","after_deny","exit1","exit2","timeout","malformed","after_exit1"]:
            case=run_case(binary,args.out.parent,mode)
            report["cases"].append(case)
            if not case["passed"]: raise AssertionError("Unexpected pinned hook behavior: "+mode)
        report["passed"]=True
    finally:
        args.out.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
