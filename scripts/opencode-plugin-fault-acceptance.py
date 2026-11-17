#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Characterize the pinned real host/plugin transport using only owned fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("opencode_host", ROOT / "scripts/opencode-mcp-acceptance.py")
HOST = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HOST)


def run_case(binary, parent, mode):
    with tempfile.TemporaryDirectory(prefix=mode + "-", dir=parent) as tmp:
        root = Path(tmp)
        home = root / "home"
        home.mkdir(mode=0o700)
        workspace = root / "workspace"
        workspace.mkdir()
        marker = "OPENCODE_OWNED_RESULT_CANARY"
        (workspace / "inventory.txt").write_text(marker)
        ledger = root / "ledger.jsonl"
        receiver = HOST.DEMO.Receiver()
        fake = root / "fake-bridge"
        # This is a transport-fault fixture, not a replacement native decision maker.
        fake.write_text("#!/usr/bin/python3\nimport json,sys,time\nframe=json.load(sys.stdin)\nmode=" + repr(mode) + "\n"
                        "if mode=='exit1': sys.exit(1)\n"
                        "if mode=='timeout': time.sleep(10)\n"
                        "if mode=='malformed': print('invalid'); sys.exit(0)\n"
                        "print(json.dumps({'decision':'deny','reason':'Owned refusal'} if mode=='deny' or (mode=='after_deny' and frame['phase']=='after') else {}))\n")
        fake.chmod(0o700)
        steps = [("demo_read_document", {"name":"inventory"}),
                 ("demo_send_http", {"url":receiver.url,"body":"owned delivery witness"})]
        provider = HOST.Provider(steps)
        plugin = ROOT / "scripts/soup-wall-opencode.mjs" if mode != "missing_plugin" else root / "absent.mjs"
        config = {"permission":"allow","autoupdate":False,"share":"disabled","enabled_providers":["owned"],
            "model":"owned/fixture","small_model":"owned/fixture","plugin":[plugin.as_uri()],
            "provider":{"owned":{"npm":"@ai-sdk/openai-compatible","name":"Owned", "options":{"baseURL":provider.url+"/v1","apiKey":"owned-synthetic"},
                        "models":{"fixture":{"name":"Fixture","tool_call":True,"limit":{"context":32768,"output":4096}}}}},
            "mcp":{"demo":{"type":"local","command":["/usr/bin/python3","-I",str(HOST.DEMO.FIXTURE),"--notes",str(workspace),"--ledger",str(ledger),"--recipient",receiver.url]}}}
        cfg = root / "opencode.json"
        cfg.write_text(json.dumps(config))
        env = {"HOME":str(home),"PATH":"/usr/bin:/bin","XDG_CONFIG_HOME":str(home/"config"),"XDG_DATA_HOME":str(home/"data"),
               "XDG_CACHE_HOME":str(home/"cache"),"XDG_STATE_HOME":str(home/"state"),"OPENCODE_CONFIG":str(cfg),
               "OPENCODE_DISABLE_PROJECT_CONFIG":"1","OPENCODE_DISABLE_MODELS_FETCH":"1","OPENCODE_DISABLE_AUTOUPDATE":"1",
               "OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER":"1","NO_PROXY":"127.0.0.1,localhost",
               "SOUP_WALL_AGENTFW":str(fake),"SOUP_WALL_HOME":str(home),"SOUP_WALL_BINDING":str(root/"unused-binding")}
        try:
            result = subprocess.run([str(binary),"run","--model","owned/fixture","--format","json","--title","Owned plugin fault","Run owned fixture."],
                                    env=env,cwd=workspace,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=60,umask=0o077)
            case = {"case":mode,"host_exit":result.returncode,"provider_requests":len(provider.requests),
                    "executions":len(HOST.DEMO.lines(ledger)),"deliveries":len(receiver.bodies),"result_reached_provider":marker in json.dumps(provider.requests)}
            (parent/(mode+".host.json")).write_text(json.dumps({"stdout":result.stdout,"stderr":result.stderr,"requests":provider.requests},indent=2))
            executed = mode in {"defer", "after_deny", "missing_plugin"}
            released = mode in {"defer", "missing_plugin"}
            case["expected_boundary"] = "plugin_load_failure_not_enforcement" if mode == "missing_plugin" else "transport_characterization"
            case["passed"] = (result.returncode==0 and len(provider.requests)==3 and case["executions"]==(2 if executed else 0)
                              and case["deliveries"]==(1 if executed else 0) and case["result_reached_provider"]==released)
            return case
        finally:
            provider.close()
            receiver.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args = parser.parse_args()
    binary = args.opencode.resolve()
    args.out.parent.mkdir(parents=True,exist_ok=True)
    version = subprocess.check_output([str(binary),"--version"],text=True).strip()
    assert version=="1.19.6"
    report = {"kind":"host_plugin_contract_characterization_not_native_enforcement_qualification","opencode_version":version,
              "source_sha":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
              "opencode_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"external_provider_requests":0,"cases":[],"passed":False}
    report.update(HOST.identities(binary))
    try:
        for mode in ["defer","deny","after_deny","exit1","timeout","malformed","missing_plugin"]:
            case=run_case(binary,args.out.parent,mode)
            report["cases"].append(case)
            if not case["passed"]: raise AssertionError("Unexpected pinned plugin behavior: "+mode)
        report["passed"]=True
    finally:
        args.out.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
