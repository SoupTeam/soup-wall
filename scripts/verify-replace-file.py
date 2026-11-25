#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native Ubuntu stdio/daemon replacement qualification; default is inert.

All data and Agent homes are disposable. Positive execution uses an unmodified
production binary and the existing public rule classifier. No provider calls.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PROFILE = "sw-native/replace-file/linux-private-root-child/1"
EXCLUSION = "operator-private-sole-writer+directory-flock/1"
OLD = "Original output: 7 widgets.\n"
NEW = "Updated output: 9 widgets.\n"
CASES = ("exact-replacement", "stale-digest", "stale-identity", "unauthorized-action",
         "ask-reject", "ask-expiry", "ask-replay", "old-change-pending", "new-change-pending",
         "target-substitution", "root-substitution", "symlink", "hardlink", "special-file",
         "no-exclusion", "cancellation", "daemon-restart", "competing-same-version",
         "stage-fault", "publication-fault", "committed-error", "result-withheld")
COMMITTED = {"exact-replacement", "ask-replay", "competing-same-version", "committed-error", "result-withheld"}
FAULT_ERRORS = {"stage-fault":"replace_stage_write_failed", "publication-fault":"replace_publish_failed",
                "committed-error":"replace_committed_directory_sync_failed"}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load("sou54_helpers", ROOT / "scripts/verify-sou54-create-file.py")
fixture = load("sou159_fixture", ROOT / "scripts/fixtures/mcp_replace_file_probe_server.py")
sha = base.sha
canonical = base.canonical
require = base.require


def snapshot(path):
    m = path.lstat()
    row = {"device": m.st_dev, "inode": m.st_ino, "mode": m.st_mode,
           "size": m.st_size, "links": m.st_nlink}
    if stat.S_ISREG(m.st_mode):
        require(m.st_size <= 4096, "snapshot byte bound")
        row["sha256"] = sha(path.read_bytes())
    return row


def registry(root, target, plan, classifier_sha256, binary_sha256, exclusion=EXCLUSION):
    tools = []
    for tool in fixture.TOOLS:
        replacing = tool["name"] == "replace_result"
        schema = sha(canonical(tool["inputSchema"]))
        policy = {"profile": {"server_id": "sou159", "tool_name": tool["name"], "schema_sha256": schema,
                              "selectors": [{"pointer": "/path", "kind": "path"}]},
                  "workspace": str(root), "cwd": str(root), "executor_sha256": sha(PROFILE.encode()) if replacing else binary_sha256,
                  "classifier_sha256": classifier_sha256,
                  "allowed_resources": [{"kind": "path", "canonical": str(target)}]}
        if replacing:
            policy["execution"] = {"operation": "replace_file", "action": "write", "executor_profile": PROFILE,
                "max_content_bytes": 4096, "path_selector": "/path", "content_selector": "/content",
                "response_contract": "sw-native/response/text/1", "replacement": {
                    "contract_version": "sw-native/replace-file/binding/1", "root": plan["root"],
                    "writer_exclusion": exclusion, "old_sha256_selector": "/old_sha256", "old_identity_selector": "/old_identity"}}
        tools.append({"name": tool["name"], "schema_sha256": schema, "action_class": "destructive" if replacing else "read_only",
                      "result_provenance": "untrusted", "egress": [], "resource_policy": policy})
    return {"contract_version": "sw-native/1", "registry_id": "sou159-private-replacement-v1", "tools": tools}


def pending(home, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        records = list((home / ".agentfw/native-pending").glob("*.json"))
        for path in records:
            row = base.strict_json(path.read_bytes())
            if row.get("state") == "pending":
                return row
        time.sleep(.02)
    raise ValueError("no bounded pending approval")


def operator(binary, env, action, record):
    args = [str(binary), "native-approval", action, record["pending_id"]]
    if action == "approve":
        args += ["--binding", record["binding_sha256"]]
    result = subprocess.run(args, env=env, capture_output=True, timeout=10)
    require(result.returncode == 0, "operator command refused")


def payload(raw):
    if not raw:
        return None
    reply = base.strict_json(raw)
    content = reply.get("result", {}).get("content", [])
    if content:
        try:
            return base.strict_json(content[0]["text"])
        except (ValueError, KeyError):
            pass
    return None


def run_case(binary, name, libraries):
    row = {"case": name, "status": "incomplete", "committed": False}
    daemon = collector = other = None
    displaced = None
    with tempfile.TemporaryDirectory(prefix="sou159-", dir=Path(tempfile.gettempdir()).resolve()) as tmp:
        root = Path(tmp).resolve()
        home = root / "home"; home.mkdir(mode=0o700)
        workspace = root / "output"; workspace.mkdir(mode=0o700)
        target = workspace / "result.txt"; target.write_text(OLD); target.chmod(0o600)
        sentinel = root / "outside-sentinel"; sentinel.write_text("OUTSIDE-UNCHANGED")
        content = root / "new.txt"; content.write_text(NEW)
        env = base.private_environment(home)
        installed = subprocess.run([str(binary), "install"], env=env, cwd=root, capture_output=True, timeout=20)
        require(installed.returncode == 0, "disposable install failed")
        preview = subprocess.run([str(binary), "replace-file-preview", "--workspace", str(workspace),
            "--target", str(target), "--content-file", str(content)], env=env, capture_output=True, timeout=10)
        require(preview.returncode == 0, "read-only preview failed")
        plan = base.strict_json(preview.stdout)
        require(plan["executing"] is False and plan["old_sha256"] == sha(OLD.encode()) and plan["new_sha256"] == sha(NEW.encode()), "preview changed bytes/authority")
        require(OLD.encode() not in preview.stdout and NEW.encode() not in preview.stdout, "preview exposed content")
        args = {"path": "result.txt", "content": NEW, "old_sha256": plan["old_sha256"], "old_identity": plan["old_identity"]}
        classifier = ROOT / "rule_baseline/rule_baseline.py"
        declarations = registry(workspace, target, plan, sha(classifier.read_bytes()), sha(binary.read_bytes()),
                                exclusion="unsupported" if name == "no-exclusion" else EXCLUSION)
        reg = canonical(declarations); (root / "registry.json").write_bytes(reg)
        action = "deny" if name == "unauthorized-action" else "ask"
        policy = f"agent_policies:\n  - name: exact-replacement\n    when: {{ action_class: destructive }}\n    action: {action}\ndefault: allow\n"
        (root / "policy.yaml").write_text(policy)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        config = {"port": port, "enforce": True, "policy": str(root / "policy.yaml"), "native": {
            "registry_path": str(root / "registry.json"), "registry_sha256": sha(reg),
            "approval": {"ttl_seconds": 1 if name == "ask-expiry" else 30}}}
        if name=="result-withheld":
            # Tighten only this disposable daemon's retained-source cap.
            # Invocation/Ask input limits remain unchanged, while recording
            # the result's nonempty Native provenance must fail after commit.
            # Production defaults and execution policies remain unchanged.
            config["provenance"]={"max_source_bytes":0}
            row["result_refusal_boundary"]="retained_provenance_max_source_0"
        (home / ".agentfw/config.yaml").write_bytes(canonical(config))
        row.update(registry_sha256=sha(reg), policy_sha256=sha(policy.encode()),
                   config_sha256=sha(canonical(config)), classifier_sha256=sha(classifier.read_bytes()),
                   old=snapshot(target), outside_before=snapshot(sentinel))
        if name == "stale-digest": args["old_sha256"] = "a" * 64
        if name == "stale-identity": args["old_identity"]["inode"] += 1
        if name == "symlink": target.unlink(); target.symlink_to(sentinel)
        if name == "hardlink": target.unlink(); os.link(sentinel, target)
        if name == "special-file": target.unlink(); os.mkfifo(target, 0o600)
        expected = snapshot(target)
        # A hardlink fixture intentionally changes link metadata during setup;
        # the independent outside baseline starts before the broker action.
        row["outside_before"]=snapshot(sentinel)
        try:
            with (root / "daemon.log").open("wb") as dlog, (root / "collector.log").open("wb") as clog:
                daemon = subprocess.Popen([str(binary), "serve"], env=env, cwd=root, stdout=dlog, stderr=dlog, start_new_session=True)
                if name == "no-exclusion":
                    require(daemon.wait(timeout=10) != 0, "missing exclusion was accepted")
                    row.update(status="pass", unsupported=True, target_unchanged=snapshot(target)==expected,
                               outside_unchanged=snapshot(sentinel)==row["outside_before"], child_dispatches=0, cleanup_verified=True)
                    return row
                require(base.healthy(port, daemon), "daemon startup failed")
                cenv = dict(env, AGENTFW_WORKSPACE=str(workspace), AGENTFW_CLASSIFIER="rule-baseline",
                            AGENTFW_RULE_BASELINE=str(classifier), AGENTFW_CLASSIFIER_PYTHON=sys.executable)
                if name in libraries:
                    cenv["LD_PRELOAD"] = str(libraries[name]); row["fault_library_sha256"] = sha(libraries[name].read_bytes())
                ledger = root / "child.jsonl"
                def start(ledger):
                    c = base.Collector([str(binary), "mcp", "--native-admission", "--id", "sou159",
                        "--native-approval-wait-seconds", "8", "--", sys.executable, "-I", "-u",
                        str(ROOT / "scripts/fixtures/mcp_replace_file_probe_server.py"), "--ledger", str(ledger)], cenv, workspace, clog,
                        capture_stderr=True)
                    require(c.send({"jsonrpc":"2.0","id":"init","method":"initialize","params":{
                        "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou159-witness","version":"1"}}}), "initialize failed")
                    listing = c.send({"jsonrpc":"2.0","id":"list","method":"tools/list"})
                    require(base.strict_json(listing)["result"]["tools"] == fixture.TOOLS, "manifest changed")
                    return c
                collector = start(ledger)
                request = base.frame("replace-1", "replace_result", args)
                denied_early = name in {"stale-digest", "stale-identity", "unauthorized-action", "symlink", "hardlink", "special-file"}
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    future = pool.submit(collector.send, request)
                    if not denied_early:
                        record = pending(home); row["binding_sha256"] = record["binding_sha256"]
                        row["approved_bindings"] = [record["binding_sha256"]]
                        require(snapshot(target)==expected and not list(workspace.glob(".soup-replace-*")), "mutation before approval")
                        details = record["resource_details"]
                        require(details["old_content_sha256"] == plan["old_sha256"] and details["new_content_sha256"] == plan["new_sha256"], "approval changed content")
                        require(details["old_identity"] == plan["old_identity"], "approval changed object")
                        if name == "ask-reject": operator(binary, env, "reject", record)
                        elif name == "ask-expiry": time.sleep(1.3)
                        elif name == "cancellation": collector.process.stdin.close()
                        elif name == "daemon-restart":
                            base.stop_owned(daemon); daemon=None
                            daemon=subprocess.Popen([str(binary),"serve"],env=env,cwd=root,stdout=dlog,stderr=dlog,start_new_session=True)
                            require(base.healthy(port,daemon),"restart failed")
                        else:
                            if name == "old-change-pending": target.write_text("changed by operator"); expected=snapshot(target)
                            if name == "target-substitution":
                                displaced=root/"previous";target.rename(displaced);row["displaced_before"]=snapshot(displaced)
                                target.write_text("operator replacement"); target.chmod(0o600); expected=snapshot(target)
                            if name == "root-substitution":
                                workspace.rename(root/"previous-output"); workspace.mkdir(mode=0o700)
                                displaced=root/"previous-output/result.txt";row["displaced_before"]=snapshot(displaced)
                                target.write_text("operator root replacement");target.chmod(0o600);expected=snapshot(target)
                            if name == "new-change-pending":
                                changed=json.loads(json.dumps(request));changed["id"]="changed";changed["params"]["arguments"]["content"]="different unapproved bytes"
                                collector.send(changed,reply=False)
                            if name == "competing-same-version":
                                other=start(root/"child2.jsonl");second=pool.submit(other.send,base.frame("replace-2","replace_result",args))
                                deadline=time.monotonic()+8
                                while len(list((home/".agentfw/native-pending").glob("*.json")))<2 and time.monotonic()<deadline:time.sleep(.02)
                                records=[base.strict_json(p.read_bytes()) for p in (home/".agentfw/native-pending").glob("*.json")]
                                require(len(records)==2,"second pending missing")
                                row["approved_bindings"] = [r["binding_sha256"] for r in records]
                                for r in records: operator(binary,env,"approve",r)
                            elif name != "new-change-pending": operator(binary, env, "approve", record)
                    raw=future.result(timeout=15)
                    data=payload(raw)
                    row["response_sha256"]=sha(raw or b"")
                    row["refusal_codes"]=[]
                    if raw:
                        for item in base.strict_json(raw).get("result",{}).get("content",[]):
                            text=item.get("text","")
                            if text.startswith("Soup Wall withheld MCP "):
                                codes=re.search(r"\(([^()]*)\)$",text)
                                if codes:
                                    row["refusal_codes"]=[c.strip() for c in codes[1].split(",") if re.fullmatch(r"[a-zA-Z0-9_:-]{1,128}",c.strip())]
                    if data:
                        row.update(result_success=data.get("success"), executor_error=data.get("error"), staged_bytes=data.get("staged_bytes"))
                    if name=="competing-same-version":
                        second_raw=second.result(timeout=15);values=[payload(raw),payload(second_raw)]
                        require(sum(v is not None and v.get("committed") is True for v in values)==1,"competing publications not single winner")
                    success=name in COMMITTED
                    if success:
                        require(target.read_text()==NEW and target.stat().st_ino!=plan["old_identity"]["inode"],"exact replacement effect missing")
                        if name not in {"competing-same-version","result-withheld"}:require(data and data.get("committed") is True,"committed outcome missing")
                        if name=="committed-error": require(data.get("success") is False,"post-commit fault reported success")
                        if name=="result-withheld":
                            require("resource_replacement_committed" in row["refusal_codes"],"withheld result lost the committed distinction")
                            row["result_withheld"]=True
                        row["committed"]=True
                    else: require(snapshot(target)==expected,"denied/unapproved target mutated")
                    if name=="ask-replay":
                        again=collector.send(base.frame("replace-replay","replace_result",args))
                        require(payload(again) is None or payload(again).get("committed") is not True,"replayed old version committed")
                    if name not in {"cancellation","daemon-restart","new-change-pending","root-substitution","special-file","symlink","hardlink","result-withheld"}:
                        follow=collector.send(base.frame("follow","read_document",{"path":str(target)}))
                        require(follow and not base.strict_json(follow).get("result",{}).get("isError",False)
                                and target.read_text().strip().encode() in follow,"useful follow-up refused")
                        row["followup_read"]=True
                row["collector_closure"]=collector.close();collector=None
                if other: row["other_closure"]=other.close();other=None
                if displaced:
                    row["displaced_after"]=snapshot(displaced)
                    require(row["displaced_after"]==row["displaced_before"],"displaced original object mutated")
                    if name=="root-substitution":
                        require(sorted(p.name for p in displaced.parent.iterdir())==["result.txt"],"displaced root inventory changed")
                    row["displaced_unchanged"]=True
                row["child_dispatches"]=len(ledger.read_bytes().splitlines())
                if (root/"child2.jsonl").exists():row["child_dispatches"]+=len((root/"child2.jsonl").read_bytes().splitlines())
                require(row["child_dispatches"]==0,"discovery child was invoked")
                audit=base.json_lines((home/".agentfw/audit.jsonl").read_bytes())
                publications=[r for r in audit if r.get("event")=="native_publish" and r.get("tool")=="replace_result" and r.get("released") is True]
                row["publication_gates"]=len(publications)
                row["publication_bindings"]=[r.get("binding_sha256") for r in publications]
                row["publication_binding_matches"]=all(b in row.get("approved_bindings",[]) for b in row["publication_bindings"])
                if name in COMMITTED or name=="publication-fault":
                    require(row["publication_gates"]==1 and row["publication_binding_matches"],"missing/crossed native publication gate")
                row.update(after=snapshot(target),target_unchanged=snapshot(target)==expected,
                           outside_unchanged=snapshot(sentinel)==row["outside_before"],
                           staging_entries=sum(1 for _ in workspace.glob(".soup-replace-*")))
                require(row["outside_unchanged"] and row["staging_entries"]==0,"outside effect or staging residue")
                require(row["collector_closure"]["reader_joined"] and not row["collector_closure"]["forced_cleanup"],"collector cleanup incomplete")
                if "other_closure" in row:
                    require(row["other_closure"]["reader_joined"] and not row["other_closure"]["forced_cleanup"],"competing collector cleanup incomplete")
                row.update(cleanup_verified=True,status="pass")
        except (OSError,ValueError,KeyError,TypeError,queue.Empty,subprocess.SubprocessError,concurrent.futures.TimeoutError) as error:
            row.update(status="fail",error_type=type(error).__name__,error_code=str(error)[:160])
        finally:
            if collector:
                collector.close()
            if other:
                other.close()
            base.stop_owned(daemon)
    return row


def validate(report):
    require(report["platform"]=="Linux" and len(report["source_commit"])==40 and len(report["binary_sha256"])==64,"unqualified source/platform")
    rows=report["cases"]
    require([r["case"] for r in rows]==list(CASES),"missing/duplicate/reordered case inventory")
    for r in rows:
        require(r["status"]=="pass" and r["child_dispatches"]==0 and r["outside_unchanged"] and r["cleanup_verified"],"runtime evidence failed")
        require(r["committed"] is (r["case"] in COMMITTED),"missing/wrong expected effect")
        if r["committed"]:
            require(r["after"]["sha256"]==sha(NEW.encode()) and r["after"]["inode"]!=r["old"]["inode"],"wrong committed effect")
            require(r.get("publication_gates")==1 and r.get("publication_binding_matches") is True,"publication receipt correlation missing")
            require(len(r.get("publication_bindings",[]))==1 and r["publication_bindings"][0] in r.get("approved_bindings",[]),"publication did not match either exact approved call")
        else: require(r["target_unchanged"],"unapproved mutation")
        if r["case"] in {"target-substitution","root-substitution"}:
            require(r.get("displaced_unchanged") is True and r.get("displaced_before") and r["displaced_before"]==r.get("displaced_after"),"displaced object preservation missing")
        if r["case"] in FAULT_ERRORS:
            require(r.get("executor_error")==FAULT_ERRORS[r["case"]] and r.get("result_success") is False
                    and len(r.get("fault_library_sha256",""))==64,"wrong/missing fault evidence")
        if r["case"]=="stage-fault": require(r.get("staged_bytes")==5,"partial write accounting changed")
        if r["case"]=="result-withheld":
            require(r.get("result_withheld") is True and {"resource_replacement_committed","native_provenance_unrecordable","native_provenance_source"}.issubset(r.get("refusal_codes",[])),"withheld commit accounting missing")
    return {"acceptance_pass":True,"cases":len(rows),"production_stdio":True,"child_dispatches":0}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true");parser.add_argument("--agentfw",type=Path)
    parser.add_argument("--output",type=Path);parser.add_argument("--fault-libraries",type=Path)
    args=parser.parse_args()
    if not args.run: print(json.dumps({"executing":False,"cases":list(CASES)}));return 0
    require(platform.system()=="Linux","native Linux required")
    require(args.agentfw and args.output and args.fault_libraries,"explicit inputs required")
    source=base.source_snapshot(ROOT)
    require(not source["tracked_dirty"],"source is dirty")
    report={"platform":"Linux","source_commit":source["commit"],"binary_sha256":sha(args.agentfw.read_bytes()),"cases":[]}
    libraries={name:args.fault_libraries/(name+".so") for name in ["stage-fault","publication-fault","committed-error"]}
    for name in CASES:
        report["cases"].append(run_case(args.agentfw.resolve(),name,libraries))
        args.output.write_bytes(canonical(report)+b"\n")
        print(name+": "+report["cases"][-1]["status"],flush=True)
        if report["cases"][-1]["status"]!="pass":return 1
    report["acceptance"]=validate(report);args.output.write_bytes(canonical(report)+b"\n");return 0


if __name__=="__main__":
    raise SystemExit(main())
