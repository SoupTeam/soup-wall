#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-source Linux Ask controls for the pinned ORIGINAL create-only server.

Uses only newly owned homes/workspaces and explicit synthetic operator decisions.
No model, live provider, arbitrary executor or expanded write authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sou83_approval_base", ROOT / "scripts/verify-sou105-selected-approval.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
B = S.BASE
require, write, sha = B.require, B.write, B.sha
FORMAT = "sw-mcp/original-create-approval-acceptance/1"
CASES = ("approve", "reject", "wrong_binding", "expire", "timeout", "cancel", "default", "deny",
         "classifier_change", "profile_change", "root_replace", "competing_target", "symlink_target",
         "disconnect", "collector_death", "restart", "lease_expiry")
CONTENT = "SOU83 explicitly approved exact bytes: café, қазақша, 🥣.\n"


def frame(identifier, leaf, content=CONTENT):
    return B.call(identifier, {"path": "/workspace/" + leaf, "content": content}, "write_file")


def snapshot(root):
    return B.snapshot(root)


def worker_events(stderr):
    return B.events(stderr, "mcp_original_create_worker")


def inspect_pending(rig, waiting, request, client):
    text = S.command(rig.args, rig.env, "native-approval", "inspect", waiting["pending_id"])
    record = S.inspected_output(text, waiting["pending_id"], waiting["binding_sha256"])
    selected, resource = record["selected_invocation"], record["resource_details"]
    args = request["params"]["arguments"]
    info = rig.workspace.stat()
    require(record["args"] == args and selected["host_call_id"] == request["id"], "pending target/host ID changed")
    require(selected["request_sha256"] == hashlib.sha256(client.sent[-1]).hexdigest(), "pending raw request changed")
    expected = {"contract_version": "sw-mcp/original-create-resource/1", "workspace": str(rig.workspace.resolve()),
                "device": info.st_dev, "inode": info.st_ino, "target": args["path"],
                "content_sha256": hashlib.sha256(args["content"].encode()).hexdigest(),
                "content_bytes": len(args["content"].encode()), "must_be_absent": True}
    require(resource == expected and selected["original_create"] == expected, "typed create evidence is not exact")
    require("content" not in resource, "resource evidence leaked raw content")
    return record


def approve(rig, waiting, success=True):
    return S.command(rig.args, rig.env, "native-approval", "approve", waiting["pending_id"],
                     "--binding", waiting["binding_sha256"], success=success)


def assert_refused(client, identifier=50):
    response, _ = client.receive(timeout=10)
    require(response.get("id") == identifier and B.refused(response), "terminal refusal lost its request identity")


def useful_read(client, identifier):
    reply, _ = client.exchange(B.call(identifier, {"path": "/workspace/notes.txt"}))
    require(not B.refused(reply) and "7 red widgets" in B.result_text(reply), "same-relay useful read was lost")


def verify_publication(root, leaf, expected=CONTENT):
    target = root / leaf
    info = target.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            "approved file is not a private one-link regular inode")
    require(target.read_bytes() == expected.encode(), "approved file bytes differ")
    return {"leaf": leaf, "bytes": info.st_size, "sha256": sha(target), "mode": "0600", "links": 1}


def audit_publication(rig, leaf, original_raw):
    raw = (rig.home / ".agentfw/audit.jsonl").read_bytes()
    require(len(raw) <= 8 * 1024 * 1024, "owned audit witness exceeded bound")
    rows = [json.loads(line) for line in raw.splitlines() if line]
    calls = [row for row in rows if row.get("event") == "native_call" and row.get("tool") == "write_file"
             and row.get("released") is True and row.get("resource_details", {}).get("target") == "/workspace/" + leaf]
    require(len(calls) == 1, "typed native call evidence is absent or repeated")
    call = calls[0]
    require(call.get("selected_invocation_sha256") and call.get("binding_sha256") and call.get("call_id"), "native resource binding absent")
    require(call["resource_details"]["content_sha256"] == hashlib.sha256(CONTENT.encode()).hexdigest(), "audited write bytes changed")
    results = [row for row in rows if row.get("event") == "native_result" and row.get("call_id") == call["call_id"]]
    require(len(results) == 1 and results[0].get("released") is True
            and results[0].get("binding_sha256") == call["binding_sha256"]
            and results[0].get("content_sha256") == hashlib.sha256(original_raw).hexdigest(),
            "original result was not independently inspected under the same resource binding")
    return {"call_id": call["call_id"], "binding_sha256": call["binding_sha256"],
            "selected_invocation_sha256": call["selected_invocation_sha256"],
            "original_result_sha256": results[0]["content_sha256"], "resource_details": call["resource_details"]}


def owned_collector(client, binary):
    client.process_witness.sample()
    matches = []
    for pid, start in client.process_witness.observed:
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if B.ProcessWitness.identity(pid) == start and argv[0] == os.fsencode(binary) and b"mcp" in argv:
                matches.append(pid)
        except OSError:
            pass
    require(len(matches) == 1, "one kernel-identified owned collector required")
    return matches[0]


def qualify(rig, report):
    # Unwrapped original calibration uses the same bytes and exact installed pin.
    direct, _, _ = rig.client("direct-calibration", direct=True)
    samples = []
    for i in range(3):
        started = time.monotonic_ns()
        reply, raw = direct.exchange(B.call(i + 20, {"path": str(rig.workspace / f"calibration-{i}.txt"), "content": CONTENT}, "write_file"))
        samples.append(time.monotonic_ns() - started)
        require(not B.refused(reply) and (rig.workspace / f"calibration-{i}.txt").read_bytes() == CONTENT.encode(), "unwrapped original write failed")
        (rig.workspace / f"calibration-{i}.txt").unlink()
    require(direct.close() == 0, "unwrapped original did not quiesce")
    report["unwrapped_write_rpc_ns"] = samples
    for case in CASES:
        if case in ("expire", "timeout"):
            rig.stop()
            rig.config["native"]["approval"]["ttl_seconds"] = 1 if case == "expire" else 30
            write(rig.home / ".agentfw/config.yaml", rig.config)
            rig.start()
        elif case == "deny":
            rig.stop(); rig.start(deny=True)
        elif case in ("classifier_change", "lease_expiry"):
            rig.stop()
            rig.config["native"]["approval"]["ttl_seconds"] = 30
            write(rig.home / ".agentfw/config.yaml", rig.config)
            rig.start()
        leaf = case + ".txt"
        request = frame(50, leaf)
        client, trace, stderr = rig.client(case, wait=1 if case == "timeout" else (0 if case == "default" else 25))
        before = snapshot(rig.workspace)
        row = {"case": case, "passed": False, "before": before}
        report["cases"].append(row)
        client.send(request)
        restored = None
        if case in ("default", "deny"):
            assert_refused(client)
            S.pending(rig.args, rig.env, empty=True)
        else:
            waiting = S.pending(rig.args, rig.env)
            record = inspect_pending(rig, waiting, request, client)
            row["resource_details"] = record["resource_details"]
            row["broker_ttl_ms"] = record["expires_at_ms"] - record["created_at_ms"]
            time.sleep(.15)
            require(snapshot(rig.workspace) == before and not worker_events(stderr)
                    and not list(rig.home.glob(".agentfw-original-create-*")), "original writer or file effect appeared before approval")
            # The write's pending Ask may not stall an independent readonly tool.
            useful_read(client, 60)
            require(snapshot(rig.workspace) == before and not worker_events(stderr)
                    and not list(rig.home.glob(".agentfw-original-create-*")), "readonly continuation activated pending writer")
            row["preapproval_publications"] = 0
            row["preapproval_original_workers"] = 0
            if case == "approve":
                approve(rig, waiting)
                response, original_raw = S.approved_response(client, row)
                require(response.get("id") == 50 and not B.refused(response), "approved original write failed")
                row["publication"] = verify_publication(rig.workspace, leaf)
                row["native_resource_audit"] = audit_publication(rig, leaf, original_raw)
                require(len(worker_events(stderr)) == 1, "approved write did not use exactly one original worker")
                approve(rig, waiting, success=False)
                client.send(frame(50, "replay.txt", "unapproved"))
                assert_refused(client)
                require(not (rig.workspace / "replay.txt").exists(), "spent host identity published again")
                useful_read(client, 61)
                # New authority after a terminal outcome, same original collector.
                client.send(frame(51, "fresh-after-approve.txt"))
                second = S.pending(rig.args, rig.env)
                approve(rig, second)
                require(not B.refused(client.receive()[0]), "fresh create continuation failed")
                row["fresh_publication"] = verify_publication(rig.workspace, "fresh-after-approve.txt")
                require(len(worker_events(stderr)) == 2, "fresh invocation reused or duplicated its worker")
            elif case in ("reject", "wrong_binding"):
                if case == "wrong_binding":
                    S.command(rig.args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", "0" * 64, success=False)
                S.command(rig.args, rig.env, "native-approval", "reject", waiting["pending_id"])
                assert_refused(client)
            elif case == "cancel":
                client.send(B.cancel(50)); assert_refused(client)
            elif case in ("expire", "timeout"):
                assert_refused(client)
                require(row["broker_ttl_ms"] == (1000 if case == "expire" else 30000), "expiry and wait timeout were conflated")
                approve(rig, waiting, success=False)
            elif case in ("classifier_change", "profile_change"):
                asset = rig.classifier if case == "classifier_change" else rig.installed / "profile.json"
                saved = asset.read_bytes()
                try:
                    if case == "classifier_change": asset.write_bytes(saved + b"\n# owned classifier drift\n")
                    else:
                        changed = json.loads(saved); changed["runtimeSha256"] = "0" * 64; write(asset, changed)
                    approve(rig, waiting); assert_refused(client)
                finally:
                    asset.write_bytes(saved)
            elif case == "root_replace":
                restored = rig.root / "original-workspace"
                rig.workspace.rename(restored)
                rig.workspace.mkdir(mode=0o700)
                approve(rig, waiting); assert_refused(client)
                require(set(snapshot(rig.workspace)) == {"."} and snapshot(restored) == before, "root replacement transferred write authority")
                rig.workspace.rmdir(); restored.rename(rig.workspace); restored = None
            elif case in ("competing_target", "symlink_target"):
                target = rig.workspace / leaf
                sentinel = rig.root / "outside-sentinel"
                sentinel.write_text("external inventory unchanged")
                if case == "competing_target": target.write_text("operator owned")
                else: target.symlink_to(sentinel)
                interference = snapshot(rig.workspace)
                approve(rig, waiting); assert_refused(client)
                require(snapshot(rig.workspace) == interference and sentinel.read_text() == "external inventory unchanged", "competing inventory was overwritten")
                target.unlink()
            elif case == "disconnect":
                client.process.stdin.close()
            elif case == "collector_death":
                row["fault"] = B.signal_owned_create_process(client, owned_collector(client, rig.args.agentfw))
            elif case == "restart":
                rig.stop(); rig.start(); approve(rig, waiting, success=False)
            elif case == "lease_expiry":
                pid = owned_collector(client, rig.args.agentfw)
                descriptor = os.pidfd_open(pid, 0)
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGSTOP, None, 0)
                    time.sleep(3)
                finally:
                    signal.pidfd_send_signal(descriptor, signal.SIGCONT, None, 0)
                    os.close(descriptor)
                approve(rig, waiting, success=False)
            S.pending(rig.args, rig.env, timeout=8, empty=True)
        client.close()
        if restored is not None:
            raise ValueError("root replacement control did not restore its owned workspace")
        if case != "approve":
            require(snapshot(rig.workspace) == before and not worker_events(stderr)
                    and not list(rig.home.glob(".agentfw-original-create-*")), "refused/expired/cancelled create produced an effect or worker")
        require(case in ("collector_death", "restart", "lease_expiry") or client.process.returncode == 0, "ordinary terminal continuation did not close cleanly")
        row["after"] = snapshot(rig.workspace)
        row["workers"] = len(worker_events(stderr))
        row["trace_sha256"] = sha(trace)
        row["raw_trace_exported"] = False
        row["passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    for name in ("agentfw", "node", "npm", "git", "bwrap", "git-launcher", "strace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    require(not args.output.is_relative_to(ROOT), "new evidence directory must be outside source")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"format": FORMAT, "status": "failed", "cases": [], "skipped": 0,
              "raw_traces_exported": False, "live_provider_used": False}
    rig = None
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "actual Linux x86-64 required")
        for name in ("agentfw", "node", "npm", "git", "bwrap", "git_launcher", "strace"):
            setattr(args, name, getattr(args, name).resolve(strict=True))
        report["source_before"] = B.source()
        require(report["source_before"]["commit"] == args.expected_commit and not report["source_before"]["dirty"], "exact clean source required")
        report["files"] = {name: sha(getattr(args, name)) for name in ("agentfw", "node", "npm", "git", "bwrap", "git_launcher", "strace")}
        rig = S.Rig(args, args.output / "create", "create")
        report["installation"] = json.loads((rig.installed / "installation.json").read_text())
        qualify(rig, report)
        report["cleanup"] = rig.close(); rig = None
        report["source_after"] = B.source()
        require(report["source_after"] == report["source_before"], "qualification changed source")
        require([row["case"] for row in report["cases"]] == list(CASES) and all(row["passed"] for row in report["cases"]), "missing original-create acceptance controls")
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)[:1000]
    finally:
        if rig is not None:
            try: report["cleanup"] = rig.close()
            except Exception as error: report["cleanup_error"] = str(error)[:500]
        write(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
