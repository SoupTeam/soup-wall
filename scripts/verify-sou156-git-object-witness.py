#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in native same-image original Git MCP component evidence, not attestation.

Reuse an installation from the accepted Git installer. The enclosing SOU-147
driver retains its unchanged default-route refusal controls separately.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GIT = load("sou156_git", "verify-sou68-real-mcp.py")
BOUNDS = load("sou156_bounds", "reproduce-sou156-git-object-confusion.py")
BASE, INSTALL = GIT.BASE, GIT.INSTALL
require, sha, write = BASE.require, BASE.sha, BASE.write
TEST = "mcp::server_sandbox::object_witness_native_tests::original_git_same_snapshot_component"
CASES = ("original_initialize_discovery", "commit", "plain_blob", "commit_looking_blob",
         "tag_commit", "nested_tag", "local_replay_refused", "direct_tree", "tag_blob",
         "tag_tree", "missing_oid", "revision_grammar", "concurrent_calls",
         "local_cancel_then_fresh", "local_inflight_source_change", "local_wait_before_write", "fresh_capture_after_restore",
         "cleanup_repository_unchanged")
LIMIT = 1_048_576
FORMAT = b"sw-mcp/git-object-witness/1"


def read(path):
    require(path.is_file() and path.stat().st_size <= LIMIT, "bounded evidence file required: " + str(path))
    with path.open("rb") as source:
        data = source.read(LIMIT + 1)
    require(len(data) <= LIMIT, "evidence file grew beyond bound")
    return data


def domain_hash(domain, data):
    return hashlib.sha256(FORMAT + b"\0" + len(domain).to_bytes(8, "big") + domain +
                          len(data).to_bytes(8, "big") + data).digest()


def verify_native(native):
    report = json.loads(read(native / "report.json"))
    require(report.get("format") == "sou156-same-snapshot-component/1" and
            report.get("status") == "pass" and report.get("skipped") == 0 and
            report.get("production_authentication") == "disabled", "incomplete native component record")
    cases = report.get("cases", [])
    require([row.get("case") for row in cases] == list(CASES) and
            all(row.get("passed") is True for row in cases), "missing, duplicated, reordered or failed native case")
    require(report["repository_before"] == report["repository_after"], "owned repository changed")
    require([row.get("directory") for row in report["sessions"]] == ["seed", "same-snapshot", "local-wait", "fresh"],
            "complete ordered session set required")
    main_requests, main_replies = {}, {}
    for session in report["sessions"]:
        cleanup = session.get("cleanup", {}).get("cleanup", {})
        require(all(cleanup.get(key) is True for key in
                    ("process_reaped", "namespace_terminated", "owned_resources_removed")), "owner cleanup unverified")
        require(cleanup.get("runtime_failure") is False and session["cleanup"].get("failed") is False,
                "owner/runtime failed before cleanup")
        directory = native / session["directory"]
        requests = sorted(directory.glob("request-*.jsonl"))
        replies = sorted(directory.glob("response-*.jsonl"))
        require(len(requests) == session["requests"] and len(replies) == session["responses"] and
                len(requests) == len(replies) + 1 and 0 < len(requests) <= 64,
                "original transcript frame set incomplete")
        request_ids, reply_ids, notifications = {}, {}, 0
        for paths, found, request in ((requests, request_ids, True), (replies, reply_ids, False)):
            for path in paths:
                raw = read(path)
                require(raw.endswith(b"\n") and b"\n" not in raw[:-1], "incomplete original wire line")
                value = json.loads(raw)
                require(value.get("jsonrpc") == "2.0", "original wire version")
                if request and "id" not in value:
                    require(value == {"jsonrpc": "2.0", "method": "notifications/initialized"}, "unexpected notification")
                    notifications += 1
                    continue
                identifier = value.get("id")
                require(type(identifier) is int and identifier not in found, "duplicate or missing original ID")
                found[identifier] = (value, raw)
        require(notifications == 1 and set(request_ids) == set(reply_ids), "original transcript correlation incomplete")
        require(sum(len(raw) for _, raw in reply_ids.values()) == session["response_bytes"], "response byte accounting")
        read(directory / "stderr.bin")
        require(json.loads(read(directory / "cleanup.json")) == session["cleanup"], "cleanup record mismatch")
        if session["directory"] == "same-snapshot":
            main_requests, main_replies = request_ids, reply_ids
        if session["directory"] == "local-wait":
            row = next(row for row in cases if row["case"] == "local_wait_before_write")
            require(row["sent_before"] == row["sent_after"] == len(requests) and
                    row["original_request_written"] is False and
                    all(value["method"] != "tools/call" for value, _ in request_ids.values()),
                    "withdrawn local wait wrote original request")
    identities = []
    for name, identifier, kind in (("commit", 10, "commit"), ("plain_blob", 11, "blob"),
                                  ("commit_looking_blob", 12, "blob"), ("tag_commit", 13, "tag"),
                                  ("nested_tag", 14, "tag")):
        claim = next(row["claim"] for row in cases if row["case"] == name)
        request, request_raw = main_requests[identifier]
        reply, reply_raw = main_replies[identifier]
        require(claim["format"] == FORMAT.decode() and claim["operation"] == "git_show" and
                claim["revision"] == request["params"]["arguments"]["revision"] and
                claim["target"]["requested"]["kind"] == kind and
                bytes(claim["schema_sha256"]) == hashlib.sha256(read(
                    ROOT / "profiles/mcp/git-readonly-v1/upstream-tools-list.json")).digest() and
                bytes(claim["request_sha256"]) == domain_hash(b"original-request-wire", request_raw) and
                bytes(claim["result_sha256"]) == domain_hash(b"original-result-wire", reply_raw) and
                claim["result_bytes"] == len(reply_raw) and not reply.get("error") and
                reply["result"].get("isError") is False, "typed claim/original frame binding mismatch")
        identities.append((claim["view_sha256"], claim["view_generation"]))
    require(all(identity == identities[0] for identity in identities), "final cases used different snapshots")
    fresh = report["sessions"][-1]["local_claim"]
    require(fresh["view_sha256"] == identities[0][0] and fresh["view_generation"] != identities[0][1],
            "restored repository did not receive a fresh snapshot generation")
    require(main_replies[10][0]["result"] == main_replies[12][0]["result"] and
            main_requests[10][0]["params"]["arguments"]["revision"] !=
            main_requests[12][0]["params"]["arguments"]["revision"], "original commit/blob ambiguity missing")
    return report


def run(args, retained_controls=None):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "native Linux x86-64 required")
    before = BASE.source()
    require(re.fullmatch(r"[0-9a-f]{40}", args.expected_commit) is not None and
            before["commit"] == args.expected_commit and not before["dirty"], "clean exact source required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new output outside source required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou156-native-component-acceptance/1", "status": "incomplete", "skipped": 0,
              "scope": "local same-image component; no SOU-155 authentication/common join",
              "source_before": before, "driver_sha256": sha(Path(__file__)),
              "existing_refusal_controls": {"route": "default accepted SOU-147 preparation",
                    "witness_override_executed": False, "retained": retained_controls}}
    try:
        profile = json.loads(read(args.profile))
        binaries = {name: Path(getattr(args, name)).resolve(strict=True) for name in
                    ("agentfw", "git", "bwrap", "git_launcher", "sandbox_test_binary")}
        require(all(path.is_file() and os.access(path, os.X_OK) for path in binaries.values()), "explicit executable asset required")
        require(sha(binaries["git"]) == args.git_sha256 == profile["git"]["sha256"] and
                sha(binaries["bwrap"]) == profile["bwrapSha256"] and
                sha(binaries["git_launcher"]) == profile["gitLauncher"]["sha256"], "accepted runtime asset mismatch")
        require(INSTALL.tree_sha(Path(profile["packageRoot"])) == profile["packageTreeSha256"] and
                sha(Path(profile["runtimePath"])) == profile["runtimeSha256"], "installed original closure changed")
        report["assets"] = {name: {"path": str(path), "sha256": sha(path)} for name, path in binaries.items()}
        libraries = profile["libraries"]
        require(1 <= len(libraries) <= 32 and len({row["path"] for row in libraries}) == len(libraries),
                "bounded unique profile library set required")
        require(all(sha(Path(row["path"])) == row["sha256"] for row in libraries), "profile library changed")
        report["libraries"] = libraries
        report["profile_sha256"] = sha(args.profile)
        with tempfile.TemporaryDirectory(prefix="sou156-driver-home-") as temporary:
            home = Path(temporary)
            env = BASE.environment(home)
            env.update(SOU68_SANDBOX_TEST_PROFILE=str(args.profile.resolve()),
                       SOU86_TEST_AGENTFW=str(binaries["agentfw"]), SOU156_TEST_OUTPUT=str(output / "native"))
            listed = BOUNDS.command([str(binaries["sandbox_test_binary"]), TEST, "--exact", "--list"], env, ROOT)
            (output / "test-list.log").write_bytes(listed)
            require(listed.decode().splitlines() == [TEST + ": test", "", "1 test, 0 benchmarks"],
                    "exact native test missing or selected more than once")
            executed = BOUNDS.command([str(binaries["sandbox_test_binary"]), TEST, "--exact", "--ignored", "--nocapture"],
                                      env, ROOT, timeout=180)
            (output / "native-test.log").write_bytes(executed)
            require(re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;", executed) is not None,
                    "native test did not execute exactly once")
        native = verify_native(output / "native")
        require(INSTALL.tree_sha(Path(profile["packageRoot"])) == profile["packageTreeSha256"] and
                sha(args.profile) == report["profile_sha256"] and
                sha(Path(profile["runtimePath"])) == profile["runtimeSha256"] and
                all(sha(Path(row["path"])) == row["sha256"] for row in report["libraries"]) and
                all(sha(Path(row["path"])) == row["sha256"] for row in report["assets"].values()), "assets changed during component test")
        report["native_report_sha256"] = sha(output / "native/report.json")
        report["passed_cases"] = [row["case"] for row in native["cases"]]
        report["source_after"] = BASE.source()
        require(report["source_after"] == before, "source changed during component test")
        report["status"] = "pass"
    except Exception as error:
        if isinstance(error, subprocess.CalledProcessError):
            (output / "failed-command.stdout").write_bytes(error.output or b"")
            (output / "failed-command.stderr").write_bytes(error.stderr or b"")
        report["status"], report["error"] = "fail", type(error).__name__ + ": " + str(error)
    write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "error": report.get("error"),
                      "cases": len(report.get("passed_cases", [])), "report": str(output / "report.json")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "git", "bwrap", "git-launcher", "sandbox-test-binary", "profile", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "test": TEST, "cases": list(CASES), "production_authentication": "disabled"}))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
