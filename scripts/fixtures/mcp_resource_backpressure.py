#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned real-MCP resource fixture for stdout ordering and backpressure.

The first permitted read has already produced an admitted result before these
checks. They do not claim rollback or zero first-call effects/released bytes.
"""
from __future__ import annotations

import argparse
import array
import fcntl
import importlib.util
import json
import queue
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import termios
import threading
import time

sys.dont_write_bytecode = True
CONTENT = "Inventory: 7 red widgets.\n" * 8000
MODES = ("complete", "partial", "cancel", "sequential", "eof")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args()
    repo, binary, mode = args.repo.resolve(), args.agentfw.resolve(), args.mode
    probe = load(repo / "scripts/verify-sou18-resources.py", "backpressure_resource_probe")
    original_load = probe.load
    witness = {}

    def patched_load(path, name):
        module = original_load(path, name)
        if name != "resource_demo":
            return module
        original_registry = module.registry

        def registry(tools):
            # The resource probe creates the file before calling this function
            # and takes its independent unchanged-byte snapshot after return.
            import os
            file = Path(os.environ["HOME"]) / "workspace/notes/inventory.txt"
            file.write_text(CONTENT, encoding="utf-8")
            return original_registry(tools)

        module.registry = registry
        original_harness = module.Harness

        class NoDrain(original_harness):
            def __init__(self, command, env, stderr):
                self.process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=stderr)
                self.lines, self.received = queue.Queue(), []
                self.audit = Path(env["HOME"]) / ".agentfw/audit.jsonl"

            def records(self):
                return [json.loads(line) for line in self.audit.read_text().splitlines()]

            def take(self):
                raw = self.lines.get(timeout=3)
                if raw is not None:
                    self.received.append(raw)
                return raw

            def send(self, frame, reply=True):
                request = json.loads(frame)
                self.process.stdin.write(frame.encode() + b"\n")
                self.process.stdin.flush()
                if not reply:
                    return None
                if request.get("method") != "tools/call":
                    if not select.select([self.process.stdout], [], [], 3)[0]:
                        raise RuntimeError("fixture handshake timeout")
                    raw = self.process.stdout.readline()
                    self.received.append(raw)
                    return raw
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    rows = self.records()
                    if any(r.get("event") == "native_result" and r.get("released") is True for r in rows):
                        break
                    if self.process.poll() is not None:
                        raise RuntimeError("collector stopped before authentic result Allow")
                    time.sleep(.005)
                else:
                    raise RuntimeError("first native result did not reach Allow")
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    pending = array.array("i", [0])
                    fcntl.ioctl(self.process.stdout.fileno(), termios.FIONREAD, pending, True)
                    if pending[0] > 0:
                        break
                    time.sleep(.005)
                if not 0 < pending[0] < len(CONTENT.encode()):
                    raise RuntimeError("partial stdout backpressure witness missing")
                witness["first_reply_bytes_already_exposed_to_pipe"] = pending[0]
                witness["first_contents_bytes"] = len(CONTENT.encode())
                witness["first_reply_complete_before_second"] = False
                second = dict(request, id="second-before-drain")
                extra = json.dumps(second, separators=(",", ":")) + "\n"
                if mode == "partial":
                    extra = extra[:30]
                elif mode == "cancel":
                    extra = json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": request["id"], "reason": "owned writer fixture"}}) + "\n"
                if mode in {"complete", "partial", "cancel"}:
                    self.process.stdin.write(extra.encode())
                    self.process.stdin.flush()
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        if any(r.get("event") == "native_session_end" for r in self.records()):
                            witness["session_ended_before_drain"] = True
                            break
                        time.sleep(.005)
                    else:
                        witness["session_ended_before_drain"] = False
                elif mode == "eof":
                    self.process.stdin.close()
                # Draining is deliberately delayed until after the overlap or
                # EOF witness. It also unblocks any already-started allowed
                # stdout write; its effects must be reported honestly.
                threading.Thread(target=self._read, daemon=True).start()
                replies = []
                first = self.take()
                if first is not None:
                    replies.append(first)
                if mode == "sequential":
                    first_value = json.loads(first)
                    assert first_value["id"] == request["id"]
                    assert first_value["result"]["content"][0]["text"] == CONTENT
                    witness["first_reply_complete_before_second"] = True
                    self.process.stdin.write(extra.encode())
                    self.process.stdin.flush()
                    second_raw = self.take()
                    if second_raw is not None:
                        replies.append(second_raw)
                elif mode == "complete" and not witness["session_ended_before_drain"]:
                    # Preserve the old executor's second actual result on the
                    # red run rather than converting a missing witness to zero.
                    second_raw = self.take()
                    if second_raw is not None:
                        replies.append(second_raw)
                if not self.process.stdin.closed:
                    self.process.stdin.close()
                while True:
                    raw = self.take()
                    if raw is None:
                        break
                    replies.append(raw)
                ids = []
                for raw in replies:
                    try:
                        ids.append(json.loads(raw)["id"])
                    except (ValueError, KeyError):
                        ids.append("incomplete-first-reply")
                witness["released_reply_ids"] = ids
                return first

        module.Harness = NoDrain
        return module

    probe.load = patched_load
    modules = [load(repo / "scripts" / filename, "backpressure_" + name) for name, filename in (
        ("setup", "clean-setup-acceptance.py"), ("status", "verify-sou18-status.py"),
        ("evidence", "measure-sou17-latency.py"), ("pending", "verify-sou17-pending-admission.py"),
        ("generic", "verify-sou17-generic-boundary.py"))]
    with tempfile.TemporaryDirectory(prefix="sou17-writer-evidence-") as temporary:
        row = probe.run_case(repo, binary, Path(temporary) / "case", "absolute-read", modules)
    native = row["native_decisions"]
    summary = {"boundary": "production_mcp_resource_stdout", "mode": mode, "witness": witness,
        "native_gates": len(native), "actual_broker_reads": sum(r["event"] == "native_call" and r["released"] is True for r in native),
        "native_call_ids": [r.get("call_id") for r in native if r["event"] == "native_call"],
        "client_tool_result_bytes": sum(len(raw.encode()) for raw in row["client_output_raw"].splitlines(keepends=True)[2:]),
        "client_output_sha256": probe.sha(row["client_output_raw"].encode()),
        "child_executor_entries": 0 if row["child_ledger_raw"] == "" else 1,
        "receiver_deliveries": row["receiver_count"], "file_bytes_unchanged": row["files_unchanged"],
        "stdout_eof_observed": row["stdout_complete"], "owned_profile_removed": row["owned_profile_removed"],
        "collector_exit": row["collector_exit"], "error": row.get("error")}
    # Print observations before assertions so a regression's actual outcomes
    # survive in the retained Rust/launcher log.
    print(json.dumps(summary), flush=True)
    assert row.get("error") is None, summary
    assert row["child_ledger_raw"] == "" and row["ledger_present"] is True, summary
    assert row["files_unchanged"] is True and row["receiver_count"] == 0, summary
    assert row["stdout_complete"] is True and row["owned_profile_removed"] is True, summary
    assert [r["event"] for r in native[:2]] == ["native_call", "native_result"], summary
    assert all(r["released"] is True and r["verdict"] == "allow" and r["shadow"] is False for r in native[:2]), summary
    assert native[0]["call_id"] == native[1]["call_id"] and native[0]["binding_sha256"] == native[1]["binding_sha256"], summary
    if mode in {"complete", "partial", "cancel"}:
        assert witness["session_ended_before_drain"] is True, summary
        assert row["collector_exit"] != 0 and "concurrent MCP requests are not supported" in row["collector_raw"], summary
        assert len(native) == 2, summary
        assert "second-before-drain" not in row["client_output_raw"], summary
    else:
        count = 2 if mode == "sequential" else 1
        assert row["collector_exit"] == 0 and len(native) == 2 * count, summary
        assert witness["released_reply_ids"] == ["absolute-read", "second-before-drain"][:count], summary
        for raw in row["client_output_raw"].splitlines()[2:]:
            assert json.loads(raw)["result"]["content"][0]["text"] == CONTENT, summary
    return 0


if __name__ == "__main__":
    sys.exit(main())
