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
import os
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
MODES = ("complete", "partial", "cancel", "sequential", "eof",
         "immediate-success", "immediate-errors", "immediate-refusals")
IMMEDIATE_SUCCESS_CALLS = 32
IMMEDIATE_ERROR_CALLS = 70
IMMEDIATE_REFUSAL_PAIRS = 16


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
    immediate = mode.startswith("immediate-")
    contents = "Inventory: 7 red widgets." if immediate else CONTENT

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
            file.write_text(contents, encoding="utf-8")
            return original_registry(tools)

        module.registry = registry
        original_harness = module.Harness

        class NoDrain(original_harness):
            def __init__(self, command, env, stderr):
                self.process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=stderr,
                                                bufsize=0 if immediate else -1)
                self.lines, self.received = queue.Queue(), []
                self.audit = Path(env["HOME"]) / ".agentfw/audit.jsonl"

            def records(self):
                return [json.loads(line) for line in self.audit.read_text().splitlines()]

            def take(self):
                raw = self.lines.get(timeout=3)
                if raw is not None:
                    self.received.append(raw)
                return raw

            def immediate_sequence(self, frame, request):
                prepared = [(frame, "allow")]
                path = request["params"]["arguments"]["path"]
                invalid = str(Path(path).parent / "invalid.txt")
                if mode == "immediate-success":
                    cases = [("read_document", path, "allow")] * (IMMEDIATE_SUCCESS_CALLS - 1)
                elif mode == "immediate-errors":
                    cases = [("read_document", invalid, "resource_read_failed")] * IMMEDIATE_ERROR_CALLS
                    cases.append(("read_document", path, "allow"))
                else:
                    cases = [("read_note", path, "resource_executor_unsupported"),
                             ("read_document", path, "allow")] * IMMEDIATE_REFUSAL_PAIRS
                for index, (tool, argument, expected) in enumerate(cases, 1):
                    next_request = json.loads(frame)
                    next_request["id"] = "rapid-" + mode + "-" + str(index)
                    next_request["params"]["name"] = tool
                    next_request["params"]["arguments"] = {"path": argument}
                    next_request["params"]["_meta"] = {
                        "claudecode/toolUseId": "toolu_sou17_rapid_" + str(index),
                        "progressToken": index + 1}
                    prepared.append((json.dumps(next_request, separators=(",", ":")), expected))
                replies = []
                released = bytearray()
                witness["prepared_frames"] = [value for value, _ in prepared]
                witness["expected_outcomes"] = [value for _, value in prepared]
                witness["next_frame_written_after_lf_before_json_validation"] = True
                # Use the actual unbuffered stdout fd, with no queue/reader thread
                # and no JSON parsing delay between LF and the next pipe write.
                for index, (_, expected) in enumerate(prepared):
                    deadline = time.monotonic() + 3
                    raw = bytearray()
                    while not raw.endswith(b"\n"):
                        if time.monotonic() >= deadline or not select.select(
                                [self.process.stdout], [], [], max(.001, deadline - time.monotonic()))[0]:
                            raise RuntimeError("immediate pipe reply timeout at " + str(index))
                        chunk = os.read(self.process.stdout.fileno(), 65536)
                        if not chunk:
                            self.stdout_eof = True
                            raise RuntimeError("collector EOF before immediate reply " + str(index))
                        raw.extend(chunk)
                    # The next frame/EOF is emitted immediately on observing LF,
                    # before parsing the completed response or consulting audit.
                    if index + 1 < len(prepared):
                        self.process.stdin.write(prepared[index + 1][0].encode() + b"\n")
                        self.process.stdin.flush()
                    else:
                        self.process.stdin.close()
                        witness["clean_eof_sent_after_final_lf"] = True
                    self.received.append(bytes(raw))
                    released.extend(raw)
                    witness.setdefault("released_response_sha256", []).append(probe.sha(bytes(raw)))
                    value = json.loads(raw)
                    result = value.get("result", {})
                    text = result.get("content", [{}])[0].get("text")
                    witness.setdefault("received_outcomes", []).append({
                        "id": value.get("id"), "jsonrpc": value.get("jsonrpc"),
                        "is_error": result.get("isError"),
                        "useful_contents_match": text == contents,
                        "expected_refusal_present": isinstance(text, str) and expected in text,
                        "technical_error_code": value.get("error", {}).get("code")})
                    replies.append(value)
                if not select.select([self.process.stdout], [], [], 3)[0]:
                    raise RuntimeError("collector failed to close stdout after clean EOF")
                extra = os.read(self.process.stdout.fileno(), 65536)
                if extra:
                    self.received.append(extra)
                    raise RuntimeError("extra bytes released after final correlated response")
                self.stdout_eof = True
                witness["released_reply_ids"] = [r["id"] for r in replies]
                witness["correlated_response_count"] = len(replies)
                witness["useful_response_count"] = sum(expected == "allow" for _, expected in prepared)
                witness["error_response_count"] = sum(expected == "resource_read_failed" for _, expected in prepared)
                witness["unsupported_refusal_count"] = sum(expected == "resource_executor_unsupported" for _, expected in prepared)
                witness["released_tool_response_sha256"] = probe.sha(bytes(released))
                return json.dumps(replies[0], separators=(",", ":")).encode() + b"\n"

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
                if immediate:
                    return self.immediate_sequence(frame, request)
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
    if immediate:
        submitted = [json.loads(raw) for raw in witness["prepared_frames"]]
        outcomes = witness["expected_outcomes"]
        observed = witness["received_outcomes"]
        assert len(observed) == len(submitted), summary
        for observation, request, expected in zip(observed, submitted, outcomes):
            assert observation["jsonrpc"] == "2.0" and observation["id"] == request["id"], summary
            assert observation["technical_error_code"] is None, summary
            if expected == "allow":
                assert observation["is_error"] in (None, False) and observation["useful_contents_match"] is True, summary
            else:
                assert observation["is_error"] is True and observation["expected_refusal_present"] is True, summary
        classified = row["classifications"]
        assert row["collector_exit"] == 0, summary
        assert witness["clean_eof_sent_after_final_lf"] is True, summary
        assert len(classified) == len(submitted) and witness["correlated_response_count"] == len(submitted), summary
        assert [record["host_call_id"] for record in classified] == [request["id"] for request in submitted], summary
        for record, request in zip(classified, submitted):
            assert record["source"] == "rule-baseline/python" and record["classifier_sha256"] == row["classifier_sha256"], summary
            assert record["tool"] == request["params"]["name"], summary
            assert record["args_sha256"] == probe.sha(json.dumps(request["params"]["arguments"], sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode()), summary
        expected_pairs = sum(outcome != "resource_executor_unsupported" for outcome in outcomes)
        assert len(native) == expected_pairs * 2, summary
        assert len({record["session"] for record in native}) == 1, summary
        call_ids = []
        gated_response_hashes = [digest for digest, outcome in zip(witness["released_response_sha256"], outcomes)
                                if outcome != "resource_executor_unsupported"]
        for index in range(0, len(native), 2):
            call, result = native[index:index + 2]
            assert call["event"] == "native_call" and result["event"] == "native_result", summary
            assert call["call_id"] == result["call_id"] and call["binding_sha256"] == result["binding_sha256"], summary
            assert call["released"] is True and call["verdict"] == "allow" and call["shadow"] is False, summary
            assert result["released"] is True and result["shadow"] is False, summary
            assert result["content_sha256"] == gated_response_hashes[index // 2], summary
            call_ids.append(call["call_id"])
        assert len(set(call_ids)) == expected_pairs, summary
        assert witness["released_reply_ids"] == [request["id"] for request in submitted], summary
        assert "native_session_end" in row["native_audit_raw"], summary
    elif mode in {"complete", "partial", "cancel"}:
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
