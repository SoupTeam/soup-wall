"""Finite trace snapshots and exact pre-approval observer controls."""
import hashlib
import importlib.util
import json
import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "qualify-prepared-pilot-run.py"
SPEC = importlib.util.spec_from_file_location("prepared_trace_bound", SOURCE)
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


def write(pid, fd, value):
    payload = json.dumps(value, separators=(",", ":")) + "\n"
    return f"{pid} write({fd}, {json.dumps(payload)}, {len(payload)}) = {len(payload)}\n"


def trace(call=False):
    binary = "/owned/agentfw"
    rows = []
    for pid, server in ((11, "filesystem"), (12, "git")):
        rows.append(f'{pid} execve("{binary}", ["{binary}", "mcp", "--id", "{server}"], 0x1) = 0\n')
        rows.append(write(pid, 4, {"jsonrpc": "2.0", "id": pid, "method": "tools/list", "params": {}}))
    args = {"path": "/workspace/credentials.txt"}
    if call:
        rows.append(write(11, 4, {"jsonrpc": "2.0", "id": 50, "method": "tools/call",
                                  "params": {"name": "read_text_file", "arguments": args}}))
    digest = hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode()).hexdigest()
    return "".join(rows), digest


class PreparedTraceBound(unittest.TestCase):
    def test_exact_dispatch_and_incomplete_live_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.private"
            clean, digest = trace()
            path.write_text(clean)
            self.assertTrue(Q.preapproval_dispatch_absent(path, "/owned/agentfw", "read_text_file", digest))
            called, _ = trace(call=True)
            path.write_text(called)
            self.assertFalse(Q.preapproval_dispatch_absent(path, "/owned/agentfw", "read_text_file", digest))
            path.write_text(called[:-1])
            self.assertIsNone(Q.preapproval_dispatch_absent(path, "/owned/agentfw", "read_text_file", digest))
            path.write_text(clean + '11 write(4, "pending" <unfinished ...>\n')
            self.assertIsNone(Q.preapproval_dispatch_absent(path, "/owned/agentfw", "read_text_file", digest))

    def test_overflow_is_never_downgraded_to_pending(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Q, "TRACE_LIMIT", 128):
            path = Path(directory) / "trace.private"
            clean, digest = trace()
            path.write_text(clean)
            with self.assertRaisesRegex(ValueError, "prepared_trace_exceeded_bound"):
                Q.preapproval_dispatch_absent(path, "/owned/agentfw", "read_text_file", digest)

    def test_provider_log_mode_keeps_close_and_normal_mode_keeps_witnesses(self):
        # pilot-demo passes a Namespace without this optional flag.
        ordinary = Q.trace_syscalls(argparse.Namespace()).split(",")
        provider = Q.trace_syscalls(argparse.Namespace(verify_provider_isolation=True)).split(",")
        self.assertEqual(set(provider) - set(ordinary), {"close"})
        self.assertTrue({"execve", "openat", "write", "writev", "clone", "clone3", "vfork", "fork"}
                        .issubset(ordinary))


if __name__ == "__main__":
    unittest.main()
