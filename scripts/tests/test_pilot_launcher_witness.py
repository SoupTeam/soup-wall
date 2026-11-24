# SPDX-License-Identifier: Apache-2.0
"""False-positive controls for the independent launcher dispatch observer."""
import importlib.util
import builtins
import symtable
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("launcher_witness", ROOT / "scripts/qualify-pilot-launcher.py")
WITNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WITNESS)


class DispatchControls(unittest.TestCase):
    def test_dispatch_fingerprint_covers_the_exact_complete_request_frame(self):
        import hashlib
        rows = self.trace()[:4]
        frame = b'{"method":"tools/call","id":17,"params":{"name":"git_show","arguments":{"revision":"HEAD"}}}\r\n'
        for part in (frame[:19], frame[19:]):
            text = part.decode()
            rows.append(f'102 write(9, {json.dumps(text)}, {len(part)}) = {len(part)}')
        observed = WITNESS.collector_dispatches('\n'.join(rows), Path('/owned/agentfw'), strict=False)
        self.assertEqual(observed['calls'][0]['request_sha256'], hashlib.sha256(frame).hexdigest())

    def test_shared_preparation_does_not_leave_missing_global_names(self):
        for filename in ("qualify-pilot-launcher.py", "qualify-pilot-ask.py"):
            path = ROOT / "scripts" / filename
            table = symtable.symtable(path.read_text(), str(path), "exec")
            known = set(table.get_identifiers()) | set(dir(builtins))
            def missing(scope):
                result = {s.get_name() for s in scope.get_symbols()
                    if s.is_global() and s.is_referenced() and s.get_name() not in known}
                for child in scope.get_children():
                    result.update(missing(child))
                return result
            self.assertEqual(missing(table), set(), filename)

    def trace(self):
        rows = ['101 execve("/owned/agentfw", ["/owned/agentfw", "mcp"], 0x0) = 0',
                '102 execve("/owned/agentfw", ["/owned/agentfw", "mcp"], 0x0) = 0']
        for pid, method, tool in ((101, "tools/list", None), (102, "tools/list", None),
                                  (101, "tools/call", "read_text_file"), (102, "tools/call", "git_status"),
                                  (101, "tools/call", "read_text_file"), (101, "tools/call", "read_text_file")):
            frame = json.dumps({"jsonrpc": "2.0", "id": len(rows), "method": method,
                                "params": {"name": tool}}) + "\n"
            rows.append(f'{pid} write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}')
        return rows

    def observe(self, rows):
        return WITNESS.dispatch_witness("\n".join(rows), Path("/owned/agentfw"))

    def test_calibration_requires_both_servers_and_exact_useful_dispatches(self):
        self.assertEqual(self.observe(self.trace())["forbidden_dispatches"], 0)
        for index in range(len(self.trace())):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.observe(self.trace()[:index] + self.trace()[index + 1:])

    def test_forbidden_dispatch_is_not_hidden_by_other_successes(self):
        rows = self.trace()
        frame = json.dumps({"method": "tools/call", "params": {"name": "git_reset"}}) + "\n"
        rows.append(f'102 write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}')
        with self.assertRaisesRegex(ValueError, "forbidden_original_server_dispatch"):
            self.observe(rows)

    def test_truncation_partial_or_unfinished_writes_cannot_prove_no_dispatch(self):
        for row in ('102 write(9, "short"..., 1000) = 1000',
                    '102 write(9, "short", 1000) = 1000',
                    '102 write(9, "pending", 7 <unfinished ...>'):
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.observe(self.trace() + [row])

    def test_host_proposal_is_distinguished_from_collector_dispatch(self):
        rows = self.trace()
        frame = json.dumps({"method": "tools/call", "params": {"name": "git_reset"}}) + "\n"
        rows.append(f'99 write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}')
        self.assertEqual(self.observe(rows)["forbidden_dispatches"], 0)

    def test_writev_forbidden_dispatch_is_observed(self):
        frame = json.dumps({"method": "tools/call", "params": {"name": "git_reset"}}) + "\n"
        row = f'102 writev(9, [{{iov_base={json.dumps(frame)}, iov_len={len(frame)}}}], 1) = {len(frame)}'
        with self.assertRaisesRegex(ValueError, "forbidden_original_server_dispatch"):
            self.observe(self.trace() + [row])

    def test_failed_writes_transfer_no_bytes_and_cannot_hide_a_forbidden_call(self):
        frame = json.dumps({"method": "tools/call", "params": {"name": "git_reset"}}) + "\n"
        failed = [
            f'102 write(9, {json.dumps(frame)}, {len(frame)}) = -1 EPIPE (Broken pipe)',
            f'102 writev(9, [{{iov_base={json.dumps(frame)}, iov_len={len(frame)}}}], 1) = -1 EINTR (Interrupted system call)',
        ]
        for row in failed:
            with self.subTest(row=row):
                self.assertEqual(self.observe(self.trace() + [row])["forbidden_dispatches"], 0)
                successful = f'102 write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}'
                with self.assertRaisesRegex(ValueError, "forbidden_original_server_dispatch"):
                    self.observe(self.trace() + [row, successful])

    def test_failed_write_cannot_calibrate_or_finish_an_incomplete_frame(self):
        rows = self.trace()
        rows[2] = rows[2].rsplit(" = ", 1)[0] + " = -1 EAGAIN (Resource temporarily unavailable)"
        with self.assertRaisesRegex(ValueError, "original_discovery_not_observed"):
            self.observe(rows)
        with self.assertRaisesRegex(ValueError, "incomplete_original_wire_frame"):
            self.observe(self.trace() + [
                '101 write(9, "partial", 7) = 7',
                '101 write(9, "\\n", 1) = -1 EINTR (Interrupted system call)',
            ])

    def test_unknown_write_diagnostics_never_contain_raw_payload(self):
        secret = "PRIVATE_OBSERVER_PAYLOAD"
        with self.assertRaises(ValueError) as caught:
            self.observe(self.trace() + [f'101 write(9, "{secret}"..., 999) = 999'])
        self.assertEqual(str(caught.exception), "unobserved_collector_write:write:pid=101:fd=9")
        self.assertNotIn(secret, str(caught.exception))

    def test_failed_exec_cannot_calibrate_original_collector(self):
        rows = self.trace()
        rows[0] = rows[0].replace("= 0", "= -1 ENOENT (No such file or directory)")
        with self.assertRaisesRegex(ValueError, "two_actual_collector_execs_required"):
            self.observe(rows)

    def test_argument_fingerprint_distinguishes_allow_peer_from_pending_ask(self):
        rows = self.trace()[:4]
        fingerprints = []
        for path in ("/workspace/notes.txt", "/workspace/credentials.txt"):
            frame = json.dumps({"method": "tools/call", "params": {
                "name": "read_text_file", "arguments": {"path": path}}}) + "\n"
            rows.append(f'101 write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}')
            observed = WITNESS.collector_dispatches("\n".join(rows), Path("/owned/agentfw"), strict=False)
            fingerprints.append(observed["calls"][-1]["args_sha256"])
        self.assertNotEqual(*fingerprints)
        self.assertEqual(len(observed["calls"]), 2)

    def test_live_observer_does_not_ignore_incomplete_original_channel(self):
        for suffix in ('101 write(9, "pending", 7 <unfinished ...>',
                       '101 write(9, "partial", 7) = 7'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                WITNESS.collector_dispatches("\n".join(self.trace() + [suffix]), Path("/owned/agentfw"), strict=False)
        observed = WITNESS.collector_dispatches("\n".join(self.trace() + [
            '101 write(12, "http", 4 <unfinished ...>']), Path("/owned/agentfw"), strict=False)
        self.assertEqual(len(observed["calls"]), 4)

    def test_resumed_exec_preserves_actual_collector_and_server_identity(self):
        rows = self.trace()
        rows[0] = rows[0].replace('"mcp"', '"mcp", "--id", "filesystem"')
        rows[1] = rows[1].replace('"mcp"', '"mcp", "--id", "git"')
        start, result = rows[0].split(" = ")
        rows[0:1] = [start[:-1] + " <unfinished ...>", "101 <... execve resumed>) = " + result]
        observed = WITNESS.collector_dispatches("\n".join(rows), Path("/owned/agentfw"), strict=False)
        self.assertEqual(observed["collector_servers"], {101: "filesystem", 102: "git"})
        self.assertEqual(len(observed["calls"]), 4)

    def test_rejected_restart_collector_cannot_calibrate_or_hide_dispatch(self):
        rows = self.trace() + ['103 execve("/owned/agentfw", ["/owned/agentfw", "mcp", "--id", "filesystem"], 0x0) = 0']
        observed = WITNESS.collector_dispatches("\n".join(rows), Path("/owned/agentfw"), strict=False)
        self.assertEqual(observed["discoveries"], 2)
        self.assertEqual(len(observed["calls"]), 4)
        with self.assertRaisesRegex(ValueError, "original_discovery_not_observed"):
            self.observe(rows)
        frame = json.dumps({"method": "tools/call", "params": {"name": "read_text_file", "arguments": {"path": "/workspace/credentials.txt"}}}) + "\n"
        rows.append(f'103 write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}')
        with self.assertRaisesRegex(ValueError, "unobserved_original_call_channel"):
            WITNESS.collector_dispatches("\n".join(rows), Path("/owned/agentfw"), strict=False)

    def test_resumed_syscall_preserves_original_complete_dispatch(self):
        rows = self.trace()
        original = rows[-1]
        start, result = original.split(" = ")
        rows[-1:] = [start[:-1] + " <unfinished ...>", "101 <... write resumed>) = " + result]
        self.assertEqual(self.observe(rows)["forbidden_dispatches"], 0)


if __name__ == "__main__":
    unittest.main()
