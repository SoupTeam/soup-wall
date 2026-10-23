# SPDX-License-Identifier: Apache-2.0
"""A qualification result must reject incomplete or misattributed stop evidence."""
import copy
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import threading
import unittest
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepared_stop_witness", ROOT / "scripts/prepared_stop_witness.py")
STOP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STOP)


class EvidenceControls(unittest.TestCase):
    def test_both_native_entries_start_before_either_readiness_wait(self):
        events = []
        class Entry:
            def __init__(self, _context, root, hold_after=True, defer_ready=False):
                self.name = root.name
                events.append(('spawn', self.name))
                if not defer_ready:
                    self.wait_ready()
            def wait_ready(self):
                events.append(('ready', self.name))
                raise ValueError('bounded_test_checkpoint')
            def diagnostic(self): return {'entry_report': 'test_only'}
            def close(self): events.append(('close', self.name))
        context = SimpleNamespace(base=SimpleNamespace(ProcessWitness=SimpleNamespace(identity=lambda _pid: 1)))
        with tempfile.TemporaryDirectory() as directory, patch.object(STOP, 'Prepared', Entry):
            with self.assertRaisesRegex(ValueError, 'bounded_test_checkpoint'):
                STOP.concurrent(context, Path(directory), {}, SimpleNamespace(pid=1))
        self.assertEqual(events[:3], [('spawn', 'selected'), ('spawn', 'peer'), ('ready', 'selected')])
        self.assertEqual(events[-2:], [('close', 'peer'), ('close', 'selected')])

    def test_launch_arguments_cannot_impersonate_the_executed_host_or_namespace_pid1(self):
        self.assertIsNone(STOP.process_role([b"/agentfw", b"pilot-launch", b"--claude", b"/claude"], 10, {}, "/claude"))
        self.assertIsNone(STOP.process_role([b"/bwrap", b"--unshare-all", b"--", b"/mcp-runtime/owner",
                                             b"--agentfw-mcp-pid1-v1"], 10, {}, "/claude"))
        self.assertEqual(STOP.process_role([b"/claude", b"-p"], 10, {}, "/claude"), "host")
        self.assertEqual(STOP.process_role([b"/mcp-runtime/owner", b"--agentfw-mcp-pid1-v1"], 10, {}, "/claude"), "pid1")
        self.assertEqual(STOP.process_role([b"/proc/self/exe", b"--agentfw-mcp-owner-v1"], 10, {}, "/claude"), "owner")

    def run_record(self):
        return {"instance_id": "daemon-one", "registry_sha256": "a" * 64,
                "host_session": "host-one", "authorities": {"filesystem": "b" * 64, "git": "c" * 64}}

    def test_namespace_pid1_requires_kernel_nested_pid_and_owned_uid(self):
        valid = "Uid:\t1001\t1001\t1001\t1001\nNSpid:\t321\t1\n"
        STOP.namespace_pid1_status(valid, 321, 1001)
        for value in (valid.replace("321\t1", "321"), valid.replace("321\t1", "321\t2"),
                      valid.replace("321\t1", "999\t1"), valid.replace("1001", "1002")):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "stop_pid1_not_in_owned_namespace"):
                STOP.namespace_pid1_status(value, 321, 1001)

    def live(self, verified=False):
        run = self.run_record()
        return {"instance_id": run["instance_id"], "registry_sha256": run["registry_sha256"],
                "pilot_cleanup": [{"authority_sha256": digest, "host_session": run["host_session"],
                    "server_id": server, "verified": verified} for server, digest in run["authorities"].items()]}

    def test_cli_success_must_identify_exact_run_and_disposition(self):
        valid = {"run": "d" * 32, "status": "stopped", "running_effects_rolled_back": False}
        STOP.exact_stop_response(valid, "d" * 32, "stopped")
        controls = [dict(valid, run="e" * 32), dict(valid, status="revoked"),
                    dict(valid, status="requested"), dict(valid, running_effects_rolled_back=True),
                    dict(valid, running_effects_rolled_back=0), dict(valid, unconfirmed_namespaces=1)]
        for value in controls:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "stop_response_not_exact"):
                STOP.exact_stop_response(value, "d" * 32, "stopped")

    def test_retirement_or_one_owner_never_proves_both_namespace_cleanup(self):
        STOP.enrolled_owners(self.run_record(), self.live(True), True)
        for rows in (None, [], self.live(True)["pilot_cleanup"][:1]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                STOP.enrolled_owners(self.run_record(), dict(self.live(True), pilot_cleanup=rows), True)
        with self.assertRaises(ValueError):
            STOP.enrolled_owners(self.run_record(), self.live(False), True)

    def test_foreign_duplicate_and_restarted_owner_observations_refuse(self):
        for field, value in [("host_session", "host-two"), ("server_id", "git"),
                             ("authority_sha256", "d" * 64), ("verified", 1)]:
            live = self.live(True)
            live["pilot_cleanup"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                STOP.enrolled_owners(self.run_record(), live, True)
        live = self.live(True)
        live["pilot_cleanup"].append(copy.deepcopy(live["pilot_cleanup"][0]))
        with self.assertRaises(ValueError):
            STOP.enrolled_owners(self.run_record(), live, True)
        for field in ("instance_id", "registry_sha256"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                STOP.enrolled_owners(self.run_record(), dict(self.live(True), **{field: "changed"}), True)

    def test_intent_and_stale_run_receipt_cannot_be_terminal_evidence(self):
        raw = b"exact original private run bytes"
        valid = {"contract": "sw-pilot-stop/1", "run_sha256": hashlib.sha256(raw).hexdigest(),
                 "status": "stopped", "signature": "a" * 43}
        STOP.receipt_state(valid, raw, True)
        with self.assertRaisesRegex(ValueError, "stop_receipt_not_exact_terminal"):
            STOP.receipt_state(valid, raw + b"changed", True)
        for state in ("requested", "revoked"):
            pending = dict(valid, status=state)
            STOP.receipt_state(pending, raw, False)
            with self.assertRaisesRegex(ValueError, "stop_receipt_not_exact_terminal"):
                STOP.receipt_state(pending, raw, True)
        with self.assertRaisesRegex(ValueError, "false_stopped_receipt"):
            STOP.receipt_state(valid, raw, False)
        # Shape validation never substitutes for the actual CLI's HMAC check.
        self.assertNotIn("signature", STOP.receipt_state(valid, raw, True))


class ProviderBarriers(unittest.TestCase):
    def provider(self, hold_after=True):
        model = SimpleNamespace(requests=[], results={})
        return STOP.Provider(model, hold_after)

    def body(self, result=None):
        return {"tools": [{"name": "mcp__filesystem__read_text_file"}, {"name": "mcp__git__git_status"}],
                "messages": [] if result is None else [{"content": [{"type": "tool_result",
                    "tool_use_id": result, "content": [{"type": "text", "text": "actual tool result"}]}]}]}

    def test_first_original_action_remains_blocked_until_peer_release(self):
        provider = self.provider(False)
        result = []
        thread = threading.Thread(target=lambda: result.append(provider.next(self.body())))
        thread.start()
        try:
            self.assertTrue(provider.ready.wait(1))
            self.assertEqual(provider.offered, set())
            self.assertEqual(result, [])
            provider.release.set(); thread.join(1)
            self.assertEqual(result[0][0]["id"], "toolu_prepared_stop_0")
        finally:
            provider.close(); thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_future_attempt_requires_both_correlated_results_and_post_stop_release(self):
        provider = self.provider()
        provider.release.set()
        provider.next(self.body())
        provider.next(self.body("toolu_prepared_stop_0"))
        result = []
        thread = threading.Thread(target=lambda: result.append(provider.next(self.body("toolu_prepared_stop_1"))))
        thread.start()
        try:
            self.assertTrue(provider.after_ready.wait(1))
            self.assertFalse(provider.future_offered.is_set())
            self.assertEqual(len(provider.model.results), 2)
            provider.after_release.set(); thread.join(1)
            self.assertTrue(provider.future_offered.is_set())
            self.assertEqual(result[0][0]["input"], {"path": "/workspace/followup.txt"})
        finally:
            provider.close(); thread.join(2)

    def test_cancellation_unblocks_without_authorizing_a_future_proposal(self):
        provider = self.provider()
        provider.close()
        self.assertEqual(provider.next(self.body())[0]["type"], "text")
        self.assertEqual(provider.offered, set())
        self.assertFalse(provider.future_offered.is_set())

    def test_reissued_proposal_is_a_failure_and_auxiliary_requests_do_not_open_barrier(self):
        provider = self.provider()
        self.assertEqual(provider.next({"tools": []})[0]["type"], "text")
        self.assertFalse(provider.ready.is_set())
        provider.release.set()
        provider.next(self.body())
        with self.assertRaisesRegex(ValueError, "stop_original_proposal_reissued"):
            provider.next(self.body())
        provider.close()


if __name__ == "__main__":
    unittest.main()
