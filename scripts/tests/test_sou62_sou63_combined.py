# SPDX-License-Identifier: Apache-2.0
"""Adversarial controls for combined original-server/shared-session evidence."""
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou62_sou63_combined", ROOT / "scripts/verify-sou62-sou63-combined.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def response(identifier, text):
    return {"jsonrpc": "2.0", "id": identifier, "result": {
        "content": [{"type": "text", "text": text}], "structuredContent": {"content": text}}}


def refusal(identifier):
    return {"jsonrpc": "2.0", "id": identifier, "result": {"isError": True,
        "content": [{"type": "text", "text": "Soup Wall withheld MCP invocation (combined-ask-mcp-derived-read)"}]}}


def fifo(path, reader):
    return {"path": path, "device": 17, "inode": 100 if path == VERIFY.CROSS_PATH else 101,
        "reader_seen": reader, "bytes_written": len(VERIFY.BASE.FIFO_TEXT.encode()) if reader else 0,
        "attempts": 9, "error": None, "thread_stopped": True}


def native(host, agent, seq):
    return {"event": "native_call", "host_session": host, "agent_id": agent, "tool": "read_text_file",
        "rule": "combined-ask-mcp-derived-read", "verdict": "ask", "released": False,
        "taint": {"origin": "mcp", "source_name": "source_a", "seq": seq}, "registry_sha256": "b" * 64}


def hook(seq):
    return {"injection_transport": "owned-signed-PostToolUse-HTTP-not-automatic-Claude-hook", "pre_before": {},
        "post_response": {}, "hook_seq": seq, "pre_after": {"hookSpecificOutput": {"hookEventName": "PreToolUse",
            "permissionDecision": "ask", "permissionDecisionReason": "[combined-ask-mcp-derived-read]"}}}


def live(host, prefix):
    return [{"host_session": host, "agent_id": prefix + suffix, "binding_sha256": value * 64}
            for suffix, value in (("-a", "c"), ("-b", "d"))]


def transcript():
    manifest = json.loads((VERIFY.BASE.INSTALL.ASSETS / "upstream-tools-list.json").read_text())["result"]
    sent = [json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"]
    received = [json.dumps({"jsonrpc": "2.0", "id": 2, "result": manifest}) + "\n"]
    return {"sent": sent, "received": received, "sent_sha256": hashlib.sha256("".join(sent).encode()).hexdigest(),
        "received_sha256": hashlib.sha256("".join(received).encode()).hexdigest(), "exit_code": 0, "forced_cleanup": False,
        "process_cleanup": {"all_stopped": True, "descendant_count": 2}}


def complete_report():
    """Construct evidence independently; a false summary must never repair it."""
    clean, shared, actual = "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"
    bindings = [{"host_session": host, "server_id": server, "agent_id": agent, "tools": ["read_text_file"], "proof_sha256": str(index) * 64}
        for index, (host, server, agent) in enumerate(((clean, "sink_b", "clean-b"), (shared, "source_a", "stdio-a"),
            (shared, "sink_b", "stdio-b"), (actual, "source_a", "claude-a"), (actual, "sink_b", "claude-b")), 1)]
    starts = [{"event": "native_session_start", "host_session": row["host_session"], "agent_id": row["agent_id"],
        "registry_sha256": "b" * 64, "verdict": "allow", "released": True} for row in bindings]
    upstream = json.loads((VERIFY.BASE.INSTALL.ASSETS / "upstream-identity.json").read_text())
    report = {"format": "sou62-sou63-combined/1", "failed": 0, "skipped": 0,
        "source_before": {"commit": "1" * 40, "tree": "2" * 40, "dirty": False},
        "source_after": {"commit": "1" * 40, "tree": "2" * 40, "dirty": False},
        **{name: "a" * 64 for name in ("binary_sha256", "claude_sha256", "sandbox_test_binary_sha256", "driver_sha256")},
        "proof_policy_sha256": hashlib.sha256(VERIFY.PROOF_POLICY.encode()).hexdigest(),
        "checks": [{"case": case, "passed": True} for case in sorted(VERIFY.EXPECTED_CHECKS)],
        "required_positive_sandbox": {"status": "pass", "exit_code": 0,
            "witnesses": {name: True for name in VERIFY.BASE.SANDBOX_WITNESSES}},
        "installed_profile": {"server_package": "@modelcontextprotocol/server-filesystem@2026.8.31",
            "upstream_identity": upstream, "upstream_identity_sha256": VERIFY.BASE.sha(VERIFY.BASE.INSTALL.ASSETS / "upstream-identity.json"),
            "package_lock_sha256": upstream["packageLockSha256"], "profile": {"format": "sw-mcp/filesystem-readonly/1"},
            "node_version": VERIFY.BASE.INSTALL.NODE_VERSION, "registry_sha256": "b" * 64},
        "bindings": bindings, "authenticated_starts": starts,
        "clean_control": {"status": "pass", "host_session": clean, "server_id": "sink_b", "agent_id": "clean-b",
            "reads": [{"path": path, "response": response(index, VERIFY.BASE.FIFO_TEXT), "fifo": fifo(path, True)}
                for index, path in enumerate((VERIFY.CROSS_PATH, VERIFY.HOOK_PATH), 10)]},
        "shared_mcp": {"status": "pass", "host_session": shared, "rule": VERIFY.RULE, "no_reader": True,
            "source_response": response(10, VERIFY.SOURCE_TEXT), "blocked_response": refusal(10),
            "benign_response": response(11, VERIFY.BASE.TEXT), "fifo": fifo(VERIFY.CROSS_PATH, False),
            "native_witness": native(shared, "stdio-b", 8), "active_bindings": live(shared, "stdio")},
        "shared_hook": {"status": "pass", "host_session": shared, "rule": VERIFY.RULE, "no_reader": True,
            **hook(41), "blocked_response": refusal(12), "benign_response": response(13, VERIFY.BASE.TEXT),
            "fifo": fifo(VERIFY.HOOK_PATH, False), "native_witness": native(shared, "stdio-b", 41)},
        "installed_profile_unchanged": True, "runtime_unchanged": True, "workspace_unchanged": True,
        "cleanup": {"all_stopped": True, "daemon_stopped": True, "private_profile_removed": True,
            "daemon_process_cleanup": {"all_stopped": True}, "clients": [transcript() for _ in range(3)]}}
    steps = [("source_a", "/workspace/source.txt"), ("sink_b", VERIFY.CROSS_PATH), ("sink_b", "/workspace/notes.txt"),
             ("sink_b", VERIFY.HOOK_PATH), ("sink_b", "/workspace/notes.txt")]
    results = {f"toolu_combined_{index}": {"is_error": False,
        "original_content": json.dumps({"content": VERIFY.SOURCE_TEXT if index == 0 else VERIFY.BASE.TEXT}, ensure_ascii=False, separators=(",", ":"))}
        for index in (0, 2, 4)}
    results.update({f"toolu_combined_{index}": {"is_error": True, "original_content": "Soup Wall withheld MCP invocation (combined-ask-mcp-derived-read)"}
        for index in (1, 3)})
    report["actual_claude_host"] = {"status": "pass", "host_session": actual, "exit_code": 0, "real_host_executed": True,
        "scripted_owned_provider": True, "live_model_efficacy_measured": False, "claude_version": "2.1.251 (Claude Code)",
        "claude_sha256": "a" * 64, "initialization": [{"session_id": actual, "mcp_servers": [
            {"name": "source_a", "status": "connected"}, {"name": "sink_b", "status": "connected"}]}],
        "host_tool_uses": [{"type": "tool_use", "id": f"toolu_combined_{index}", "name": f"mcp__{server}__read_text_file", "input": {"path": path}}
            for index, (server, path) in enumerate(steps)], "model_results": results, "provider_request_count": 6,
        "read_presentations": {str(index): VERIFY.presentation(results[f"toolu_combined_{index}"], VERIFY.SOURCE_TEXT if index == 0 else VERIFY.BASE.TEXT) for index in (0, 2, 4)},
        "fifo_probes": [fifo(path, False) for path in (VERIFY.CROSS_PATH, VERIFY.HOOK_PATH)], "no_reader": True,
        "signed_hook": hook(58), "native_asks": [native(actual, "claude-b", seq) for seq in (8, 58)],
        "active_bindings": live(actual, "claude"), "process_cleanup": {"all_stopped": True, "descendant_count": 4}}
    audit = copy.deepcopy(starts)
    for host, prefix, seq in ((shared, "stdio", 41), (actual, "claude", 58)):
        audit.append({"event": "native_result", "host_session": host, "agent_id": prefix + "-a", "tool": "read_text_file",
            "registry_sha256": "b" * 64, "verdict": "allow", "released": True, "delivery": "mcp_host"})
        audit.append(native(host, prefix + "-b", 8))
        audit.append({"event": "post_tool_use", "session": host, "agent_id": prefix + "-a", "seq": seq, "verdict": "allow"})
        audit.append(native(host, prefix + "-b", seq))
    report.update(owned_audit=audit, owned_audit_sha256=VERIFY.digest(audit))
    return report


class EvidenceControls(unittest.TestCase):
    def assertRejected(self, mutation):
        item = complete_report()
        mutation(item)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            VERIFY.grade(item)

    def test_complete_independent_evidence_passes(self):
        VERIFY.grade(complete_report())

    def test_summary_pass_flags_cannot_replace_exact_clean_execution(self):
        for mutation in (
            lambda r: r["clean_control"]["reads"].pop(),
            lambda r: r["clean_control"]["reads"][0]["fifo"].update(reader_seen=False),
            lambda r: r["clean_control"]["reads"][0]["fifo"].update(bytes_written=0),
            lambda r: r["clean_control"]["reads"][0].update(response=response(10, "unrelated")),
            lambda r: r["clean_control"]["reads"][0]["response"].update(id="10"),
            lambda r: r["clean_control"].update(host_session=r["shared_mcp"]["host_session"])):
            with self.subTest(mutation=mutation):
                self.assertRejected(mutation)

    def test_zero_effect_requires_both_exact_calibrated_fifo_targets(self):
        for mutation in (
            lambda r: r["shared_mcp"]["fifo"].update(inode=999),
            lambda r: r["shared_hook"]["fifo"].update(attempts=0),
            lambda r: r["shared_hook"]["fifo"].update(error="permission"),
            lambda r: r["actual_claude_host"]["fifo_probes"][1].update(path=VERIFY.CROSS_PATH),
            lambda r: r["actual_claude_host"]["fifo_probes"][0].update(reader_seen=True),
            lambda r: r["actual_claude_host"]["fifo_probes"][1].update(bytes_written=1)):
            with self.subTest(mutation=mutation):
                self.assertRejected(mutation)

    def test_other_refusals_or_native_sources_are_not_shared_provenance_proof(self):
        for name in ("shared_mcp", "shared_hook"):
            for field, value in (("rule", "unsupported_tool"), ("tool", "write_file"), ("agent_id", "stdio-a"),
                                 ("verdict", "deny"), ("registry_sha256", "e" * 64), ("released", True)):
                with self.subTest(name=name, field=field):
                    self.assertRejected(lambda r, n=name, f=field, v=value: r[n]["native_witness"].update({f: v}))
        for index in (0, 1):
            for field, value in (("host_session", "foreign"), ("tool", "write_file"), ("rule", "unsupported"), ("released", True)):
                with self.subTest(index=index, field=field):
                    self.assertRejected(lambda r, i=index, f=field, v=value: r["actual_claude_host"]["native_asks"][i].update({f: v}))

    def test_hook_only_sequence_and_clean_precondition_are_independent(self):
        for mutation in (
            lambda r: r["shared_hook"].update(hook_seq=8),
            lambda r: r["shared_hook"].update(pre_before={"denied": True}),
            lambda r: r["shared_hook"]["pre_after"]["hookSpecificOutput"].update(permissionDecision="allow"),
            lambda r: r["actual_claude_host"]["signed_hook"].update(pre_before={"permissionDecision": "ask"}),
            lambda r: r["actual_claude_host"]["signed_hook"].update(hook_seq=999),
            lambda r: r["shared_hook"].update(injection_transport="automatic-Claude-hook")):
            with self.subTest(mutation=mutation):
                self.assertRejected(mutation)

    def test_exact_five_actual_host_steps_results_and_connected_bound_session_required(self):
        for mutation in (
            lambda r: r["actual_claude_host"]["host_tool_uses"].pop(),
            lambda r: r["actual_claude_host"]["model_results"].pop("toolu_combined_4"),
            lambda r: r["actual_claude_host"]["initialization"][0].update(session_id="unbound"),
            lambda r: r["actual_claude_host"]["initialization"][0]["mcp_servers"].pop(),
            lambda r: r["actual_claude_host"].update(real_host_executed=False),
            lambda r: r["actual_claude_host"].update(claude_version="newer"),
            lambda r: r["actual_claude_host"].update(live_model_efficacy_measured=True),
            lambda r: r["actual_claude_host"]["model_results"]["toolu_combined_1"].update(is_error=False),
            lambda r: r["actual_claude_host"]["model_results"]["toolu_combined_4"].update(original_content="missing bytes")):
            with self.subTest(mutation=mutation):
                self.assertRejected(mutation)

    def test_scope_grants_live_bindings_and_authenticated_start_receipts_required(self):
        for mutation in (
            lambda r: r["bindings"][1].update(server_id="sink_b"),
            lambda r: r["bindings"][4].update(host_session=r["shared_mcp"]["host_session"]),
            lambda r: r["bindings"][0].update(tools=["read_text_file", "write_file"]),
            lambda r: r["bindings"][0].update(child_authority="never-persist-proof"),
            lambda r: r["shared_mcp"]["active_bindings"][0].update(binding_sha256="invalid"),
            lambda r: r["actual_claude_host"]["active_bindings"].pop(),
            lambda r: r["authenticated_starts"][0].update(registry_sha256="e" * 64),
            lambda r: r["authenticated_starts"].pop()):
            with self.subTest(mutation=mutation):
                self.assertRejected(mutation)

    def test_original_audit_source_release_and_hook_receipt_required(self):
        def mutate_audit(report, predicate):
            report["owned_audit"] = [row for row in report["owned_audit"] if not predicate(row)]
            report["owned_audit_sha256"] = VERIFY.digest(report["owned_audit"])
        for predicate in (
            lambda row: row["event"] == "native_result",
            lambda row: row["event"] == "post_tool_use",
            lambda row: row["event"] == "native_call" and row["agent_id"] == "stdio-b",
            lambda row: row["event"] == "native_session_start",
            lambda row: row["event"] == "native_call" and row["agent_id"] == "claude-b"):
            with self.subTest(predicate=predicate):
                self.assertRejected(lambda r, p=predicate: mutate_audit(r, p))
        self.assertRejected(lambda r: r.update(owned_audit_sha256="0" * 64))

    def test_dirty_assets_policy_weakening_missing_checks_or_cleanup_never_pass(self):
        for mutation in (
            lambda r: r.update(skipped=1), lambda r: r.update(failed=1),
            lambda r: r.update(proof_policy_sha256="f" * 64), lambda r: r["checks"].pop(),
            lambda r: r["source_after"].update(dirty=True), lambda r: r.update(workspace_unchanged=False),
            lambda r: r["installed_profile"].update(server_package="fixture"),
            lambda r: r["required_positive_sandbox"]["witnesses"].update(allowed_read=False),
            lambda r: r["cleanup"]["clients"][0].update(forced_cleanup=True),
            lambda r: r["cleanup"]["daemon_process_cleanup"].update(all_stopped=False),
            lambda r: r["actual_claude_host"]["process_cleanup"].update(all_stopped=False),
            lambda r: r["cleanup"].update(private_profile_removed=False),
            lambda r: r["cleanup"]["clients"][0]["received"].append('{}\n')):
            with self.subTest(mutation=mutation):
                self.assertRejected(mutation)

    def test_renderer_accepts_only_closed_exact_json_and_observed_reminder(self):
        expected = VERIFY.BASE.TEXT
        valid = json.dumps({"content": expected}, ensure_ascii=False)
        suffix = "\n\n<system-reminder>\n<total_tokens>1423 tokens left</total_tokens>\n</system-reminder>"
        VERIFY.presentation({"is_error": False, "original_content": valid + suffix}, expected)
        for text in (expected, valid + " extra", json.dumps({"content": expected, "extra": "ignored"}),
            '{"content":"wrong","content":' + json.dumps(expected) + '}',
            json.dumps({"content": expected + "wrong"}), valid + "\n\n<system-reminder>arbitrary</system-reminder>"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                VERIFY.presentation({"is_error": False, "original_content": text}, expected)

    def test_owned_credentials_are_redacted_from_errors_and_written_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(VERIFY, "SECRETS", ["owned-proof", "owned-bearer"]):
            target = Path(temporary) / "report.json"
            VERIFY.write(target, {"error": "owned-proof / owned-bearer"})
            self.assertEqual(json.loads(target.read_text()), {"error": "[REDACTED] / [REDACTED]"})
            if os.name == "posix":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_missing_runtime_prerequisite_is_explicit_failure_with_zero_skips(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = str(Path(temporary) / "does-not-exist")
            command = [sys.executable, "-B", str(ROOT / "scripts/verify-sou62-sou63-combined.py"), "--run",
                "--agentfw", missing, "--node", missing, "--bwrap", missing, "--claude", missing,
                "--sandbox-test-binary", missing, "--expected-commit", "1" * 40, "--output", str(Path(temporary) / "report")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            status = json.loads(result.stdout)
            self.assertEqual((status["status"], status["failed"], status["skipped"]), ("fail", 1, 0))
            self.assertFalse((Path(temporary) / "report").exists())


@unittest.skipUnless(hasattr(os, "mkfifo"), "actual FIFO opening requires POSIX")
class FifoObserverControls(unittest.TestCase):
    def test_calibrated_writer_detects_real_reader_and_closes_its_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.fifo"
            os.mkfifo(path)
            probe = VERIFY.FifoProbe(path)
            with path.open("rb", buffering=0) as reader:
                self.assertEqual(reader.read(), VERIFY.BASE.FIFO_TEXT.encode())
            witness = probe.finish()
            self.assertTrue(witness["reader_seen"])
            self.assertEqual(witness["bytes_written"], len(VERIFY.BASE.FIFO_TEXT.encode()))
            self.assertTrue(witness["thread_stopped"])
            with self.assertRaises(OSError) as refused:
                os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            self.assertEqual(refused.exception.errno, errno.ENXIO)

    def test_no_reader_probe_performs_real_open_attempts_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.fifo"
            os.mkfifo(path)
            probe = VERIFY.FifoProbe(path)
            time.sleep(0.025)
            witness = probe.finish()
            self.assertGreater(witness["attempts"], 0)
            self.assertFalse(witness["reader_seen"])
            self.assertEqual(witness["bytes_written"], 0)
            self.assertIsNone(witness["error"])


if __name__ == "__main__":
    unittest.main()
