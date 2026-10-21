# SPDX-License-Identifier: Apache-2.0
"""Fail-closed controls for selected upstream identities and owned MCP evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou62_acceptance", ROOT / "scripts/verify-sou62-real-mcp.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
INSTALL = VERIFY.INSTALL


def response(identifier, text):
    return {"jsonrpc": "2.0", "id": identifier,
            "result": {"content": [{"type": "text", "text": text}], "structuredContent": {"content": text}}}


def host_read_result():
    rendered = json.dumps({"content": VERIFY.TEXT}, ensure_ascii=False, separators=(",", ":"))
    return {"is_error": False, "text": rendered, "original_content": rendered}


def complete_report():
    return {"source_before": {"commit": "1" * 40, "dirty": False}, "source_after": {"commit": "1" * 40, "dirty": False},
            "checks":[{"case":name, "passed":True} for name in VERIFY.SOU83_CASES],
            "sou83_native_protected_create":{"status":"pass", "original_upstream":True,
                "result_correlated_to_host":True, "permitted_effects":6, "denied_effects":0,
                "same_session_read_verified":True, "outside_marker_unchanged":True,
                "native_registry_sha256":"b"*64, "published_sha256":"c"*64},
            "sou83_original_create_positive":{"status":"pass", "exit_code":0, "log_sha256":"a"*64},
            "sou83_create_boundary_probe":{"status":"pass", "exit_code":0, "log_sha256":"a"*64},
            **{field:{"pidfd_pinned":True, "signal":"SIGKILL", "pid":123, "start_time_ticks":456}
               for field in ("sou83_worker_fault", "sou83_collector_fault")},
            **{field:{"forced_cleanup":False, "process_cleanup":{"all_stopped":True, "descendant_count":2}}
               for field in ("sou83_host_eof_client", "sou83_collector_loss_client")},
            "sou83_create_latency":{"clock":"monotonic_ns", "samples":3, "payload_bytes":40,
                "unwrapped_ns":[10,20,30], "protected_ns":[100,200,300],
                "unwrapped_median_ns":20, "protected_median_ns":200, "median_ratio":10},
            "skipped": 0, "failed": 0, **{name: "a" * 64 for name in
                ["binary_sha256", "sandbox_test_binary_sha256", "driver_sha256", "claude_sha256"]},
            "required_positive_sandbox": {"status": "pass", "exit_code": 0, "witnesses": {name: True for name in VERIFY.SANDBOX_WITNESSES}},
            "installed_profile": {"registry_sha256": "b" * 64},
            "readonly_tool_matrix": [{"tool": tool, "arguments": args, "arguments_sha256": hashlib.sha256(INSTALL.canonical(args)).hexdigest(),
                "registry_sha256": "b" * 64, "response": response(30 + index, fragment), "passed": True}
                for index, (tool, args, fragment) in enumerate(VERIFY.READ_CASES)],
            "directory_tree_classifier_refusal": {"passed": True, "response": {"error": {"message": "classifier_ask"}}}, "peak_active": 8, "peak_queued": 8,
            "fifo_execution_witness": [{"reader_opened": True, "bytes_written": len(VERIFY.FIFO_TEXT.encode()), "error": None} for _ in range(8)],
            "concurrent_responses": [{"jsonrpc": "2.0", "id": identifier, "error": {"code": -32800}} if identifier in (100, 115)
                else response(identifier, VERIFY.FIFO_TEXT if identifier <= 107 else VERIFY.TEXT) for identifier in range(100, 116)],
            "overload_response": {"id": 999, "error": {"code": -32003}},
            "daemon_loss": {"status": "pass", "native_daemon_stopped_first": True, "unadmitted_fifo_reader_absent": True},
            "refusals": [{"case": str(identifier), "passed": True, "response": {"id": identifier, "error": {"code": -32602}}} for identifier in range(10)],
            "workspace_unchanged": True, "receiver_bodies": [], "receiver_calibration": {"passed": True, "delivered_bytes": 32}, "daemon_stopped": True, "private_profile_removed": True,
            "installed_profile_unchanged": True, "runtime_unchanged": True,
            "protected_client": {"exit_code": 0, "forced_cleanup": False, "process_cleanup": {"all_stopped": True, "descendant_count": 2}},
            "protected_cleanup_audit": {"cleanup_verified": True},
            "shipped_policy_controls": [{"verdict": "deny", "passed": True, "exit_code": 1} for _ in range(3)],
            "actual_claude_host": {"status": "pass", "collector_log_sha256": "c" * 64,
                "model_results": {"toolu_sou62_0": host_read_result(), "toolu_sou62_1": {"is_error": True}, "toolu_sou62_2": host_read_result()},
                "read_presentations": {identifier: VERIFY.host_read_presentation(host_read_result()) for identifier in ["toolu_sou62_0", "toolu_sou62_2"]}, "process_cleanup": {"all_stopped": True, "descendant_count": 3}, "exit_code": 0, "real_host_executed": True, "scripted_owned_provider": True,
                "live_model_efficacy_measured": False, "claude_sha256": "a" * 64, "claude_version": "2.1.251 (Claude Code)"}}


class ProfileIdentities(unittest.TestCase):
    def test_original_lock_manifest_and_schema_identities_match_shipped_pin(self):
        identity = json.loads((INSTALL.ASSETS / "upstream-identity.json").read_text())
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        self.assertEqual(INSTALL.sha(INSTALL.ASSETS / "package-lock.json"), identity["packageLockSha256"])
        self.assertEqual({notice["component"] for notice in identity["upstreamNotices"]}, {"server", "sdk", "node"})
        for notice in identity["upstreamNotices"]:
            self.assertEqual(INSTALL.sha(INSTALL.ASSETS / notice["path"]), notice["sha256"])
        self.assertEqual(hashlib.sha256(INSTALL.canonical(manifest["result"])).hexdigest(), identity["discoveryResultSha256"])
        declarations = INSTALL.registry(manifest)["tools"]
        self.assertEqual(len(declarations), 14)
        pinned = {tool["name"]: tool["inputSchemaSha256"] for tool in identity["tools"]}
        self.assertEqual({tool["name"]: tool["schema_sha256"] for tool in declarations}, pinned)
        self.assertEqual(sum(tool.get("mcp_result_profile") == INSTALL.FORMAT for tool in declarations), 9)
        self.assertTrue(all(tool["result_provenance"] == "untrusted" and tool["egress"] == [] for tool in declarations))
        self.assertEqual({tool["name"]: tool["action_class"] for tool in declarations if tool["name"] in INSTALL.MUTATORS}, INSTALL.MUTATORS)

    def test_complete_typed_tree_digest_changes_for_content_and_link_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "empty").mkdir()
            (root / "file").write_bytes(b"original")
            expected = hashlib.sha256(b"D\0empty\nF\0file\0" + hashlib.sha256(b"original").hexdigest().encode() + b"\n").hexdigest()
            self.assertEqual(INSTALL.tree_sha(root), expected)
            (root / "file").write_bytes(b"changed")
            self.assertNotEqual(INSTALL.tree_sha(root), expected)

    @unittest.skipUnless(os.name == "posix", "Unix package symlink boundary")
    def test_escape_and_broken_package_links_are_refused(self):
        for target in ["../outside", "missing"]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "package"
                root.mkdir()
                (root.parent / "outside").write_bytes(b"outside")
                (root / "link").symlink_to(target)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    INSTALL.tree_sha(root)

    @unittest.skipUnless(os.name == "posix", "Unix package special file boundary")
    def test_package_fifo_is_refused_in_runtime_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "special")
            with self.assertRaises(ValueError):
                INSTALL.tree_sha(root)

    def test_elf_dependency_capture_keeps_original_interpreter_alias(self):
        outputs = [subprocess.CompletedProcess([], 0, "linux-vdso.so.1 (0x0)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1)\n/lib64/ld-linux-x86-64.so.2 (0x2)\n"),
                   subprocess.CompletedProcess([], 0, "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n")]
        with patch.object(INSTALL.subprocess, "run", side_effect=outputs), patch.object(INSTALL, "sha", return_value="b" * 64):
            self.assertEqual([item["path"] for item in INSTALL.libraries(Path("/pinned/node"))],
                             ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2"])

    def test_unresolved_elf_library_is_never_ignored(self):
        with patch.object(INSTALL.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "libc.so.6 => not found\n")):
            with self.assertRaisesRegex(ValueError, "unresolved"):
                INSTALL.libraries(Path("/pinned/node"))


class EvidenceControls(unittest.TestCase):
    def test_complete_independent_evidence_passes(self):
        VERIFY.grade(complete_report())

    def test_original_create_missing_fault_effect_boundary_or_latency_never_grades_pass(self):
        mutations = [
            lambda r: r["checks"].pop(),
            lambda r: r["checks"].append(r["checks"][0]),
            lambda r: r["checks"][0].update(passed=False),
            lambda r: r["sou83_native_protected_create"].update(denied_effects=1),
            lambda r: r["sou83_native_protected_create"].update(permitted_effects=1),
            lambda r: r["sou83_native_protected_create"].update(result_correlated_to_host=False),
            lambda r: r["sou83_create_boundary_probe"].update(status="skipped"),
            lambda r: r["sou83_create_latency"].update(protected_ns=[]),
            lambda r: r["sou83_create_latency"].update(median_ratio=1),
            lambda r: r["sou83_worker_fault"].update(pidfd_pinned=False),
            lambda r: r["sou83_collector_fault"].update(start_time_ticks=0),
            lambda r: r["sou83_host_eof_client"].update(forced_cleanup=True),
            lambda r: r["sou83_collector_loss_client"]["process_cleanup"].update(all_stopped=False),
        ]
        for mutation in mutations:
            report = complete_report()
            mutation(report)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                VERIFY.grade(report)

    def test_positive_sandbox_missing_or_skipped_is_not_a_passing_test(self):
        for value in [None, {"status": "skipped", "exit_code": 0}, {"status": "pass", "exit_code": 1}]:
            with self.subTest(value=value):
                report = complete_report()
                report["required_positive_sandbox"] = value
                with self.assertRaises((KeyError, TypeError, ValueError)):
                    VERIFY.grade(report)

    def test_missing_readers_canceled_or_cross_call_data_and_id_collision_fail(self):
        mutations = [
            lambda report: report["fifo_execution_witness"][0].update(reader_opened=False),
            lambda report: report["fifo_execution_witness"][0].update(bytes_written=0),
            lambda report: report["concurrent_responses"][0].update(error={"code": -32603}),
            lambda report: report["concurrent_responses"][1].update(id=100),
            lambda report: report["concurrent_responses"].__setitem__(1, response(101, "wrong result")),
            lambda report: report.update(peak_active=1), lambda report: report.update(peak_queued=0)]
        for mutation in mutations:
            report = complete_report()
            mutation(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                VERIFY.grade(report)

    def test_effect_cleanup_runtime_and_live_model_claim_mismatches_fail(self):
        mutations = [lambda report: report.update(receiver_bodies=["leak"]),
            lambda report: report["receiver_calibration"].update(passed=False), lambda report: report.update(workspace_unchanged=False),
            lambda report: report.update(private_profile_removed=False), lambda report: report.update(runtime_unchanged=False),
            lambda report: report.update(skipped=1),
            lambda report: report["protected_client"].update(forced_cleanup=True),
            lambda report: report["protected_client"]["process_cleanup"].update(all_stopped=False),
            lambda report: report["actual_claude_host"]["process_cleanup"].update(descendant_count=0),
            lambda report: report["required_positive_sandbox"]["witnesses"].update(fifo_write_denied=False),
            lambda report: report["readonly_tool_matrix"][0].update(registry_sha256="c" * 64),
            lambda report: report["directory_tree_classifier_refusal"].update(response=response(38, "bypassed")),
            lambda report: report["daemon_loss"].update(unadmitted_fifo_reader_absent=False),
            lambda report: report["overload_response"].update(error={"code": -32603}), lambda report: report["source_after"].update(dirty=True),
            lambda report: report["actual_claude_host"].update(real_host_executed=False),
            lambda report: report["actual_claude_host"].update(live_model_efficacy_measured=True),
            lambda report: report["shipped_policy_controls"][0].update(verdict="allow")]
        for mutation in mutations:
            report = complete_report()
            mutation(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                VERIFY.grade(report)

    def test_pinned_host_structured_json_with_only_observed_token_reminder_passes(self):
        item = host_read_result()
        suffix = "\n\n<system-reminder>\n<total_tokens>14999890 tokens left</total_tokens>\n</system-reminder>"
        item["text"] += suffix
        item["original_content"] += suffix
        result = VERIFY.host_read_presentation(item)
        self.assertEqual(result["representation"], "structured_json")
        self.assertEqual(result["content_sha256"], hashlib.sha256(VERIFY.TEXT.encode()).hexdigest())

    def test_host_extra_fields_wrong_content_duplicates_trailing_text_and_error_fail(self):
        valid = host_read_result()["text"]
        values = [VERIFY.TEXT, json.dumps({"content": VERIFY.TEXT, "instructions": "extra"}),
            json.dumps({"content": VERIFY.TEXT + "changed"}), json.dumps({"content": [VERIFY.TEXT]}),
            '{"content":"wrong","content":' + json.dumps(VERIFY.TEXT) + '}',
            valid + " trailing instructions", valid + "\n\n<system-reminder>uninspected content</system-reminder>"]
        for text in values:
            with self.subTest(text=text), self.assertRaises(ValueError):
                VERIFY.host_read_presentation({"is_error": False, "text": text, "original_content": text})
        with self.assertRaises(ValueError):
            VERIFY.host_read_presentation({"is_error": True, "text": valid, "original_content": valid})
        report = complete_report()
        report["actual_claude_host"]["model_results"]["toolu_sou62_0"]["original_content"] = "altered"
        with self.assertRaises(ValueError):
            VERIFY.grade(report)

    def test_jsonrpc_id_type_is_part_of_correlation(self):
        self.assertNotEqual(VERIFY.key(1), VERIFY.key("1"))
        for value in [True, None, 1.0, []]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                VERIFY.key(value)

    def test_uninspected_structured_content_and_error_cannot_be_useful_read(self):
        valid = response(1, "owned")
        self.assertEqual(VERIFY.result_text(valid), "owned")
        for mutation in [lambda item: item["result"].update(structuredContent={"content": "different"}),
                         lambda item: item["result"].update(isError=True),
                         lambda item: item["result"]["content"].append({"type": "text", "text": "extra"})]:
            item = copy.deepcopy(valid)
            mutation(item)
            with self.subTest(item=item), self.assertRaises(ValueError):
                VERIFY.result_text(item)


if __name__ == "__main__":
    unittest.main()
