# SPDX-License-Identifier: Apache-2.0
"""Boundary controls for the installed private-output self-test driver."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("private_edit_self_test", ROOT / "scripts/private_edit_self_test.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@contextlib.contextmanager
def process_fixture(infos, children, exited=None, on_open=None):
    exited = set() if exited is None else exited
    class BaseWitness:
        def __init__(self, parent):
            self.parent, self.observed = parent, {}
            self.stopped, self.thread, self.final = mock.Mock(), mock.Mock(), None
            self.thread.is_alive.return_value = False
            self.sample()
    class ProcPath:
        def __init__(self, path):
            self.path = path
        def open(self, _mode):
            pid = int(self.path.split("/")[2])
            if pid not in infos:
                raise FileNotFoundError()
            if self.path.endswith("/stat"):
                start, ppid = infos[pid]
                tail = [b"S", str(ppid).encode(), *([b"0"] * 17), str(start).encode()]
                return io.BytesIO(str(pid).encode() + b" (process) " + b" ".join(tail))
            return io.BytesIO(" ".join(map(str, children.get(pid, []))).encode())
    def pin(pid, _flags):
        if on_open:
            on_open(pid)
        return pid + 1000
    with mock.patch.object(probe, "Path", side_effect=ProcPath), \
         mock.patch.object(probe.os, "getpid", return_value=50), \
         mock.patch.object(probe.os, "pidfd_open", side_effect=pin, create=True), \
         mock.patch.object(probe.signal, "pidfd_send_signal", create=True) as sending, \
         mock.patch.object(probe.os, "kill") as numeric, \
         mock.patch.object(probe.os, "close") as closing, \
         mock.patch.object(probe.select, "select", side_effect=lambda read, *_: ([fd for fd in read if fd in exited], [], [])):
        witness = probe.owned_process_witness(SimpleNamespace(ProcessWitness=BaseWitness), 100)
        yield witness, sending, numeric, closing


def seed():
    rows = probe.inventory()
    for row in rows:
        row.update(status="passed", attempted=True)
    facts = {
        "create-read": {"exact_readback": True}, "replace-read": {"exact_readback": True},
        "ask-reject-replay": {"rejection_observed": True, "replay_refused": True},
        "aggregate-quota": {"second_target_absent": True, "quota_not_refunded": True,
                            "mutation_ceiling_enforced": True, "byte_ceiling_enforced": True},
        "exact-run-stop": {"independent_run_preserved": True},
        "stopped-authority": {"stale_approval_refused": True},
        "daemon-loss": {"read_only_diagnosis": True, "effects": "indeterminate",
                        "host_delivery": "unknown", "model_consumption": "unknown"},
        "fresh-run-recovery": {"old_epoch_refused": True, "old_run_preserved": True,
                               "fresh_ask_required": True, "automatic_retry": False},
    }
    for row in rows:
        row.update(facts[row["id"]])
    return {"format": probe.FORMAT, "status": "passed", "executed": True, "paid_inference": False,
            "expected": list(probe.CASES), "cases": rows,
            "cleanup": {"all_owned_processes_stopped": True, "workspace_removed": True},
            "preservation": {"installed_state_unchanged": True, "original_projects_unchanged": True,
                             "unrelated_sentinel_unchanged": True}}


class PrivateEditSelfTest(unittest.TestCase):
    def test_quota_authorization_count_is_separate_from_physical_reservations(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "result"
            target.write_bytes(probe.NEW)
            row = {"id": "aggregate-quota"}
            suite = SimpleNamespace(report={"active_case": "aggregate-quota", "cases": [row]})
            observed = {"toolu_self_test_" + str(i): {"is_error": False, "content": text.decode()}
                        for i, text in enumerate((probe.OLD, b"created", probe.NEW))}
            run = SimpleNamespace(target=target, suite=suite, observed=observed)
            facts = {"native_write_authorizations": 2,
                     "quota": {"admitted_mutation_attempts": 1, "known_committed_mutations": 1}}
            probe.useful(run, facts, expected_authorizations=2)
            self.assertTrue(row["runtime_attempts"][-1]["readback"]["expected_write_authorizations"])
            with self.assertRaisesRegex(ValueError, "useful_expected_write_authorizations_missing"):
                probe.useful(run, facts)
            observed["toolu_self_test_2"]["content"] = "unrelated private payload"
            with self.assertRaisesRegex(ValueError, "useful_final_read_exact_missing"):
                probe.useful(run, facts, expected_authorizations=2)
            self.assertNotIn("unrelated private payload", json.dumps(row))

    def test_quota_refusal_requires_exact_code_and_no_reset_or_retry(self):
        code = "edit_quota_mutation_limit"
        value = {"error_code": code, "automatic_retry": False, "active_run_reset_available": False}
        result = {"is_error": True, "content": [{"type": "text", "text": json.dumps(value)}]}
        self.assertTrue(probe.quota_refusal(result, code))
        self.assertFalse(probe.quota_refusal(result, "edit_quota_write_byte_limit"))
        self.assertFalse(probe.quota_refusal(dict(result, is_error=False), code))
        for field in ("automatic_retry", "active_run_reset_available"):
            changed = dict(value, **{field: True})
            self.assertFalse(probe.quota_refusal(dict(result, content=json.dumps(changed)), code))
        self.assertFalse(probe.quota_refusal(dict(result, content=code), code))

    def test_only_budget_scan_tolerates_vanished_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            temporary_file = root / "publication-stage"
            temporary_file.write_bytes(b"synthetic")
            original = Path.lstat
            def disappearing(path):
                if path == temporary_file:
                    raise FileNotFoundError(2, "private-payload", "/private/path")
                return original(path)
            with mock.patch.object(Path, "lstat", disappearing):
                with self.assertRaises(FileNotFoundError):
                    probe.tree_witness(root)
                probe.tree_witness(root, contents=False, transient=True)
                with self.assertRaisesRegex(ValueError, "transient_content_witness_refused"):
                    probe.tree_witness(root, transient=True)

    def test_failure_observation_omits_exception_text_paths_and_payloads(self):
        try:
            probe.bounded(Path("/absent-owned-failure-location/private-payload"))
        except OSError as error:
            value = probe.failure_observation(error)
        self.assertEqual(value["kind"], "FileNotFoundError")
        self.assertEqual(value["errno"], 2)
        self.assertEqual(value["helper_function"], "bounded")
        self.assertGreater(value["helper_line"], 0)
        self.assertNotIn("private-payload", json.dumps(value))
        self.assertNotIn("absent-owned", json.dumps(value))

    def test_symlink_witness_and_cleanup_never_follow_or_modify_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned = base / "owned"
            owned.mkdir()
            outside = base / "outside"
            outside.write_bytes(b"external sentinel")
            alias = owned / "latest"
            try:
                alias.symlink_to(outside)
            except OSError:
                self.skipTest("creating symlinks is unavailable for this user")
            before = probe.snapshot(outside)
            first = probe.tree_witness(owned)
            alias.unlink()
            alias.symlink_to(base / "absent-target")
            self.assertNotEqual(probe.tree_witness(owned), first)
            probe.remove_owned(owned)
            self.assertFalse(owned.exists())
            self.assertEqual(probe.snapshot(outside), before)

    def test_fixed_inventory_does_not_accept_missing_duplicate_reordered_or_unattempted_rows(self):
        self.assertTrue(probe.passed(seed()))
        for index in range(len(probe.CASES)):
            for mutation in ("missing", "unattempted", "incomplete", "unsupported"):
                report = seed()
                if mutation == "missing":
                    report["cases"].pop(index)
                elif mutation == "unattempted":
                    report["cases"][index]["attempted"] = False
                else:
                    report["cases"][index]["status"] = mutation
                self.assertFalse(probe.passed(report))
        for mutation in ("reorder", "duplicate"):
            report = seed()
            if mutation == "reorder":
                report["cases"].reverse()
            else:
                report["cases"].append(copy.deepcopy(report["cases"][0]))
            self.assertFalse(probe.passed(report))

    def test_log_verdict_without_independent_witness_cannot_pass(self):
        for index, original in enumerate(seed()["cases"]):
            for key in set(original) - {"id", "attempted", "status"}:
                report = seed()
                report["cases"][index].pop(key)
                self.assertFalse(probe.passed(report), (original["id"], key))
        for section, field in (("cleanup", "all_owned_processes_stopped"),
                               ("preservation", "installed_state_unchanged"),
                               ("preservation", "original_projects_unchanged"),
                               ("preservation", "unrelated_sentinel_unchanged")):
            report = seed(); report[section][field] = False
            self.assertFalse(probe.passed(report))

    def test_interrupted_matching_bytes_never_mean_success_or_delivery(self):
        for field in ("effects", "host_delivery", "model_consumption"):
            report = seed()
            row = next(row for row in report["cases"] if row["id"] == "daemon-loss")
            row[field] = "success"
            self.assertFalse(probe.passed(report))
        report = seed(); report["cases"][-1]["automatic_retry"] = True
        self.assertFalse(probe.passed(report))

    def test_exact_readback_rejects_prefix_suffix_and_payload_in_other_field(self):
        expected = probe.NEW
        for value in (expected.decode(), {"content": expected.decode()}):
            content = json.dumps(value) if isinstance(value, dict) else value
            self.assertTrue(probe.exact_result(content, expected))
            self.assertTrue(probe.exact_result([{"type": "text", "text": content}], expected))
        for content in ("prefix" + expected.decode(), expected.decode() + "suffix",
                        json.dumps({"other": expected.decode()}),
                        json.dumps({"content": expected.decode(), "other": "ignored"}),
                        [{"type": "image", "text": expected.decode()}], None):
            self.assertFalse(probe.exact_result(content, expected))

    def test_preview_has_no_write_process_or_provider_even_with_output_argument(self):
        identities = {"component_sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "must-not-exist"
            with mock.patch.object(probe, "platform_profile", return_value={"id": "native-linux-x86_64", "supported": True}), \
                 mock.patch.object(probe.os, "geteuid", return_value=1000, create=True), \
                 mock.patch.object(probe, "preflight", return_value=(None, {}, {}, identities)), \
                 mock.patch.object(probe.subprocess, "Popen", side_effect=AssertionError("process in preview")), \
                 mock.patch.object(probe, "Suite", side_effect=AssertionError("execution in preview")), \
                 contextlib.redirect_stdout(io.StringIO()) as text:
                code = probe.main(["--home", temp, "--selection", temp, "--agent", temp, "--output", str(output)])
            self.assertEqual(code, 0)
            value = json.loads(text.getvalue())
            self.assertEqual(value["status"], "preview")
            self.assertFalse(value["executed"])
            self.assertEqual(value["inventory"]["attempted"], 0)
            self.assertFalse(output.exists())

    def test_checkout_preview_never_falls_back_to_git_or_path_programs(self):
        args = SimpleNamespace(home=Path("/owned/home"))
        source = SimpleNamespace(installed=lambda _root: None)
        with mock.patch.object(probe, "load", return_value=source), \
             mock.patch.object(probe.subprocess, "Popen", side_effect=AssertionError("ambient process")):
            with self.assertRaisesRegex(ValueError, "verified_installed_component_required"):
                probe.preflight(args)

    def test_unsupported_platform_is_distinct_and_inert(self):
        with mock.patch.object(probe, "platform_profile", return_value={"id": "unsupported", "supported": False}), \
             mock.patch.object(probe, "preflight", side_effect=AssertionError("unsupported preflight")), \
             contextlib.redirect_stdout(io.StringIO()) as text:
            code = probe.main(["--home", "/missing", "--selection", "/missing", "--agent", "/missing"])
        value = json.loads(text.getvalue())
        self.assertEqual(code, 5)
        self.assertEqual(value["status"], "unsupported")
        self.assertEqual(value["inventory"]["unsupported"], len(probe.CASES))
        self.assertFalse(value["executed"])

    def test_public_reason_never_contains_paths_payloads_or_arbitrary_exception_text(self):
        secret = "owned-secret-canary"
        for error in (OSError("/private/" + secret), ValueError("payload " + secret),
                      RuntimeError(secret), KeyError(secret)):
            self.assertEqual(probe.reason(error), "self_test_observation_incomplete")
        self.assertEqual(probe.reason(ValueError("aggregate_quota_not_enforced")), "aggregate_quota_not_enforced")
        self.assertEqual(probe.reason(TimeoutError()), "self_test_deadline")

    def test_provider_limits_before_retention_including_auxiliary_requests(self):
        requests = probe.BoundedRequests()
        for _ in range(32):
            requests.append(b"{}")
        with self.assertRaisesRegex(ValueError, "provider_request_limit"):
            requests.append(b"private payload must not be retained")
        self.assertEqual(len(requests), 32)
        requests = probe.BoundedRequests()
        with self.assertRaisesRegex(ValueError, "provider_request_limit"):
            requests.append(b"x" * (probe.MAX_STREAM + 1))
        self.assertEqual(requests, [])
        self.assertEqual(requests.bytes, 0)

    def test_bounded_reader_rejects_large_special_linked_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input"
            path.write_bytes(b"1234")
            self.assertEqual(probe.bounded(path, 4), b"1234")
            with self.assertRaisesRegex(ValueError, "bounded_regular_file_required"):
                probe.bounded(path, 3)
            alias = path.with_name("alias")
            os.link(path, alias)
            with self.assertRaisesRegex(ValueError, "bounded_regular_file_required"):
                probe.bounded(path, 4)

    def test_finite_project_witness_detects_content_change_and_addition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").write_text("first")
            before = probe.tree_witness(root)
            (root / "source").write_text("other")
            self.assertNotEqual(probe.tree_witness(root), before)
            before = probe.tree_witness(root)
            (root / "added").write_text("new")
            self.assertNotEqual(probe.tree_witness(root), before)
            with mock.patch.object(probe, "MAX_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "witness_entry_limit"):
                    probe.tree_witness(root)

    def test_opaque_hyphenated_pending_id_is_only_a_positional_argument(self):
        suite = object.__new__(probe.Suite)
        suite.cli = mock.Mock(return_value=(1, None))
        pending = {"pending_id": "--help", "binding_sha256": "a" * 64}
        suite.ask(Path("/owned/run"), "approve", pending)
        words = suite.cli.call_args.args
        self.assertEqual(words[-2:], ("--", "--help"))
        self.assertEqual(words[-4:-2], ("--binding", "a" * 64))

    def test_counts_preserve_unattempted_failed_and_unsupported_distinctions(self):
        rows = probe.inventory()
        rows[0].update(attempted=True, status="failed")
        rows[1].update(status="unsupported")
        value = probe.counts(rows)
        self.assertEqual(value["attempted"], 1)
        self.assertEqual(value["failed"], 1)
        self.assertEqual(value["unsupported"], 1)
        self.assertEqual(value["incomplete"], len(rows) - 2)

    def test_cli_requires_execution_consent_and_valid_deadline(self):
        for words in (["--run"], ["--timeout-seconds", "9"], ["--timeout-seconds", "601"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                probe.main(["--home", "/owned", "--selection", "/owned", "--agent", "/owned", *words])
            self.assertEqual(result.exception.code, 2)

    def test_cleanup_removes_readonly_owned_plan_and_preserves_peer(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            owned = parent / "owned"; owned.mkdir()
            plan = owned / "plan"; plan.mkdir()
            (plan / "profile.json").write_text("synthetic plan")
            (plan / "profile.json").chmod(0o400); plan.chmod(0o500)
            peer = parent / "peer"; peer.write_text("preserve")
            probe.remove_owned(owned)
            self.assertFalse(owned.exists())
            self.assertEqual(peer.read_text(), "preserve")
            with self.assertRaisesRegex(ValueError, "cleanup_root_identity_changed"):
                probe.remove_owned(parent)

    def test_process_witness_never_adopts_reused_parent_or_foreign_descendants(self):
        class BaseWitness:
            def __init__(self, parent):
                self.parent, self.observed = parent, {}
                self.stopped, self.thread, self.final = mock.Mock(), mock.Mock(), None
                self.thread.is_alive.return_value = False
                self.sample()
            def finish(self):
                return {"all_stopped": True}
        starts = {100: 10, 101: 11, 202: 22}
        children = {100: [101], 101: [], 202: []}
        class ProcPath:
            def __init__(self, path):
                self.path = path
            def open(self, _mode):
                parts = self.path.split("/")
                pid = int(parts[2])
                if self.path.endswith("/stat"):
                    ppid = 50 if pid == 100 else 100
                    tail = [b"S", str(ppid).encode(), *([b"0"] * 17), str(starts[pid]).encode(), b"0"]
                    return io.BytesIO(str(pid).encode() + b" (owned process) " + b" ".join(tail))
                return io.BytesIO(" ".join(map(str, children[pid])).encode())
        base = SimpleNamespace(ProcessWitness=BaseWitness)
        with mock.patch.object(probe, "Path", side_effect=ProcPath), \
             mock.patch.object(probe.os, "getpid", return_value=50), \
             mock.patch.object(probe.os, "pidfd_open", side_effect=lambda pid, _flags: pid + 1000, create=True), \
             mock.patch.object(probe.signal, "pidfd_send_signal", create=True), \
             mock.patch.object(probe.os, "close"), \
             mock.patch.object(probe.select, "select", side_effect=lambda read, *_: (read, [], [])):
            witness = probe.owned_process_witness(base, 100)
            self.assertEqual(set(witness.observed), {(100, 10), (101, 11)})
            before = copy.deepcopy(witness.observed)
            starts[100] = 99
            children[100] = [202]
            witness.sample()
            self.assertEqual(witness.observed, before)
            self.assertNotIn((100, 99), witness.observed)
            self.assertNotIn((202, 22), witness.observed)

    def test_process_witness_caps_recursive_observations(self):
        class BaseWitness:
            def __init__(self, parent):
                self.parent, self.observed = parent, {}
                self.stopped, self.thread, self.final = mock.Mock(), mock.Mock(), None
                self.thread.is_alive.return_value = False
                self.sample()
            def finish(self):
                return {"all_stopped": True}
        class ProcPath:
            def __init__(self, path):
                self.path = path
            def open(self, _mode):
                if self.path.endswith("/stat"):
                    return io.BytesIO(b"100 (owned) " + b" ".join([b"S", b"50", *([b"0"] * 17), b"10"]))
                return io.BytesIO(b" ".join(str(n).encode() for n in range(1, 130)))
        with mock.patch.object(probe, "Path", side_effect=ProcPath), \
             mock.patch.object(probe.os, "getpid", return_value=50), \
             mock.patch.object(probe.os, "pidfd_open", return_value=1000, create=True), \
             mock.patch.object(probe.signal, "pidfd_send_signal", create=True), \
             mock.patch.object(probe.os, "close"), \
             mock.patch.object(probe.select, "select", side_effect=lambda read, *_: (read, [], [])):
            witness = probe.owned_process_witness(SimpleNamespace(ProcessWitness=BaseWitness), 100)
            self.assertEqual(witness.observation_error, "process_observation_incomplete")
            self.assertFalse(witness.finish()["all_stopped"])

    def test_retained_workspace_only_passes_with_explicit_keep_consent(self):
        report = seed()
        report["cleanup"].update(workspace_removed=False, workspace_retained=True)
        self.assertFalse(probe.passed(report))
        report["cleanup"]["keep_workspace_requested"] = False
        self.assertFalse(probe.passed(report))
        report["cleanup"]["keep_workspace_requested"] = True
        self.assertTrue(probe.passed(report))

    def test_recycled_child_with_foreign_parent_is_never_signalled(self):
        class BaseWitness:
            def __init__(self, parent):
                self.parent, self.observed = parent, {}
                self.stopped, self.thread, self.final = mock.Mock(), mock.Mock(), None
                self.thread.is_alive.return_value = False
                self.sample()
        for race in (False, True):
            child = {"start": 11, "parent": 100 if race else 999}
            class ProcPath:
                def __init__(self, path):
                    self.path = path
                def open(self, _mode):
                    pid = int(self.path.split("/")[2])
                    if self.path.endswith("/stat"):
                        start, ppid = (10, 50) if pid == 100 else (child["start"], child["parent"])
                        tail = [b"S", str(ppid).encode(), *([b"0"] * 17), str(start).encode()]
                        return io.BytesIO(str(pid).encode() + b" (process) " + b" ".join(tail))
                    return io.BytesIO(b"101" if pid == 100 else b"")
            def pin(pid, _flags):
                if pid == 101 and race:
                    # The child exits and this numeric PID becomes a foreign
                    # process between the first stat read and pidfd_open.
                    child.update(start=22, parent=999)
                return pid + 1000
            with mock.patch.object(probe, "Path", side_effect=ProcPath), \
                 mock.patch.object(probe.os, "getpid", return_value=50), \
                 mock.patch.object(probe.os, "pidfd_open", side_effect=pin, create=True) as opening, \
                 mock.patch.object(probe.signal, "pidfd_send_signal", create=True) as sending, \
                 mock.patch.object(probe.os, "kill") as numeric_signal, \
                 mock.patch.object(probe.os, "close") as closing, \
                 mock.patch.object(probe.select, "select", side_effect=lambda read, *_: (read, [], [])):
                witness = probe.owned_process_witness(SimpleNamespace(ProcessWitness=BaseWitness), 100)
                self.assertEqual(set(witness.observed), {(100, 10)})
                self.assertEqual(set(witness.handles), {(100, 10)})
                self.assertIsNone(witness.observation_error)
                witness.signal_owned(9)
                self.assertEqual([call.args[0] for call in sending.call_args_list], [1100])
                numeric_signal.assert_not_called()
                result = witness.finish()
                self.assertTrue(result["all_stopped"])
                witness.finish(); witness.signal_owned(9)
                self.assertEqual(len(sending.call_args_list), 1)
                self.assertEqual(sorted(call.args[0] for call in closing.call_args_list), [1100, 1101])
                self.assertEqual([call.args[0] for call in opening.call_args_list], [100, 101])

    def test_already_pinned_child_remains_owned_after_original_parent_exits(self):
        infos = {100: (10, 50), 101: (11, 100), 102: (12, 101)}
        exited = set()
        with process_fixture(infos, {100: [101], 101: [102]}, exited) as (witness, sending, numeric, closing):
            infos.pop(101); infos[102] = (12, 1); exited.add(1101)
            self.assertEqual(witness.pin(102, 101, 11), (102, 12))
            self.assertIsNone(witness.observation_error)
            witness.signal_owned(9)
            self.assertEqual({call.args[0] for call in sending.call_args_list}, {1100, 1101, 1102})
            numeric.assert_not_called()
            exited.update((1100, 1102))
            self.assertTrue(witness.finish()["all_stopped"])
            self.assertEqual(closing.call_count, 3)

    def test_same_birth_child_reparent_during_pin_requires_original_parent_pidfd_exit(self):
        infos = {100: (10, 50), 101: (11, 100)}
        exited = set()
        def on_open(pid):
            if pid == 101:
                infos.pop(100); infos[101] = (11, 1); exited.add(1100)
        with process_fixture(infos, {100: [101]}, exited, on_open) as (witness, _sending, numeric, _closing):
            self.assertEqual(set(witness.observed), {(100, 10), (101, 11)})
            self.assertEqual(witness.reparented_owned, 1)
            self.assertIsNone(witness.observation_error)
            numeric.assert_not_called()
            exited.add(1101)
            self.assertTrue(witness.finish()["all_stopped"])

    def test_exited_hint_after_pin_is_benign_and_not_signalled(self):
        infos = {100: (10, 50), 101: (11, 100)}
        exited = set()
        def on_open(pid):
            if pid == 101:
                infos.pop(101); exited.add(1101)
        with process_fixture(infos, {100: [101]}, exited, on_open) as (witness, sending, numeric, closing):
            self.assertEqual(set(witness.observed), {(100, 10)})
            self.assertEqual(witness.exited_hints, 1)
            witness.signal_owned(9)
            self.assertEqual([call.args[0] for call in sending.call_args_list], [1100])
            numeric.assert_not_called()
            exited.add(1100)
            self.assertTrue(witness.finish()["all_stopped"])
            self.assertEqual(closing.call_count, 2)

    def test_live_unproven_hint_prevents_complete_cleanup_and_is_never_signalled(self):
        infos = {100: (10, 50), 101: (11, 999)}
        exited = set()
        with process_fixture(infos, {100: [101]}, exited) as (witness, sending, numeric, _closing):
            self.assertEqual(set(witness.handles), {(100, 10)})
            self.assertEqual(set(witness.unproven), {(101, 11)})
            witness.signal_owned(9)
            self.assertEqual([call.args[0] for call in sending.call_args_list], [1100])
            numeric.assert_not_called()
            exited.add(1100)
            with mock.patch.object(probe.time, "monotonic", side_effect=(0, 6)):
                result = witness.finish()
            self.assertFalse(result["all_stopped"])
            self.assertEqual(result["unproven_hints_remaining"], [{"pid": 101, "start_time_ticks": 11}])
            exited.add(1101)
            self.assertTrue(witness.finish()["all_stopped"])

    def test_missing_pidfd_support_refuses_before_creating_owned_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            args = SimpleNamespace(output=Path(temp))
            with mock.patch.object(probe.os, "pidfd_open", side_effect=OSError(38, "unsupported"), create=True), \
                 mock.patch.object(probe.signal, "pidfd_send_signal", create=True), \
                 mock.patch.object(probe.subprocess, "Popen") as starting:
                with self.assertRaises(OSError):
                    probe.Suite(args, {}, {}, {})
                starting.assert_not_called()
                self.assertFalse((args.output / "owned").exists())

    def test_missing_observation_is_incomplete_but_forbidden_effect_is_failed(self):
        for error, expected_code, expected_status in (
                (probe.ObservationIncomplete("owned_process_cleanup_incomplete"), 4, "incomplete"),
                (ValueError("rejected_write_had_effect"), 3, "failed")):
            with mock.patch.object(probe, "platform_profile", return_value={"id": "native-linux-x86_64", "supported": True}), \
                 mock.patch.object(probe.os, "geteuid", return_value=1000, create=True), \
                 mock.patch.object(probe, "preflight", side_effect=error), \
                 contextlib.redirect_stdout(io.StringIO()) as text:
                code = probe.main(["--home", "/owned", "--selection", "/owned", "--agent", "/owned"])
            result = json.loads(text.getvalue())
            self.assertEqual((code, result["status"]), (expected_code, expected_status))
            self.assertEqual(result["reason"], str(error))

    def test_directory_enumeration_stops_at_bound_before_retaining_all_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "owned"
            root.mkdir()
            for number in range(20):
                (root / str(number)).write_text("synthetic")
            original = os.scandir
            yielded = []
            class Tracked:
                def __init__(self, path):
                    self.entries = original(path)
                def __enter__(self):
                    return self
                def __exit__(self, *_):
                    self.entries.close()
                def __iter__(self):
                    return self
                def __next__(self):
                    entry = next(self.entries)
                    yielded.append(entry.name)
                    return entry
            with mock.patch.object(probe.os, "scandir", side_effect=Tracked), \
                 mock.patch.object(probe, "MAX_ENTRIES", 3):
                with self.assertRaisesRegex(ValueError, "witness_entry_limit"):
                    probe.tree_witness(root)
                self.assertEqual(len(yielded), 3)
                yielded.clear()
                with self.assertRaisesRegex(ValueError, "cleanup_entry_limit"):
                    probe.remove_owned(root)
                self.assertEqual(len(yielded), 3)
            self.assertEqual(len(list(root.iterdir())), 20)

    def test_default_cleanup_failure_forces_incomplete_report(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "attempt"
            fake_suite = SimpleNamespace(active=[], roots={}, work=output / "owned", sentinel=output / "owned/sentinel")
            def create_output(_args, _roots):
                output.mkdir()
                fake_suite.work.mkdir()
                fake_suite.sentinel.write_bytes(b"synthetic")
                fake_suite.sentinel_before = probe.snapshot(fake_suite.sentinel)
            def execute(_suite, report):
                complete = seed()
                report["cases"] = complete["cases"]
            with mock.patch.object(probe, "platform_profile", return_value={"id": "native-linux-x86_64", "supported": True}), \
                 mock.patch.object(probe.os, "geteuid", return_value=1000, create=True), \
                 mock.patch.object(probe, "preflight", return_value=(None, {}, {}, {})), \
                 mock.patch.object(probe, "output_directory", side_effect=create_output), \
                 mock.patch.object(probe, "tree_witness", return_value="unchanged"), \
                 mock.patch.object(probe, "bounded", return_value=b"unchanged"), \
                 mock.patch.object(probe, "Suite", return_value=fake_suite) as suite_class, \
                 mock.patch.object(probe, "execute", side_effect=execute), \
                 mock.patch.object(probe, "remove_owned", side_effect=OSError("injected failure")), \
                 contextlib.redirect_stdout(io.StringIO()) as text:
                suite_class.write = lambda path, raw: path.write_bytes(raw)
                code = probe.main(["--home", "/owned/home", "--selection", "/owned/selection", "--agent", "/owned/agent",
                                   "--run", "--output", str(output)])
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(code, 4)
            self.assertEqual(json.loads(text.getvalue())["status"], "incomplete")
            self.assertFalse(report["cleanup"]["workspace_removed"])
            self.assertTrue(report["cleanup"]["workspace_retained"])
            self.assertFalse(report["cleanup"]["keep_workspace_requested"])


if __name__ == "__main__":
    unittest.main()
