# SPDX-License-Identifier: Apache-2.0
"""Boundary regressions for the opt-in Linux notification drill; no Docker is launched."""
import contextlib
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import shutil
import ssl
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

SCRIPT = Path(__file__).resolve().parents[1] / "linux-alert-acceptance.py"
SPEC = importlib.util.spec_from_file_location("linux_alert_acceptance_under_test", SCRIPT)
DRILL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRILL)

SOURCE = {"commit": "1" * 40, "tree": "2" * 40, "clean": True, "cargo_lock_sha256": "3" * 64}
IMAGE_ID = "sha256:" + "a" * 64


def plan_fixture(source=None):
    return {"schema_version": 1, "status": "plan", "executed": False,
            "source": dict(source or SOURCE), "images": {"images": image_inventory()}}


def image_inventory():
    return {name: {"image": "example/" + name + "@sha256:" + "a" * 64}
            for name in ["prometheus", "alertmanager", "postgres", "redis", "python", "rust"]}


def complete_receipts():
    rows = []
    for index, alert in enumerate(DRILL.ALERTS.values()):
        labels = {"alertname": alert[0], "job": DRILL.JOB, "instance": DRILL.INSTANCE,
                  "severity": "critical", "component": alert[1]}
        cycle_id = hashlib.sha256(json.dumps(labels, sort_keys=True).encode()).hexdigest()
        for status in ["firing", "resolved"]:
            rows.append({"labels": labels, "status": status, "cycle_id": cycle_id,
                         "event_id": hashlib.sha256((cycle_id + status).encode()).hexdigest(),
                         "starts_at": f"2026-10-14T12:0{index}:00Z",
                         "ends_at": "0001-01-01T00:00:00Z" if status == "firing" else f"2026-10-14T12:1{index}:00Z"})
    return {"records": rows, "total_unique_events": 6, "returned_records": 6, "has_more": False}


class SourceArchiveExtraction(unittest.TestCase):
    def archive(self, members):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w") as bundle:
            for name, kind, data in members:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                member.mode = 0o7777
                member.linkname = "../outside"
                bundle.addfile(member, io.BytesIO(data) if member.isfile() else None)
        content.seek(0)
        return tarfile.open(fileobj=content)

    def test_regular_git_files_extract_without_filter_api_and_without_privilege_bits(self):
        with tempfile.TemporaryDirectory() as temporary, self.archive([
                ("deploy/", tarfile.DIRTYPE, b""),
                ("deploy/run.sh", tarfile.REGTYPE, b"#!/bin/sh\n"),
                ("README.md", tarfile.REGTYPE, b"owned snapshot")]) as bundle:
            with patch.object(bundle, "extractall", side_effect=AssertionError("unsafe API")):
                DRILL.extract_source_archive(bundle, Path(temporary))
            self.assertEqual((Path(temporary) / "deploy/run.sh").read_bytes(), b"#!/bin/sh\n")
            if os.name == "posix":
                self.assertEqual((Path(temporary) / "deploy/run.sh").stat().st_mode & 0o7777, 0o755)

    @unittest.skipUnless(os.name == "posix", "Docker source permissions require Unix modes")
    def test_private_umask_preserves_public_source_modes_and_private_parent(self):
        with tempfile.TemporaryDirectory() as temporary, self.archive([
                ("policies/", tarfile.DIRTYPE, b""),
                ("policies/default.yaml", tarfile.REGTYPE, b"owned public policy"),
                ("scripts/receiver.py", tarfile.REGTYPE, b"owned public helper")]) as bundle:
            parent = Path(temporary)
            parent.chmod(0o700)
            destination = parent / "source"
            destination.mkdir(mode=0o700)
            bundle.getmember("policies/default.yaml").mode = 0o644
            original = os.umask(0o077)
            try:
                DRILL.extract_source_archive(bundle, destination)
                observed = os.umask(0o077)
            finally:
                os.umask(original)
            self.assertEqual(observed, 0o077)
            self.assertEqual(parent.stat().st_mode & 0o7777, 0o700)
            for directory in [destination, destination / "policies", destination / "scripts"]:
                self.assertEqual(directory.stat().st_mode & 0o7777, 0o755)
            self.assertEqual((destination / "policies/default.yaml").stat().st_mode & 0o7777, 0o644)
            self.assertEqual((destination / "scripts/receiver.py").stat().st_mode & 0o7777, 0o755)

    def test_rejects_paths_links_devices_duplicates_and_file_parents_before_writing(self):
        for members in [
                [(name, tarfile.REGTYPE, b"bad")] for name in
                ["../escape", "/absolute", "a/../escape", "a//b", "./local", "a\\b"]
            ] + [
                [("link", kind, b"")] for kind in
                [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]
            ] + [
                [("same", tarfile.REGTYPE, b"first"), ("same", tarfile.REGTYPE, b"second")],
                [("file", tarfile.REGTYPE, b"first"), ("file/child", tarfile.REGTYPE, b"second")],
                [("file/child", tarfile.REGTYPE, b"first"), ("file", tarfile.REGTYPE, b"second")]]:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as temporary, self.archive(members) as bundle:
                with self.assertRaises(DRILL.DrillError):
                    DRILL.extract_source_archive(bundle, Path(temporary))
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_nonempty_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary, self.archive([]) as bundle:
            existing = Path(temporary) / "keep"
            existing.write_bytes(b"unchanged")
            with self.assertRaises(DRILL.DrillError):
                DRILL.extract_source_archive(bundle, Path(temporary))
            self.assertEqual(existing.read_bytes(), b"unchanged")


@unittest.skipUnless(os.name == "posix", "protected fixture files require Unix ownership and permissions")
class ProtectedFixtureFiles(unittest.TestCase):
    def test_first_secret_byte_is_written_only_to_exclusive_0600_owned_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, witness = Path(temporary), []
            path = directory / "credentials"
            original_fdopen = os.fdopen

            class WitnessStream:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    self.stream.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def __getattr__(self, name):
                    return getattr(self.stream, name)

                def write(inner, content):
                    details = os.fstat(inner.stream.fileno())
                    self.assertEqual(details.st_mode & 0o777, 0o600)
                    self.assertEqual(details.st_uid, os.geteuid())
                    self.assertEqual(details.st_nlink, 1)
                    self.assertFalse(path.exists(), "partial contents must not be published")
                    witness.append(len(content))
                    return inner.stream.write(content)

            original_umask = os.umask(0)
            try:
                with patch.object(DRILL.os, "fdopen", side_effect=lambda *a, **kw: WitnessStream(original_fdopen(*a, **kw))):
                    DRILL.protected_file(path, "synthetic disposable credential")
            finally:
                os.umask(original_umask)
            self.assertEqual(witness, [31])
            self.assertEqual(path.read_text(), "synthetic disposable credential")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(list(directory.iterdir()), [path])

    def test_existing_files_and_links_are_never_followed_or_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            victim = directory / "existing"
            victim.write_text("preserve existing owned data")
            victim.chmod(0o640)
            link = directory / "symlink"
            link.symlink_to(victim)
            hardlink = directory / "hardlink"
            os.link(victim, hardlink)
            for path in (victim, link, hardlink):
                with self.subTest(path=path.name), self.assertRaises(FileExistsError):
                    DRILL.protected_file(path, "must not be written")
            self.assertEqual(victim.read_text(), "preserve existing owned data")
            self.assertEqual(victim.stat().st_mode & 0o777, 0o640)
            self.assertTrue(link.is_symlink())
            self.assertEqual({p.name for p in directory.iterdir()}, {"existing", "symlink", "hardlink"})

    def test_bad_parent_permissions_ownership_and_links_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            unsafe = directory / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o777)
            with self.assertRaises(DRILL.DrillError):
                DRILL.protected_file(unsafe / "credential", "must not be written")
            with patch.object(DRILL.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaises(DRILL.DrillError):
                DRILL.protected_file(directory / "credential", "must not be written")
            linked = directory / "linked"
            linked.symlink_to(unsafe)
            with self.assertRaises(OSError):
                DRILL.protected_file(linked / "credential", "must not be written")
            self.assertEqual(list(unsafe.iterdir()), [])
            self.assertFalse((directory / "credential").exists())

    def test_write_failure_never_publishes_partial_data_and_removes_owned_temporary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original_fdopen = os.fdopen

            class FailedStream:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def write(self, _):
                    self.stream.write("partial synthetic data")
                    raise OSError("synthetic disk failure")

            with patch.object(DRILL.os, "fdopen", side_effect=lambda *a, **kw: FailedStream(original_fdopen(*a, **kw))):
                with self.assertRaises(OSError):
                    DRILL.protected_file(directory / "credentials", "must not be published")
            self.assertEqual(list(directory.iterdir()), [])

    def test_public_readonly_config_and_exclusive_name_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            public = directory / "public-config"
            DRILL.protected_file(public, "public fixture configuration", 0o444)
            self.assertEqual(public.stat().st_mode & 0o777, 0o444)
            collision = directory / (".protected-" + "a" * 32)
            collision.write_text("unrelated existing temporary")
            with patch.object(DRILL.secrets, "token_hex", return_value="a" * 32), self.assertRaises(FileExistsError):
                DRILL.protected_file(directory / "credentials", "must not be written")
            self.assertEqual(collision.read_text(), "unrelated existing temporary")
            self.assertFalse((directory / "credentials").exists())
            with self.assertRaises(DRILL.DrillError):
                DRILL.protected_file(directory / "unsafe-mode", "must not be written", 0o666)
            self.assertFalse((directory / "unsafe-mode").exists())


@unittest.skipUnless(os.name == "posix", "Linux fixture credential files require Unix permissions")
class LinuxAlertCredentialStorage(unittest.TestCase):
    def test_service_passwords_remain_in_child_environment_and_redis_uses_acl_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = object.__new__(DRILL.Runtime)
            runtime.directory = Path(temporary)
            runtime.environment = os.environ.copy()
            runtime.admin = "synthetic-admin-token-for-private-runtime"
            before = dict(os.environ)
            runtime.prepare_credentials()
            self.assertTrue(dict(os.environ) == before, "global process environment was changed")
            postgres_password = runtime.environment["SOUP_WALL_DRILL_POSTGRES_PASSWORD"]
            redis_password = DRILL.urllib.parse.urlsplit(runtime.environment["SOUP_WALL_DRILL_REDIS_URL"]).password
            self.assertTrue(len(postgres_password) == 64 and len(redis_password) == 64,
                            "fixture password generation did not retain its entropy bound")
            self.assertTrue(runtime.environment["SOUP_WALL_DRILL_ADMIN_TOKEN"] == runtime.admin,
                            "runtime admin credential was not supplied to the child environment")
            config = (runtime.directory / "redis.conf").read_text()
            for secret in (postgres_password, redis_password, runtime.admin,
                           runtime.environment["SOUP_WALL_DRILL_POSTGRES_URL"],
                           runtime.environment["SOUP_WALL_DRILL_REDIS_URL"]):
                self.assertTrue(secret not in config, "raw runtime credentials were written to Redis configuration")
            self.assertIn("user default on resetpass #" + hashlib.sha256(redis_password.encode("ascii")).hexdigest(), config)
            self.assertNotIn("requirepass", config)
            self.assertNotIn("nopass", config)
            self.assertEqual((runtime.directory / "redis.conf").stat().st_mode & 0o777, 0o600)
            self.assertEqual({p.name for p in runtime.directory.iterdir()}, {"redis.conf"})

    def test_saved_compose_contains_only_credential_references_and_protected_receiver_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = object.__new__(DRILL.Runtime)
            runtime.report, runtime.output = plan_fixture(), Mock()
            runtime.report["checks"] = []
            runtime.directory, runtime.project, runtime.owner = Path(temporary), "owned-credential-test", "owned-run"
            runtime.environment = os.environ.copy()
            runtime.token, runtime.admin, runtime.tenant_token = "synthetic-receiver-bearer-token-0000", "synthetic-admin-token-00000000", None
            runtime.urls, runtime.started = {}, False
            runtime.prepare_tls = Mock()
            class ConfigurationsReady(Exception):
                pass
            def command(arguments, **_):
                if arguments[:3] == ["docker", "image", "inspect"]:
                    return IMAGE_ID + " " + SOURCE["commit"]
                if arguments[:2] == ["docker", "ps"]:
                    return ""
                if any("hashlib.sha256" in argument for argument in arguments):
                    return "f" * 64
                return "safe owned command response"
            runtime.command = Mock(side_effect=command)
            runtime.compose = Mock(side_effect=ConfigurationsReady)
            def archive(arguments, **kwargs):
                self.assertEqual(arguments[:2], ["git", "archive"])
                with tarfile.open(fileobj=kwargs["stdout"], mode="w") as bundle:
                    for name in ("prometheus-alerts.yaml", "prometheus-alerts.test.yaml"):
                        content = b"groups: []\n"
                        item = tarfile.TarInfo("deploy/" + name)
                        item.size = len(content)
                        bundle.addfile(item, io.BytesIO(content))
                return subprocess.CompletedProcess(arguments, 0)
            with patch.object(DRILL.subprocess, "run", side_effect=archive), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ConfigurationsReady):
                    runtime.setup(skip_build=True)
            saved = runtime.compose_file.read_text()
            services = json.loads(saved)["services"]
            expected = {
                "POSTGRES_PASSWORD": "${SOUP_WALL_DRILL_POSTGRES_PASSWORD:?runtime PostgreSQL credential is required}",
                "LLM_FW_ADMIN_TOKEN": "${SOUP_WALL_DRILL_ADMIN_TOKEN:?runtime admin credential is required}",
                "LLM_FW_POSTGRES_URL": "${SOUP_WALL_DRILL_POSTGRES_URL:?runtime PostgreSQL URL is required}",
                "LLM_FW_REDIS_URL": "${SOUP_WALL_DRILL_REDIS_URL:?runtime Redis URL is required}",
            }
            self.assertEqual(services["postgres"]["environment"]["POSTGRES_PASSWORD"], expected["POSTGRES_PASSWORD"])
            for field in ("LLM_FW_ADMIN_TOKEN", "LLM_FW_POSTGRES_URL", "LLM_FW_REDIS_URL"):
                self.assertEqual(services["gateway"]["environment"][field], expected[field])
            raw_credentials = (runtime.environment["SOUP_WALL_DRILL_POSTGRES_PASSWORD"], runtime.admin,
                               runtime.environment["SOUP_WALL_DRILL_POSTGRES_URL"],
                               runtime.environment["SOUP_WALL_DRILL_REDIS_URL"],
                               DRILL.urllib.parse.urlsplit(runtime.environment["SOUP_WALL_DRILL_REDIS_URL"]).password)
            for path in runtime.directory.rglob("*"):
                if path.is_file():
                    contents = path.read_bytes()
                    self.assertTrue(all(secret.encode() not in contents for secret in raw_credentials),
                                    "raw PostgreSQL/Redis/admin credentials were persisted in a fixture artifact")
            self.assertEqual((runtime.directory / "token").stat().st_mode & 0o777, 0o600)
            self.assertTrue((runtime.directory / "token").read_text().strip() == runtime.token,
                            "the protected standard Alertmanager credential input is missing")
            self.assertTrue(all(secret not in json.dumps(runtime.report) for secret in raw_credentials),
                            "raw runtime credentials reached report data")
            arguments = json.dumps([call.args for call in runtime.command.call_args_list])
            self.assertTrue(all(secret not in arguments for secret in raw_credentials),
                            "raw runtime credentials reached subprocess arguments")


class LinuxAlertEvidence(unittest.TestCase):
    def setUp(self):
        original = os.umask(0o077)
        os.umask(original)
        self.addCleanup(os.umask, original)

    def run_drill(self, *, source=None, failure=None, receipt_data=None, receipt_status=200,
                  after_source=None, expected_commit=None):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output_path = base / "evidence.json"
            runtime_path = base / "private-profile"
            runtime_path.mkdir()
            actual_runtime = DRILL.Runtime

            class FakeRuntime:
                def __init__(self, report, output):
                    self.report, self.output, self.directory = report, output, runtime_path

                def setup(self, _):
                    if failure == "setup":
                        raise OSError("private setup error must not leak")

                def seed_tenant(self):
                    pass

                def rejection_probes(self):
                    pass

                def useful(self, stage):
                    if failure == "runtime":
                        raise DRILL.DrillError("private runtime error must not leak")

                def dependency_cycle(self, *_, **__):
                    pass

                def gateway_cycle(self):
                    pass

                def receipts(self):
                    if failure == "receipts":
                        raise DRILL.DrillError("private unavailable receipts")
                    return receipt_status, receipt_data if receipt_data is not None else complete_receipts()

                def check(self, *args, **kwargs):
                    return actual_runtime.check(self, *args, **kwargs)

                def cleanup(self):
                    if failure == "cleanup_error":
                        raise PermissionError("private cleanup error must not leak")
                    return failure != "cleanup_incomplete"

            args = SimpleNamespace(out=output_path, expected_commit=expected_commit, no_build=True)
            selected_plan = Mock(side_effect=DRILL.DrillError("private plan error")) if failure == "plan" else Mock(return_value=plan_fixture(source))
            with patch.object(DRILL, "plan", selected_plan), patch.object(DRILL, "Runtime", FakeRuntime), \
                    patch.object(DRILL, "source_identity", return_value=dict(after_source or source or SOURCE)), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = DRILL.execute(args)
            return code, json.loads(output_path.read_text()), runtime_path.exists()

    def test_dirty_or_wrong_source_never_creates_a_runtime(self):
        for source, expected in [(dict(SOURCE, clean=False), None), (SOURCE, "9" * 40)]:
            with self.subTest(source=source, expected=expected), tempfile.TemporaryDirectory() as temporary:
                args = SimpleNamespace(out=Path(temporary) / "evidence.json", expected_commit=expected, no_build=True)
                with patch.object(DRILL, "plan", return_value=plan_fixture(source)), \
                        patch.object(DRILL, "Runtime") as runtime, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(DRILL.execute(args), 2)
                report = json.loads(args.out.read_text())
                self.assertEqual(report["status"], "incomplete")
                self.assertFalse(report["executed"])
                runtime.assert_not_called()

    def test_planning_setup_runtime_and_cleanup_failures_keep_incomplete_evidence(self):
        for phase in ["plan", "setup", "runtime", "receipts", "cleanup_error", "cleanup_incomplete"]:
            with self.subTest(phase=phase):
                code, report, profile_retained = self.run_drill(failure=phase)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("finished_at_utc", report)
                self.assertNotIn("private ", json.dumps(report))
                if phase != "plan":
                    self.assertTrue(profile_retained)
                    self.assertTrue(report["cleanup"]["private_profile_retained"])
                else:
                    self.assertFalse(report["executed"])
                if phase.startswith("cleanup"):
                    self.assertFalse(report["cleanup"]["owned_services_stopped"])

    def test_only_complete_receipts_clean_source_and_successful_cleanup_can_pass(self):
        code, report, retained = self.run_drill()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "pass")
        self.assertFalse(retained)
        self.assertTrue(report["cleanup"]["owned_services_stopped"])
        self.assertFalse(report["cleanup"]["private_profile_retained"])

    def test_missing_truncated_or_unavailable_receipts_cannot_pass(self):
        missing = complete_receipts()
        missing["records"] = missing["records"][:-1]
        truncated = dict(complete_receipts(), has_more=True)
        foreign = complete_receipts()
        foreign["records"][0]["labels"]["instance"] = "unrelated:8080"
        uncorrelated = complete_receipts()
        uncorrelated["records"][1]["cycle_id"] = "0" * 64
        duplicate = complete_receipts()
        duplicate["records"][1] = duplicate["records"][0]
        for data, status in [(missing, 200), (truncated, 200), (complete_receipts(), 503),
                             (foreign, 200), (uncorrelated, 200), (duplicate, 200)]:
            with self.subTest(status=status, truncated=data["has_more"], records=len(data["records"])):
                code, report, _ = self.run_drill(receipt_data=data, receipt_status=status)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "incomplete")

    def test_a_source_change_after_runtime_verification_keeps_acceptance_open(self):
        code, report, retained = self.run_drill(after_source=dict(SOURCE, commit="4" * 40))
        self.assertEqual(code, 2)
        self.assertTrue(retained)
        self.assertEqual(report["checks"][-1]["check"], "source_unchanged")
        self.assertEqual(report["checks"][-1]["outcome"], "fail")

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            path.write_text('reserved existing evidence')
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                DRILL.Output(path)
            self.assertEqual(path.read_bytes(), original)

    def test_atomic_output_refuses_replaced_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            output = DRILL.Output(path)
            path.rename(path.with_suffix(".original"))
            path.write_text('{"unrelated":true}')
            with self.assertRaises(DRILL.DrillError):
                output.save({"status": "pass"})
            self.assertEqual(json.loads(path.read_text()), {"unrelated": True})

    def test_default_main_prints_a_plan_without_runtime_side_effects(self):
        with patch.object(DRILL, "plan", return_value=plan_fixture()), \
                patch.object(DRILL, "Runtime") as runtime, patch.object(DRILL, "Output") as output, \
                patch("sys.argv", [str(SCRIPT)]), contextlib.redirect_stdout(io.StringIO()) as text:
            self.assertEqual(DRILL.main(), 0)
        self.assertFalse(json.loads(text.getvalue())["executed"])
        runtime.assert_not_called()
        output.assert_not_called()


class LinuxAlertBoundaries(unittest.TestCase):
    def runtime(self):
        runtime = object.__new__(DRILL.Runtime)
        runtime.report = {"checks": []}
        runtime.output = Mock()
        return runtime

    def test_missing_metric_is_distinct_from_an_observed_zero(self):
        self.assertIsNone(DRILL.metric("unrelated_metric 0\n", "dependency_ready"))
        self.assertEqual(DRILL.metric("dependency_ready 0\n", "dependency_ready"), 0)
        self.assertIsNone(DRILL.metric("dependency_ready_suffix 0\n", "dependency_ready"))

    def test_missing_alertmanager_retry_counter_does_not_become_zero(self):
        runtime = self.runtime()
        runtime.urls = {"alertmanager": "http://127.0.0.1:9093"}
        with patch.object(DRILL, "request", return_value=(200, b"unrelated_counter 0\n")):
            with self.assertRaises(DRILL.DrillError):
                runtime.failures()

    def test_retry_counter_must_be_finite_and_nonnegative(self):
        runtime = self.runtime()
        runtime.urls = {"alertmanager": "http://127.0.0.1:9093"}
        for value in ["NaN", "+Inf", "-Inf", "-1"]:
            content = ('alertmanager_notification_requests_failed_total{integration="webhook"} ' + value + "\n").encode()
            with self.subTest(value=value), patch.object(DRILL, "request", return_value=(200, content)):
                with self.assertRaises(DRILL.DrillError):
                    runtime.failures()

    def test_missing_dependency_metric_cannot_establish_actual_outage(self):
        runtime = self.runtime()
        runtime.gateway = Mock(side_effect=[(503, json.dumps({"control_plane": "unavailable", "redis": "ready"}).encode()),
                                           (200, b"unrelated_gauge 0\n")])
        runtime.query = Mock(return_value=[{"value": [0, "1"]}])
        witness = runtime.health_witness("postgres", healthy=False)
        self.assertFalse(witness["matched"])
        self.assertIsNone(witness["metrics"]["llm_firewall_control_plane_ready"])

    def test_durable_audit_witness_counts_only_successful_chat_requests(self):
        runtime = self.runtime()
        runtime.tenant, runtime.admin = "fixture-tenant", "fixture-admin-token"
        rows = [{"id": 1, "path": "/v1/chat/completions", "status_code": 200, "outcome": "completed"},
                {"id": 2, "path": "/v1/chat/completions", "status_code": 503, "outcome": "failed"},
                {"id": 3, "path": "/admin/v1/tenants", "status_code": 200, "outcome": "completed"}]
        runtime.gateway = Mock(return_value=(200, json.dumps(rows).encode()))
        self.assertEqual(runtime.completed_audit_ids(), {1})
        self.assertEqual(runtime.gateway.call_args.args[0], "/admin/v1/tenants/fixture-tenant/audit?limit=100")
        self.assertEqual(runtime.gateway.call_args.kwargs["headers"],
                         {"x-llm-firewall-admin-token": "Bearer fixture-admin-token"})
        for code, rows in [(503, []), (200, {}), (200, [{"id": 1}] * 100), (200, [{"id": "invalid"}])]:
            with self.subTest(code=code, count=len(rows)):
                runtime.gateway.return_value = code, json.dumps(rows).encode()
                with self.assertRaises(DRILL.DrillError):
                    runtime.completed_audit_ids()

    def test_useful_call_requires_both_provider_effect_and_durable_audit_row(self):
        runtime = self.runtime()
        runtime.tenant, runtime.admin, runtime.tenant_token = "fixture-tenant", "fixture-admin", "fixture-tenant-token"
        runtime.provider_count = Mock(side_effect=[0, 1, 1])
        completed = [{"id": 1, "path": "/v1/chat/completions", "status_code": 200, "outcome": "completed"}]
        runtime.gateway = Mock(side_effect=[(200, b"[]"),
                                           (200, json.dumps({"choices": [{"message": {"content": DRILL.TEXT}}]}).encode()),
                                           (200, json.dumps(completed).encode())])
        with patch.object(DRILL.time, "monotonic", side_effect=[0, 0, 1.5]), contextlib.redirect_stdout(io.StringIO()):
            runtime.useful("controlled_fixture")
        self.assertEqual(runtime.report["checks"][0]["provider_entries_delta"], 1)
        self.assertEqual(runtime.report["checks"][1]["elapsed_seconds"], 1.5)
        self.assertEqual(runtime.report["checks"][-1]["new_completed_audit_rows"], 1)
        self.assertTrue(all(call.args[0] != "/metrics" for call in runtime.gateway.call_args_list))

    def test_receipt_selection_refuses_unavailable_and_truncated_evidence(self):
        runtime = self.runtime()
        for response in [(503, complete_receipts()), (200, dict(complete_receipts(), has_more=True))]:
            with self.subTest(response=response):
                runtime.receipts = Mock(return_value=response)
                with self.assertRaises(DRILL.DrillError):
                    runtime.receipt("postgres", "firing")

    def test_wait_success_and_timeout_are_recorded_with_measured_latency(self):
        runtime = self.runtime()
        with patch.object(DRILL.time, "monotonic", side_effect=[0, 0, 1.25]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.wait("durable_delivery", lambda: {"event_id": "safe"}), {"event_id": "safe"})
        self.assertEqual(runtime.report["checks"][-1]["elapsed_seconds"], 1.25)
        self.assertEqual(runtime.report["checks"][-1]["outcome"], "pass")
        with patch.object(DRILL.time, "monotonic", side_effect=[0, 0, 3, 3]), \
                patch.object(DRILL.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(DRILL.DrillError):
                runtime.wait("durable_delivery_timeout", lambda: None, timeout=2)
        self.assertEqual(runtime.report["checks"][-1]["elapsed_seconds"], 3)
        self.assertEqual(runtime.report["checks"][-1]["outcome"], "fail")
        self.assertEqual(runtime.output.save.call_count, 2)

    def test_refused_witness_is_persisted_before_raising(self):
        runtime = self.runtime()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(DRILL.DrillError):
            runtime.check("provider_must_not_run", False, provider_entries_delta=1)
        self.assertEqual(runtime.report["checks"][-1]["provider_entries_delta"], 1)
        self.assertEqual(runtime.report["checks"][-1]["outcome"], "fail")
        runtime.output.save.assert_called_once_with(runtime.report)

    def test_foreign_cleanup_label_prevents_compose_down(self):
        runtime = self.runtime()
        runtime.started, runtime.owner = True, "owned-run"
        runtime.compose = Mock(return_value="foreign-container")
        runtime.command = Mock(return_value="foreign-run")
        with self.assertRaises(DRILL.DrillError):
            runtime.cleanup()
        runtime.compose.assert_called_once_with("ps", "--all", "--quiet")

    def test_owned_cleanup_removes_only_its_checked_project(self):
        runtime = self.runtime()
        runtime.started, runtime.owner, runtime.project = True, "owned-run", "owned-project"
        runtime.compose = Mock(side_effect=["container-a container-b", ""])
        runtime.command = Mock(side_effect=["owned-run", "owned-run", ""])
        self.assertTrue(runtime.cleanup())
        self.assertEqual(runtime.compose.call_args_list[-1].args, ("down", "--volumes", "--timeout", "3"))
        self.assertEqual(runtime.command.call_args_list[-1].args[0][-1], "label=com.docker.compose.project=owned-project")

    def test_endpoint_discovery_uses_owned_actual_docker_assigned_loopback_binding(self):
        runtime = self.runtime()
        runtime.owner, runtime.project = "owned-run", "owned-project"
        runtime.compose = Mock(return_value="a" * 64)
        runtime.command = Mock(return_value=json.dumps({"owner": runtime.owner, "project": runtime.project,
            "service": "receiver", "ports": {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49152"}]}}))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.published_endpoint("receiver", 8443), "https://127.0.0.1:49152")
        runtime.compose.assert_called_once_with("ps", "--quiet", "receiver")
        template = runtime.command.call_args.args[0][3]
        self.assertIn(".NetworkSettings.Ports", template)
        self.assertNotIn(".HostConfig.PortBindings", template)
        self.assertEqual(runtime.report["checks"][-1]["assigned_host_port"], 49152)

    def test_endpoint_discovery_refuses_unpublished_zero_foreign_and_ambiguous_bindings(self):
        runtime = self.runtime()
        runtime.owner, runtime.project = "owned-run", "owned-project"
        runtime.compose = Mock(return_value="a" * 64)
        for bindings in [None, [], [{"HostIp": "127.0.0.1", "HostPort": "0"}],
                         [{"HostIp": "0.0.0.0", "HostPort": "49152"}],
                         [{"HostIp": "127.0.0.1", "HostPort": "70000"}],
                         [{"HostIp": "127.0.0.1", "HostPort": "49152"}] * 2]:
            data = {"owner": runtime.owner, "project": runtime.project, "service": "gateway",
                    "ports": {"8080/tcp": bindings}}
            with self.subTest(bindings=bindings):
                runtime.command = Mock(return_value=json.dumps(data))
                with self.assertRaises(DRILL.DrillError):
                    runtime.published_endpoint("gateway", 8080)
        for field in ["owner", "project", "service"]:
            data = {"owner": runtime.owner, "project": runtime.project, "service": "gateway",
                    "ports": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49152"}]}}
            data[field] = "foreign"
            with self.subTest(field=field):
                runtime.command = Mock(return_value=json.dumps(data))
                with self.assertRaises(DRILL.DrillError):
                    runtime.published_endpoint("gateway", 8080)
        runtime.compose.return_value = "a" * 64 + " " + "b" * 64
        runtime.command.reset_mock()
        with self.assertRaises(DRILL.DrillError):
            runtime.published_endpoint("gateway", 8080)
        runtime.command.assert_not_called()
        self.assertEqual(runtime.report["checks"], [])

    def test_http_transport_refuses_non_loopback_endpoints_before_opening(self):
        for url in ["https://example.test:443/alerts", "http://localhost:80/alerts", "http://127.0.0.1/alerts",
                    "http://credential@127.0.0.1:8080/alerts", "file:///tmp/alerts", "https://[::1]:8443/alerts"]:
            with self.subTest(url=url), patch.object(DRILL.urllib.request, "build_opener") as opener:
                with self.assertRaises(DRILL.DrillError):
                    DRILL.request(url)
                opener.assert_not_called()

    def test_receiver_tls_uses_supplied_ca_without_proxies_or_redirects(self):
        context = Mock()
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b"{}"
        opener = Mock()
        opener.open.return_value = response
        with patch.object(DRILL.ssl, "create_default_context", return_value=context) as tls, \
                patch.object(DRILL.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(DRILL.request("https://127.0.0.1:8443/receipts", ca=Path("fixture-ca.pem")), (200, b"{}"))
        tls.assert_called_once_with(cafile="fixture-ca.pem")
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(handler, DRILL.urllib.request.ProxyHandler) and handler.proxies == {} for handler in handlers))
        redirect = next(handler for handler in handlers if isinstance(handler, DRILL.NoRedirect))
        self.assertIsNone(redirect.redirect_request(None, None, None, None, None, None))
        opener.open.assert_called_once()

    def test_redirect_response_is_returned_without_a_second_request(self):
        error = urllib.error.HTTPError("http://127.0.0.1:8080/", 302, "Found", {"Location": "https://unrelated.test/"}, io.BytesIO(b""))
        opener = Mock()
        opener.open.side_effect = error
        with patch.object(DRILL.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(DRILL.request("http://127.0.0.1:8080/"), (302, b""))
        opener.open.assert_called_once()

    def test_response_size_is_bounded(self):
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b"a" * 262145
        opener = Mock()
        opener.open.return_value = response
        with patch.object(DRILL.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(DRILL.DrillError):
                DRILL.request("http://127.0.0.1:8080/")

    def test_image_inventory_requires_every_dependency_and_immutable_digests(self):
        inventories = [image_inventory()]
        missing = image_inventory()
        del missing["redis"]
        inventories.append(missing)
        mutable = image_inventory()
        mutable["prometheus"]["image"] = "prom/prometheus:latest"
        inventories.append(mutable)
        extra = image_inventory()
        extra["unrelated"] = {"image": "example/unrelated@sha256:" + "a" * 64}
        inventories.append(extra)
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "deploy").mkdir()
            for index, inventory in enumerate(inventories):
                with self.subTest(inventory=index):
                    (repo / "deploy/monitoring-images.json").write_text(json.dumps({"images": inventory}))
                    with patch.object(DRILL, "REPO", repo):
                        if index == 0:
                            self.assertEqual(DRILL.pinned_images()["images"], inventory)
                        else:
                            with self.assertRaises(DRILL.DrillError):
                                DRILL.pinned_images()

    def test_verified_source_image_is_used_by_id_after_tag_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = self.runtime()
            runtime.report.update(plan_fixture())
            runtime.directory, runtime.project = Path(temporary), "fixture-owned"
            class StopAfterBinding(Exception):
                pass
            runtime.command = Mock(side_effect=["29.2.1", "2.0.0", "", IMAGE_ID + " " + SOURCE["commit"], StopAfterBinding()])
            def archive(args, **kwargs):
                self.assertEqual(args[:2], ["git", "archive"])
                with tarfile.open(fileobj=kwargs["stdout"], mode="w"):
                    pass
                return subprocess.CompletedProcess(args, 0)
            with patch.object(DRILL.subprocess, "run", side_effect=archive), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(StopAfterBinding):
                    runtime.setup(skip_build=True)
            command = runtime.command.call_args_list[-1].args[0]
            self.assertEqual(command[command.index("python3") + 1], IMAGE_ID)
            self.assertEqual(runtime.report["gateway_image_id"], IMAGE_ID)


class LinuxCommandEvidence(unittest.TestCase):
    def setUp(self):
        original = os.umask(0o077)
        self.addCleanup(os.umask, original)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = object.__new__(DRILL.Runtime)
        self.runtime.directory = Path(self.temporary.name)
        self.runtime.sequence = 0
        self.runtime.report, self.runtime.output = {"checks": [], "executed": False}, Mock()
        self.runtime.environment = {"PATH": "/fixture-only", "FIXTURE_PRIVATE": "private-environment-token"}

    def test_promtool_uses_the_private_rules_owner_without_changing_mount_permissions(self):
        rules = self.runtime.directory / "rules"
        rules.mkdir(mode=0o755)
        self.assertEqual(rules.stat().st_mode & 0o777, 0o700)
        self.runtime.command = Mock(return_value="SUCCESS")
        images = {"prometheus": image_inventory()["prometheus"]["image"]}
        with contextlib.redirect_stdout(io.StringIO()):
            self.runtime.verify_rules(images, rules)
        self.assertEqual(self.runtime.command.call_count, 2)
        for call in self.runtime.command.call_args_list:
            args = call.args[0]
            self.assertEqual(args[args.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
            self.assertEqual(args[args.index("--network") + 1], "none")
            self.assertIn("--read-only", args)
            self.assertTrue(args[args.index("--mount") + 1].endswith("readonly"))
            self.assertIn(call.kwargs["phase"], {"promtool_rule_check", "promtool_rule_tests"})
        self.assertEqual(rules.stat().st_mode & 0o777, 0o700)

    def test_failed_command_reports_phase_exit_and_log_hash_without_private_arguments(self):
        secret = b"private-command-argument-and-private-stderr"
        def failed(args, **kwargs):
            kwargs["stdout"].write(secret)
            self.assertEqual(kwargs["env"], self.runtime.environment)
            return subprocess.CompletedProcess(args, 13)
        with patch.object(DRILL.subprocess, "run", side_effect=failed), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(DRILL.DrillError):
                self.runtime.command(["docker", "run", "--private", secret.decode()], phase="promtool_rule_tests")
        record = self.runtime.report["command_failures"][0]
        self.assertEqual(record["phase"], "promtool_rule_tests")
        self.assertEqual(record["return_code"], 13)
        self.assertEqual(record["failure_kind"], "nonzero_exit")
        self.assertEqual(record["private_log_sha256"], hashlib.sha256(secret).hexdigest())
        self.assertGreaterEqual(record["elapsed_seconds"], 0)
        self.assertNotIn(secret.decode(), json.dumps(self.runtime.report) + output.getvalue())
        self.assertNotIn("private-environment-token", json.dumps(self.runtime.report) + output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["command_failure"], record)
        self.assertTrue(self.runtime.report["executed"])

    def test_timeout_and_launch_error_preserve_safe_command_diagnostics(self):
        for kind in ["timeout", "launch_error"]:
            with self.subTest(kind=kind):
                self.runtime.report["command_failures"] = []
                def failing(args, **kwargs):
                    kwargs["stdout"].write(b"private-output")
                    if kind == "timeout":
                        raise subprocess.TimeoutExpired(args, 1, output=b"private-exception-detail")
                    raise OSError("private-exception-detail")
                with patch.object(DRILL.subprocess, "run", side_effect=failing), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(DRILL.DrillError):
                        self.runtime.command(["docker", "compose", "--project-name", "fixture",
                                              "--file", "private-config-location", "up", "--detach"], timeout=1)
                record = self.runtime.report["command_failures"][0]
                self.assertEqual(record["phase"], "compose_start")
                self.assertEqual(record["failure_kind"], kind)
                self.assertIsNone(record["return_code"])
                public = json.dumps(self.runtime.report) + output.getvalue()
                for private in ["private-output", "private-exception-detail", "private-config-location"]:
                    self.assertNotIn(private, public)

    def test_unapproved_phase_cannot_leak_into_public_evidence(self):
        with patch.object(DRILL.subprocess, "run") as execute:
            with self.assertRaises(DRILL.DrillError):
                self.runtime.command(["fixture"], phase="private-phase-secret")
        execute.assert_not_called()
        self.assertFalse(self.runtime.report["executed"])
        self.assertNotIn("private-phase-secret", json.dumps(self.runtime.report))



class LinuxAlertEndpointRecovery(unittest.TestCase):
    def cycle_fixture(self):
        runtime = object.__new__(DRILL.Runtime)
        runtime.report, runtime.output = {"checks": []}, Mock()
        runtime.owner, runtime.project = "fixture-owned-run", "fixture-owned-project"
        runtime.token, runtime.admin, runtime.tenant, runtime.tenant_token = "fixture-receiver-token", "fixture-admin", "fixture-tenant", "fixture-proxy-token"
        runtime.ca = Path("fixture-ca.pem")
        runtime.urls = {"receiver": "https://127.0.0.1:49151", "gateway": "http://127.0.0.1:49140",
                        "prometheus": "http://127.0.0.1:49160", "alertmanager": "http://127.0.0.1:49161"}
        state = {"receiver_port": 49151, "gateway_port": 49140, "receiver_running": True,
                 "gateway_running": True, "postgres_running": True, "provider_count": 0,
                 "audit": [], "records": [], "requests": []}
        fixtures = {(row["labels"]["alertname"], row["status"]): row for row in complete_receipts()["records"]}
        def accept(key, status):
            row = fixtures[DRILL.ALERTS[key][0], status]
            if all(item["event_id"] != row["event_id"] for item in state["records"]):
                state["records"].append(row)
        def compose(*args):
            if args[:2] == ("ps", "--quiet"):
                return ("a" if args[2] == "receiver" else "b") * 64
            service = args[-1]
            if args[0] == "stop":
                state[service + "_running"] = False
                if service == "gateway":
                    accept("gateway", "firing")
            elif args[0] in {"start", "restart"}:
                state[service + "_running"] = True
                if service in {"receiver", "gateway"}:
                    state[service + "_port"] += 1
                if service == "receiver" and not state["postgres_running"]:
                    accept("postgres", "firing")
                elif service == "postgres":
                    accept("postgres", "resolved")
                elif service == "gateway":
                    accept("gateway", "resolved")
            else:
                raise AssertionError("unexpected external lifecycle command")
            return ""
        def inspect(args, **_):
            self.assertEqual(args[:3], ["docker", "inspect", "--format"])
            service = "receiver" if args[-1] == "a" * 64 else "gateway"
            target = 8443 if service == "receiver" else 8080
            return json.dumps({"owner": runtime.owner, "project": runtime.project, "service": service,
                               "ports": {str(target) + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(state[service + "_port"])}]}})
        def request(url, *, body=None, headers=None, ca=None, **_):
            parsed = DRILL.urllib.parse.urlsplit(url)
            state["requests"].append(url)
            def response(code, data):
                return code, json.dumps(data).encode()
            if parsed.scheme == "https":
                if parsed.port != state["receiver_port"] or not state["receiver_running"]:
                    raise urllib.error.URLError("stale fixture receiver endpoint")
                self.assertEqual(ca, runtime.ca)
                self.assertEqual(headers, {"Authorization": "Bearer " + runtime.token})
                if parsed.path == "/receipts":
                    return response(200, {"records": state["records"], "total_unique_events": len(state["records"]),
                                          "returned_records": len(state["records"]), "has_more": False})
                self.assertEqual(parsed.path, "/alerts")
                self.assertEqual(body["receiver"], DRILL.RECEIVER)
                self.assertEqual(body["externalURL"], DRILL.EXTERNAL_URL)
                self.assertEqual(body["alerts"][0]["labels"]["job"], DRILL.JOB)
                self.assertEqual(body["alerts"][0]["labels"]["instance"], DRILL.INSTANCE)
                return response(200, {"duplicates": 1})
            if parsed.port == 49160:
                query = DRILL.urllib.parse.parse_qs(parsed.query)["query"][0]
                if query.startswith("up{"):
                    rows = [{"value": [0, "1" if state["gateway_running"] else "0"]}]
                elif query.startswith("llm_firewall_control_plane_ready{"):
                    rows = [] if not state["gateway_running"] else [{"value": [0, "1"]}]
                else:
                    self.assertTrue(query.startswith("ALERTS{"))
                    rows = [{"value": [0, "1"]}]
                return response(200, {"status": "success", "data": {"result": rows}})
            if parsed.port == 49161:
                self.assertFalse(state["receiver_running"])
                return 200, b'alertmanager_notification_requests_failed_total{integration="webhook"} 2\n'
            if parsed.port != state["gateway_port"] or not state["gateway_running"]:
                raise urllib.error.URLError("stale fixture Gateway endpoint")
            if parsed.path == "/readyz":
                return response(200 if state["postgres_running"] else 503,
                                {"control_plane": "ready" if state["postgres_running"] else "unavailable", "redis": "ready"})
            if parsed.path == "/metrics":
                value = "1" if state["postgres_running"] else "0"
                return 200, ("llm_firewall_control_plane_ready " + value + "\nllm_firewall_redis_limits_ready 1\n").encode()
            if parsed.path.endswith("/audit"):
                self.assertEqual(headers, {"x-llm-firewall-admin-token": "Bearer " + runtime.admin})
                return response(200, state["audit"])
            self.assertEqual(parsed.path, "/v1/chat/completions")
            self.assertEqual(headers, {"x-llm-firewall-token": "Bearer " + runtime.tenant_token, "Authorization": "Bearer fixture-only"})
            if not state["postgres_running"]:
                return response(503, {"error": "fixture unavailable"})
            state["provider_count"] += 1
            state["audit"].append({"id": state["provider_count"], "path": parsed.path, "status_code": 200, "outcome": "completed"})
            return response(200, {"choices": [{"message": {"content": DRILL.TEXT}}]})
        runtime.compose, runtime.command = Mock(side_effect=compose), Mock(side_effect=inspect)
        runtime.provider_count = Mock(side_effect=lambda: state["provider_count"])
        return runtime, state, request

    def test_receiver_cycle_rebinds_before_receipts_and_authenticated_replay(self):
        runtime, state, transport = self.cycle_fixture()
        with patch.object(DRILL, "request", side_effect=transport),                 patch.object(DRILL.time, "monotonic", side_effect=itertools.count()),                 patch.object(DRILL.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            runtime.dependency_cycle("postgres", receiver_fault=True)
        self.assertEqual(runtime.urls["receiver"], "https://127.0.0.1:49153")
        self.assertFalse(any(url.startswith("https://127.0.0.1:49151/") for url in state["requests"]))
        self.assertIn("https://127.0.0.1:49152/receipts?limit=1000", state["requests"])
        self.assertIn("https://127.0.0.1:49153/alerts", state["requests"])
        self.assertEqual(state["provider_count"], 1)
        self.assertEqual(len(state["records"]), 2)
        self.assertTrue(all(row["outcome"] == "pass" for row in runtime.report["checks"]))

    def test_gateway_cycle_rebinds_before_readiness_and_useful_recovery(self):
        runtime, state, transport = self.cycle_fixture()
        with patch.object(DRILL, "request", side_effect=transport),                 patch.object(DRILL.time, "monotonic", side_effect=itertools.count()),                 patch.object(DRILL.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            runtime.gateway_cycle()
        self.assertEqual(runtime.urls["gateway"], "http://127.0.0.1:49141")
        self.assertFalse(any(url.startswith("http://127.0.0.1:49140/") for url in state["requests"]))
        self.assertIn("http://127.0.0.1:49141/readyz", state["requests"])
        self.assertIn("http://127.0.0.1:49141/v1/chat/completions", state["requests"])
        self.assertEqual(state["provider_count"], 1)
        self.assertEqual(len(state["records"]), 2)
        self.assertTrue(all(row["outcome"] == "pass" for row in runtime.report["checks"]))


@unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
class LinuxAlertStrictTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.runtime = object.__new__(DRILL.Runtime)
        cls.runtime.directory = Path(cls.temporary.name)
        cls.runtime.report, cls.runtime.output, cls.runtime.sequence = {"checks": [], "executed": False}, Mock(), 0
        with contextlib.redirect_stdout(io.StringIO()):
            cls.runtime.prepare_tls()

    def test_generated_chain_passes_strict_openssl_server_and_hostname_checks(self):
        for verification in [["-verify_ip", "127.0.0.1"], ["-verify_hostname", "receiver"]]:
            result = subprocess.run(["openssl", "verify", "-x509_strict", "-purpose", "sslserver", *verification,
                                     "-CAfile", str(self.runtime.ca), str(self.runtime.directory / "server.pem")],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.runtime.report["checks"][-1]["check"], "receiver_certificate_chain_strict")
        self.assertEqual((self.runtime.directory / "ca.key").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.runtime.directory / "server.key").stat().st_mode & 0o777, 0o600)

    def test_protected_receiver_health_succeeds_with_strict_stdlib_tls(self):
        sys.path.insert(0, str(SCRIPT.parent))
        from alert_receiver import ReceiptStore, ReceiverPolicy, create_server
        token = b"soup-wall-local-fixture-token-00000000"
        store = ReceiptStore(self.runtime.directory / "receipt-data", 30, 100)
        server = None
        try:
            server = create_server(("127.0.0.1", 0), token, ReceiverPolicy.from_dict(DRILL.make_policy()), store,
                                   tls_cert=self.runtime.directory / "server.pem", tls_key=self.runtime.directory / "server.key")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            context = ssl.create_default_context(cafile=str(self.runtime.ca))
            context.verify_flags |= ssl.VERIFY_X509_STRICT
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            with patch.object(DRILL.ssl, "create_default_context", return_value=context):
                code, raw = DRILL.request(f"https://127.0.0.1:{server.server_port}/healthz", ca=self.runtime.ca)
                self.assertEqual(code, 200)
                self.assertEqual(json.loads(raw), {"status": "serving"})
                code, raw = DRILL.request(f"https://127.0.0.1:{server.server_port}/receipts?limit=100",
                                          headers={"Authorization": "Bearer " + token.decode()}, ca=self.runtime.ca)
                self.assertEqual(code, 200)
                self.assertEqual(json.loads(raw)["total_unique_events"], 0)
        finally:
            if server:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
            store.close()


if __name__ == "__main__":
    unittest.main()
