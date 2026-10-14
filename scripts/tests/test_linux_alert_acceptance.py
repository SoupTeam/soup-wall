# SPDX-License-Identifier: Apache-2.0
"""Boundary regressions for the opt-in Linux notification drill; no Docker is launched."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
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
            content = ('alertmanager_notifications_failed_total{integration="webhook"} ' + value + "\n").encode()
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


if __name__ == "__main__":
    unittest.main()
