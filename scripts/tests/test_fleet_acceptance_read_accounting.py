# SPDX-License-Identifier: Apache-2.0
"""Keep local ACK-age checks distinct from independently polled heartbeat reads."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "fleet-console-acceptance.py"
SPEC = importlib.util.spec_from_file_location("fleet_acceptance_read_accounting", SCRIPT)
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCEPTANCE)


class FleetReadAccountingTests(unittest.TestCase):
    def test_list_and_detail_gets_remain_snapshot_reads(self):
        for path in (
            "/admin/v1/tenants/alpha/agent-fleet",
            "/admin/v1/tenants/alpha/agent-fleet?limit=25&after=edge",
            "/admin/v1/tenants/alpha/agent-fleet/edge",
            "/admin/v1/tenants/alpha/agent-fleet/edge?limit=25&before_sequence=2",
            "/admin/v1/tenants/alpha/agent-fleet/heartbeat",
            "/admin/v1/tenants/alpha/agent-fleet/edge%2D1",
        ):
            with self.subTest(path=path):
                self.assertEqual(ACCEPTANCE.fleet_read_kind("GET", "https://console.example" + path), "snapshot")

    def test_heartbeat_is_observed_separately_from_snapshot_reads(self):
        url = "https://console.example/admin/v1/tenants/alpha/agent-fleet/edge/heartbeat"
        self.assertEqual(ACCEPTANCE.fleet_read_kind("GET", url), "heartbeat")
        self.assertIsNone(ACCEPTANCE.fleet_read_kind("POST", url))

    def test_mutations_nested_and_other_endpoints_never_count_as_snapshot_reads(self):
        for method, path in (
            ("POST", "/admin/v1/tenants/alpha/agent-fleet"),
            ("DELETE", "/admin/v1/tenants/alpha/agent-fleet/edge"),
            ("GET", "/admin/v1/tenants/alpha/agent-fleet/edge/history"),
            ("GET", "/admin/v1/tenants/alpha/agent-fleet/edge/heartbeat/extra"),
            ("GET", "/admin/v1/tenants/alpha/agent-fleet-extra"),
            ("GET", "/admin/v1/tenants//agent-fleet"),
            ("GET", "/other/admin/v1/tenants/alpha/agent-fleet"),
            ("GET", "/admin/v1/tenants/alpha/agent-triage"),
        ):
            with self.subTest(method=method, path=path):
                self.assertIsNone(ACCEPTANCE.fleet_read_kind(method, "https://console.example" + path))


if __name__ == "__main__":
    unittest.main()
