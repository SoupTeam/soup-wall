# SPDX-License-Identifier: Apache-2.0
"""Opt-in Agent heartbeat status component: browser regressions.

The shipped admin page is assembled as admin_ui.rs does and driven against a
fixture of GET .../agent-fleet/:agent/heartbeat (sw-agent-heartbeat-status/1)
and the existing fleet reads. Every value is synthetic. The real Agent ->
Console -> browser path is scripts/console-agent-heartbeat-acceptance.py.
Optional: pip install playwright; python -m playwright install chromium.
"""
import importlib.util
import json
from pathlib import Path
import unittest
from urllib.parse import urlsplit

AVAILABLE = importlib.util.find_spec("playwright") is not None
SRC = Path(__file__).resolve().parents[2] / "crates/proxy/src"
ORIGIN = "https://console.example.test"
TENANT, OTHER = "tenant-a", "tenant-b"
T0 = 1800000000
DIGEST = "ab" * 32


def page_html():
    html = (SRC / "admin_dashboard.html").read_text(encoding="utf-8")
    for marker, name in (("FLEET_PANEL", "fleet_panel.js"), ("ROLLOUT_PANEL", "rollout_panel.js"),
                         ("ENROLLMENT_PANEL", "enrollment_panel.js"), ("AGENT_HISTORY", "agent_history.js"),
                         ("FLEET_TRIAGE", "fleet_triage.js"), ("AGENT_HEARTBEAT", "heartbeat_panel.js"),
                         ("SINGLE_AGENT_POLICY", "single_agent_policy.js"), ("OPERATOR_AUDIT", "operator_audit_panel.js")):
        html = html.replace(f"/* {marker} */", (SRC / name).read_text(encoding="utf-8"))
    return html


def heartbeat(tenant, agent, status, age=None, reported=True, generation=1):
    return {"contract_version": "sw-agent-heartbeat-status/1", "tenant_id": tenant, "agent_id": agent,
            "observed_at_unix": T0 + 1000, "status": status, "expires_after_seconds": 90, "age_seconds": age,
            "current_credential_generation": generation,
            "reported": {"credential_generation": 1, "registered_at_unix": T0, "sequence": 7,
                         "last_received_at_unix": None if age is None else T0 + 1000 - age,
                         "observed_policy": {"deployment_sequence": 3, "revision": "r-deny", "policy_sha256": DIGEST}}
            if reported else None, "note": "fixture"}


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class HeartbeatPanelBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True)
        except Exception:
            cls.playwright.stop()
            raise unittest.SkipTest("optional Chromium fixture runtime unavailable")
        cls.html = page_html()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.states = {(TENANT, "edge-1"): heartbeat(TENANT, "edge-1", "fresh", 12),
                       (TENANT, "legacy"): heartbeat(TENANT, "legacy", "unsupported", reported=False),
                       (OTHER, "edge-1"): heartbeat(OTHER, "edge-1", "stale", 600)}
        self.plan, self.held, self.mutations, self.reads = [], [], [], []
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    def json(self, route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        if request.method != "GET":
            self.mutations.append((request.method, path))
        parts = path.split("/")
        if path == "/admin":
            return route.fulfill(status=200, content_type="text/html", body=self.html)
        if path == "/admin/v1/whoami":
            return self.json(route, {"admin_name": "Fixture viewer", "role": "viewer"})
        if path == "/admin/v1/tenants":
            return self.json(route, [{"id": TENANT, "name": "Alpha", "active": True}, {"id": OTHER, "name": "Beta", "active": True}])
        if path.endswith("/heartbeat"):
            key = (parts[4], parts[6])
            self.reads.append(key)
            if self.plan:
                action = self.plan.pop(0)
                if action == "hold":
                    return self.held.append((route, key))
                if isinstance(action, int):
                    return self.json(route, {"error": "fixture"}, action)
                return self.json(route, action(self.states[key]))
            return self.json(route, self.states[key])
        if path.endswith("/agent-fleet"):
            tenant = parts[4]
            rows = [{"tenant_id": tenant, "agent_id": a, "enrolled_at_unix": T0, "revoked_at_unix": None, "latest_issued": None,
                     "last_reported_applied": None} for (t, a) in self.states if t == tenant]
            return self.json(route, {"contract_version": "sw-agent-fleet/1", "tenant_id": tenant, "agents": rows, "next_after": None,
                                     "observed_at_unix": T0 + 1000})
        if "/agent-fleet/" in path:
            return self.json(route, {"contract_version": "sw-agent-fleet/1", "observed_at_unix": T0 + 1000,
                                     "agent": {"tenant_id": parts[4], "agent_id": parts[6], "enrolled_at_unix": T0, "revoked_at_unix": None,
                                               "latest_issued": None, "last_reported_applied": None, "current_liveness": "unknown",
                                               "runtime_coverage": "unknown", "registry_identity": None},
                                     "deployments": [], "next_before_sequence": None})
        if path.endswith("/agent-triage"):
            return self.json(route, {"error": "not in this fixture"}, 503)
        if path.endswith(("/model-policy", "/limits")):
            return self.json(route, None)
        if path.endswith(("/tokens", "/audit", "/agents", "/groups")):
            return self.json(route, [])
        return self.json(route, {"error": "unexpected fixture request"}, 418)

    def open(self, tenant="Alpha", width=1280, clock=False):
        self.page.set_viewport_size({"width": width, "height": 900})
        if clock:
            self.page.clock.install(time=T0 + 1000)
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#console").wait_for(state="visible")
        self.page.locator("#tenant-list button").filter(has_text=tenant).click()
        self.page.locator("#fleet-list").get_by_role("button", name="edge-1", exact=True).wait_for()

    def pick(self, agent="edge-1"):
        self.page.locator("#fleet-list").get_by_role("button", name=agent, exact=True).click()

    def wait_status(self, text):
        self.page.wait_for_function("t => document.getElementById('heartbeat-status').textContent.includes(t)", arg=text)

    def text(self):
        return self.page.locator("#heartbeat-panel").inner_text()

    def test_each_status_is_explicit_and_never_health(self):
        cases = {
            "fresh": ("received 12 s before this read", "heartbeat-fresh"),
            "stale": ("Stale: the last authenticated self-report", "outcome-other"),
            "registered_no_report": ("no self-report received yet", "outcome-other"),
            "credential_changed": ("credential changed after the last self-report", "outcome-other"),
            "revoked": ("Credential revoked", "outcome-block"),
            "unsupported": ("No heartbeat registration", "note"),
            "unavailable": ("not migrated", "outcome-other"),
        }
        self.open()
        for state, (text, cls) in cases.items():
            with self.subTest(state=state):
                age = {"fresh": 12, "stale": 600}.get(state)
                self.states[(TENANT, "edge-1")] = heartbeat(TENANT, "edge-1", state, age, reported=state not in ("unsupported", "unavailable"))
                self.pick()
                self.wait_status(text)
                self.assertEqual(self.page.locator("#heartbeat-status").get_attribute("class"), cls)
                body = self.text()
                for claim in ("Healthy", "healthy", "Protected", "protected now", "enforcing"):
                    self.assertNotIn(claim, body)
                self.assertIn("not runtime attestation", body)
                if state in ("fresh", "stale"):
                    self.assertIn("Self-reported loaded policy: #3 · r-deny", body)
                    self.assertIn(DIGEST, body)
        self.assertEqual(self.mutations, [])

    def test_unopted_agent_stays_unknown(self):
        self.open()
        self.pick("legacy")
        self.wait_status("No heartbeat registration")
        self.assertIn("Liveness and protection are unknown", self.text())
        self.assertNotIn("Self-reported loaded policy", self.text())

    def test_periodic_reread_moves_fresh_to_stale_without_client_clock_math(self):
        self.open(clock=True)
        self.pick()
        self.wait_status("received 12 s before this read")
        reads = len(self.reads)
        self.states[(TENANT, "edge-1")] = heartbeat(TENANT, "edge-1", "stale", 102)
        self.page.clock.run_for(30_000)
        self.wait_status("Stale")
        self.assertEqual(len(self.reads), reads + 1)

    def test_stale_reply_after_agent_and_tenant_change_is_discarded(self):
        self.plan = ["hold"]
        self.open()
        self.pick()
        self.page.wait_for_function("() => document.getElementById('heartbeat-status').textContent.includes('Loading')")
        self.pick("legacy")
        self.wait_status("No heartbeat registration")
        route, key = self.held.pop()
        self.json(route, self.states[key])
        self.page.wait_for_timeout(200)
        self.assertIn("No heartbeat registration", self.page.locator("#heartbeat-status").inner_text())
        self.page.locator("#tenant-list button").filter(has_text="Beta").click()
        self.wait_status("Select an Agent")
        self.assertEqual(self.page.locator("#heartbeat-detail").inner_text(), "")
        self.assertTrue(self.page.locator("#heartbeat-refresh").is_disabled())

    def test_mismatched_or_malformed_responses_are_refused(self):
        bad = [lambda d: d | {"agent_id": "legacy"}, lambda d: d | {"tenant_id": OTHER}, lambda d: d | {"status": "healthy"},
               lambda d: d | {"contract_version": "sw-agent-fleet/1"}, lambda d: d | {"age_seconds": -5},
               lambda d: d | {"reported": d["reported"] | {"observed_policy": {"deployment_sequence": 1, "revision": "<b>x</b>", "policy_sha256": DIGEST}}},
               lambda d: d | {"reported": d["reported"] | {"observed_policy": {"deployment_sequence": 1, "revision": "r", "policy_sha256": "ZZ"}}}]
        self.open()
        for change in bad:
            with self.subTest(n=bad.index(change)):
                self.plan = [change]
                self.pick()
                self.wait_status("discarded")
                self.assertEqual(self.page.locator("#heartbeat-detail").inner_text(), "")
        self.assertEqual(self.page.locator("#heartbeat-panel b").count(), 0)

    def test_errors_and_lost_authorization(self):
        self.open(clock=True)
        for code, text in ((404, "not found"), (503, "could not be read"), (403, "cannot read"), (401, "Session expired")):
            with self.subTest(code=code):
                self.plan = [code]
                self.pick()
                self.wait_status(text)
                self.assertEqual(self.page.locator("#heartbeat-detail").inner_text(), "")
        # After 401 the periodic re-read stops.
        reads = len(self.reads)
        self.page.clock.run_for(95_000)
        self.page.wait_for_timeout(100)
        self.assertEqual(len(self.reads), reads)

    def test_narrow_layout_and_no_storage(self):
        self.open(width=390)
        self.pick()
        self.wait_status("received 12 s")
        overflow = self.page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        self.assertLessEqual(overflow, 0)
        self.assertEqual(self.page.evaluate("localStorage.length + sessionStorage.length"), 0)
        self.assertEqual(self.page.url, ORIGIN + "/admin")


if __name__ == "__main__":
    unittest.main()
