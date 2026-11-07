# SPDX-License-Identifier: Apache-2.0
"""SOU-242 stale-restore recovery panel: browser regressions.

The shipped admin page is assembled as admin_ui.rs does and driven against a
fixture of GET .../stale-recovery and POST .../stale-recovery/{preview,confirm}
(sw-console-stale-restore-recovery/1) plus the existing fleet reads. Every
value is synthetic. The real Agent -> Console -> browser path is
scripts/console-stale-restore-acceptance.py.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit

AVAILABLE = importlib.util.find_spec("playwright") is not None
SRC = Path(__file__).resolve().parents[2] / "crates/proxy/src"
ORIGIN = "https://console.example.test"
TENANT = "tenant-a"
T0 = 1800000000
DIGEST, BUNDLE, BINDING = "ab" * 32, "cd" * 32, "ef" * 32
CONTRACT = "sw-console-stale-restore-recovery/1"
RESTRICTIONS = ["Only this tenant, enrollment credential generation and current issuer key are covered."]
PHRASE = "recover edge-1 from 2 to 4 efefefefefef"


def page_html():
    html = (SRC / "admin_dashboard.html").read_text(encoding="utf-8")
    for marker, name in (("AGENT_REJECTION_REASONS", "agent_rejection_reasons.js"), ("FLEET_PANEL", "fleet_panel.js"), ("ROLLOUT_PANEL", "rollout_panel.js"),
                         ("ENROLLMENT_PANEL", "enrollment_panel.js"), ("AGENT_HISTORY", "agent_history.js"),
                         ("FLEET_TRIAGE", "fleet_triage.js"), ("AGENT_HEARTBEAT", "heartbeat_panel.js"), ("STALE_RECOVERY", "stale_recovery_panel.js"),
                         ("SINGLE_AGENT_POLICY", "single_agent_policy.js"), ("OPERATOR_AUDIT", "operator_audit_panel.js")):
        html = html.replace(f"/* {marker} */", (SRC / name).read_text(encoding="utf-8"))
    return html


def fence(state="fenced"):
    return {"fence_sequence": 4, "restored_sequence": 2, "evidence_revision": "r-deny", "evidence_policy_sha256": DIGEST,
            "evidence_bundle_sha256": BUNDLE, "issuer_key_id": "issuer-a", "credential_generation": 1,
            "unrecoverable_interval": {"from_sequence": 3, "to_sequence": 3}, "observed_at_unix": T0, "confirmed_by": "bootstrap_owner",
            "confirmed_at_unix": T0 + 5, "state": state,
            "completion": {"deployment_sequence": 5, "revision": "r-allow", "policy_sha256": DIGEST, "applied_at_unix": T0 + 60} if state == "complete" else None}


def status(state, tenant=TENANT, agent="edge-1"):
    return {"contract_version": CONTRACT, "tenant_id": tenant, "agent_id": agent, "state": state, "restored_sequence": 2,
            "fences": [] if state == "none" else [fence(state)], "restrictions": RESTRICTIONS}


def preview(agent="edge-1"):
    return {"contract_version": CONTRACT, "tenant_id": TENANT, "agent_id": agent, "restored_sequence": 2, "latest_restored_sequence": 3, "restored_status": "rejected",
            "evidence": {"deployment_sequence": 4, "revision": "r-deny", "policy_sha256": DIGEST, "issuer_key_id": "issuer-a",
                         "issued_at_unix": T0, "bundle_sha256": BUNDLE},
            "observed_at_unix": T0, "observation_age_seconds": 7, "credential_generation": 1, "issuer_public_key_sha256": DIGEST,
            "unrecoverable_interval": {"from_sequence": 3, "to_sequence": 3}, "next_sequence": 5, "state_binding": BINDING,
            "confirmation": PHRASE, "restrictions": RESTRICTIONS}


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class StaleRecoveryPanelBrowserTests(unittest.TestCase):
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
        cls.folder = tempfile.TemporaryDirectory()
        cls.evidence = Path(cls.folder.name) / "managed-policy-active.json"
        cls.evidence.write_text(json.dumps({"schema_version": 1, "tenant_id": TENANT, "agent_id": "edge-1", "deployment_sequence": 4}))

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.folder.cleanup()

    def setUp(self):
        self.role, self.state, self.posts, self.preview_reply, self.confirm_reply = "owner", "none", [], (200, preview()), (201, None)
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    def json(self, route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def route(self, route):
        request = route.request
        path = urlsplit(request.url).path
        parts = path.split("/")
        if path == "/admin":
            return route.fulfill(status=200, content_type="text/html", body=self.html)
        if path == "/admin/v1/whoami":
            return self.json(route, {"admin_name": "Fixture " + self.role, "role": self.role})
        if path == "/admin/v1/admins":
            return self.json(route, [])
        if path == "/admin/v1/tenants":
            return self.json(route, [{"id": TENANT, "name": "Alpha", "active": True}])
        if path.endswith("/stale-recovery/preview"):
            self.posts.append(("preview", json.loads(request.post_data)))
            code, body = self.preview_reply
            return self.json(route, body, code)
        if path.endswith("/stale-recovery/confirm"):
            self.posts.append(("confirm", json.loads(request.post_data)))
            code, body = self.confirm_reply
            if code == 201:
                self.state = "fenced"
                body = {"contract_version": CONTRACT, "replayed": False, "fence": fence()}
            return self.json(route, body, code)
        if path.endswith("/stale-recovery"):
            value = self.state if isinstance(self.state, dict) else status(self.state, parts[4], parts[6])
            return self.json(route, value)
        if path.endswith("/agent-fleet"):
            rows = [{"tenant_id": TENANT, "agent_id": "edge-1", "enrolled_at_unix": T0, "revoked_at_unix": None, "latest_issued": None,
                     "last_reported_applied": None}]
            return self.json(route, {"contract_version": "sw-agent-fleet/1", "tenant_id": TENANT, "agents": rows, "next_after": None,
                                     "observed_at_unix": T0 + 1000})
        if "/agent-fleet/" in path and path.endswith("/heartbeat"):
            return self.json(route, {"error": "not in this fixture"}, 503)
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

    def open(self, width=1280):
        self.page.set_viewport_size({"width": width, "height": 900})
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#console").wait_for(state="visible")
        self.page.locator("#tenant-list button").filter(has_text="Alpha").click()
        self.page.locator("#fleet-list").get_by_role("button", name="edge-1", exact=True).click()

    def wait_status(self, text):
        self.page.wait_for_function("t => document.getElementById('recovery-status').textContent.includes(t)", arg=text)

    def text(self):
        return self.page.locator("#recovery-panel").inner_text()

    def test_states_are_explicit(self):
        for state, text in (("none", "No stale-restore recovery recorded"), ("fenced", "not complete"), ("complete", "Recovery complete: #5")):
            with self.subTest(state=state):
                self.state = state
                self.open()
                self.wait_status(text)
                if state != "none":
                    self.assertIn("Unrecoverable history interval: #3 to #3", self.text())
                self.assertIn("Remaining restrictions", self.text())

    def test_owner_preview_requires_the_exact_phrase(self):
        self.open()
        self.wait_status("No stale-restore recovery")
        self.page.locator("#recovery-evidence").set_input_files(str(self.evidence))
        self.page.locator("#recovery-preview").click()
        self.wait_status("Preview only")
        body = self.text()
        self.assertIn("Restored Console sequence: #2 · newest restored record #3 (rejected)", body)
        self.assertIn("Agent evidence: #4 · r-deny", body)
        self.assertIn(PHRASE, body)
        self.assertIn("Next issuance after confirmation: #5", body)
        self.assertTrue(self.page.locator("#recovery-confirm").is_disabled())
        self.page.locator("#recovery-phrase").fill(PHRASE[:-1])
        self.assertTrue(self.page.locator("#recovery-confirm").is_disabled())
        self.page.locator("#recovery-phrase").fill(PHRASE)
        self.page.locator("#recovery-confirm").click()
        self.wait_status("Recovery fenced at #4, not complete")
        kinds = [k for k, _ in self.posts]
        self.assertEqual(kinds, ["preview", "confirm"])
        sent = self.posts[1][1]
        self.assertEqual((sent["state_binding"], sent["confirmation"], sent["evidence"]["deployment_sequence"]), (BINDING, PHRASE, 4))
        self.assertEqual(self.page.evaluate("localStorage.length + sessionStorage.length"), 0)

    def test_refusals_keep_recovery_closed(self):
        self.preview_reply = (409, {"error": "Evidence is not newer than the restored or already fenced sequence.", "refusal": "evidence_not_ahead"})
        self.open()
        self.wait_status("No stale-restore")
        self.page.locator("#recovery-evidence").set_input_files(str(self.evidence))
        self.page.locator("#recovery-preview").click()
        self.wait_status("Recovery stays closed: Evidence is not newer")
        self.assertTrue(self.page.locator("#recovery-confirm").is_disabled())
        # A confirmation refused after a state change also stays closed.
        self.preview_reply = (200, preview())
        self.confirm_reply = (409, {"error": "The restored state changed after the preview; preview again.", "refusal": "state_changed"})
        self.page.locator("#recovery-preview").click()
        self.wait_status("Preview only")
        self.page.locator("#recovery-phrase").fill(PHRASE)
        self.page.locator("#recovery-confirm").click()
        self.wait_status("Recovery stays closed: The restored state changed")
        self.assertEqual(self.page.locator("#recovery-preview-detail").inner_text(), "")
        # A preview for another Agent, or with free text, is discarded.
        self.preview_reply = (200, preview(agent="edge-2"))
        self.page.locator("#recovery-preview").click()
        self.wait_status("unexpected shape")
        self.preview_reply = (200, preview() | {"confirmation": "<b>x</b>" * 40})
        self.page.locator("#recovery-preview").click()
        self.wait_status("unexpected shape")
        self.assertEqual(self.page.locator("#recovery-panel b").count(), 0)

    def test_malformed_status_is_discarded(self):
        self.state = status("complete") | {"fences": [fence("complete") | {"completion": None}]}
        self.open()
        self.wait_status("unexpected shape")
        self.assertEqual(self.page.locator("#recovery-detail").inner_text(), "")

    def test_viewer_sees_state_without_controls(self):
        self.role, self.state = "viewer", "fenced"
        self.open(width=390)
        self.wait_status("not complete")
        self.assertFalse(self.page.locator("#recovery-preview").is_visible())
        self.assertFalse(self.page.locator("#recovery-confirm").is_visible())
        overflow = self.page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        self.assertLessEqual(overflow, 0)
        self.assertEqual(self.posts, [])


if __name__ == "__main__":
    unittest.main()
