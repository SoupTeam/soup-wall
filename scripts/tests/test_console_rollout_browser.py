# SPDX-License-Identifier: Apache-2.0
"""Managed Agent rollout panel: browser regressions against bounded API fixtures.

The shipped admin page is assembled exactly as admin_ui.rs does. The fixture
server answers the existing group/revision/rollout endpoints; the real
browser -> Console -> Agent path is scripts/console-rollout-acceptance.py.
Optional: pip install playwright; python -m playwright install chromium.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

AVAILABLE = importlib.util.find_spec("playwright") is not None
SRC = Path(__file__).resolve().parents[2] / "crates/proxy/src"
ORIGIN = "https://console.example.test"
TENANT, OTHER = "tenant-a", "tenant-b"
DIGEST = "a" * 64
PLAN = {"tenant_id": TENANT, "group_id": "fleet", "rollout_id": "ro_1", "revision": "candidate",
        "policy_sha256": DIGEST, "issuer_key_id": "key", "phase": "pilot", "pilot_agents": ["pilot"],
        "standard_agents": ["worker-1", "worker-2"], "active_deployments": {"pilot": 2},
        "initial_sequences": {"pilot": 1, "worker-1": 1, "worker-2": 1},
        "previous_revisions": {"pilot": "baseline", "worker-1": "baseline", "worker-2": "baseline"},
        "agents": {"pilot": {"expected_sequence": 2, "latest_sequence": 2, "status": "pending",
                             "acknowledgement_deadline_unix": 1900000000, "last_matching_acknowledgement": None},
                   "worker-1": {"expected_sequence": None, "latest_sequence": 1, "status": "not_issued",
                                "acknowledgement_deadline_unix": None, "last_matching_acknowledgement": None},
                   "worker-2": {"expected_sequence": None, "latest_sequence": 1, "status": "not_issued",
                                "acknowledgement_deadline_unix": None, "last_matching_acknowledgement": None}},
        "failure_reason": None, "created_at_unix": 1800000000, "updated_at_unix": 1800000000}


def page_html():
    return ((SRC / "admin_dashboard.html").read_text(encoding="utf-8")
            .replace("/* FLEET_PANEL */", (SRC / "fleet_panel.js").read_text(encoding="utf-8"))
            .replace("/* ROLLOUT_PANEL */", (SRC / "rollout_panel.js").read_text(encoding="utf-8")))


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class RolloutPanelBrowserTests(unittest.TestCase):
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
        self.role = "owner"
        self.plan = copy.deepcopy(PLAN)
        self.members = [{"tenant_id": TENANT, "group_id": "fleet", "agent_id": a, "is_pilot": a == "pilot",
                         "joined_at_unix": 1} for a in ("pilot", "worker-1", "worker-2")]
        self.revisions = [{"tenant_id": TENANT, "group_id": "fleet", "revision": "candidate",
                           "policy_sha256": DIGEST, "approved": True}]
        self.groups = [{"tenant_id": TENANT, "group_id": "fleet", "name": "Fleet", "created_at_unix": 1}]
        self.posts, self.overrides, self.held = [], {}, []
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    def json(self, route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def route(self, route):
        request = route.request
        path = request.url.removeprefix(ORIGIN).split("?")[0]
        method = request.method
        key = (method, path)
        if key in self.overrides:
            action = self.overrides[key]
            if isinstance(action, list):
                action = action.pop(0) if len(action) > 1 else action[0]
            if method != "GET":
                self.posts.append(key)
            if action == "abort":
                route.abort("failed")
            elif action == "hold":
                self.held.append(route)
            elif callable(action):
                action(route)
            else:
                self.json(route, action[1], action[0])
            return
        if path == "/admin":
            route.fulfill(status=200, content_type="text/html", body=self.html)
        elif path == "/admin/v1/whoami":
            self.json(route, {"admin_name": "Fixture " + self.role, "role": self.role})
        elif path == "/admin/v1/tenants":
            self.json(route, [{"id": TENANT, "name": "Alpha", "active": True}, {"id": OTHER, "name": "Beta", "active": True}])
        elif path == "/admin/v1/admins":
            self.json(route, [])
        elif path.endswith("/agent-fleet"):
            tenant = path.split("/")[4]
            self.json(route, {"contract_version": "sw-agent-fleet/1", "tenant_id": tenant, "agents": [],
                              "next_after": None, "observed_at_unix": 1800000000})
        elif path.endswith(("/model-policy", "/limits")):
            self.json(route, None)
        elif path.endswith(("/tokens", "/audit")):
            self.json(route, [])
        elif method == "GET" and path.endswith("/groups"):
            tenant = path.split("/")[4]
            self.json(route, [dict(g, tenant_id=tenant) for g in self.groups] if tenant == TENANT else [])
        elif method == "GET" and path.endswith("/groups/fleet/members"):
            self.json(route, self.members)
        elif method == "GET" and path.endswith("/groups/fleet/revisions"):
            self.json(route, self.revisions)
        elif method == "GET" and path.endswith("/groups/fleet/rollout"):
            self.json(route, self.plan) if self.plan else self.json(route, {"error": "no rollout found for group"}, 404)
        else:
            self.posts.append(key)
            self.json(route, {"error": "unexpected fixture request"}, 418)

    def open(self, group=True):
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#console").wait_for(state="visible")
        self.page.locator("#tenant-list button").filter(has_text="Alpha").click()
        if group:
            self.wait_status("Choose a group")
            self.page.locator("#rollout-group").select_option("fleet")
            self.wait_status("Server state read")

    def wait_status(self, text):
        self.page.wait_for_function("t => document.getElementById('rollout-status').textContent.includes(t)", arg=text)

    def owner_buttons_enabled(self):
        return self.page.evaluate("[...document.querySelectorAll('#rollout-panel .rollout-mutation')].filter(b => !b.disabled).length")

    def confirm(self, text):
        self.page.locator("#rollout-confirm-input").fill(text)
        self.page.locator("#rollout-confirm").get_by_role("button", name="Confirm").click()

    def rollout_path(self, suffix=""):
        return f"/admin/v1/tenants/{TENANT}/groups/fleet/rollout{suffix}"

    def test_viewer_and_operator_see_the_plan_without_any_mutation_control(self):
        for role in ("viewer", "operator"):
            with self.subTest(role=role):
                self.role = role
                self.open()
                self.assertIn("ro_1", self.page.locator("#rollout-plan").inner_text())
                self.assertEqual(self.page.locator("#rollout-panel .owner-action:visible").count(), 0)
                self.assertTrue(self.page.locator("#rollout-actions").inner_text().startswith("Read-only"))
                self.assertEqual(self.posts, [])

    def test_frozen_plan_shows_exact_identity_and_keeps_states_distinct(self):
        self.plan["agents"]["pilot"].update(status="applied", last_matching_acknowledgement={
            "tenant_id": TENANT, "agent_id": "pilot", "deployment_sequence": 2, "revision": "candidate",
            "policy_sha256": DIGEST, "action": "deploy", "status": "applied", "issued_at_unix": 1800000000,
            "applied_at_unix": 1800000010})
        self.open()
        text = self.page.locator("#rollout-plan").inner_text()
        for fragment in (DIGEST, "ro_1", "Frozen workers", "worker-1, worker-2", "#2 · candidate · deploy · recorded applied",
                         "historical acknowledgement; not current health", "Not issued (waits for its wave)", "1 / 2 / 2"):
            self.assertIn(fragment, text)

    def test_typed_confirmation_is_exact_and_promotion_sends_one_request(self):
        self.overrides[("POST", self.rollout_path("/advance"))] = (200, self.plan)
        self.open()
        self.page.get_by_role("button", name="Evaluate pilot gate (promote to workers)").click()
        confirm = self.page.locator("#rollout-confirm").get_by_role("button", name="Confirm")
        self.page.locator("#rollout-confirm-input").fill("Candidate")
        self.assertTrue(confirm.is_disabled())
        self.confirm("candidate")
        self.wait_status("Promote / evaluate: accepted")
        self.assertEqual(self.posts, [("POST", self.rollout_path("/advance"))])

    def test_double_submission_sends_one_request(self):
        self.overrides[("POST", self.rollout_path("/pause"))] = "hold"
        self.open()
        pause = self.page.get_by_role("button", name="Pause")
        pause.click()
        self.page.wait_for_function("() => document.getElementById('rollout-status').textContent.includes('sending')")
        self.assertTrue(pause.is_disabled())
        pause.click(force=True)
        self.assertEqual(self.owner_buttons_enabled(), 0)
        self.assertEqual(len(self.held), 1)
        self.plan["phase"] = "paused"
        self.held[0].fulfill(status=200, content_type="application/json", body=json.dumps(self.plan))
        self.wait_status("Pause: accepted")
        self.assertEqual(self.posts, [("POST", self.rollout_path("/pause"))])

    def test_ambiguous_result_is_reconciled_from_server_state_without_retry(self):
        self.overrides[("POST", self.rollout_path("/pause"))] = "abort"
        self.overrides[("GET", self.rollout_path())] = [(200, self.plan), (503, {"error": "Console unavailable"})]
        self.open()
        self.overrides[("GET", self.rollout_path())] = [(200, self.plan), (503, {"error": "Console unavailable"})]
        self.page.get_by_role("button", name="Pause").click()
        self.wait_status("could not be read")
        self.assertEqual(self.owner_buttons_enabled(), 0)
        self.assertTrue(self.page.get_by_role("button", name="Reconcile with server state").is_enabled())
        paused = dict(self.plan, phase="paused")
        self.overrides[("GET", self.rollout_path())] = (200, paused)
        self.page.get_by_role("button", name="Reconcile with server state").click()
        self.wait_status("Reconciled")
        self.assertIn("paused", self.page.locator("#rollout-plan").inner_text())
        self.assertEqual(self.posts, [("POST", self.rollout_path("/pause"))])
        self.assertTrue(self.page.get_by_role("button", name="Resume").is_enabled())

    def test_concurrent_change_before_submission_sends_nothing(self):
        self.open()
        self.plan["phase"] = "standard"
        self.page.get_by_role("button", name="Pause").click()
        self.wait_status("changed since it was displayed")
        self.assertEqual(self.posts, [])
        self.assertIn("standard", self.page.locator("#rollout-plan").inner_text())

    def test_authorization_loss_makes_the_panel_read_only(self):
        for status, text in ((403, "does not permit"), (401, "no longer authorized")):
            with self.subTest(status=status):
                self.posts.clear()
                self.overrides[("POST", self.rollout_path("/pause"))] = (status, {"error": "refused"})
                self.open()
                self.page.get_by_role("button", name="Pause").click()
                self.wait_status(text)
                self.assertEqual(self.owner_buttons_enabled(), 0)
                self.assertEqual(self.posts, [("POST", self.rollout_path("/pause"))])

    def test_start_reports_a_frozen_cohort_that_differs_from_the_preview(self):
        self.plan = None
        self.revisions.append({"tenant_id": TENANT, "group_id": "fleet", "revision": "baseline",
                               "policy_sha256": "b" * 64, "approved": True})
        frozen = dict(PLAN, revision="baseline", policy_sha256="b" * 64, standard_agents=["worker-1"])

        def start(route):
            self.plan = frozen
            self.json(route, frozen, 201)

        self.overrides[("POST", self.rollout_path())] = start
        self.open()
        self.page.locator("#rollout-start-revision").select_option("baseline")
        self.page.get_by_role("button", name="Start pilot deployment").click()
        self.assertIn("Preview workers: worker-1, worker-2", self.page.locator("#rollout-confirm").inner_text())
        self.confirm("baseline")
        self.wait_status("froze a different cohort than your preview")
        self.assertIn("Current membership differs from the frozen cohort", self.page.locator("#rollout-members").inner_text())
        self.assertEqual(json.loads(self.page.evaluate("JSON.stringify(Object.keys(localStorage))")), [])

    def test_revision_digest_mismatch_is_not_presented_as_reviewed(self):
        def create(route):
            self.revisions.append({"tenant_id": TENANT, "group_id": "fleet", "revision": "v3",
                                   "policy_sha256": "c" * 64, "approved": False})
            self.json(route, self.revisions[-1], 201)

        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/groups/fleet/revisions")] = create
        self.open()
        self.page.locator("#rollout-revision-id").fill("v3")
        self.page.locator("#rollout-revision-yaml").fill("default: deny\n")
        self.page.wait_for_function("() => document.getElementById('rollout-revision-digest').textContent.includes('SHA-256')")
        self.page.locator("#rollout-create-revision button").click()
        self.wait_status("Do not approve it")

    def test_tenant_switch_discards_a_late_response(self):
        self.overrides[("GET", self.rollout_path())] = "hold"
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#tenant-list button").filter(has_text="Alpha").click()
        self.wait_status("Choose a group")
        self.page.locator("#rollout-group").select_option("fleet")
        self.page.wait_for_function("() => document.getElementById('rollout-status').textContent.includes('Loading group')")
        self.page.locator("#tenant-list button").filter(has_text="Beta").click()
        self.wait_status("No Agent groups")
        self.held[0].fulfill(status=200, content_type="application/json", body=json.dumps(self.plan))
        self.page.wait_for_timeout(200)
        self.assertNotIn("ro_1", self.page.locator("#rollout-panel").inner_text())

    def test_revision_digest_completion_cannot_submit_to_a_new_group(self):
        self.groups.append({"tenant_id": TENANT, "group_id": "other", "name": "Other", "created_at_unix": 1})
        for suffix in ("members", "revisions"):
            self.overrides[("GET", f"/admin/v1/tenants/{TENANT}/groups/other/{suffix}")] = (200, [])
        self.overrides[("GET", f"/admin/v1/tenants/{TENANT}/groups/other/rollout")] = (404, {"error": "no rollout"})
        self.open()
        self.page.evaluate("""() => {
            window.pendingDigests = [];
            crypto.subtle.digest = () => new Promise(resolve => window.pendingDigests.push(resolve));
        }""")
        self.page.locator("#rollout-revision-id").fill("old-group-revision")
        self.page.locator("#rollout-revision-yaml").fill("default: deny\n")
        self.page.locator("#rollout-create-revision button").click()
        self.page.wait_for_function("() => window.pendingDigests.length >= 2")
        self.assertEqual(self.owner_buttons_enabled(), 0)
        self.page.locator("#rollout-group").select_option("other")
        self.wait_status("Server state read")
        self.page.evaluate("() => window.pendingDigests.forEach(resolve => resolve(new Uint8Array(32).buffer))")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.posts, [])
        self.assertEqual(self.page.locator("#rollout-group").input_value(), "other")

    def test_empty_and_error_states(self):
        self.groups = []
        self.open(group=False)
        self.wait_status("No Agent groups in this tenant")
        self.overrides[("GET", f"/admin/v1/tenants/{TENANT}/groups")] = (503, {"error": "Console unavailable"})
        self.page.locator("#rollout-refresh").click()
        self.wait_status("Unable to load Agent groups")


if __name__ == "__main__":
    unittest.main()
