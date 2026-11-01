# SPDX-License-Identifier: Apache-2.0
"""Recorded Agent history and incident snapshot: browser regressions.

The shipped admin page is assembled as admin_ui.rs does and driven against a
fixture of the existing fleet detail read (GET .../agent-fleet/:agent), with
its keyset paging. Every value here is synthetic. The real browser -> Console
-> Agent path is scripts/console-agent-history-acceptance.py.
Optional: pip install playwright; python -m playwright install chromium.
"""
import importlib.util
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlsplit

AVAILABLE = importlib.util.find_spec("playwright") is not None
SRC = Path(__file__).resolve().parents[2] / "crates/proxy/src"
ORIGIN = "https://console.example.test"
TENANT, OTHER = "tenant-a", "tenant-b"
SYNTHETIC = "sw_agent_" + "SYNTHETICxCREDENTIALxFORxPUBLICxEVIDENCEx00"
T0 = 1800000000


def page_html():
    html = (SRC / "admin_dashboard.html").read_text(encoding="utf-8")
    for marker, name in (("FLEET_PANEL", "fleet_panel.js"), ("ROLLOUT_PANEL", "rollout_panel.js"),
                         ("ENROLLMENT_PANEL", "enrollment_panel.js"), ("AGENT_HISTORY", "agent_history.js")):
        html = html.replace(f"/* {marker} */", (SRC / name).read_text(encoding="utf-8"))
    return html


def dep(seq, state, applied=None, revision=None, action="activate"):
    return {"sequence": str(seq), "revision": revision or f"rev-{seq}", "policy_sha256": f"{seq:x}".rjust(64, "a"),
            "action": action, "recorded_state": state, "issued_at_unix": T0 + seq * 100,
            "reported_applied_at_unix": applied, "delivered_at_unix": None, "rejected_at_unix": None}


MIXED = [dep(1, "applied", T0 + 150), dep(2, "issued"), dep(3, "rejected"), dep(4, "applied", T0 + 450, action="rollback"),
         dep(5, "delivered")]


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class AgentHistoryBrowserTests(unittest.TestCase):
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
        self.history = {(TENANT, "edge-1"): list(MIXED), (TENANT, "edge-2"): [], (OTHER, "edge-1"): [dep(1, "issued")]}
        self.revoked = {}
        self.page_size = None
        self.pages = {}       # (agent, before) -> replacement response body
        self.statuses = {}    # (agent, before) -> list of HTTP statuses/"abort"/"hold"
        self.held, self.mutations, self.history_reads = [], [], []
        self.context = self.browser.new_context(accept_downloads=True)
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    def json(self, route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def detail(self, tenant, agent, limit, before):
        records = sorted(self.history[(tenant, agent)], key=lambda d: -int(d["sequence"]))
        latest = records[0] if records else None
        applied = next((d for d in records if d["recorded_state"] == "applied"), None)
        if before is not None:
            records = [d for d in records if int(d["sequence"]) < before]
        page = records[:limit + 1]
        more = len(page) > limit
        page = page[:limit]
        return {"contract_version": "sw-agent-fleet/1", "observed_at_unix": T0 + 1000,
                "agent": {"tenant_id": tenant, "agent_id": agent, "enrolled_at_unix": T0,
                          "revoked_at_unix": self.revoked.get((tenant, agent)), "latest_issued": latest,
                          "last_reported_applied": applied, "current_liveness": "unknown",
                          "runtime_coverage": "unknown", "registry_identity": None},
                "deployments": page, "next_before_sequence": page[-1]["sequence"] if more else None}

    def route(self, route):
        request = route.request
        url = urlsplit(request.url)
        path, query = url.path, parse_qs(url.query)
        if request.method != "GET":
            self.mutations.append((request.method, path))
        if path == "/admin":
            return route.fulfill(status=200, content_type="text/html", body=self.html)
        if path == "/admin/v1/whoami":
            return self.json(route, {"admin_name": "Fixture viewer", "role": "viewer"})
        if path == "/admin/v1/tenants":
            return self.json(route, [{"id": TENANT, "name": "Alpha", "active": True}, {"id": OTHER, "name": "Beta", "active": True}])
        parts = path.split("/")
        if path.endswith("/agent-fleet"):
            tenant = parts[4]
            agents = sorted({a for (t, a) in self.history if t == tenant})
            rows = [{"tenant_id": tenant, "agent_id": a, "enrolled_at_unix": T0, "revoked_at_unix": None,
                     "latest_issued": None, "last_reported_applied": None} for a in agents]
            return self.json(route, {"contract_version": "sw-agent-fleet/1", "tenant_id": tenant, "agents": rows,
                                     "next_after": None, "observed_at_unix": T0 + 1000})
        if "/agent-fleet/" in path:
            tenant, agent = parts[4], parts[6]
            limit = int(query["limit"][0])
            before = int(query["before_sequence"][0]) if "before_sequence" in query else None
            if limit == 50:  # the history module's page size; 25 is the fleet table
                self.history_reads.append((tenant, agent, before))
                limit = self.page_size or limit
                plan = self.statuses.get((agent, before))
                if plan:
                    action = plan.pop(0)
                    if action == "hold":
                        return self.held.append((route, tenant, agent, limit, before))
                    if action == "abort":
                        return route.abort("failed")
                    if isinstance(action, int):
                        return self.json(route, {"error": {"message": "fixture"}}, action)
                if (agent, before) in self.pages:
                    return self.json(route, self.pages[(agent, before)])
            return self.json(route, self.detail(tenant, agent, limit, before))
        if path.endswith(("/model-policy", "/limits")):
            return self.json(route, None)
        if path.endswith(("/tokens", "/audit", "/groups", "/agents")):
            return self.json(route, [])
        if path == "/admin/v1/managed-issuer":
            return self.json(route, {"key_id": "synthetic-issuer", "public_key_hex": "ab" * 32})
        return self.json(route, {"error": "unexpected fixture request"}, 418)

    # helpers
    def open(self, tenant="Alpha", width=1280):
        self.page.set_viewport_size({"width": width, "height": 900})
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#console").wait_for(state="visible")
        self.page.locator("#tenant-list button").filter(has_text=tenant).click()
        self.page.locator("#fleet-list").get_by_role("button", name="edge-1", exact=True).wait_for()

    def pick(self, agent="edge-1"):
        self.page.locator("#fleet-list").get_by_role("button", name=agent, exact=True).click()

    def wait_status(self, text):
        self.page.wait_for_function("t => document.getElementById('history-status').textContent.includes(t)", arg=text)

    def summary(self):
        return self.page.locator("#history-summary").inner_text()

    def events(self):
        return self.page.locator("#history-timeline li").all_inner_texts()

    def snapshot(self):
        self.page.locator("#history-preview").click()
        return json.loads(self.page.locator("#history-snapshot").text_content())

    # tests
    def test_mixed_history_is_chronological_and_never_green(self):
        self.open()
        self.pick()
        self.wait_status("No older pages")
        kinds = [e.split(" · ")[0] for e in self.events()]
        self.assertEqual(kinds, ["Enrolled", "Issued", "Applied", "Issued", "Superseded", "Issued", "Rejected",
                                 "Issued", "Applied", "Issued", "Fetched", "Pending"])
        text = self.summary()
        self.assertIn("Loaded 5 of 5 deployment records in 1 page(s)", text)
        self.assertIn("Current protection and liveness: unknown", text)
        self.assertIn("2 unresolved outcome(s)", text)
        self.assertIn("rotations", text)
        self.assertEqual(self.page.locator("#history-summary .outcome-ok").count(), 0)
        # Latest issued and historical last applied link to their timeline entries.
        self.assertEqual(self.page.locator("#history-summary a").evaluate_all("a => a.map(x => x.getAttribute('href'))"),
                         ["#history-dep-5", "#history-dep-4"])
        snap = self.snapshot()
        self.assertEqual(snap["completeness"]["status"], "complete_records")
        self.assertFalse(snap["partial"])
        self.assertEqual(snap["summary"]["current_protection"], "unknown")
        self.assertEqual(len(snap["unresolved_event_ids"]), 2)
        self.assertEqual(len({e["event_id"] for e in snap["events"]}), len(snap["events"]))
        self.assertEqual(self.mutations, [])

    def test_pagination_denominators_and_export_bounds(self):
        self.page_size = 2
        self.open()
        self.pick()
        self.wait_status("Older records may exist")
        self.assertIn("Loaded 2 of 5 deployment records in 1 page(s)", self.summary())
        self.assertIn("Incomplete history", self.summary())
        snap = self.snapshot()
        self.assertTrue(snap["partial"])
        self.assertEqual(snap["coverage"]["missing_sequence_ranges"], [[1, 3]])
        self.assertIn("older_records_not_loaded", [r["code"] for r in snap["completeness"]["reasons"]])
        with self.page.expect_download() as info:
            self.page.locator("#history-download").click()
        download = info.value
        self.assertTrue(download.suggested_filename.endswith("-partial.json"))
        exported = json.loads(Path(download.path()).read_text(encoding="utf-8"))
        self.assertEqual(exported["coverage"]["expected_deployments"], 5)
        self.assertEqual(exported["coverage"]["loaded_deployments"], 2)
        self.page.locator("#history-more").click()
        self.wait_status("Older records may exist")
        self.assertIn("Loaded 4 of 5 deployment records in 2 page(s)", self.summary())
        self.page.locator("#history-more").click()
        self.wait_status("No older pages")
        self.assertIn("Loaded 5 of 5 deployment records in 3 page(s)", self.summary())
        self.assertTrue(self.page.locator("#history-more").is_disabled())
        snap = self.snapshot()
        self.assertFalse(snap["partial"])
        self.assertEqual([p["before_sequence"] for p in snap["coverage"]["pages"]], [None, 4, 2])
        self.assertEqual(self.history_reads, [(TENANT, "edge-1", None), (TENANT, "edge-1", 4), (TENANT, "edge-1", 2)])
        self.assertEqual(self.mutations, [])

    def test_page_bound_stops_and_stays_partial(self):
        self.history[(TENANT, "edge-1")] = [dep(n, "applied" if n == 20 else "issued", T0 + 2050 if n == 20 else None) for n in range(1, 21)]
        self.page_size = 2
        self.open()
        self.pick()
        for _ in range(7):
            self.wait_status("Older records may exist")
            self.page.locator("#history-more").click()
        self.wait_status("Older records may exist")
        self.assertTrue(self.page.locator("#history-more").is_disabled())
        self.assertIn("Loaded 16 of 20 deployment records in 8 page(s)", self.summary())
        snap = self.snapshot()
        self.assertTrue(snap["partial"])
        self.assertIn("page_bound_reached", [r["code"] for r in snap["completeness"]["reasons"]])
        self.assertEqual(len(self.history_reads), 8)

    def test_gap_overlap_conflict_and_missing_history(self):
        self.page_size = 2
        base = self.detail(TENANT, "edge-1", 2, 4)
        # Cursor 4 skips #3: the page holds #2 and #1 only.
        self.pages[("edge-1", 4)] = dict(base, deployments=[dep(2, "issued"), dep(1, "applied", T0 + 150)], next_before_sequence=None)
        self.open()
        self.pick()
        self.wait_status("Older records may exist")
        self.page.locator("#history-more").click()
        self.wait_status("No older pages")
        codes = [r["code"] for r in self.snapshot()["completeness"]["reasons"]]
        self.assertIn("sequence_gap", codes)
        self.assertIn("Incomplete history", self.summary())
        # An overlapping page that repeats #4 with a different state is contradictory.
        self.pages[("edge-1", 4)] = dict(base, deployments=[dep(4, "rejected"), dep(3, "rejected")], next_before_sequence="3")
        self.pick()
        self.wait_status("Older records may exist")
        self.page.locator("#history-more").click()
        self.wait_status("Older records may exist")
        snap = self.snapshot()
        self.assertEqual(snap["completeness"]["status"], "contradictory")
        self.assertIn("overlapping_pages", [r["code"] for r in snap["completeness"]["reasons"]])
        self.assertIn("conflicting_duplicate", [c["code"] for c in snap["completeness"]["contradictions"]])
        self.assertIn("Contradictory records", self.summary())
        # Expired history: the server has no records older than #3.
        self.page_size = None
        self.pages.clear()
        self.history[(TENANT, "edge-1")] = [d for d in MIXED if int(d["sequence"]) >= 3]
        self.pick()
        self.wait_status("No older pages")
        snap = self.snapshot()
        self.assertIn("history_missing", [r["code"] for r in snap["completeness"]["reasons"]])
        self.assertEqual(snap["coverage"]["missing_sequence_ranges"], [[1, 2]])
        self.assertTrue(snap["partial"])

    def test_malformed_and_private_fields_are_dropped_not_rendered(self):
        hostile = dict(dep(3, "rejected"), revision='<img src=x onerror="window.pwned=1">')
        leaky = dict(dep(5, "delivered"), token=SYNTHETIC, policy_yaml="default: deny", bundle_json="{}",
                     note="/home/operator/.agentfw/enrollment-token")
        self.history[(TENANT, "edge-1")] = MIXED[:2] + [hostile, MIXED[3], leaky]
        self.open()
        self.pick()
        self.wait_status("No older pages")
        self.assertEqual(self.page.locator("#history-panel img").count(), 0)
        self.assertFalse(self.page.evaluate("window.pwned === 1"))
        self.assertNotIn("onerror", self.page.locator("#history-panel").inner_text())
        snap = self.snapshot()
        raw = json.dumps(snap)
        for private in (SYNTHETIC, "default: deny", "bundle_json", "policy_yaml", "/home/", "onerror"):
            self.assertNotIn(private, raw)
        self.assertEqual(snap["coverage"]["malformed_records_dropped"], 1)
        codes = [r["code"] for r in snap["completeness"]["reasons"]]
        self.assertIn("malformed_records", codes)
        self.assertIn("sequence_gap", codes)
        self.assertTrue(snap["partial"])

    def test_malformed_older_record_is_counted(self):
        self.history[(TENANT, "edge-1")] = [dict(dep(1, "applied", T0 + 150), revision="bad revision!")] + MIXED[1:]
        self.open()
        self.pick()
        self.wait_status("No older pages")
        snap = self.snapshot()
        self.assertEqual(snap["coverage"]["malformed_records_dropped"], 1)
        self.assertIn("malformed_records", [r["code"] for r in snap["completeness"]["reasons"]])
        self.assertTrue(snap["partial"])
        self.assertNotIn("bad revision!", json.dumps(snap))

    def test_delayed_reply_after_agent_and_tenant_change_is_discarded(self):
        self.statuses[("edge-1", None)] = ["hold"]
        self.open()
        self.pick("edge-1")
        self.page.wait_for_function("() => document.getElementById('history-status').textContent.includes('Loading')")
        self.pick("edge-2")
        self.wait_status("No older pages")
        self.page.locator("#tenant-list button").filter(has_text="Beta").click()
        self.page.locator("#fleet-list").get_by_role("button", name="edge-1", exact=True).wait_for()
        route, tenant, agent, limit, before = self.held.pop()
        self.json(route, self.detail(tenant, agent, limit, before))
        self.page.wait_for_timeout(200)
        self.assertEqual(self.events(), [])
        self.assertIn("Select an Agent", self.page.locator("#history-status").inner_text())
        # Same Agent ID in the other tenant shows only that tenant's record.
        self.pick("edge-1")
        self.wait_status("No older pages")
        self.assertIn("Loaded 1 of 1", self.summary())
        self.assertNotIn("rev-5", self.page.locator("#history-panel").inner_text())

    def test_delayed_older_page_after_switch_does_not_splice(self):
        self.page_size = 2
        self.statuses[("edge-1", 4)] = ["hold"]
        self.open()
        self.pick()
        self.wait_status("Older records may exist")
        self.page.locator("#history-more").click()
        self.page.wait_for_function("() => document.getElementById('history-status').textContent.includes('older than #4')")
        self.pick("edge-2")
        self.wait_status("No older pages")
        route, tenant, agent, limit, before = self.held.pop()
        self.json(route, self.detail(tenant, agent, limit, before))
        self.page.wait_for_timeout(200)
        self.assertIn("Loaded 0 of 0", self.summary())
        self.assertEqual([e.split(" · ")[0] for e in self.events()], ["Enrolled"])

    def test_wrong_scope_response_is_refused(self):
        self.pages[("edge-1", None)] = self.detail(TENANT, "edge-2", 50, None)
        self.open()
        self.pick()
        self.wait_status("did not match")
        self.assertEqual(self.events(), [])
        self.assertTrue(self.page.locator("#history-preview").is_disabled())

    def test_network_failure_then_retry_and_loading_state(self):
        self.page_size = 2
        self.statuses[("edge-1", 4)] = ["abort"]
        self.open()
        self.pick()
        self.wait_status("Older records may exist")
        self.page.locator("#history-more").click()
        self.wait_status("could not be read")
        snap = self.snapshot()
        self.assertIn("page_request_failed", [r["code"] for r in snap["completeness"]["reasons"]])
        self.assertTrue(snap["partial"])
        self.assertIn("Loaded 2 of 5", self.summary())
        self.page.locator("#history-more").click()
        self.wait_status("Older records may exist")
        self.assertIn("Loaded 4 of 5", self.summary())
        self.assertNotIn("page_request_failed", [r["code"] for r in self.snapshot()["completeness"]["reasons"]])

    def test_lost_authorization_forgets_history(self):
        for code, text in ((401, "Session expired"), (403, "cannot read Agent history"), (404, "not found")):
            with self.subTest(code=code):
                self.page_size = 2
                self.statuses[("edge-1", 4)] = [code]
                self.open()
                self.pick()
                self.wait_status("Older records may exist")
                self.page.locator("#history-more").click()
                self.wait_status(text)
                self.assertEqual(self.events(), [])
                self.assertEqual(self.summary(), "")
                self.assertTrue(self.page.locator("#history-download").is_disabled())

    def test_empty_revoked_and_narrow_layout(self):
        self.revoked[(TENANT, "edge-2")] = T0 + 50
        self.open(width=390)
        self.pick("edge-2")
        self.wait_status("No older pages")
        self.assertEqual([e.split(" · ")[0] for e in self.events()], ["Enrolled", "Revoked"])
        self.assertIn("No deployment history", self.summary())
        self.assertFalse(self.snapshot()["partial"])
        self.pick("edge-1")
        self.wait_status("No older pages")
        self.page.locator("#history-preview").click()
        overflow = self.page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        self.assertLessEqual(overflow, 0)
        self.assertEqual(self.page.evaluate("localStorage.length + sessionStorage.length"), 0)

    def test_snapshot_refuses_private_looking_identifiers(self):
        # Valid ID syntax can still look like a credential; export is refused.
        self.history[(TENANT, "edge-1")] = [dep(1, "applied", T0 + 150, revision="sw_agent_lookslikeacredential")]
        self.open()
        self.pick()
        self.wait_status("No older pages")
        self.page.locator("#history-preview").click()
        self.wait_status("Snapshot refused")
        self.assertTrue(self.page.locator("#history-snapshot").is_hidden())


if __name__ == "__main__":
    unittest.main()
