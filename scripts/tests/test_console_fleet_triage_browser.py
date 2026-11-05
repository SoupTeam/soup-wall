# SPDX-License-Identifier: Apache-2.0
"""Fleet triage overview: browser regressions.

The shipped admin page is assembled as admin_ui.rs does and driven against a
fixture of the triage projection (GET .../agent-triage) and the existing
fleet, history and rollout reads. Every value is synthetic. The real
browser -> Console -> Agent path is scripts/console-fleet-triage-acceptance.py.
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
T0 = 1800000000
PROBLEMS = ["pending", "rejected", "mismatch", "revoked", "incomplete_history", "no_ack", "stale_ack", "no_history"]


def page_html():
    html = (SRC / "admin_dashboard.html").read_text(encoding="utf-8")
    for marker, name in (("FLEET_PANEL", "fleet_panel.js"), ("ROLLOUT_PANEL", "rollout_panel.js"), ("SINGLE_AGENT_POLICY", "single_agent_policy.js"),
                         ("ENROLLMENT_PANEL", "enrollment_panel.js"), ("AGENT_HISTORY", "agent_history.js"),
                         ("FLEET_TRIAGE", "fleet_triage.js"), ("AGENT_HEARTBEAT", "heartbeat_panel.js")):
        html = html.replace(f"/* {marker} */", (SRC / name).read_text(encoding="utf-8"))
    return html


def dep(seq, state, applied=None, revision="r1"):
    return {"sequence": str(seq), "revision": revision, "policy_sha256": "a" * 64, "action": "activate",
            "recorded_state": state, "issued_at_unix": T0 + seq, "reported_applied_at_unix": applied,
            "delivered_at_unix": None, "rejected_at_unix": None}


def agent(agent_id, problems, applied=None, tenant=TENANT, group=None):
    latest = None if "no_history" in problems else dep(2, "rejected" if "rejected" in problems else "issued" if "pending" in problems else "applied",
                                                       None if {"pending", "rejected"} & set(problems) else applied)
    return {"tenant_id": tenant, "agent_id": agent_id, "enrolled_at_unix": T0, "revoked_at_unix": T0 + 9 if "revoked" in problems else None,
            "latest_issued": latest, "last_reported_applied": dep(1, "applied", applied) if applied else None,
            "deployment_records": 0 if latest is None else (1 if "incomplete_history" in problems else 2),
            "problems": [p for p in PROBLEMS if p in problems], "first_group_id": group, "group_count": 2 if group else 0,
            "current_liveness": "unknown", "runtime_coverage": "unknown"}


MIXED = [agent("applied", [], T0 + 900, group="fleet"), agent("pending", ["pending", "no_ack"]),
         agent("rejected", ["rejected", "no_ack"]), agent("mismatch", ["pending", "mismatch"], T0 + 500),
         agent("revoked", ["revoked", "no_history"]), agent("fresh", ["no_history"]),
         agent("gap", ["incomplete_history"], T0 + 700), agent("old", ["stale_ack"], T0 - 90000, group="fleet")]


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class FleetTriageBrowserTests(unittest.TestCase):
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
        self.agents = {TENANT: [dict(a) for a in MIXED], OTHER: [agent("other-1", ["no_history"], tenant=OTHER)]}
        self.complete = True
        self.plan, self.held, self.mutations, self.triage_reads, self.reads = [], [], [], [], []
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    def json(self, route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def triage(self, tenant, q):
        problem, sort, prefix = q.get("problem", ["attention"])[0], q.get("sort", ["agent_id"])[0], q.get("prefix", [""])[0]
        limit = int(q.get("limit", ["25"])[0])
        rows = sorted(self.agents[tenant], key=lambda a: a["agent_id"])
        ack = lambda a: (a["last_reported_applied"] or {}).get("reported_applied_at_unix") or -1
        match = lambda a: bool(a["agent_id"].startswith(prefix) and (problem == "all" or (problem == "attention" and a["problems"])
                                                              or (problem == "no_recorded_problem" and not a["problems"]) or problem in a["problems"]))
        counts = {p: sum(p in a["problems"] for a in rows) for p in PROBLEMS}
        counts.update(counted_agents=len(rows), scan_limit=10000, complete=self.complete, attention=sum(bool(a["problems"]) for a in rows),
                      no_recorded_problem=sum(not a["problems"] for a in rows), matching=sum(match(a) for a in rows))
        page = [a for a in rows if match(a)]
        if sort == "ack_oldest":
            page.sort(key=lambda a: (ack(a), a["agent_id"]))
        if "after" in q:
            after, after_ack = q["after"][0], int(q.get("after_ack", ["-2"])[0])
            page = [a for a in page if (ack(a), a["agent_id"]) > (after_ack, after)] if sort == "ack_oldest" else [a for a in page if a["agent_id"] > after]
        more = len(page) > limit
        page = page[:limit]
        nxt = {"after": page[-1]["agent_id"], "after_ack": ack(page[-1]) if sort == "ack_oldest" else None} if more else None
        return {"contract_version": "sw-agent-fleet-triage/1", "tenant_id": tenant, "observed_at_unix": T0 + 1000, "problem": problem,
                "sort": sort, "prefix": prefix, "ack_age_seconds": int(q.get("ack_age_seconds", ["86400"])[0]), "counts": counts,
                "agents": page, "next": nxt}

    def route(self, route):
        request = route.request
        url = urlsplit(request.url)
        path, q = url.path, parse_qs(url.query)
        if request.method != "GET":
            self.mutations.append((request.method, path))
        self.reads.append(path)
        if path == "/admin":
            return route.fulfill(status=200, content_type="text/html", body=self.html)
        if path == "/admin/v1/whoami":
            return self.json(route, {"admin_name": "Fixture viewer", "role": "viewer"})
        if path == "/admin/v1/tenants":
            return self.json(route, [{"id": TENANT, "name": "Alpha", "active": True}, {"id": OTHER, "name": "Beta", "active": True}])
        parts = path.split("/")
        if path.endswith("/agent-triage"):
            tenant = parts[4]
            self.triage_reads.append((tenant, {k: v[0] for k, v in q.items()}))
            if self.plan:
                action = self.plan.pop(0)
                if action == "hold":
                    return self.held.append((route, tenant, q))
                if isinstance(action, int):
                    return self.json(route, {"error": {"message": "fixture"}}, action)
                if callable(action):
                    return self.json(route, action(self.triage(tenant, q)))
            return self.json(route, self.triage(tenant, q))
        if path.endswith("/agent-fleet"):
            tenant = parts[4]
            return self.json(route, {"contract_version": "sw-agent-fleet/1", "tenant_id": tenant, "agents": [], "next_after": None,
                                     "observed_at_unix": T0 + 1000})
        if path.endswith("/heartbeat"):
            parts = path.split("/")
            return self.json(route, {"contract_version": "sw-agent-heartbeat-status/1", "tenant_id": parts[4], "agent_id": parts[6],
                                     "observed_at_unix": 1800000000, "status": "unsupported", "expires_after_seconds": 90,
                                     "age_seconds": None, "current_credential_generation": 1, "reported": None, "note": "fixture"})
        if "/agent-fleet/" in path:
            tenant, agent_id = parts[4], parts[6]
            a = next(x for x in self.agents[tenant] if x["agent_id"] == agent_id)
            deployments = [d for d in (a["latest_issued"],) if d]
            return self.json(route, {"contract_version": "sw-agent-fleet/1", "observed_at_unix": T0 + 1000,
                                     "agent": {k: a[k] for k in ("tenant_id", "agent_id", "enrolled_at_unix", "revoked_at_unix", "latest_issued",
                                                                 "last_reported_applied", "current_liveness", "runtime_coverage")} | {"registry_identity": None},
                                     "deployments": deployments, "next_before_sequence": None})
        if path.endswith("/groups"):
            return self.json(route, [{"tenant_id": parts[4], "group_id": "fleet", "name": "Fleet", "created_at_unix": T0}])
        if path.endswith(("/model-policy", "/limits")):
            return self.json(route, None)
        if path.endswith(("/tokens", "/audit", "/agents")):
            return self.json(route, [])
        return self.json(route, {"error": {"message": "unexpected fixture request"}}, 418)

    def open(self, tenant="Alpha", width=1280):
        self.page.set_viewport_size({"width": width, "height": 900})
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#console").wait_for(state="visible")
        self.page.locator("#tenant-list button").filter(has_text=tenant).click()

    def wait_status(self, text):
        self.page.wait_for_function("t => document.getElementById('triage-status').textContent.includes(t)", arg=text)

    def status(self):
        return self.page.locator("#triage-status").inner_text()

    def listed(self):
        return self.page.locator("#triage-list tbody tr td:first-child").all_inner_texts()

    def count(self, key):
        return self.page.locator(f"#triage-summary [data-problem='{key}'] strong").inner_text()

    def test_counts_denominators_and_filters(self):
        self.open()
        self.wait_status("Page 1")
        self.assertEqual(self.listed(), ["fresh", "gap", "mismatch", "old", "pending", "rejected", "revoked"])
        self.assertIn("Seen 7 of 7 matching", self.status())
        self.assertEqual([self.count(k) for k in ("attention", "pending", "rejected", "mismatch", "revoked", "incomplete_history",
                                                   "no_ack", "stale_ack", "no_history", "no_recorded_problem")],
                         ["7", "2", "1", "1", "1", "1", "2", "1", "2", "1"])
        summary = self.page.locator("#triage-summary").inner_text()
        self.assertIn("of 8", summary)
        self.assertIn("not proof of health", summary)
        self.assertNotIn("Healthy", summary)
        self.page.locator("#triage-summary [data-problem='no_recorded_problem']").click()
        self.wait_status("Seen 1 of 1")
        self.assertEqual(self.listed(), ["applied"])
        self.assertIn("None recorded (not proof of health)", self.page.locator("#triage-list").inner_text())
        self.page.locator("#triage-problem").select_option("stale_ack")
        self.page.locator("#triage-filter button[type=submit]").click()
        self.wait_status("Seen 1 of 1")
        self.assertIn("historical", self.page.locator("#triage-list").inner_text())
        self.page.locator("#triage-problem").select_option("all")
        self.page.locator("#triage-sort").select_option("ack_oldest")
        self.page.locator("#triage-prefix").fill("")
        self.page.locator("#triage-filter button[type=submit]").click()
        self.wait_status("Seen 8 of 8")
        self.assertEqual(self.listed()[:5], ["fresh", "pending", "rejected", "revoked", "old"])
        self.assertEqual(self.triage_reads[-1][1]["sort"], "ack_oldest")
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.page.url, ORIGIN + "/admin")
        self.assertEqual(self.page.evaluate("localStorage.length + sessionStorage.length"), 0)

    def test_pages_partial_counts_and_changed_records(self):
        self.agents[TENANT] = [agent(f"edge-{n:02d}", ["no_history"]) for n in range(30)]
        self.complete = False
        self.open()
        self.wait_status("Page 1")
        self.assertIn("Seen 25 of 30 matching among the first 30 Agents by ID", self.status())
        self.assertIn("later Agents are neither counted nor listed", self.page.locator("#triage-summary").inner_text())
        self.page.locator("#triage-next").click()
        self.wait_status("Page 2")
        self.assertIn("Seen 30 of 30", self.status())
        self.assertEqual(self.triage_reads[-1][1]["after"], "edge-24")
        self.assertTrue(self.page.locator("#triage-next").is_disabled())
        # Records change between pages: a repeated Agent and one fewer than counted.
        self.page.locator("#triage-first").click()
        self.wait_status("Page 1")
        self.plan = [lambda body: body | {"agents": [self.agents[TENANT][24]] + body["agents"][:3]}]
        self.page.locator("#triage-next").click()
        self.wait_status("Page 2")
        self.assertIn("1 Agent(s) repeated", self.status())
        self.assertIn("Fewer than counted", self.status())

    def test_listed_agent_outside_the_counted_universe_is_refused(self):
        # The reviewer's probe: complete=false, matching=0, yet one Agent listed.
        outside = agent("agent-10000", [])
        self.plan = [lambda b: b | {"counts": b["counts"] | {"complete": False, "counted_agents": 10000, "matching": 0},
                                    "agents": [outside]}]
        self.open()
        self.wait_status("discarded")
        self.assertEqual(self.listed(), [])
        self.assertNotIn("Seen 1 of 0", self.status())
        for counts in ({"matching": 9, "counted_agents": 8}, {"counted_agents": 10001, "matching": 1}):
            with self.subTest(counts=counts):
                self.plan = [lambda b, c=counts: b | {"counts": b["counts"] | c}]
                self.page.locator("#triage-refresh").click()
                self.wait_status("discarded")

    def test_more_seen_than_counted_is_never_a_denominator(self):
        self.agents[TENANT] = [agent(f"edge-{n:02d}", ["no_history"]) for n in range(30)]
        self.open()
        self.wait_status("Page 1")
        self.plan = [lambda b: b | {"counts": b["counts"] | {"matching": 26}}]
        self.page.locator("#triage-next").click()
        self.wait_status("Page 2")
        self.assertIn("Seen 26 of 26 matching", self.status())
        self.assertIn("4 more seen than the current count", self.status())
        self.assertNotIn("Seen 30 of 26", self.status())

    def test_stale_reply_after_tenant_switch_is_discarded(self):
        self.plan = ["hold"]
        self.open()
        self.page.wait_for_function("() => document.getElementById('triage-status').textContent.includes('Loading')")
        self.page.locator("#tenant-list button").filter(has_text="Beta").click()
        self.wait_status("Page 1")
        route, tenant, q = self.held.pop()
        self.json(route, self.triage(tenant, q))
        self.page.wait_for_timeout(200)
        self.assertEqual(self.listed(), ["other-1"])

    def test_mixed_tenant_malformed_and_mismatched_responses_are_refused(self):
        bad = [
            lambda b: b | {"agents": b["agents"] + [agent("intruder", ["no_history"], tenant=OTHER)]},
            lambda b: b | {"agents": [b["agents"][0] | {"problems": ["healthy"]}]},
            lambda b: b | {"agents": [b["agents"][0] | {"agent_id": "<img src=x onerror=window.pwned=1>"}]},
            lambda b: b | {"agents": [b["agents"][0], b["agents"][0]]},
            lambda b: b | {"problem": "all"},
            lambda b: b | {"tenant_id": OTHER},
            lambda b: b | {"counts": b["counts"] | {"matching": -1}},
            lambda b: b | {"contract_version": "sw-agent-fleet/1"},
        ]
        self.open()
        self.wait_status("Page 1")
        for change in bad:
            with self.subTest(n=bad.index(change)):
                self.plan = [change]
                self.page.locator("#triage-refresh").click()
                self.wait_status("discarded")
                self.assertEqual(self.listed(), [])
                self.assertEqual(self.page.locator("#triage-summary").inner_text(), "")
        self.assertEqual(self.page.locator("#triage-panel img").count(), 0)
        self.assertFalse(self.page.evaluate("window.pwned === 1"))

    def test_errors_clear_and_are_specific(self):
        self.open()
        self.wait_status("Page 1")
        for code, text in ((401, "Session expired"), (403, "cannot read fleet triage"), (404, "Tenant not found"), (503, "Unable to load")):
            with self.subTest(code=code):
                self.plan = [code]
                self.page.locator("#triage-refresh").click()
                self.wait_status(text)
                self.assertEqual(self.listed(), [])
                self.assertTrue(self.page.locator("#triage-next").is_disabled())

    def test_deep_links_open_history_and_rollout(self):
        self.open()
        self.wait_status("Page 1")
        self.page.get_by_role("button", name="Open recorded history for old").click()
        self.page.wait_for_function("() => document.getElementById('history-status').textContent.includes('History for old')")
        self.assertEqual(self.page.locator("#fleet-agent-detail h3").first.text_content(), "Agent old")
        self.page.get_by_role("button", name="Open rollout group fleet for old").click()
        self.page.wait_for_function("() => document.getElementById('rollout-group').value === 'fleet'")
        self.assertTrue(any(p.endswith("/groups/fleet") or "/groups/fleet/" in p for p in self.reads))
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.page.url, ORIGIN + "/admin")

    def test_invalid_prefix_refused_locally_and_empty_state(self):
        self.open()
        self.wait_status("Page 1")
        reads = len(self.triage_reads)
        self.page.locator("#triage-prefix").fill("../x")
        self.page.locator("#triage-filter button[type=submit]").click()
        self.wait_status("prefix may contain")
        self.assertEqual(len(self.triage_reads), reads)
        self.page.locator("#triage-prefix").fill("zzz")
        self.page.locator("#triage-filter button[type=submit]").click()
        self.wait_status("Seen 0 of 0")
        self.assertIn("No enrolled Agents match", self.page.locator("#triage-list").inner_text())

    def test_narrow_layout(self):
        self.open(width=390)
        self.wait_status("Page 1")
        overflow = self.page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        self.assertLessEqual(overflow, 0)


if __name__ == "__main__":
    unittest.main()
