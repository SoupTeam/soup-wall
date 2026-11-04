# SPDX-License-Identifier: Apache-2.0
"""Individual policy UI controls against bounded API fixtures, no credentials retained."""
import copy
import hashlib
import json
import unittest
from scripts.tests.test_console_rollout_browser import RolloutPanelBrowserTests as Base, ORIGIN, TENANT, OTHER

YAML = "default: deny\n"
DIGEST = hashlib.sha256(YAML.encode()).hexdigest()


class SinglePolicyBrowserTests(unittest.TestCase):
    setUpClass = classmethod(Base.setUpClass.__func__)
    tearDownClass = classmethod(Base.tearDownClass.__func__)
    json = Base.json

    def setUp(self):
        Base.setUp(self)
        self.documents = {"r1": {"revision": "r1", "policy_sha256": DIGEST, "policy_yaml": YAML, "approved": True}}
        self.issuances, self.keys, self.calls = [], {}, []
        self.lose, self.hold, self.mismatch = False, False, False
        self.deploy_status = None
        self.revoked = False

    def route(self, route):
        req = route.request
        path = req.url.removeprefix(ORIGIN).split("?")[0]
        parts = path.split("/")
        if "/agents" not in path:
            return Base.route(self, route)
        tenant = parts[4]
        if len(parts) == 6:
            return self.json(route, [{"tenant_id": tenant, "agent_id": a, "revoked_at_unix": 1 if self.revoked else None} for a in ("agent-a", "agent-b")])
        agent = parts[6]
        decorate = lambda value: dict(copy.deepcopy(value), tenant_id=tenant, agent_id=agent)
        if parts[7] == "deployments":
            return self.json(route, [decorate(d) for d in self.issuances])
        if len(parts) == 8 and req.method == "GET":
            if self.hold:
                self.held.append(route)
                return
            return self.json(route, [decorate({k: v for k, v in d.items() if k != "policy_yaml"}) for d in self.documents.values()])
        if len(parts) == 8 and req.method == "POST":
            value = req.post_data_json
            self.documents[value["revision"]] = dict(value, policy_sha256=hashlib.sha256(value["policy_yaml"].encode()).hexdigest(), approved=False)
            return self.json(route, decorate(self.documents[value["revision"]]), 201)
        revision = parts[8]
        if req.method == "GET":
            doc = decorate(self.documents[revision])
            if self.mismatch:
                doc["policy_sha256"] = "0" * 64
            return self.json(route, doc)
        if parts[-1] == "approve":
            self.documents[revision]["approved"] = True
            return route.fulfill(status=204)
        if parts[-1] == "deploy":
            if self.deploy_status:
                return self.json(route, {"error": "refused"}, self.deploy_status)
            key = req.headers.get("idempotency-key")
            self.calls.append((key, req.post_data_json))
            if key not in self.keys:
                d = decorate({"deployment_sequence": len(self.issuances) + 1, "revision": revision,
                    "policy_sha256": self.documents[revision]["policy_sha256"], "action": "rollback" if req.post_data_json["rollback"] else "activate",
                    "status": "issued", "issued_at_unix": 1800000000, "applied_at_unix": None,
                    "idempotency": {"key": key, "envelope_sha256": "e" * 64, "replayed": False}})
                self.keys[key] = d
                self.issuances.append(d)
            if self.lose:
                self.lose = False
                return route.abort("failed")
            return self.json(route, self.keys[key], 201)
        self.json(route, {"error": "unexpected request"}, 418)

    def open(self):
        Base.open(self, group=False)
        self.page.locator("#single-agent").select_option("agent-a")
        self.page.wait_for_function("!document.getElementById('single-create').disabled || document.body.classList.contains('role-viewer') || document.body.classList.contains('role-operator')")
        self.page.on("dialog", lambda dialog: dialog.accept())

    def review(self, revision="r1"):
        self.page.locator("#single-revision").select_option(revision)
        self.page.wait_for_function("document.getElementById('single-document').textContent.includes('Server SHA-256')")

    def test_exact_yaml_create_approve_and_deploy(self):
        self.open()
        self.page.locator("#single-new-revision").fill("r2")
        self.page.locator("#single-yaml").fill(YAML)
        self.page.locator("#single-create").click()
        self.page.wait_for_function("[...document.getElementById('single-revision').options].some(o=>o.value==='r2')")
        self.review("r2")
        self.assertIn(DIGEST, self.page.locator("#single-document").inner_text())
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.page.locator("#single-approve").click()
        self.page.wait_for_function("[...document.getElementById('single-revision').options].some(o=>o.textContent==='r2 · approved')")
        self.review("r2")
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 1')")
        self.assertEqual(len(self.issuances), 1)
        self.assertEqual(self.page.evaluate("localStorage.length+sessionStorage.length"), 0)

    def test_lost_response_retry_and_duplicate_submit_reuse_key(self):
        self.open(); self.review(); self.lose = True
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('outcome unresolved')")
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.page.evaluate("document.getElementById('single-retry').click();document.getElementById('single-retry').click()")
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 1')")
        self.assertEqual(len(self.issuances), 1)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0], self.calls[1])

    def test_changed_intent_requires_new_confirmation_and_key(self):
        self.open(); self.review()
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 1')")
        self.review(); self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 2')")
        self.assertNotEqual(self.calls[0][0], self.calls[1][0])

    def test_viewer_operator_and_live_role_change_cannot_mutate(self):
        for role in ("viewer", "operator"):
            self.role = role; self.open()
            self.assertEqual(self.page.locator("#single-policy-panel .owner-action:visible").count(), 0)
            self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.role = "owner"; self.open(); self.review(); self.role = "viewer"
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.body.classList.contains('role-viewer')")
        self.assertEqual(self.calls, [])

    def test_inconsistent_yaml_digest_blocks_approval_and_deploy(self):
        self.open(); self.mismatch = True
        self.page.locator("#single-revision").select_option("r1")
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('inconsistent')")
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.assertTrue(self.page.locator("#single-approve").is_disabled())

    def test_agent_switch_clears_review_and_draft(self):
        self.open(); self.review()
        self.page.locator("#single-yaml").fill("private draft")
        self.page.locator("#single-agent").select_option("agent-b")
        self.assertEqual(self.page.locator("#single-yaml").input_value(), "")
        self.assertNotIn("Server SHA-256", self.page.locator("#single-document").inner_text())
        self.assertEqual(self.calls, [])

    def test_stale_reply_after_tenant_switch_cannot_restore_review(self):
        self.open(); self.hold = True
        self.page.locator("#single-refresh").click()
        self.page.wait_for_timeout(50)
        self.page.locator("#tenant-list button").filter(has_text="Beta").click()
        for route in self.held:
            try:
                self.json(route, [])
            except Exception:
                pass  # aborted old GETs are expected
        self.assertNotIn("Server SHA-256", self.page.locator("#single-document").inner_text())
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.assertEqual(self.calls, [])

    def test_403_and_overlap_conflict_leave_explicit_refusal(self):
        for status, text in [(403, "Authorization refused"), (409, "Overlap conflict")]:
            self.open(); self.review(); self.deploy_status = status
            self.page.locator("#single-deploy").click()
            self.page.wait_for_function("text=>document.getElementById('single-policy-status').textContent.includes(text)", arg=text)
            self.assertTrue(self.page.locator("#single-deploy").is_disabled())
            self.assertEqual(self.issuances, [])

    def test_revocation_and_rejection_are_distinct_from_applied(self):
        self.open()
        self.issuances.append({"revision":"r1", "policy_sha256":DIGEST, "deployment_sequence":1, "action":"activate", "status":"rejected", "issued_at_unix":1, "applied_at_unix":None})
        self.page.locator("#single-refresh").click()
        self.page.wait_for_function("document.getElementById('single-deployments').textContent.includes('rejected')")
        self.revoked = True
        self.page.locator("#single-refresh").click()
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('Agent revoked')")
        self.assertTrue(self.page.locator("#single-create").is_disabled())
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromTestCase(SinglePolicyBrowserTests)


if __name__ == "__main__":
    unittest.main()
