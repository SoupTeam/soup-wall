# SPDX-License-Identifier: Apache-2.0
"""Individual policy UI controls against bounded API fixtures, no credentials retained."""
import copy
import hashlib
import json
import unittest
from urllib.parse import parse_qs, urlsplit
from scripts.tests.test_console_rollout_browser import RolloutPanelBrowserTests as Base, AVAILABLE, ORIGIN, TENANT, OTHER

YAML = "default: deny\n"
DIGEST = hashlib.sha256(YAML.encode()).hexdigest()


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class SinglePolicyBrowserTests(unittest.TestCase):
    setUpClass = classmethod(Base.setUpClass.__func__)
    tearDownClass = classmethod(Base.tearDownClass.__func__)
    json = Base.json

    def setUp(self):
        Base.setUp(self)
        self.documents = {"r1": {"revision": "r1", "policy_sha256": DIGEST, "policy_yaml": YAML, "approved": True}}
        self.issuances, self.keys, self.calls = [], {}, []
        self.agent_ids = ("agent-a", "agent-b")
        self.lose, self.hold, self.mismatch = False, False, False
        self.deploy_status = None
        self.revoked = False
        self.callback_errors = []
        self.page.on("pageerror", lambda error: self.callback_errors.append(str(error)))
        def accept(dialog):
            try:
                dialog.accept()
            except Exception as error:
                self.callback_errors.append(str(error))
        self.page.on("dialog", accept)

    def tearDown(self):
        self.assertEqual(self.callback_errors, [])

    def route(self, route):
        req = route.request
        path = req.url.removeprefix(ORIGIN).split("?")[0]
        parts = path.split("/")
        if "/agents" not in path:
            return Base.route(self, route)
        tenant = parts[4]
        if len(parts) == 6:
            return self.json(route, [{"tenant_id": tenant, "agent_id": a, "revoked_at_unix": 1 if self.revoked else None} for a in self.agent_ids])
        if len(parts) >= 7 and parts[6].startswith("policy-"):
            query = parse_qs(urlsplit(req.url).query)
            parts = parts[:6] + [query["agent_id"][0], parts[6].removeprefix("policy-")] + parts[7:]
        if len(parts) < 8:
            return self.json(route, {"error": "unexpected path"}, 404)
        agent = parts[6]
        decorate = lambda value: dict(copy.deepcopy(value), tenant_id=tenant, agent_id=agent)
        if parts[7] == "deployments":
            return self.json(route, [decorate(d) for d in self.issuances if d.get("tenant_id", tenant) == tenant and d.get("agent_id", agent) == agent])
        if parts[7] == "revisions" and len(parts) == 8 and req.method == "GET":
            if self.hold:
                self.held.append(route)
                return
            return self.json(route, [decorate({k: v for k, v in d.items() if k != "policy_yaml"}) for d in self.documents.values()])
        if parts[7] == "revisions" and len(parts) == 8 and req.method == "POST":
            value = req.post_data_json
            self.documents[value["revision"]] = dict(value, policy_sha256=hashlib.sha256(value["policy_yaml"].encode()).hexdigest(), approved=False)
            return self.json(route, decorate(self.documents[value["revision"]]), 201)
        revision = parse_qs(urlsplit(req.url).query)["revision"][0] if parts[7] == "revision" else parts[8]
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
                d = decorate({"deployment_sequence": 1 + max((d["deployment_sequence"] for d in self.issuances if d["tenant_id"] == tenant and d["agent_id"] == agent), default=0), "revision": revision,
                    "policy_sha256": self.documents[revision]["policy_sha256"], "action": "rollback" if req.post_data_json["rollback"] else "activate",
                    "status": "issued", "issued_at_unix": 1800000000, "applied_at_unix": None,
                    "idempotency": {"key": key, "envelope_sha256": "e" * 64, "replayed": False, "issuer_key_id": "fixture-key", "expires_at_unix": 1800003600}})
                self.keys[key] = d
                self.issuances.append(d)
            if self.lose:
                self.lose = False
                return route.abort("failed")
            return self.json(route, self.keys[key], 201)
        self.json(route, {"error": "unexpected request"}, 418)

    def open(self, agent="agent-a"):
        Base.open(self, group=False)
        self.page.locator("#single-agent").select_option(agent)
        self.page.wait_for_function("!document.getElementById('single-create').disabled || document.body.classList.contains('role-viewer') || document.body.classList.contains('role-operator')")

    def review(self, revision="r1"):
        self.page.locator("#single-revision").select_option(revision)
        self.page.wait_for_function("document.getElementById('single-document').textContent.includes('Server SHA-256')")

    def test_dot_agent_identities_are_preserved_through_review_and_issuance(self):
        self.agent_ids = (".", "..")
        for agent in self.agent_ids:
            with self.subTest(agent=agent):
                self.open(agent)
                self.review()
                self.page.locator("#single-deploy").click()
                self.page.wait_for_function(
                    "document.getElementById('single-intent').textContent.includes('sequence 1')")
                self.assertEqual(self.issuances[-1]["agent_id"], agent)
                self.assertEqual(self.issuances[-1]["deployment_sequence"], 1)
        self.assertEqual(len(self.issuances), 2)
        self.assertNotEqual(self.calls[0][0], self.calls[1][0])

    def test_dot_revisions_can_be_reviewed_approved_deployed_and_rolled_back(self):
        self.documents = {
            revision: {"revision": revision, "policy_sha256": DIGEST,
                       "policy_yaml": YAML, "approved": False}
            for revision in (".", "..")
        }
        self.open()
        for sequence, revision in enumerate((".", ".."), start=1):
            with self.subTest(revision=revision):
                self.review(revision)
                self.page.locator("#single-approve").click()
                self.page.wait_for_function(
                    "revision => [...document.getElementById('single-revision').options]"
                    ".some(o => o.value === revision && o.textContent.endsWith('approved') "
                    "&& !o.textContent.endsWith('unapproved'))", arg=revision)
                self.review(revision)
                button = "#single-deploy" if sequence == 1 else "#single-rollback"
                self.page.locator(button).click()
                self.page.wait_for_function(
                    "sequence => document.getElementById('single-intent').textContent"
                    ".includes('sequence ' + sequence)", arg=sequence)
                self.assertEqual(len(self.issuances), sequence)
                self.assertEqual(self.issuances[-1]["revision"], revision)
                self.assertEqual(self.issuances[-1]["action"],
                                 "activate" if sequence == 1 else "rollback")

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
        self.open()
        self.review()
        self.lose = True
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('outcome unresolved')")
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.page.evaluate("document.getElementById('single-retry').click();document.getElementById('single-retry').click()")
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 1')")
        self.assertEqual(len(self.issuances), 1)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0], self.calls[1])

    def test_initial_duplicate_submission_issues_once(self):
        self.open()
        self.review()
        self.page.evaluate("document.getElementById('single-deploy').click();document.getElementById('single-deploy').click()")
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 1')")
        self.assertEqual(len(self.issuances),1)
        self.assertEqual(len(self.calls),1)

    def test_rollback_to_current_revision_is_disabled(self):
        self.open()
        self.issuances.append({"revision":"r1", "policy_sha256":DIGEST, "deployment_sequence":1, "action":"activate", "status":"applied", "issued_at_unix":1, "applied_at_unix":2})
        self.page.locator("#single-refresh").click()
        self.page.wait_for_function("document.getElementById('single-deployments').textContent.includes('applied')")
        self.review()
        self.assertTrue(self.page.locator("#single-rollback").is_disabled())
        self.assertFalse(self.page.locator("#single-deploy").is_disabled())

    def test_changed_intent_requires_new_confirmation_and_key(self):
        self.open()
        self.review()
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 1')")
        self.review()
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.getElementById('single-intent').textContent.includes('sequence 2')")
        self.assertNotEqual(self.calls[0][0], self.calls[1][0])

    def test_viewer_operator_and_live_role_change_cannot_mutate(self):
        for role in ("viewer", "operator"):
            self.role = role
            self.open()
            self.assertEqual(self.page.locator("#single-policy-panel .owner-action:visible").count(), 0)
            self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.role = "owner"
        self.open()
        self.review()
        self.role = "viewer"
        self.page.locator("#single-deploy").click()
        self.page.wait_for_function("document.body.classList.contains('role-viewer')")
        self.assertEqual(self.calls, [])

    def test_inconsistent_yaml_digest_blocks_approval_and_deploy(self):
        self.open()
        self.mismatch = True
        self.page.locator("#single-revision").select_option("r1")
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('inconsistent')")
        self.assertTrue(self.page.locator("#single-deploy").is_disabled())
        self.assertTrue(self.page.locator("#single-approve").is_disabled())

    def test_agent_switch_clears_review_and_draft(self):
        self.open()
        self.review()
        self.page.locator("#single-yaml").fill("private draft")
        self.page.locator("#single-agent").select_option("agent-b")
        self.assertEqual(self.page.locator("#single-yaml").input_value(), "")
        self.assertNotIn("Server SHA-256", self.page.locator("#single-document").inner_text())
        self.assertEqual(self.calls, [])

    def test_stale_reply_after_tenant_switch_cannot_restore_review(self):
        self.open()
        self.hold = True
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
        for status, text in [(401, "Authorization refused"), (403, "Authorization refused"), (409, "Overlap conflict")]:
            self.open()
            self.review()
            self.deploy_status = status
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


    def test_rejected_candidate_shows_reason_apart_from_applied(self):
        """SOU-241: fixed reason text and next step; applied stays separate."""
        self.open()
        self.issuances += [
            {"revision": "r1", "policy_sha256": DIGEST, "deployment_sequence": 1, "action": "activate", "status": "applied", "issued_at_unix": 1, "applied_at_unix": 2},
            {"revision": "r1", "policy_sha256": DIGEST, "deployment_sequence": 2, "action": "activate", "status": "rejected", "issued_at_unix": 3, "applied_at_unix": None,
             "rejected_at_unix": 4, "rejection_code": "issuer_key_unknown"},
            {"revision": "r1", "policy_sha256": DIGEST, "deployment_sequence": 3, "action": "activate", "status": "rejected", "issued_at_unix": 5, "applied_at_unix": None}]
        self.page.locator("#single-refresh").click()
        self.page.wait_for_function("document.getElementById('single-deployments').textContent.includes('Rejected candidate')")
        text = self.page.locator("#single-deployments").text_content()
        blocks = {b.split(" · ")[0]: b for b in text.split("\n\n")}
        self.assertIn("issuer key the Agent does not trust", blocks["Sequence 2"])
        self.assertIn("Received by Console 4", blocks["Sequence 2"])
        self.assertIn("next step: Deploy again with a trusted Console signing key", blocks["Sequence 2"])
        self.assertIn("did not report a reason", blocks["Sequence 3"])
        self.assertIn("Received by Console not recorded", blocks["Sequence 3"])
        self.assertNotIn("Rejected candidate", blocks["Sequence 1"])
        # A reason on a non-rejected record or with free text fails closed.
        self.issuances[0]["rejection_code"] = "bundle_expired"
        self.page.locator("#single-refresh").click()
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('Unresolved')")
        self.issuances[0].pop("rejection_code")
        self.issuances[1]["rejection_code"] = "Key <unknown>"
        self.page.locator("#single-refresh").click()
        self.page.wait_for_function("document.getElementById('single-policy-status').textContent.includes('Unresolved')")
        self.assertEqual(self.callback_errors, [])

def load_tests(loader, tests, pattern):
    return loader.loadTestsFromTestCase(SinglePolicyBrowserTests)


if __name__ == "__main__":
    unittest.main()
