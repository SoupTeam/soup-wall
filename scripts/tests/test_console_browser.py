# SPDX-License-Identifier: Apache-2.0
"""Execute the shipped Console JavaScript against bounded browser fixtures.

Optional: pip install playwright; python -m playwright install chromium.
The real Keycloak drill is scripts/keycloak-oidc-acceptance.py.
"""
import importlib.util
import json
from pathlib import Path
import unittest

AVAILABLE = importlib.util.find_spec("playwright") is not None
HTML = Path(__file__).resolve().parents[2] / "crates/proxy/src/customer_dashboard.html"


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class ConsoleSessionBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True)
        except Exception:
            cls.playwright.stop()
            raise unittest.SkipTest("optional Chromium fixture runtime unavailable")

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.session_status = 200
        self.logout_status = 204
        self.requests = []
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    def route(self, route):
        self.requests.append(route.request.url)
        path = route.request.url.removeprefix("https://console.example.test")
        if path == "/customer":
            route.fulfill(status=200, content_type="text/html", body=HTML.read_text(encoding="utf-8"))
        elif path == "/customer/v1/session":
            route.fulfill(status=self.session_status, content_type="application/json", body=json.dumps(
                {"access": {"organization_id": "organization", "workspace_id": "workspace",
                            "principal_id": "principal", "role": "analyst"}}))
        elif path == "/auth/logout":
            if self.logout_status is None:
                route.abort()
            else:
                route.fulfill(status=self.logout_status, body="")
        else:
            route.fulfill(status=403, content_type="application/json", body="{}")

    def open_signed_in(self):
        self.page.goto("https://console.example.test/customer")
        self.page.locator("#identity").wait_for(state="visible")

    def test_missing_session_offers_real_oidc_entry_form(self):
        self.session_status = 401
        self.page.goto("https://console.example.test/customer")
        self.page.locator("#sign-in").wait_for(state="visible")
        self.assertFalse(self.page.locator("#identity").is_visible())
        self.page.locator("#login-organization").fill("org & one")
        self.page.locator("#login-workspace").fill("workspace/one")
        self.page.locator("#sign-in-form button").click()
        self.page.wait_for_url("**/auth/oidc/start?**")
        from urllib.parse import parse_qs, urlsplit
        self.assertEqual(parse_qs(urlsplit(self.page.url).query),
                         {"organization_id": ["org & one"], "workspace_id": ["workspace/one"]})

    def test_successful_logout_removes_workspace_data_and_offers_sign_in(self):
        self.open_signed_in()
        self.page.locator("#logout").click()
        self.page.locator("#sign-in").wait_for(state="visible")
        self.assertEqual(self.page.locator("#identity").inner_html(), "")
        self.assertIn("logged out", self.page.locator("#status").inner_text())

    def test_http_logout_failure_keeps_retry_and_does_not_claim_success(self):
        self.logout_status = 503
        self.open_signed_in()
        self.page.locator("#logout").click()
        self.page.wait_for_function("document.getElementById('status').textContent.includes('could not be confirmed')")
        self.assertTrue(self.page.locator("#identity").is_visible())
        self.assertTrue(self.page.locator("#logout").is_enabled())
        self.assertFalse(self.page.locator("#sign-in").is_visible())

    def test_network_logout_failure_keeps_retry(self):
        self.logout_status = None
        self.open_signed_in()
        self.page.locator("#logout").click()
        self.page.wait_for_function("document.getElementById('status').textContent.includes('could not be confirmed')")
        self.assertTrue(self.page.locator("#logout").is_enabled())

    def test_expired_api_session_clears_loaded_data_and_blocks_late_render(self):
        self.open_signed_in()
        self.session_status = 401
        self.page.evaluate("customerFetch('/customer/v1/session').catch(() => {})")
        self.assertTrue(self.page.locator("#sign-in").is_visible())
        self.assertEqual(self.page.locator("#identity").inner_html(), "")
        self.assertIn("expired", self.page.locator("#status").inner_text())


if __name__ == "__main__":
    unittest.main()
