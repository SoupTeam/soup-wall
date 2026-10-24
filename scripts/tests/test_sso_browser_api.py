# SPDX-License-Identifier: Apache-2.0
"""Narrow browser transport retry; authorization and mutations stay observable."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

SPEC = importlib.util.spec_from_file_location("sso_api_diagnostics", Path(__file__).resolve().parents[1] / "sso_diagnostics.py")
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class BrowserApiTransportTests(unittest.TestCase):
    def setUp(self):
        self.page = Mock()
        self.listeners = {}
        self.page.on.side_effect = lambda event, callback: self.listeners.setdefault(event, []).append(callback)
        self.page.remove_listener.side_effect = lambda event, callback: self.listeners[event].remove(callback)
        self.report = {}

    def request(self, method="GET", failure="net::ERR_NETWORK_CHANGED", response=False, count=1):
        for _ in range(count):
            req = Mock(url="https://gateway.test/customer/v1/billing/invoice-preview", method=method, failure=failure)
            for callback in self.listeners.get("request", []):
                callback(req)
            if response:
                for callback in self.listeners.get("response", []):
                    callback(Mock(request=req))
            for callback in self.listeners.get("requestfailed", []):
                callback(req)

    def fetch(self, **kwargs):
        return D.browser_api_fetch(self.page, "https://gateway.test", "/customer/v1/billing/invoice-preview", self.report, **kwargs)

    def test_confirmed_network_change_retries_one_get_and_preserves_403(self):
        def evaluate(*_):
            if self.page.evaluate.call_count == 1:
                self.request()
                raise RuntimeError("private cookie=secret")
            return {"status": 403, "data": None}
        self.page.evaluate.side_effect = evaluate
        self.assertEqual(self.fetch()["status"], 403)
        self.assertEqual(self.page.evaluate.call_count, 2)
        self.assertTrue(self.report["browser_api_failures"][0]["retry"])
        self.assertNotIn("secret", str(self.report))
        self.assertTrue(all(not values for values in self.listeners.values()))

    def test_authorization_responses_are_returned_without_retry(self):
        for status in (401, 403, 500):
            self.page.evaluate.reset_mock()
            self.page.evaluate.return_value = {"status": status, "data": None}
            self.assertEqual(self.fetch()["status"], status)
            self.page.evaluate.assert_called_once()
        self.assertEqual(self.report, {})

    def test_mutations_never_retry(self):
        for method in ("POST", "PATCH", "DELETE"):
            self.page.evaluate.reset_mock()
            def evaluate(*_, method=method):
                self.request(method=method)
                raise RuntimeError("transport")
            self.page.evaluate.side_effect = evaluate
            with self.assertRaises(RuntimeError):
                self.fetch(method=method, body="private payload")
            self.page.evaluate.assert_called_once()
            self.assertFalse(self.report["browser_api_failures"][-1]["retry"])

    def test_unknown_or_other_transport_errors_do_not_retry(self):
        for failure in (None, "net::ERR_CONNECTION_RESET", "net::ERR_CERT_AUTHORITY_INVALID", "private failure"):
            self.page.evaluate.reset_mock()
            def evaluate(*_, failure=failure):
                if failure is not None:
                    self.request(failure=failure)
                raise RuntimeError("private URL and body")
            self.page.evaluate.side_effect = evaluate
            with self.assertRaises(RuntimeError):
                self.fetch()
            self.page.evaluate.assert_called_once()
        self.assertNotIn("private", str(self.report))

    def test_received_response_or_ambiguous_requests_prevent_retry(self):
        for options in ({"response": True}, {"count": 2}):
            self.page.evaluate.reset_mock()
            def evaluate(*_, options=options):
                self.request(**options)
                raise RuntimeError("transport")
            self.page.evaluate.side_effect = evaluate
            with self.assertRaises(RuntimeError):
                self.fetch()
            self.page.evaluate.assert_called_once()

    def test_second_network_failure_is_retained_and_raised(self):
        def evaluate(*_):
            self.request()
            raise RuntimeError("still failed")
        self.page.evaluate.side_effect = evaluate
        with self.assertRaisesRegex(RuntimeError, "still failed"):
            self.fetch()
        self.assertEqual(self.page.evaluate.call_count, 2)
        self.assertEqual([row["retry"] for row in self.report["browser_api_failures"]], [True, False])
        self.assertTrue(all(not values for values in self.listeners.values()))

    def test_unrelated_request_failure_cannot_trigger_retry(self):
        def evaluate(*_):
            req = Mock(url="https://other.test/private", method="GET", failure="net::ERR_NETWORK_CHANGED")
            for callback in self.listeners.get("request", []):
                callback(req)
            for callback in self.listeners.get("requestfailed", []):
                callback(req)
            raise RuntimeError("other")
        self.page.evaluate.side_effect = evaluate
        with self.assertRaises(RuntimeError):
            self.fetch()
        self.page.evaluate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
