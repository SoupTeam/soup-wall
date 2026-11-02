# SPDX-License-Identifier: Apache-2.0
"""Agent enrollment and credential lifecycle panel: browser regressions.

The shipped admin page is assembled as admin_ui.rs does and driven against
bounded fixtures of the existing /agents endpoints. Every credential here is a
controlled synthetic value. The real browser -> Console -> Agent path is
scripts/console-enrollment-acceptance.py.
Optional: pip install playwright; python -m playwright install chromium.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

AVAILABLE = importlib.util.find_spec("playwright") is not None
SRC = Path(__file__).resolve().parents[2] / "crates/proxy/src"
ORIGIN = "https://console.example.test"
TENANT, OTHER = "tenant-a", "tenant-b"
SYNTHETIC = "sw_agent_" + "SYNTHETICxCREDENTIALxFORxPUBLICxEVIDENCEx00"
assert len(SYNTHETIC) == 52


def page_html():
    html = (SRC / "admin_dashboard.html").read_text(encoding="utf-8")
    for marker, name in (("FLEET_PANEL", "fleet_panel.js"), ("ROLLOUT_PANEL", "rollout_panel.js"),
                         ("ENROLLMENT_PANEL", "enrollment_panel.js"), ("AGENT_HISTORY", "agent_history.js")):
        html = html.replace(f"/* {marker} */", (SRC / name).read_text(encoding="utf-8"))
    return html


@unittest.skipUnless(AVAILABLE, "optional Playwright browser fixture dependency unavailable")
class EnrollmentPanelBrowserTests(unittest.TestCase):
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
        self.agents = {TENANT: [self.row("edge-1", 1)], OTHER: []}
        self.posts, self.overrides, self.held = [], {}, []
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()

    @staticmethod
    def row(agent, generation, tenant=TENANT, revoked=None):
        return {"tenant_id": tenant, "agent_id": agent, "created_at_unix": 1800000000,
                "revoked_at_unix": revoked, "credential_generation": generation}

    def json(self, route, value, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value))

    def route(self, route):
        request = route.request
        path = request.url.removeprefix(ORIGIN).split("?")[0]
        key = (request.method, path)
        if request.method != "GET" and path.startswith("/admin/v1/tenants/"):
            self.posts.append((key, request.post_data))
        if key in self.overrides:
            action = self.overrides[key]
            if isinstance(action, list):
                action = action.pop(0) if len(action) > 1 else action[0]
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
        elif path == "/admin/v1/managed-issuer":
            self.json(route, {"key_id": "synthetic-issuer", "public_key_hex": "ab" * 32})
        elif path.endswith("/agent-fleet"):
            self.json(route, {"contract_version": "sw-agent-fleet/1", "tenant_id": path.split("/")[4], "agents": [],
                              "next_after": None, "observed_at_unix": 1800000000})
        elif path.endswith(("/model-policy", "/limits")):
            self.json(route, None)
        elif path.endswith(("/tokens", "/audit", "/groups")):
            self.json(route, [])
        elif request.method == "GET" and path.endswith("/agents"):
            self.json(route, self.agents[path.split("/")[4]])
        else:
            self.json(route, {"error": "unexpected fixture request"}, 418)

    def open(self, tenant="Alpha"):
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#console").wait_for(state="visible")
        self.page.locator("#tenant-list button").filter(has_text=tenant).click()
        self.wait_status("Enrollment records read")

    def wait_status(self, text):
        self.page.wait_for_function("t => document.getElementById('enroll-status').textContent.includes(t)", arg=text)

    def status(self):
        return self.page.locator("#enroll-status").inner_text()

    def enabled_mutations(self):
        return self.page.evaluate("[...document.querySelectorAll('#enroll-panel .enroll-mutation')].filter(b => !b.disabled).length")

    def enroll_ok(self, agent="edge-2", tenant=TENANT):
        def respond(route):
            self.agents[tenant].append(self.row(agent, 1, tenant))
            self.json(route, dict(self.row(agent, 1, tenant), token=SYNTHETIC), 201)
        return respond

    def confirm(self, text):
        self.page.locator("#enroll-confirm-input").fill(text)
        self.page.locator("#enroll-confirm").get_by_role("button", name="Confirm").click()

    def rotations(self):
        return [json.loads(body) for (method, path), body in self.posts if path.endswith("/credential-rotations")]

    def test_viewer_and_operator_have_no_enrollment_controls(self):
        for role in ("viewer", "operator"):
            with self.subTest(role=role):
                self.role = role
                self.open()
                self.assertIn("edge-1", self.page.locator("#enroll-list").inner_text())
                self.assertEqual(self.page.locator("#enroll-panel .owner-action:visible").count(), 0)
                self.assertEqual(self.page.locator("#enroll-list button").count(), 0)
                self.assertEqual(self.posts, [])

    def test_enrollment_shows_a_one_time_secret_and_clears_it(self):
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = self.enroll_ok()
        self.open()
        self.page.locator("#enroll-agent-id").focus()
        self.page.keyboard.type("edge-2")
        self.page.keyboard.press("Enter")
        self.wait_status("edge-2 enrolled")
        self.assertEqual(self.page.locator("#enroll-secret-value").inner_text(), SYNTHETIC)
        self.page.wait_for_function("() => document.getElementById('enroll-secret-steps').textContent.includes('synthetic-issuer')")
        steps = self.page.locator("#enroll-secret-steps").inner_text()
        for fragment in ("SOUP_MANAGED_AGENT_TENANT=tenant-a", "SOUP_MANAGED_AGENT_ID=edge-2", "SOUP_MANAGED_AGENT_TOKEN_FILE",
                         "agentfw serve", "cannot be shown again"):
            self.assertIn(fragment, steps)
        self.assertNotIn(SYNTHETIC, steps)
        self.assertEqual(self.page.evaluate("document.activeElement.id"), "enroll-secret-copy")
        self.assertEqual(self.enabled_mutations(), 0)
        # Optional public evidence: only this synthetic credential is ever captured.
        if os.environ.get("ENROLLMENT_SCREENSHOTS"):
            self.page.locator("#enroll-panel").screenshot(path=os.path.join(os.environ["ENROLLMENT_SCREENSHOTS"], "synthetic-secret-view.png"))
        self.assertNotIn(SYNTHETIC, self.page.url)
        self.assertTrue(self.page.evaluate("localStorage.length === 0 && sessionStorage.length === 0"))
        self.assertFalse(self.page.evaluate(f"document.documentElement.outerHTML.replace(document.getElementById('enroll-secret-value').outerHTML, '').includes('{SYNTHETIC}')"))
        self.page.get_by_role("button", name="I stored it, clear it").click()
        self.assertEqual(self.page.locator("#enroll-secret-value").inner_text(), "")
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.assertFalse(self.page.evaluate(f"document.documentElement.outerHTML.includes('{SYNTHETIC}')"))
        self.assertGreater(self.enabled_mutations(), 0)

    def test_delayed_enrollment_response_never_reaches_another_tenant(self):
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = "hold"
        self.open()
        self.page.locator("#enroll-agent-id").fill("edge-2")
        self.page.locator("#enroll-form button").click()
        self.wait_status("sending")
        self.page.locator("#tenant-list button").filter(has_text="Beta").click()
        self.wait_status("Enrollment records read")
        self.held[0].fulfill(status=201, content_type="application/json",
                             body=json.dumps(dict(self.row("edge-2", 1), token=SYNTHETIC)))
        self.page.wait_for_timeout(300)
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.assertFalse(self.page.evaluate(f"document.documentElement.outerHTML.includes('{SYNTHETIC}')"))
        self.assertIn("No Agents are enrolled", self.page.locator("#enroll-list").inner_text())

    def test_duplicate_identity_is_refused_without_a_credential(self):
        self.open()
        self.page.locator("#enroll-agent-id").fill("edge-1")
        self.page.locator("#enroll-form button").click()
        self.wait_status("duplicate identity")
        self.assertEqual(self.posts, [])

        def refused(route):
            self.agents[TENANT].append(self.row("edge-3", 1))
            self.json(route, {"error": "Agent enrollment refused"}, 400)

        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = refused
        self.page.locator("#enroll-agent-id").fill("edge-3")
        self.page.locator("#enroll-form button").click()
        self.wait_status("already enrolled (duplicate identity). This request issued no credential")
        self.page.locator("#enroll-agent-id").fill("bad id/../x")
        self.page.locator("#enroll-form button").click()
        self.wait_status("Use 1 to 128 letters")
        self.assertEqual(len(self.posts), 1)

    def test_ambiguous_enrollment_reconciles_and_never_resends(self):
        def lost(route):
            self.agents[TENANT].append(self.row("edge-2", 1))
            route.abort("failed")

        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = lost
        self.open()
        self.page.locator("#enroll-agent-id").fill("edge-2")
        self.page.locator("#enroll-form button").click()
        self.wait_status("its one-time credential did not reach this browser")
        self.assertEqual(len(self.posts), 1)
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.assertIn("edge-2", self.page.locator("#enroll-list").inner_text())

    def test_rotation_sends_a_fresh_pinned_request_and_shows_the_new_credential_once(self):
        def rotate(route):
            body = json.loads(route.request.post_data)
            self.agents[TENANT][0]["credential_generation"] = 2
            self.json(route, {"tenant_id": TENANT, "agent_id": "edge-1", "generation": 2,
                              "operation_id": body["operation_id"], "already_applied": False})

        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents/edge-1/credential-rotations")] = rotate
        self.open()
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        confirm = self.page.locator("#enroll-confirm").get_by_role("button", name="Confirm")
        self.page.locator("#enroll-confirm-input").fill("edge-")
        self.assertTrue(confirm.is_disabled())
        self.confirm("edge-1")
        self.wait_status("rotated to generation 2")
        body = self.rotations()[0]
        self.assertEqual(set(body), {"expected_generation", "operation_id", "replacement_token"})
        self.assertEqual(body["expected_generation"], 1)
        self.assertRegex(body["operation_id"], r"^[0-9a-f]{32}$")
        self.assertRegex(body["replacement_token"], r"^sw_agent_[A-Za-z0-9_-]{43}$")
        self.assertEqual(self.page.locator("#enroll-secret-value").inner_text(), body["replacement_token"])
        self.assertIn("generation 2", self.page.locator("#enroll-secret-agent").inner_text())
        self.assertIn("atomic rename", self.page.locator("#enroll-secret-steps").inner_text())

    def test_ambiguous_rotation_is_confirmed_only_with_the_identical_request(self):
        path = f"/admin/v1/tenants/{TENANT}/agents/edge-1/credential-rotations"

        def lost(route):
            self.agents[TENANT][0]["credential_generation"] = 2
            route.abort("failed")

        def duplicate(route):
            body = json.loads(route.request.post_data)
            self.json(route, {"tenant_id": TENANT, "agent_id": "edge-1", "generation": 2,
                              "operation_id": body["operation_id"], "already_applied": True})

        self.overrides[("POST", path)] = [lost, duplicate]
        self.open()
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        self.confirm("edge-1")
        self.wait_status("Confirm with the same request")
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.assertEqual(self.enabled_mutations(), 0)
        self.assertEqual(len(self.rotations()), 1)
        self.page.get_by_role("button", name="Confirm with the same request").click()
        self.wait_status("this exact request was already committed")
        first, second = self.rotations()
        self.assertEqual(first, second)
        self.assertEqual(self.page.locator("#enroll-secret-value").inner_text(), first["replacement_token"])

    def abort_committed_body_once(self, suffix, reconcile_abort=False, error="AbortError"):
        # The server response exists, but its body never reaches the application.
        # A same-context AbortError is not a tenant-switch cancellation.
        config = json.dumps({"suffix": suffix, "reconcile": reconcile_abort, "error": error})
        self.page.add_init_script("""(() => {
          const config = CONFIG, original = window.fetch;
          let committed = false, readAborted = false;
          window.fetch = async (...args) => {
            const response = await original(...args), url = String(args[0]);
            if (!committed && args[1]?.method === 'POST' && url.endsWith(config.suffix)) {
              committed = true; await response.text();
              if (config.error === 'AbortError') throw new DOMException('Owned response loss', 'AbortError');
              throw new TypeError('Owned response loss');
            }
            if (config.reconcile && committed && !readAborted && !args[1]?.method && url.endsWith('/agents')) {
              readAborted = true; await response.text();
              throw new DOMException('Owned inventory response loss', 'AbortError');
            }
            return response;
          };
        })();""".replace("CONFIG", config))

    def test_body_abort_after_enrollment_reconciles_without_resending(self):
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = self.enroll_ok()
        self.abort_committed_body_once("/agents")
        self.open()
        self.page.locator("#enroll-agent-id").fill("edge-2")
        self.page.locator("#enroll-form button").click()
        self.wait_status("its one-time credential did not reach this browser")
        self.assertEqual(len(self.posts), 1)
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.assertIn("edge-2", self.page.locator("#enroll-list").inner_text())

    def committed_rotation(self, route):
        body = json.loads(route.request.post_data)
        applied = self.agents[TENANT][0]["credential_generation"] == 2
        self.agents[TENANT][0]["credential_generation"] = 2
        self.json(route, {"tenant_id": TENANT, "agent_id": "edge-1", "generation": 2,
                          "operation_id": body["operation_id"], "already_applied": applied})

    def test_body_abort_after_rotation_keeps_exact_pending_request(self):
        path = f"/admin/v1/tenants/{TENANT}/agents/edge-1/credential-rotations"
        self.overrides[("POST", path)] = self.committed_rotation
        self.abort_committed_body_once("/credential-rotations")
        self.open()
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        self.confirm("edge-1")
        self.wait_status("Confirm with the same request")
        self.assertEqual(self.agents[TENANT][0]["credential_generation"], 2)
        self.assertEqual(len(self.rotations()), 1)
        self.assertEqual(self.enabled_mutations(), 0)
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.page.get_by_role("button", name="Confirm with the same request").click()
        self.wait_status("this exact request was already committed")
        first, second = self.rotations()
        self.assertEqual(first, second)
        self.assertEqual(self.agents[TENANT][0]["credential_generation"], 2)

    def test_body_abort_after_revoke_reconciles_without_resending(self):
        def committed(route):
            self.agents[TENANT][0]["revoked_at_unix"] = 1800000100
            route.fulfill(status=204, body="")
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents/edge-1/revoke")] = committed
        self.abort_committed_body_once("/revoke")
        self.open()
        self.page.get_by_role("button", name="Revoke edge-1").click()
        self.confirm("edge-1")
        self.wait_status("Server state confirms edge-1 is revoked")
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.page.locator("#enroll-list button").count(), 0)

    def test_body_abort_during_reconcile_keeps_pending_and_allows_read_retry(self):
        path = f"/admin/v1/tenants/{TENANT}/agents/edge-1/credential-rotations"
        self.overrides[("POST", path)] = self.committed_rotation
        self.abort_committed_body_once("/credential-rotations", reconcile_abort=True, error="TypeError")
        self.open()
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        self.confirm("edge-1")
        self.wait_status("The outcome is unknown and the server state could not be read")
        self.assertEqual(len(self.rotations()), 1)
        self.assertEqual(self.enabled_mutations(), 0)
        self.page.get_by_role("button", name="Check again").click()
        self.wait_status("Confirm with the same request")
        self.assertEqual(len(self.rotations()), 1)
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())

    def test_refused_or_uncommitted_rotation_discards_its_credential(self):
        path = f"/admin/v1/tenants/{TENANT}/agents/edge-1/credential-rotations"
        self.overrides[("POST", path)] = (409, {"error": "credential rotation refused"})
        self.open()
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        self.confirm("edge-1")
        self.wait_status("is discarded and is not valid")
        self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.overrides[("POST", path)] = "abort"
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        self.confirm("edge-1")
        self.wait_status("is not committed (generation 1)")
        self.page.get_by_role("button", name="Discard").click()
        self.wait_status("Pending rotation discarded")
        self.assertGreater(self.enabled_mutations(), 0)
        self.assertEqual(len(self.rotations()), 2)

    def test_revocation_is_confirmed_from_server_state(self):
        def revoke(route):
            self.agents[TENANT][0]["revoked_at_unix"] = 1800000100
            route.fulfill(status=204, body="")

        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents/edge-1/revoke")] = revoke
        self.open()
        self.page.get_by_role("button", name="Revoke edge-1").click()
        self.page.locator("#enroll-confirm-input").press("Escape")
        self.assertEqual(self.page.locator("#enroll-confirm").inner_text(), "")
        self.page.get_by_role("button", name="Revoke edge-1").click()
        self.confirm("edge-1")
        self.wait_status("edge-1 revoked")
        self.assertIn("Revoked", self.page.locator("#enroll-list").inner_text())
        self.assertEqual(self.page.locator("#enroll-list button").count(), 0)

    def test_authorization_loss_and_unavailable_api(self):
        for status, text in ((403, "does not permit"), (401, "expired or is no longer authorized")):
            with self.subTest(status=status):
                self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = (status, {"error": "refused"})
                self.open()
                self.page.locator("#enroll-agent-id").fill("edge-9")
                self.page.locator("#enroll-form button").click()
                self.wait_status(text)
                self.assertEqual(self.enabled_mutations(), 0)
                self.assertFalse(self.page.locator("#enroll-secret").is_visible())
        self.overrides[("GET", f"/admin/v1/tenants/{TENANT}/agents")] = (503, {"error": "Agent inventory unavailable"})
        self.open_unavailable()

    def open_unavailable(self):
        self.page.goto(ORIGIN + "/admin")
        self.page.locator("#admin-token").fill("fixture-admin-token")
        self.page.locator("#unlock-form button").click()
        self.page.locator("#tenant-list button").filter(has_text="Alpha").click()
        self.wait_status("Unable to load enrollment records")
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = "abort"
        self.page.locator("#enroll-agent-id").fill("edge-7")
        self.page.locator("#enroll-form button").click()
        self.wait_status("could not be read")
        self.assertEqual(self.enabled_mutations(), 0)
        self.assertTrue(self.page.get_by_role("button", name="Check again").is_enabled())

    def test_authorization_loss_on_inventory_reads_locks_every_change(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self.overrides.clear()
                self.open()
                self.assertGreater(self.enabled_mutations(), 0)
                self.overrides[("GET", f"/admin/v1/tenants/{TENANT}/agents")] = (status, {"error": "refused"})
                self.page.locator("#enroll-refresh").click()
                self.wait_status("Reading enrollment records")
                self.assertEqual(self.enabled_mutations(), 0)
                self.page.locator("#enroll-agent-id").fill("edge-5")
                self.page.locator("#enroll-agent-id").press("Enter")
                self.page.wait_for_timeout(200)
                self.assertEqual(self.posts, [])

    def displayed_installers(self):
        """The exact install commands the one-time views show, for both kinds."""
        def rotate(route):
            body = json.loads(route.request.post_data)
            self.json(route, {"tenant_id": TENANT, "agent_id": "edge-1", "generation": 2,
                              "operation_id": body["operation_id"], "already_applied": False})

        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = self.enroll_ok()
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents/edge-1/credential-rotations")] = rotate
        self.open()
        self.page.locator("#enroll-agent-id").fill("edge-2")
        self.page.locator("#enroll-form button").click()
        self.wait_status("edge-2 enrolled")
        self.page.wait_for_function("() => document.querySelector('#enroll-secret-steps code')")
        enroll = self.page.locator("#enroll-secret-steps li").first.locator("code").inner_text()
        self.page.get_by_role("button", name="I stored it, clear it").click()
        self.page.get_by_role("button", name="Rotate credential for edge-1").click()
        self.confirm("edge-1")
        self.wait_status("rotated to generation 2")
        self.page.wait_for_function("() => document.querySelector('#enroll-secret-steps code')")
        rotate_command = self.page.locator("#enroll-secret-steps li").first.locator("code").inner_text()
        self.assertNotIn(SYNTHETIC, enroll + rotate_command)
        self.assertNotIn("umask", enroll + rotate_command)
        return enroll, rotate_command

    @unittest.skipUnless(shutil.which("bash") and shutil.which("mktemp") and shutil.which("find"), "POSIX tools needed")
    def test_displayed_installer_is_private_exclusive_and_refuses_unsafe_targets(self):
        enroll, rotate_command = self.displayed_installers()
        token = SYNTHETIC

        def run(command, home, shell, data=token, extra=None):
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home), **(extra or {})}
            return subprocess.run([shell, "-c", command], input=data.encode(), env=env, capture_output=True, timeout=30)

        for shell in [s for s in ("bash", "sh") if shutil.which(s)]:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                # Fresh install: a private 52-byte file, no staging left behind.
                home = root / "fresh"
                home.mkdir()
                self.assertEqual(run(enroll, home, shell).returncode, 0)
                target = home / ".agentfw/enrollment-token"
                self.assertEqual(target.read_bytes(), token.encode())
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
                self.assertEqual(sorted(p.name for p in target.parent.iterdir()), ["enrollment-token"])
                # Existing link, public file and foreign-writable or linked directory are refused unchanged.
                cases = {}
                for name in ("link", "public", "writable", "linked-dir", "next-link", "invalid"):
                    case = root / name
                    (case / ".agentfw").mkdir(parents=True, mode=0o700)
                    cases[name] = case
                victim = root / "victim"
                victim.write_text("owned other file\n")
                victim.chmod(0o644)
                (cases["link"] / ".agentfw/enrollment-token").symlink_to(victim)
                public = cases["public"] / ".agentfw/enrollment-token"
                public.write_text("old public\n")
                public.chmod(0o644)
                (cases["writable"] / ".agentfw").chmod(0o770)
                real = root / "real-dir"
                real.mkdir(mode=0o700)
                shutil.rmtree(cases["linked-dir"] / ".agentfw")
                (cases["linked-dir"] / ".agentfw").symlink_to(real)
                for name in ("link", "public", "writable", "linked-dir"):
                    result = run(enroll, cases[name], shell)
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertIn(b"Refused", result.stderr, name)
                self.assertEqual(victim.read_text(), "owned other file\n")
                self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o644)
                self.assertEqual(public.read_text(), "old public\n")
                self.assertEqual(list(real.iterdir()), [])
                self.assertEqual(sorted(p.name for p in (cases["writable"] / ".agentfw").iterdir()), [])
                # A planted fixed-name staging link is never used.
                (cases["next-link"] / ".agentfw/enrollment-token.next").symlink_to(victim)
                self.assertEqual(run(enroll, cases["next-link"], shell).returncode, 0)
                self.assertEqual(victim.read_text(), "owned other file\n")
                # Invalid input leaves nothing behind.
                result = run(enroll, cases["invalid"], shell, data="x" * 52)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list((cases["invalid"] / ".agentfw").iterdir()), [])
                # Rotation replaces the configured private file atomically and
                # refuses when the token file is not configured.
                configured = {"SOUP_MANAGED_AGENT_TOKEN_FILE": str(target)}
                newer = "sw_agent_" + "N" * 43
                self.assertEqual(run(rotate_command, home, shell, data=newer, extra=configured).returncode, 0)
                self.assertEqual(target.read_bytes(), newer.encode())
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                self.assertNotEqual(run(rotate_command, home, shell, data=newer).returncode, 0)
                linked = {"SOUP_MANAGED_AGENT_TOKEN_FILE": str(cases["link"] / ".agentfw/enrollment-token")}
                self.assertNotEqual(run(rotate_command, cases["link"], shell, extra=linked).returncode, 0)
                self.assertEqual(victim.read_text(), "owned other file\n")

    def test_lock_console_forgets_the_secret(self):
        self.overrides[("POST", f"/admin/v1/tenants/{TENANT}/agents")] = self.enroll_ok()
        self.open()
        self.page.locator("#enroll-agent-id").fill("edge-2")
        self.page.locator("#enroll-form button").click()
        self.wait_status("edge-2 enrolled")
        self.page.get_by_role("button", name="Lock console").click()
        self.page.locator("#unlock").wait_for(state="visible")
        self.assertFalse(self.page.evaluate(f"document.documentElement.outerHTML.includes('{SYNTHETIC}')"))
        self.assertEqual(self.page.locator("#admin-token").input_value(), "")

    def test_narrow_layout_keeps_controls_reachable(self):
        self.page.set_viewport_size({"width": 390, "height": 900})
        self.open()
        width = self.page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"
                                   " && document.getElementById('enroll-panel').scrollWidth <= document.getElementById('enroll-panel').clientWidth + 1")
        self.assertTrue(width)
        self.assertTrue(self.page.get_by_role("button", name="Rotate credential for edge-1").is_visible())
        self.assertTrue(re.search("Enroll Agent", self.page.locator("#enroll-form").inner_text()))


if __name__ == "__main__":
    unittest.main()
