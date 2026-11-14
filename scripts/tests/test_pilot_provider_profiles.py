# SPDX-License-Identifier: Apache-2.0
"""Finite private provider setup and source-selection regressions."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("provider_profiles", ROOT / "scripts/pilot_provider_profiles.py")
if sys.platform.startswith("linux"):
    PROFILE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(PROFILE)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux descriptor-safe store")
class ProviderProfiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / ".agentfw"
        self.home.mkdir(mode=0o700)
        self.secret = "SOU172-SYNTHETIC-CANARY-9f452"
        self.public = {"model": "claude-sonnet-4-20250514",
                       "ANTHROPIC_BASE_URL": "http://127.0.0.1:19001/v1"}

    def create(self, name="owned", secret=None):
        with PROFILE.Store(self.home, create=True) as store:
            return store.create(name, self.public, {"ANTHROPIC_API_KEY": secret or self.secret})

    def test_create_select_use_existing_carrier_and_redacted_inventory(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            inventory = store.inspect()
            self.assertEqual(inventory["selected"], None)
            self.assertEqual(inventory["profiles"][0]["model"], self.public["model"])
            self.assertNotIn(self.secret, json.dumps(inventory))
            store.select("owned")
        values, model, selected, identity = PROFILE.chosen(self.home, {})
        self.assertEqual(values["ANTHROPIC_API_KEY"], self.secret)
        self.assertEqual(values["ANTHROPIC_BASE_URL"], self.public["ANTHROPIC_BASE_URL"])
        self.assertEqual(model, self.public["model"])
        self.assertEqual(selected, "owned")
        PROFILE.unchanged(self.home, selected, identity)
        with PROFILE.PROVIDER.carrier(values) as fd:
            self.assertEqual(os.fstat(fd).st_nlink, 0)
            self.assertEqual(json.loads(os.read(fd, 16385))["ANTHROPIC_API_KEY"], self.secret)
        for path in (self.home / PROFILE.DIRECTORY).iterdir():
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn(self.secret, json.dumps(inventory))

    def test_conflict_changed_selection_removal_and_explicit_environment(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
        for ambient in ({"ANTHROPIC_API_KEY": "other"}, {"HTTP_PROXY": "http://127.0.0.1:7"}):
            with self.assertRaisesRegex(PROFILE.Refusal, "provider_source_conflict"):
                PROFILE.chosen(self.home, ambient)
        values, model, selected, identity = PROFILE.chosen(self.home, {})
        with PROFILE.Store(self.home) as store:
            replacement = dict(self.public, model="claude-sonnet-4-20250515",
                               ANTHROPIC_BASE_URL="http://127.0.0.1:19002/v1")
            store.create("owned", replacement, {"ANTHROPIC_API_KEY": "changed-canary"}, replace=True)
            before_select = store.inspect()
            self.assertTrue(before_select["selection_valid"])
            self.assertFalse(before_select["selected_is_current"])
            self.assertEqual(before_select["selected_model"], self.public["model"])
            self.assertEqual(before_select["profiles"][0]["model"], replacement["model"])
        PROFILE.unchanged(self.home, selected, identity)
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret,
                         "explicit create --replace must not rotate an already selected profile")
        with PROFILE.Store(self.home) as store:
            store.select("owned")
            after_select = store.inspect()
            self.assertTrue(after_select["selected_is_current"])
            self.assertEqual(after_select["selected_model"], replacement["model"])
            self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], "changed-canary")
            store.remove("owned")
        with self.assertRaisesRegex(PROFILE.Refusal, "provider_profile_missing"):
            PROFILE.chosen(self.home, {})
        with PROFILE.Store(self.home) as store:
            store.environment()
        self.assertEqual(PROFILE.chosen(self.home, {"ANTHROPIC_AUTH_TOKEN": "explicit"})[0],
                         {"ANTHROPIC_AUTH_TOKEN": "explicit"})

    def test_interrupted_replacement_preserves_last_profile_and_selection(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
            before, identity = store.profile("owned")
            with patch.object(PROFILE.os, "replace", side_effect=OSError("synthetic interruption")):
                with self.assertRaises(OSError):
                    store.create("owned", self.public, {"ANTHROPIC_API_KEY": "new-canary"}, replace=True)
            after, same = store.profile("owned")
            self.assertEqual(after, before)
            self.assertEqual(same, identity)
            self.assertEqual(store.selected()["profile_sha256"], identity)
            self.assertFalse(any(p.name.startswith(".next-") for p in (self.home / PROFILE.DIRECTORY).iterdir()))

    def test_bad_private_files_and_redirected_parents_refuse(self):
        self.create()
        directory = self.home / PROFILE.DIRECTORY
        path = directory / "owned.json"
        path.chmod(0o644)
        with PROFILE.Store(self.home) as store, self.assertRaisesRegex(PROFILE.Refusal, "provider_private_file_required"):
            store.profile("owned")
        path.chmod(0o600)
        path.unlink()
        path.symlink_to(self.root / "unrelated")
        with PROFILE.Store(self.home) as store, self.assertRaisesRegex(PROFILE.Refusal, "provider_private_file_required"):
            store.profile("owned")
        path.unlink()
        os.mkfifo(path, 0o600)
        with PROFILE.Store(self.home) as store, self.assertRaisesRegex(PROFILE.Refusal, "provider_private_file_required"):
            store.profile("owned")
        path.unlink()
        self.create()
        duplicate = self.root / "hardlink"
        os.link(path, duplicate)
        with PROFILE.Store(self.home) as store, self.assertRaisesRegex(PROFILE.Refusal, "provider_private_file_required"):
            store.profile("owned")
        duplicate.unlink()
        path.write_bytes(b"x" * (PROFILE.MAX_FILE + 1))
        with PROFILE.Store(self.home) as store, self.assertRaisesRegex(PROFILE.Refusal, "provider_private_file_required"):
            store.profile("owned")
        path.unlink()
        self.create("owned")
        with PROFILE.Store(self.home) as store:
            moved = self.root / "moved"
            self.home.rename(moved)
            self.home.symlink_to(moved)
            with self.assertRaises((OSError, PROFILE.Refusal)):
                store.profile("owned")

    def test_redirected_profile_directory_refuses_without_touching_target(self):
        self.create()
        directory = self.home / PROFILE.DIRECTORY
        external = self.root / "external"
        external.mkdir(mode=0o700)
        (external / "sentinel").write_text("untouched")
        directory.rename(self.home / "real-profiles")
        directory.symlink_to(external)
        with self.assertRaisesRegex(PROFILE.Refusal, "provider_home_invalid"):
            PROFILE.Store(self.home)
        self.assertEqual((external / "sentinel").read_text(), "untouched")

    def test_schema_endpoint_name_and_limits_refuse(self):
        for bad in ("../x", "UPPER", "x" * 33, "two parts", "selected"):
            with self.assertRaisesRegex(PROFILE.Refusal, "provider_name_invalid"):
                PROFILE.name(bad)
        for endpoint in ("http://example.com/v1", "https://user:pass@example.com/v1",
                         "https://example.com/v1?token=secret", "https://example.com/a/../v1",
                         "https://example.com/a/%2e%2e/v1", "https://example.com\\@other.test/v1"):
            with self.assertRaisesRegex(PROFILE.Refusal, "provider_transport_invalid"):
                PROFILE.validate_public(dict(self.public, ANTHROPIC_BASE_URL=endpoint))
        for raw in (b'{"format":"x","format":"y"}', b"[1,2]", b" " * (PROFILE.MAX_FILE + 1)):
            with self.assertRaisesRegex(PROFILE.Refusal, "provider_profile_invalid"):
                PROFILE.strict(raw)
        with self.assertRaisesRegex(PROFILE.Refusal, "provider_profile_invalid"):
            PROFILE.validate_profile({"format": PROFILE.FORMAT, "name": "owned", "public": self.public,
                                      "secrets": {"ANTHROPIC_API_KEY": "one", "ANTHROPIC_AUTH_TOKEN": "two"}})

    def test_hidden_or_fd_secret_input_and_consent_before_read(self):
        from types import SimpleNamespace
        args = SimpleNamespace(secret_fd=None, prompt_api_key=True)
        with patch.object(PROFILE.sys.stdin, "isatty", return_value=True), \
             patch.object(PROFILE.getpass, "getpass", return_value=self.secret):
            self.assertEqual(PROFILE.secret_input(args), {"ANTHROPIC_API_KEY": self.secret})
        with tempfile.TemporaryFile(mode="w+b") as source:
            os.fchmod(source.fileno(), 0o600)
            source.write(PROFILE.encoded({"ANTHROPIC_AUTH_TOKEN": self.secret}))
            source.seek(0)
            args.secret_fd = source.fileno()
            self.assertEqual(PROFILE.secret_input(args), {"ANTHROPIC_AUTH_TOKEN": self.secret})
        with PROFILE.PROVIDER.carrier({"ANTHROPIC_API_KEY": self.secret}) as sealed:
            args.secret_fd = sealed
            self.assertEqual(PROFILE.secret_input(args), {"ANTHROPIC_API_KEY": self.secret})

    def test_installed_entry_style_cli_never_prints_secret_and_requires_consent(self):
        script = ROOT / "scripts/pilot.py"
        base = [sys.executable, "-I", "-B", str(script), "--agent-home", str(self.home), "provider"]
        with tempfile.TemporaryFile(mode="w+b") as source:
            os.fchmod(source.fileno(), 0o600)
            source.write(PROFILE.encoded({"ANTHROPIC_API_KEY": self.secret}))
            source.seek(0)
            command = [*base, "create", "--name", "owned", "--model", self.public["model"],
                       "--base-url", self.public["ANTHROPIC_BASE_URL"],
                       "--secret-fd", str(source.fileno())]
            denied = subprocess.run(command, pass_fds=(source.fileno(),), capture_output=True, timeout=15)
            self.assertNotEqual(denied.returncode, 0)
            self.assertFalse((self.home / PROFILE.DIRECTORY).exists())
            created = subprocess.run([*command, "--apply"], pass_fds=(source.fileno(),),
                                     capture_output=True, timeout=15)
        self.assertEqual(created.returncode, 0, created.stderr)
        selected = subprocess.run([*base, "select", "--name", "owned", "--apply"],
                                  capture_output=True, timeout=15)
        preview = subprocess.run([*base, "preview"], capture_output=True, timeout=15)
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        for result in (denied, created, selected, preview):
            self.assertNotIn(self.secret.encode(), result.stdout + result.stderr)
        self.assertEqual(json.loads(preview.stdout)["selected"], "owned")

    def test_update_preview_is_inert_and_rotation_pins_old_and_new_launches(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
        old_values, _, selected, old_identity = PROFILE.chosen(self.home, {})
        new_secret = "SOU181-SYNTHETIC-NEW-7d52"
        new_url = "http://127.0.0.1:19002/v1"
        cli = [sys.executable, "-I", "-B", str(ROOT / "scripts/pilot.py"),
               "--agent-home", str(self.home), "provider"]
        before = {path.name: path.read_bytes() for path in (self.home / PROFILE.DIRECTORY).iterdir()}
        preview = subprocess.run([*cli, "update", "--name", "owned", "--base-url", new_url,
                                  "--secret-fd", "987654"], capture_output=True, timeout=15)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        plan = json.loads(preview.stdout)
        self.assertEqual(plan["status"], "plan")
        self.assertEqual(plan["version"], "legacy")
        self.assertEqual(plan["changed_fields"], ["ANTHROPIC_BASE_URL"])
        self.assertTrue(plan["credential_rotation_requested"])
        self.assertEqual(before, {path.name: path.read_bytes() for path in
                                  (self.home / PROFILE.DIRECTORY).iterdir()})
        self.assertNotIn(self.secret.encode(), preview.stdout + preview.stderr)
        self.assertNotIn(hashlib.sha256(self.secret.encode()).hexdigest().encode(), preview.stdout)
        refused = subprocess.run([*cli, "update", "--name", "owned", "--expected-version", "legacy",
                                  "--base-url", new_url, "--secret-fd", "987654", "--apply"],
                                 capture_output=True, timeout=15)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(json.loads(refused.stdout)["reason"], "provider_secret_input_invalid")
        self.assertEqual(before, {path.name: path.read_bytes() for path in
                                  (self.home / PROFILE.DIRECTORY).iterdir()})
        with PROFILE.Store(self.home) as store:
            result = store.update("owned", {"ANTHROPIC_BASE_URL": new_url},
                                  {"ANTHROPIC_API_KEY": new_secret}, "legacy")
            self.assertTrue(result["selected"])
            self.assertTrue(result["credential_rotated"])
            self.assertRegex(result["version"], r"\A[0-9a-f]{32}\Z")
            self.assertRegex(result["previous_version"], r"\A[0-9a-f]{32}\Z")
            self.assertNotEqual(result["version"], result["previous_version"])
            inventory = store.inspect()
            self.assertIn(result["previous_version"], inventory["profiles"][0]["retained_versions"])
        self.assertEqual(old_values["ANTHROPIC_API_KEY"], self.secret,
                         "an already launched host keeps its copied configuration")
        self.assertEqual(old_values["ANTHROPIC_BASE_URL"], self.public["ANTHROPIC_BASE_URL"])
        with self.assertRaisesRegex(PROFILE.Refusal, "provider_selection_stale"):
            PROFILE.unchanged(self.home, selected, old_identity)
        new_values, _, new_name, new_identity = PROFILE.chosen(self.home, {})
        self.assertEqual(new_name, "owned")
        self.assertEqual(new_values["ANTHROPIC_API_KEY"], new_secret)
        self.assertEqual(new_values["ANTHROPIC_BASE_URL"], new_url)
        PROFILE.unchanged(self.home, new_name, new_identity)
        restore = subprocess.run([*cli, "restore", "--name", "owned", "--version",
                                  result["previous_version"], "--expected-version",
                                  result["version"], "--apply"], capture_output=True, timeout=15)
        self.assertEqual(restore.returncode, 0, restore.stderr)
        restored = json.loads(restore.stdout)
        self.assertNotIn(new_secret.encode(), restore.stdout + restore.stderr)
        self.assertEqual(restored["version"], result["previous_version"])
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)
        prune = subprocess.run([*cli, "prune", "--name", "owned", "--version",
                                result["version"], "--apply"], capture_output=True, timeout=15)
        self.assertEqual(prune.returncode, 0, prune.stderr)
        self.assertEqual(json.loads(prune.stdout)["removed_version"], result["version"])
        self.assertNotIn(new_secret.encode(), prune.stdout + prune.stderr)
        for public in (plan, result, inventory, restored):
            blob = json.dumps(public)
            self.assertNotIn(self.secret, blob)
            self.assertNotIn(new_secret, blob)
            self.assertNotIn(hashlib.sha256(new_secret.encode()).hexdigest(), blob)

    def test_interrupted_index_publication_keeps_legacy_selection_usable(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
            original = store._write
            def interrupted(filename, raw, **kwargs):
                if filename == PROFILE.INDEX_FILE:
                    raise OSError("simulated index publication interruption")
                return original(filename, raw, **kwargs)
            with patch.object(store, "_write", side_effect=interrupted):
                with self.assertRaises(OSError):
                    store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                 None, "legacy")
            self.assertIsNone(store.read(PROFILE.INDEX_FILE))
            self.assertIsNone(store.read(PROFILE.VERSIONED_FILE))
            self.assertEqual(store.selected()["name"], "owned")
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)
        with PROFILE.Store(self.home) as store:
            outcome = store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                   None, "legacy")
        self.assertEqual(outcome["selected"], True)
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)

    def test_missing_index_after_committed_update_restore_or_environment_refuses(self):
        for final_action in ("update", "restore", "environment"):
            with self.subTest(final_action=final_action), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary) / ".agentfw"
                home.mkdir(mode=0o700)
                with PROFILE.Store(home, create=True) as store:
                    store.create("owned", self.public, {"ANTHROPIC_API_KEY": self.secret})
                    store.select("owned")
                    first = store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                         {"ANTHROPIC_API_KEY": "SOU181-SYNTHETIC-NEW"}, "legacy")
                    if final_action == "restore":
                        store.restore("owned", first["previous_version"], first["version"])
                    elif final_action == "environment":
                        store.environment()
                with PROFILE.Store(home) as reopened:
                    self.assertIsNotNone(reopened.read(PROFILE.VERSIONED_FILE))
                    if final_action == "update":
                        self.assertEqual(PROFILE.chosen(home, {})[0]["ANTHROPIC_API_KEY"],
                                         "SOU181-SYNTHETIC-NEW")
                    elif final_action == "restore":
                        self.assertEqual(PROFILE.chosen(home, {})[0]["ANTHROPIC_API_KEY"], self.secret)
                    else:
                        self.assertIsNone(reopened.selected())
                (home / PROFILE.DIRECTORY / PROFILE.INDEX_FILE).unlink()
                with PROFILE.Store(home) as reopened:
                    with self.assertRaisesRegex(PROFILE.Refusal, "provider_index_invalid"):
                        reopened.selected()
                with self.assertRaisesRegex(PROFILE.Refusal, "provider_index_invalid"):
                    PROFILE.chosen(home, {})

    def test_versioned_index_without_marker_or_with_unsafe_marker_refuses(self):
        for alteration in ("missing", "content", "mode", "symlink", "hardlink"):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / ".agentfw"
                home.mkdir(mode=0o700)
                with PROFILE.Store(home, create=True) as store:
                    store.create("owned", self.public, {"ANTHROPIC_API_KEY": self.secret})
                    store.select("owned")
                    store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                 {"ANTHROPIC_API_KEY": "SOU181-SYNTHETIC-NEW"}, "legacy")
                marker = home / PROFILE.DIRECTORY / PROFILE.VERSIONED_FILE
                if alteration == "missing":
                    marker.unlink()
                elif alteration == "content":
                    marker.write_bytes(b'{"format":"wrong"}\n')
                elif alteration == "mode":
                    marker.chmod(0o644)
                elif alteration == "symlink":
                    foreign = root / "foreign"
                    foreign.write_bytes(marker.read_bytes())
                    marker.unlink()
                    marker.symlink_to(foreign)
                else:
                    os.link(marker, root / "hardlink")
                with self.assertRaises(PROFILE.Refusal):
                    PROFILE.chosen(home, {})

    def test_killed_writer_partial_version_is_not_adopted(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
        orphan_id = "0" * 32
        orphan = self.home / PROFILE.DIRECTORY / ("v-" + orphan_id)
        orphan.write_bytes(b'{"partial":')
        orphan.chmod(0o600)
        with PROFILE.Store(self.home) as store:
            self.assertEqual(store.inspect()["selected"], "owned")
            self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)
            updated = store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                   None, "legacy")
            self.assertNotIn(orphan_id, store.inspect()["profiles"][0]["retained_versions"])
            self.assertNotEqual(updated["version"], orphan_id)
        self.assertEqual(orphan.read_bytes(), b'{"partial":',
                         "an unpublished version remains private evidence, not a selected input")

    def test_unpublished_pre_and_post_freeze_temporaries_do_not_replace_selection(self):
        for mode in (0o600, 0o400):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary) / ".agentfw"
                home.mkdir(mode=0o700)
                with PROFILE.Store(home, create=True) as store:
                    store.create("owned", self.public, {"ANTHROPIC_API_KEY": self.secret})
                    store.select("owned")
                temporary_file = home / PROFILE.DIRECTORY / (".next-" + "a" * 32)
                temporary_file.write_bytes(b'{"interrupted":')
                temporary_file.chmod(mode)
                self.assertEqual(PROFILE.chosen(home, {})[0]["ANTHROPIC_API_KEY"], self.secret)
                with PROFILE.Store(home) as store:
                    self.assertEqual(store.inspect()["selected"], "owned")
                    result = store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                          None, "legacy")
                self.assertFalse(temporary_file.exists(), "only the owned unpublished temp is cleaned")
                self.assertEqual(PROFILE.chosen(home, {})[0]["ANTHROPIC_API_KEY"], self.secret)
                self.assertRegex(result["previous_version"], r"\A[0-9a-f]{32}\Z")

    def test_complete_unpublished_version_can_be_pruned_without_index(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
        orphan_id = "1" * 32
        orphan = self.home / PROFILE.DIRECTORY / ("v-" + orphan_id)
        orphan.write_bytes(PROFILE.encoded({"format": PROFILE.FORMAT, "name": "owned",
                                             "public": self.public,
                                             "secrets": {"ANTHROPIC_API_KEY": self.secret}}))
        orphan.chmod(0o400)
        with PROFILE.Store(self.home) as store:
            with self.assertRaises(PROFILE.Refusal):
                store.prune("other", orphan_id)
            self.assertTrue(orphan.is_file())
            pruned = store.prune("owned", orphan_id)
        self.assertEqual(pruned["removed_version"], orphan_id)
        self.assertFalse(orphan.exists())
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)

    def test_concurrent_expected_version_allows_only_one_update(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
        cli = [sys.executable, "-I", "-B", str(ROOT / "scripts/pilot.py"),
               "--agent-home", str(self.home), "provider", "update", "--name", "owned",
               "--expected-version", "legacy", "--apply"]
        first = subprocess.Popen([*cli, "--model", "claude-sonnet-4-20250515"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        second = subprocess.Popen([*cli, "--model", "claude-sonnet-4-20250516"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outcomes = []
        for process in (first, second):
            stdout, stderr = process.communicate(timeout=15)
            self.assertNotIn(self.secret.encode(), stdout + stderr)
            outcomes.append((process.returncode, json.loads(stdout)))
        self.assertEqual(sorted(code for code, _ in outcomes), [0, 2])
        self.assertEqual(next(row["reason"] for code, row in outcomes if code == 2),
                         "provider_version_stale", outcomes)
        self.assertIn(PROFILE.chosen(self.home, {})[1],
                      ("claude-sonnet-4-20250515", "claude-sonnet-4-20250516"))

    def test_invalid_update_endpoint_refuses_without_publication(self):
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
            before = {path.name: path.read_bytes() for path in
                      (self.home / PROFILE.DIRECTORY).iterdir()}
            with self.assertRaisesRegex(PROFILE.Refusal, "provider_transport_invalid"):
                store.preview_update("owned", {"ANTHROPIC_BASE_URL": "http://example.com/v1"}, True)
            with self.assertRaisesRegex(PROFILE.Refusal, "provider_transport_invalid"):
                store.update("owned", {"ANTHROPIC_BASE_URL": "http://example.com/v1"},
                             {"ANTHROPIC_API_KEY": "SOU181-UNUSED-SECRET"}, "legacy")
            self.assertEqual(before, {path.name: path.read_bytes() for path in
                                      (self.home / PROFILE.DIRECTORY).iterdir()})
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)

    def test_prune_only_named_retained_version_and_refuse_active_version(self):
        self.create()
        self.create("other", "SOU181-OTHER-SECRET")
        with PROFILE.Store(self.home) as store:
            store.select("owned")
            updated = store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                   None, "legacy")
            with self.assertRaises(PROFILE.Refusal):
                store.prune("owned", updated["version"])
            with self.assertRaises(PROFILE.Refusal):
                store.prune("other", updated["previous_version"])
            pruned = store.prune("owned", updated["previous_version"])
            self.assertEqual(pruned["removed_version"], updated["previous_version"])
            self.assertEqual([row["name"] for row in store.inspect()["profiles"]], ["other", "owned"])
            store.select("other")
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], "SOU181-OTHER-SECRET")

    def test_all_legacy_names_and_full_profile_capacity_survive_rotation(self):
        names = ["index", "versioned"] + ["owned" + str(i) for i in range(14)]
        with PROFILE.Store(self.home, create=True) as store:
            for item in names:
                store.create(item, self.public, {"ANTHROPIC_API_KEY": self.secret})
            store.select("index")
            store.update("index", {"model": "rotated-model"},
                         {"ANTHROPIC_API_KEY": "SYNTHETIC-ROTATED"}, "legacy")
        with PROFILE.Store(self.home) as reopened:
            self.assertEqual(reopened.names(), sorted(names))
            self.assertEqual(len(reopened.inspect()["profiles"]), 16)
            self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"],
                             "SYNTHETIC-ROTATED")
            reopened.select("versioned")
        self.assertEqual(PROFILE.chosen(self.home, {})[0]["ANTHROPIC_API_KEY"], self.secret)

    def test_old_draft_metadata_never_reactivates_retained_legacy_credentials(self):
        for old_layout in ("both", "index-only", "marker-only"):
            with self.subTest(old_layout=old_layout), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary) / ".agentfw"
                home.mkdir(mode=0o700)
                with PROFILE.Store(home, create=True) as store:
                    store.create("owned", self.public, {"ANTHROPIC_API_KEY": self.secret})
                    store.select("owned")
                    store.update("owned", {"model": "rotated-model"},
                                 {"ANTHROPIC_API_KEY": "SYNTHETIC-ROTATED"}, "legacy")
                    old_index = store.read(PROFILE.INDEX_FILE)
                    old_marker = store.read(PROFILE.VERSIONED_FILE)
                directory = home / PROFILE.DIRECTORY
                old_files = {"both": (("index.json", old_index), ("versioned.json", old_marker)),
                             "index-only": (("index.json", old_index),),
                             "marker-only": (("versioned.json", old_marker),)}
                for filename, raw in old_files[old_layout]:
                    descriptor = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(raw)
                (directory / PROFILE.INDEX_FILE).unlink()
                (directory / PROFILE.VERSIONED_FILE).unlink()
                with self.assertRaisesRegex(PROFILE.Refusal, "provider_index_invalid"):
                    PROFILE.chosen(home, {})

    def test_selected_version_rejects_wrong_mode_symlink_and_hardlink(self):
        for altered in ("mode", "symlink", "hardlink"):
            with self.subTest(altered=altered), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / ".agentfw"
                home.mkdir(mode=0o700)
                with PROFILE.Store(home, create=True) as store:
                    store.create("owned", self.public, {"ANTHROPIC_API_KEY": self.secret})
                    store.select("owned")
                    result = store.update("owned", {"model": "claude-sonnet-4-20250515"},
                                          None, "legacy")
                path = home / PROFILE.DIRECTORY / ("v-" + result["version"])
                if altered == "mode":
                    path.chmod(0o600)
                elif altered == "symlink":
                    foreign = root / "foreign"
                    foreign.write_bytes(path.read_bytes())
                    path.unlink()
                    path.symlink_to(foreign)
                else:
                    os.link(path, root / "hardlink")
                with self.assertRaises(PROFILE.Refusal):
                    PROFILE.chosen(home, {})

    def test_bad_selected_profile_refuses_runner_before_any_spawn(self):
        spec = importlib.util.spec_from_file_location("provider_run", ROOT / "scripts/pilot-run.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        self.create()
        with PROFILE.Store(self.home) as store:
            store.select("owned")
        (self.home / PROFILE.DIRECTORY / "owned.json").chmod(0o644)
        from types import SimpleNamespace
        args = SimpleNamespace(provider_home=self.home)
        with patch.object(runner.PREP, "supported_platform"), patch.object(runner.subprocess, "Popen") as spawned:
            with self.assertRaisesRegex(ValueError, "provider_private_file_required"):
                runner.run(args, {})
            spawned.assert_not_called()

    def test_export_and_exec_witness_reject_non_host_canary(self):
        spec = importlib.util.spec_from_file_location("installed_profile_qualifier",
                                                   ROOT / "scripts/qualify-installed-front-door.py")
        qualifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualifier)
        self.assertGreaterEqual(qualifier.QUAL.PROVIDER_TRACE_STRING_BYTES, 131072)
        canary, endpoint = self.secret, self.public["ANTHROPIC_BASE_URL"]
        claude = Path("/owned/claude")
        def row(pid, image, argv, environment):
            return (f'{pid} execve({json.dumps(image)}, {json.dumps(argv)}, '
                    + json.dumps([key + "=" + value for key, value in environment.items()]) + ') = 0')
        trace = self.root / "trace.private"
        rows = [row(10, "/usr/bin/python3", ["python3", "pilot.py"], {}),
                row(11, "/owned/agentfw", ["agentfw", "serve"], {}),
                row(12, "/owned/agentfw", ["agentfw", "pilot-launch"], {}),
                row(13, "/owned/agentfw", ["agentfw", "mcp"], {}),
                row(14, "/mcp-runtime/git", ["git"], {}),
                row(15, str(claude), [str(claude), "--restricted", "-p", "owned"],
                    {"ANTHROPIC_API_KEY": canary, "ANTHROPIC_BASE_URL": endpoint})]
        rows[0] = row(10, "/usr/bin/python3", ["python3", "pilot.py"], {"LONG": "x" * 5000})
        trace.write_text("\n".join(rows) + "\n")
        good = qualifier.provider_exec_witness(trace, claude, canary, endpoint)
        self.assertEqual(good["selected_host_execs"], 1)
        self.assertFalse(good["canary_in_other_children"])
        rows[2] = row(12, "/owned/agentfw", ["agentfw", "pilot-launch"],
                      {"ANTHROPIC_API_KEY": canary})
        trace.write_text("\n".join(rows) + "\n")
        with self.assertRaisesRegex(ValueError, "provider_value_in_unrelated_child"):
            qualifier.provider_exec_witness(trace, claude, canary, endpoint)

    def test_execveat_witness_checks_success_failure_and_interleaved_rows(self):
        spec = importlib.util.spec_from_file_location("installed_profile_qualifier_execveat",
                                                   ROOT / "scripts/qualify-installed-front-door.py")
        qualifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualifier)
        canary, endpoint = self.secret, self.public["ANTHROPIC_BASE_URL"]
        claude = Path("/owned/claude")
        def execve(pid, image, argv, environment):
            return (f'{pid} execve({json.dumps(image)}, {json.dumps(argv)}, '
                    + json.dumps(environment) + ') = 0')
        others = [execve(pid, image, [image], []) for pid, image in enumerate(
            ("/usr/bin/python3", "/owned/agentfw", "/mcp-runtime/git", "/usr/bin/strace"), 10)]
        host_env = ["ANTHROPIC_API_KEY=" + canary, "ANTHROPIC_BASE_URL=" + endpoint]
        host = execve(15, str(claude), [str(claude), "--restricted", "-p"], host_env)
        trace = self.root / "execveat.trace.private"
        def witness(*extra, selected=host):
            trace.write_text("\n".join([*others, selected, *extra]) + "\n")
            return qualifier.provider_exec_witness(trace, claude, canary, endpoint)

        self.assertEqual(witness()["other_execs_checked"], 4)
        absolute = '20 execveat(AT_FDCWD, "/usr/bin/true", ["true"], [], 0) = 0'
        self.assertEqual(witness(absolute)["other_execs_checked"], 5)
        self.assertEqual(witness(execve(20, "relative-helper", ["relative-helper"], []))
                         ["other_execs_checked"], 5)
        host_at = (f'15 execveat(AT_FDCWD, {json.dumps(str(claude))}, '
                   f'{json.dumps([str(claude), "--restricted", "-p"])}, '
                   f'{json.dumps(host_env)}, 0) = 0')
        self.assertEqual(witness(selected=host_at)["selected_host_execs"], 1)
        duplicate = ["ANTHROPIC_API_KEY=wrong", *host_env]
        duplicate_host = (f'15 execveat(AT_FDCWD, {json.dumps(str(claude))}, '
                          f'{json.dumps([str(claude), "--restricted", "-p"])}, '
                          f'{json.dumps(duplicate)}, 0) = 0')
        with self.assertRaisesRegex(ValueError, "provider_host_values_ambiguous"):
            witness(selected=duplicate_host)
        duplicate_url = ["ANTHROPIC_BASE_URL=http://127.0.0.1:1", *host_env]
        with self.assertRaisesRegex(ValueError, "provider_host_values_ambiguous"):
            witness(selected=execve(15, str(claude),
                    [str(claude), "--restricted", "-p"], duplicate_url))
        failed = '21 execveat(AT_FDCWD, "/missing", ["missing"], [], 0) = -1 ENOENT (No such file or directory)'
        self.assertEqual(witness(failed)["other_execs_checked"], 4)
        foreign = (f'22 execveat(AT_FDCWD, "/usr/bin/other", ["other"], '
                   f'{json.dumps(["ANTHROPIC_API_KEY=" + canary])}, 0) = 0')
        with self.assertRaisesRegex(ValueError, "provider_value_in_unrelated_child"):
            witness(foreign)
        foreign_url = (f'22 execveat(AT_FDCWD, "/usr/bin/other", ["other"], '
                       f'{json.dumps(["ANTHROPIC_BASE_URL=" + endpoint])}, 0) = 0')
        with self.assertRaisesRegex(ValueError, "provider_value_in_unrelated_child"):
            witness(foreign_url)
        with self.assertRaisesRegex(ValueError, "provider_exec_identity_incomplete:empty"):
            witness('23 execveat(7, "", ["helper"], [], AT_EMPTY_PATH) = 0')
        with self.assertRaisesRegex(ValueError, "provider_exec_identity_incomplete:empty"):
            witness(f'23 execveat(7, "", ["helper"], '
                    f'{json.dumps(["ANTHROPIC_API_KEY=" + canary])}, AT_EMPTY_PATH) = 0')
        with self.assertRaisesRegex(ValueError, "provider_exec_parse_incomplete"):
            witness('24 execveat(AT_FDCWD, "/usr/bin/true", ["true"], [...], 0) = 0')
        with self.assertRaisesRegex(ValueError, "provider_exec_parse_incomplete"):
            witness('24 execve("/usr/bin/true", ["true"], [...]) = 0')
        resumed = ('25 execveat(AT_FDCWD, "/usr/bin/true", ["true"], <unfinished ...>',
                   '25 <... execveat resumed> [], 0) = 0')
        self.assertEqual(witness(resumed[0], absolute, resumed[1])["other_execs_checked"], 6)
        with self.assertRaisesRegex(ValueError, "provider_trace_resume_mismatch"):
            witness(resumed[0], '25 <... execve resumed> [], 0) = 0')
        with self.assertRaisesRegex(ValueError, "provider_trace_incomplete"):
            witness(resumed[0])


if __name__ == "__main__":
    unittest.main()
