import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def load():
    spec = importlib.util.spec_from_file_location("update_under_test", ROOT / "scripts/pilot_update.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(sys.platform == "linux", "Linux descriptor and lease controls")
class JournalControls(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.root = self.parent / "coordinator"
        self.root.mkdir(mode=0o700)
        self.a = {"generation": "a" * 32, "inventory_sha256": "a" * 64}
        self.b = {"generation": "b" * 32, "inventory_sha256": "b" * 64}

    def state(self, current, previous=None):
        return {"format": "sw-pilot-update-state/1", "current": current, "previous": previous}

    def write(self, name, value):
        with self.m.Directory(self.root) as directory:
            directory.write(name, value)

    def read(self, name):
        with self.m.Directory(self.root) as directory:
            return directory.read(name)

    def test_preview_absent_root_has_no_effect(self):
        missing = self.parent / "absent"
        self.assertEqual(self.m.state(missing), self.state(None))
        self.assertFalse(missing.exists())

    def test_publication_is_atomic_and_old_state_is_retained(self):
        old, new = self.state(self.a), self.state(self.b, self.a)
        self.write("current.json", old)
        with self.m.Directory(self.root) as directory:
            self.m.publish(directory, old, new, "c" * 64)
        self.assertEqual(self.read("current.json"), new)
        self.assertEqual(self.read("journal.json")["phase"], "complete")
        self.assertEqual(self.read("journal.json")["before"], old)

    def test_failure_before_selection_preserves_current_and_journal(self):
        old, new = self.state(self.a), self.state(self.b, self.a)
        self.write("current.json", old)
        actual = self.m.Directory.write
        def interrupted(directory, name, value):
            if name == "current.json":
                raise OSError(28, "No space left")
            return actual(directory, name, value)
        with self.m.Directory(self.root) as directory, patch.object(self.m.Directory, "write", interrupted):
            with self.assertRaises(OSError):
                self.m.publish(directory, old, new, "c" * 64)
        self.assertEqual(self.read("current.json"), old)
        self.assertEqual(self.m.recovery_plan(self.root)["outcome"], "before_selection")

    def test_failure_after_selection_is_observed_without_replay(self):
        old, new = self.state(self.a), self.state(self.b, self.a)
        self.write("current.json", old)
        actual = self.m.Directory.write
        def interrupted(directory, name, value):
            if name == "journal.json" and value["phase"] == "complete":
                raise PermissionError("lost write permission")
            return actual(directory, name, value)
        with self.m.Directory(self.root) as directory, patch.object(self.m.Directory, "write", interrupted):
            with self.assertRaises(PermissionError):
                self.m.publish(directory, old, new, "c" * 64)
        self.assertEqual(self.read("current.json"), new)
        self.assertEqual(self.m.recovery_plan(self.root)["outcome"], "after_selection")

    def test_operator_edit_is_never_recovered_over(self):
        old, new = self.state(self.a), self.state(self.b, self.a)
        self.write("current.json", self.state(None))
        self.write("journal.json", {"format": self.m.JOURNAL, "phase": "selecting", "before": old,
                                    "after": new, "plan_sha256": "c" * 64})
        self.assertEqual(self.m.recovery_plan(self.root)["outcome"], "conflicting_state")
        self.assertEqual(self.read("current.json"), self.state(None))

    def test_replacement_and_linked_parents_are_refused(self):
        with self.m.Directory(self.root) as directory:
            self.root.rename(self.parent / "displaced")
            self.root.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "directory_replaced"):
                directory.write("current.json", self.state(self.a))
        self.assertEqual(list(self.root.iterdir()), [])
        linked = self.parent / "linked"
        linked.symlink_to(self.root)
        with self.assertRaises((OSError, ValueError)):
            self.m.Directory(linked)

    def test_record_symlink_hardlink_and_duplicate_fields_are_refused(self):
        sentinel = self.parent / "sentinel"
        sentinel.write_text("keep")
        target = self.root / "current.json"
        target.symlink_to(sentinel)
        with self.assertRaises((OSError, ValueError)):
            self.read("current.json")
        target.unlink()
        os.link(sentinel, target)
        with self.assertRaises(ValueError):
            self.read("current.json")
        target.unlink()
        target.write_bytes(b'{"current":null,"current":42}')
        target.chmod(0o600)
        with self.assertRaises(ValueError):
            self.read("current.json")
        self.assertEqual(sentinel.read_text(), "keep")

    def test_shared_run_lease_blocks_update_before_publication(self):
        self.write("current.json", self.state(self.a))
        with self.m.Directory(self.root) as first, self.m.Directory(self.root) as second:
            with first.lock(exclusive=False):
                with self.assertRaisesRegex(ValueError, "active_or_concurrent_operation"):
                    with second.lock(exclusive=True):
                        self.fail("exclusive lease admitted")
        self.assertEqual(self.read("current.json"), self.state(self.a))

    def test_repeated_recovery_does_not_republish_or_create_authority(self):
        old, new = self.state(self.a), self.state(self.b, self.a)
        self.write("current.json", old)
        self.write("journal.json", {"format": self.m.JOURNAL, "phase": "selecting", "before": old,
                                    "after": new, "plan_sha256": "c" * 64})
        report = self.m.recovery_plan(self.root)
        with patch.object(self.m, "verify_binding", return_value={"verified": True}):
            result = self.m.recover(self.root, report["plan_sha256"])
            again = self.m.recovery_plan(self.root)
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(again["outcome"], "nothing_pending")
        self.assertEqual(self.read("current.json"), old)
        self.assertNotIn("token", json.dumps(self.read("journal.json")))


class InventoryControls(unittest.TestCase):
    def test_unknown_inventory_fields_and_nonfinite_json_are_refused(self):
        m = load()
        for raw in (b'{"x":NaN}', b'{"x":1,"x":2}'):
            with self.assertRaises(ValueError):
                m.decode(raw)

    def test_same_version_does_not_replace_exact_source_binding(self):
        m = load()
        source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
        selection = {"source": source}
        helper = {"commit": "d" * 40, "tree": "b" * 40}
        with self.assertRaisesRegex(ValueError, "mixed_source"):
            m.compatible(source, helper, selection)
        helper["commit"] = source["commit"]
        m.compatible(source, helper, selection)
        selection["source"] = {**source, "files_sha256": "d" * 64}
        with self.assertRaisesRegex(ValueError, "mixed_source"):
            m.compatible(source, helper, selection)


@unittest.skipUnless(sys.platform == "linux", "Linux input and installed-generation controls")
class CandidateControls(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "updates"
        self.prefix = self.base / "prepared"
        self.source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
        self.prepared = self.prefix / "preparation" / "generations" / ("1" * 32)
        self.prepared.mkdir(mode=0o700, parents=True)
        for directory in (self.prefix, self.prefix / "preparation", self.prepared.parent):
            directory.chmod(0o700)
        self.runtime = {}
        for name in ("agentfw", "git_launcher", "sandbox_tests", "python", "git", "claude", "bwrap", "node", "npm"):
            path = self.base / name
            path.write_bytes(b"owned fixture binary " + name.encode())
            path.chmod(0o700)
            self.runtime[name] = self.record(path)
        self.selection = {"source": self.source, "files": {name: {key: record[key] for key in ("path", "sha256")}
                                                          for name, record in self.runtime.items()}}
        path = self.prepared / "selection.json"
        path.write_bytes(self.m.canonical(self.selection))
        path.chmod(0o600)
        self.selection_record = self.record(path)
        with self.m.Directory(self.prefix / "preparation") as directory:
            directory.write("current.json", {"format": "sw-pilot-preparation/1", "generation": self.prepared.name,
                            "selection_sha256": self.selection_record["sha256"], "status": "prepared-not-active"})
        state = {"format": "sw-pilot-front-door/1", "selection": str(path),
                 "selection_sha256": self.selection_record["sha256"], "commit": self.source["commit"],
                 "tree": self.source["tree"]}
        door = self.prefix / "front-door.json"
        door.write_bytes(self.m.canonical(state))
        door.chmod(0o600)
        spec = importlib.util.spec_from_file_location("fixture_component_builder", ROOT / "scripts/build-pilot-front-door.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        files = {"scripts/pilot.py": b"fixture entry", "scripts/prepare-installed-pilot.py": b"fixture preparation",
                 "scripts/pilot-run.py": b"fixture runner"}
        raw, manifest = builder.assemble(files, self.source)
        archive = self.base / "component.tar"
        archive.write_bytes(raw)
        archive.chmod(0o600)
        self.component_id = hashlib.sha256(manifest).hexdigest()
        self.value = {"format": "sw-pilot-update-inventory/1", "source": self.source, "version": "fixture-a",
                      "prefix": str(self.prefix), "runtime": self.runtime, "selection": self.selection_record,
                      "front_door": self.record(door), "component": self.record(archive),
                      "interpreter": self.runtime["python"]}

    def record(self, path):
        return self.m.read_file(path, self.m.MAX_BINARY)[0]

    def installed(self, binding=None):
        self.root.mkdir(mode=0o700, exist_ok=True)
        binding = binding or {"generation": "a" * 32, "inventory_sha256": self.m.digest(self.value)}
        destination = self.m.generation_dir(self.root, binding)
        destination.mkdir(mode=0o700)
        with self.m.Directory(destination) as directory:
            directory.write("inventory.json", self.value)
            directory.write("owner.json", {"format": self.m.FORMAT, "generation": binding["generation"],
                            "device": directory.identity[0], "inode": directory.identity[1]})
        home = destination / "agent-home" / ".agentfw"
        versions = home / "versions"
        versions.mkdir(mode=0o700, parents=True)
        home.chmod(0o700)
        home.parent.chmod(0o700)
        binary = versions / ("agentfw-" + self.value["version"])
        binary.write_bytes(Path(self.runtime["agentfw"]["path"]).read_bytes())
        binary.chmod(0o700)
        with self.m.Directory(versions) as directory:
            active = {"version": self.value["version"], "binary": binary.name, "digest": self.runtime["agentfw"]["sha256"]}
            directory.write("lifecycle.json", {"active": active, "owned": [active], "previous": None,
                            "process": None, "operation": None, "pending_stage": None})
        (versions / ".lock").touch(mode=0o600)
        component_root = home / "pilot-front-door"
        installed = component_root / "components" / self.component_id
        installed.mkdir(mode=0o700, parents=True)
        component_root.chmod(0o700)
        (component_root / "components").chmod(0o700)
        with tarfile.open(self.value["component"]["path"]) as archive:
            for member in archive.getmembers():
                path = installed / (member.name if member.name == "manifest.json" else "tree/" + member.name)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
                path.chmod(0o400)
        for path in installed.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        with self.m.Directory(component_root) as directory:
            directory.write("current.json", {"schema": "sw-pilot-front-door-current/1", "component": self.component_id,
                            "python": {"path": self.value["interpreter"]["path"],
                                       "sha256": self.value["interpreter"]["sha256"], "version": "3.12.0"}})
        return binding, home

    def test_valid_preview_has_no_writes_or_children_and_binds_exact_bytes(self):
        before = sorted(str(p) for p in self.base.rglob("*"))
        with patch.object(self.m.subprocess, "run", side_effect=AssertionError("preview started a child")):
            result = self.m.plan(self.root, self.value)
        self.assertEqual(result["target"]["component"], self.component_id)
        self.assertEqual(result["target"]["source"]["commit"], "a" * 40)
        self.assertEqual(result["protection"], "not_observed")
        self.assertEqual(before, sorted(str(p) for p in self.base.rglob("*")))

    def test_changed_confirmation_refuses_before_coordinator_creation(self):
        report = self.m.plan(self.root, self.value)
        altered = copy.deepcopy(self.value)
        altered["version"] = "fixture-b"
        with self.assertRaisesRegex(ValueError, "plan_confirmation_changed"):
            self.m.apply(self.root, altered, report["plan_sha256"])
        self.assertFalse(self.root.exists())

    def test_parent_replacement_after_preview_refuses_before_creating_root(self):
        parent = self.base / "coordinator-parent"
        parent.mkdir(mode=0o700)
        self.root = parent / "updates"
        report = self.m.plan(self.root, self.value)
        parent.rename(self.base / "original-parent")
        parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "plan_confirmation_changed"):
            self.m.apply(self.root, self.value, report["plan_sha256"])
        self.assertFalse(self.root.exists())

    def test_missing_runtime_or_extra_inventory_fields_are_refused(self):
        for value in ({**self.value, "automatic_download": True},
                      {**self.value, "runtime": {key: item for key, item in self.runtime.items() if key != "git_launcher"}}):
            with self.assertRaises(ValueError):
                self.m.plan(self.root, value)
        self.assertFalse(self.root.exists())

    def test_interpreter_binary_and_mode_changes_invalidate_plan(self):
        report = self.m.plan(self.root, self.value)
        for name in ("python", "agentfw", "git_launcher"):
            path = Path(self.runtime[name]["path"])
            old = path.read_bytes()
            path.write_bytes(old + b"changed")
            with self.assertRaisesRegex(ValueError, "input_identity_changed"):
                self.m.plan(self.root, self.value)
            path.write_bytes(old)
        path.chmod(0o500)
        with self.assertRaisesRegex(ValueError, "input_identity_changed"):
            self.m.plan(self.root, self.value)
        self.assertFalse(self.root.exists())
        self.assertTrue(report["plan_sha256"])

    def test_component_source_cannot_be_relabeled(self):
        altered = copy.deepcopy(self.value)
        altered["source"]["files_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "component_source_mismatch"):
            self.m.plan(self.root, altered)

    def test_installed_generation_revalidates_helper_and_managed_binary(self):
        binding, home = self.installed()
        verified = self.m.verify_binding(self.root, binding)
        self.assertEqual(verified["component"], self.component_id)
        helper = home / "pilot-front-door/components" / self.component_id / "tree/scripts/pilot.py"
        helper.chmod(0o600)
        helper.write_bytes(b"altered helper")
        helper.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "installed_helper_changed"):
            self.m.verify_binding(self.root, binding)

    def test_unlisted_helper_cannot_be_accepted_during_recovery(self):
        binding, home = self.installed()
        foreign = home / "pilot-front-door/components" / self.component_id / "tree/scripts/typing.py"
        foreign.write_text("unlisted module")
        foreign.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "unlisted_component_entry"):
            self.m.verify_binding(self.root, binding)

    def test_cleanup_retains_current_and_previous_without_effects(self):
        binding, _ = self.installed()
        with self.m.Directory(self.root) as directory:
            directory.write("current.json", {"format": self.m.STATE, "current": binding, "previous": None})
        with self.assertRaisesRegex(ValueError, "generation_still_retained"):
            self.m.cleanup_plan(self.root, binding)

    def test_selected_command_rejects_prefix_override_before_child_start(self):
        binding, _ = self.installed()
        with self.m.Directory(self.root) as directory:
            directory.write("current.json", {"format": self.m.STATE, "current": binding, "previous": None})
        with patch.object(self.m.subprocess, "run", side_effect=AssertionError("child started")):
            with self.assertRaisesRegex(ValueError, "prefix_override"):
                self.m.selected_command(self.root, ["run", "--prefix=/tmp/foreign"])

    def test_dispatch_timeout_does_not_claim_that_execution_was_blocked(self):
        binding, _ = self.installed()
        with self.m.Directory(self.root) as directory:
            directory.write("current.json", {"format": self.m.STATE, "current": binding, "previous": None})
        with patch.object(self.m.subprocess, "run", side_effect=subprocess.TimeoutExpired("owned child", 3700)):
            with self.assertRaises(self.m.DispatchInterrupted) as caught:
                self.m.selected_command(self.root, ["run"])
        self.assertTrue(caught.exception.dispatch_started)

    def test_existing_preparation_lease_refuses_without_mutating_selection(self):
        lock = self.m.load_helper("fixture_lock", ROOT, "pilot-selection-lock.py")
        before = (self.prefix / "preparation/current.json").read_bytes()
        with lock.hold(self.prefix / "preparation", exclusive=False):
            with self.assertRaisesRegex(ValueError, "selected_generation_in_use"):
                with self.m.selection_leases([self.value]):
                    self.fail("active preparation admitted")
        self.assertEqual((self.prefix / "preparation/current.json").read_bytes(), before)

    def test_provider_secrets_are_not_in_control_command_environment(self):
        env = self.m.environment(self.base)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("PATH", env)

    def test_cleanup_refuses_unrelated_empty_directory_and_sentinel(self):
        binding, home = self.installed()
        self.m.cleanup_plan(self.root, binding)
        sentinel = home / "pilot-front-door/unrelated"
        sentinel.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "unrelated_generation_state_preserved"):
            self.m.cleanup_plan(self.root, binding)
        sentinel.rmdir()
        sentinel.write_text("keep")
        with self.assertRaisesRegex(ValueError, "unrelated_generation_state_preserved"):
            self.m.cleanup_plan(self.root, binding)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_cleanup_cannot_follow_forged_lifecycle_owned_entries(self):
        binding, home = self.installed()
        with self.m.Directory(home / "versions") as directory:
            receipt = directory.read("lifecycle.json")
            receipt["owned"].append({"version": "foreign", "binary": "agentfw-foreign", "digest": "f" * 64})
            directory.write("lifecycle.json", receipt)
        with self.assertRaisesRegex(ValueError, "managed_binary_binding_changed"):
            self.m.cleanup_plan(self.root, binding)

    def test_inventory_builder_requires_independent_archive_digest(self):
        value = self.m.make_inventory(self.prefix, Path(self.value["component"]["path"]),
                                      self.value["component"]["sha256"], "a" * 40, "fixture-a")
        self.assertEqual(value, self.value)
        with self.assertRaisesRegex(ValueError, "reviewed_component_digest_required"):
            self.m.make_inventory(self.prefix, Path(self.value["component"]["path"]),
                                  "0" * 64, "a" * 40, "fixture-a")

    def test_control_command_output_is_bounded_and_child_failure_is_not_success(self):
        executable = str(Path(sys.executable).resolve())
        with self.assertRaisesRegex(ValueError, "component_command_output_limit"):
            self.m.command([executable, "-I", "-B", "-c", "print('x'*100000)"], self.base)
        with self.assertRaisesRegex(ValueError, "accepted_component_operation_failed"):
            self.m.command([executable, "-I", "-B", "-c", "raise SystemExit(7)"], self.base)
        self.assertEqual(self.m.command([executable, "-I", "-B", "-c", "print('verified')"], self.base), b"verified\n")

    def test_lifecycle_home_matches_the_explicit_component_home(self):
        managed_home = self.base / "operator" / ".agentfw"
        managed_home.mkdir(mode=0o700, parents=True)
        raw = self.m.command([str(Path(sys.executable).resolve()), "-I", "-B", "-c",
                              'from pathlib import Path;print(Path.home()/".agentfw")'], managed_home)
        self.assertEqual(raw.decode().strip(), str(managed_home))

    def test_coordinator_switch_and_rollback_with_installer_fixture(self):
        m = self.m
        actual_load = m.load_helper
        class Guard:
            def __init__(self, *args):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def recheck(self, phase):
                pass
        capacity = SimpleNamespace(Guard=Guard, Demand=lambda *args: args, Refusal=RuntimeError)
        def selected_load(name, root, filename):
            return capacity if filename == "pilot_capacity.py" else actual_load(name, root, filename)
        def fixture_stage(root, binding, value, directory, guard):
            original = self.value
            try:
                self.value = value
                self.installed(binding)
            finally:
                self.value = original
        with patch.object(m, "load_helper", selected_load), patch.object(m, "stage", fixture_stage), \
                patch.object(m, "accepted_validation", return_value=None):
            a = m.plan(self.root, self.value)
            m.apply(self.root, self.value, a["plan_sha256"])
            first = m.state(self.root)["current"]
            b = {**self.value, "version": "fixture-b"}
            reviewed = m.plan(self.root, b)
            m.apply(self.root, b, reviewed["plan_sha256"])
            selected = m.state(self.root)
            self.assertNotEqual(selected["current"], first)
            self.assertEqual(selected["previous"], first)
            self.assertEqual(selected["current"]["inventory_sha256"], m.digest(b))
            with self.assertRaisesRegex(ValueError, "plan_confirmation_changed"):
                m.apply(self.root, b, reviewed["plan_sha256"])
            back = m.rollback_plan(self.root)
            result = m.rollback(self.root, back["plan_sha256"])
            self.assertEqual(m.state(self.root)["current"], first)
            self.assertEqual(result["authority"], "fresh_run_required")
        self.assertEqual(m.state(self.root)["previous"], selected["current"])

    def test_malformed_journal_is_refused_without_traceback_or_effects(self):
        self.root.mkdir(mode=0o700)
        with self.m.Directory(self.root) as directory:
            for value in ([], 7, {"phase": "complete"}):
                directory.write("journal.json", value)
                with self.assertRaisesRegex(ValueError, "invalid_update_journal"):
                    self.m.recovery_plan(self.root)
                self.assertIsNone(directory.read("current.json"))


@unittest.skipUnless(sys.platform == "linux", "Linux fixture file modes")
class QualificationFixtureControls(unittest.TestCase):
    def test_read_only_qualification_prints_both_source_identities(self):
        spec = importlib.util.spec_from_file_location("update_qualification_test", ROOT / "scripts/qualify-pilot-update.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            sources = [{"commit": letter * 40} for letter in ("a", "b")]
            paths = []
            for index, source in enumerate(sources):
                path = parent / (str(index) + ".json")
                path.write_text(json.dumps({"source": source}))
                path.chmod(0o600)
                paths.append(path)
            args = ["qualification", "--entry-agent", "/owned/agentfw", "--entry-home", "/owned/bootstrap",
                    "--inventory-a", str(paths[0]), "--inventory-b", str(paths[1]),
                    "--fixture-root", str(parent), "--output", str(parent / "new-output"),
                    "--expected-commit", "c" * 40, "--expected-text", "Owned text"]
            output = io.StringIO()
            with patch.object(sys, "argv", args), patch.object(module.UPDATE, "inventory"), \
                    patch.object(module.QUAL.BASE, "source", return_value={"dirty": False, "commit": "c" * 40}), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(module.main(), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["accepted_sources"], sources)
            self.assertIs(report["writes"], False)
            self.assertFalse((parent / "new-output").exists())

    def test_fixture_uses_accepted_cli_and_explicit_offline_inputs(self):
        spec = importlib.util.spec_from_file_location("update_fixture_test", ROOT / "scripts/prepare-pilot-update-fixture.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            build = parent / "build.json"
            build.write_text(json.dumps({role: "/owned/" + role for role in
                                        ("agentfw", "git_launcher", "sandbox_tests")}))
            args = SimpleNamespace(source_a=ROOT, build_a=build, build_b=build,
                                   output=parent / "fixtures", git=Path("/usr/bin/git"))
            for role in ("node_archive", "bwrap", "claude", "python_archive", "npm_cache", "wheelhouse"):
                setattr(args, role, Path("/owned") / role)
            spec = importlib.util.spec_from_file_location("update_fixture_front_door", ROOT / "scripts/pilot.py")
            front = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(front)
            commands = []
            def call(words, source, env):
                words = [str(word) for word in words]
                commands.append(words)
                if words[2].endswith("build-pilot-front-door.py"):
                    return {"commit": "a" * 40, "archive_sha256": "b" * 64}
                if words[2].endswith("pilot.py"):
                    parsed = front.parser().parse_args(words[3:])
                    self.assertFalse(parsed.allow_download)
                    for role in ("python_archive", "npm_cache", "wheelhouse", "agentfw", "sandbox_tests"):
                        self.assertTrue(getattr(parsed, role).is_absolute())
                    return {"status": "prepared-not-active"}
                return {"ok": True}
            with patch.object(module, "call", call), \
                    patch.object(module.subprocess, "check_output", return_value="a" * 40), \
                    patch.object(module.UPDATE, "make_inventory", return_value={"fixture": True}):
                module.prepare(args)
            self.assertEqual(sum(words[2].endswith("pilot.py") for words in commands), 2)
            result = json.loads((args.output / "inputs.json").read_text())
            self.assertEqual(result["status"], "prepared-not-qualified")
            self.assertEqual(result["entry_agent"], "/owned/agentfw")


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("SOU164_TEST_AGENT"),
                     "requires an explicitly supplied local Agent for real installer interoperability")
class RealInstallerControls(unittest.TestCase):
    def test_real_lifecycle_component_and_rejected_invalid_preparation_do_not_select_partial_set(self):
        fixture = CandidateControls("test_valid_preview_has_no_writes_or_children_and_binds_exact_bytes")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        m = fixture.m
        agent = Path(fixture.runtime["agentfw"]["path"])
        shutil.copyfile(os.environ["SOU164_TEST_AGENT"], agent)
        agent.chmod(0o700)
        fixture.runtime["agentfw"] = fixture.record(agent)
        fixture.runtime["python"] = fixture.record(Path(sys.executable).resolve())
        fixture.value["interpreter"] = fixture.runtime["python"]
        fixture.selection["files"] = {name: {key: item[key] for key in ("path", "sha256")}
                                       for name, item in fixture.runtime.items()}
        selection = Path(fixture.selection_record["path"])
        selection.write_bytes(m.canonical(fixture.selection))
        fixture.value["selection"] = fixture.record(selection)
        with m.Directory(fixture.prefix) as directory:
            door = directory.read("front-door.json")
            door["selection_sha256"] = fixture.value["selection"]["sha256"]
            directory.write("front-door.json", door)
        fixture.value["front_door"] = fixture.record(fixture.prefix / "front-door.json")
        with m.Directory(fixture.prefix / "preparation") as directory:
            marker = directory.read("current.json")
            marker["selection_sha256"] = fixture.value["selection"]["sha256"]
            directory.write("current.json", marker)
        m.inventory(fixture.value)
        fixture.root.mkdir(mode=0o700)
        binding = {"generation": "d" * 32, "inventory_sha256": m.digest(fixture.value)}
        guard = SimpleNamespace(bind=lambda *args: None, recheck=lambda *args: None)
        with m.Directory(fixture.root) as directory:
            m.stage(fixture.root, binding, fixture.value, directory, guard)
        verified = m.verify_binding(fixture.root, binding)
        self.assertEqual(verified["binary"].name, "agentfw-fixture-a")
        with self.assertRaisesRegex(ValueError, "accepted_component_operation_failed"):
            m.accepted_validation(verified)
        self.assertIsNone(m.state(fixture.root)["current"])


if __name__ == "__main__":
    unittest.main()
