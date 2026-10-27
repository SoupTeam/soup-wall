import importlib.util
from contextlib import ExitStack, contextmanager, redirect_stdout
import io
import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_capacity as capacity


class CapacityTotals(unittest.TestCase):
    def observation(self, device="1", available=1000, quota="disabled"):
        return {"filesystem_id": device, "available_bytes": available,
                "available_inodes": 100, "quota": quota, "filesystem_type": "ext4",
                "read_only": False}

    def test_shared_filesystem_has_one_available_balance_and_one_reserve(self):
        demands = [capacity.Demand("build", Path("/owned/build"), 400),
                   capacity.Demand("cache", Path("/owned/cache"), 400)]
        result = capacity.summarize(demands, [self.observation(), self.observation()], 250)
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(len(result["filesystems"]), 1)
        self.assertEqual(result["filesystems"][0]["required_bytes"], 1050)
        self.assertEqual(result["filesystems"][0]["available_bytes"], 1000)

    def test_different_filesystems_cannot_borrow_available_bytes(self):
        demands = [capacity.Demand("build", Path("/build"), 400),
                   capacity.Demand("cache", Path("/cache"), 400)]
        result = capacity.summarize(demands, [self.observation("1", 9000), self.observation("2", 100)], 0)
        self.assertEqual(result["status"], "insufficient")

    def test_unknown_quota_or_allowance_cannot_admit_preparation(self):
        for amount, quota in [(None, "disabled"), (100, "unknown"), (100, "enabled")]:
            with self.subTest(amount=amount, quota=quota):
                result = capacity.summarize([capacity.Demand("build", Path("/build"), amount)],
                                            [self.observation(quota=quota)], 0)
                self.assertEqual(result["status"], "unknown")
                self.assertFalse(result["admitted"])

    def test_sufficient_means_only_the_declared_budget_at_observation_time(self):
        result = capacity.summarize([capacity.Demand("build", Path("/build"), 900)],
                                    [self.observation()], 100)
        self.assertEqual(result["status"], "sufficient")
        self.assertTrue(result["admitted"])
        self.assertFalse(result["space_reserved"])

    def test_conflicting_shared_observations_use_the_lower_free_balance(self):
        demands = [capacity.Demand("build", Path("/build"), 400),
                   capacity.Demand("cache", Path("/cache"), 400)]
        result = capacity.summarize(demands, [self.observation(available=1000),
                                             self.observation(available=700)], 0)
        self.assertEqual(result["status"], "insufficient")

    def test_missing_capacity_and_read_only_or_inode_exhaustion_do_not_admit(self):
        for changes in ({"available_bytes": None}, {"read_only": True},
                        {"available_inodes": 0}, {"available_inodes": None}):
            observation = {**self.observation(), **changes}
            result = capacity.summarize([capacity.Demand("build", Path("/build"), 1)],
                                       [observation], 0)
            self.assertFalse(result["admitted"])

    def test_invalid_numbers_are_refused_without_wrapping_or_coercion(self):
        for amount in (-1, True, "100", 2**80):
            with self.subTest(amount=amount):
                with self.assertRaises(capacity.Refusal):
                    capacity.summarize([capacity.Demand("build", Path("/build"), amount)],
                                       [self.observation()], 0)


class QuotaObservation(unittest.TestCase):
    def test_quota_errors_never_mean_accounting_is_disabled(self):
        for error in (errno.ENOSYS, errno.EPERM, errno.EOPNOTSUPP, errno.EINVAL):
            def query(*args):
                ctypes.set_errno(error)
                return -1
            with self.subTest(error=error), patch.object(capacity.platform, "machine", return_value="x86_64"), \
                 patch.object(capacity.ctypes, "CDLL", return_value=SimpleNamespace(syscall=query)):
                self.assertEqual(capacity.quota_state(3, "ext4"), "unknown")

    def test_quota_disabled_requires_negative_answers_for_all_three_types(self):
        calls = []
        def query(*args):
            calls.append(args)
            ctypes.set_errno(errno.ESRCH)
            return -1
        with patch.object(capacity.platform, "machine", return_value="x86_64"), \
             patch.object(capacity.ctypes, "CDLL", return_value=SimpleNamespace(syscall=query)):
            self.assertEqual(capacity.quota_state(3, "ext4"), "disabled")
        self.assertEqual(len(calls), 3)


@unittest.skipUnless(sys.platform == "linux", "Linux descriptor observations")
class DestinationBoundaries(unittest.TestCase):
    def test_completed_read_only_generation_can_still_be_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / "generation"
            observation = CapacityTotals().observation(available=1000)
            with patch.object(capacity, "observe", return_value=observation):
                with capacity.Guard([capacity.Demand("build", root, 100)], 0) as guard:
                    generation.mkdir(mode=0o700)
                    guard.bind(generation)
                    generation.chmod(0o500)
                    guard.recheck("before_selection")

    def test_new_generation_replacement_invalidates_the_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / "generation"
            observation = CapacityTotals().observation(available=1000)
            with patch.object(capacity, "observe", return_value=observation):
                with capacity.Guard([capacity.Demand("build", root, 100)], 0) as guard:
                    generation.mkdir(mode=0o700)
                    guard.bind(generation)
                    generation.rename(root / "retained")
                    generation.mkdir(mode=0o700)
                    with self.assertRaises(capacity.Refusal) as caught:
                        guard.recheck("before_build")
                    self.assertEqual(caught.exception.report["reason"], "destination_changed")

    def test_unwritable_destination_is_refused_before_work(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(capacity.os, "access", return_value=False):
            result = capacity.plan([capacity.Demand("build", Path(directory), 100)], 0)
            self.assertEqual(result["reason"], "destination_not_writable")
            self.assertFalse(result["admitted"])

    def test_phase_hooks_refuse_before_download_build_install_or_selection(self):
        cases = (("prepare-native-pilot-prerequisites.py", "native", "download"),
                 ("prepare-native-pilot-prerequisites.py", "native", "build"),
                 ("prepare-native-pilot-prerequisites.py", "native", "extract"),
                 ("build-native-pilot-inputs.py", "source", "bounded_cargo"),
                 ("prepare-installed-pilot.py", "assets", "selected_paths"),
                 ("prepare-installed-pilot.py", "assets", "publish_marker"))
        for filename, stage, operation in cases:
            spec = importlib.util.spec_from_file_location("capacity_phase_test", ROOT / "scripts" / filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = SimpleNamespace(output=root, guard_capacity=True, capacity_build_bytes=4096,
                    capacity_cache_bytes=4096, capacity_temp_bytes=4096, capacity_reserve_bytes=100,
                    npm_cache=None)
                observation = CapacityTotals().observation(available=100 * capacity.GIB)
                with patch.object(capacity, "observe", return_value=observation), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("child started")):
                    with capacity.checked(stage, args):
                        observation["available_bytes"] = 0
                        with self.assertRaises(capacity.Refusal):
                            if operation == "download":
                                module.download("git", root / "archive")
                            elif operation == "build":
                                module.build([], cwd=root, env={}, log=root / "log", seconds=1, stage="test")
                            elif operation == "extract":
                                module.extract(root / "archive", root, "git")
                            elif operation == "bounded_cargo":
                                module.bounded_cargo([], root=root, env={}, target=root, log=root / "log", stage="test")
                            elif operation == "selected_paths":
                                module.selected_paths(args, root)
                            else:
                                module.publish_marker(root, {})
                self.assertEqual(list(root.iterdir()), [])

    def test_bounded_selection_inventory_does_not_verify_or_credit_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "current.json"
            marker.write_text(json.dumps({"generation": "a" * 32}))
            result = capacity.selected_inventory(root)
            self.assertEqual(result["state"], "selected_marker_observed")
            self.assertFalse(result["verified"])
            marker.write_text("[" * 2000 + "0" + "]" * 2000)
            self.assertIn(capacity.selected_inventory(root)["state"], ("invalid", "unreadable_or_untrusted"))

    def test_symlink_and_fifo_selection_markers_are_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "other"
            target.write_bytes(b"retain")
            marker = root / "current.json"
            marker.symlink_to(target)
            self.assertFalse(capacity.selected_inventory(root)["verified"])
            marker.unlink()
            os.mkfifo(marker, mode=0o600)
            self.assertEqual(capacity.selected_inventory(root)["state"], "untrusted")
            self.assertEqual(target.read_bytes(), b"retain")

    def test_observed_archive_bytes_are_separate_from_unverified_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "archive"
            archive.write_bytes(b"unverified-input")
            result = capacity.archive_inventory(SimpleNamespace(git_archive=archive))
            self.assertEqual(result[0]["bytes"], len(b"unverified-input"))
            self.assertFalse(result[0]["pin_verified"])

    def test_mid_preparation_loss_preserves_selection_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "current.json"
            marker.write_bytes(b"previous-selection")
            unrelated = root / "unrelated"
            unrelated.write_bytes(b"retain")
            observation = CapacityTotals().observation(available=1000)
            with patch.object(capacity, "observe", return_value=observation):
                with capacity.Guard([capacity.Demand("build", root, 400)], 100) as guard:
                    observation["available_bytes"] = 50
                    with self.assertRaises(capacity.Refusal) as caught:
                        guard.recheck("before_selection")
            self.assertEqual(caught.exception.report["reason"], "low_space")
            self.assertEqual(caught.exception.report["work"], "may_have_started")
            self.assertEqual(marker.read_bytes(), b"previous-selection")
            self.assertEqual(unrelated.read_bytes(), b"retain")

    def test_new_owned_subdirectories_are_accepted_without_recharging_spent_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "generations"
            observation = CapacityTotals().observation(available=1000)
            with patch.object(capacity, "observe", return_value=observation):
                with capacity.Guard([capacity.Demand("build", target, 800)], 100) as guard:
                    target.mkdir(mode=0o700)
                    observation["available_bytes"] = 200
                    guard.recheck("before_selection")

    def test_read_only_plan_creates_no_missing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing" / "generations"
            before = set(Path(directory).iterdir())
            report = capacity.plan([capacity.Demand("build", path, 100)], 0)
            self.assertEqual(report["format"], "sw-pilot-capacity/1")
            self.assertEqual(set(Path(directory).iterdir()), before)
            self.assertFalse(path.exists())

    def test_symlink_component_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "owned").mkdir()
            (root / "link").symlink_to(root / "owned", target_is_directory=True)
            result = capacity.plan([capacity.Demand("build", root / "link" / "new", 100)], 0)
            self.assertEqual(result["status"], "refused")
            self.assertEqual(result["reason"], "unsafe_destination")
            self.assertFalse((root / "owned" / "new").exists())

    def test_replacement_invalidates_a_pinned_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "selected"
            target.mkdir(mode=0o700)
            demand = capacity.Demand("build", target, 10)
            with patch.object(capacity, "observe", return_value=CapacityTotals().observation()):
                with capacity.Guard([demand], 0) as guard:
                    target.rename(root / "retained")
                    target.mkdir(mode=0o700)
                    with self.assertRaises(capacity.Refusal) as caught:
                        guard.recheck("before_build")
                    self.assertEqual(caught.exception.report["reason"], "destination_changed")


class PreparedEvidence(unittest.TestCase):
    def driver(self):
        spec = importlib.util.spec_from_file_location("capacity_driver", ROOT / "scripts/test-pilot-capacity.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def records(self, root):
        for stage in ("native", "source", "assets"):
            (root / ("capacity-" + stage + ".json")).write_text(json.dumps({
                "format": capacity.FORMAT, "status": "sufficient", "admitted": True,
                "space_reserved": False, "inventory": {"stage": stage}}))
        for prefix, first_status in (("native-", "prepared-not-qualified"),
                                     ("source-", "built-not-qualified"), ("", "prepared-not-active")):
            for label, state in (("first", first_status), ("reused", "reused"), ("recovered", "reused")):
                (root / (prefix + label + ".json")).write_text(json.dumps({"status": state}))

    def test_prepared_evidence_requires_all_three_real_stage_outcomes(self):
        module = self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.records(root)
            result = module.prepared_records(root, "a" * 40)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["source_commit"], "a" * 40)
            self.assertEqual(len(result["stages"]), 3)
            (root / "source-reused.json").write_text('{"status":"built-not-qualified"}')
            with self.assertRaises(ValueError):
                module.prepared_records(root, "a" * 40)

    def test_workflow_retains_records_needed_to_replay_capacity_qualification(self):
        import fnmatch
        import shutil

        workflow = (ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text()
        upload = workflow.split("- name: Retain bounded result and first failure", 1)[1]
        path_block = upload.split("path: |", 1)[1].split("retention-days:", 1)[0]
        patterns = [line.strip().removeprefix("${{ runner.temp }}/sou111-assets/")
                    for line in path_block.splitlines()
                    if line.strip().startswith("${{ runner.temp }}/sou111-assets/")]
        module = self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, retained = root / "original", root / "retained"
            original.mkdir()
            retained.mkdir()
            self.records(original)
            for record in original.iterdir():
                if any(fnmatch.fnmatchcase(record.name, pattern) for pattern in patterns):
                    shutil.copyfile(record, retained / record.name)
            self.assertEqual(module.prepared_records(retained, "a" * 40),
                             module.prepared_records(original, "a" * 40))

    def test_unknown_or_falsely_successful_capacity_cannot_be_published_as_pass(self):
        module = self.driver()
        for change in ({"status": "unknown", "admitted": False}, {"admitted": False},
                       {"space_reserved": True}, {"format": "other"}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.records(root)
                plan = json.loads((root / "capacity-native.json").read_text())
                plan.update(change)
                (root / "capacity-native.json").write_text(json.dumps(plan))
                with self.assertRaises(ValueError):
                    module.prepared_records(root, "a" * 40)

    def test_oversized_evidence_is_rejected(self):
        module = self.driver()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.records(root)
            target = root / "capacity-native.json"
            target.write_bytes(b" " * 65537)
            with self.assertRaises(ValueError):
                module.prepared_records(root, "a" * 40)

    @unittest.skipUnless(os.name == "posix", "POSIX links")
    def test_linked_evidence_is_rejected(self):
        module = self.driver()
        for link in ("symlink", "hardlink"):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.records(root)
                target = root / "capacity-native.json"
                retained = root / "retained.json"
                target.rename(retained)
                if link == "symlink":
                    target.symlink_to(retained)
                else:
                    os.link(retained, target)
                with self.assertRaises(ValueError):
                    module.prepared_records(root, "a" * 40)


class CapacityCLI(unittest.TestCase):
    def test_lost_reserve_while_waiting_refuses_before_generation(self):
        for name, stage in (("prepare-native-pilot-prerequisites.py", "native"),
                            ("build-native-pilot-inputs.py", "source")):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                spec = importlib.util.spec_from_file_location("capacity_coordination_" + stage, ROOT / "scripts" / name)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                root, locked = Path(directory), {"acquired": False}
                output = root / "prepared"
                archive = root / "owned-archive"
                archive.write_bytes(b"owned fixture")
                args = SimpleNamespace(output=output, guard_capacity=True,
                    capacity_build_bytes=4096, capacity_cache_bytes=4096,
                    capacity_temp_bytes=4096, capacity_reserve_bytes=1024,
                    wait_seconds=1, expected_commit="a" * 40, prepare=True,
                    rebuild=False, allow_download=False, git_archive=archive,
                    bwrap_archive=archive)

                def observe(*_args, **_kwargs):
                    # Model another owner consuming the reserve during the wait.
                    status, reason = ("insufficient", "low_space") if locked["acquired"] else (
                        "sufficient", "declared_budget_available")
                    return capacity.record(status, reason), []

                @contextmanager
                def hold(*_args, **_kwargs):
                    locked["acquired"] = True
                    yield SimpleNamespace(waited_seconds=0.1, contended=True)

                with ExitStack() as stack:
                    stack.enter_context(patch.object(capacity, "inspect", side_effect=observe))
                    stack.enter_context(patch.object(module.coordination, "hold", side_effect=hold))
                    stack.enter_context(patch.object(module, "source_identity", return_value="a" * 40))
                    if stage == "source":
                        stack.enter_context(patch.object(module, "inventory", return_value={"missing": [], "tools": {}}))
                        stack.enter_context(patch.object(module, "tool_identity", return_value={}))
                    else:
                        stack.enter_context(patch.object(module, "platform_missing", return_value=[]))
                        stack.enter_context(patch.object(module, "tool_inventory", return_value=({}, [])))
                        stack.enter_context(patch.object(module, "execution_inputs", return_value={}))
                    with capacity.checked(stage, args), self.assertRaises(capacity.Refusal) as caught:
                        if stage == "source":
                            module.run_build(root, output, args.expected_commit, wait_seconds=1)
                        else:
                            module.prepare(args)
                    self.assertEqual(caught.exception.report["reason"], "low_space")
                    self.assertTrue(locked["acquired"])
                    self.assertFalse((output / "generations").exists())
                    self.assertFalse((output / "current.json").exists())

    def test_guarded_refusals_never_enter_preparers_or_write_failure_records(self):
        for name, flag, operation in (("prepare-native-pilot-prerequisites.py", "--prepare", "prepare"),
                ("build-native-pilot-inputs.py", "--build", "run_build"),
                ("prepare-installed-pilot.py", "--prepare", "prepare")):
            spec = importlib.util.spec_from_file_location("capacity_cli_test", ROOT / "scripts" / name)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for status, reason in (("insufficient", "low_space"), ("unknown", "unknown_quota")):
                with self.subTest(name=name, reason=reason), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "missing"
                    argv = [name, flag, "--guard-capacity", "--output", str(output),
                            "--expected-commit", "a" * 40, "--capacity-build-bytes", "4096",
                            "--capacity-cache-bytes", "4096", "--capacity-temp-bytes", "4096"]
                    stream = io.StringIO()
                    with patch.object(sys, "argv", argv), redirect_stdout(stream), \
                         patch.object(capacity, "inspect", return_value=(capacity.record(status, reason), [])), \
                         patch.object(module, operation) as prepare:
                        self.assertEqual(module.main(), 2)
                        prepare.assert_not_called()
                    self.assertEqual(json.loads(stream.getvalue())["work"], "not_started")
                    self.assertFalse(output.exists())

    def test_sufficient_budget_dispatches_existing_preparation_and_reuse(self):
        for name, flag, operation in (("prepare-native-pilot-prerequisites.py", "--prepare", "prepare"),
                ("build-native-pilot-inputs.py", "--build", "run_build"),
                ("prepare-installed-pilot.py", "--prepare", "prepare")):
            spec = importlib.util.spec_from_file_location("capacity_cli_success", ROOT / "scripts" / name)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for state in ("prepared-not-qualified", "reused"):
                with self.subTest(name=name, state=state), tempfile.TemporaryDirectory() as directory:
                    argv = [name, flag, "--guard-capacity", "--output", directory,
                            "--expected-commit", "a" * 40, "--capacity-build-bytes", "4096",
                            "--capacity-cache-bytes", "4096", "--capacity-temp-bytes", "4096"]
                    with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()), \
                         patch.object(capacity, "inspect", return_value=(capacity.record(
                             "sufficient", "declared_budget_available"), [])), \
                         patch.object(module, operation, return_value={"status": state}) as prepare:
                        if hasattr(module, "platform_missing"):
                            with patch.object(module, "platform_missing", return_value=[]):
                                self.assertEqual(module.main(), 0)
                        else:
                            self.assertEqual(module.main(), 0)
                        prepare.assert_called_once()

    def test_plans_do_not_execute_hostile_path_programs_or_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trap = root / "started"
            for program in ("git", "rustup", "cargo", "pkg-config", "node", "npm", "ldd", "readelf"):
                script = root / program
                script.write_text('#!/bin/sh\nprintf started > "' + str(trap) + '"\nexit 99\n')
                script.chmod(0o700)
            for name in ("prepare-native-pilot-prerequisites.py", "build-native-pilot-inputs.py",
                         "prepare-installed-pilot.py"):
                output = root / (name + "-output")
                result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / name),
                    "--capacity-plan", "--output", str(output)],
                    env={**os.environ, "PATH": str(root)}, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(result.stdout)
                self.assertEqual(record["format"], "sw-pilot-capacity/1")
                self.assertFalse(record["space_reserved"])
                self.assertFalse(trap.exists())
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
