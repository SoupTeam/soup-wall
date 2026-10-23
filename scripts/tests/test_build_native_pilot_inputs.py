# SPDX-License-Identifier: Apache-2.0
"""Source and inventory boundaries for the SOU-119 Agent binary builder."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/build-native-pilot-inputs.py"
BUILD = None


def builder():
    global BUILD
    if BUILD is not None:
        return BUILD
    spec = importlib.util.spec_from_file_location("sou119_builder", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    BUILD = module
    return BUILD


def git(*argv, cwd):
    return subprocess.check_output(["git", *argv], cwd=cwd, text=True,
                                   stderr=subprocess.DEVNULL, timeout=10).strip()


def fake_generation(_root, generation, _tools):
    """Make three distinguishable ELF-shaped files; never invoke the compiler."""
    binary_dir = generation / "bin"
    binary_dir.mkdir(mode=0o700)
    for role in builder().ROLES:
        binary = binary_dir / role
        binary.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00" + role.encode())
        binary.chmod(0o700)
    return 0.25


def fake_inputs(build):
    source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False,
              "files_sha256": "c" * 64, "cargo_lock_sha256": "d" * 64,
              "rust_toolchain_sha256": "e" * 64}
    # run_build verifies selected tool bytes; use one stable, real executable.
    tools = {name: str(Path(sys.executable).resolve())
             for name in ("cargo", "rustc", "cc", "c++", "ar", "ranlib", "cmake")}
    return source, tools


class SourceBuildBoundary(unittest.TestCase):
    def test_unexpected_build_error_reports_code_location_without_private_path(self):
        build = builder()
        output = io.StringIO()
        with patch.object(build, "run_build", side_effect=FileNotFoundError("/private-fixture/secret")), \
             patch.object(sys, "stdout", output):
            code = build.main(["--build"])
        self.assertEqual(code, 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["reason"], "FileNotFoundError_failed")
        self.assertEqual(report["failure_location"]["function"], "main")
        self.assertGreater(report["failure_location"]["line"], 0)
        self.assertNotIn("private-fixture", output.getvalue())

    def test_quota_inventory_tolerates_removed_cargo_temporary_files(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transient = root / "cargo-download.part"
            retained = root / "retained"
            retained.write_bytes(b"123456")
            original = Path.lstat

            def removed_before_stat(path, *args, **kwargs):
                if path == transient:
                    transient.unlink()
                return original(path, *args, **kwargs)

            for limit, expected in ((6, True), (5, False)):
                with self.subTest(limit=limit):
                    transient.write_bytes(b"temporary")
                    with patch.object(Path, "lstat", removed_before_stat), \
                         patch.object(build, "MAX_TARGET_BYTES", limit):
                        self.assertEqual(build.target_within_limit(root), expected)
                    self.assertFalse(transient.exists())

    def test_quota_inventory_refuses_missing_root_and_unreadable_entries(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                build.target_within_limit(root / "missing")
            retained = root / "retained"
            retained.write_bytes(b"retained")
            original = Path.lstat

            def unreadable(path, *args, **kwargs):
                if path == retained:
                    raise PermissionError("owned fixture is unreadable")
                return original(path, *args, **kwargs)

            with patch.object(Path, "lstat", unreadable), self.assertRaises(PermissionError):
                build.target_within_limit(root)

    def test_quota_inventory_distinguishes_removed_directories_from_unreadable_walk(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "retained").write_bytes(b"123456")

            def vanished_directory(path, *, followlinks, onerror):
                onerror(FileNotFoundError(2, "removed", str(root / "cargo-temp")))
                yield str(path), [], ["retained"]

            with patch.object(build.os, "walk", vanished_directory), \
                 patch.object(build, "MAX_TARGET_BYTES", 5):
                self.assertFalse(build.target_within_limit(root), "retained bytes must still enforce the quota")

            def unreadable_directory(path, *, followlinks, onerror):
                onerror(PermissionError(13, "unreadable", str(root / "private")))
                yield str(path), [], []

            with patch.object(build.os, "walk", unreadable_directory), self.assertRaises(PermissionError):
                build.target_within_limit(root)

    def test_cargo_artifacts_bind_exact_workspace_package(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "crates" / "agentfw"
            package.mkdir(parents=True)
            actual = f"path+{package.as_uri()}#agentfw@0.3.0"
            lookalike = f"path+{(root / 'crates' / 'agentfw-lookalike').as_uri()}#agentfw@0.3.0"
            self.assertTrue(build.package_matches(actual, package, "0.3.0"))
            self.assertTrue(build.package_matches(f"path+{package.as_uri()}#0.3.0",
                                                  package, "0.3.0"))
            self.assertFalse(build.package_matches(lookalike, package, "0.3.0"))
            self.assertFalse(build.package_matches(actual.replace("0.3.0", "0.3.1"),
                                                   package, "0.3.0"))

    @unittest.skipUnless(os.name == "posix", "hardlink ownership requires POSIX modes")
    def test_cargo_hardlinked_source_is_copied_into_single_link_selection(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / "cargo-bin"
            cargo.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00native")
            cargo.chmod(0o700)
            os.link(cargo, root / "cargo-deps-link")
            self.assertEqual(build.cargo_artifact_source(cargo).st_nlink, 2)
            selected = root / "selected"
            selected.write_bytes(cargo.read_bytes())
            selected.chmod(0o700)
            self.assertEqual(build.checked_binary(selected, root)["size"], cargo.stat().st_size)
            self.assertEqual(selected.stat().st_nlink, 1)

    def test_default_plan_does_not_create_output_or_change_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "private-output"
            # Managed Windows worktree .git files are not portable to WSL Git.
            try:
                before = git("status", "--porcelain", cwd=ROOT)
            except subprocess.CalledProcessError:
                before = None
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--output", str(output),
                 "--expected-commit", "0" * 40],
                cwd=ROOT, capture_output=True, text=True, timeout=45, check=True)
            plan = json.loads(result.stdout)
            self.assertEqual(plan["status"], "plan")
            self.assertIs(plan["executed"], False)
            self.assertFalse(output.exists(), "inventory must not create a generation")
            if before is not None:
                self.assertEqual(git("status", "--porcelain", cwd=ROOT), before)
            self.assertEqual(plan["toolchain"], "1.94.1")
            self.assertEqual(len(plan["commands"]), 2)
            self.assertTrue(all("--locked" in command for command in plan["commands"]))
            self.assertTrue(plan.get("missing") or plan.get("tools"),
                            "inventory must explain required toolchain/native inputs")

    def test_incomplete_build_request_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "private-output"
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--build", "--output", str(output),
                 "--expected-commit", "0" * 40],
                cwd=ROOT, capture_output=True, text=True, timeout=45)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists(), "invalid build request must leave output untouched")

    def test_source_identity_rejects_changed_commit_and_dirty_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=source, check=True, timeout=10)
            subprocess.run(["git", "config", "user.email", "source-test@example.invalid"],
                           cwd=source, check=True, timeout=10)
            subprocess.run(["git", "config", "user.name", "Source Test"],
                           cwd=source, check=True, timeout=10)
            tracked = source / "tracked.txt"
            tracked.write_text("reviewed\n", encoding="utf-8")
            (source / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (source / "rust-toolchain.toml").write_text(
                '[toolchain]\nchannel = "stable"\n', encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt", "Cargo.lock", "rust-toolchain.toml"],
                           cwd=source, check=True, timeout=10)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "reviewed"], cwd=source,
                           check=True, timeout=10)
            expected = git("rev-parse", "HEAD", cwd=source)
            build = builder()
            identity = build.source_identity(source, expected)
            self.assertIn(expected, json.dumps(identity))
            with self.assertRaises(build.Failure):
                build.source_identity(source, "0" * 40)
            tracked.write_text("drifted\n", encoding="utf-8")
            with self.assertRaises(build.Failure):
                build.source_identity(source, expected)
            tracked.write_text("reviewed\n", encoding="utf-8")
            (source / "untracked.txt").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaises(build.Failure):
                build.source_identity(source, expected)

    @unittest.skipUnless(os.name == "posix", "owned generations require POSIX modes")
    def test_verified_reuse_and_source_drift_preserve_selected_generation(self):
        build = builder()
        source, tools = fake_inputs(build)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "build"
            with patch.object(build, "inventory", return_value={"missing": [], "tools": tools}), \
                 patch.object(build, "source_identity", return_value=source) as identity, \
                 patch.object(build, "build_generation", side_effect=fake_generation) as compile_one:
                first = build.run_build(ROOT, output, source["commit"])
                self.assertEqual(first["status"], "built-not-qualified")
                self.assertEqual(first["build_seconds"], 0.25)
                self.assertFalse(first["active_protection"])
                self.assertEqual(compile_one.call_count, 1)
                marker = (output / "current.json").read_bytes()
                repeated = build.run_build(ROOT, output, source["commit"])
                self.assertEqual(repeated["status"], "reused")
                self.assertEqual(repeated["build_seconds"], 0)
                self.assertEqual(compile_one.call_count, 1, "verified reuse must not rebuild")
                for role in build.ROLES:
                    self.assertEqual(first[role], repeated[role])
                    self.assertTrue(Path(first[role]).is_absolute())
                self.assertEqual(first["receipt"], repeated["receipt"])
                identity.return_value = {**source, "files_sha256": "f" * 64}
                with self.assertRaisesRegex(build.Failure, "receipt_identity_changed"):
                    build.run_build(ROOT, output, source["commit"])
                self.assertEqual((output / "current.json").read_bytes(), marker)
                self.assertEqual(compile_one.call_count, 1)

    @unittest.skipUnless(os.name == "posix", "owned generations require POSIX modes")
    def test_failed_rebuild_preserves_marker_and_unrelated_file(self):
        build = builder()
        source, tools = fake_inputs(build)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "build"
            unrelated = root / "unrelated.txt"
            unrelated.write_text("keep", encoding="utf-8")
            with patch.object(build, "inventory", return_value={"missing": [], "tools": tools}), \
                 patch.object(build, "source_identity", return_value=source), \
                 patch.object(build, "build_generation", side_effect=fake_generation) as compile_one:
                first = build.run_build(ROOT, output, source["commit"])
                marker = (output / "current.json").read_bytes()
                compile_one.side_effect = build.Failure("deliberate_build_failure", "compile")
                with self.assertRaisesRegex(build.Failure, "deliberate_build_failure"):
                    build.run_build(ROOT, output, source["commit"], rebuild=True)
                self.assertEqual((output / "current.json").read_bytes(), marker)
                self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")
                self.assertEqual(build.run_build(ROOT, output, source["commit"])["receipt"],
                                 first["receipt"])

    @unittest.skipUnless(os.name == "posix", "owned generations require POSIX modes")
    def test_reuse_rejects_nonexecutable_and_digest_mismatched_binary(self):
        build = builder()
        source, tools = fake_inputs(build)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "build"
            with patch.object(build, "inventory", return_value={"missing": [], "tools": tools}), \
                 patch.object(build, "source_identity", return_value=source), \
                 patch.object(build, "build_generation", side_effect=fake_generation):
                first = build.run_build(ROOT, output, source["commit"])
                marker = (output / "current.json").read_bytes()
                binary = Path(first["agentfw"])
                binary.chmod(0o400)
                with self.assertRaises((build.Failure, build.native.Failure)):
                    build.run_build(ROOT, output, source["commit"])
                binary.chmod(0o700)
                binary.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00modified")
                binary.chmod(0o500)
                with self.assertRaisesRegex(build.Failure, "binary_digest_or_mode_changed"):
                    build.run_build(ROOT, output, source["commit"])
                self.assertEqual((output / "current.json").read_bytes(), marker)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process groups required")
    def test_bounded_build_reaps_descendant_after_leader_exit(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            worker = root / "worker.py"
            pids = root / "pids.json"
            ready = root / "ready"
            worker.write_text('''import json, os, pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c",
    "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)",
    sys.argv[2]])
for _ in range(200):
    if pathlib.Path(sys.argv[2]).exists():
        break
    time.sleep(0.01)
pathlib.Path(sys.argv[1]).write_text(json.dumps({"leader": os.getpid(), "child": child.pid}))
''', encoding="utf-8")
            try:
                with patch.object(build, "BUILD_SECONDS", 1):
                    with self.assertRaisesRegex(build.Failure, "fixture_timeout"):
                        build.bounded_cargo(
                            [sys.executable, str(worker), str(pids), str(ready)],
                            root=root, env={"PATH": "/usr/bin:/bin"}, target=target,
                            log=root / "build.log", stage="fixture")
                self.assertTrue(pids.exists(), "the descendant must have started")
                group = json.loads(pids.read_text())["leader"]
                self.assertFalse(build.native.group_has_running_member(group),
                                 "timed-out compilation must reap its owned descendants")
                self.assertLessEqual((root / "build.log").stat().st_size, build.native.MAX_LOG)
                self.assertEqual(stat.S_IMODE((root / "build.log").stat().st_mode), 0o600)
            finally:
                if pids.exists():
                    try:
                        os.killpg(json.loads(pids.read_text())["leader"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process groups required")
    def test_bounded_build_refuses_target_quota_overrun(self):
        build = builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir(mode=0o700)
            worker = root / "grow.py"
            worker.write_text('''import pathlib,sys,time
pathlib.Path(sys.argv[1]).write_bytes(b"x" * 128)
time.sleep(10)
''', encoding="utf-8")
            with patch.object(build, "MAX_TARGET_BYTES", 64), \
                 patch.object(build, "BUILD_SECONDS", 5):
                with self.assertRaisesRegex(build.Failure, "fixture_target_limit"):
                    build.bounded_cargo([sys.executable, str(worker), str(target / "large")],
                                        root=root, env={"PATH": "/usr/bin:/bin"}, target=target,
                                        log=root / "build.log", stage="fixture")
            self.assertLessEqual((root / "build.log").stat().st_size, build.native.MAX_LOG)


if __name__ == "__main__":
    unittest.main()
