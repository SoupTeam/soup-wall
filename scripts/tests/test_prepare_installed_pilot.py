# SPDX-License-Identifier: Apache-2.0
"""Failure boundaries for the SOU-111 preparation transaction."""
import errno
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou111_preparation", ROOT / "scripts/prepare-installed-pilot.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


@unittest.skipUnless(os.name == "posix", "private installer logs require POSIX permissions")
class InstallerFailurePrivacy(unittest.TestCase):
    @contextmanager
    def failed_installer(self, root, kind, exit_code):
        output = root / "output"
        generation = "a" * 32
        canary = b"owned-installer-diagnostic-canary"
        contents = b"x" * (2 * 1024 * 1024) + b"\n" + canary + b"\xff\n"
        args = SimpleNamespace(output=output, expected_commit="b" * 40, rebuild=False,
                               npm_cache=None, wheelhouse=None, python_archive=None, node_archive=None,
                               allow_download=True, refusal_verdict="ask", refusal_rule="exact-rule")
        paths = {role: Path(os.sys.executable) for role in PREP.PILOT.ROLES}

        def init_git(command, **_):
            (Path(command[-1]) / ".git").mkdir()

        def fail(*_, log, **__):
            log.write(contents)
            log.flush()
            raise subprocess.CalledProcessError(exit_code, [canary.decode()],
                                                output=canary, stderr=canary)

        with ExitStack() as stack:
            stack.enter_context(patch.object(PREP, "supported_platform"))
            stack.enter_context(patch.object(PREP.PILOT, "source", return_value={
                "dirty": False, "commit": args.expected_commit}))
            stack.enter_context(patch.object(PREP, "selected_paths", return_value=paths))
            stack.enter_context(patch.object(PREP.uuid, "uuid4", return_value=SimpleNamespace(hex=generation)))
            stack.enter_context(patch.object(PREP.subprocess, "run", side_effect=init_git))
            for name, installer in (("filesystem", PREP.FS), ("git", PREP.GIT)):
                stack.enter_context(patch.object(installer, "install", side_effect=fail if name == kind else None))
            yield args, output / "generations" / generation / (kind + "-install.log"), contents

    def assert_retained_private_log(self, args, log_path, contents):
        self.assertEqual(log_path.read_bytes(), contents)
        self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)
        self.assertFalse((args.output / "current.json").exists())

    def test_actual_failed_preparation_never_reads_installer_log(self):
        for kind in ("filesystem", "git"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                with self.failed_installer(Path(temporary), kind, 9) as (args, log_path, contents):
                    original_open = Path.open

                    def no_log_reads(path, mode="r", *positional, **keywords):
                        if path.name.endswith("-install.log") and ("r" in mode or "+" in mode):
                            self.fail("failure formatting must not read the private installer log")
                        return original_open(path, mode, *positional, **keywords)

                    with patch.object(Path, "open", no_log_reads):
                        with self.assertRaises(ValueError) as caught:
                            PREP.prepare(args)
                    self.assertEqual(str(caught.exception), kind + "_installer_failed")
                    self.assert_retained_private_log(args, log_path, contents)

    def test_actual_main_exports_only_finite_installer_failure_fields(self):
        for kind in ("filesystem", "git"):
            for exit_code in (9, -15):
                with self.subTest(kind=kind, exit_code=exit_code), tempfile.TemporaryDirectory() as temporary:
                    with self.failed_installer(Path(temporary), kind, exit_code) as (args, log_path, contents):
                        stdout, stderr = io.StringIO(), io.StringIO()
                        argv = ["prepare-installed-pilot.py", "--prepare", "--allow-download",
                                "--output", str(args.output), "--expected-commit", args.expected_commit]
                        with patch.object(PREP.sys, "argv", argv), redirect_stdout(stdout), redirect_stderr(stderr):
                            self.assertEqual(PREP.main(), 2)
                        self.assertEqual(json.loads(stdout.getvalue()), {
                            "status": "failed", "reason": kind + "_installer_failed", "exit_code": exit_code,
                            "private_log": log_path.relative_to(args.output).as_posix()})
                        self.assertEqual(stderr.getvalue(), "")
                        self.assert_retained_private_log(args, log_path, contents)


class MarkerStorageRecovery(unittest.TestCase):
    def setUp(self):
        # These tests exercise filesystem transactions on every host. Linux
        # ownership and actual directory fsync remain covered by POSIX checks.
        if not hasattr(PREP.os, "fchmod"):
            self.fchmod = patch.object(PREP.os, "fchmod", create=True)
            self.fchmod.start()
            self.addCleanup(self.fchmod.stop)

    def test_partial_write_failures_remove_only_the_created_file(self):
        original_open = Path.open
        for code in (errno.ENOSPC, errno.EACCES, errno.EROFS):
            with self.subTest(errno=code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "selection.json"
                unrelated = root / "unrelated"
                unrelated.write_bytes(b"keep")

                class PartialWrite:
                    def __enter__(self):
                        self.output = original_open(target, "xb")
                        return self

                    def __exit__(self, *_):
                        self.output.close()

                    def fileno(self):
                        return self.output.fileno()

                    def write(self, raw):
                        self.output.write(raw[:3])
                        self.output.flush()
                        raise OSError(code, "injected write failure")

                with patch.object(Path, "open", return_value=PartialWrite()):
                    with self.assertRaises(OSError) as failure:
                        PREP.write_json(target, {"value": "complete"})
                self.assertEqual(failure.exception.errno, code)
                self.assertFalse(target.exists())
                self.assertEqual(unrelated.read_bytes(), b"keep")
                PREP.write_json(target, {"value": "retry"})
                self.assertEqual(json.loads(target.read_bytes()), {"value": "retry"})

    def test_existing_json_is_preserved_when_exclusive_create_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "selection.json"
            target.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                PREP.write_json(target, {"replacement": True})
            self.assertEqual(target.read_bytes(), b"existing")

    def test_colliding_marker_temporary_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "current.json"
            marker.write_bytes(b"prior marker")
            collision = root / (".current-" + "a" * 32)
            collision.write_bytes(b"another attempt")
            with patch.object(PREP.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)):
                with self.assertRaises(FileExistsError):
                    PREP.publish_marker(root, {"generation": "new"})
            self.assertEqual(marker.read_bytes(), b"prior marker")
            self.assertEqual(collision.read_bytes(), b"another attempt")

    def test_cleanup_failure_reports_retained_unpublished_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "current.json"
            marker.write_bytes(b"prior marker")
            with patch.object(PREP.os, "fsync", side_effect=OSError(errno.ENOSPC, "injected full disk")), \
                 patch.object(Path, "unlink", side_effect=OSError(errno.EACCES, "injected cleanup denial")):
                with self.assertRaisesRegex(ValueError, "unpublished_file_cleanup_failed") as failure:
                    PREP.publish_marker(root, {"generation": "new"})
            self.assertIn("injected full disk", str(failure.exception))
            self.assertIn("injected cleanup denial", str(failure.exception))
            self.assertEqual(marker.read_bytes(), b"prior marker")
            self.assertEqual(len(list(root.glob(".current-*"))), 1)

    def test_marker_write_sync_and_replace_failures_preserve_prior_selection(self):
        for phase in ("file_sync", "replace"):
            for code in (errno.ENOSPC, errno.EACCES, errno.EROFS):
                with self.subTest(phase=phase, errno=code), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    marker = root / "current.json"
                    marker.write_bytes(b"prior marker")
                    unrelated = root / "unrelated"
                    unrelated.write_bytes(b"keep")
                    function = "fsync" if phase == "file_sync" else "replace"
                    with patch.object(PREP.os, function, side_effect=OSError(code, "injected failure")), \
                         patch.object(PREP, "sync_directory") as sync:
                        with self.assertRaises(OSError) as failure:
                            PREP.publish_marker(root, {"generation": "new"})
                        sync.assert_not_called()
                    self.assertEqual(failure.exception.errno, code)
                    self.assertEqual(marker.read_bytes(), b"prior marker")
                    self.assertEqual(sorted(path.name for path in root.iterdir()), ["current.json", "unrelated"])
                    self.assertEqual(unrelated.read_bytes(), b"keep")
                    with patch.object(PREP, "sync_directory"):
                        PREP.publish_marker(root, {"generation": "retry"})
                    self.assertEqual(json.loads(marker.read_bytes()), {"generation": "retry"})

    def test_interrupted_unpublished_marker_is_cleaned_and_can_retry(self):
        for phase in ("fsync", "replace"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "current.json"
                marker.write_bytes(b"prior marker")
                with patch.object(PREP.os, phase, side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        PREP.publish_marker(root, {"generation": "new"})
                self.assertEqual(marker.read_bytes(), b"prior marker")
                self.assertEqual(list(root.iterdir()), [marker])
                with patch.object(PREP, "sync_directory"):
                    PREP.publish_marker(root, {"generation": "retry"})
                self.assertEqual(json.loads(marker.read_bytes()), {"generation": "retry"})

    def test_directory_sync_failure_reports_published_marker_without_rollback(self):
        for failure in (OSError(errno.ENOSPC, "full"), OSError(errno.EIO, "sync failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "current.json"
                marker.write_bytes(b"prior marker")
                with patch.object(PREP, "sync_directory", side_effect=failure):
                    with self.assertRaisesRegex(ValueError, "completion_marker_published_durability_uncertain"):
                        PREP.publish_marker(root, {"generation": "new"})
                self.assertEqual(json.loads(marker.read_bytes()), {"generation": "new"})
                self.assertEqual(list(root.iterdir()), [marker])

    def test_interruption_after_replace_reports_uncertainty_and_keeps_new_marker(self):
        original_replace = os.replace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "current.json"
            marker.write_bytes(b"prior marker")

            def interrupted_replace(source, destination):
                original_replace(source, destination)
                raise KeyboardInterrupt()

            with patch.object(PREP.os, "replace", side_effect=interrupted_replace), \
                 patch.object(PREP, "sync_directory") as sync:
                with self.assertRaisesRegex(ValueError, "completion_marker_publication_uncertain"):
                    PREP.publish_marker(root, {"generation": "new"})
                sync.assert_not_called()
            self.assertEqual(json.loads(marker.read_bytes()), {"generation": "new"})
            self.assertEqual(list(root.iterdir()), [marker])

    def test_marker_syncs_file_before_replace_and_directory_afterwards(self):
        original_fsync, original_replace = os.fsync, os.replace
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def sync_file(fd):
                events.append("file_sync")
                original_fsync(fd)

            def replace(source, destination):
                events.append("replace")
                original_replace(source, destination)

            with patch.object(PREP.os, "fsync", side_effect=sync_file), \
                 patch.object(PREP.os, "replace", side_effect=replace), \
                 patch.object(PREP, "sync_directory", side_effect=lambda _: events.append("directory_sync")):
                PREP.publish_marker(root, {"generation": "new"})
            self.assertEqual(events, ["file_sync", "replace", "directory_sync"])


class PreparationBoundary(unittest.TestCase):
    def test_default_plan_is_non_mutating_and_inventories_missing_inputs(self):
        import subprocess
        result = subprocess.run([os.sys.executable, "-B", str(ROOT / "scripts/prepare-installed-pilot.py"),
                                 "--output", "/tmp/sou111-plan-does-not-create"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["status"], "plan")
        self.assertFalse(plan["executed"])
        self.assertIn("--agentfw PATH", plan["missing"])
        self.assertFalse(Path("/tmp/sou111-plan-does-not-create").exists())

    def test_wrong_digest_and_corrupt_archive_do_not_extract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, destination = root / "node.tar.xz", root / "runtime"
            destination.mkdir()
            archive.write_bytes(b"not the pinned runtime")
            with self.assertRaisesRegex(ValueError, "input_digest_mismatch"):
                PREP.extract_node(archive, destination)
            self.assertEqual(list(destination.iterdir()), [])
            with patch.object(PREP, "NODE_ARCHIVE_SHA256", PREP.FS.sha(archive)):
                with self.assertRaises(tarfile.TarError):
                    PREP.extract_node(archive, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_archive_rejects_traversal_external_symlink_and_link_parent(self):
        for name, kind, link in (("node-v22.22.0-linux-x64/../escape", tarfile.REGTYPE, ""),
                                 ("node-v22.22.0-linux-x64/bin/npm", tarfile.SYMTYPE, "/etc/passwd"),
                                 ("node-v22.22.0-linux-x64/bin/npm/x", tarfile.REGTYPE, "")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive, destination = root / "node.tar.xz", root / "runtime"
                destination.mkdir()
                with tarfile.open(archive, "w:xz") as bundle:
                    if name.endswith("/x"):
                        parent = tarfile.TarInfo("node-v22.22.0-linux-x64/bin/npm")
                        parent.type, parent.linkname = tarfile.SYMTYPE, "../lib"
                        bundle.addfile(parent)
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, link
                    if kind == tarfile.REGTYPE:
                        entry.size = 1
                        bundle.addfile(entry, io.BytesIO(b"x"))
                    else:
                        bundle.addfile(entry)
                with patch.object(PREP, "NODE_ARCHIVE_SHA256", PREP.FS.sha(archive)):
                    with self.assertRaises(ValueError):
                        PREP.extract_node(archive, destination)
                self.assertFalse((root / "escape").exists())

    @unittest.skipUnless(os.name == "posix", "owned POSIX mode and ldd checks require Linux")
    def test_private_path_and_native_dependency_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            PREP.private_dir(private)
            private.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "private_owned_0700"):
                PREP.private_dir(private)
            private.chmod(0o700)
            (root / "link").symlink_to(private)
            with self.assertRaisesRegex(ValueError, "private_directory_required"):
                PREP.private_dir(root / "link")
            with patch.object(PREP.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "libmissing.so => not found"
                run.return_value.stderr = ""
                with self.assertRaisesRegex(ValueError, "native_dependency_missing"):
                    PREP.check_native(Path(os.sys.executable))

    @unittest.skipUnless(os.name == "posix", "profile ownership requires Linux")
    def test_changed_package_and_runtime_fail_revalidation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "entry.js").write_text("original")
            profile = {"format": PREP.FS.FORMAT, "packageRoot": str(package),
                       "packageTreeSha256": PREP.FS.tree_sha(package), "runtimePath": os.sys.executable,
                       "runtimeSha256": PREP.FS.sha(os.sys.executable), "libraries": [],
                       "workspace": str(root / "workspace"), "bwrapPath": os.sys.executable,
                       "bwrapSha256": PREP.FS.sha(os.sys.executable)}
            (root / "workspace").mkdir()
            assets = PREP.FS.ASSETS
            registry = PREP.FS.registry(json.loads((assets / "upstream-tools-list.json").read_text()))
            for name, value in (("profile.json", profile), ("registry.json", registry)):
                (root / name).write_text(json.dumps(value))
            (root / "policy.yaml").write_bytes((assets / "policy.yaml").read_bytes())
            receipt = {"format": "sou62-profile-installation/1", "profile": profile,
                       **{name + "_sha256": PREP.FS.sha(root / (name + (".yaml" if name == "policy" else ".json")))
                          for name in ("profile", "registry", "policy")}}
            (root / "installation.json").write_text(json.dumps(receipt))
            paths = {"bwrap": Path(os.sys.executable), "node": Path(os.sys.executable)}
            PREP.verify_profile("filesystem", root, paths, root / "workspace")
            (package / "entry.js").write_text("changed")
            with self.assertRaisesRegex(ValueError, "profile_package_changed"):
                PREP.verify_profile("filesystem", root, paths, root / "workspace")
            (package / "entry.js").write_text("original")
            profile["runtimeSha256"] = "0" * 64
            (root / "profile.json").write_text(json.dumps(profile))
            receipt["profile"] = profile
            receipt["profile_sha256"] = PREP.FS.sha(root / "profile.json")
            (root / "installation.json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "profile_runtime_changed"):
                PREP.verify_profile("filesystem", root, paths, root / "workspace")

    @unittest.skipUnless(os.name == "posix", "private generation ownership requires Linux")
    def test_marker_is_atomic_and_old_or_unrelated_files_survive_failed_rebuild(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unrelated = root / "unrelated.txt"
            unrelated.write_text("keep")
            output = root / "output"
            before = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
            args = SimpleNamespace(output=output, expected_commit="a" * 40, rebuild=False,
                                   npm_cache=None, wheelhouse=None, python_archive=None, node_archive=None,
                                   allow_download=True, refusal_verdict="ask", refusal_rule="exact-rule")
            paths = {role: Path(os.sys.executable) for role in PREP.PILOT.ROLES}
            profiles = {kind: {"profile": {"path": str(root / kind), "sha256": "d" * 64},
                               "registry_sha256": "e" * 64, "package_tree_sha256": "f" * 64}
                        for kind in ("filesystem", "git")}

            def init_git(command, **_):
                (Path(command[-1]) / ".git").mkdir()

            with patch.object(PREP, "supported_platform"), patch.object(PREP.PILOT, "source", return_value=before), \
                 patch.object(PREP, "selected_paths", return_value=paths), \
                 patch.object(PREP, "verify_profile", side_effect=lambda kind, *_: profiles[kind]), \
                 patch.object(PREP, "verify_generation", side_effect=lambda gen, *_: (gen / "selection.json", profiles)), \
                 patch.object(PREP.subprocess, "run", side_effect=init_git), \
                 patch.object(PREP.FS, "install") as fs_install, patch.object(PREP.GIT, "install"):
                first = PREP.prepare(args)
                marker = json.loads((output / "current.json").read_text())
                self.assertEqual(first["status"], "prepared-not-active")
                self.assertIsNotNone(fs_install.call_args_list[0].kwargs["log"])
                self.assertEqual(stat.S_IMODE((output / "generations" / first["generation"] /
                                               "filesystem-install.log").stat().st_mode), 0o600)
                self.assertEqual(PREP.prepare(args)["status"], "reused")
                fs_install.side_effect = ValueError("interrupted_install")
                args.rebuild = True
                with self.assertRaisesRegex(ValueError, "interrupted_install"):
                    PREP.prepare(args)
                self.assertEqual(json.loads((output / "current.json").read_text()), marker)
                self.assertEqual(unrelated.read_text(), "keep")
                self.assertEqual(len(list((output / "generations").iterdir())), 2)


if __name__ == "__main__":
    unittest.main()
