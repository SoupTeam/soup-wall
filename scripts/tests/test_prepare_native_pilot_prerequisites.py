# SPDX-License-Identifier: Apache-2.0
"""Failure boundaries for the two pinned native prerequisite builds."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "sou115_prerequisites", ROOT / "scripts/prepare-native-pilot-prerequisites.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


def args(root, *, prepare=True, rebuild=False):
    git, bwrap = root / "git.tar.xz", root / "bwrap.tar.xz"
    git.write_bytes(b"local git")
    bwrap.write_bytes(b"local bwrap")
    return SimpleNamespace(prepare=prepare, rebuild=rebuild, allow_download=False,
                           output=root / "private", expected_commit="a" * 40,
                           git_archive=git, bwrap_archive=bwrap,
                           pkg_config_libdir=None, pkg_config_sysroot=None,
                           meson_pythonpath=None)


class PreparationBoundary(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "process signals require Linux")
    def test_cancelled_build_stops_owned_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "worker.py"
            worker.write_text('''import json, os, pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c",
    "import pathlib,sys,time; time.sleep(1.5); pathlib.Path(sys.argv[1]).write_text('escaped')",
    sys.argv[2]])
pathlib.Path(sys.argv[1]).write_text(json.dumps({"worker": os.getpid(), "child": child.pid}))
time.sleep(30)
''')
            helper = root / "helper.py"
            helper.write_text('''import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("preparation", sys.argv[1])
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)
root = pathlib.Path(sys.argv[2])
try:
    preparation.build([sys.executable, str(root / "worker.py"),
                       str(root / "pids.json"), str(root / "escaped")],
                      cwd=root, env={"PATH": "/usr/bin:/bin"},
                      log=root / "build.log", seconds=30, stage="build")
except preparation.Failure as error:
    print(error.reason)
''')
            process = subprocess.Popen([os.sys.executable, str(helper),
                                        str(ROOT / "scripts/prepare-native-pilot-prerequisites.py"),
                                        str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True)
            pids = root / "pids.json"
            try:
                deadline = time.monotonic() + 5
                while not pids.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(pids.exists(), "the owned descendant must have started")
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertIn("build_cancelled", stdout)
                time.sleep(1.7)
                self.assertFalse((root / "escaped").exists(),
                                 "a cancelled build must not leave its descendant running")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                if pids.exists():
                    try:
                        os.killpg(json.loads(pids.read_text())["worker"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(os.name == "posix", "POSIX symlink modes require Linux")
    def test_frozen_generation_accepts_internal_symlink_and_rejects_changed_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "generation"
            generation.mkdir(mode=0o700)
            target = generation / "target"
            target.write_text("original")
            (generation / "link").symlink_to("target")
            before = PREP.tree_digest(generation)
            PREP.freeze(generation)
            self.assertEqual(PREP.tree_digest(generation, completed=True), before)
            target.chmod(0o600)
            target.write_text("changed")
            target.chmod(0o400)
            self.assertNotEqual(PREP.tree_digest(generation, completed=True), before)

    def test_plan_is_read_only_and_reports_exact_missing_build_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = args(root, prepare=False)
            with patch.object(PREP, "platform_missing", return_value=[]), \
                 patch.object(PREP, "tool_inventory", return_value=({}, [
                     {"dependency": "libcap", "install": "libcap-dev"}])):
                plan = PREP.prepare(values)
            self.assertEqual(plan["status"], "plan")
            self.assertFalse(plan["executed"])
            self.assertIn("libcap: install libcap-dev", plan["missing"])
            self.assertFalse(values.output.exists())
            self.assertEqual(plan["pins"]["git"]["sha256"], PREP.SOURCES["git"][3])

    def test_missing_dependency_and_bad_digest_never_create_build_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = args(root)
            with patch.object(PREP, "platform_missing", return_value=[]), \
                 patch.object(PREP, "tool_inventory", return_value=({}, [
                     {"dependency": "zlib", "install": "zlib1g-dev"}])):
                with self.assertRaisesRegex(PREP.Failure, "missing_prerequisites"):
                    PREP.prepare(values)
            self.assertFalse(values.output.exists())
            with self.assertRaisesRegex(PREP.Failure, "git_archive_digest_mismatch"):
                PREP.bounded_archive(values.git_archive, "git")

    def test_extraction_rejects_traversal_links_special_files_and_duplicate_paths(self):
        cases = (
            [("git-2.51.2/../outside", tarfile.REGTYPE, "")],
            [("git-2.51.2/bad", tarfile.SYMTYPE, "../../outside")],
            [("git-2.51.2/fifo", tarfile.FIFOTYPE, "")],
            [("git-2.51.2/dup", tarfile.REGTYPE, ""),
             ("git-2.51.2/dup", tarfile.REGTYPE, "")],
            [("git-2.51.2/link", tarfile.SYMTYPE, "target"),
             ("git-2.51.2/link/child", tarfile.REGTYPE, "")],
        )
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive, destination = root / "source.tar.xz", root / "source"
                destination.mkdir()
                with tarfile.open(archive, "w:xz") as bundle:
                    for name, kind, link in entries:
                        member = tarfile.TarInfo(name)
                        member.type, member.linkname = kind, link
                        if kind == tarfile.REGTYPE:
                            member.size = 1
                            bundle.addfile(member, io.BytesIO(b"x"))
                        else:
                            bundle.addfile(member)
                with self.assertRaises(PREP.Failure):
                    PREP.extract(archive, destination, "git")
                self.assertFalse((root / "outside").exists())

    @unittest.skipUnless(os.name == "posix", "process group controls require Linux")
    def test_failed_and_timed_out_build_leave_bounded_private_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, code, seconds in (("failure", "raise SystemExit(7)", 5),
                                         ("timeout", "import time; time.sleep(30)", 1)):
                with self.subTest(label=label):
                    log = root / (label + ".log")
                    with self.assertRaises(PREP.Failure) as caught:
                        PREP.build([os.sys.executable, "-c", code], cwd=root,
                                   env={"PATH": "/usr/bin:/bin"}, log=log,
                                   seconds=seconds, stage=label)
                    self.assertIn(label, caught.exception.reason)
                    self.assertLessEqual(log.stat().st_size, PREP.MAX_LOG)
                    self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "owned POSIX generations require Linux")
    def test_failed_rebuild_and_tampered_cache_preserve_marker_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = args(root)
            unrelated = root / "unrelated.txt"
            unrelated.write_text("keep")
            tools = {name: str(Path(os.sys.executable).resolve()) for name in PREP.TOOLS}

            def build(command, *, cwd, env, log, seconds, stage):
                log.write_bytes(b"build\n")
                if stage == "git_build":
                    binary = cwd / "git"
                elif stage == "bwrap_build":
                    binary = cwd / "bwrap-build/bwrap"
                    binary.parent.mkdir(exist_ok=True)
                else:
                    return
                binary.write_bytes(b"verified " + stage.encode())
                binary.chmod(0o700)

            def version(command, **_):
                if command[1] == "--help":
                    return "--ro-bind-fd"
                return "git version 2.51.2" if command[0].endswith("/git") else "bubblewrap 0.13.1"

            with patch.object(PREP, "platform_missing", return_value=[]), \
                 patch.object(PREP, "tool_inventory", return_value=(tools, [])), \
                 patch.object(PREP, "source_identity", return_value="a" * 40), \
                 patch.object(PREP, "bounded_archive", side_effect=lambda path, _: path), \
                 patch.object(PREP, "extract"), patch.object(PREP, "build", side_effect=build) as builder, \
                 patch.object(PREP, "captured", side_effect=version), \
                 patch.object(PREP, "native_libraries", return_value={}):
                first = PREP.prepare(values)
                self.assertEqual(first["status"], "prepared-not-qualified")
                marker = (values.output / "current.json").read_bytes()
                self.assertEqual(PREP.prepare(values)["status"], "reused")
                values.rebuild = True
                builder.side_effect = PREP.Failure("interrupted_build", "git_build")
                with self.assertRaisesRegex(PREP.Failure, "interrupted_build"):
                    PREP.prepare(values)
                self.assertEqual((values.output / "current.json").read_bytes(), marker)
                self.assertEqual(unrelated.read_text(), "keep")
                git = Path(first["git"])
                git.chmod(0o700)
                git.write_bytes(b"tampered")
                values.rebuild = False
                with self.assertRaisesRegex(PREP.Failure, "generation_tree_changed|completed_generation_writable"):
                    PREP.prepare(values)
                self.assertEqual((values.output / "current.json").read_bytes(), marker)


if __name__ == "__main__":
    unittest.main()
