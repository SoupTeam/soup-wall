# SPDX-License-Identifier: Apache-2.0
"""Failure boundaries for the two pinned native prerequisite builds."""
import importlib.util
from contextlib import contextmanager, nullcontext
import io
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
CONCURRENCY_WORKER = ROOT / "scripts/tests/fixtures/preparation_concurrency_worker.py"
SPEC = importlib.util.spec_from_file_location(
    "sou115_prerequisites", ROOT / "scripts/prepare-native-pilot-prerequisites.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


def args(root, *, prepare=True, rebuild=False):
    git, bwrap = root / "git.tar.xz", root / "bwrap.tar.xz"
    git.write_bytes(b"local git")
    bwrap.write_bytes(b"local bwrap")
    return SimpleNamespace(prepare=prepare, rebuild=rebuild, resume=False,
                           allow_download=False,
                           output=root / "private", expected_commit="a" * 40,
                           git_archive=git, bwrap_archive=bwrap,
                           pkg_config_libdir=None, pkg_config_sysroot=None,
                           meson_pythonpath=None)


class PreparationBoundary(unittest.TestCase):
    def test_composed_failure_retains_transfer_and_completed_build_evidence(self):
        progress = {"attempts": 1, "received_bytes": 7}
        failure = PREP.Failure("download_timeout", "download", progress=progress)
        failure.stages = {"git": {"status": "reused"}, "bwrap": {"status": "failed"}}
        record = PREP.failure_record(None, failure)
        self.assertEqual(record["download_progress"], progress)
        self.assertEqual(record["stages"], failure.stages)
        self.assertEqual(record["status"], "failed")
        self.assertIs(record["active_protection"], False)

    @unittest.skipUnless(os.name == "posix", "interpreter identity uses Linux file modes")
    def test_selected_interpreter_identity_accepts_hosted_toolcache_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            interpreter = Path(temporary) / "python"
            interpreter.write_bytes(b"selected interpreter fixture")
            interpreter.chmod(0o775)
            values = SimpleNamespace(git_archive=None, bwrap_archive=None,
                                     pkg_config_libdir=None, pkg_config_sysroot=None,
                                     meson_pythonpath=None)
            with patch.object(PREP.sys, "executable", str(interpreter)):
                first = PREP.execution_inputs(values)
                self.assertEqual(first["python"]["path"], str(interpreter))
                interpreter.write_bytes(b"changed interpreter fixture")
                self.assertNotEqual(PREP.execution_inputs(values), first)

    @unittest.skipUnless(os.name == "posix", "dependency links require Linux")
    def test_unresolved_package_link_is_bound_and_external_target_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            dependency = Path(temporary) / "selected"
            dependency.mkdir(mode=0o700)
            (dependency / "missing-link").symlink_to(dependency / "absent")
            values = SimpleNamespace(git_archive=None, bwrap_archive=None,
                                     pkg_config_libdir=None, pkg_config_sysroot=dependency,
                                     meson_pythonpath=None)
            before = PREP.execution_inputs(values)
            (dependency / "absent").write_bytes(b"now present")
            self.assertNotEqual(PREP.execution_inputs(values), before)
            external = Path(temporary) / "external"
            external.write_bytes(b"outside selected root")
            (dependency / "outside").symlink_to(external)
            with self.assertRaisesRegex(PREP.Failure, "dependency_link_escape"):
                PREP.execution_inputs(values)

    @unittest.skipUnless(os.name == "posix", "process signals require Linux")
    def test_cancelled_build_stops_owned_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "worker.py"
            worker.write_text('''import json, os, pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c",
    "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)",
    sys.argv[2]])
for _ in range(200):
    if pathlib.Path(sys.argv[2]).exists():
        break
    time.sleep(0.01)
if not pathlib.Path(sys.argv[2]).exists():
    raise RuntimeError("descendant was not ready")
pathlib.Path(sys.argv[1]).write_text(json.dumps({"worker": os.getpid(), "child": child.pid}))
''')
            helper = root / "helper.py"
            helper.write_text('''import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("preparation", sys.argv[1])
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)
root = pathlib.Path(sys.argv[2])
try:
    preparation.build([sys.executable, str(root / "worker.py"),
                       str(root / "pids.json"), str(root / "ready")],
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
                self.assertFalse(PREP.group_has_running_member(json.loads(pids.read_text())["worker"]),
                                 "a cancelled build must stop a SIGTERM-resistant descendant")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                if pids.exists():
                    try:
                        os.killpg(json.loads(pids.read_text())["worker"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(os.name == "posix", "process groups require Linux")
    def test_timeout_stops_resistant_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "worker.py"
            worker.write_text('''import json, os, pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c",
    "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)",
    sys.argv[2]])
for _ in range(200):
    if pathlib.Path(sys.argv[2]).exists():
        break
    time.sleep(0.01)
if not pathlib.Path(sys.argv[2]).exists():
    raise RuntimeError("descendant was not ready")
pathlib.Path(sys.argv[1]).write_text(json.dumps({"worker": os.getpid(), "child": child.pid}))
''')
            pids = root / "pids.json"
            try:
                with self.assertRaisesRegex(PREP.Failure, "owned_fixture_timeout"):
                    PREP.build([os.sys.executable, str(worker), str(pids), str(root / "ready")], cwd=root,
                               env={"PATH": "/usr/bin:/bin"}, log=root / "build.log",
                               seconds=1, stage="owned_fixture")
                self.assertTrue(pids.exists())
                self.assertFalse(PREP.group_has_running_member(json.loads(pids.read_text())["worker"]),
                                 "timeout must stop the descendant even after the leader exits")
            finally:
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
            meson = root / "meson-python"
            meson.mkdir(mode=0o700)
            module = meson / "reviewed_module.py"
            module.write_text("version = 1\n")
            values.meson_pythonpath = meson
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
                module.write_text("version = 2\n")
                with self.assertRaisesRegex(PREP.Failure, "receipt_execution_inputs_changed"):
                    PREP.prepare(values)
                self.assertEqual((values.output / "current.json").read_bytes(), marker)
                values.rebuild = True
                rebuilt = PREP.prepare(values)
                self.assertEqual(rebuilt["status"], "prepared-not-qualified")
                self.assertNotEqual(rebuilt["receipt"], first["receipt"])
                first = rebuilt
                marker = (values.output / "current.json").read_bytes()
                values.rebuild = False
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


@contextmanager
def staged_build_fixture(root):
    """Exercise the real publication path with bounded fake compiler outputs."""
    values = args(root)
    selected_tool = root / "selected-tool"
    selected_tool.write_bytes(b"selected native tool")
    selected_tool.chmod(0o700)
    library = root / "selected-library"
    library.write_bytes(b"selected runtime library")
    tools = {name: str(selected_tool) for name in PREP.TOOLS}
    calls = []
    state = {"fail_git": False, "fail_bwrap_once": True}

    def build(_command, *, cwd, env, log, seconds, stage):
        calls.append(stage)
        log.write_bytes((stage + "\n").encode())
        if stage == "git_build":
            if state["fail_git"]:
                raise PREP.Failure("controlled_git_cancellation", stage)
            binary = cwd / "git"
        elif stage == "bwrap_build":
            if state["fail_bwrap_once"]:
                state["fail_bwrap_once"] = False
                raise PREP.Failure("controlled_bwrap_failure", stage)
            binary = cwd / "bwrap-build/bwrap"
            binary.parent.mkdir(exist_ok=True)
        else:
            return
        binary.write_bytes(("verified " + stage).encode())
        binary.chmod(0o700)

    def captured(command, **_):
        if command[1] == "--help":
            return "--ro-bind-fd"
        return "git version 2.51.2" if command[0].endswith("/git") else "bubblewrap 0.13.1"

    def libraries(_binary, _tools):
        return {str(library): PREP.digest(library)}

    with patch.object(PREP, "platform_missing", return_value=[]), \
         patch.object(PREP, "tool_inventory", return_value=(tools, [])), \
         patch.object(PREP, "source_identity", side_effect=lambda expected: expected), \
         patch.object(PREP, "bounded_archive", side_effect=lambda path, _: path), \
         patch.object(PREP, "extract"), \
         patch.object(PREP, "build", side_effect=build), \
         patch.object(PREP, "captured", side_effect=captured), \
         patch.object(PREP, "native_libraries", side_effect=libraries):
        yield values, calls, state, selected_tool, library


@unittest.skipUnless(os.name == "posix", "owned stage checkpoints require Linux")
class CompletedGitStageRecovery(unittest.TestCase):
    def test_verified_git_stage_survives_bwrap_failure_and_retry_skips_git_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with staged_build_fixture(root) as (values, calls, _state, _tool, _library):
                with self.assertRaisesRegex(PREP.Failure, "controlled_bwrap_failure") as caught:
                    PREP.prepare(values)
                self.assertEqual(caught.exception.stages["git"]["status"], "built")
                self.assertEqual(caught.exception.stages["bwrap"]["status"], "failed")
                self.assertFalse((values.output / "current.json").exists())
                self.assertTrue((values.output / "git-stage-current.json").is_file())
                self.assertEqual(calls.count("git_build"), 1)

                values.resume = True
                result = PREP.prepare(values)
                self.assertEqual(result["status"], "prepared-not-qualified")
                self.assertEqual(result["stages"]["git"]["status"], "reused")
                self.assertEqual(result["stages"]["bwrap"]["status"], "built")
                self.assertTrue(math.isfinite(result["stages"]["git"]["seconds"]))
                self.assertGreaterEqual(result["stages"]["git"]["seconds"], 0)
                self.assertGreaterEqual(result["stages"]["bwrap"]["seconds"], 0)
                self.assertEqual(calls.count("git_build"), 1,
                                 "a complete verified Git stage must not be rebuilt")
                self.assertEqual(calls.count("bwrap_build"), 2)
                self.assertEqual(PREP.prepare(values)["status"], "reused")
                self.assertTrue(Path(result["git"]).is_file())
                self.assertTrue(Path(result["bwrap"]).is_file())

    def test_incomplete_git_build_has_no_reusable_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with staged_build_fixture(root) as (values, calls, state, _tool, _library):
                state["fail_git"] = True
                with self.assertRaisesRegex(PREP.Failure, "controlled_git_cancellation"):
                    PREP.prepare(values)
                self.assertFalse((values.output / "git-stage-current.json").exists())
                self.assertFalse((values.output / "current.json").exists())
                state["fail_git"] = False
                values.resume = True
                with self.assertRaisesRegex(PREP.Failure, "completed_git_stage_missing"):
                    PREP.prepare(values)
                self.assertEqual(calls.count("git_build"), 1)

    def test_changed_stage_binary_checkpoint_tool_library_and_recipe_refuse_reuse(self):
        for changed in ("binary", "checkpoint", "tool", "library", "source",
                        "recipe", "archive_pin"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with staged_build_fixture(root) as (values, calls, _state, tool, library):
                    with self.assertRaisesRegex(PREP.Failure, "controlled_bwrap_failure"):
                        PREP.prepare(values)
                    stage, = (values.output / "git-stages").iterdir()
                    if changed == "binary":
                        executable, = (entry for entry in stage.rglob("*")
                                       if entry.is_file() and os.access(entry, os.X_OK))
                        executable.chmod(0o700)
                        executable.write_bytes(b"tampered completed Git")
                        executable.chmod(0o500)
                    elif changed == "checkpoint":
                        receipt = stage / "receipt.json"
                        receipt.chmod(0o600)
                        receipt.write_bytes(b"{\n")
                        receipt.chmod(0o400)
                    elif changed == "tool":
                        tool.write_bytes(b"changed native tool")
                    elif changed == "library":
                        library.write_bytes(b"changed runtime library")
                    elif changed == "source":
                        values.expected_commit = "b" * 40
                    change_context = nullcontext()
                    if changed == "recipe":
                        change_context = patch.object(PREP, "GIT_FLAGS",
                                                      (*PREP.GIT_FLAGS, "CONTROLLED_RECIPE_DRIFT=1"))
                    elif changed == "archive_pin":
                        git_source = PREP.SOURCES["git"]
                        change_context = patch.object(PREP, "SOURCES",
                                                      {**PREP.SOURCES,
                                                       "git": (*git_source[:3], "f" * 64,
                                                               git_source[4])})
                    values.resume = True
                    with change_context:
                        with self.assertRaises(PREP.Failure):
                            PREP.prepare(values)
                    self.assertEqual(calls.count("git_build"), 1)
                    self.assertFalse((values.output / "current.json").exists())

    def test_unpublished_checkpoint_and_unsafe_stage_entries_are_not_adopted(self):
        for changed in ("missing_marker", "external_binary_link", "binary_fifo",
                        "too_many_entries"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with staged_build_fixture(root) as (values, calls, _state, _tool, _library):
                    with self.assertRaisesRegex(PREP.Failure, "controlled_bwrap_failure"):
                        PREP.prepare(values)
                    stage, = (values.output / "git-stages").iterdir()
                    if changed == "missing_marker":
                        marker = values.output / "git-stage-current.json"
                        marker.rename(values.output / ".interrupted-stage-marker")
                        expected = "completed_git_stage_missing"
                    elif changed in ("external_binary_link", "binary_fifo"):
                        executable, = (entry for entry in stage.rglob("*")
                                       if entry.is_file() and os.access(entry, os.X_OK))
                        stage.chmod(0o700)
                        executable.unlink()
                        if changed == "external_binary_link":
                            external = root / "foreign-executable"
                            external.write_bytes(b"foreign")
                            external.chmod(0o700)
                            executable.symlink_to(external)
                        else:
                            os.mkfifo(executable, 0o600)
                        stage.chmod(0o500)
                        expected = "completed_git_stage_invalid"
                    else:
                        stage.chmod(0o700)
                        for index in range(4):
                            (stage / f"unexpected-{index}").write_bytes(b"extra")
                        stage.chmod(0o500)
                        expected = "completed_git_stage_invalid"
                    values.resume = True
                    with patch.object(PREP, "captured",
                                      side_effect=AssertionError("invalid stage binary executed")):
                        with self.assertRaisesRegex(PREP.Failure, expected):
                            PREP.prepare(values)
                    self.assertEqual(calls.count("git_build"), 1)
                    self.assertFalse((values.output / "current.json").exists())

    def test_non_object_stage_marker_and_receipt_refuse_before_execution(self):
        for record in ("marker", "receipt"):
            for invalid in (b"[]\n", b"1\n"):
                with self.subTest(record=record, invalid=invalid), \
                     tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    with staged_build_fixture(root) as (values, calls, _state, _tool, _library):
                        with self.assertRaisesRegex(PREP.Failure, "controlled_bwrap_failure"):
                            PREP.prepare(values)
                        marker = values.output / "git-stage-current.json"
                        if record == "marker":
                            marker.write_bytes(invalid)
                        else:
                            stage, = (values.output / "git-stages").iterdir()
                            receipt = stage / "receipt.json"
                            receipt.chmod(0o600)
                            receipt.write_bytes(invalid)
                            receipt.chmod(0o400)
                            pointer = json.loads(marker.read_text())
                            pointer["receipt_sha256"] = PREP.digest(receipt)
                            marker.write_text(json.dumps(pointer) + "\n")
                        values.resume = True
                        with patch.object(PREP, "captured",
                                          side_effect=AssertionError("invalid stage executed")):
                            with self.assertRaisesRegex(PREP.Failure,
                                                        "completed_git_stage_invalid"):
                                PREP.prepare(values)
                        self.assertEqual(calls.count("git_build"), 1)
                        self.assertFalse((values.output / "current.json").exists())

    def test_failed_replacement_preserves_last_good_marker_until_resumed_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with staged_build_fixture(root) as (values, calls, state, _tool, _library):
                state["fail_bwrap_once"] = False
                first = PREP.prepare(values)
                self.assertEqual(first["stages"]["git"]["status"], "built")
                marker = (values.output / "current.json").read_bytes()
                values.rebuild = True
                state["fail_bwrap_once"] = True
                with self.assertRaisesRegex(PREP.Failure, "controlled_bwrap_failure"):
                    PREP.prepare(values)
                self.assertEqual((values.output / "current.json").read_bytes(), marker)
                values.resume = True
                second = PREP.prepare(values)
                self.assertEqual(second["stages"]["git"]["status"], "reused")
                self.assertNotEqual(second["receipt"], first["receipt"])
                self.assertNotEqual((values.output / "current.json").read_bytes(), marker)
                self.assertEqual(calls.count("git_build"), 2,
                                 "the resumed replacement must reuse its Git stage")
                self.assertEqual(calls.count("bwrap_build"), 3)


@unittest.skipUnless(sys.platform.startswith("linux"), "actual process locks require Linux")
class CompletedGitStageProcessRecovery(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "git.tar.xz").write_bytes(b"simulated pinned Git archive")
        (self.root / "bwrap.tar.xz").write_bytes(b"simulated pinned bubblewrap archive")
        self.output = self.root / "private"
        self.witness = self.root / "independent-git-build-invocations"
        self.processes = []
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def start(self, *, operation="build", failure="ok", gate=None, wait=0,
              contended=None):
        command = [sys.executable, "-B", str(CONCURRENCY_WORKER), "native",
                   str(self.output), str(self.witness), str(gate) if gate else "-",
                   "a", operation, str(wait), failure]
        environment = {**os.environ}
        if contended:
            environment["SIMULATED_CONTENDED_WITNESS"] = str(contended)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=environment)
        self.processes.append(process)
        return process

    def finished(self, process, code=0):
        stdout, stderr = process.communicate(timeout=12)
        self.assertEqual(process.returncode, code, stderr)
        self.assertEqual(len(stdout.splitlines()), 1, stdout)
        return json.loads(stdout)

    def wait_for_lines(self, path, count=1):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if path.exists() and len(path.read_text().splitlines()) >= count:
                return
            time.sleep(0.02)
        self.fail(f"the independent process witness did not reach {count}: {path.name}")

    def test_concurrent_resume_busy_wait_and_single_git_build(self):
        failure = self.finished(self.start(failure="fail-bwrap"), code=2)
        self.assertEqual(failure["reason"], "simulated_bwrap_failure")
        self.assertEqual(failure["stages"]["git"]["status"], "built")
        self.assertEqual(failure["stages"]["bwrap"]["status"], "failed")
        self.assertGreaterEqual(failure["stages"]["git"]["seconds"], 0)
        self.assertTrue((self.output / "git-stage-current.json").exists())
        self.assertFalse((self.output / "current.json").exists())
        self.wait_for_lines(self.witness)

        gate = self.root / "release-resumed-owner"
        owner = self.start(operation="resume", gate=gate)
        self.wait_for_lines(self.witness.with_name(self.witness.name + "-resumed-bwrap"))
        busy = self.finished(self.start(operation="resume"), code=3)
        self.assertEqual((busy["status"], busy["reason"]),
                         ("busy", "preparation_in_progress"))
        expired = self.finished(self.start(operation="resume", wait=0.2), code=3)
        self.assertEqual(expired["reason"], "bounded_wait_expired")
        contended = self.root / "waiter-actually-contended"
        waiter = self.start(operation="resume", wait=5, contended=contended)
        self.wait_for_lines(contended)
        self.assertEqual(len(self.witness.read_text().splitlines()), 1,
                         "only the first process may invoke simulated Git compilation")
        gate.touch()
        built = self.finished(owner)
        reused = self.finished(waiter)
        self.assertEqual(built["status"], "prepared-not-qualified")
        self.assertEqual(built["stages"]["git"]["status"], "reused")
        self.assertTrue(math.isfinite(built["stages"]["git"]["seconds"]))
        self.assertGreaterEqual(built["stages"]["git"]["seconds"], 0)
        self.assertEqual(reused["status"], "reused")
        self.assertTrue(reused["contended"])
        self.assertEqual(reused["receipt"], built["receipt"])
        self.assertEqual(len(self.witness.read_text().splitlines()), 1)

    def test_killed_resume_owner_releases_lock_and_retains_completed_git_stage(self):
        self.finished(self.start(failure="fail-bwrap"), code=2)
        gate = self.root / "never-release-resumed-owner"
        owner = self.start(operation="resume", gate=gate)
        self.wait_for_lines(self.witness.with_name(self.witness.name + "-resumed-bwrap"))
        owner.kill()
        owner.communicate(timeout=5)
        self.assertFalse((self.output / "current.json").exists())
        recovered = self.finished(self.start(operation="resume"))
        self.assertEqual(recovered["status"], "prepared-not-qualified")
        self.assertEqual(recovered["stages"]["git"]["status"], "reused")
        self.assertGreaterEqual(recovered["retained_interrupted_generations"], 2)
        self.assertEqual(len(self.witness.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
