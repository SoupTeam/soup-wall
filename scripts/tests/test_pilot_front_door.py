# SPDX-License-Identifier: Apache-2.0
"""Guided pilot entry point: positive and adversarial controls without a host.

These are public, local controls. Native first-use evidence is the separate
qualify-pilot-front-door.py run on Ubuntu 24.04.
"""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("pilot_front_door", ROOT / "scripts/pilot.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
COMMIT = "a" * 40


def clean_source():
    return {"commit": COMMIT, "tree": "b" * 40, "dirty": False}


class Prefix(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.temporary)]))

    def test_prefix_must_be_absolute_canonical_private_and_separate(self):
        good = self.temporary / "prefix"
        M.check_prefix(good, [])
        for bad, code in ((Path("relative"), "absolute_prefix_required"),
                          (ROOT / "pilot-state", "prefix_inside_checkout"),
                          (Path.home().resolve(), "home_directory_prefix_refused")):
            with self.assertRaises(M.Failure) as caught:
                M.check_prefix(bad, [])
            self.assertEqual(caught.exception.code, code)
        link = self.temporary / "link"
        link.symlink_to(self.temporary)
        with self.assertRaises(M.Failure) as caught:
            M.check_prefix(link / "prefix", [])
        self.assertEqual(caught.exception.code, "canonical_prefix_required")
        project = self.temporary / "project"
        project.mkdir()
        with self.assertRaises(M.Failure) as caught:
            M.check_prefix(self.temporary / "absent" / "prefix", [])
        self.assertEqual(caught.exception.code, "prefix_parent_must_exist")
        for overlapping in (project / "inside", self.temporary):
            with self.assertRaises(M.Failure) as caught:
                M.check_prefix(overlapping, [project])
            self.assertEqual(caught.exception.code, "prefix_overlaps_workspace")

    def test_both_workspaces_or_neither(self):
        args = argparse.Namespace(filesystem_workspace=Path("/a"), git_workspace=None)
        with self.assertRaises(M.Failure) as caught:
            M.roots(args)
        self.assertEqual(caught.exception.code, "both_workspaces_or_neither")


class State(unittest.TestCase):
    def setUp(self):
        self.prefix = Path(tempfile.mkdtemp()).resolve()
        os.chmod(self.prefix, 0o700)
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.prefix)]))
        prep = self.prefix / "preparation" / "generations" / ("c" * 32)
        prep.mkdir(parents=True)
        self.selection = prep / "selection.json"
        self.selection.write_text("{}")
        self.record = {"format": M.FORMAT, "commit": COMMIT, "selection": str(self.selection),
                       "selection_sha256": "d" * 64, "inputs": {}}
        M.write_state(self.prefix, self.record)
        (self.prefix / "preparation/current.json").write_text(json.dumps(
            {"format": "sw-pilot-preparation/1", "generation": "c" * 32, "selection_sha256": "d" * 64,
             "status": "prepared-not-active"}))

    def state(self):
        with mock.patch.object(M, "source", clean_source):
            return M.verified_state(self.prefix)

    def failure(self):
        with self.assertRaises(M.Failure) as caught:
            self.state()
        return caught.exception.code

    def test_current_record_is_accepted(self):
        self.assertEqual(self.state()["selection"], str(self.selection))
        self.assertEqual(os.stat(self.prefix / M.STATE).st_mode & 0o777, 0o600)

    def test_missing_stale_foreign_and_tampered_records_are_refused(self):
        (self.prefix / M.STATE).unlink()
        self.assertEqual(self.failure(), "not_prepared")
        M.write_state(self.prefix, dict(self.record, commit="e" * 40))
        self.assertEqual(self.failure(), "stale_source")
        (self.prefix / M.STATE).unlink()
        M.write_state(self.prefix, dict(self.record, selection_sha256="0" * 64))
        self.assertEqual(self.failure(), "selection_not_current")
        (self.prefix / M.STATE).unlink()
        M.write_state(self.prefix, dict(self.record, format="other/1"))
        self.assertEqual(self.failure(), "front_door_state_invalid")
        (self.prefix / M.STATE).unlink()
        M.write_state(self.prefix, self.record)
        os.chmod(self.prefix / M.STATE, 0o644)
        self.assertEqual(self.failure(), "front_door_state_invalid")
        os.chmod(self.prefix / M.STATE, 0o600)
        (self.prefix / M.STATE).write_text('{"format": "x", "format": "y"}')
        self.assertEqual(self.failure(), "front_door_state_invalid")
        (self.prefix / M.STATE).unlink()
        M.write_state(self.prefix, self.record)
        (self.prefix / "preparation/current.json").unlink()
        self.assertEqual(self.failure(), "selection_not_current")

    def test_dirty_checkout_is_refused(self):
        with mock.patch.object(M, "source", lambda: dict(clean_source(), dirty=True)):
            with self.assertRaises(M.Failure) as caught:
                M.verified_state(self.prefix)
        self.assertEqual(caught.exception.code, "dirty_source")


class Run(unittest.TestCase):
    """The front door delegates and preserves exact status and signals."""

    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.temporary)]))
        self.args = argparse.Namespace(prefix=self.temporary, timeout_seconds=180, ask_wait_seconds=0, port=0,
                                       state_root=None, prompt="Read notes.", json=False)
        self.state = {"selection": "/private/selection.json", "commit": COMMIT}

    def runner(self, body):
        script = self.temporary / "fake-pilot-run.py"
        script.write_text("import json, os, signal, sys, time\n" + body)
        return script

    def run_front_door(self, body):
        script = self.runner(body)
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch.object(M, "RUNNER", script), mock.patch.object(M, "verified_state", lambda _: self.state), \
                redirect_stdout(out), redirect_stderr(err):
            code = M.run(self.args)
        return code, out.getvalue(), err.getvalue()

    def test_arguments_are_the_original_bounded_list_without_a_shell(self):
        code, out, _ = self.run_front_door(
            "print(json.dumps({'status': 'completed', 'cleanup': 'owned_state_removed', 'argv': sys.argv[1:]}))\n")
        self.assertEqual(code, 0)
        argv = json.loads(out)["argv"]
        self.assertEqual(argv[:5], ["--run", "--selection", "/private/selection.json", "--expected-commit", COMMIT])
        self.assertEqual(argv[argv.index("--prompt") + 1], "Read notes.")

    def test_exact_nonzero_status_and_operator_hint(self):
        code, out, err = self.run_front_door(
            "print(json.dumps({'status': 'failed', 'reason': 'owned_daemon_not_ready'}))\nsys.exit(1)\n")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["reason"], "owned_daemon_not_ready")
        self.assertIn("No host was started", err)
        code, _, _ = self.run_front_door("sys.exit(3)\n")
        self.assertEqual(code, 3)

    def test_signal_death_is_propagated_with_the_same_signal(self):
        script = self.runner("os.kill(os.getpid(), signal.SIGTERM)\n")
        probe = self.temporary / "probe.py"
        probe.write_text(
            "import argparse, importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('m', {str(ROOT / 'scripts/pilot.py')!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            f"m.RUNNER = __import__('pathlib').Path({str(script)!r})\n"
            f"m.verified_state = lambda _: {{'selection': '/s', 'commit': {COMMIT!r}}}\n"
            "args = argparse.Namespace(prefix=None, timeout_seconds=1, ask_wait_seconds=0, port=0, state_root=None, prompt=None)\n"
            "sys.exit(m.run(args))\n")
        result = subprocess.run([sys.executable, "-B", str(probe)], capture_output=True, timeout=60)
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_terminate_is_forwarded_and_interrupt_is_left_to_the_supervisor(self):
        script = self.runner(
            "def stop(signum, _):\n"
            "    print(json.dumps({'status': 'failed', 'reason': 'pilot_cancelled', 'signal': signum})); sys.exit(1)\n"
            "signal.signal(signal.SIGTERM, stop)\n"
            "open(sys.argv[-1] if False else os.environ['READY'], 'w').close()\n"
            "time.sleep(30)\n")
        ready = self.temporary / "ready"
        probe = self.temporary / "probe.py"
        probe.write_text(
            "import argparse, importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('m', {str(ROOT / 'scripts/pilot.py')!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            f"m.RUNNER = __import__('pathlib').Path({str(script)!r})\n"
            f"m.verified_state = lambda _: {{'selection': '/s', 'commit': {COMMIT!r}}}\n"
            "args = argparse.Namespace(prefix=None, timeout_seconds=1, ask_wait_seconds=0, port=0, state_root=None, prompt=None)\n"
            "sys.exit(m.run(args))\n")
        process = subprocess.Popen([sys.executable, "-B", str(probe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=dict(os.environ, READY=str(ready)))
        for _ in range(200):
            if ready.exists():
                break
            __import__("time").sleep(.05)
        process.send_signal(signal.SIGINT)  # ignored by the front door itself
        __import__("time").sleep(.3)
        self.assertIsNone(process.poll())
        process.send_signal(signal.SIGTERM)
        out, _ = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(out.decode().splitlines()[-1])["signal"], signal.SIGTERM)

    def test_unprepared_run_fails_without_starting_anything(self):
        args = M.parser().parse_args(["run", "--prefix", str(self.temporary / "absent")])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("started")), \
                redirect_stdout(out), redirect_stderr(err):
            code = M.main(["run", "--prefix", str(self.temporary / "absent")])
        self.assertEqual(code, 1)
        report = json.loads(out.getvalue())
        self.assertEqual((report["reason"], report["executed"]), ("not_prepared", False))
        self.assertIn("prepare --apply", err.getvalue())
        self.assertTrue(args.prefix.is_absolute())


class Status(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.root)]))

    def run_dir(self, pids):
        directory = self.root / "soup-wall-run-abc"
        home = directory / ".agentfw"
        (home / "pilot-runs" / ("f" * 32)).mkdir(parents=True)
        (home / "pilot-runs" / ("f" * 32) / "run.json").write_text("{}")
        (home / "native-token").write_text("SECRET-TOKEN-MUST-NOT-APPEAR")
        (directory / "run.json").write_text(json.dumps({"format": "sw-prepared-pilot-run/1", "home": str(home),
            "supervisor_pid": pids[0], "launcher_pid": pids[1], "daemon_pid": pids[2], "port": 1}))
        return home

    def test_dead_run_is_unavailable_and_live_needs_an_authenticated_answer(self):
        self.run_dir([2 ** 22 + 1] * 3)
        rows = M.live_runs([self.root], Path("/bin/false"), "0" * 64)
        self.assertEqual(rows[0]["protection"], "unavailable")
        self.assertEqual(rows[0]["run_ids"], ["f" * 32])
        self.assertNotIn("SECRET-TOKEN", json.dumps(rows))
        subprocess.run(["rm", "-rf", str(self.root / "soup-wall-run-abc")])
        self.run_dir([os.getpid()] * 3)
        rows = M.live_runs([self.root], Path("/bin/false"), "0" * 64)
        self.assertEqual(rows[0]["protection"], "unavailable")
        rows = M.live_runs([self.root], None, None)
        self.assertEqual(rows[0]["protection"], "unknown")
        self.assertNotIn("SECRET-TOKEN", json.dumps(rows))

    def test_unreadable_or_foreign_record_is_unknown_not_live(self):
        directory = self.root / "soup-wall-run-xyz"
        directory.mkdir()
        (directory / "run.json").write_text("{not json")
        rows = M.live_runs([self.root], Path("/bin/true"), "0" * 64)
        self.assertEqual(rows[0]["protection"], "unknown")

    def test_human_status_lists_the_existing_stop_command(self):
        text = M.human({"command": "status", "protection": "observed-live", "meaning": "m",
                        "selection": {"state": "configured"},
                        "runs": [{"run_directory": "/r", "protection": "observed-live", "home": "/r/.agentfw",
                                  "run_ids": ["f" * 32]}]})
        self.assertIn("agentfw pilot-approval --home /r/.agentfw --run " + "f" * 32 + " stop", text)


class Preview(unittest.TestCase):
    def test_help_lists_every_path(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(M.main(["help"]), 0)
        for word in ("preview", "prepare", "run", "status"):
            self.assertIn(word, out.getvalue())

    def test_failure_messages_never_echo_raw_exceptions(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(M, "plan", side_effect=OSError("/secret/path token=abc")), \
                redirect_stdout(out), redirect_stderr(err):
            code = M.main(["preview", "--prefix", "/tmp/x"])
        self.assertEqual(code, 2)
        self.assertNotIn("secret", out.getvalue() + err.getvalue())
        self.assertNotIn("token", out.getvalue() + err.getvalue())

    def test_apply_is_explicit(self):
        calls = []
        with mock.patch.object(M, "plan", lambda args: calls.append("plan") or {"command": "preview", "missing": [],
                               "next": "n", "stages": [], "platform": {"supported": True, "reason": None},
                               "source": clean_source(), "prefix": {"path": "/p", "exists": False},
                               "workspaces": {"mode": "generated-demo"}}), \
                mock.patch.object(M, "prepare", side_effect=AssertionError("applied")), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(M.main(["prepare", "--prefix", "/tmp/x"]), 0)
        self.assertEqual(calls, ["plan"])

    def test_child_steps_cannot_auto_install_toolchains(self):
        seen = {}

        def fake(command, **kwargs):
            seen.update(kwargs["env"])
            return subprocess.CompletedProcess(command, 0, b'{"status": "plan"}\n', b"")
        with mock.patch.object(subprocess, "run", fake):
            self.assertEqual(M.child(["scripts/x.py"], timeout=1), (0, {"status": "plan"}))
        self.assertEqual(seen["RUSTUP_AUTO_INSTALL"], "0")


if __name__ == "__main__":
    unittest.main()
