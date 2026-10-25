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
    """Status counts only a live run of the requested selection."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.processes = []
        self.addCleanup(self.cleanup)
        # A stand-in "agentfw": bash runs the subcommand file of the same name
        # from its working directory, keeping argv[0:2] as `agentfw SUBCOMMAND`.
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.agentfw = self.bin / "agentfw"
        self.agentfw.write_bytes(Path("/bin/bash").read_bytes())
        self.agentfw.chmod(0o755)
        self.runner = self.root / "fake-pilot-run.py"
        self.runner.write_text("import time\ntime.sleep(60)\n")
        self.policies = {}

    def cleanup(self):
        for process in self.processes:
            process.kill()
            process.wait()
        subprocess.run(["rm", "-rf", str(self.root)])

    def expected(self, name, workspace=None):
        prefix = self.root / name
        prefix.mkdir(exist_ok=True)
        policy = prefix / "policy.yaml"
        policy.write_text("default: allow # " + name + "\n")
        return {"selection": str(prefix / "selection.json"), "commit": COMMIT, "selection_sha256": "c" * 64,
                "agentfw": str(self.agentfw), "agentfw_sha256": "d" * 64,
                "policy": str(policy), "policy_sha256": M.sha(policy),
                "claude": str(prefix / "claude"), "registry_sha256": "e" * 64,
                "workspace": workspace or str(self.root / "project"), "git_workspace": str(self.root / "repo"),
                "fs_profile": str(prefix / "fs.json"), "git_profile": str(prefix / "git.json")}

    def start(self, words, cwd):
        process = subprocess.Popen(words, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        self.processes.append(process)
        return process.pid

    def live_run(self, name, identity, daemon_policy=None, registry=None):
        """Owned processes whose argv is exactly what pilot-run starts."""
        directory = self.root / ("soup-wall-run-" + name)
        home = directory / ".agentfw"
        (home / "pilot-runs" / ("f" * 32)).mkdir(parents=True)
        (home / "pilot-runs" / ("f" * 32) / "run.json").write_text("{}")
        (home / "native-token").write_text("SECRET-TOKEN-MUST-NOT-APPEAR")
        for script in ("pilot-launch", "serve"):
            (directory / script).write_text("sleep 60\n")
        supervisor = self.start([sys.executable, str(self.runner), "--run", "--selection", identity["selection"],
                                 "--expected-commit", identity["commit"]], directory)
        launcher = self.start([str(self.agentfw), "pilot-launch", "--claude", identity["claude"], "--agent-bin",
                               str(self.agentfw), "--home", str(home), "--workspace", identity["workspace"],
                               "--git-workspace", identity["git_workspace"], "--fs-profile", identity["fs_profile"],
                               "--git-profile", identity["git_profile"], "--policy", identity["policy"]], directory)
        daemon = self.start([str(self.agentfw), "serve"], directory)
        # The daemon's current configuration and an authenticated-query stand-in
        # that answers only for the daemon's actual registry.
        actual_registry = registry or identity["registry_sha256"]
        (home / "config.yaml").write_text(json.dumps({"enforce": True, "policy": daemon_policy or identity["policy"],
            "native": {"registry_sha256": actual_registry}}))
        snapshot = json.dumps({"snapshot": {"runtime": {"pid": daemon, "instance": "i-" + name},
                                            "policy": {"sha256": "9" * 64}}})
        (directory / "protection-status").write_text(f'[ "$8" = "{actual_registry}" ] || exit 2\necho \'{snapshot}\'\n')
        (directory / "run.json").write_text(json.dumps({"format": "sw-prepared-pilot-run/1", "home": str(home),
            "supervisor_pid": supervisor, "launcher_pid": launcher, "daemon_pid": daemon, "port": 1}))
        import time
        for _ in range(100):
            try:
                if all(M.argv(pid)[:1] for pid in (supervisor, launcher, daemon)) and len(M.argv(launcher)) > 3:
                    break
            except OSError:
                pass
            time.sleep(.02)
        return home

    def rows(self, expected):
        with mock.patch.object(M, "RUNNER", self.runner):
            return M.live_runs([self.root], expected)

    def test_live_run_of_this_selection_is_observed(self):
        a = self.expected("a")
        self.live_run("a", a)
        rows = self.rows(a)
        self.assertEqual((rows[0]["protection"], rows[0]["selection_match"]), ("observed-live", True))
        self.assertEqual(M.overall(rows, "configured"), "observed-live")
        self.assertNotIn("SECRET-TOKEN", json.dumps(rows))

    def test_another_prefix_live_run_never_proves_this_selection(self):
        a, b = self.expected("a"), self.expected("b")
        self.live_run("b", b)
        rows = self.rows(a)
        self.assertEqual(rows[0]["protection"], "unrelated")
        self.assertEqual(M.overall(rows, "configured"), "configured-not-running")

    def test_same_binary_with_another_policy_or_workspace_is_not_this_selection(self):
        a = self.expected("a")
        self.live_run("policy", dict(a, policy=str(self.root / "other-policy.yaml")))
        self.live_run("workspace", dict(a, workspace=str(self.root / "other-project")))
        rows = self.rows(a)
        self.assertEqual([row["protection"] for row in rows], ["unrelated", "unrelated"])
        self.assertEqual(M.overall(rows, "configured"), "configured-not-running")

    def test_matching_argv_but_different_enforced_policy_or_registry_is_unavailable_not_live(self):
        a = self.expected("a")
        other = self.expected("b")["policy"]
        self.live_run("policy", a, daemon_policy=other)
        self.live_run("registry", a, registry="0" * 64)
        rows = self.rows(a)
        self.assertEqual([(row["protection"], row["selection_match"]) for row in rows], [("unavailable", True)] * 2)
        self.assertEqual(M.overall(rows, "configured"), "unavailable")
        # Policy bytes changed after the run started: not live either.
        subprocess.run(["rm", "-rf", *[str(path) for path in self.root.glob("soup-wall-run-*")]])
        self.live_run("a", a)
        Path(a["policy"]).write_text("default: deny\n")
        self.assertEqual(self.rows(a)[0]["protection"], "unavailable")

    def test_dead_or_unreadable_records_are_never_live(self):
        directory = self.root / "soup-wall-run-dead"
        home = directory / ".agentfw"
        home.mkdir(parents=True)
        (directory / "run.json").write_text(json.dumps({"format": "sw-prepared-pilot-run/1", "home": str(home),
            "supervisor_pid": 2 ** 22 + 1, "launcher_pid": 2 ** 22 + 2, "daemon_pid": 2 ** 22 + 3, "port": 1}))
        broken = self.root / "soup-wall-run-broken"
        broken.mkdir()
        (broken / "run.json").write_text("{not json")
        rows = self.rows(self.expected("a"))
        self.assertEqual(sorted(row["protection"] for row in rows), ["unavailable", "unknown"])
        self.assertEqual(M.overall(rows, "configured"), "unknown")
        self.assertNotEqual(M.overall(rows, "configured"), "observed-live")

    def test_human_status_lists_the_existing_stop_command(self):
        text = M.human({"command": "status", "protection": "observed-live", "meaning": "m",
                        "selection": {"state": "configured"},
                        "runs": [{"run_directory": "/r", "protection": "observed-live", "home": "/r/.agentfw",
                                  "run_ids": ["f" * 32]}]})
        self.assertIn("agentfw pilot-approval --home /r/.agentfw --run " + "f" * 32 + " stop", text)


class Prepare(unittest.TestCase):
    def test_claude_install_never_runs_an_unverified_node_or_npm(self):
        temporary = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(temporary)]))
        marker = temporary / "marker"
        helper = temporary / "npm"
        helper.write_text(f"#!/bin/sh\ntouch {marker}\n")
        helper.chmod(0o755)
        archive = temporary / "node.tar.xz"
        archive.write_bytes(b"not the pinned archive")
        for inputs in ({"npm": helper, "node": helper}, {"node_archive": archive, "npm": helper}):
            with self.assertRaises(M.Failure) as caught:
                M.install_claude(inputs, temporary)
            self.assertEqual(caught.exception.code, "claude_install_requires_pinned_node_archive_or_supply_claude")
        self.assertFalse(marker.exists())

    def test_prepare_never_executes_the_supplied_host(self):
        """A helper with the right name and version output is never run by the
        front door; the accepted selection step decides from the pinned digest."""
        temporary = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(temporary)]))
        marker = temporary / "marker"
        helper = temporary / "claude"
        helper.write_text(f"#!/bin/sh\ntouch {marker}\necho '{M.CLAUDE_VERSION}'\n")
        helper.chmod(0o755)
        prefix = temporary / "prefix"
        words = ["prepare", "--apply", "--prefix", str(prefix), "--claude", str(helper)]
        for name in ("git", "bwrap", "agentfw", "git-launcher", "sandbox-tests", "node", "npm", "python"):
            words += ["--" + name, str(helper)]
        args = M.parser().parse_args(words)
        selection = prefix / "preparation/generations" / ("c" * 32) / "selection.json"
        report = {"command": "prepare", "missing": [], "source": clean_source(), "stages": []}

        def child(command, **_):
            # The real selection step would compare the pinned host digest here.
            selection.parent.mkdir(parents=True, exist_ok=True)
            selection.write_text("{}")
            return 0, {"status": "prepared-not-active", "selection": str(selection)}
        with mock.patch.object(M, "plan", lambda _: dict(report)), mock.patch.object(M, "child", child), \
                mock.patch.object(M.PREP, "private_dir", lambda path, create=False: path):
            result = M.prepare(args)
        self.assertEqual(result["status"], "prepared-not-active")
        self.assertFalse(marker.exists(), "the front door executed the supplied host")


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
