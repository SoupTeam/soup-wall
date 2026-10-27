"""Private qualification failure evidence; no protected host or model calls."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installed_front_door_diagnostics", ROOT / "scripts/qualify-installed-front-door.py")
QUAL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(QUAL)


class ComponentResults(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(agentfw=Path("/owned/agentfw"), work=Path("/owned/work"),
                                    component_python=Path("/usr/bin/python3.12"))

    def result(self, stdout, stderr=b"", code=0):
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def test_normal_success_preserves_result_and_does_not_emit_failure_diagnostics(self):
        report = {}
        output = {"component": "a" * 64, "files": 49}
        with patch.object(QUAL.subprocess, "run", return_value=self.result(json.dumps(output).encode())) as run, \
                patch.object(QUAL, "interpreter_diagnostic") as probe:
            value = QUAL.install_component(self.args, Path("/owned/home"), Path("/owned/archive"),
                                           "b" * 64, output["component"], {"TOKEN": "not-for-report"}, report)
        self.assertEqual(value, output)
        self.assertEqual(report, {})
        probe.assert_not_called()
        self.assertEqual(run.call_args.args[0], [str(self.args.agentfw), "pilot-component", "--home",
                                                str(Path("/owned/home")), "install", str(Path("/owned/archive")),
                                                "--sha256", "b" * 64, "--python", str(self.args.component_python)])

    def test_non_object_invalid_and_oversized_stdout_cannot_establish_success(self):
        for raw, kind in [(b"[]", "non_object"), (b"null", "non_object"), (b"true", "non_object"),
                          (b'"text"', "non_object"), (b"bad", "invalid_json"),
                          (b'{"value":NaN}', "invalid_json"), (b'{"value":1e400}', "invalid_json"),
                          (b"", "empty"), (b"x" * (QUAL.COMPONENT_STDOUT_LIMIT + 1), "oversized")]:
            with self.subTest(kind=kind, prefix=raw[:30]):
                report = {}
                with patch.object(QUAL.subprocess, "run", return_value=self.result(raw)), \
                        patch.object(QUAL, "interpreter_diagnostic", return_value={"version_probe": {"status": "not_run"}}):
                    with self.assertRaisesRegex(Exception, "component_install_failed"):
                        QUAL.install_component(self.args, Path("/owned/home"), Path("/owned/archive"),
                                               "b" * 64, "a" * 64, {}, report)
                self.assertEqual(report["component_install_failure"]["stdout_kind"], kind)

    def test_failure_retains_exit_and_object_with_bounded_utf8_stderr_but_no_environment(self):
        report = {}
        output = {"error": "interpreter probe failed"}
        diagnostic = {"canonical": "/usr/bin/python3.12", "mode": "0o755", "uid": 0,
                      "version_probe": {"status": "completed", "exit": 127}}
        with patch.object(QUAL.subprocess, "run", return_value=self.result(
                json.dumps(output).encode(), b"\xff" * 8000, 2)), \
                patch.object(QUAL, "interpreter_diagnostic", return_value=diagnostic):
            with self.assertRaisesRegex(Exception, "component_install_failed"):
                QUAL.install_component(self.args, Path("/owned/home"), Path("/owned/archive"),
                                       "b" * 64, "a" * 64, {"TOKEN": "not-for-report"}, report)
        row = report["component_install_failure"]
        self.assertEqual(row["exit"], 2)
        self.assertEqual(row["stdout"], output)
        self.assertTrue(row["stderr_truncated"])
        self.assertLessEqual(len(row["stderr"].encode()), 4096)
        self.assertEqual(row["selected_python"], diagnostic)
        self.assertNotIn("not-for-report", json.dumps(report))

    def test_large_object_is_explicitly_omitted_from_private_diagnostics(self):
        diagnostic = {}
        with patch.object(QUAL.subprocess, "run", return_value=self.result(
                json.dumps({"error": "x" * 5000}).encode(), code=2)):
            code, value, _ = QUAL.component(self.args, Path("/owned/home"), None, None,
                                            "verify", env={}, diagnostic=diagnostic)
        self.assertEqual(code, 2)
        self.assertIn("error", value)
        self.assertTrue(diagnostic["stdout_omitted"])
        self.assertIsNone(diagnostic["stdout"])


@unittest.skipUnless(os.name == "posix", "Unix qualification interpreter metadata")
class InterpreterEvidence(unittest.TestCase):
    def test_group_writable_interpreter_is_not_executed_for_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            python = Path(temporary) / "python"
            python.write_text("must not execute")
            python.chmod(0o775)
            with patch.object(QUAL.subprocess, "run") as run:
                row = QUAL.interpreter_diagnostic(python)
        run.assert_not_called()
        self.assertEqual(row["mode"], "0o775")
        self.assertEqual(row["version_probe"], {"status": "not_run", "reason": "unprotected_interpreter"})

    def test_protected_interpreter_probe_is_fixed_and_environment_free(self):
        python = Path(sys.executable).resolve()
        with patch.object(QUAL.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"cpython 3 12 3\n", b"")) as run:
            row = QUAL.interpreter_diagnostic(python)
        self.assertEqual(row["canonical"], str(python))
        self.assertEqual(row["version_probe"]["exit"], 0)
        self.assertEqual(run.call_args.kwargs["env"], {})
        self.assertEqual(run.call_args.kwargs["cwd"], "/")
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertEqual(run.call_args.args[0], [str(python), "-I", "-S", "-c",
                                                "import sys;print(sys.implementation.name, *sys.version_info[:3])"])

    def test_probe_timeout_is_an_unavailable_observation_not_success(self):
        with patch.object(QUAL.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 5)):
            row = QUAL.interpreter_diagnostic(Path(sys.executable).resolve())
        self.assertEqual(row["version_probe"]["status"], "timeout")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux workflow shell")
class WorkflowInterpreter(unittest.TestCase):
    def test_native_component_uses_os_python_even_when_driver_is_hosted_group_writable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hosted = root / "hosted/bin"
            hosted.mkdir(parents=True)
            driver = hosted / "python3"
            capture_code = "import json,os,sys;open(os.environ['CAPTURE_ARGV'],'w').write(json.dumps(sys.argv[1:]))"
            driver.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I -c " + shlex.quote(capture_code) + ' "$@"\n')
            driver.chmod(0o775)
            for name in ("mcp-real-filesystem.yml", "ci-components.yml"):
                with self.subTest(workflow=name):
                    text = (ROOT / ".github/workflows" / name).read_text()
                    start = text.index("python3 -B scripts/qualify-installed-front-door.py --run")
                    end = text.index("2>&1 | tee", start)
                    command = text[start:end].rstrip().removesuffix("\\").rstrip()
                    capture = root / (name + ".json")
                    env = dict(os.environ, PATH=str(hosted) + ":/usr/bin:/bin", CAPTURE_ARGV=str(capture),
                               RUNNER_TEMP=str(root), SOU115_GIT="git-input", SOU111_BWRAP="bwrap-input",
                               SOU119_AGENTFW="agent-input", SOU119_GIT_LAUNCHER="launcher-input",
                               SOU119_SANDBOX_TESTS="tests-input")
                    result = subprocess.run(["/bin/bash", "-c", 'asset="$RUNNER_TEMP/assets"\n' + command],
                                            cwd=ROOT, env=env, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    words = json.loads(capture.read_text())
                    self.assertEqual(words[:2], ["-B", "scripts/qualify-installed-front-door.py"])
                    self.assertEqual(words[words.index("--component-python") + 1], "/usr/bin/python3.12")
                    self.assertNotEqual(words[words.index("--component-python") + 1], str(driver))


if __name__ == "__main__":
    unittest.main()
