# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

SPEC = importlib.util.spec_from_file_location(
    "manual_gemini", Path(__file__).resolve().parents[1] / "sou218-manual-gemini.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ManualLauncherTests(unittest.TestCase):
    def test_ci_and_missing_terminal_refuse_before_build_or_credentials(self):
        with patch.object(MODULE.sys, "argv", ["manual", "--config", "unused"]), \
                patch.object(MODULE.sys, "platform", "linux"), \
                patch.object(MODULE.subprocess, "run") as run:
            with patch.dict(MODULE.os.environ, {"CI": "true"}, clear=True):
                with self.assertRaises(SystemExit):
                    MODULE.main()
            with patch.dict(MODULE.os.environ, {}, clear=True), \
                    patch("builtins.open", side_effect=OSError("no tty")):
                with self.assertRaises(SystemExit):
                    MODULE.main()
            run.assert_not_called()

    def test_only_exact_manual_child_inherits_terminal_and_config_path(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "operator.json"
            config.write_text("{}", encoding="utf-8")
            artifact = {"reason": "compiler-artifact", "target": {"name": "agentfw"},
                        "profile": {"test": True}, "executable": "/build/agentfw-test"}
            with patch.object(MODULE.sys, "argv", ["manual", "--config", str(config)]), \
                    patch.object(MODULE.sys, "platform", "linux"), \
                    patch.dict(MODULE.os.environ, {}, clear=True), \
                    patch("builtins.open", MagicMock()), \
                    patch.object(MODULE.subprocess, "run", side_effect=[
                        MagicMock(stdout=json.dumps(artifact)), MagicMock(returncode=0)
                    ]) as run:
                with self.assertRaises(SystemExit) as stopped:
                    MODULE.main()
                self.assertEqual(stopped.exception.code, 0)
                child = run.call_args_list[1]
                self.assertIn("--exact", child.args[0])
                self.assertIn("--ignored", child.args[0])
                self.assertEqual(child.args[0][1], "pilot-launch")
                self.assertNotIn("stdout", child.kwargs)
                self.assertNotIn("stdin", child.kwargs)
                self.assertEqual(child.kwargs["env"], {
                    "SOUP_WALL_GEMINI_MANUAL_CONFIG": str(config.resolve())})


if __name__ == "__main__":
    unittest.main()
