# SPDX-License-Identifier: Apache-2.0
"""Diagnostic controls; simulated kernel metadata is not WSL acceptance."""
from pathlib import Path
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wsl_preflight as WSL


class WslPreflightControls(unittest.TestCase):
    def test_native_linux_and_wsl1_cannot_qualify_as_wsl2(self):
        self.assertEqual(WSL.kernel_kind("Linux", "6.8.0-generic"), "native_linux")
        self.assertEqual(WSL.kernel_kind("Linux", "4.4.0-Microsoft"), "wsl1_or_unknown")
        self.assertEqual(WSL.kernel_kind("Windows", "10"), "non_linux")
        self.assertEqual(WSL.kernel_kind("Linux", "6.6.87.2-microsoft-standard-WSL2"), "wsl2")

    def test_nested_windows_mount_is_not_misreported_as_root_ext4(self):
        mounts = ("1 0 8:1 / / rw - ext4 /dev/sda rw\n"
                  "2 1 0:2 / /home/user/windows rw - 9p drvfs rw\n"
                  "3 1 0:3 / /home/user/space\\040dir rw - cifs remote rw\n")
        self.assertEqual(WSL.mount_type("/home/user/private/run", mounts), "ext4")
        self.assertEqual(WSL.mount_type("/home/user/windows/tool", mounts), "9p")
        self.assertEqual(WSL.mount_type("/home/user/windows-copy/tool", mounts), "ext4")
        self.assertEqual(WSL.mount_type("/home/user/space dir/tool", mounts), "cifs")
        with self.assertRaises(ValueError):
            WSL.mount_type("/home/user", "malformed")

    def test_non_wsl_does_not_probe_or_claim_protection(self):
        with patch.object(WSL.platform, "system", return_value="Windows"), \
             patch.object(WSL, "probe") as probe:
            report = WSL.inspect(Path("unused"))
        probe.assert_not_called()
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["active_protection"], "not_measured")
        self.assertEqual(report["runtime_qualification"], "not_executed")

    def test_only_linux_ext4_and_home_stage_are_supported(self):
        for filesystem in ("9p", "drvfs", "cifs", "fuse", "overlay", "unknown"):
            self.assertFalse(WSL.supported_path("/home/user/private", filesystem, "stage_root"))
            self.assertFalse(WSL.supported_path("/usr/bin/node", filesystem, "node"))
        for path in ("/mnt/c/pilot", "/tmp/pilot", "/home-other/pilot"):
            self.assertFalse(WSL.supported_path(path, "ext4", "stage_root"))
            self.assertFalse(WSL.supported_path(path, "ext4", "report_output"))
        self.assertTrue(WSL.supported_path("/home/user/private", "ext4", "stage_root"))
        self.assertTrue(WSL.supported_path("/usr/bin/node", "ext4", "node"))

    @unittest.skipIf(WSL.kernel_kind(WSL.platform.system(), WSL.platform.release()) == "wsl2",
                     "This refusal control requires a non-WSL host")
    def test_actual_preflight_cli_refuses_non_wsl_without_creating_stage(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "never-created"
            driver = Path(__file__).resolve().parents[1] / "qualify-installed-pilot.py"
            result = subprocess.run([sys.executable, "-B", str(driver), "--wsl-preflight",
                                     "--wsl-root", str(stage)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "unsupported")
            self.assertEqual(report["runtime_qualification"], "not_executed")
            self.assertFalse(stage.exists())

    def test_probe_distinguishes_refusal_missing_executable_and_timeout(self):
        for result, expected in ((subprocess.CompletedProcess([], 0), "ready"),
                                 (subprocess.CompletedProcess([], 1), "incompatible")):
            with patch.object(WSL.subprocess, "run", return_value=result) as run:
                self.assertEqual(WSL.probe(["/selected/bwrap"]), expected)
                self.assertEqual(run.call_args.kwargs["timeout"], 5)
                self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
                self.assertNotIn("shell", run.call_args.kwargs)
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("probe", 5)):
            with patch.object(WSL.subprocess, "run", side_effect=error):
                self.assertEqual(WSL.probe(["/selected/bwrap"]), "unavailable")

    def test_selection_failures_are_actionable_without_leaking_input(self):
        import tempfile
        driver = Path(__file__).resolve().parents[1] / "qualify-installed-pilot.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection = root / "private-operator-selection.json"
            for content, status, reason in (
                (None, "unavailable", "selection_unreadable"),
                ('{"secret": "PRIVATE_VALUE",', "incompatible", "selection_invalid"),
                ('["PRIVATE_VALUE"]', "incompatible", "selection_invalid"),
                ('null', "incompatible", "selection_invalid"),
                ('42', "incompatible", "selection_invalid"),
                ('{"format": "wrong", "secret": "PRIVATE_VALUE"}', "incompatible", "selection_version"),
            ):
                if content is not None:
                    selection.write_text(content)
                result = subprocess.run([sys.executable, "-B", str(driver), "--wsl-preflight",
                    "--wsl-root", str(root), "--selection", str(selection),
                    "--expected-commit", "0" * 40], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 1)
                report = json.loads(result.stdout)
                self.assertEqual(report["status"], status)
                self.assertEqual(report["checks"][0]["reason"], reason)
                self.assertEqual(report["runtime_qualification"], "not_executed")
                self.assertEqual(result.stderr, "")
                self.assertNotIn("PRIVATE_VALUE", result.stdout)
                self.assertNotIn("private-operator-selection", result.stdout)

    def test_optional_budget_observations_never_advertise_enforcement(self):
        for writable, controllers, expected in (
            (False, "cpu memory pids", "unavailable"),
            (True, "cpu pids", "unavailable"),
            (True, "cpu memory pids", "ready"),
        ):
            with patch.object(WSL.Path, "read_text", side_effect=["0::/user.slice\n", controllers]), \
                 patch.object(WSL.os, "access", return_value=writable):
                report = WSL.resource_budget_prerequisites()
            self.assertEqual(report["status"], expected)
            self.assertFalse(report["advertised"])
            self.assertEqual(report["enforcement"], "not_measured")
        for content in ("1:cpu:/legacy\n", "0::/../outside\n"):
            with patch.object(WSL.Path, "read_text", return_value=content):
                self.assertEqual(WSL.resource_budget_prerequisites()["status"], "unavailable")
        with patch.object(WSL.Path, "read_text", side_effect=PermissionError):
            self.assertEqual(WSL.resource_budget_prerequisites()["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
