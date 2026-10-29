# SPDX-License-Identifier: Apache-2.0
"""The native qualification cannot substitute missing or simulated evidence."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("private_edit_qualification", ROOT / "scripts/qualify-private-edit-self-test.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class QualificationControls(unittest.TestCase):
    def seed(self):
        expected = {"source_commit": "a" * 40, "source_tree": "b" * 40,
                    "component_sha256": "c" * 64, "selection_sha256": "d" * 64,
                    "agentfw_sha256": "e" * 64}
        value = {"format": PROBE.SELF_TEST, "status": "passed", "executed": True,
            "paid_inference": False, "expected": list(PROBE.CASES),
            "cases": [{"id": name, "attempted": True, "status": "passed"} for name in PROBE.CASES],
            "cleanup": {"all_owned_processes_stopped": True, "workspace_removed": True, "workspace_retained": False},
            "preservation": {"installed_state_unchanged": True, "original_projects_unchanged": True,
                             "unrelated_sentinel_unchanged": True},
            "identities": {key: val for key, val in expected.items() if key != "agentfw_sha256"},
            "inventory": {"expected": 8, "attempted": 8, "passed": 8, "failed": 0, "incomplete": 0, "unsupported": 0},
            "platform": {"id": "native-linux-x86_64"}}
        value["identities"]["installed_sha256"] = {"agentfw": expected["agentfw_sha256"]}
        return value, expected

    def test_missing_failed_unattempted_or_reordered_native_cases_cannot_pass(self):
        value, expected = self.seed()
        self.assertTrue(PROBE.positive_report(value, expected))
        for index in range(len(PROBE.CASES)):
            for field, bad in (("status", "incomplete"), ("status", "failed"), ("attempted", False)):
                changed = copy.deepcopy(value)
                changed["cases"][index][field] = bad
                self.assertFalse(PROBE.positive_report(changed, expected))
            changed = copy.deepcopy(value)
            changed["cases"].pop(index)
            self.assertFalse(PROBE.positive_report(changed, expected))
        changed = copy.deepcopy(value)
        changed["cases"].reverse()
        self.assertFalse(PROBE.positive_report(changed, expected))

    def test_cleanup_preservation_platform_and_exact_identity_are_required(self):
        value, expected = self.seed()
        for section in ("cleanup", "preservation"):
            for key in value[section]:
                changed = copy.deepcopy(value)
                changed[section][key] = not changed[section][key]
                self.assertFalse(PROBE.positive_report(changed, expected))
        for key in expected:
            changed_expected = dict(expected, **{key: "0" * len(expected[key])})
            self.assertFalse(PROBE.positive_report(value, changed_expected))
        changed = copy.deepcopy(value)
        changed["platform"]["id"] = "wsl2-linux-x86_64"
        self.assertFalse(PROBE.positive_report(changed, expected))
        changed = copy.deepcopy(value)
        changed["inventory"]["attempted"] -= 1
        self.assertFalse(PROBE.positive_report(changed, expected))
        for section in ("cleanup", "preservation", "identities", "inventory", "platform"):
            changed = copy.deepcopy(value)
            changed[section] = "malformed"
            self.assertFalse(PROBE.positive_report(changed, expected))

    def test_default_is_inert_without_paths_or_permission(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/qualify-private-edit-self-test.py")],
            capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertFalse(value["executed"])
        self.assertEqual(value["checks"], list(PROBE.CHECKS))
        self.assertNotIn("status", value)

    def test_summary_requires_all_controls_and_unchanged_selected_inputs(self):
        value = {"format": PROBE.FORMAT, "status": "passed", "selected_inputs_unchanged": True,
                 "checks": [{"id": name, "attempted": True, "status": "passed"} for name in PROBE.CHECKS]}
        self.assertTrue(PROBE.passed(value))
        for index in range(len(PROBE.CHECKS)):
            changed = copy.deepcopy(value)
            changed["checks"][index]["attempted"] = False
            self.assertFalse(PROBE.passed(changed))
        value["selected_inputs_unchanged"] = False
        self.assertFalse(PROBE.passed(value))

    def test_explicit_wsl_report_never_substitutes_for_native_evidence(self):
        value, expected = self.seed()
        self.assertFalse(PROBE.positive_report(value, expected, platform_id=PROBE.WSL_PROFILE))
        value["platform"]["id"] = PROBE.WSL_PROFILE
        self.assertFalse(PROBE.positive_report(value, expected))
        self.assertTrue(PROBE.positive_report(value, expected, platform_id=PROBE.WSL_PROFILE))
        self.assertFalse(PROBE.positive_report(value, expected, platform_id="wsl1_or_unknown"))
        value["cases"][0]["status"] = "failed"
        self.assertFalse(PROBE.positive_report(value, expected, platform_id=PROBE.WSL_PROFILE))

    def test_actual_kernel_and_explicit_opt_in_are_both_required_before_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            selected_root = Path(temporary).resolve()
            for kernel, root, expected in (
                    (b"6.18.54-microsoft-standard-WSL2\n", None, "native_linux_required_wsl_is_separate"),
                    (b"4.4.0-microsoft\n", selected_root, "explicit_wsl2_kernel_required"),
                    (b"6.8.0-generic\n", selected_root, "explicit_wsl2_kernel_required")):
                args = SimpleNamespace(wsl_root=root)
                with self.subTest(kernel=kernel), mock.patch.object(PROBE.platform, "system", return_value="Linux"), \
                        mock.patch.object(PROBE.platform, "machine", return_value="x86_64"), \
                        mock.patch.object(PROBE.os, "geteuid", return_value=1000, create=True), \
                        mock.patch.object(PROBE, "bounded_file", return_value=kernel), \
                        mock.patch.object(PROBE, "Driver") as install:
                    with self.assertRaisesRegex(ValueError, expected):
                        PROBE.qualify(args, {})
                    install.assert_not_called()
            with mock.patch.object(PROBE.platform, "system", return_value="Linux"), \
                    mock.patch.object(PROBE.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(PROBE.os, "geteuid", return_value=1000, create=True), \
                    mock.patch.object(PROBE, "bounded_file", return_value=b"6.18.54-microsoft-standard-WSL2\n"):
                observed = PROBE.environment_profile(SimpleNamespace(wsl_root=selected_root))
            self.assertEqual(observed["id"], PROBE.WSL_PROFILE)
            self.assertTrue(observed["wsl_opt_in"])
            self.assertRegex(observed["kernel_sha256"], "^[0-9a-f]{64}$")

    def test_wsl_preflight_follows_accepted_generation_validation_and_refuses_failure(self):
        args = SimpleNamespace(run=True, selection=Path("selection.json"), agentfw=Path("agentfw"),
                               python=Path("python"), wsl_root=Path("stage"), output=Path("out"))
        order = []
        pilot = SimpleNamespace(PREP=SimpleNamespace(PILOT=SimpleNamespace(source=lambda: {
            "dirty": False, "commit": "a" * 40})))
        def selected(value):
            self.assertEqual(value.expected_commit, "a" * 40)
            order.append("accepted-generation")
            return {}, {"agentfw": args.agentfw, "bwrap": Path("bwrap")}, {}
        pilot.selected = selected
        def inspect(root, paths, *, output):
            order.append("namespace-preflight")
            self.assertEqual(root, args.wsl_root)
            self.assertEqual(output, args.output)
            self.assertEqual(paths["helper_python"], args.python)
            self.assertEqual(paths["selection"], args.selection)
            self.assertEqual(paths["source"], PROBE.Path(PROBE.__file__).resolve())
            return {"status": "unsupported", "checks": [{"id": "filesystem_source", "status": "unsupported"}]}
        wsl = SimpleNamespace(inspect=inspect)
        report = {"wsl": {"attested": False}}
        with mock.patch.object(PROBE, "load", side_effect=[pilot, wsl]), \
                mock.patch.object(PROBE, "Driver") as install:
            with self.assertRaisesRegex(ValueError, "wsl_prerequisites_not_ready"):
                PROBE.attest_wsl(args, report)
            install.assert_not_called()
        self.assertEqual(order, ["accepted-generation", "namespace-preflight"])
        self.assertFalse(report["wsl"]["attested"])
        self.assertEqual(report["wsl"]["preflight_status"], "unsupported")
        self.assertRegex(report["wsl"]["preflight_sha256"], "^[0-9a-f]{64}$")
        self.assertNotIn("filesystem_source", json.dumps(report))
        args.run = False
        with mock.patch.object(PROBE, "load") as loader:
            with self.assertRaisesRegex(ValueError, "explicit_run_consent_required"):
                PROBE.attest_wsl(args, report)
            loader.assert_not_called()

    def test_wsl_pass_requires_attestation_and_unchanged_host_settings(self):
        value = {"format": PROBE.FORMAT, "status": "passed", "selected_inputs_unchanged": True,
                 "checks": [{"id": name, "attempted": True, "status": "passed"} for name in PROBE.CHECKS],
                 "platform": {"id": PROBE.WSL_PROFILE, "wsl_opt_in": True},
                 "wsl": {"attested": True, "accepted_prepared_selection": True,
                         "preflight_status": "ready", "preflight_sha256": "a" * 64,
                         "host_settings_before_sha256": "b" * 64, "host_settings_after_sha256": "b" * 64}}
        self.assertTrue(PROBE.passed(value))
        for key, bad in (("attested", False), ("accepted_prepared_selection", False),
                         ("preflight_status", "unsupported"), ("preflight_sha256", None),
                         ("host_settings_after_sha256", "c" * 64)):
            changed = copy.deepcopy(value)
            changed["wsl"][key] = bad
            self.assertFalse(PROBE.passed(changed))
        value["platform"]["wsl_opt_in"] = False
        self.assertFalse(PROBE.passed(value))
        witness = SimpleNamespace(host_settings=lambda: {"/etc/wsl.conf": "private-config-hash"})
        with mock.patch.object(PROBE, "load", return_value=witness):
            observed = PROBE.host_settings_digest()
        self.assertRegex(observed, "^[0-9a-f]{64}$")
        self.assertNotIn("private-config", observed)

    def test_wsl_flag_without_run_remains_inert_and_never_loads_probe_helpers(self):
        with mock.patch.object(PROBE, "load") as loader, \
                mock.patch.object(PROBE.subprocess, "Popen") as process, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(PROBE.main(["--wsl-root", "nonexistent-stage"]), 0)
        self.assertFalse(json.loads(output.getvalue())["executed"])
        loader.assert_not_called()
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
