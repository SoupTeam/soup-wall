# SPDX-License-Identifier: Apache-2.0
"""Drift and unsupported-input controls for the pilot toolchain attestation (SOU-122)."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_pilot_toolchain", REPO / "scripts/verify-pilot-toolchain.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

RUSTC = """#!/bin/sh
cat <<OUT
rustc {release} ({commit} 2026-10-13)
binary: rustc
commit-hash: {full}
host: {host}
release: {release}
OUT
"""
CARGO = "#!/bin/sh\necho 'cargo {release} (abc 2026-10-13)'\n"


def copy(relative, root):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / relative, target)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name).resolve()
        self.root, self.bin = base / "repo", base / "bin"
        self.root.mkdir()
        self.bin.mkdir()
        self.pins = json.loads((REPO / "profiles/toolchain/linux-pilot-toolchain.json").read_text())
        files = ["profiles/toolchain/linux-pilot-toolchain.json", "rust-toolchain.toml", "Cargo.lock",
                 *self.pins["inputs"].values(), *self.pins["build_scripts"]]
        for name in set(files):
            copy(name, self.root)
        workflows = self.root / ".github/workflows"
        workflows.mkdir(parents=True)
        pinned, legacy = self.pins["rust"]["version"], self.pins["legacy_lane"]
        (workflows / "a.yml").write_text(f"steps:\n  - uses: dtolnay/rust-toolchain@{pinned}\n")
        (workflows / legacy["workflows"][0].split("/")[-1]).write_text(
            f"steps:\n  - uses: dtolnay/rust-toolchain@{legacy['version']}\n")
        for command in (["init", "-q"], ["add", "-A"],
                        ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(self.root), *command], check=True, capture_output=True)
        self.fake_tools()
        self.addCleanup(self.temporary.cleanup)

    def fake_tools(self, release=None, commit=None, host=None, cargo=None, rustc=True):
        rust = self.pins["rust"]
        for name in ("rustc", "cargo"):
            (self.bin / name).unlink(missing_ok=True)
        if rustc:
            body = RUSTC.format(release=release or rust["version"], commit=commit or rust["commit_prefix"],
                                full=(commit or rust["commit_prefix"]) + "0" * 31, host=host or rust["host"])
            self.write_exec("rustc", body)
        self.write_exec("cargo", CARGO.format(release=cargo or release or rust["version"]))

    def write_exec(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def attest(self, **overrides):
        values = dict(pins=self.root / "profiles/toolchain/linux-pilot-toolchain.json", root=self.root,
                      expected_commit=None, python=sys.executable, python_role="classifier", git_archive=None,
                      python_archive=None, allow_dirty=False, output=None)
        values.update(overrides)
        out = io.StringIO()
        with patch.dict(os.environ, {"PATH": f"{self.bin}:{os.environ['PATH']}"}), redirect_stdout(out):
            code = VERIFY.attest(type("Args", (), values))
        return code, json.loads(out.getvalue())

    def failed(self, report):
        return {c["check"]: c.get("detail", "") for c in report["checks"] if c["status"] == "fail"}

    def commit_change(self):
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "commit", "-qm", "y"], check=True, capture_output=True)


class Attestation(Fixture):
    def test_matching_inputs_are_verified_and_byte_equality_is_not_claimed(self):
        code, report = self.attest()
        self.assertEqual((code, report["status"]), (0, "verified"), self.failed(report))
        self.assertFalse(report["reproducibility"]["byte_for_byte"] is True)
        self.assertEqual(report["resolved"]["compiler"]["host"], "x86_64-unknown-linux-gnu")

    def test_floating_channel_is_refused(self):
        (self.root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\n')
        code, report = self.attest(allow_dirty=True)
        self.assertEqual(code, 2)
        self.assertIn("floating", self.failed(report)["toolchain-file"])

    def test_floating_or_unrecorded_workflow_refs_are_refused(self):
        (self.root / ".github/workflows/a.yml").write_text("- uses: dtolnay/rust-toolchain@stable\n")
        (self.root / ".github/workflows/b.yml").write_text("- uses: dtolnay/rust-toolchain@1.94.1\n")
        code, report = self.attest(allow_dirty=True)
        detail = self.failed(report)["workflow-toolchain-refs"]
        self.assertEqual(code, 2)
        self.assertIn("a.yml:1 @stable (floating)", detail)
        self.assertIn("b.yml:1 @1.94.1 (unrecorded)", detail)

    def test_compiler_drift_is_refused_for_release_commit_host_and_cargo(self):
        for kwargs, text in ((dict(release="1.99.0"), "is not the pinned"),
                             (dict(commit="deadbeef0"), "commit hash"),
                             (dict(host="aarch64-apple-darwin"), "host target"),
                             (dict(cargo="1.98.0"), "cargo 1.98.0")):
            self.fake_tools(**kwargs)
            code, report = self.attest()
            self.assertEqual(code, 2, kwargs)
            self.assertIn(text, self.failed(report)["compiler"])

    def test_missing_compiler_is_refused_without_installing(self):
        self.fake_tools(rustc=False)
        empty = Path(self.temporary.name) / "empty"
        empty.mkdir()
        out = io.StringIO()
        values = dict(pins=self.root / "profiles/toolchain/linux-pilot-toolchain.json", root=self.root,
                      expected_commit=None, python=sys.executable, python_role="classifier", git_archive=None,
                      python_archive=None, allow_dirty=False, output=None)
        git = shutil.which("git")
        with patch.dict(os.environ, {"PATH": f"{empty}:{Path(git).parent}"}), redirect_stdout(out):
            code = VERIFY.attest(type("Args", (), values))
        report = json.loads(out.getvalue())
        self.assertEqual(code, 2)
        self.assertIn("unavailable", self.failed(report)["compiler"])

    def test_interpreter_must_be_supplied_and_exist_and_match_role(self):
        code, report = self.attest(python=None)
        self.assertIn("required", self.failed(report)["interpreter"])
        code, report = self.attest(python="/nonexistent/python3")
        self.assertIn("existing absolute", self.failed(report)["interpreter"])
        code, report = self.attest(python=sys.executable, python_role="git_runtime")
        self.assertIn("is not the pinned 3.11.14", self.failed(report)["interpreter"])

    def test_old_classifier_interpreter_is_refused(self):
        pins = self.root / "profiles/toolchain/linux-pilot-toolchain.json"
        data = json.loads(pins.read_text())
        data["python"]["classifier"]["minimum_version"] = "99.0"
        pins.write_text(json.dumps(data))
        self.commit_change()
        code, report = self.attest()
        self.assertIn("older than 99.0", self.failed(report)["interpreter"])

    def test_dirty_tree_and_wrong_commit_are_refused(self):
        (self.root / "extra.txt").write_text("x")
        code, report = self.attest()
        self.assertIn("uncommitted", self.failed(report)["source"])
        (self.root / "extra.txt").unlink()
        code, report = self.attest(expected_commit="0" * 40)
        self.assertIn("not the expected commit", self.failed(report)["source"])
        code, report = self.attest(expected_commit="abc")
        self.assertIn("40 hex", self.failed(report)["source"])

    def test_pinned_input_digest_drift_is_refused(self):
        lock = self.root / self.pins["inputs"]["git_requirements_lock"]
        lock.write_text(lock.read_text() + "# drift\n")
        self.commit_change()
        code, report = self.attest()
        self.assertEqual(code, 2)
        self.assertIn("requirements.lock digest differs", self.failed(report)["pinned-inputs"])

    def test_supplied_archive_must_match_pinned_digest(self):
        archive = Path(self.temporary.name) / "git.tar.xz"
        archive.write_bytes(b"not the pinned archive")
        code, report = self.attest(git_archive=str(archive))
        self.assertIn("does not match its pinned digest", self.failed(report)["pinned-inputs"])

    def test_missing_build_script_and_lockfile_are_refused(self):
        (self.root / "scripts/prepare-installed-pilot.py").unlink()
        (self.root / "Cargo.lock").unlink()
        self.commit_change()
        code, report = self.attest()
        failed = self.failed(report)
        self.assertIn("prepare-installed-pilot.py", failed["build-scripts"])
        self.assertIn("lockfile", failed)

    def test_unsupported_pins_format_and_inexact_version_are_refused(self):
        pins = self.root / "profiles/toolchain/linux-pilot-toolchain.json"
        data = json.loads(pins.read_text())
        data["format"] = "other/9"
        pins.write_text(json.dumps(data))
        code, report = self.attest(allow_dirty=True)
        self.assertEqual((code, self.failed(report)), (2, {"pins": "pins_format_unsupported"}))
        data["format"], data["rust"]["version"] = "sw-pilot-toolchain-pins/1", "stable"
        pins.write_text(json.dumps(data))
        code, report = self.attest(allow_dirty=True)
        self.assertEqual(self.failed(report), {"pins": "pinned_rust_version_not_exact"})

    def test_commands_are_bounded_by_a_deadline(self):
        self.write_exec("slow", "#!/bin/sh\nsleep 30\n")
        code, text = VERIFY.run([str(self.bin / "slow")], timeout=1)
        self.assertIsNone(code)
        self.assertIn("timed out", text)

    def test_output_report_refuses_to_overwrite(self):
        target = Path(self.temporary.name) / "report.json"
        target.write_text("old")
        out = io.StringIO()
        with patch.dict(os.environ, {"PATH": f"{self.bin}:{os.environ['PATH']}"}), redirect_stdout(out):
            code = VERIFY.finish(VERIFY.Report(), 0.0, type("A", (), {"output": target}))
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(), "old")


class RepositoryPins(unittest.TestCase):
    def test_checked_in_pins_match_toolchain_file_and_workflows(self):
        pins = VERIFY.load_pins(REPO / "profiles/toolchain/linux-pilot-toolchain.json")
        report = VERIFY.Report()
        VERIFY.check_toolchain_file(report, REPO, pins)
        VERIFY.check_workflow_refs(report, REPO, pins)
        self.assertTrue(report.verified, report.checks)


if __name__ == "__main__":
    unittest.main()
