"""Process-level local feedback controls; no hosted status or provider calls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/local_pr_verify.py"
sys.path.insert(0, str(ROOT / "scripts"))
import local_pr_verify as VERIFY  # noqa: E402


class LocalPrVerify(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sou206-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Synthetic Contributor")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n')
        self.write("Cargo.lock", "# synthetic locked input\n")
        for name in ("sou91_ruleset_patch", "ci_activation", "ci_impact"):
            self.write(f"scripts/{name}.py", (ROOT / "scripts" / f"{name}.py").read_text(encoding="utf-8"))
        self.write("scripts/check_docs.py", "from pathlib import Path\nimport sys\n"
                   "sys.exit(1 if 'broken' in Path('docs/guide.md').read_text() else 0)\n")
        self.write("scripts/tests/test_check_docs.py", "import unittest\n"
                   "class Docs(unittest.TestCase):\n    def test_fixture(self): self.assertTrue(True)\n")
        self.write("scripts/tests/test_ci_impact.py", "import unittest\n"
                   "class CI(unittest.TestCase):\n    def test_fixture(self): self.assertTrue(True)\n")
        self.write("docs/guide.md", "# Good\n")
        self.write("eval/sample.py", "answer = 1\n")
        self.commit("fixture base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("docs/guide.md", "# Updated public guide\n")
        self.write("eval/sample.py", "answer = 2\n")
        self.commit("public docs and Python")

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True,
                                text=True, timeout=10, check=True)
        return result.stdout

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "-qm", message)

    def command(self, mode, *extras):
        return [sys.executable, str(RUNNER), mode, "--repo", str(self.repo),
                "--base", self.base, "--head", "HEAD", *extras]

    def invoke(self, mode, *extras):
        result = subprocess.run(self.command(mode, *extras), capture_output=True,
                                text=True, timeout=30)
        return result, json.loads(result.stdout)

    def test_plan_is_read_only_and_names_remote_gates(self):
        before = self.git("status", "--porcelain")
        result, plan = self.invoke("plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(plan["impact_mode"], "docs+python")
        self.assertEqual(plan["source_contract"]["rust_channel"], "1.99.1")
        self.assertIn("Analyze (rust)", plan["remote_required"]["codeql"])
        self.assertFalse(plan["github_status_posted"])
        self.assertFalse(plan["trusted_admission"])
        self.assertFalse(plan["full_qualification"])
        self.assertEqual(self.git("status", "--porcelain"), before)

    def test_valid_public_change_runs_checks_and_preserves_dirty_checkout(self):
        self.write("local-notes.txt", "my uncommitted note\n")
        self.write("docs/guide.md", "# Staged draft\n")
        self.git("add", "docs/guide.md")
        self.write("docs/guide.md", "# Unstaged draft\n")
        staged = self.git("show", ":docs/guide.md")
        dirty_status = self.git("status", "--porcelain")
        saved = Path(self.temp.name) / "private-report.json"
        result, report = self.invoke("run", "--report-json", str(saved))
        self.assertEqual(result.returncode, 0, report)
        self.assertTrue(report["dirty_worktree_excluded"])
        self.assertEqual((report["counts"]["selected"], report["counts"]["passed"]), (4, 4))
        self.assertEqual(report["counts"]["executed"], 4)
        self.assertEqual(report["counts"]["skipped"], 4)
        self.assertEqual((self.repo / "local-notes.txt").read_text(), "my uncommitted note\n")
        self.assertEqual((self.repo / "docs/guide.md").read_text(), "# Unstaged draft\n")
        self.assertEqual(self.git("show", ":docs/guide.md"), staged)
        self.assertEqual(self.git("status", "--porcelain"), dirty_status)
        self.assertEqual(json.loads(saved.read_text()), report)
        if os.name == "posix":
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertFalse(report["full_qualification"])
        self.assertTrue(report["remote_required"]["workflows"])

    def test_real_failing_python_syntax_is_not_success(self):
        self.write("eval/sample.py", "def broken(:\n")
        self.commit("broken Python regression")
        result, report = self.invoke("run")
        self.assertEqual(result.returncode, 2)
        check = next(item for item in report["checks"] if item["name"] == "python_syntax")
        self.assertEqual((check["status"], check["reason"]), ("failed", "exit_nonzero"))
        self.assertFalse(report["local_checks_passed"])
        self.assertFalse(report["full_qualification"])

    def test_missing_pinned_toolchain_is_unavailable_not_passed(self):
        self.write("rust-toolchain.toml", '[toolchain]\nchannel = "99.99.99"\n')
        self.write("crates/agentfw/src/lib.rs", "pub fn synthetic() {}\n")
        self.commit("new pinned Rust source")
        result, report = self.invoke("run", "--step-seconds", "3")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["source_contract"]["rust_channel"], "99.99.99")
        for check in report["checks"]:
            if check["name"].startswith("rust_"):
                self.assertEqual((check["status"], check["reason"]),
                                 ("unavailable", "pinned_toolchain_missing"))
        self.assertFalse(report["local_checks_passed"])

    def test_offline_cargo_cache_miss_is_executed_unavailable(self):
        self.assertEqual(VERIFY.availability(
            "rust_clippy", "failed", "exit_nonzero",
            "error: failed to download `ctutils v0.4.4`\n"
            "Caused by: attempting to make an HTTP request, but --offline was specified"),
            ("unavailable", "offline_dependency_unavailable"))
        self.assertEqual(VERIFY.availability("rust_clippy", "failed", "exit_nonzero",
                                             "assertion failed"), ("failed", "exit_nonzero"))

    def test_unknown_mixed_path_selects_full_remote_plan(self):
        self.write("mystery.bin", "unknown input\n")
        self.commit("unknown path")
        result, plan = self.invoke("plan")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(plan["impact_mode"], "full")
        self.assertGreater(len(plan["remote_required"]["workflows"]), 10)
        self.assertTrue(all(item["selected"] for item in plan["local_checks"]
                            if item["name"] != "python_syntax"))

    def test_changed_head_selector_cannot_narrow_accepted_base_plan(self):
        self.write("scripts/ci_impact.py", "raise RuntimeError('head selector must not run')\n")
        self.commit("malicious head selector")
        result, plan = self.invoke("plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(plan["impact_mode"], "full")
        self.assertIn("ci_impact", plan["selector_base_sha256"])
        self.assertGreater(len(plan["remote_required"]["workflows"]), 10)

    def test_source_change_during_check_refuses_with_partial_results(self):
        marker = Path(self.temp.name) / "checker-started"
        self.write("scripts/check_docs.py", "from pathlib import Path\nimport time\n"
                   f"Path({str(marker)!r}).write_text('started')\n"
                   "time.sleep(1)\nPath('docs/guide.md').read_text()\n")
        self.commit("slow safe docs checker")
        process = subprocess.Popen(self.command("run"), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            until = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < until:
                time.sleep(.05)
            self.assertTrue(marker.exists())
            self.write("local-notes.txt", "changed during check\n")
            output, error = process.communicate(timeout=15)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        report = json.loads(output)
        self.assertEqual(process.returncode, 2, error)
        self.assertEqual(report["reason"], "source_changed_during_check")
        self.assertGreater(report["counts"]["executed"], 0)
        self.assertFalse(report["local_checks_passed"])
        self.assertEqual((self.repo / "local-notes.txt").read_text(), "changed during check\n")

    def test_stale_cached_report_is_refused_without_overwrite(self):
        forged = Path(self.temp.name) / "forged.json"
        forged.write_text('{"full_qualification":true,"trusted_admission":true}')
        before = forged.read_bytes()
        result, report = self.invoke("run", "--report-json", str(forged))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["reason"], "report_exists")
        self.assertEqual(forged.read_bytes(), before)

    def test_output_limit_stops_checker_without_counting_success(self):
        self.write("scripts/check_docs.py", "import sys,time\n"
                   "sys.stdout.write('x' * 100000)\nsys.stdout.flush()\ntime.sleep(5)\n")
        self.commit("oversized checker output")
        result, report = self.invoke("run", "--step-seconds", "2")
        self.assertEqual(result.returncode, 2)
        check = next(item for item in report["checks"] if item["name"] == "docs_links")
        self.assertEqual((check["status"], check["reason"]), ("incomplete", "output_limit"))
        self.assertLessEqual(check["output_bytes_retained"], VERIFY.MAX_LOG)
        self.assertEqual(report["counts"]["incomplete"], 1)
        self.assertFalse(report["local_checks_passed"])

    def test_plan_cannot_write_a_cached_report_or_touch_source(self):
        path = Path(self.temp.name) / "plan.json"
        result, value = self.invoke("plan", "--report-json", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(value["reason"], "plan_is_read_only")
        self.assertFalse(path.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process-group witness")
    def test_sigint_reaps_owned_checker_descendants(self):
        marker = Path(self.temp.name) / "child.pid"
        self.write("scripts/check_docs.py", "import pathlib,subprocess,time\n"
                   "p=subprocess.Popen(['sleep','30'])\n"
                   f"pathlib.Path({str(marker)!r}).write_text(str(p.pid))\n"
                   "time.sleep(30)\n")
        self.commit("cancellable docs checker")
        process = subprocess.Popen(self.command("run"), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            until = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < until:
                time.sleep(.05)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            output, error = process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        report = json.loads(output)
        self.assertEqual(process.returncode, 2, error)
        self.assertEqual(report["counts"]["incomplete"], 1)
        self.assertGreater(report["counts"]["not-run"], 0)
        pid = int(marker.read_text())
        until = time.monotonic() + 2
        while time.monotonic() < until:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(.05)
        else:
            self.fail("owned descendant remained after cancellation")


if __name__ == "__main__":
    unittest.main()
