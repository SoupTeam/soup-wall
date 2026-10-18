# SPDX-License-Identifier: Apache-2.0
"""Native standard-user acceptance for the installed Agent self-test."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

K = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
if K:
    K.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    K.CreateFileW.restype = wintypes.HANDLE
    K.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    K.OpenProcess.restype = wintypes.HANDLE
    K.CloseHandle.argtypes = [wintypes.HANDLE]
    K.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

@contextmanager
def owned_stage():
    identity = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe"),
                               "/user", "/fo", "csv", "/nh"], capture_output=True, check=True, timeout=10)
    sids = re.findall(rb"S-1-5-21-(?:[0-9]+-){3}[0-9]+", identity.stdout)
    require(len(sids) == 1, "current account identity unavailable")
    sid = sids[0].decode("ascii")
    directory = Path(tempfile.gettempdir()) / ("sw71-" + uuid.uuid4().hex)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    K.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    K.CreateDirectoryW.restype = wintypes.BOOL
    K.LocalFree.argtypes = [ctypes.c_void_p]
    K.LocalFree.restype = ctypes.c_void_p
    class Attributes(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]
    descriptor = ctypes.c_void_p()
    require(convert(f"O:{sid}D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;SY)", 1, ctypes.byref(descriptor), None),
            "private fixture descriptor unavailable")
    try:
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor.value, False)
        require(K.CreateDirectoryW(str(directory), ctypes.byref(attributes)), "private fixture creation failed")
    finally:
        K.LocalFree(descriptor)
    identity = directory.stat()
    try:
        yield directory
    finally:
        observed = directory.lstat()
        require((observed.st_dev, observed.st_ino) == (identity.st_dev, identity.st_ino)
                and not observed.st_file_attributes & 0x400, "fixture identity changed before cleanup")
        shutil.rmtree(directory)


class Acceptance:
    def __init__(self, args, stage):
        self.args, self.stage = args, stage
        self.agent = stage / "installed" / "agentfw.exe"
        self.agent.parent.mkdir()
        shutil.copyfile(args.agent, self.agent)
        self.baseline = self.agent.parent / "rule_baseline.py"
        shutil.copyfile(args.baseline, self.baseline)
        self.python = Path(sys.executable).resolve()
        self.results = []
        self.counter = 0
        self.sentinel = stage / "unrelated.json"
        self.sentinel.write_text('{"keep": "unchanged"}\n', encoding="ascii")
        self.sentinel_hash = digest(self.sentinel)
        self.host = stage / "unrelated-profile"
        (self.host / ".agentfw").mkdir(parents=True)
        (self.host / ".claude").mkdir()
        self.host_files = [self.host / ".agentfw" / "config.yaml",
                           self.host / ".agentfw" / "audit.jsonl",
                           self.host / ".claude" / "settings.json"]
        for path in self.host_files:
            path.write_bytes(b"synthetic operator sentinel\n")
        self.host_hashes = [digest(path) for path in self.host_files]
        runtime = stage / "runtime-temp"
        runtime.mkdir()
        self.env = dict(os.environ, USERPROFILE=str(self.host), HOME=str(self.host),
                        TEMP=str(runtime), TMP=str(runtime))

    def case(self):
        self.counter += 1
        root = self.stage / f"case-{self.counter}"
        root.mkdir()
        (root / "work").mkdir()
        return root

    def command(self, root, **changes):
        values = {
            "agent": self.agent, "classifier": "rule-baseline",
            "classifier-script": self.baseline, "classifier-sha256": digest(self.baseline),
            "classifier-python": self.python, "report": root / "report.json",
            "work-parent": root / "work", "timeout-seconds": 90,
        }
        values.update(changes)
        return [str(self.agent), "self-test"] + [
            str(item) for pair in values.items() for item in ("--" + pair[0], pair[1])
        ]

    def run(self, root, **changes):
        result = subprocess.run(self.command(root, **changes), cwd=root,
                                env=self.env, capture_output=True, timeout=115)
        report = read(root / "report.json") if (root / "report.json").is_file() else None
        return result, report

    def complete(self, result, report):
        require(result.returncode == 0, f"self-test exit {result.returncode}: {result.stdout.decode(errors='replace')[-600:]} {result.stderr.decode(errors='replace')[-600:]}")
        require(report["exit_code"] == 0, "report exit code mismatch")
        require(report["schema_version"] == "sw-self-test/1", "report schema changed")
        require(report["profile"]["id"] == "windows-stdio-mcp-admission-v1", "wrong platform")
        require(report["result"] == "passed", "positive run did not pass")
        require([s["status"] for s in report["scenarios"]] == ["passed"] * 5, "scenario missing")
        require([s["id"] for s in report["scenarios"]] == [
            "allowed_read", "adversarial_result", "protected_send_refused",
            "useful_read_after_refusal", "daemon_loss"], "scenario identities changed")
        require(report["identities"]["agent"]["sha256"] == digest(self.agent), "wrong binary identity")
        require(report["identities"]["classifier"]["source_sha256"] == digest(self.baseline), "wrong classifier identity")
        for key in ("policy", "registry", "fixtures"):
            require(len(report["identities"][key]["sha256"]) == 64, f"missing {key} identity")
        for scenario in report["scenarios"][:4]:
            require(scenario["receipts"]["classification"]["classifier_sha256_matches"], "classifier receipt missing")
            require(scenario["receipts"]["classification"]["policy"] == "reached", "policy was not reached")
        require(report["scenarios"][0]["observed"]["checks"]["exact_expected_bytes"], "read mismatch")
        require(report["scenarios"][1]["observed"]["outcome"] == "result_withheld", "injection released")
        require(report["scenarios"][1]["observed"]["marker_reached_client"] is False, "marker released")
        require(any(r["verdict"] == "ask" and r["released"] is False for r in report["scenarios"][1]["receipts"]["native_audit"]),
                "Ask result was not independently withheld")
        send = report["scenarios"][2]
        require(send["observed"]["mcp_child_executions"] == 0, "refused send executed")
        require(send["observed"]["receiver_connections"] == 0, "refused send reached receiver")
        require(send["receipts"]["native_audit"][0]["verdict"] == "deny", "send was not denied")
        require(report["scenarios"][4]["observed"]["daemon_killed"], "daemon-loss witness missing")
        require(report["scenarios"][4]["observed"]["collector_exited"], "collector survived daemon loss")
        require(report["cleanup"]["workspace"] == "removed", "workspace not removed")
        require(report["cleanup"]["receiver"]["socket_closed"], "receiver socket not closed")
        require(report["cleanup"]["collector"]["job_empty"], "collector job not empty")
        require(report["cleanup"]["daemon"]["job_empty"], "daemon job not empty")
        require(report["cleanup"]["final_effects"]["exact_execution_ledger"], "full execution ledger mismatch")
        require(report["cleanup"]["final_effects"]["no_unexpected_effects"], "late execution or delivery")
        raw = json.dumps(report)
        for text in (str(self.stage), str(self.python), "AKIAIOSFODNN7EXAMPLE", "SOUP-WALL-SELF-TEST-MARKER"):
            require(text not in raw, "report includes paths or synthetic sensitive content")

    def record(self, name, test):
        started = time.monotonic()
        try:
            observed = test()
            self.results.append({"id": name, "status": "passed", "duration_ms": round((time.monotonic() - started) * 1000), "observed": observed})
            print("PASS", name, flush=True)
        except Exception as error:
            self.results.append({"id": name, "status": "failed", "error": str(error)})
            print("FAIL", name, str(error), flush=True)

    def positive(self):
        root = self.case()
        result, report = self.run(root)
        self.complete(result, report)
        require(not list((root / "work").iterdir()), "workspace retained")
        shutil.copyfile(root / "report.json", self.args.out / "self-test-report.json")
        return {"scenarios": 5, "exit_code": result.returncode, "final_effects": report["cleanup"]["final_effects"]}

    def invalid_asset(self, option, value):
        root = self.case()
        result, report = self.run(root, **{option: value})
        require(result.returncode == 4, "invalid prerequisite passed")
        require(report["result"] == "incomplete", "invalid prerequisite was not incomplete")
        require(not any(s["status"] == "passed" for s in report["scenarios"]), "unrun scenario passed")
        require(not list((root / "work").iterdir()), "invalid prerequisite created workspace")
        return {"exit_code": 4, "no_scenarios_passed": True}

    def defaults(self):
        root = self.case()
        command = self.command(root, report="report.json")
        index = command.index("--work-parent")
        del command[index:index + 2]
        result = subprocess.run(command, cwd=root, env=self.env, capture_output=True, timeout=115)
        self.complete(result, read(root / "report.json"))
        return {"relative_report": True, "default_temporary_parent": True, "exit_code": 0}

    def existing_report(self):
        root = self.case()
        path = root / "report.json"
        path.write_bytes(b"existing evidence\n")
        result = subprocess.run(self.command(root), cwd=root, env=self.env, capture_output=True, timeout=20)
        require(result.returncode == 4 and path.read_bytes() == b"existing evidence\n", "existing report changed")
        require(not list((root / "work").iterdir()), "existing report started execution")
        return {"exit_code": 4, "existing_bytes_preserved": True}

    def report_aliases(self):
        root = self.case()
        existing = root / "existing.json"
        existing.write_bytes(b"keep")
        for name in ("existing.json:stream", "trailing.json.", "NUL"):
            result = subprocess.run(self.command(root, report=root / name), cwd=root,
                                    env=self.env, capture_output=True, timeout=20)
            require(result.returncode == 4, "unsafe report alias accepted")
        require(existing.read_bytes() == b"keep", "existing file changed")
        require(sorted(path.name for path in root.iterdir()) == ["existing.json", "work"], "alias created a file")
        try:
            with open(str(existing) + ":stream", "rb"):
                raise AssertionError("report created an alternate data stream")
        except FileNotFoundError:
            pass
        return {"exit_code": 4, "ads_device_and_trailing_aliases_refused": True}

    def reparse(self, report_parent=False):
        root = self.case()
        link = root / "linked"
        target = root / "target"
        target.mkdir()
        (target / "keep").write_bytes(b"untouched")
        made = subprocess.run([os.environ["ComSpec"], "/d", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, timeout=10)
        require(made.returncode == 0, "junction fixture creation failed")
        try:
            changes = {"report": link / "new.json"} if report_parent else {"work-parent": link}
            result = subprocess.run(self.command(root, **changes), cwd=root, env=self.env, capture_output=True, timeout=30)
            require(result.returncode == 4, "junction accepted")
            require((target / "keep").read_bytes() == b"untouched", "junction target changed")
            require(sorted(p.name for p in target.iterdir()) == ["keep"], "self-test wrote through junction")
        finally:
            os.rmdir(link)
        return {"exit_code": 4, "target_unchanged": True}

    def foreign_owner(self):
        root = self.case()
        result, report = self.run(root, **{"work-parent": Path(os.environ["SystemRoot"])})
        require(result.returncode == 4 and report["result"] == "incomplete", "foreign owner accepted")
        require(not list((root / "work").iterdir()), "foreign owner created workspace")
        return {"exit_code": 4, "foreign_directory_refused": True}

    def broad_parent(self):
        root = self.case()
        result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/icacls.exe"),
                                 str(root / "work"), "/grant", "*S-1-5-32-545:(OI)(CI)F"],
                                capture_output=True, timeout=10)
        require(result.returncode == 0, "broad parent ACL fixture failed")
        result, report = self.run(root)
        require(result.returncode == 4 and report["result"] == "incomplete", "broad parent ACL accepted")
        require(not list((root / "work").iterdir()), "unsafe parent received fixture files")
        return {"exit_code": 4, "untrusted_parent_write_access_refused": True}

    def collision(self):
        root = self.case()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(0.2)
            result, report = self.run(root, **{"daemon-port": listener.getsockname()[1]})
            self.complete(result, report)
            attempts = report["configured"]["daemon"]["start_attempts"]
            require(attempts[0]["outcome"] == "port_in_use", "foreign port was not skipped")
            require(attempts[-1]["outcome"] == "started", "owned daemon not established")
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                connection = None
            if connection:
                connection.close()
                raise AssertionError("foreign listener received self-test traffic")
        return {"foreign_listener_untouched": True, "owned_daemon_started": True}

    def mutation(self, mode):
        root = self.case()
        process = subprocess.Popen(self.command(root), cwd=root, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        handle = None
        workspace = None
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and process.poll() is None:
                candidates = list((root / "work").glob("agentfw-self-test-*"))
                if candidates and (candidates[0] / ".agentfw-self-test-owner").exists():
                    workspace = candidates[0]
                    break
                time.sleep(0.01)
            require(workspace is not None, "workspace was not created")
            if mode == "locked":
                handle = K.CreateFileW(str(workspace / "held.bin"), 0xC0000000, 3, None, 1, 0x80, None)
                require(handle not in (None, ctypes.c_void_p(-1).value), "cleanup lock fixture failed")
            else:
                sid = "*S-1-5-32-545:(OI)(CI)F"
                result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/icacls.exe"),
                                         str(workspace), "/grant", sid], capture_output=True, timeout=10)
                require(result.returncode == 0, "unsafe ACL fixture failed")
            stdout, _ = process.communicate(timeout=110)
            report = read(root / "report.json")
            require(process.returncode == 4 and report["result"] == "incomplete", "failed cleanup reported success: " + stdout.decode(errors="replace")[-300:])
            require(report["cleanup"]["workspace"] != "removed", "failed cleanup marked removed")
            require(workspace.exists(), "unverified workspace removed")
            return {"exit_code": 4, "cleanup_failure_reported": True}
        finally:
            if handle not in (None, ctypes.c_void_p(-1).value):
                K.CloseHandle(handle)
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)

    def interrupt(self):
        root = self.case()
        marker = root / "descendant.pid"
        slow = root / "slow_baseline.py"
        source = self.baseline.read_text(encoding="utf-8")
        injection = ("\nimport subprocess, time\n"
                     "_probe = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(90)'])\n"
                     f"open({str(marker)!r}, 'w').write(str(_probe.pid))\n"
                     "time.sleep(90)\n")
        source = source.replace("import sys\n", "import sys\n" + injection, 1)
        require("time.sleep(90)" in source, "slow classifier fixture not inserted")
        slow.write_text(source, encoding="utf-8")
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(self.command(root, **{"classifier-script": slow, "classifier-sha256": digest(slow)}),
                                   cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.env, creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
        descendant = None
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and process.poll() is None:
                if marker.is_file():
                    try:
                        pid = int(marker.read_text())
                        descendant = K.OpenProcess(0x00100000 | 0x1000, False, pid)
                        if descendant:
                            break
                    except (ValueError, OSError):
                        pass
                time.sleep(0.005)
            require(descendant is not None, "active classifier descendant not witnessed")
            require(K.WaitForSingleObject(descendant, 0) == 258, "descendant exited before interruption")
            helper = (
                "import ctypes,time; k=ctypes.windll.kernel32; k.FreeConsole(); "
                f"assert k.AttachConsole({process.pid}); "
                "h=ctypes.WINFUNCTYPE(ctypes.c_int,ctypes.c_uint)(lambda code:1); "
                "assert k.SetConsoleCtrlHandler(h,1); assert k.GenerateConsoleCtrlEvent(0,0); time.sleep(.2); k.FreeConsole()"
            )
            subprocess.run([str(self.python), "-I", "-c", helper], check=True, timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            process.communicate(timeout=30)
            report = read(root / "report.json")
            require(process.returncode == 4 and report["result"] == "incomplete", "interrupted run passed")
            require(K.WaitForSingleObject(descendant, 3000) == 0, "descendant survived interruption")
            require(not list((root / "work").iterdir()), "interrupted workspace retained")
            return {"exit_code": 4, "control_event": "ctrl_c", "active_descendant_observed": True, "descendant_stopped": True}
        finally:
            if descendant:
                K.CloseHandle(descendant)
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)

    def execute(self):
        self.record("installed_standard_user_positive", self.positive)
        self.record("relative_report_and_default_workspace", self.defaults)
        self.record("wrong_classifier_revision", lambda: self.invalid_asset("classifier-sha256", "0" * 64))
        self.record("missing_classifier", lambda: self.invalid_asset("classifier-script", self.stage / "missing.py"))
        self.record("missing_python", lambda: self.invalid_asset("classifier-python", self.stage / "missing.exe"))
        self.record("missing_agent", lambda: self.invalid_asset("agent", self.stage / "missing.exe"))
        self.record("existing_report", self.existing_report)
        self.record("report_stream_device_and_trailing_aliases", self.report_aliases)
        self.record("reparse_work_parent", self.reparse)
        self.record("reparse_report_parent", lambda: self.reparse(True))
        self.record("foreign_owned_work_parent", self.foreign_owner)
        self.record("broad_work_parent_acl", self.broad_parent)
        self.record("occupied_foreign_daemon_port", self.collision)
        self.record("locked_file_cleanup_failure", lambda: self.mutation("locked"))
        self.record("changed_workspace_acl", lambda: self.mutation("acl"))
        self.record("interrupt_with_active_descendant", self.interrupt)
        self.record("unrelated_sentinel_unchanged", lambda: require(digest(self.sentinel) == self.sentinel_hash, "unrelated sentinel changed"))
        self.record("operator_profile_sentinels_unchanged", lambda: require(
            [digest(path) for path in self.host_files] == self.host_hashes,
            "operator configuration or audit changed"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "nt", "native Windows required")
    require(not ctypes.windll.shell32.IsUserAnAdmin(), "a standard-user token is required")
    require(not args.out.exists(), "fresh evidence directory required")
    args.out.mkdir(parents=True)
    with owned_stage() as directory:
        acceptance = Acceptance(args, Path(directory))
        unrelated = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(300)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            acceptance.execute()
            acceptance.record("unrelated_process_unchanged", lambda: require(unrelated.poll() is None, "unrelated process stopped"))
        finally:
            if unrelated.poll() is None:
                unrelated.terminate()
                unrelated.wait(timeout=10)
        report = {
            "schema_version": "sou71-windows-self-test-acceptance/1",
            "status": "passed" if all(r["status"] == "passed" for r in acceptance.results) else "failed",
            "platform": platform.platform(), "native_windows": True, "elevated": False,
            "administrator_group_present": b"S-1-5-32-544" in subprocess.run(
                [str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe"), "/groups", "/fo", "csv"],
                capture_output=True, check=True, timeout=10).stdout,
            "agent_sha256": digest(args.agent), "classifier_sha256": digest(args.baseline),
            "python_sha256": digest(sys.executable), "checks": acceptance.results,
            "passed": sum(r["status"] == "passed" for r in acceptance.results),
            "failed": sum(r["status"] == "failed" for r in acceptance.results),
        }
        (args.out / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
