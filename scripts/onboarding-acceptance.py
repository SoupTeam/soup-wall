#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-69 onboarding acceptance on owned clean Linux homes, outside the source checkout.

For every scenario the runner creates a fresh owned root with an installed copy of the
selected agentfw binary, the Task 1 rule baseline, the accepted MCP admission fixture
server and its reviewed registry, a Claude-style host config with an unrelated sentinel
entry and setting, and an unrelated sentinel file. It runs `agentfw onboard` from inside
that root and checks outcomes, journals, retained files, processes and sentinels.
No model, provider, network destination or real credential is used.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parents[1]
SERVER = REPO / "scripts/fixtures/mcp_admission_demo_server.py"
CLASSIFIER = REPO / "rule_baseline/rule_baseline.py"
CLASSES = {"read_document": ("read_only", "untrusted"), "send_http": ("network", "local_system"),
           "publish_report": ("network", "local_system"), "delete_note": ("destructive", "local_system")}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Root:
    """One owned clean home with installed assets and sentinels."""

    def __init__(self, base: Path, name: str, agentfw: Path):
        self.root = base / name
        self.user = self.root / "user"
        self.out = self.root / "out"
        for path in [self.user / "work/notes", self.user / ".claude", self.root / "opt/soup-wall/bin",
                     self.root / "opt/soup-wall/classifier", self.root / "opt/notes-server", self.out]:
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.user, 0o700)
        os.chmod(self.user / ".claude", 0o700)
        self.agent = self.root / "opt/soup-wall/bin/agentfw"
        shutil.copyfile(agentfw, self.agent)
        os.chmod(self.agent, 0o755)
        self.classifier = self.root / "opt/soup-wall/classifier/rule_baseline.py"
        shutil.copyfile(CLASSIFIER, self.classifier)
        self.server = self.root / "opt/notes-server/server.py"
        shutil.copyfile(SERVER, self.server)
        (self.user / "work/notes/inventory.txt").write_text("Inventory: 7 red widgets.", encoding="utf-8")
        (self.user / "sentinel.txt").write_text("operator sentinel file\n", encoding="utf-8")
        spec = importlib.util.spec_from_file_location("onboarding_fixture_server", self.server)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tools = [{"name": t["name"], "schema_sha256": sha(canonical(t["inputSchema"])),
                  "action_class": CLASSES[t["name"]][0], "result_provenance": CLASSES[t["name"]][1],
                  "egress": [{"pointer": "/url", "kind": "url_host", "optional": False}]
                  if CLASSES[t["name"]][0] == "network" else []} for t in module.TOOLS]
        self.registry = self.root / "opt/notes-server/registry.json"
        self.registry.write_text(json.dumps({"contract_version": "sw-native/1", "registry_id": "notes-fixture-v1",
                                             "tools": tools}), encoding="utf-8")
        python = os.path.realpath("/usr/bin/python3")
        self.entry = {"command": python, "args": ["-I", "-u", str(self.server), "--notes", str(self.user / "work/notes"),
                                                  "--ledger", str(self.user / "work/ledger.jsonl"),
                                                  "--recipient", "http://127.0.0.1:9/capture"]}
        self.sentinel_entry = {"command": "/bin/true", "args": ["sentinel-entry"]}
        self.host = self.user / ".claude/mcp.json"
        self.host.write_text(json.dumps({"theme": "dark", "mcpServers": {"notes": self.entry, "unrelated": self.sentinel_entry}},
                                        indent=2), encoding="utf-8")
        os.chmod(self.host, 0o600)
        self.home = self.user / ".agentfw"
        self.state = self.user / ".soup-wall-onboarding"
        self.port = free_port()
        self.reports = 0

    def inputs(self, **overrides):
        values = {
            "--agent": str(self.agent), "--agent-sha256": sha(self.agent.read_bytes()),
            "--classifier": "rule-baseline", "--classifier-script": str(self.classifier),
            "--classifier-sha256": sha(self.classifier.read_bytes()),
            "--classifier-python": os.path.realpath("/usr/bin/python3"),
            "--registry": str(self.registry), "--registry-sha256": sha(self.registry.read_bytes()),
            "--workspace": str(self.user / "work"), "--agent-home": str(self.home),
            "--host-config": str(self.host), "--server": "notes", "--port": str(self.port),
            "--probe-tool": "read_document", "--probe-args": '{"name":"inventory"}',
        }
        values.update(overrides)
        return [item for key, value in values.items() if value is not None for item in (key, value)]

    def report_path(self, label: str) -> Path:
        self.reports += 1
        return self.out / f"{self.reports:02d}-{label}.json"

    def onboard(self, operation: str, args, label: str, timeout=900, popen=False):
        report = self.report_path(label)
        command = [str(self.agent), "onboard", operation, *args, "--report", str(report)]
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.user), "LANG": "C.UTF-8"}
        if popen:
            return subprocess.Popen(command, cwd=self.user, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT), report
        result = subprocess.run(command, cwd=self.user, env=env, capture_output=True, timeout=timeout)
        return result.returncode, json.loads(report.read_text()) if report.exists() else None

    def preview_digest(self, **overrides):
        code, report = self.onboard("preview", self.inputs(**overrides), "preview")
        return code, report, (report or {}).get("plan_sha256")

    def undo(self, label="undo", purge=False):
        args = ["--agent", str(self.agent), "--agent-home", str(self.home), "--host-config", str(self.host), "--server", "notes"]
        if purge:
            args.append("--purge-agent-home")
        return self.onboard("undo", args, label)

    def host_value(self):
        return json.loads(self.host.read_text())

    def sentinels(self):
        value = self.host_value()
        return {"sentinel_file": sha((self.user / "sentinel.txt").read_bytes()),
                "unrelated_entry": value["mcpServers"].get("unrelated"), "theme": value.get("theme"),
                "workspace_notes": sha((self.user / "work/notes/inventory.txt").read_bytes())}

    def owned_processes(self):
        needle = str(self.root)
        count = 0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                if needle in (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace"):
                    count += 1
            except OSError:
                pass
        return count

    def journal(self):
        try:
            return json.loads((self.state / "journal.json").read_text())
        except (OSError, ValueError):
            return None


class ForeignListener:
    """An unrelated TCP listener that onboarding must never adopt."""

    def __init__(self, port):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.socket.listen(8)
        self.stop = False
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        self.socket.settimeout(0.2)
        while not self.stop:
            try:
                connection, _ = self.socket.accept()
                connection.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.socket.close()


def wait_for(predicate, limit=300.0):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def check(results, name, passed, **observed):
    results.append({"check": name, "passed": bool(passed), **observed})
    print(f"  {'PASS' if passed else 'FAIL'}  {name}")


def scenario_success(root: Root):
    out = []
    before = root.sentinels()
    original = root.host_value()["mcpServers"]["notes"]
    code, report, digest = root.preview_digest()
    check(out, "preview_ready_and_read_only", code == 0 and report["result"] == "plan_ready"
          and not root.home.exists() and not root.state.exists())
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply")
    check(out, "apply_verified", code == 0 and report["result"] == "verified", result=report and report["result"])
    check(out, "configured_identity_separate", report and all(report["configured"]["checks"].values())
          and report["configured"]["note"].startswith("daemon identity"))
    check(out, "host_probe_verified", report and report["host_probe"]["status"] == "verified_for_this_probe")
    check(out, "self_test_scoped_and_passed", report and report["self_test"]["result"] == "passed"
          and "does not show that the configured host is protected" in report["self_test"]["scope"])
    check(out, "host_coverage_unknown", report and report["coverage"]["host_session"] == "unknown")
    check(out, "wrapped_only_selected_entry", root.host_value()["mcpServers"]["notes"]["command"] == "/usr/bin/env"
          and root.sentinels() == before)
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-retry")
    check(out, "safe_retry_reverifies", code == 0 and report["result"] == "verified" and report["resumed"] is True)
    code, report = root.undo()
    check(out, "undo_reverses_and_keeps_audit", code == 0 and report["result"] == "undone"
          and root.host_value()["mcpServers"]["notes"] == original and (root.home / "audit.jsonl").exists())
    code, report = root.undo("undo-purge", purge=True)
    check(out, "purge_removes_owned_home_and_state", code == 0 and not root.home.exists() and not root.state.exists())
    check(out, "sentinels_preserved", root.sentinels() == before)
    check(out, "no_owned_processes", root.owned_processes() == 0)
    retained = sorted(p.name for p in (root.user / ".claude").iterdir() if p.name != "mcp.json")
    check(out, "only_documented_connection_recovery_files_retained",
          all(name.startswith(".soup-wall-") for name in retained), retained=len(retained))
    return out


def scenario_classifier(root: Root):
    out = []
    code, report, _ = root.preview_digest(**{"--classifier-script": str(root.root / "missing.py")})
    check(out, "missing_classifier_refused", code == 4 and report["result"] == "refused"
          and any(c["id"] == "classifier" and c["status"] == "refused" for c in report["checks"]))
    code, report, _ = root.preview_digest(**{"--classifier-sha256": "0" * 64})
    check(out, "wrong_classifier_revision_refused", code == 4 and "wrong revision" in json.dumps(report["checks"]))
    check(out, "nothing_created", not root.home.exists() and not root.state.exists())
    return out


def scenario_existing_config(root: Root):
    out = []
    root.home.mkdir(mode=0o700)
    (root.home / "config.yaml").write_text("enforce: true\nport: 1\n", encoding="utf-8")
    (root.home / "token").write_text("operator-token\n", encoding="utf-8")
    before = {p.name: sha(p.read_bytes()) for p in root.home.iterdir()}
    code, report, _ = root.preview_digest()
    check(out, "existing_home_conflict", code == 4 and any(c["id"] == "agent_home" and c["status"] == "conflict"
                                                           for c in report["checks"]))
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", "0" * 64], "apply")
    check(out, "apply_refused_without_changes", code == 4 and report["result"] == "refused")
    check(out, "existing_files_untouched", {p.name: sha(p.read_bytes()) for p in root.home.iterdir()} == before
          and not root.state.exists())
    return out


def scenario_port(root: Root):
    out = []
    listener = ForeignListener(root.port)
    try:
        code, report, _ = root.preview_digest()
        check(out, "occupied_port_conflict", code == 4 and any(c["id"] == "port" and c["status"] == "conflict"
                                                               for c in report["checks"]))
    finally:
        listener.close()
    code, _, digest = root.preview_digest()
    listener = ForeignListener(root.port)
    try:
        code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-after-listener")
        check(out, "listener_after_preview_refused_on_revalidation", code == 4 and report["result"] == "refused"
              and not root.home.exists())
    finally:
        listener.close()
    return out


def scenario_interrupted(root: Root):
    out = []
    before = root.sentinels()
    _, _, digest = root.preview_digest()
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-interrupted", popen=True)
    reached = wait_for(lambda: (root.journal() or {}).get("steps", {}).get("lifecycle_install") == "done")
    process.send_signal(signal.SIGINT)
    process.communicate(timeout=600)
    report = json.loads(report_path.read_text())
    check(out, "interrupt_stops_at_step_boundary", reached and process.returncode == 4 and report["result"] == "incomplete"
          and report["explanation"].startswith("Interrupted"), result=report["result"])
    check(out, "journal_retained_without_rollback", (root.journal() or {}).get("phase") == "interrupted" and root.home.exists())
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-resume")
    check(out, "rerun_resumes_to_verified", code == 0 and report["result"] == "verified" and report["resumed"] is True)
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-killed", popen=True)
    wait_for(lambda: (root.journal() or {}).get("steps", {}).get("verify_server") == "started")
    process.kill()
    process.communicate(timeout=60)
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-after-kill")
    check(out, "rerun_after_sigkill_recovers", code == 0 and report["result"] == "verified")
    code, _ = root.undo("undo-purge", purge=True)
    check(out, "undo_after_recovery_clean", code == 0 and not root.home.exists() and root.sentinels() == before
          and root.owned_processes() == 0)
    return out


def scenario_external_edits(root: Root):
    out = []
    _, _, digest = root.preview_digest()
    value = root.host_value()
    value["editorSetting"] = "changed after preview"
    root.host.write_text(json.dumps(value, indent=2), encoding="utf-8")
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-stale-plan")
    check(out, "host_edit_after_preview_refused", code == 4 and report["result"] == "refused" and not root.home.exists())
    _, _, digest = root.preview_digest()
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply")
    check(out, "apply_after_new_preview_verified", code == 0 and report["result"] == "verified")
    # The operator edits the selected (wrapped) entry: undo must not overwrite it.
    value = root.host_value()
    value["mcpServers"]["notes"]["args"].append("--operator-edit")
    root.host.write_text(json.dumps(value, indent=2), encoding="utf-8")
    edited = root.host_value()["mcpServers"]["notes"]
    code, report = root.undo("undo-conflict")
    check(out, "selected_entry_edit_blocks_undo", code == 4 and report["result"] == "incomplete"
          and root.host_value()["mcpServers"]["notes"] == edited and root.journal()["phase"] == "rollback_conflict")
    value["mcpServers"]["notes"]["args"].pop()
    root.host.write_text(json.dumps(value, indent=2), encoding="utf-8")
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-during-conflict")
    check(out, "apply_refuses_unresolved_conflict", code == 4 and report["result"] == "refused")
    # An owned file changed outside onboarding is retained, never deleted.
    config = root.home / "config.yaml"
    original = config.read_bytes()
    config.write_bytes(original + b"\n# operator edit\n")
    code, report = root.undo("undo-file-conflict")
    check(out, "owned_file_edit_retained", code == 4 and config.read_bytes().endswith(b"# operator edit\n")
          and any(r["step"] == "config" and r["outcome"] == "conflict" for r in report["rollback"]))
    config.write_bytes(original)
    code, report = root.undo("undo-purge", purge=True)
    check(out, "undo_after_resolution_clean", code == 0 and not root.home.exists() and not root.state.exists()
          and root.owned_processes() == 0)
    return out


def scenario_rollback(root: Root):
    out = []
    before = root.sentinels()
    host_before = sha(root.host.read_bytes())
    _, _, digest = root.preview_digest()
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-race", popen=True)
    listener = None
    if wait_for(lambda: (root.journal() or {}).get("steps", {}).get("lifecycle_install") in ("started", "done")):
        listener = ForeignListener(root.port)
    process.communicate(timeout=600)
    if listener:
        listener.close()
    report = json.loads(report_path.read_text())
    reversed_steps = [r["step"] for r in report.get("rollback", []) if r["outcome"] == "reversed"]
    check(out, "foreign_listener_race_not_adopted", process.returncode == 4 and report["result"] == "incomplete"
          and "not adopted" in report["explanation"], result=report["result"])
    check(out, "rollback_reverses_only_proven_changes", "lifecycle" in reversed_steps and "config" in reversed_steps
          and not root.home.exists() and not root.state.exists())
    check(out, "host_config_and_sentinels_untouched", sha(root.host.read_bytes()) == host_before and root.sentinels() == before
          and root.owned_processes() == 0)
    return out


def add_foreign_files(root: Root):
    """Operator files inside directories onboarding or the Agent recognize."""
    created = not (root.home / "grants").exists()
    (root.home / "grants").mkdir(exist_ok=True)
    files = {root.home / "grants/operator-notes.txt": b"operator notes\n",
             root.home / "onboarding/operator.txt": b"operator file\n"}
    for path, data in files.items():
        path.write_bytes(data)
    return files, created


def remove_foreign_files(root: Root, files, created):
    for path in files:
        path.unlink()
    if created:  # a directory the operator created is the operator's to remove
        (root.home / "grants").rmdir()


def foreign_preserved(files):
    return all(path.exists() and path.read_bytes() == data for path, data in files.items())


def home_conflict(report):
    return any(r["step"] == "agent_home" and r["outcome"] == "conflict" for r in (report or {}).get("rollback", []))


def scenario_foreign_files(root: Root):
    out = []
    before = root.sentinels()
    original = root.host_value()["mcpServers"]["notes"]
    _, _, digest = root.preview_digest()
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply")
    check(out, "apply_verified", code == 0 and report["result"] == "verified")
    files, created = add_foreign_files(root)
    # A retry re-runs the verification steps; it must not adopt the operator's files.
    code, report = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-retry")
    check(out, "retry_does_not_adopt_foreign_files", code == 0 and report["result"] == "verified"
          and not any(rel in (root.journal() or {}).get("inventory", {})
                      for rel in ("grants/operator-notes.txt", "onboarding/operator.txt")))
    code, report = root.undo("undo-foreign")
    check(out, "undo_preserves_foreign_bytes", code == 4 and report["result"] == "incomplete" and home_conflict(report)
          and foreign_preserved(files) and (root.journal() or {}).get("phase") == "rollback_conflict",
          result=report and report["result"])
    check(out, "undo_reversed_connection_and_lifecycle", root.host_value()["mcpServers"]["notes"] == original
          and root.owned_processes() == 0)
    code, report = root.undo("undo-foreign-purge", purge=True)
    check(out, "purge_never_deletes_foreign_bytes", code == 4 and home_conflict(report) and foreign_preserved(files))
    remove_foreign_files(root, files, created)
    code, report = root.undo("undo-purge", purge=True)
    check(out, "undo_after_removal_clean", code == 0 and not root.home.exists() and not root.state.exists())
    # Failure rollback: foreign files added while apply was interrupted, then a listener race.
    _, _, digest = root.preview_digest()
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-interrupted", popen=True)
    wait_for(lambda: (root.journal() or {}).get("steps", {}).get("create_token") in ("started", "done"))
    process.send_signal(signal.SIGINT)
    process.communicate(timeout=600)
    steps = (root.journal() or {}).get("steps", {})
    check(out, "interrupted_before_lifecycle", process.returncode == 4 and "lifecycle_install" not in steps)
    files, created = add_foreign_files(root)
    process, report_path = root.onboard("apply", root.inputs() + ["--plan-sha256", digest], "apply-race", popen=True)
    listener = None
    if wait_for(lambda: (root.journal() or {}).get("steps", {}).get("lifecycle_install") in ("started", "done")):
        listener = ForeignListener(root.port)
    process.communicate(timeout=600)
    if listener:
        listener.close()
    report = json.loads(report_path.read_text())
    reversed_steps = [r["step"] for r in report.get("rollback", []) if r["outcome"] == "reversed"]
    check(out, "failure_rollback_preserves_foreign_bytes", process.returncode == 4 and home_conflict(report)
          and "lifecycle" in reversed_steps and "config" in reversed_steps and foreign_preserved(files)
          and (root.journal() or {}).get("phase") == "rollback_conflict", result=report["result"])
    remove_foreign_files(root, files, created)
    code, report = root.undo("undo-after-rollback", purge=True)
    check(out, "undo_after_rollback_clean", code == 0 and not root.home.exists() and not root.state.exists()
          and root.sentinels() == before and root.owned_processes() == 0)
    return out


def scenario_unsafe_host(root: Root):
    out = []
    os.chmod(root.host, 0o644)
    code, report, _ = root.preview_digest()
    check(out, "non_private_host_config_refused", code == 4 and any(c["id"] == "host_config" and c["status"] == "refused"
                                                                    for c in report["checks"]))
    check(out, "permissions_not_changed", (root.host.stat().st_mode & 0o777) == 0o644)
    return out


SCENARIOS = [("success_retry_undo", scenario_success), ("missing_or_wrong_classifier", scenario_classifier),
             ("existing_active_config", scenario_existing_config), ("occupied_port_foreign_listener", scenario_port),
             ("interrupted_and_killed_apply", scenario_interrupted), ("external_edit_conflicts", scenario_external_edits),
             ("rollback_after_listener_race", scenario_rollback), ("foreign_files_in_agent_home", scenario_foreign_files),
             ("unsafe_host_config", scenario_unsafe_host)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="fresh evidence directory")
    parser.add_argument("--work-parent", type=Path, help="parent for owned roots (default: system temp)")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--only", nargs="*")
    options = parser.parse_args()
    if sys.platform != "linux":
        sys.exit("onboarding acceptance supports Linux only")
    options.out.mkdir(parents=False, exist_ok=False)
    base = Path(tempfile.mkdtemp(prefix="sou69-onboarding-", dir=options.work_parent)).resolve()
    if str(base).startswith(str(REPO)):
        sys.exit("work parent must be outside the source checkout")
    summary = {"schema": "sw-onboarding-acceptance/1", "agentfw_sha256": sha(options.agentfw.read_bytes()),
               "classifier_sha256": sha(CLASSIFIER.read_bytes()), "server_sha256": sha(SERVER.read_bytes()),
               "outside_source_checkout": True, "scenarios": []}
    started = time.monotonic()
    for name, function in SCENARIOS:
        if options.only and name not in options.only:
            continue
        print(f"{name}:")
        root = Root(base, name, options.agentfw)
        began = time.monotonic()
        try:
            checks = function(root)
        except Exception as error:  # a crashed scenario is a failed scenario, never skipped
            checks = [{"check": "scenario_completed", "passed": False, "error": type(error).__name__}]
            print(f"  FAIL  scenario raised {type(error).__name__}: {error}")
        reports = []
        for report in sorted(root.out.glob("*.json")):
            text = report.read_text().replace(str(root.root), "<root>")
            (options.out / f"{name}-{report.name}").write_text(text)
            reports.append(report.name)
        leaked = [report for report in reports if str(root.root) in (root.out / report).read_text()]
        checks.append({"check": "reports_contain_no_raw_paths", "passed": not leaked})
        summary["scenarios"].append({"scenario": name, "passed": all(c["passed"] for c in checks), "checks": checks,
                                     "reports": reports, "duration_s": round(time.monotonic() - began, 1)})
    if not options.keep:
        shutil.rmtree(base)
    summary["cleanup"] = {"owned_roots_removed": not options.keep and not base.exists()}
    summary["passed"] = all(s["passed"] for s in summary["scenarios"])
    summary["duration_s"] = round(time.monotonic() - started, 1)
    (options.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"{'PASSED' if summary['passed'] else 'FAILED'}: {sum(s['passed'] for s in summary['scenarios'])}/"
          f"{len(summary['scenarios'])} scenarios; evidence {options.out}")
    sys.exit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
