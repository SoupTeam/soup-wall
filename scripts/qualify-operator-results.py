"""Exercise structured CLI results with the existing original-server pilot harness."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
import threading
import signal

from pilot_operator_results import validate

ROOT = Path(__file__).resolve().parents[1]


class QualificationFailure(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(condition, reason):
    if not condition:
        raise QualificationFailure(reason)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("agentfw", "git-launcher", "claude", "node", "npm", "bwrap", "git", "strace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--offline-inputs", type=Path)
    return parser.parse_args()


if __name__ == "__main__":
    ARGS = arguments()

SPEC = importlib.util.spec_from_file_location("operator_ask", ROOT / "scripts/qualify-pilot-ask.py")
ASK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASK)


class StructuredPilot(ASK.Pilot):
    results = []

    def operator(self, *words, success=True, without_home=False):
        env = dict(self.setup.env)
        if without_home:
            env.pop("HOME", None)
        command = [str(self.setup.binary), "pilot-approval", "--output", "json-v1",
                   "--home", str(self.setup.home), "--run", self.run_id, *words]
        result = subprocess.run(command, cwd=self.root, env=env, capture_output=True, timeout=12)
        require(len(result.stdout) < 16 * 1024 * 1024 and not result.stderr,
                    "operator_output_contract_failed")
        record = validate(json.loads(result.stdout), words[0], result.returncode)
        require(len(self.results) < 4096, "operator_observation_limit")
        self.results.append({key: record[key] for key in ("operation", "outcome", "reason", "identity")})
        self.results[-1]["exit_code"] = result.returncode
        if success is not None:
            require((result.returncode == 0) == success, "operator_unexpected_exit")
        if record["identity"] is not None:
            require(record["identity"]["run_id"] == self.run_id, "operator_wrong_run_identity")
            if "pending_id" in record["identity"]:
                require(record["identity"]["pending_id"] == words[1], "operator_wrong_pending_identity")
        if words[0] in ("approve", "reject") and words[-1] == "0" * 64:
            require(record["reason"] == "binding_changed", "wrong_binding_reason_not_preserved")
        legacy_control = result.returncode == 0 and (words[0] == "inspect" or
            (words[0] == "list" and not self.proposals.released.is_set()))
        if legacy_control:
            legacy = subprocess.run([str(self.setup.binary), "pilot-approval", "--home",
                str(self.setup.home), "--run", self.run_id, *words], cwd=self.root, env=env,
                capture_output=True, timeout=12)
            require(legacy.returncode == 0 and not legacy.stderr
                        and len(legacy.stdout) < 16 * 1024 * 1024
                        and json.loads(legacy.stdout) == record["data"], "legacy_result_shape_changed")
            self.results[-1]["legacy_compatible"] = True
        return record if success is None else record["data"] if success else None


def qualify_stop(args, private, report):
    private.mkdir(mode=0o700)
    setup = ASK.LAUNCH.prepare_original_launch(args, private, report)
    classifier = private / "classifier.py"
    classifier.write_bytes((ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py").read_bytes())
    (setup.workspace / "credentials.txt").write_text("Owned synthetic inventory: 7 red widgets\n")
    (setup.workspace / "notes.txt").write_text("Owned useful continuation: 7 red widgets\n")
    setup.policy.write_text("agent_policies:\n  - name: operator-stop-ask\n    when: { action_class: read_only, touches_sensitive_path: true }\n    action: ask\ndefault: allow\n")
    ASK.BASE.write(setup.home / "config.yaml", {"port": setup.port, "enforce": True,
        "policy": str(setup.policy), "native": {"registry_path": str(setup.registry),
        "registry_sha256": ASK.LAUNCH.sha(setup.registry), "approval": {"ttl_seconds": 30},
        "liveness": {"default_lease_seconds": 4, "max_lease_seconds": 60, "maintenance_interval_ms": 100}}})
    pilot, daemon = None, None
    try:
        with (private / "daemon.private").open("ab") as log:
            daemon = subprocess.Popen([str(setup.binary), "serve"], cwd=private,
                                      env=setup.env, stdout=log, stderr=log)
        require(ASK.BASE.DEMO.wait_healthy(setup.port, daemon), "daemon_not_ready")
        pilot = StructuredPilot(setup, private / "stop", classifier, "filesystem")
        waiting = pilot.waiting()
        pilot.inspect(waiting)
        require(pilot.undispatched(), "dispatch_before_stop")
        result = pilot.operator("stop")
        require(result["status"] == "stopped", "stop_not_confirmed")
        pilot.process.wait(timeout=15)
        pilot.out.flush()
        host = json.loads((pilot.root / "host.stdout.private").read_text())
        require(host["status"] == "stopped" and pilot.process.returncode == 0, "host_stop_not_confirmed")
        cleanup = pilot.witness.finish()
        require(cleanup["all_stopped"], "owned_process_survived_stop")
        require(pilot.effects() == pilot.dispatches() == 0, "stopped_request_executed")
        require(pilot.operator("stop")["status"] == "already_stopped", "stop_retry_not_idempotent")
        report.update(stop_confirmed=True, forbidden_dispatches=0, process_cleanup=cleanup)
        pilot.close()
        report["concurrent_decisions"] = {"status": "incomplete"}
        pilot = StructuredPilot(setup, private / "concurrent-decision", classifier, "filesystem")
        waiting = pilot.waiting()
        pilot.inspect(waiting)
        barrier = threading.Barrier(2, timeout=10)
        def approve():
            barrier.wait()
            return pilot.operator("approve", waiting["pending_id"], "--binding",
                                  waiting["binding_sha256"], success=None)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(approve) for _ in range(2)]
            decisions = [future.result(timeout=15) for future in futures]
        require(sum(item["outcome"] == "decision_submitted" for item in decisions) == 1,
                    "concurrent_submission_count_wrong")
        refused = [item for item in decisions if item["outcome"] != "decision_submitted"]
        require(len(refused) == 1 and refused[0]["reason"] in ("decision_conflict", "pending_unavailable"),
                    "concurrent_refusal_not_attributed")
        pilot.finish()
        primary = pilot.model.results.get("primary")
        require(primary and primary["is_error"] is False and "7 red widgets" in json.dumps(primary),
                    "concurrent_useful_result_missing")
        require(pilot.effects() == pilot.dispatches() == 1, "concurrent_request_executed_twice")
        report["concurrent_decisions"] = {"status": "pass", "submissions": 1, "dispatches": 1,
                                          "kernel_effects": 1, "useful_result": True}
        pilot.close()
        report["daemon_unavailable"] = {"status": "incomplete"}
        pilot = StructuredPilot(setup, private / "daemon-unavailable", classifier, "filesystem")
        waiting = pilot.waiting()
        pilot.inspect(waiting)
        require(ASK.BASE.ProcessWitness.identity(pilot.launcher_pid) == pilot.launcher_start,
                "unavailable_launcher_identity_changed")
        owner = os.pidfd_open(pilot.launcher_pid)
        try:
            require(ASK.BASE.ProcessWitness.identity(pilot.launcher_pid) == pilot.launcher_start,
                    "unavailable_launcher_identity_changed")
            signal.pidfd_send_signal(owner, signal.SIGSTOP)
            ASK.until(lambda: Path(f"/proc/{pilot.launcher_pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                      in ("T", "t"), "unavailable_launcher_not_paused", seconds=2)
            ASK.stop(daemon)
            daemon = None
            unavailable = pilot.operator("list", success=None)
            require(unavailable["outcome"] == "unavailable" and unavailable["reason"] == "daemon_unavailable",
                    "daemon_loss_not_reported_as_unavailable")
        finally:
            try:
                signal.pidfd_send_signal(owner, signal.SIGCONT)
            except ProcessLookupError:
                pass
            os.close(owner)
        pilot.close()
        require(pilot.effects() == pilot.dispatches() == 0, "daemon_loss_dispatched_request")
        require(pilot.witness.finish()["all_stopped"], "unavailable_owned_process_survived")
        report["daemon_unavailable"] = {"status": "pass", "reason": "daemon_unavailable", "dispatches": 0}
        report["source_after"] = ASK.BASE.source()
        require(report["source"] == report["source_after"], "stop_source_changed")
        report["status"] = "pass"
    finally:
        try:
            if pilot is not None:
                pilot.close()
        finally:
            ASK.stop(daemon)


def main(args):
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"format": "sw-pilot-operator-qualification/1", "status": "incomplete",
              "real_host_executed": False, "scripted_owned_provider": True,
              "paid_api_calls": 0, "physical_human_presence_proven": False,
              "native_ubuntu_verified": False, "stage": "native_environment"}
    StructuredPilot.results = []
    try:
        require(ASK.BASE.platform.system() == "Linux", "linux_required")
        os_release = Path("/etc/os-release").read_text()
        require('ID=ubuntu' in os_release and 'VERSION_ID="24.04"' in os_release
                    and not any(Path(name).exists() for name in ("/.dockerenv", "/run/.containerenv"))
                    and "microsoft" not in ASK.BASE.platform.release().lower(),
                    "native_ubuntu_24_04_required")
        report["stage"] = "source_identity"
        report["source"] = ASK.BASE.source()
        require(not report["source"]["dirty"], "clean_source_required")
        with tempfile.TemporaryDirectory(prefix="operator-results-") as directory:
            original = Path(directory) / "original"
            original.mkdir(mode=0o700)
            report["stage"] = "original_host"
            ASK.qualify(args, original, report, pilot_class=StructuredPilot)
            report["stop_control"] = {"status": "incomplete"}
            report["stage"] = "confirmed_stop"
            qualify_stop(args, Path(directory) / "confirmed-stop", report["stop_control"])
        report["stage"] = "completed"
        report["native_ubuntu_verified"] = report.get("status") == "pass"
    except Exception as error:
        report.update(status="failed", failure_type=type(error).__name__,
                      failure_reason=error.reason if isinstance(error, QualificationFailure) else "unknown")
    finally:
        report["operator_results"] = StructuredPilot.results
        ASK.BASE.write(args.output / "operator-results.json", report)
    print(json.dumps({key: report[key] for key in ("status", "native_ubuntu_verified")}))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(ARGS))
