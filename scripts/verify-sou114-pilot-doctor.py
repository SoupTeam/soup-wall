#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-114 exact-source installed diagnosis, never a launcher replacement.

The acceptance driver alone prepares disposable originals, starts its owned
managed daemon and records a real refusal. The diagnostic must only observe.
Only reviewed allowlisted reports are published; raw server/authority logs stay
in the private temporary root and are never part of the output archive.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

BASE = load("sou114_fs", "verify-sou62-real-mcp.py")
GIT = load("sou114_git", "verify-sou68-real-mcp.py")
require, sha, write = BASE.require, BASE.sha, BASE.write
FILES = ("crates/agentfw/src/doctor.rs", "crates/agentfw/src/pilot_doctor.rs",
         "crates/agentfw/src/pilot_doctor/io.rs", "crates/agentfw/src/pilot_doctor/incident.rs",
         "crates/agentfw/src/support_bundle.rs", "scripts/verify-sou114-pilot-doctor.py")
CASES = ("healthy-json", "healthy-text", "recorded-refusal", "changed-asset", "changed-classifier", "missing-incident",
         "stale-incident", "mismatched-incident", "malformed-input", "oversized-input",
         "symlink-input", "fifo-input", "public-input", "existing-output", "symlink-output",
         "workspace-output", "daemon-unavailable")
CANARIES = (b"SOU114-PRIVATE-ARGUMENT-8569cc", b"SOU114-PRIVATE-CONFIG-b60cb8", b"SOU114-PRIVATE-LOG-43eddf")
STREAM_CAP = 256 * 1024
TRACE_CAP = 1024 * 1024
DIAGNOSTIC_SECONDS = 90
PRIVATE_FILE_CAP = 2 * 1024 * 1024
PRIVATE_TOTAL_CAP = 32 * 1024 * 1024
SUPPORT_NAMES = ("healthy-support", "incident-support")

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def scan(data, secrets):
    require(not any(secret and secret in data for secret in secrets), "published_privacy_canary")

def process_witness(observed, binary):
    """Reject every extra execution attempt, including failed execveat calls."""
    attempts = [line for line in observed.splitlines() if re.search(r"\b(?:execve|execveat)\(", line)]
    require(len(attempts) == 1 and re.search(r"\bexecve\(" + re.escape(json.dumps(str(binary))) + r",.*\)\s*= 0$", attempts[0]),
            "diagnostic_spawned_program")
    for line in observed.splitlines():
        require(not re.search(r"\b(?:fork|vfork)\(", line), "diagnostic_spawned_process")
        if re.search(r"\b(?:clone|clone3)\(", line):
            require("CLONE_THREAD" in line, "diagnostic_spawned_process")
    return {"format": "sw-pilot-doctor-process/1", "executed_programs": 1,
            "extra_execution_attempts": 0, "non_thread_process_attempts": 0,
            "trace_sha256": hashlib.sha256(observed.encode()).hexdigest()}

def run_observed(command, cwd, env, trace, evidence, label):
    """Bound streams, trace, lifetime and late descendants without publishing raw data."""
    exceeded = threading.Event()
    stream_failed = threading.Event()
    buffers = [bytearray(), bytearray()]
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    def drain(stream, index, suffix):
        try:
            with (evidence / (label + suffix)).open("xb") as retained:
                os.chmod(retained.name, 0o600)
                while chunk := stream.read(4096):
                    remaining = STREAM_CAP - len(buffers[index])
                    buffers[index].extend(chunk[:remaining])
                    retained.write(chunk[:remaining])
                    if len(chunk) > remaining:
                        exceeded.set()
                        break
        except Exception:
            stream_failed.set()
        finally:
            stream.close()
    threads = [threading.Thread(target=drain, args=(stream, index, suffix), daemon=True)
               for index, (stream, suffix) in enumerate(((process.stdout, ".stdout.private"), (process.stderr, ".stderr.private")))]
    for thread in threads: thread.start()
    deadline = time.monotonic() + DIAGNOSTIC_SECONDS
    timed_out = False
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if exceeded.is_set() or (trace.exists() and trace.stat().st_size > TRACE_CAP):
                exceeded.set()
                break
            time.sleep(0.01)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        for thread in threads: thread.join(timeout=3)
        if any(thread.is_alive() for thread in threads):
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            for thread in threads: thread.join(timeout=3)
        if trace.exists():
            with trace.open("rb") as source, (evidence / (label + ".syscalls.private")).open("xb") as retained:
                retained.write(source.read(TRACE_CAP))
                os.chmod(retained.name, 0o600)
    require(not timed_out, "diagnostic_deadline_exceeded")
    require(not exceeded.is_set() and trace.stat().st_size <= TRACE_CAP, "diagnostic_output_bound_exceeded")
    require(not stream_failed.is_set() and not any(thread.is_alive() for thread in threads), "diagnostic_stream_incomplete")
    return subprocess.CompletedProcess(command, process.returncode, bytes(buffers[0]), bytes(buffers[1]))

def inspect_support(directory):
    """Regrade the two-file private export instead of trusting an export flag."""
    require(directory.is_dir() and not directory.is_symlink(), "support_directory_missing")
    require(sorted(p.name for p in directory.iterdir()) == ["manifest.json", "report.json"], "support_allowlist_mismatch")
    for path in (directory, directory / "report.json", directory / "manifest.json"):
        mode = path.lstat()
        require(mode.st_uid == os.geteuid() and stat.S_IMODE(mode.st_mode) == (0o700 if path == directory else 0o600), "support_private_mode")
        require(not path.is_symlink() and (path == directory or (stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1)), "support_unsafe_file")
        if path != directory:
            require(mode.st_size <= (128 * 1024 if path.name == "report.json" else 8191), "support_cap_exceeded")
    with (directory / "report.json").open("rb") as stream: raw = stream.read(128 * 1024 + 1)
    with (directory / "manifest.json").open("rb") as stream: manifest_raw = stream.read(8192)
    require(len(raw) <= 128 * 1024 and len(manifest_raw) < 8192, "support_cap_exceeded")
    value, manifest = json.loads(raw), json.loads(manifest_raw)
    require(value["schema"] == "sw-agent-doctor/1" and value["pilot"]["schema"] == "sw-agent-doctor-pilot/1"
            and value["active_host_call_protection"] == "unknown" and value["pilot"]["active_host_call_protection"] == "unknown", "support_schema_or_overclaim")
    require(manifest["schema"] == "sw-agent-doctor-support/1" and manifest["report_schema"] == value["schema"]
            and manifest["pilot_schema"] == value["pilot"]["schema"] and manifest["active_host_call_protection"] == "unknown"
            and manifest["privacy"] == "fixed_allowlist_no_raw_inputs_no_network"
            and manifest["files"] == [{"name": "report.json", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}], "support_manifest_mismatch")
    return {"name": directory.name, "schema": manifest["schema"], "pilot_schema": manifest["pilot_schema"],
            "report_sha256": hashlib.sha256(raw).hexdigest(), "report_bytes": len(raw),
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(), "manifest_bytes": len(manifest_raw), "private_modes_verified": True}

def preserve_private(private, evidence):
    """Retain bounded failure evidence outside the artifact allowlist, never raw installs."""
    for name in ("installer.private", "collector.private", "selected-native-record.private.json"):
        source = private / name
        if source.is_file():
            with source.open("rb") as stream, (evidence / name).open("xb") as retained:
                retained.write(stream.read(PRIVATE_FILE_CAP))
                os.chmod(retained.name, 0o600)
    require(sum(p.stat().st_size for p in evidence.rglob("*") if p.is_file() and not p.is_symlink()) <= PRIVATE_TOTAL_CAP, "private_evidence_bound_exceeded")

def grade(report, output=None):
    require(report["source_before"] == report["source_after"] and not report["source_before"]["dirty"], "exact_source_changed")
    require(report["source_files_before"] == report["source_files_after"], "source_files_changed")
    require([r["case"] for r in report["cases"]] == list(CASES) and all(r["passed"] and r["executed_programs"] == 1 for r in report["cases"]), "required_cases_incomplete")
    require(report["original_profiles_verified"] and report["real_managed_daemon"] and report["real_refusal"]
            and report["workspace_unchanged"] and report["operator_config_unchanged"] and report["daemon_stopped"], "required_installed_evidence_missing")
    refusal = report["real_refusal"]
    require(isinstance(refusal, dict) and refusal["verdict"] == "deny" and refusal["released"] is False
            and refusal["useful_prior_read"] is True and refusal["collector_cleanup"] is True
            and refusal["forced_cleanup"] is False and refusal["collector_exit_code"] == 0
            and all(re.fullmatch(r"[0-9a-f]{64}", refusal[key]) for key in ("record_sha256", "process_witness_sha256")), "real_refusal_or_cleanup_missing")
    require(report["skipped"] == 0 and report["privacy_scan_passed"], "required_skip_or_privacy_failure")
    require([item["name"] for item in report["support_exports"]] == list(SUPPORT_NAMES), "support_exports_missing")
    for item in report["support_exports"]:
        require(item["schema"] == "sw-agent-doctor-support/1" and item["pilot_schema"] == "sw-agent-doctor-pilot/1"
                and item["private_modes_verified"] is True and 0 < item["report_bytes"] <= 128 * 1024 and 0 < item["manifest_bytes"] < 8192
                and all(re.fullmatch(r"[0-9a-f]{64}", item[key]) for key in ("report_sha256", "manifest_sha256")), "support_evidence_invalid")
    if output is not None:
        require(report["support_exports"] == [inspect_support(output / name) for name in SUPPORT_NAMES], "support_export_changed")
        for row in report["cases"]:
            for suffix in ("stdout", "stderr", "process.json"):
                path = output / (row["case"] + "." + suffix)
                require(not path.is_symlink() and path.is_file(), "case_artifact_missing")
                expected = row["process_sha256"] if suffix == "process.json" else row[suffix + "_sha256"]
                require(sha(path) == expected, "case_artifact_changed")
            witness = json.loads((output / (row["case"] + ".process.json")).read_bytes())
            require(witness["format"] == "sw-pilot-doctor-process/1" and witness["executed_programs"] == 1
                    and witness["extra_execution_attempts"] == 0 and witness["non_thread_process_attempts"] == 0
                    and re.fullmatch(r"[0-9a-f]{64}", witness["trace_sha256"]), "process_witness_invalid")



@contextmanager
def running_owned_daemon(lifecycle):
    """Cover setup failures too; explicit stop and final cleanup share one owner."""
    running = True
    def stop():
        nonlocal running
        if running:
            lifecycle("stop")
            running = False
    try:
        lifecycle("start")
        yield stop
    finally:
        stop()


def qualify(args, private, output, evidence, report, secrets):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "linux_x86_64_required")
    report["source_before"] = BASE.source()
    require(not report["source_before"]["dirty"] and report["source_before"]["commit"] == args.expected_commit, "exact_clean_candidate_required")
    report["source_files_before"] = {name: sha(ROOT / name) for name in FILES}
    selected = {name: getattr(args, name).resolve(strict=True) for name in ("agentfw", "git_launcher", "node", "npm", "bwrap", "git", "strace")}
    report["selected_sha256"] = {name: sha(path) for name, path in selected.items()}
    workspace = private / "workspace"; workspace.mkdir(mode=0o700)
    home_root = private / "user"; home_root.mkdir(mode=0o700)
    env = BASE.environment(home_root)
    env.update(PATH=str(selected["node"].parent) + os.pathsep + os.defpath,
               GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0",
               GIT_AUTHOR_NAME="Owned diagnostic witness", GIT_COMMITTER_NAME="Owned diagnostic witness",
               GIT_AUTHOR_EMAIL="owned@example.invalid", GIT_COMMITTER_EMAIL="owned@example.invalid")
    def git(*cmd):
        return subprocess.check_output([str(selected["git"]), *cmd], cwd=workspace, env=env, timeout=15)
    git("init", "--initial-branch=main", "--template=")
    (workspace / "notes.txt").write_text("SOU114 useful original-server notes.\n")
    (workspace / "credentials.txt").write_bytes(CANARIES[0])
    git("add", "."); git("commit", "-m", "Owned baseline")
    # Cargo's top-level debug binary is normally hard-linked to its deps entry.
    # The installed diagnostic deliberately refuses hard-linked selected assets.
    # Preparation alone stages an exact private single-linked installation copy;
    # no diagnostic path changes assets or relaxes the no-follow/single-link rule.
    launcher = private / "agentfw-git-sandbox"
    shutil.copyfile(selected["git_launcher"], launcher); launcher.chmod(0o700)
    require(sha(launcher) == report["selected_sha256"]["git_launcher"] and launcher.stat().st_nlink == 1,
            "owned_launcher_copy_mismatch")
    report["installed_launcher"] = {"sha256": sha(launcher), "single_link": True,
        "source_link_count": selected["git_launcher"].stat().st_nlink}
    fs, gt = private / "filesystem", private / "git"
    with (private / "installer.private").open("wb") as log:
        BASE.INSTALL.install(fs, workspace, selected["node"], selected["bwrap"], selected["npm"], log=log)
        GIT.INSTALL.install(gt, workspace, selected["git"], sha(selected["git"]), selected["bwrap"], launcher, log=log)
    report["profiles"] = {kind: {"profile_sha256": sha(path / "profile.json"), "receipt_sha256": sha(path / "installation.json"),
        "package_tree_sha256": json.loads((path / "profile.json").read_text())["packageTreeSha256"]} for kind, path in (("filesystem", fs), ("git", gt))}
    registry = private / "registry.json"
    write(registry, {"contract_version": "sw-native/1", "registry_id": "sou114-installed-pair", "tools":
        json.loads((fs / "registry.json").read_text())["tools"] + json.loads((gt / "registry.json").read_text())["tools"]})
    classifier = private / "classifier.py"
    shutil.copyfile(ROOT / "rule_baseline/rule_baseline.py", classifier); classifier.chmod(0o600)
    binary = private / "agentfw"; shutil.copyfile(selected["agentfw"], binary); binary.chmod(0o700)
    policy = private / "policy.yaml"
    policy.write_text("agent_policies:\n  - name: owned-refusal\n    when: { action_class: read_only, touches_sensitive_path: true }\n    action: deny\ndefault: allow\n")
    policy.chmod(0o600)
    def lifecycle(*cmd):
        result = subprocess.run([str(binary), "lifecycle", *cmd], cwd=private, env=env, capture_output=True, timeout=30)
        require(result.returncode == 0, "owned_lifecycle_failed")
        return result
    # Preparation is explicit in this driver, never in the doctor command.
    subprocess.run([str(binary), "install"], cwd=private, env=env, capture_output=True, timeout=30, check=True)
    home = home_root / ".agentfw"
    write(home / "config.yaml", {"port": BASE.DEMO.free_port(), "enforce": True, "policy": str(policy),
        "native": {"registry_path": str(registry), "registry_sha256": sha(registry)}})
    with (home / "config.yaml").open("ab") as stream: stream.write(b"# " + CANARIES[1] + b"\n")
    operator = private / "operator-settings.json"; write(operator, {"unrelated": CANARIES[1].decode()})
    lifecycle("install", "sou114", str(binary), "--sha256", sha(binary))
    installed_bin = home / "versions/agentfw-sou114"
    clients = []
    with running_owned_daemon(lifecycle) as stop_daemon:
        report["real_managed_daemon"] = True
        secrets.extend([private.as_posix().encode(), (home / "token").read_bytes().strip(), (home / "native-token").read_bytes().strip()])
        baseline = {p: p.read_bytes() for p in (home / "config.yaml", home / "versions/lifecycle.json", policy, registry, operator, classifier, fs / "profile.json", gt / "profile.json")}
        workspace_before = digest(BASE.snapshot(workspace))
        common = [str(installed_bin), "doctor", "--pilot", "--home", str(home), "--agent", str(installed_bin),
            "--fs-profile", str(fs / "profile.json"), "--git-profile", str(gt / "profile.json"), "--workspace", str(workspace),
            "--classifier-script", str(classifier), "--classifier-sha256", sha(classifier)]
        report["cases"] = []
        report["support_exports"] = []
        support_stage = evidence / "support-staging"
        support_stage.mkdir(mode=0o700)
        def publish_support(name):
            staged = support_stage / name
            verified = inspect_support(staged)
            for file in staged.iterdir(): scan(file.read_bytes(), secrets)
            os.rename(staged, output / name)
            report["support_exports"].append(verified)
        def doctor(label, extra=(), code=0, reason=None, text=False):
            require(label in CASES, "unknown_diagnostic_case")
            print(json.dumps({"format":"sw-pilot-doctor-progress/1", "case":label, "status":"starting"}), flush=True)
            before = {p: p.read_bytes() for p in baseline}
            before_workspace = digest(BASE.snapshot(workspace))
            started = time.monotonic()
            report["current_case"] = label
            trace = private / (label + ".syscalls.private")
            result = run_observed([str(selected["strace"]), "-f", "-qq", "-s", "8192", "-e", "trace=process", "-o", str(trace), "--",
                *common, *([] if text else ["--json"]), *extra], private, env, trace, evidence, label)
            observed = trace.read_text()
            witness = process_witness(observed, installed_bin)
            scan(result.stdout + result.stderr, secrets)
            (output / (label + ".stdout")).write_bytes(result.stdout)
            (output / (label + ".stderr")).write_bytes(result.stderr)
            (output / (label + ".stdout")).chmod(0o600)
            (output / (label + ".stderr")).chmod(0o600)
            require(result.returncode == code, "diagnostic_exit_" + label)
            if text:
                require(b"Next:" in result.stdout and b"active-host protection UNKNOWN" in result.stdout, "operator_text_missing")
                value = None
            else:
                value = json.loads(result.stdout)
                require(value["active_host_call_protection"] == "unknown" and value["pilot"]["active_host_call_protection"] == "unknown", "execution_overclaim")
                if reason:
                    found = [c["reason_code"] for c in value["pilot"]["checks"]]
                    if value["pilot"].get("incident"): found.append(value["pilot"]["incident"]["reason_code"])
                    require(reason in found, "diagnostic_reason_" + label)
            require(before == {p: p.read_bytes() for p in before}, "diagnostic_changed_operator_input")
            require(before_workspace == digest(BASE.snapshot(workspace)), "diagnostic_changed_workspace")
            write(output / (label + ".process.json"), witness)
            report["cases"].append({"case": label, "exit_code": code, "elapsed_ms": round((time.monotonic()-started)*1000),
                "executed_programs": 1, "process_observer": "strace process syscalls", "process_sha256": sha(output / (label + ".process.json")),
                "stdout_sha256": sha(output / (label + ".stdout")), "stderr_sha256": sha(output / (label + ".stderr")), "passed": True})
            print(json.dumps({"format":"sw-pilot-doctor-progress/1", "case":label, "status":"pass"}), flush=True)
            return value
        try:
            healthy = doctor("healthy-json", ["--support-bundle", str(support_stage / "healthy-support")], reason="current_instance_ready_not_execution")
            require(all(any(c["id"]==kind+"_profile" and c["reason_code"]=="original_profile_pins_verified" for c in healthy["pilot"]["checks"]) for kind in ("filesystem", "git")), "original_pair_not_verified")
            publish_support("healthy-support")
            report["original_profiles_verified"] = True
            doctor("healthy-text", text=True)
            # Actual selected original server and enforcing daemon generate the
            # incident. This setup call is outside doctor and separately recorded.
            with (private / "collector.private").open("wb") as log:
                profile = json.loads((fs / "profile.json").read_text())
                collector_env = dict(env, AGENTFW_MCP_SERVER_PROFILE=str(fs / "profile.json"), AGENTFW_WORKSPACE=str(workspace),
                    AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(classifier), AGENTFW_CLASSIFIER_PYTHON=sys.executable)
                client = BASE.Client([str(installed_bin), "mcp", "--native-admission", "--id", "filesystem", "--",
                    profile["runtimePath"], str(Path(profile["packageRoot"]) / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), "/workspace"], collector_env, workspace, log, "owned real incident")
                clients.append(client)
                client.initialize()
                useful, _ = client.exchange(BASE.call(10, {"path": "/workspace/notes.txt"}))
                require("SOU114 useful" in BASE.result_text(useful), "useful_original_read_missing")
                refused, _ = client.exchange(BASE.call(11, {"path": "/workspace/credentials.txt"}))
                require(BASE.refused(refused), "actual_refusal_missing")
                client.close()
            rows = [json.loads(line) for line in (home / "audit.jsonl").read_bytes().splitlines()]
            selected_rows = [r for r in rows if r.get("event")=="native_call" and r.get("tool")=="read_text_file" and r.get("verdict")=="deny" and r.get("released") is False and r.get("rule")=="owned-refusal"]
            require(len(selected_rows)==1, "exact_recorded_refusal_missing")
            incident = selected_rows[0]
            write(private / "selected-native-record.private.json", incident)
            report["real_refusal"] = {"record_sha256": digest(incident), "verdict": "deny", "released": False,
                "useful_prior_read": True, "collector_cleanup": client.process_witness.final["all_stopped"],
                "forced_cleanup": client.forced_cleanup, "collector_exit_code": client.process.returncode,
                "process_witness_sha256": digest(client.process_witness.final)}
            require(not client.forced_cleanup and client.process.returncode == 0, "collector_cleanup_not_completed_normally")
            reference = ["--incident-file", str(home / "audit.jsonl"), "--incident-source", "native-audit",
                "--incident-session", incident["session"], "--incident-seq", str(incident["seq"])]
            value = doctor("recorded-refusal", reference + ["--support-bundle", str(support_stage / "incident-support")], reason="recorded_native_policy_refusal")
            require(value["pilot"]["incident"]["current_instance_binding"] == "not_recorded_by_this_source", "audit_upgraded_to_current_instance")
            require(value["pilot"]["incident"]["selected_record_sha256"] == [digest(incident)], "selected_refusal_digest_mismatch")
            publish_support("incident-support")
            changed = Path(profile["packageRoot"]) / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
            original = changed.read_bytes(); changed.write_bytes(original+b"\n// changed asset\n")
            doctor("changed-asset", code=3, reason="pilot_package_changed_or_unsafe")
            changed.write_bytes(original)
            original_classifier = classifier.read_bytes()
            classifier.write_bytes(original_classifier + b"\n# " + CANARIES[2] + b"\n")
            changed_classifier = doctor("changed-classifier", code=3, reason="pilot_classifier_pin_mismatch_or_unavailable")
            require(changed_classifier["pilot"]["setup"] == "failed", "classifier_drift_reported_ready")
            classifier.write_bytes(original_classifier)
            # Synthetic negative evidence tests the reader; it is never a positive
            # original-daemon substitute or represented as authenticated history.
            incident_file = private / "incident.jsonl"
            def event_file(row):
                incident_file.write_text(json.dumps(row)+"\n"); incident_file.chmod(0o600)
            synthetic_ref = ["--incident-file", str(incident_file), *reference[2:]]
            event_file(dict(incident, seq=incident["seq"]+999))
            doctor("missing-incident", synthetic_ref, reason="incident_missing_or_rotated")
            event_file(dict(incident, at_ms=1))
            doctor("stale-incident", synthetic_ref, reason="incident_stale_or_future_record")
            event_file(dict(incident, registry_sha256="0"*64))
            doctor("mismatched-incident", synthetic_ref, reason="incident_mismatched_or_ambiguous")
            incident_file.write_bytes(b"not-json " + CANARIES[2] + b"\n")
            doctor("malformed-input", synthetic_ref, reason="incident_malformed_record")
            with incident_file.open("wb") as stream: stream.truncate(8*1024*1024+1)
            doctor("oversized-input", synthetic_ref, reason="incident_unavailable_or_unsafe")
            incident_file.unlink(); incident_file.symlink_to(home / "audit.jsonl")
            doctor("symlink-input", synthetic_ref, reason="incident_unavailable_or_unsafe")
            incident_file.unlink(); os.mkfifo(incident_file, 0o600)
            doctor("fifo-input", synthetic_ref, reason="incident_unavailable_or_unsafe")
            incident_file.unlink(); event_file(incident); incident_file.chmod(0o644)
            doctor("public-input", synthetic_ref, reason="incident_unavailable_or_unsafe")
            doctor("existing-output", ["--support-bundle", str(output / "healthy-support")], code=4)
            (output / "link").symlink_to(output / "healthy-support", target_is_directory=True)
            doctor("symlink-output", ["--support-bundle", str(output / "link")], code=4)
            (output / "link").unlink()
            doctor("workspace-output", ["--support-bundle", str(workspace / "must-not-exist")], code=4)
            require(baseline == {p: p.read_bytes() for p in baseline}, "operator_inputs_changed")
            report["operator_config_unchanged"] = True
            report["workspace_unchanged"] = digest(BASE.snapshot(workspace)) == workspace_before
            stop_daemon()
            doctor("daemon-unavailable", code=3, reason="pilot_daemon_unavailable_or_unverifiable")
            report["daemon_stopped"] = True
            for file in output.rglob("*"):
                require(not file.is_symlink(), "published_link")
                if file.is_file(): scan(file.read_bytes(), secrets)
            report["privacy_scan_passed"] = True
            report.pop("current_case", None)
        finally:
            for client in clients:
                if client.process.poll() is None: client.close()
    report["source_after"] = BASE.source()
    report["source_files_after"] = {name: sha(ROOT / name) for name in FILES}
    grade(report, output)


def emit_public_evidence(output, secrets):
    """Mirror only already-sanitized finite public evidence into readable CI logs.

    Raw private incident/authority/syscall/server files are never eligible.
    This also makes a failed check diagnosable when artifact download is absent.
    """
    names = ["report.json"]
    names += [case + "." + suffix for case in CASES for suffix in ("stdout", "stderr", "process.json")]
    names += [name + "/" + file for name in SUPPORT_NAMES for file in ("report.json", "manifest.json")]
    frames = []
    total = 0
    for name in names:
        path = output / name
        if not path.exists():
            continue
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= STREAM_CAP, "public_evidence_type_or_cap")
        raw = path.read_bytes()
        total += len(raw)
        require(total <= 2 * 1024 * 1024, "public_evidence_total_cap")
        scan(raw, secrets)
        frames.append({"format": "sw-pilot-doctor-public-file/1", "name": name,
                       "sha256": hashlib.sha256(raw).hexdigest(), "text": raw.decode("utf-8")})
    for frame in frames:
        print(json.dumps(frame, sort_keys=True))

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    for name in ("agentfw", "git-launcher", "node", "npm", "bwrap", "git", "strace"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args=parser.parse_args(argv)
    args.output=args.output.absolute()
    require(not args.output.exists() and not args.output.is_symlink() and not args.output.is_relative_to(ROOT), "new_external_output_required")
    args.output.mkdir(mode=0o700)
    report={"format":"sw-pilot-doctor-acceptance/1","status":"incomplete","cases":[],"skipped":0}
    # The artifact uploader selects only args.output. These bounded raw failure
    # witnesses are sibling files in a distinct private directory, never published.
    evidence = Path(tempfile.mkdtemp(prefix="sou114-private-evidence-", dir=args.output.parent))
    secrets = list(CANARIES)
    try:
        with tempfile.TemporaryDirectory(prefix="sou114-owned-", dir="/tmp") as root:
            try:
                qualify(args, Path(root), args.output, evidence, report, secrets)
            finally:
                preserve_private(Path(root), evidence)
        report["status"]="pass"
    except Exception as error:
        report["status"]="fail";report["error_code"]="required_diagnostic_acceptance_failed"
        finite_case_errors = {"diagnostic_" + kind + "_" + case for kind in ("exit", "reason") for case in CASES}
        if isinstance(error, ValueError) and str(error) in finite_case_errors | {
            "linux_x86_64_required", "exact_clean_candidate_required", "owned_lifecycle_failed", "original_pair_not_verified",
            "exact_recorded_refusal_missing", "collector_cleanup_not_completed_normally", "actual_refusal_missing", "useful_original_read_missing",
            "published_privacy_canary", "diagnostic_spawned_program", "diagnostic_spawned_process", "diagnostic_deadline_exceeded",
            "diagnostic_output_bound_exceeded", "diagnostic_stream_incomplete", "private_evidence_bound_exceeded"
        }:
            report["error_code"] = str(error)
        # An arbitrary exception could contain private paths or credentials.
        # Keep only the finite failure code in published output.
    try:
        scan(json.dumps(report, sort_keys=True).encode(), secrets)
    except ValueError:
        # Do not publish a partial report if a future field introduces raw data.
        report = {"format": "sw-pilot-doctor-acceptance/1", "status": "fail", "cases": [],
                  "skipped": 0, "error_code": "published_report_privacy_failure"}
    write(args.output / "report.json", report)
    print(json.dumps({key: report[key] for key in ("format","status","skipped")}, sort_keys=True))
    emit_public_evidence(args.output, secrets)
    return 0 if report["status"]=="pass" else 1

if __name__=="__main__":
    raise SystemExit(main())
