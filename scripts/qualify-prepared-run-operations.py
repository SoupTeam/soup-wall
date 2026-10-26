#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native Ubuntu witness for discovery and completed runtime-state archival.

Only owned scripted providers, accepted prepared selections and pinned original
servers are used. Raw process identities, traces, state and archives stay private.
The public report contains finite outcomes, counts and content/source digests.
"""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_run_state as S


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


Q = load("operations_original_qualification", "qualify-prepared-pilot-run.py")
A = load("operations_archive", "pilot-run-archive.py")
require = Q.require


class Prepared(Q.STOP.Prepared):
    """Use the accepted kernel/provider witnesses with one shared state parent."""
    def __init__(self, context, root, state, hold=True):
        self.c, self.root, self.state = context, root, state
        root.mkdir(mode=0o700)
        self.trace = root / "trace.private"
        self.model = context.base.DEMO.ScriptedModel([])
        self.model.server.handle_error = lambda *_: None
        self.provider = Q.STOP.Provider(self.model, hold)
        self.model.next = self.provider.next
        self.env = dict(context.env, ANTHROPIC_BASE_URL=self.model.url,
                        ANTHROPIC_API_KEY="owned-loopback-only", NO_PROXY="127.0.0.1,localhost,::1")
        command = [str(context.args.strace), "-f", "-qq", "-s", "4096", "-e",
            "trace=execve,openat,write,writev,kill", "-o", str(self.trace), sys.executable, "-B",
            str(ROOT / "scripts/pilot-run.py"), "--run", "--selection", str(context.args.selection),
            "--expected-commit", context.args.expected_commit, "--state-root", str(state),
            "--timeout-seconds", "90"]
        self.provider_values = self.protocol = self.budget_path = None
        self.out = (root / "stdout.private").open("wb")
        self.err = (root / "stderr.private").open("wb")
        self.process = subprocess.Popen(command, cwd=root, env=self.env, stdout=self.out, stderr=self.err,
                                        start_new_session=True)
        self.witness = context.base.ProcessWitness(self.process.pid)
        self.record = self.run = self.manifest = None
        self.identities = {}
        try:
            self.wait_ready()
        except BaseException:
            self.close()
            raise

    def wait_ready(self):
        def identify():
            require(self.process.poll() is None, "operations_prepared_entry_exited")
            for path in self.state.glob("*/run.json"):
                try:
                    record = json.loads(path.read_bytes())
                    pid = record["supervisor_pid"]
                    ppid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
                    if ppid != self.process.pid:
                        continue
                    home = Path(record["home"])
                    for manifest in (home / "pilot-runs").glob("*/run.json"):
                        run = json.loads(manifest.read_bytes())
                        require(run["launcher_pid"] == record["launcher_pid"] and run["home"] == str(home)
                                and run["run_id"] == manifest.parent.name, "operations_native_identity_mismatch")
                        self.record, self.home, self.run, self.manifest = record, home, run, manifest
                        return True
                except (OSError, ValueError, KeyError):
                    continue
        Q.until(identify, "operations_prepared_not_ready", seconds=90)
        Q.until(self.provider.ready.is_set, "operations_actual_host_not_ready", seconds=90)
        self.observe()
        self.capture_identities()
        self.initial_owners = Q.STOP.enrolled_owners(self.run, self.native(), False)

    def finish(self, stopped=False, failure=None):
        self.process.wait(timeout=105)
        self.out.flush(); self.err.flush()
        outcome = json.loads((self.root / "stdout.private").read_text().splitlines()[-1])
        if failure:
            require(self.process.returncode != 0 and outcome["status"] == "failed"
                    and outcome.get("reason") in failure, "operations_expected_loss_not_reported")
        else:
            require(self.process.returncode == 0 and outcome["status"] == ("stopped" if stopped else "completed"),
                    "operations_terminal_outcome_wrong")
        cleanup = self.witness.finish()
        require(cleanup["all_stopped"] and all(self.c.base.ProcessWitness.identity(pid) != start
                for pid, start in self.identities), "operations_owned_descendant_survived")
        if stopped:
            require(outcome["cleanup"] == "owned_processes_stopped_state_retained", "operations_stop_state_lost")
            self.receipt(True)
            self.operator(True, "already_stopped")
        else:
            require(outcome["cleanup"] == "owned_processes_stopped_audit_retained", "operations_audit_state_lost")
            S.AUDIT.verify_cleanup(self.home.parent)
        return {"entry_status": outcome["status"], "owned_processes_stopped": True,
                "observed_roles": {role: len(rows) for role, rows in self.roles.items()},
                "trace_sha256": S.sha(self.trace.read_bytes())}


def snapshot(root):
    return {str(path.relative_to(root)): [path.lstat().st_mode, path.lstat().st_uid,
            path.lstat().st_size, path.lstat().st_mtime_ns,
            S.sha(path.read_bytes()) if path.is_file() and not path.is_symlink() else None]
            for path in root.rglob("*")}


def qualify(args, private, report, save):
    Q.RUN.PREP.supported_platform()
    require({name for _, name in socket.if_nameindex()} == {"lo"}, "operations_private_loopback_required")
    before = Q.RUN.PREP.PILOT.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit,
            "operations_clean_exact_source_required")
    config = argparse.Namespace(selection=args.selection, expected_commit=args.expected_commit,
                                ask_wait_seconds=0, timeout_seconds=90, port=0)
    selection, paths, profiles = Q.RUN.selected(config)
    fs, repository, notes = Q.prepare_owned_workspaces(selection, profiles)
    workspaces = {"filesystem": Q.BASE.snapshot(fs), "git": Q.BASE.snapshot(repository)}
    selected_hashes = {key: Q.BASE.sha(path) for key, path in paths.items()}
    state, archives = private / "state", private / "archives"
    state.mkdir(mode=0o700); archives.mkdir(mode=0o700)
    marker = private / "unrelated.txt"
    marker.write_text("Owned unrelated state must survive.\n")
    unrelated = subprocess.Popen(["/usr/bin/sleep", "600"], start_new_session=True)
    unrelated_identity = Q.BASE.ProcessWitness.identity(unrelated.pid)
    context = SimpleNamespace(args=args, source=ROOT, base=Q.BASE, run=Q.RUN, launch=Q.LAUNCH, ask=Q.ASK,
        paths=paths, notes=notes, useful=Q.useful_result,
        env={"PATH": "/usr/bin:/bin", "HOME": str(private), "LANG": "C.UTF-8"})
    active = []
    report.update(source_before=before, selected_sha256=selected_hashes, cases=[],
                  environment={"kernel": os.uname().release, "ubuntu": "24.04", "non_root": os.getuid() != 0,
                               "private_loopback": True}, provider="owned-scripted-loopback", paid_provider_calls=0)
    save()
    def passed(case, **evidence):
        report["cases"].append({"case": case, "status": "passed", **evidence})
        save()
    def cli(script, words, label, injection=None, timeout=30):
        trace = private / (label + ".trace.private")
        command = [str(args.strace), "-f", "-qq", "-s", "256", "-e",
            "trace=execve,connect,openat,unlinkat,renameat2,rmdir,kill,chmod,fchmod", "-o", str(trace)]
        if injection:
            command += ["-e", "inject=" + injection]
        command += [sys.executable, "-B", str(ROOT / "scripts" / script), *map(str, words)]
        value = subprocess.run(command, cwd=private, env=context.env, capture_output=True, timeout=timeout)
        require(len(value.stdout) <= 256 * 1024, "operations_cli_output_limit")
        # No private logs, token bytes, prompts/results or raw responses escape.
        payload = S.strict(value.stdout) if value.stdout.strip() else None
        text = trace.read_text(errors="replace")
        return value.returncode, payload, text
    def observe(label, ids, probe=False):
        calls = [len(p.model.requests) for p in active]
        controls = {str(p.root): {name: (p.home / name).read_bytes() for name in ("config.yaml", "token", "native-token")}
                    for p in active if p.process.poll() is None}
        words = ["--state-parent", state]
        for identity in ids:
            words += ["--run-id", identity]
        if probe:
            words += ["--probe", "--probe-seconds", "30"]
        code, value, trace = cli("pilot-runs.py", words, label, timeout=40)
        require([len(p.model.requests) for p in active] == calls, "operations_probe_contacted_provider")
        for p in active:
            if str(p.root) in controls and p.process.poll() is None:
                require(all((p.home / name).read_bytes() == raw for name, raw in controls[str(p.root)].items()),
                        "operations_observation_changed_settings")
        require(not any(op in trace for op in ("unlinkat(", "renameat2(", "rmdir(", "chmod(", "fchmod(")),
                "operations_observation_wrote_state")
        if not probe:
            require("connect(" not in trace, "operations_default_contacted_endpoint")
        else:
            ports = {str(p.record["port"]) for p in active if p.record}
            contacts = re.findall(r"sin_port=htons\(([0-9]+)\).*?sin_addr=inet_addr\(\"([^\"]+)\"\)", trace)
            require(all(port in ports and address == "127.0.0.1" for port, address in contacts), "operations_foreign_endpoint_contact")
        return code, value, S.sha(trace.encode())
    def identity(pilot):
        return pilot.home.parent.name.removeprefix("soup-wall-run-")
    def planned(run_id, label):
        code, plan, _ = cli("pilot-run-archive.py", ["preview", "--state-parent", state, "--run-id", run_id], label)
        require(code == 0 and len(plan["runs"]) == 1, "operations_completed_preview_failed")
        path = archives / (label + ".json")
        path.write_bytes(S.encoded(plan)); path.chmod(0o600)
        return plan, path
    def command(action, plan, path, label, injection=None):
        return cli("pilot-run-archive.py", [action, "--plan", path, "--confirm", plan["plan_sha256"],
                   "--archive-directory", archives], label, injection)
    try:
        subject = Prepared(context, private / "subject", state, hold=True); active.append(subject)
        peer = Prepared(context, private / "peer", state, hold=False); active.append(peer)
        ids = [identity(subject), identity(peer)]
        code, listing, digest = observe("simultaneous-list", ids)
        require(code == 0 and len(listing["runs"]) == 2, "operations_two_runs_not_listed")
        passed("two-simultaneous-recorded-runs", count=2, no_effects=True, trace_sha256=digest)
        code, observed, digest = observe("simultaneous-probe", ids, True)
        require(code == 0 and all(row["observation"]["state"] == "authenticated_daemon_observed"
            and len(row["observation"]["paths"]) == 7 and row["protection"] == "unknown"
            and row["observation"]["binary_sha256"] == row["recorded"]["binary_sha256"]
            for row in observed["runs"]), "operations_authenticated_probe_failed")
        require(len({row["observation"]["policy_sha256"] for row in observed["runs"]}) == 1,
                "operations_selected_policy_observations_differ")
        passed("two-authenticated-original-runs", count=2, accepted_diagnostic_projection=True,
               probe_provider_requests=0, settings_unchanged=True, trace_sha256=digest)
        for run_id in ids:
            code, value, _ = cli("pilot-run-archive.py", ["preview", "--state-parent", state, "--run-id", run_id], "active-preview-" + run_id)
            require(code == 2 and not value["runs"], "operations_active_cleanup_eligible")
        passed("active-run-removal-refused", excluded=2)
        # A live unrelated PID cannot substitute for a sealed launcher identity.
        original_record = (subject.home.parent / "run.json").read_bytes()
        changed = S.strict(original_record); changed["launcher_pid"] = unrelated.pid
        (subject.home.parent / "run.json").write_bytes(S.encoded(changed))
        code, value, _ = observe("foreign-process", [ids[0]], True)
        require(code == 2 and value["runs"][0]["observation"]["state"] == "unavailable", "operations_foreign_process_accepted")
        (subject.home.parent / "run.json").write_bytes(original_record)
        passed("foreign-process-refused", unrelated_survived=Q.BASE.ProcessWitness.identity(unrelated.pid) == unrelated_identity)
        old_instance = subject.run["instance_id"]
        subject.signal(subject.record["daemon_pid"], signal.SIGKILL)
        code, value, _ = observe("daemon-loss-probe", [ids[0]], True)
        require(code == 2, "operations_lost_daemon_accepted")
        loss = subject.finish(failure={"owned_daemon_lost"}); active.remove(subject); subject.close()
        passed("daemon-loss", **loss)
        fresh = Prepared(context, private / "fresh", state, hold=True); active.append(fresh)
        require(fresh.run["instance_id"] != old_instance, "operations_daemon_restart_reused_identity")
        code, value, _ = observe("fresh-and-peer", [identity(fresh), ids[1]], True)
        require(code == 0, "operations_restart_or_peer_probe_failed")
        fresh.useful()
        fresh.operator(True)
        stopped = fresh.finish(stopped=True); active.remove(fresh); fresh.close()
        code, value, _ = observe("retained-stop", [identity(fresh)])
        require(value["runs"][0]["lifecycle"] == "retained_stop_state", "operations_retained_stop_misclassified")
        code, value, _ = cli("pilot-run-archive.py", ["preview", "--state-parent", state, "--run-id", identity(fresh)], "retained-preview")
        require(code == 2 and not value["runs"], "operations_stop_receipt_cleanup_eligible")
        passed("restart-and-retained-stop", fresh_instance=True, repeated_stop_verified=True, **stopped)
        peer.provider.release.set()
        completed = peer.finish(); peer.check_useful(); active.remove(peer); peer.close()
        passed("genuine-original-completed-state", filesystem_kernel_reads=1, git_status_dispatches=1, **completed)
        completed_path, completed_id = peer.home.parent, ids[1]
        import fcntl
        with (completed_path / "audit/writer.lock").open("rb") as writer:
            fcntl.flock(writer.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, value, _ = cli("pilot-run-archive.py", ["preview", "--state-parent", state, "--run-id", completed_id], "held-writer-lock")
            require(code == 2 and value["excluded"][0]["reason"] == "active_audit_writer", "operations_live_writer_not_refused")
        passed("held-native-audit-writer-refused", source_retained=True)
        baseline = snapshot(completed_path)
        code, value, _ = observe("completed-list", [completed_id])
        require(code == 0 and value["runs"][0]["lifecycle"] == "completed_audit_only"
                and snapshot(completed_path) == baseline, "operations_completed_state_not_read_only")
        passed("completed-audit-only-discovery", state_unchanged=True)
        code, value, _ = cli("pilot-runs.py", ["--state-parent", state, "--scan-limit", "1"], "scan-limit")
        require(code == 2 and not value["complete"], "operations_scan_limit_hidden")
        passed("scan-limit-explicit")
        # Genuine state with controlled malformed/oversized records; restore each
        # exact original byte sequence before the next independent preview.
        receipt = completed_path / "audit-run.json"
        original_receipt = receipt.read_bytes()
        for label, replacement in (("malformed", b"{"), ("oversized", b" " * 65537)):
            receipt.write_bytes(replacement)
            before_bad = snapshot(completed_path)
            code, value, _ = observe(label + "-record", [completed_id])
            require(code == 2 and snapshot(completed_path) == before_bad, "operations_bad_record_changed")
            receipt.write_bytes(original_receipt)
            passed(label + "-record-refused", state_unchanged=True)
        audit_manifest = completed_path / "audit/manifest.json"
        saved_manifest = audit_manifest.read_bytes()
        changed_manifest = S.strict(saved_manifest)
        segment = completed_path / "audit" / f"segment-{changed_manifest['segments'][0]['id']:020}.jsonl"
        saved_segment = segment.read_bytes()
        for label in ("corrupt", "oversized-audit"):
            if label == "corrupt":
                changed_manifest["segments"][0].update(closed=True, bytes=len(saved_segment), sha256="0" * 64)
                audit_manifest.write_bytes(S.encoded(changed_manifest))
            else:
                segment.write_bytes(b" " * 65537)
            changed_snapshot = snapshot(completed_path)
            code, value, _ = cli("pilot-run-archive.py", ["preview", "--state-parent", state, "--run-id", completed_id], label)
            require(code == 2 and snapshot(completed_path) == changed_snapshot, "operations_bad_audit_not_retained")
            audit_manifest.write_bytes(saved_manifest); segment.write_bytes(saved_segment)
            passed(label + "-refused", source_retained=True)
        renamed = state / "owned-saved-completed"
        completed_path.rename(renamed)
        completed_path.symlink_to(renamed, target_is_directory=True)
        saved_snapshot = snapshot(renamed)
        code, _, _ = observe("linked-candidate", [completed_id])
        require(code == 2 and snapshot(renamed) == saved_snapshot, "operations_linked_candidate_accepted")
        completed_path.unlink(); renamed.rename(completed_path)
        passed("symlink-candidate-refused", target_unchanged=True)
        # Exact real foreign uid fixture is provisioned by the trusted parent.
        foreign_before = [(p.relative_to(args.foreign_state).as_posix(), p.lstat().st_uid,
                           p.lstat().st_mode, p.lstat().st_ino, p.lstat().st_size) for p in args.foreign_state.rglob("*")]
        code, value, _ = cli("pilot-runs.py", ["--state-parent", args.foreign_state, "--probe"], "foreign-uid")
        require(code == 2 and any(row["reason"] == "private_regular_file_required" for row in value["runs"]),
                "operations_foreign_uid_not_refused")
        foreign_after = [(p.relative_to(args.foreign_state).as_posix(), p.lstat().st_uid,
                          p.lstat().st_mode, p.lstat().st_ino, p.lstat().st_size) for p in args.foreign_state.rglob("*")]
        require(foreign_before == foreign_after, "operations_foreign_state_changed")
        passed("native-foreign-ownership-refused", unchanged=True, emulated=False)
        plan, plan_path = planned(completed_id, "completed-preview")
        original_manifest = (completed_path / "audit/manifest.json").read_bytes()
        manifest = S.strict(original_manifest)
        manifest["generation"] += 1
        (completed_path / "audit/manifest.json").write_bytes(S.encoded(manifest))
        code, _, _ = command("archive", plan, plan_path, "changed-plan")
        require(code != 0 and completed_path.exists(), "operations_changed_plan_archived")
        (completed_path / "audit/manifest.json").write_bytes(original_manifest)
        passed("changed-plan-refused", source_retained=True)
        plan, plan_path = planned(completed_id, "archive-preview")
        before_write_failure = snapshot(completed_path)
        code, result, _ = command("archive", plan, plan_path, "failed-archive", "linkat:error=ENOSPC:when=1")
        require(code != 0 and snapshot(completed_path) == before_write_failure, "operations_archive_write_failure_not_preserved")
        code, result, _ = command("archive", plan, plan_path, "uncertain-archive-publication", "fsync:error=EIO:when=2")
        require(code != 0 and snapshot(completed_path) == before_write_failure, "operations_uncertain_archive_removed_source")
        passed("archive-write-and-publication-faults", faults=["ENOSPC", "EIO"], source_retained=True)
        # Successful archive, repeated verification, then an actual syscall-level
        # interruption during apply. No production fault/test switches exist.
        code, result, _ = command("archive", plan, plan_path, "archive")
        require(code == 0, "operations_archive_failed")
        archive_path = archives / A.archive_name(plan, plan["runs"][0])
        A.verify_archive(archive_path.read_bytes(), plan, plan["runs"][0])
        code, _, _ = command("archive", plan, plan_path, "repeated-archive")
        require(code == 0, "operations_repeat_archive_failed")
        archive_original = archive_path.read_bytes()
        archive_path.write_bytes(b"corrupted archive")
        code, _, _ = command("apply", plan, plan_path, "corrupt-archive-apply")
        require(code != 0 and snapshot(completed_path) == before_write_failure, "operations_corrupt_archive_removed_source")
        archive_path.write_bytes(archive_original)
        passed("corrupt-archive-refused", source_retained=True)
        passed("verified-private-archive", archive_sha256=S.sha(archive_path.read_bytes()), exact_member_hashes=True,
               source_retained=True, failed_write_preserved=True)
        # Retain this genuine source for interrupted removal; a second genuine
        # finished run (the loss run) supplies the independent positive apply.
        code, _, _ = command("apply", plan, plan_path, "interrupted-apply", "unlinkat:signal=SIGKILL:when=3")
        require(code != 0, "operations_interruption_not_exercised")
        quarantines = list(state.glob(".soup-wall-cleanup-*"))
        require(len(quarantines) == 1 and (quarantines[0] / "cleanup.json").is_file(), "operations_interruption_journal_missing")
        code, inspection, _ = cli("pilot-run-archive.py", ["inspect", "--plan", plan_path,
            "--confirm", plan["plan_sha256"], "--archive-directory", archives, "--quarantine", quarantines[0].name], "inspect-partial")
        require(code == 0 and inspection["runs"][0]["outcome"] == "partial"
                and inspection["runs"][0]["archive_verified"], "operations_partial_inspection_failed")
        code, value, _ = command("apply", plan, plan_path, "repeat-partial-apply")
        require(code != 0 and value.get("complete") is False, "operations_repeated_partial_claimed_success")
        passed("interrupted-deletion-recovery", archive_verified=True, remaining_files=inspection["runs"][0]["remaining_files"],
               repeated_apply_not_success=True, no_automatic_repair=True)
        loss_id = identity(subject)
        def race(kind):
            race_plan, race_path = planned(loss_id, kind + "-race-preview")
            require(command("archive", race_plan, race_path, kind + "-race-archive")[0] == 0,
                    "operations_race_archive_failed")
            previous = {p.name for p in state.glob(".soup-wall-cleanup-*")}
            trace = private / (kind + "-race.trace.private")
            command_words = [str(args.strace), "-f", "-qq", "-e", "trace=renameat2",
                "-e", "inject=renameat2:delay_enter=2s:when=" + ("2" if kind == "member" else "1"),
                "-o", str(trace), sys.executable, "-B", str(ROOT / "scripts/pilot-run-archive.py"),
                "apply", "--plan", str(race_path), "--confirm", race_plan["plan_sha256"],
                "--archive-directory", str(archives)]
            process = subprocess.Popen(command_words, cwd=private, env=context.env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            saved = state / ("owned-race-saved-" + kind)
            try:
                def barrier():
                    require(process.poll() is None, "operations_race_exited_before_barrier")
                    found = [p for p in state.glob(".soup-wall-cleanup-*")
                             if p.name not in previous and (p / "cleanup.json").exists()]
                    return found[0] if len(found) == 1 and (kind != "member" or (found[0] / "run").is_dir()) else None
                quarantine = Q.until(barrier, "operations_race_barrier_missing", seconds=15)
                if kind == "member":
                    source_member = quarantine / "run/audit/manifest.json"
                    source_member.rename(saved)
                    source_member.write_bytes(b"Owned concurrent foreign member.\n"); source_member.chmod(0o600)
                else:
                    subject.home.parent.rename(saved)
                    if kind == "symlink":
                        subject.home.parent.symlink_to(marker)
                    else:
                        subject.home.parent.mkdir(mode=0o700)
                        (subject.home.parent / "foreign.txt").write_text("Owned concurrent foreign member.\n")
                stdout, stderr = process.communicate(timeout=30)
                result = S.strict(stdout)
                require(process.returncode == 2 and result["runs"][0]["outcome"] == "partial",
                        "operations_concurrent_race_not_refused")
                if kind == "member":
                    held = [p for p in quarantine.glob("member-*") if p.read_bytes() == b"Owned concurrent foreign member.\n"]
                    require(len(held) == 1, "operations_concurrent_member_deleted")
                    saved.rename(quarantine / "run/audit/manifest.json")
                    (quarantine / "run").rename(subject.home.parent)
                else:
                    require(saved.is_dir(), "operations_original_run_lost_in_race")
                    if kind == "symlink":
                        require((quarantine / "run").is_symlink() and marker.read_text() == "Owned unrelated state must survive.\n",
                                "operations_link_target_changed")
                    else:
                        require((quarantine / "run/foreign.txt").read_text() == "Owned concurrent foreign member.\n",
                                "operations_replacement_run_deleted")
                    saved.rename(subject.home.parent)
                passed(kind + "-concurrent-race-refused", original_retained=True, replacement_retained=True,
                       syscall_delay_observed="DELAYED" in trace.read_text(), trace_sha256=S.sha(trace.read_bytes()))
            finally:
                if process.poll() is None:
                    process.kill(); process.communicate()
        for kind in ("rename", "symlink", "member"):
            race(kind)
        plan2, path2 = planned(loss_id, "positive-apply-preview")
        code, _, _ = command("archive", plan2, path2, "positive-archive")
        require(code == 0, "operations_second_archive_failed")
        code, value, _ = command("apply", plan2, path2, "positive-apply")
        require(code == 0 and value["runs"][0]["outcome"] == "archived_and_removed"
                and not subject.home.parent.exists(), "operations_positive_apply_failed")
        code, _, _ = command("apply", plan2, path2, "repeat-removed-apply")
        require(code != 0, "operations_repeat_removed_reported_success")
        passed("exact-removal-and-repeat-refusal", removed_only_selected=True, retained_stop_state=fresh.home.parent.exists())
        require(Q.BASE.ProcessWitness.identity(unrelated.pid) == unrelated_identity
                and marker.read_text() == "Owned unrelated state must survive.\n", "operations_unrelated_state_changed")
        require(workspaces == {"filesystem": Q.BASE.snapshot(fs), "git": Q.BASE.snapshot(repository)}, "operations_workspace_changed")
        require(selected_hashes == {key: Q.BASE.sha(path) for key, path in paths.items()}, "operations_selected_assets_changed")
        after = Q.RUN.PREP.PILOT.source()
        require(after == before, "operations_closing_source_changed")
        report.update(source_after=after, unrelated_process_and_file_preserved=True, workspaces_unchanged=True,
                      selected_assets_unchanged=True, native_acceptance=True, status="passed")
    finally:
        for pilot in active:
            pilot.close()
        if unrelated.poll() is None and Q.BASE.ProcessWitness.identity(unrelated.pid) == unrelated_identity:
            unrelated.terminate()
        unrelated.wait(timeout=10)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--foreign-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    private = args.output / "private"
    private.mkdir(mode=0o700)
    report = {"format": "sw-prepared-run-native-qualification/1", "status": "incomplete",
              "native_acceptance": False, "cases": []}
    def save():
        (args.output / "report.json").write_bytes(S.encoded(report) + b"\n")
    save()
    try:
        qualify(args, private, report, save)
        return 0
    except BaseException as error:
        report.update(status="failed", native_acceptance=False,
                      reason=str(error) if type(error) is ValueError and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", str(error))
                      else "native_qualification_unavailable")
        return 1
    finally:
        save()
        print(json.dumps({"status": report["status"], "native_acceptance": report["native_acceptance"],
                          "cases_passed": len(report["cases"]), "reason": report.get("reason")}, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
