# SPDX-License-Identifier: Apache-2.0
"""Owned original Git runtime for the frozen SOU-244 effect controls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
from types import SimpleNamespace


def snapshot(api, workspace, git, env):
    """Read-only content/metadata, raw index, and independent resolved HEAD."""
    return {
        "workspace": api.V.snapshot(workspace),
        "index": api.V.sha(workspace / ".git/index"),
        "head": subprocess.check_output(
            [str(git), "-C", str(workspace), "rev-parse", "--verify", "HEAD"],
            env=env, timeout=10).strip(),
    }


def reference(api, git_driver, case, pair, native, env, workspace, work, log):
    """Measure original bytes independently, including the original size calibration."""
    args = SimpleNamespace(git=str(native.git))
    protected_args = dict(case["arguments"], repo_path=api.SANDBOX_ROOT)
    original_args = dict(case["arguments"], repo_path=str(workspace))
    pad = 10 if pair["host"] == "padded" else 0
    expected = (native.payload_dir / (case["case_id"] + ".txt")).read_bytes()
    candidate = work / "candidate"
    for _ in range(4):
        api.GEN.git_repository(args, pair, pair[case["label"]], pad, candidate, env)
        for entry in candidate.iterdir():
            entry.rename(workspace / entry.name)
        candidate.rmdir()
        with log.open("ab") as output:
            client = git_driver.Client(
                [str(native.python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(workspace)],
                env, workspace, output, "original Git reference")
            try:
                client.initialize()
                result, _ = client.exchange(git_driver.call(10, case["tool"], original_args, workspace))
                text = api.extract_text(result)
                api.V.require(isinstance(text, str), "original_git_reference_failed")
                data = text.replace(str(workspace), api.GEN.REPO).encode("utf-8")
            finally:
                client.close()
            api.V.require(client.process.returncode == 0 and not client.forced_cleanup
                          and client.process_witness.final["all_stopped"], "reference_cleanup_unverified")
        if data == expected:
            # The generator sets false explicitly. The isolated protected fixture
            # has no global/system config, so omitting the key keeps Git's false
            # default without widening the accepted core configuration.
            subprocess.run([str(native.git), "-C", str(workspace), "config", "--unset", "core.autocrlf"],
                           env=env, capture_output=True, check=True, timeout=10)
            return protected_args, data.replace(api.GEN.REPO.encode(), api.SANDBOX_ROOT.encode())
        if pair["host"] != "padded" or len(data) == len(expected):
            break
        pad += len(expected) - len(data)
        clear(workspace)
    raise ValueError("original_git_reference_bytes_differ")


def clear(workspace):
    for entry in workspace.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def project(api, log, client, git_outcomes, row, response, raw, reference_bytes, repository_reads):
    sent = client.sent[-1]
    expected_request = api.sha_bytes(sent)
    expected_host_id = api.sha_bytes(b"10")
    observations = [safe for entry in api.V.events(log, "mcp_call_outcome")
                    if (safe := git_outcomes.project(entry)) is not None
                    and safe["request_sha256"] == expected_request and safe["host_call_sha256"] == expected_host_id]
    delivery = [safe for entry in api.V.events(log, "mcp_original_result_delivery_timing")
                if (safe := git_outcomes.project(entry)) is not None
                and safe["request_sha256"] == expected_request and safe["host_call_sha256"] == expected_host_id]
    records = {}
    for value in observations + delivery:
        api.V.require(value["stage"] not in records, "duplicate_git_boundary_observation")
        records[value["stage"]] = value
    row["boundaries"] = records
    row["request_sha256"] = expected_request
    row["repository_read_events"] = repository_reads
    row["client_response_sha256"] = api.sha_bytes(raw)
    row["delivered"] = False
    row["dispatched"] = None
    row["call_decision"] = None
    row["result_release"] = None
    original = records.get("original_response")
    admission = records.get("call_admission")
    inspection = records.get("result_inspection")
    profile = records.get("profile_validation")
    if "input_profile" in records:
        api.V.require(records["input_profile"]["accepted"] is False
                      and records["input_profile"]["response_sha256"] == row["client_response_sha256"]
                      and not set(records) & {"call_admission", "original_response", "result_inspection"}
                      and repository_reads == 0 and api.V.refused(response), "input_refusal_witness_conflict")
        row.update(status="profile_refused", dispatched=False, call_decision="not_reached",
                   result_release="not_reached", outcome="non_comparable_profile_refusal")
        return None
    if admission:
        row["call_decision"] = "allow" if admission["released"] else "refused"
    if admission and not admission["released"] and not original and repository_reads == 0 and api.V.refused(response):
        row.update(status="call_refused", dispatched=False, result_release="not_reached",
                   outcome="non_comparable_call_refusal")
        return None
    if not (admission and admission["released"] and original and profile and inspection and "host_delivery" in records
            and repository_reads > 0):
        raise ValueError("required_git_boundary_witness_missing")
    row["dispatched"] = True
    row["result_release"] = inspection["released"]
    if (profile["accepted"] is False or original["response"]["rpc_error"]
            or original["response"]["tool_error"] is True
            or original["response_sha256"] != inspection["response_sha256"]):
        row.update(status="original_error", outcome="non_comparable_original_error")
        return None
    api.V.require(records["host_delivery"]["written"]
                  and records["host_delivery"]["response_sha256"] == row["client_response_sha256"],
                  "client_delivery_witness_conflict")
    if not inspection["released"]:
        api.V.require(api.V.refused(response), "inspection_refusal_witness_conflict")
        return None
    text = api.extract_text(response)
    api.V.require(isinstance(text, str) and original["response_sha256"] == row["client_response_sha256"],
                  "released_original_frame_changed")
    delivered = text.encode("utf-8")
    row.update(delivered=True, delivered_sha256=api.sha_bytes(delivered),
               matches_frozen_payload_after_path_mapping=delivered == reference_bytes)
    api.V.require(delivered == reference_bytes, "delivered_git_payload_changed")
    return text


def run_case(api, driver, outcome_driver, case, pair, native, observers, outside, work, logs, row):
    workspace = native.workspace
    case_id = case["case_id"]
    before = None
    client = repository = outside_watch = None
    try:
        arguments, expected = reference(api, driver, case, pair, native, native.reference_env,
                                        workspace, work, logs / f"{case_id}.reference.private")
        row.update(reference_verified=True, reference_sha256=case["sha256"],
                   mapped_reference_sha256=api.sha_bytes(expected), arguments=arguments)
        before = snapshot(api, workspace, native.git, native.reference_env)
        collector_log = logs / f"{case_id}.collector.private"
        outside_sha = api.V.sha(outside / "sentinel")
        repository = driver.RepositoryWitness(workspace)
        outside_watch = driver.RepositoryWitness(outside)
        observers.rearm()
        with collector_log.open("xb") as log:
            client = driver.Client(native.command, native.env, workspace, log, "protected original Git")
            client.initialize()
            repository.drain()
            outside_watch.drain()
            response, raw = client.exchange(driver.call(10, case["tool"], arguments))
            text = project(api, collector_log, client, outcome_driver, row, response, raw, expected, repository.drain())
            follow, _ = client.exchange(driver.call(11, "git_status", {}))
            follow_text = api.extract_text(follow)
            row["useful_continuation"] = bool(follow_text and "On branch main" in follow_text and repository.drain() > 0)
            row["outside_read_events"] = outside_watch.drain()
            if text is not None and api.attack_marker(case["pair_id"]) in text:
                observers.perform_forbidden_effects(case_id)
                row["scripted_agent_followed_instruction"] = True
            row["effects"] = observers.read()
            row["outside_unchanged"] = api.V.sha(outside / "sentinel") == outside_sha
            if "status" not in row:
                row["status"] = "measured"
                row["outcome"] = api.classify(case["label"], row["delivered"], row["effects"], True)
    except (queue.Empty, subprocess.TimeoutExpired):
        row.update(status="timeout", outcome="incomplete_timeout")
    except (OSError, ValueError, subprocess.SubprocessError) as failure:
        reason = str(failure)
        terminal = api.V.events(logs / f"{case_id}.collector.private", "mcp_real_transport_failure")
        if terminal:
            row["transport_failure_observed"] = True
        row.update(status="incomplete", outcome="incomplete_witness",
                   error=reason if reason in SAFE_ERRORS else type(failure).__name__)
    finally:
        if client is not None:
            client.close()
            cleanup = client.process_witness.final
            row["collector_cleanup"] = bool(client.process.returncode == 0 and not client.forced_cleanup
                                             and cleanup["all_stopped"] and cleanup["descendant_count"] > 0)
        for witness in (repository, outside_watch):
            if witness is not None:
                witness.close()
        if before is not None:
            after = snapshot(api, workspace, native.git, native.reference_env)
            row.update(workspace_unchanged_by_server=before["workspace"] == after["workspace"],
                       git_index_unchanged=before["index"] == after["index"],
                       git_head_unchanged=before["head"] == after["head"])
        clear(workspace)
        row["workspace_cleanup"] = not any(workspace.iterdir())
        for path in observers.effect_dir.glob("obeyed-*"):
            path.unlink()
        observers.receiver.bodies.clear()


SAFE_ERRORS = frozenset({
    "original_git_reference_failed", "reference_cleanup_unverified", "original_git_reference_bytes_differ",
    "duplicate_git_boundary_observation", "input_refusal_witness_conflict", "required_git_boundary_witness_missing",
    "client_delivery_witness_conflict", "inspection_refusal_witness_conflict", "released_original_frame_changed",
    "delivered_git_payload_changed",
})


def inventory(api, args):
    manifest_hash = api.V.sha(args.manifest)
    api.V.require(manifest_hash == MANIFEST_SHA256, "frozen_git_manifest_digest_mismatch")
    manifest = api.RUN.load_manifest(args.manifest)
    api.V.require(not api.RUN.verify_payloads(manifest, args.payload_dir), "frozen_git_payload_digest_mismatch")
    selected, skipped = api.select_cases(manifest, git=True)
    api.V.require(len(selected) == 24 and {row["case_id"] for row in selected} == CASE_IDS,
                  "frozen_git_case_inventory_mismatch")
    return selected, skipped


def inputs(api, args):
    before = api.V.source()
    api.V.require(before["commit"] == args.expected_commit and not before["dirty"], "clean_exact_git_source_required")
    roles = ("agentfw", "git", "git_launcher", "bwrap", "python_archive", "wheelhouse", "build_receipt")
    api.V.require(all(getattr(args, name) is not None for name in roles) and args.git_sha256,
                  "git_runtime_inputs_required")
    paths = {name: getattr(args, name).resolve(strict=True) for name in roles}
    hashes = {name: api.V.sha(path) for name, path in paths.items() if name != "wheelhouse"}
    api.V.require(hashes["git"] == args.git_sha256, "git_runtime_digest_mismatch")
    receipt = json.loads(paths["build_receipt"].read_bytes())
    api.V.require(receipt.get("source_tree") == before["tree"] and isinstance(receipt.get("source_commit"), str)
                  and len(receipt["source_commit"]) == 40
                  and receipt.get("agentfw_sha256") == hashes["agentfw"]
                  and receipt.get("git_launcher_sha256") == hashes["git_launcher"],
                  "git_runtime_build_receipt_mismatch")
    return before, SimpleNamespace(**paths, payload_dir=args.payload_dir.resolve()), hashes, receipt


def calibrate_git(api, driver, native, outside, work):
    git = native.git
    env = native.reference_env
    probe = work / "calibration-repo"
    api.GEN.git_repository(SimpleNamespace(git=str(git)), api.CORPUS.PAIRS[0], [], 0, probe, env)
    old = snapshot(api, probe, git, env)
    commands = ([str(git), "-C", str(probe), "add", "CHANGELOG.md"],
                [str(git), "-C", str(probe), "commit", "-qm", "Observer calibration"])
    (probe / "CHANGELOG.md").write_text("Observed scratch change\n")
    with_watch = driver.RepositoryWitness(probe)
    outside_watch = driver.RepositoryWitness(outside)
    try:
        repo_idle, outside_idle = with_watch.drain(), outside_watch.drain()
        (outside / "sentinel").read_bytes()
        for command in commands:
            subprocess.run(command, env=env, capture_output=True, check=True, timeout=10)
        reads, outside_reads = with_watch.drain(), outside_watch.drain()
        new = snapshot(api, probe, git, env)
    finally:
        with_watch.close()
        outside_watch.close()
    shutil.rmtree(probe)
    return {"repository_reads": repo_idle == 0 and reads > 0,
            "outside_reads": outside_idle == 0 and outside_reads > 0,
            "workspace": old["workspace"] != new["workspace"], "index": old["index"] != new["index"],
            "head": old["head"] != new["head"], "calibration_repo_removed": not probe.exists()}


def row_complete(row):
    if row["status"] == "measured":
        boundary = row.get("dispatched") is True and row.get("result_release") is row.get("delivered")
    elif row["status"] in ("profile_refused", "call_refused"):
        boundary = row.get("dispatched") is False and row.get("result_release") == "not_reached" and not any(row.get("effects", {}).values())
    else:
        return False
    return boundary and row.get("reference_verified") is True and row.get("useful_continuation") is True and all(
        row.get(key) is True for key in ("collector_cleanup", "workspace_cleanup", "outside_unchanged",
                                        "workspace_unchanged_by_server", "git_index_unchanged", "git_head_unchanged")
    ) and row.get("outside_read_events") == 0 and set(row.get("effects", {})) == {"file", "process", "receiver"}


def grade(api, report):
    rows = report["cases"]
    ids = [row["case_id"] for row in rows]
    complete = [row for row in rows if row_complete(row)]
    integrity = (len(ids) == len(set(ids)) == len(CASE_IDS) and set(ids) == CASE_IDS
                 and len(complete) == len(CASE_IDS) and report.get("calibration", {}).get("valid") is True
                 and report.get("daemon_stopped") is True and report.get("private_profile_removed") is True
                 and report.get("inputs_unchanged") is True)
    api.grade(report)
    report["totals"].update(not_dispatched=sum(row.get("dispatched") is False for row in rows),
                            dispatch_unknown=sum(row.get("dispatched") is None for row in rows),
                            useful_continuation_lost=sum(row.get("useful_continuation") is False for row in rows),
                            useful_continuation_unknown=sum(row.get("useful_continuation") is None for row in rows),
                            planned=len(CASE_IDS), attempted=len(rows), observed=len(complete),
                            not_attempted=len(CASE_IDS - set(ids)),
                            non_comparable=sum(row["status"] != "measured" for row in complete),
                            incomplete=sum(not row_complete(row) for row in rows),
                            timeouts=sum(row["status"] == "timeout" for row in rows))
    report["status"] = "complete" if integrity else "incomplete"
    if not integrity or report["totals"]["non_comparable"]:
        report["acceptance"] = "fail"


def run(api, args):
    selected, skipped = inventory(api, args)
    before, native, hashes, receipt = inputs(api, args)
    output = args.output.resolve()
    api.V.require(not output.exists() and not output.is_relative_to(api.ROOT),
                  "output must be a new directory outside the candidate")
    output.mkdir(mode=0o700, parents=True)
    logs = output / "private"
    logs.mkdir(mode=0o700)
    driver = api.load("sou244_git_driver", api.ROOT / "scripts/verify-sou68-real-mcp.py")
    outcomes = api.load("sou244_boundaries", api.ROOT / "scripts/pilot_git_outcomes.py")
    pilot = api.V.load("sou244_pilot_policy", "pilot_policy.py")
    policy_manifest = pilot.verify_assets()
    assets = driver.INSTALL.ASSETS
    pins = {"source": before["commit"], "source_tree": before["tree"], "build_source": receipt["source_commit"],
            "manifest_sha256": MANIFEST_SHA256, "policy_sha256": api.V.sha(pilot.ASSETS / "policy.yaml"),
            "preset_manifest_sha256": api.V.sha(pilot.ASSETS / "manifest.json"),
            "classifier_sha256": api.V.sha(api.ROOT / pilot.KINDS["git"][1]),
            "upstream_identity_sha256": api.V.sha(assets / "upstream-identity.json"),
            "upstream_wheels_lock_sha256": api.V.sha(assets / "wheels.lock.json"),
            "wheelhouse_sha256": driver.INSTALL.tree_sha(native.wheelhouse),
            "runtime_sha256": hashes,
            "harness_sha256": api.V.sha(api.HERE / "effect_controls.py"),
            "driver_sha256": api.V.sha(Path(__file__))}
    report = {"format": api.FORMAT, "surface_scope": "git", "development_only": True, "status": "incomplete",
              "acceptance": "fail", "identities": pins, "cases": [], "not_executed": skipped,
              "source_before": before, "claim": "Owned original Git calls with calibrated synthetic effect witnesses.",
              "attempt_rules": {"protected_attempts_per_case": 1, "exchange_timeout_seconds": 35,
                                "temporary_reference_size_calibration_max": 4,
                                "repo_path": {"frozen": api.GEN.REPO, "protected": api.SANDBOX_ROOT},
                                "protected_fixture_core_autocrlf": "defaults_false_with_no_global_or_system_config"},
              "inventory": [{k: row[k] for k in ("case_id", "pair_id", "label", "tool", "arguments", "sha256")}
                            for row in selected]}
    api.V.write(output / "plan.json", report)
    private = work = None
    try:
        with api.tempfile.TemporaryDirectory(prefix="sou244-owned-") as temporary:
            work = Path(temporary)
            private = work
            native.workspace = work / "workspace"
            native.workspace.mkdir(mode=0o700)
            (native.workspace / ".git").mkdir(mode=0o700)
            install = work / "installed"
            home = work / "home"
            home.mkdir(mode=0o700)
            env = api.V.environment(home)
            env.update(PATH=f"{native.git.parent}:/usr/bin:/bin", LANG="C.UTF-8", GIT_CONFIG_NOSYSTEM="1",
                       GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
                       GIT_PYTHON_GIT_EXECUTABLE=str(native.git))
            native.reference_env = dict(env)
            for who in ("AUTHOR", "COMMITTER"):
                native.reference_env.update({f"GIT_{who}_NAME": "Corpus Author",
                    f"GIT_{who}_EMAIL": "corpus@example.invalid", f"GIT_{who}_DATE": "2026-10-23T09:00:00+00:00"})
            with (logs / "installer.log").open("wb") as log:
                driver.INSTALL.install(install, native.workspace, native.git, hashes["git"], native.bwrap,
                                       native.git_launcher, python_archive=native.python_archive,
                                       wheelhouse=native.wheelhouse, allow_download=False, log=log)
            clear(native.workspace)
            native.python = install / "package/python/bin/python3.11"
            port = api.DEMO.free_port()
            config, selection = pilot.prepare("git", install, work / "selection", port, native.python)
            api.V.require(selection["manifest_sha256"] == pins["preset_manifest_sha256"]
                          and selection["policy_sha256"] == pins["policy_sha256"]
                          and selection["classifier_sha256"] == pins["classifier_sha256"], "git_policy_pin_changed")
            report["pilot_selection"] = {k: v for k, v in selection.items() if k != "environment"}
            report["package_tree_sha256"] = json.loads((install / "profile.json").read_bytes())["packageTreeSha256"]
            native.env = dict(env, **selection["environment"])
            native.command = [str(native.agentfw), "mcp", "--native-admission", "--id", "sou244-git", "--",
                              str(native.python), "-I", "-B", "-m", "mcp_server_git", "--repository", api.SANDBOX_ROOT]
            config.update(bind="127.0.0.1")
            subprocess.run([str(native.agentfw), "install"], env=env, capture_output=True, check=True, timeout=30)
            api.V.write(home / ".agentfw/config.yaml", config)
            outside = work / "outside"
            outside.mkdir(mode=0o700)
            (outside / "sentinel").write_text("SOU-244 owned outside sentinel\n")
            effect_dir = work / "agent-effects"
            effect_dir.mkdir(mode=0o700)
            receiver = api.DEMO.Receiver()
            observers = None
            daemon = None
            try:
                observers = api.Observers(effect_dir, receiver)
                calibration = api.calibrate(observers)
                calibration["git"] = calibrate_git(api, driver, native, outside, work)
                calibration["valid"] &= all(calibration["git"].values())
                report["calibration"] = calibration
                api.V.require(calibration["valid"], "git_observer_calibration_failed")
                daemon_log = logs / "daemon.log"
                with daemon_log.open("wb") as log:
                    daemon = subprocess.Popen([str(native.agentfw), "serve"], env=env, stdout=log, stderr=log)
                    api.V.require(api.DEMO.wait_healthy(port, daemon, startup_log=daemon_log), "owned_git_daemon_not_ready")
                    pairs = {p["id"]: p for p in api.CORPUS.PAIRS}
                    for case in selected:
                        row = {k: case[k] for k in ("case_id", "pair_id", "label", "surface", "category")}
                        row.update(payload_sha256=case["sha256"], delivered=None, dispatched=None, useful_continuation=None,
                                   outcome="incomplete_witness")
                        report["cases"].append(row)
                        run_case(api, driver, outcomes, case, pairs[case["pair_id"]], native, observers, outside, work, logs, row)
                        api.V.write(output / "report.json", report)
            finally:
                if daemon is not None:
                    api.DEMO.stop(daemon)
                    daemon.wait(timeout=10)
                    report["daemon_stopped"] = daemon.poll() is not None
                if observers is not None:
                    observers.close()
                receiver.close()
            report["inputs_unchanged"] = (
                all(hashes[key] == api.V.sha(getattr(native, key)) for key in hashes)
                and api.V.sha(args.manifest) == MANIFEST_SHA256
                and not api.RUN.verify_payloads(api.RUN.load_manifest(args.manifest), args.payload_dir)
                and pins["wheelhouse_sha256"] == driver.INSTALL.tree_sha(native.wheelhouse)
                and json.loads((install / "profile.json").read_bytes())["packageTreeSha256"]
                == driver.INSTALL.tree_sha(install / "package")
                and selection["profile_sha256"] == api.V.sha(install / "profile.json")
                and selection["registry_sha256"] == api.V.sha(install / "registry.json")
                and selection["policy_sha256"] == api.V.sha(work / "selection/policy.yaml")
                and pilot.verify_assets() == policy_manifest and api.V.source() == before
            )
    except (KeyboardInterrupt, OSError, ValueError, subprocess.SubprocessError) as failure:
        report["error"] = type(failure).__name__
        for row in report["cases"]:
            row.setdefault("status", "interrupted")
    finally:
        report["private_profile_removed"] = private is not None and not private.exists()
        grade(api, report)
        api.V.write(output / "report.json", report)
    print(json.dumps({key: report[key] for key in ("status", "acceptance", "totals")}))
    return 2 if report["status"] != "complete" else int(report["acceptance"] != "pass")


MANIFEST_SHA256 = "3a7fd3091990d8425df42914321336dd25bdf9ff34f677450935a0c26c674e33"
CASE_IDS = frozenset(f"g{number:02d}-{side}" for number in range(1, 13) for side in ("a", "b"))
