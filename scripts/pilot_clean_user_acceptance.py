#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-216 workload for the existing installed-front-door producer.

Only the measurement driver is new. Installation, preparation, host execution,
Ask, walkthrough and component recovery use the selected pinned product source.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import time

sys.dont_write_bytecode = True
DRIVER = Path(__file__).resolve().parents[1]
BASELINE = "9a3c5b38e56ebc6ebbeedfda98805f6a327cb371"
PRODUCT = "75875f16dfbc19503feb22fe6871116cf6bd7618"
ROLES = ("git", "bwrap", "agentfw", "git_launcher", "sandbox_tests", "agent_output",
         "node", "npm", "node_archive", "claude", "python", "python_archive",
         "npm_cache", "wheelhouse")
PROJECTS = {
    "catalog-service": {
        "files": {
            "README.md": "# Catalog service\nA small owned product catalog API.\n",
            "docs/api.md": "Catalog API contract: GET /v1/catalog returns at most 50 entries; expired entries are omitted.\n",
            "src/catalog.py": "def visible(entries):\n    return [row for row in entries if not row['expired']]\n",
            "config/service.toml": "page_limit = 50\ncache_seconds = 30\n",
            "tests/catalog_cases.csv": "name,expired,visible\nfresh,false,true\nold,true,false\n",
        },
        "read": "docs/api.md", "change": "config/service.toml",
        "second": "Document catalog cache expiry", "pending": "cache_seconds = 45\n",
    },
    "release-ledger": {
        "files": {
            "README.md": "# Release ledger\nAn owned local release review project.\n",
            "docs/release notes.md": "Ledger review contract: retain the previous release and record the next release before publishing.\n",
            "src/ledger.py": "def previous(releases):\n    return releases[-2] if len(releases) > 1 else None\n",
            "config/ledger.toml": "retain_releases = 3\n",
            "tests/ledger_cases.csv": "releases,previous\n2,first\n1,none\n",
        },
        "read": "docs/release notes.md", "change": "config/ledger.toml",
        "second": "Record ledger retention rationale", "pending": "retain_releases = 4\n",
    },
}
TASKS = ("read-contract", "review-pending-diff", "trace-local-history", "inspect-last-commit")


def require(ok, code):
    if not ok:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(root, *words, env=None):
    result = subprocess.run(["/usr/bin/git", "-C", str(root), *words], env=env,
                            capture_output=True, timeout=30)
    require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024, "source_query_failed")
    return result.stdout.decode().strip()


def source(root, expected):
    require(root.is_absolute() and root.resolve(strict=True) == root, "canonical_source_required")
    require(git(root, "rev-parse", "HEAD") == expected, "source_commit_mismatch")
    require(not git(root, "status", "--porcelain", "--untracked-files=all"), "source_not_clean")
    return {"commit": expected, "tree": git(root, "rev-parse", "HEAD^{tree}"), "dirty": False}


def load(root, name, filename):
    spec = importlib.util.spec_from_file_location(name, root / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def verify_utility(row, value, expected, kind, decode):
    """An exit code, marker or partial result cannot replace a useful result."""
    require(row.get("exit") == 0 and row.get("status") == "completed", "developer_task_runtime_failed")
    require(row.get("live_status", {}).get("protection") == "observed-live", "developer_task_not_observed_live")
    require(row.get("process_cleanup", {}).get("all_stopped") is True, "developer_task_cleanup_unconfirmed")
    require(value is not None and value.get("is_error") is False, "developer_task_original_error")
    text = decode(value, kind)
    if kind == "filesystem":
        require(isinstance(expected.get("text"), str) and expected["text"], "independent_expectation_missing")
        require(text == expected["text"], "developer_task_exact_bytes_mismatch")
    else:
        require(isinstance(expected.get("parts"), list) and expected["parts"]
                and all(isinstance(p, str) and p for p in expected["parts"]), "independent_expectation_missing")
        require(all(part and part in text for part in expected["parts"]), "developer_task_history_or_diff_mismatch")
    return {"observed_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "expected_sha256": digest(expected), "original_result_useful": True}


def save(path, report):
    raw = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False).encode()
    require(len(raw) <= 256 * 1024, "acceptance_report_bound")
    temporary = path.with_suffix(".next")
    with temporary.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
    temporary.replace(path)


def project(args, name, root, env, installed):
    definition = PROJECTS[name]
    fs, repository = root / "files", root / "repository"
    for base in (fs, repository):
        base.mkdir(mode=0o700, parents=True)
        for relative, text in definition["files"].items():
            path = base / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_text(text, encoding="utf-8")
    def command(*words):
        return subprocess.check_output([str(args.git), "-C", str(repository), *words],
                                       env=env, text=True, timeout=30).strip()
    command("init", "--initial-branch=main", "--template=")
    command("add", ".")
    command("commit", "-qm", "Create owned " + name)
    baseline = command("rev-parse", "HEAD")
    (repository / "docs" / "design.md").write_text(definition["second"] + "\n")
    command("add", ".")
    command("commit", "-qm", definition["second"])
    head = command("rev-parse", "HEAD")
    (repository / definition["change"]).write_text(definition["pending"])
    (repository / "review scratch.txt").write_text("Owned untracked notes must survive.\n")
    # Independent expectations are frozen before any host/model is constructed.
    expected = {
        "read-contract": {"text": definition["files"][definition["read"]]},
        "review-pending-diff": {"parts": [command("diff", "--no-ext-diff", "HEAD", "--", definition["change"])]},
        "trace-local-history": {"parts": [head, baseline, definition["second"], "Create owned " + name]},
        "inspect-last-commit": {"parts": [head, definition["second"], command("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD")]},
    }
    require(all(e.get("text") or all(e["parts"]) for e in expected.values()), "empty_project_expectation")
    (root / "expected.private.json").write_bytes(canonical(expected))
    os.chmod(root / "expected.private.json", 0o600)
    proposals = {
        "read-contract": ("mcp__filesystem__read_text_file", {"path": "/workspace/" + definition["read"]}),
        "review-pending-diff": ("mcp__git__git_diff", {"repo_path": "/workspace", "target": "HEAD"}),
        "trace-local-history": ("mcp__git__git_log", {"repo_path": "/workspace", "max_count": 2}),
        "inspect-last-commit": ("mcp__git__git_show", {"repo_path": "/workspace", "revision": "HEAD"}),
    }
    chosen = argparse.Namespace(**vars(args))
    chosen.project, chosen.repository = fs, repository
    chosen.prefix = root / "preparation"
    chosen.other_prefix = args.other_prefix
    door = installed.InstalledDoor(chosen, env, args.work, args.agent_home)
    return chosen, door, expected, proposals


def operator(a, env, *words):
    result = subprocess.run([str(a.agentfw), *map(str, words)], cwd=a.work, env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
    require(len(result.stdout) <= 512 * 1024, "operator_report_bound")
    value = json.loads(result.stdout)
    reason = value.get("reason", "unknown")
    require(result.returncode == 0, "operator_refused:" + str(reason))
    return value


def coordinated_update(a, env, archive, built, fixture, installed, q, report):
    """Exercise the current coordinated controller with two accepted selections.

    Both generations deliberately retain the one reviewed product source and
    binary set. This is selection-generation recovery, not a version upgrade.
    """
    chosen, first_door = fixture
    second = argparse.Namespace(**vars(chosen))
    second.prefix = a.output / "update-preparation"
    second_door = installed.InstalledDoor(second, env, a.work, a.agent_home)
    code, prepared, _ = second_door.call("prepare", "--apply", timeout=3600)
    require(code == 0 and prepared.get("status") == "prepared-not-active", "update_prepare_failed")
    update = load(a.runtime_source, "sou216_accepted_update", "pilot_update.py")
    controller = a.output / "coordinator"
    paths, candidates = [], []
    for label, prefix in (("a", chosen.prefix), ("b", second.prefix)):
        value = update.make_inventory(prefix, archive, built["archive_sha256"], PRODUCT, "accepted-" + label)
        path = a.output / ("update-" + label + ".private.json")
        save(path, value)
        paths.append(path); candidates.append(value)
    door_args = argparse.Namespace(**vars(chosen)); door_args.prefix = controller
    door = installed.InstalledDoor(door_args, env, a.work, a.agent_home)
    observations = []
    def change(action, path=None):
        words = ["pilot", "--home", a.agent_home, "update", action, "--prefix", controller]
        if path is not None: words += ["--inventory", path]
        preview = operator(a, env, *words)
        if action == "preview":
            require(preview.get("writes") is False, "update_preview_wrote_state")
            return preview
        return preview
    for label, path in zip(("installed-a", "updated-b"), paths):
        preview = change("preview", path)
        result = operator(a, env, "pilot", "--home", a.agent_home, "update", "apply",
                          "--prefix", controller, "--inventory", path, "--confirm", preview["plan_sha256"])
        require(result.get("status") == "selected", "coordinated_update_not_selected")
        row, values, _ = q.run_case(door_args, door, report, label,
            [("mcp__filesystem__read_text_file", {"path": "/workspace/" + PROJECTS["catalog-service"]["read"]})])
        value = values.get("toolu_front_" + label + "_0")
        original = load(a.runtime_source, "sou216_update_original", "qualify-installed-pilot.py")
        verify_utility(row, value, {"text": PROJECTS["catalog-service"]["files"][PROJECTS["catalog-service"]["read"]]},
                       "filesystem", original.host_text)
        observations.append(update.state(controller))
    require(observations[1]["current"] != observations[0]["current"]
            and observations[1]["previous"] == observations[0]["current"], "coordinated_generation_unchanged")
    preview = change("rollback")
    result = operator(a, env, "pilot", "--home", a.agent_home, "update", "rollback",
                      "--prefix", controller, "--confirm", preview["plan_sha256"])
    require(update.state(controller)["current"] == observations[0]["current"], "coordinated_rollback_failed")
    row, values, _ = q.run_case(door_args, door, report, "rolled-back-a",
        [("mcp__filesystem__read_text_file", {"path": "/workspace/" + PROJECTS["catalog-service"]["read"]})])
    verify_utility(row, values.get("toolu_front_rolled-back-a_0"),
        {"text": PROJECTS["catalog-service"]["files"][PROJECTS["catalog-service"]["read"]]}, "filesystem", original.host_text)
    return {"scope": "actual coordinated selection-generation update and rollback; one accepted binary/source set",
            "selection_sha256": [v["selection"]["sha256"] for v in candidates],
            "states": observations + [update.state(controller)], "useful_runs": 3}, second.prefix


def qualify(a, report):
    require(platform.system() == "Linux" and platform.machine() == "x86_64" and os.geteuid() != 0,
            "ordinary_native_linux_user_required")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == "24.04",
            "native_ubuntu_24_04_required")
    require("microsoft" not in platform.release().lower(), "wsl_is_separate")
    driver_identity = source(DRIVER, a.expected_commit)
    runtime_identity = source(a.runtime_source, PRODUCT)
    require(not a.output.exists() and a.output.is_absolute()
            and not a.output.is_relative_to(DRIVER) and not a.output.is_relative_to(a.runtime_source),
            "new_external_output_required")
    os.umask(0o077)
    a.output.mkdir(mode=0o700)
    report.update(driver_source=driver_identity, source_before=runtime_identity,
                  accepted_baseline=BASELINE, runtime_source=PRODUCT, runtime_review_status="author candidate; not merge approval", scope="two-new-projects-one-clean-user-environment",
                  full_product_acceptance="not_established", novice_human_evidence="not_measured",
                  live_model_effectiveness="not_tested", paid_api_calls=0,
                  useful_latency_threshold="unapproved; observations only",
                  fixture_sha256=digest(PROJECTS))
    # No product module is imported before the pinned product source is checked.
    sys.path.insert(0, str(a.runtime_source / "scripts"))
    installed = load(a.runtime_source, "sou216_accepted_installed", "qualify-installed-front-door.py")
    q = installed.QUAL
    original = load(a.runtime_source, "sou216_accepted_original_result", "qualify-installed-pilot.py")
    report["format"] = installed.FORMAT
    process_status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    capabilities = int(process_status["CapEff"].strip(), 16)
    require(capabilities == 0, "ordinary_user_capabilities_required")
    report["environment"] = {
        "effective_capabilities": capabilities,
        "uid": os.getuid(), "gid": os.getgid(), "kernel": platform.release(),
        "boot_identity_sha256": sha("/proc/sys/kernel/random/boot_id"),
        "user_namespace": os.readlink("/proc/self/ns/user"),
        "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "job": os.environ.get("GITHUB_JOB"), "runner_image": os.environ.get("ImageVersion"),
        "ordinary_user": True, "fresh_private_home": True,
        "sandbox_precondition": "existing job-scoped exact-binary AppArmor permission; no global relaxation",
        "unassisted_stock_host_acceptance": "not_established",
    }
    q.BASE.require(os.geteuid() != 0, "non_root_operator_required")
    require(all(getattr(a, key) is not None for key in
                ("git", "bwrap", "agentfw", "git_launcher", "sandbox_tests", "claude", "node_archive", "python")),
            "explicit_pinned_inputs_required")
    receipt = json.loads(a.source_build_receipt.read_bytes())
    require(receipt.get("format") == "sw-native-pilot-agent-source-build/1"
            and receipt.get("source", {}).get("commit") == PRODUCT, "accepted_build_receipt_required")
    for role in ("agentfw", "git_launcher", "sandbox_tests"):
        require(receipt["binaries"][role]["sha256"] == sha(getattr(a, role)), "accepted_binary_receipt_mismatch")
    report["source_build_receipt_sha256"] = sha(a.source_build_receipt)
    report["build_source"] = receipt["source"]
    report["compiler_inputs"] = receipt["tools"]
    report["native_source_build_seconds"] = receipt["build_seconds"]
    a.expected_commit = PRODUCT
    a.agent_output = None
    home = a.output / "user-home"; home.mkdir(mode=0o700)
    a.agent_home = a.output / "agent-home"; a.agent_home.mkdir(mode=0o700)
    a.work = a.output / "work"; a.work.mkdir(mode=0o700)
    a.state_root = a.output / "runs"; a.state_root.mkdir(mode=0o700)
    a.other_prefix = a.output / "unused-prefix"
    a.prefix = a.output / "demo-preparation"
    # These are newly created synthetic user files, never the operator's home.
    q.user_config(home)
    (a.agent_home / "unrelated-user-file").write_text("Owned Agent user data must survive.\n")
    user_before = q.snapshot(home)
    env = q.qualification_environment(home)
    for key in ("RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME"):
        env.pop(key, None)
    selected_inputs = {key: sha(getattr(a, key)) for key in ROLES
                       if getattr(a, key) is not None and getattr(a, key).is_file()}
    report["inputs_sha256"] = selected_inputs
    # Preserve every task's denominator even if setup or a preceding case fails.
    required = ["component-install", *[name + ":" + task for name in PROJECTS for task in (*TASKS, "denied-calls")],
                "documented-walkthrough", "ask-once-replay", "update-rollback", "remove-preserves-user-data"]
    report["clean_user"] = {"required": required, "cases": [
        {"id": name, "status": "incomplete", "attempted": False} for name in required]}
    rows = {row["id"]: row for row in report["clean_user"]["cases"]}
    def begin(name):
        rows[name]["attempted"] = True
        rows[name]["started_at_ms"] = time.time_ns() // 1_000_000
        report["clean_user"]["active_case"] = name
        save(a.output / "report.json", report)
        print(json.dumps({"case": name, "status": "started"}), flush=True)
        return time.monotonic()
    def done(name, start, **facts):
        rows[name].update(status="passed", elapsed_ms=round((time.monotonic() - start) * 1000, 3), **facts)
        save(a.output / "report.json", report)
        print(json.dumps({"case": name, "status": "passed", "elapsed_ms": rows[name]["elapsed_ms"]}), flush=True)
    started = begin("component-install")
    archive = a.output / "component.tar"
    built = installed.build(a.runtime_source, archive, env)
    require(built["commit"] == PRODUCT, "accepted_component_identity_mismatch")
    a.component_python = a.component_python.resolve(strict=True)
    installed.install_component(a, a.agent_home, archive, built["archive_sha256"], built["component"], env, report)
    code, verified, _ = installed.component(a, a.agent_home, None, None, "verify", env=env)
    require(code == 0 and verified.get("ok") is True, "installed_component_verify_failed")
    report["component"] = built
    done("component-install", started, archive_sha256=built["archive_sha256"], component_sha256=built["component"])
    receiver = q.ISOLATION.Receiver()
    fixtures, baselines = [], {}
    try:
        for name in PROJECTS:
            root = a.output / name; root.mkdir(mode=0o700)
            chosen, door, expected, proposals = project(a, name, root, env, installed)
            fixtures.append((name, chosen, door))
            baseline = {"files": q.snapshot(chosen.project), "repository": q.snapshot(chosen.repository)}
            baselines[name] = baseline
            report.setdefault("projects", {})[name] = {"expected_sha256": digest(expected),
                "fixture_sha256": digest(PROJECTS[name]), "source_before_sha256": digest(baseline)}
            setup_started = time.monotonic()
            code, plan, _ = door.call("preview", timeout=600)
            require(code == 0 and plan.get("executed") is False and not chosen.prefix.exists(), "clean_preview_failed")
            code, prepared, _ = door.call("prepare", "--apply", timeout=3600)
            require(code == 0 and prepared.get("status") == "prepared-not-active", "clean_prepare_failed")
            code, repeated, _ = door.call("prepare", "--apply", inputs=False, timeout=900)
            require(code == 0 and repeated.get("status") == "reused", "clean_prepare_reuse_failed")
            selection = Path(prepared["selection"])
            selected_value = json.loads(selection.read_bytes())
            report["projects"][name]["selected_sha256"] = {
                role: item["sha256"] for role, item in selected_value["files"].items()}
            report["projects"][name]["selected_source"] = selected_value["source"]
            report["projects"][name].update(setup_seconds=round(time.monotonic() - setup_started, 3),
                selection_sha256=sha(selection), profiles=json.loads(selection.read_bytes())["prepared_profiles"])
            for task in TASKS:
                label = name + ":" + task
                started = begin(label)
                trace = a.output / (name + "-" + task + ".trace.private")
                row, results, _ = q.run_case(chosen, door, report, name + "-" + task, [proposals[task]],
                                             provider_trace=trace, trace_events="execve,execveat,write,writev")
                require(row["process_cleanup"]["all_stopped"], "developer_task_cleanup_unconfirmed")
                value = results.get("toolu_front_" + name + "-" + task + "_0")
                try:
                    facts = verify_utility(row, value, expected[task],
                                           "filesystem" if task == "read-contract" else "git", original.host_text)
                    done(label, started, **facts)
                except ValueError as error:
                    rows[label].update(status="failed", reason=str(error),
                        original_is_error=None if value is None else value["is_error"],
                        result_sha256=digest(value), tool=proposals[task][0],
                        native_codes=sorted(set(re.findall(r"native_[a-z_]{1,80}", json.dumps(value)))),
                        owned_failure_scope="SOU-97/157/177; no classifier or original Git patch",
                        elapsed_ms=round((time.monotonic() - started) * 1000, 3))
                    save(a.output / "report.json", report)
                require({"files": q.snapshot(chosen.project), "repository": q.snapshot(chosen.repository)} == baseline,
                        "developer_task_changed_user_files")
            label = name + ":denied-calls"; started = begin(label)
            marker = root / "forbidden-effect"
            # Calibrate the independent receiver and file witness before negative calls.
            import urllib.request
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(receiver.url, timeout=5) as response: response.read()
            require(receiver.count > 0, "receiver_positive_control_missing")
            receiver.count = 0
            proposals = [
                ("mcp__filesystem__write_file", {"path": "/workspace/forbidden.txt", "content": "forbidden"}),
                ("mcp__git__git_reset", {"repo_path": "/workspace"}),
                ("Bash", {"command": "curl " + shlex.quote(receiver.url) + " > " + shlex.quote(str(marker))}),
                ("mcp__filesystem__read_text_file", {"path": "/workspace/" + PROJECTS[name]["read"]})]
            trace = root / "denied.trace.private"
            row, results, _ = q.run_case(chosen, door, report, name + "-denied", proposals,
                                         provider_trace=trace, trace_events="execve,execveat,write,writev")
            require(row["exit"] == 0 and row["process_cleanup"]["all_stopped"], "denied_case_runtime_or_cleanup_failed")
            ids = ["toolu_front_" + name + "-denied_" + str(i) for i in range(4)]
            require(set(results) == set(ids) and all(results[i]["is_error"] for i in ids[:3]), "denied_result_missing")
            require(original.host_text(results[ids[3]], "filesystem") == PROJECTS[name]["files"][PROJECTS[name]["read"]],
                    "denied_case_useful_continuation_failed")
            dispatch = installed.LAUNCH.collector_dispatches(trace.read_text(errors="replace"), chosen.agentfw, strict=False)
            require(not any(call["tool"] in {"write_file", "git_reset", "Bash"} for call in dispatch["calls"]),
                    "denied_original_dispatch_observed")
            require(not marker.exists() and receiver.count == 0
                    and not (chosen.project / "forbidden.txt").exists(), "denied_effect_observed")
            require({"files": q.snapshot(chosen.project), "repository": q.snapshot(chosen.repository)} == baseline,
                    "denied_case_changed_user_files")
            done(label, started, positive_receiver=True, forbidden_network_connections=0,
                 forbidden_files=0, forbidden_original_dispatches=0, unchanged_user_files=True,
                 useful_continuation=True, process_cleanup=row["process_cleanup"])
        # Reuse the documented generated-workspace walkthrough without changing its inventory.
        started = begin("documented-walkthrough")
        demo_door = installed.InstalledDoor(a, env, a.work, a.agent_home)
        code, prepared, _ = demo_door.call("prepare", "--apply", project_roots=False, timeout=3600)
        require(code == 0, "walkthrough_preparation_failed")
        selection = Path(prepared["selection"])
        report["walkthrough_selection_sha256"] = sha(selection)
        process = subprocess.run([str(a.component_python), "-I", "-B", str(a.runtime_source / "scripts/pilot-demo.py"),
            "--run", "--selection", str(selection), "--expected-commit", PRODUCT,
            "--strace", str(a.strace), "--output", str(a.output / "walkthrough")],
            cwd=a.work, env=env, capture_output=True, timeout=1800)
        demo = json.loads((a.output / "walkthrough/report.json").read_bytes())
        report["walkthrough"] = {key: demo.get(key) for key in ("format", "status", "reason", "elapsed_seconds", "fixture_cleanup")}
        report["walkthrough"]["cases"] = [
            {key: row.get(key) for key in ("case", "passed", "status", "exit", "reason", "process_cleanup", "elapsed_seconds")}
            for row in demo.get("cases", [])]
        require(process.returncode == 0 and demo.get("status") == "passed"
                and demo.get("fixture_cleanup", {}).get("complete") is True, "documented_walkthrough_failed")
        done("documented-walkthrough", started, original_report_sha256=sha(a.output / "walkthrough/report.json"),
             cases=len(demo["cases"]), original_inventory_preserved=True)
        started = begin("ask-once-replay")
        files = json.loads(selection.read_bytes())["files"]
        words = [str(a.component_python), "-I", "-B", str(a.runtime_source / "scripts/qualify-pilot-ask.py"),
                 "--approval-smoke", "--require-five-second-pending", "--output", str(a.output / "ask")]
        for role in ("agentfw", "git_launcher", "claude", "node", "npm", "bwrap", "git"):
            words += ["--" + role.replace("_", "-"), files[role]["path"]]
        words += ["--strace", str(a.strace)]
        process = subprocess.run(words, cwd=a.work, env=env, capture_output=True, timeout=1200)
        ask = json.loads((a.output / "ask/qualification.json").read_bytes())
        report["ask"] = {key: ask.get(key) for key in ("contract_version", "status", "qualification_scope", "first_pending", "error")}
        report["ask"]["cases"] = [
            {key: row.get(key) for key in ("profile", "case", "passed", "stage", "dispatched", "kernel_effects", "approved", "cleanup", "decision_to_result_ms")}
            for row in ask.get("cases", [])]
        require(process.returncode == 0 and ask.get("status") == "pass", "ask_once_replay_failed")
        done("ask-once-replay", started, original_report_sha256=sha(a.output / "ask/qualification.json"),
             scope="existing two-profile approval correctness smoke, not the full 15-case inventory")
        started = begin("update-rollback")
        coordinated, update_prefix = coordinated_update(a, env, archive, built,
            (fixtures[0][1], fixtures[0][2]), installed, q, report)
        report["coordinated_update"] = coordinated
        update, update_row = installed.update_candidate(a, env)
        code, installed_update, _ = installed.component(a, a.agent_home, update, update_row["archive_sha256"], "install", env=env)
        require(code == 0 and installed_update.get("previous") == built["component"], "component_update_failed")
        _, stale, _ = fixtures[0][2].call("status", "--state-root", str(a.state_root), inputs=False, timeout=120)
        require(stale.get("selection", {}).get("reason") == "stale_source", "updated_source_not_refused")
        code, rolled, _ = installed.component(a, a.agent_home, None, None, "rollback", env=env)
        require(code == 0 and rolled.get("component") == built["component"], "component_rollback_failed")
        code, status, _ = fixtures[0][2].call("status", "--state-root", str(a.state_root), inputs=False, timeout=120)
        require(code == 0 and status.get("protection") == "configured-not-running", "rollback_status_failed")
        done("update-rollback", started, update_source="synthetic identity-only component control",
             updated_component=update_row["component"], restored_component=built["component"],
             coordinated_selection_recovery=coordinated)
        started = begin("remove-preserves-user-data")
        for name, chosen, _ in fixtures:
            after_lifecycle = {"files": q.snapshot(chosen.project), "repository": q.snapshot(chosen.repository)}
            require(after_lifecycle == baselines[name], "lifecycle_changed_user_project")
            report["projects"][name]["after_lifecycle_sha256"] = digest(after_lifecycle)
        before_remove = {name: {"files": q.snapshot(chosen.project), "repository": q.snapshot(chosen.repository),
                               "preparation": q.snapshot(chosen.prefix)} for name, chosen, _ in fixtures}
        recovery = a.output / "removal-recovery"; recovery.mkdir(mode=0o700)
        journal = recovery / "journal"
        words = ["--home", a.agent_home, "--state", a.state_root, "--journal", journal]
        for prefix in [chosen.prefix for _, chosen, _ in fixtures] + [a.prefix, update_prefix]:
            words += ["--prefix", prefix]
        preview = operator(a, env, "pilot-removal", "preview", *words)
        report["removal_preview"] = {key: preview.get(key) for key in ("status", "blockers", "confirmation_sha256")}
        require(preview.get("executed") is False and preview.get("confirmation_sha256") and not journal.exists(),
                "removal_preview_failed")
        removed = operator(a, env, "pilot-removal", "apply", *words,
            "--confirm", preview["confirmation_sha256"], "--consent-remove", "--exclusive-maintenance")
        require(removed.get("status") == "removed" and removed.get("success_ack")
                and not (a.agent_home / "pilot-front-door").exists(), "pilot_removal_failed")
        status = operator(a, env, "pilot-removal", "status", "--journal", journal,
            "--expect-plan", preview["confirmation_sha256"], "--success-ack", removed["success_ack"])
        require(status.get("status") == "removed", "removal_retained_status_failed")
        report["removal"] = {"command": "agentfw pilot-removal preview/apply/status",
            "status": status["status"], "confirmation_sha256": preview["confirmation_sha256"],
            "journal_retained": journal.exists(), "success_ack_sha256": digest(removed["success_ack"])}
        require((a.agent_home / "unrelated-user-file").read_text() == "Owned Agent user data must survive.\n",
                "component_removal_changed_user_state")
        require(before_remove == {name: {"files": q.snapshot(chosen.project), "repository": q.snapshot(chosen.repository),
                                        "preparation": q.snapshot(chosen.prefix)} for name, chosen, _ in fixtures}
                and q.snapshot(home) == user_before, "component_removal_changed_user_files")
        done("remove-preserves-user-data", started, user_files_preserved=True, selections_preserved=True)
    finally:
        receiver.close()
    report["source_after"] = source(a.runtime_source, PRODUCT)
    require(report["source_after"] == report["source_before"], "accepted_source_changed")
    require(source(DRIVER, driver_identity["commit"]) == driver_identity, "driver_source_changed")
    report["clean_user"]["status"] = "passed" if all(row["status"] == "passed" for row in rows.values()) else "failed"
    report["status"] = report["clean_user"]["status"]
    report["decision"] = ("GO for this measured preprovisioned path only" if report["status"] == "passed"
                          else "NO-GO: inspect failed and incomplete observations")
    report["remaining_blockers"] = [row["id"] for row in rows.values() if row["status"] != "passed"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--clean-user-only", action="store_true", required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--source-build-receipt", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True, help="measurement driver commit, distinct from accepted product source")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--component-python", type=Path, required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--allow-download", action="store_true")
    for role in ROLES:
        parser.add_argument("--" + role.replace("_", "-"), type=Path)
    a = parser.parse_args(argv)
    report = {"format": "sw-installed-front-door-qualification/1", "status": "incomplete",
              "cases": [], "skipped": 0, "provider": "owned-scripted-loopback"}
    try:
        qualify(a, report)
    except Exception as error:
        report.update(status="failed", decision="NO-GO", error=(
            str(error) if re.fullmatch(r"[a-z0-9_][a-z0-9_:=.-]{0,240}", str(error)) else type(error).__name__))
        inventory = report.get("clean_user", {})
        for row in inventory.get("cases", []):
            if row["id"] == inventory.get("active_case") and row["status"] == "incomplete" and row["attempted"]:
                row.update(status="failed", reason=report["error"])
        report["remaining_blockers"] = [r["id"] for r in inventory.get("cases", []) if r["status"] != "passed"]
    if a.output.exists():
        save(a.output / "report.json", report)
    print(json.dumps({key: report.get(key) for key in ("status", "error", "accepted_baseline", "runtime_source", "decision", "clean_user")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
