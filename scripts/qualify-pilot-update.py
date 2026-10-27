import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


UPDATE = load("qualified_update", "pilot_update.py")
QUAL = load("update_host_qualification", "qualify-pilot-front-door.py")
require = UPDATE.require


class Door(QUAL.FrontDoor):
    def words(self, command, *extra, inputs=False, prefix=None, project_roots=False):
        return [str(self.args.entry_agent), "pilot", "--home", str(self.args.entry_home),
                command, "--prefix", str(prefix or self.args.prefix), *[str(word) for word in extra]]


def update(door, operation, inventory_path=None, confirmation=None):
    words = [operation, "--prefix", str(door.args.prefix)]
    if inventory_path is not None:
        words += ["--inventory", str(inventory_path)]
    if confirmation is not None:
        words += ["--confirm", confirmation]
    result = QUAL.subprocess.run([str(door.args.entry_agent), "pilot", "--home", str(door.args.entry_home),
                                  "update", *words], cwd=door.cwd, env=door.env,
                                 capture_output=True, timeout=600)
    require(len(result.stdout) <= UPDATE.LIMIT, "update_report_limit")
    value = UPDATE.decode(result.stdout)
    require(result.returncode == 0, "installed_update_operation_failed:" + str(value.get("reason")))
    return value


def qualify(args, candidates, report):
    output = args.output
    output.mkdir(mode=0o700)
    args.prefix = output / "coordinator"
    args.other_prefix = output / "unused-prefix"
    args.state_root = output / "runs"
    args.state_root.mkdir(mode=0o700)
    home = output / "operator-home"
    home.mkdir(mode=0o700)
    sentinel = home / "unrelated.txt"
    sentinel.write_text("keep this unrelated file\n")
    env = QUAL.qualification_environment(home)
    door = Door(args, env, home)
    report["entry_agent_sha256"] = UPDATE.read_file(args.entry_agent, UPDATE.MAX_BINARY)[0]["sha256"]
    snapshots = {}
    for value in candidates:
        selection = UPDATE.decode(UPDATE.checked_file(value["selection"], UPDATE.LIMIT))
        for kind, profile in selection["prepared_profiles"].items():
            raw = Path(profile["profile"]["path"]).read_bytes()
            workspace = Path(UPDATE.decode(raw)["workspace"])
            require(workspace.is_relative_to(args.fixture_root), "owned_fixture_workspace_required")
            require(workspace.stat().st_uid == os.getuid(), "owned_fixture_workspace_required")
            snapshots[str(workspace)] = QUAL.snapshot(workspace)
    forbidden = output / "forbidden-send-marker"
    proposals = [("mcp__filesystem__read_text_file", {"path": "/workspace/README.md"}),
                 ("mcp__git__git_log", {"repo_path": "/workspace", "max_count": 1}),
                 ("Bash", {"command": "printf denied > " + shlex.quote(str(forbidden))})]

    def useful(label):
        row, results, _ = QUAL.run_case(args, door, report, label, proposals)
        require(row["exit"] == 0 and row["status"] == "completed", "useful_original_run_failed")
        require(row["live_status"]["protection"] == "observed-live", "active_protection_not_observed")
        require(row["process_cleanup"]["all_stopped"], "owned_process_cleanup_failed")
        for index in (0, 1):
            result = results["toolu_front_" + label + "_" + str(index)]
            require(result["is_error"] is False and result["content"], "original_useful_result_missing")
        require(args.expected_text in json.dumps(results["toolu_front_" + label + "_0"]["content"]),
                "original_read_content_missing")
        require(results["toolu_front_" + label + "_2"]["is_error"] is True and not forbidden.exists(),
                "forbidden_effect_observed")
        row["passed"] = True
        for path, before in snapshots.items():
            require(QUAL.snapshot(Path(path)) == before, "fixture_workspace_changed")
        require(sentinel.read_text() == "keep this unrelated file\n", "unrelated_state_changed")

    preview = update(door, "preview", args.inventory_a)
    require(preview["writes"] is False and not args.prefix.exists(), "preview_changed_state")
    first = update(door, "apply", args.inventory_a, preview["plan_sha256"])
    report["install"] = first
    useful("installed_a")
    current_a = UPDATE.state(args.prefix)
    for point in ("before_staging", "after_agent", "after_helper", "before_selection", "after_selection"):
        review = UPDATE.plan(args.prefix, candidates[1])
        before = UPDATE.state(args.prefix)
        actual_command, actual_write = UPDATE.command, UPDATE.Directory.write
        calls = 0
        def interrupted_command(words, home):
            nonlocal calls
            raw = actual_command(words, home)
            calls += 1
            if (point == "after_agent" and calls == 1) or (point == "after_helper" and calls == 2):
                raise OSError(28, "owned staging interruption")
            return raw
        def interrupted_write(directory, name, value):
            if directory.path == args.prefix:
                if (point == "before_staging" and name == "journal.json" and value["phase"] == "staging"):
                    raise PermissionError("owned permission-loss interruption")
                if point == "before_selection" and name == "current.json":
                    raise OSError(28, "owned publication interruption")
                if point == "after_selection" and name == "journal.json" and value["phase"] == "complete":
                    raise PermissionError("owned journal interruption")
            return actual_write(directory, name, value)
        failed = False
        with patch.object(UPDATE, "command", interrupted_command), patch.object(UPDATE.Directory, "write", interrupted_write):
            try:
                UPDATE.apply(args.prefix, candidates[1], review["plan_sha256"])
            except OSError:
                failed = True
        require(failed, "owned_fault_not_reached:" + point)
        recovery = UPDATE.recovery_plan(args.prefix)
        expected = "after_selection" if point == "after_selection" else (
            "nothing_pending" if point == "before_staging" else "before_selection")
        require(recovery["outcome"] == expected, "interrupted_selection_outcome_wrong")
        if expected == "before_selection":
            require(UPDATE.state(args.prefix) == before, "partial_generation_selected")
        UPDATE.recover(args.prefix, recovery["plan_sha256"])
        repeated = UPDATE.recovery_plan(args.prefix)
        require(repeated["outcome"] == "nothing_pending", "recovery_not_idempotent")
        UPDATE.recover(args.prefix, repeated["plan_sha256"])
        abandoned = recovery.get("journal", {}).get("after", {}).get("current") if expected != "nothing_pending" else None
        if expected == "after_selection":
            back = UPDATE.rollback_plan(args.prefix)
            UPDATE.rollback(args.prefix, back["plan_sha256"])
        removed = False
        if point in ("after_helper", "before_selection"):
            removal = UPDATE.cleanup_plan(args.prefix, abandoned)
            UPDATE.cleanup(args.prefix, abandoned, removal["plan_sha256"])
            removed = True
        require(UPDATE.state(args.prefix)["current"] == current_a["current"], "interruption_lost_current_set")
        report["cases"].append({"case": point, "passed": True, "injection": "owned phase-level I/O error",
                                "outcome": expected, "repeated_recovery": True, "owned_cleanup": removed,
                                "abandoned": abandoned})
    preview = update(door, "preview", args.inventory_b)
    report["update"] = update(door, "apply", args.inventory_b, preview["plan_sha256"])
    current_b = UPDATE.state(args.prefix)
    require(current_b["current"] != current_a["current"] and current_b["previous"] == current_a["current"],
            "coordinated_generation_did_not_change")
    useful("updated_b")
    preview = update(door, "rollback")
    report["rollback"] = update(door, "rollback", confirmation=preview["plan_sha256"])
    require(UPDATE.state(args.prefix)["current"] == current_a["current"], "full_set_rollback_failed")
    useful("rolled_back_a")
    report["identities"] = [{"source": value["source"], "component_sha256": value["component"]["sha256"],
                              "selection_sha256": value["selection"]["sha256"],
                              "runtime_sha256": {name: record["sha256"] for name, record in value["runtime"].items()}}
                             for value in candidates]
    report["states"] = {"installed": current_a, "updated": current_b, "rolled_back": UPDATE.state(args.prefix)}
    report["workspace_snapshots_sha256"] = {name: QUAL.digest(value) for name, value in snapshots.items()}
    report["interruption_qualification"] = "five owned phase-level I/O interruptions; not a physical disk-full claim"


def main():
    parser = argparse.ArgumentParser(description="Qualify two supplied compatible sets using only an owned scripted provider.")
    parser.add_argument("--run", action="store_true")
    for name in ("entry-agent", "entry-home", "inventory-a", "inventory-b", "fixture-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-text", required=True)
    args = parser.parse_args()
    report = {"format": "sw-pilot-update-qualification/1", "status": "not_run", "cases": [],
              "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_tested"}
    try:
        before = QUAL.BASE.source()
        require(not before["dirty"] and before["commit"] == args.expected_commit, "exact_clean_source_required")
        report["source"] = before
        candidates = [UPDATE.decode(UPDATE.read_file(path, UPDATE.LIMIT)[1])
                      for path in (args.inventory_a, args.inventory_b)]
        for value in candidates:
            UPDATE.inventory(value)
        require(candidates[0]["source"] != candidates[1]["source"], "two_identified_sources_required")
        require(args.output.is_absolute() and not args.output.exists() and not args.output.is_relative_to(ROOT),
                "new_external_output_required")
        require(args.fixture_root.is_absolute() and args.fixture_root.resolve(strict=True) == args.fixture_root,
                "owned_fixture_root_required")
        if not args.run:
            report.update(status="plan", writes=False, accepted_sources=[value["source"] for value in candidates])
        else:
            preparation = UPDATE.load_helper("update_native_platform", ROOT, "prepare-installed-pilot.py")
            preparation.supported_platform()
            qualify(args, candidates, report)
            require(QUAL.BASE.source() == before, "qualification_source_changed")
            report["status"] = "passed_useful_runs"
    except Exception as error:
        report.update(status="failed", error=str(error)[:500])
    if args.run and args.output.exists():
        target = args.output / "qualification.json"
        with target.open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "error": report.get("error")}))
    return 0 if report["status"] in ("plan", "passed_useful_runs") else 1


if __name__ == "__main__":
    raise SystemExit(main())
