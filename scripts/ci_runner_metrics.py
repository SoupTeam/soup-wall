#!/usr/bin/env python3
"""Read-only, exact-head Actions occupancy inventory for SOU-91.

The result is observed runner occupancy, not GitHub billing or inferred savings.
An explicit run ID pins a comparable before/after observation. Rerun attempts
can copy completed jobs forward; identical execution intervals count once.
Full workflow_dispatch controls are measured separately and never stand in for
the exact-candidate pull_request evidence required by admission.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any

from ci_admission import GitHub, component_names, get_jobs, latest, required_names
from ci_impact import plan


def seconds(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    elapsed = (datetime.fromisoformat(end.replace("Z", "+00:00")) -
               datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds()
    return elapsed if elapsed >= 0 else None


def execution_key(job: dict[str, Any]) -> tuple[object, ...] | None:
    """Identify one actual execution even if GitHub copies it into a rerun."""
    if seconds(job.get("started_at"), job.get("completed_at")) is None:
        return None
    runner = job.get("runner_id") or job.get("runner_name")
    if runner:
        return ("interval", runner, job.get("name"), job["started_at"], job["completed_at"])
    # Without runner identity, only a stable job ID is safe to deduplicate.
    return ("job", job.get("id")) if job.get("id") is not None else None


def occupancy(api: GitHub, run: dict[str, Any]) -> dict[str, Any]:
    attempts = int(run["run_attempt"])
    if attempts < 1:
        raise ValueError("run attempt unavailable")
    seen: set[tuple[object, ...]] = set()
    total = 0.0
    executed = 0
    unknown = 0
    copied = 0
    latest_jobs: list[dict[str, Any]] = []
    for attempt in range(1, attempts + 1):
        jobs = get_jobs(api, {**run, "run_attempt": attempt})
        if attempt == attempts:
            latest_jobs = jobs
        for job in jobs:
            if job.get("conclusion") == "skipped":
                continue  # GitHub may timestamp a skipped check without a runner.
            duration = seconds(job.get("started_at"), job.get("completed_at"))
            if duration is None:
                # Missing timestamps are unavailable rather than silently zero.
                unknown += 1
                continue
            key = execution_key(job)
            if key is None:
                unknown += 1
                continue
            if key in seen:
                copied += 1
                continue
            seen.add(key)
            total += duration
            executed += 1
    # run_started_at moves to the newest attempt on a rerun. created_at is
    # stable and keeps queue time and the interval between attempts visible.
    wall = seconds(run.get("created_at") or run.get("run_started_at"), run.get("updated_at"))
    latest_wall = seconds(run.get("run_started_at"), run.get("updated_at"))
    return {
        "run_id": run["id"], "head_sha": run["head_sha"],
        "attempts": attempts, "status": run["status"],
        "conclusion": run.get("conclusion"),
        "runner_minutes": round(total / 60, 2),
        "executed_jobs": executed, "copied_forward_job_records": copied,
        "timings_unavailable": unknown,
        "wall_minutes": round(wall / 60, 2) if wall is not None else None,
        "latest_attempt_wall_minutes": round(latest_wall / 60, 2) if latest_wall is not None else None,
        "latest_attempt_jobs": latest_jobs,
    }


def summarize_checks(observed: dict[str, Any], jobs: list[dict[str, Any]],
                     modeled: dict[str, Any]) -> None:
    """Keep modeled requirements distinct from jobs observed in one run."""
    names: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        names.setdefault(job.get("name", ""), []).append(job)
    selected = tuple(required_names("ci.yml", modeled["workflows"]["ci.yml"])) + tuple(
        name for workflow, job_ids in modeled["workflows"].items() if workflow != "ci.yml"
        for name in component_names(workflow, job_ids))
    observed["modeled_required_checks_missing_or_unsuccessful"] = [
        name for name in selected if len(names.get(name, [])) != 1 or
        names[name][0].get("status") != "completed" or names[name][0].get("conclusion") != "success"]
    observed["latest_attempt_active_job_names"] = sorted(
        name for name, entries in names.items() if any(
            entry.get("status") != "completed" or entry.get("conclusion") != "skipped"
            for entry in entries))
    observed["latest_attempt_skipped_job_names"] = sorted(
        name for name, entries in names.items() if all(
            entry.get("status") == "completed" and entry.get("conclusion") == "skipped"
            for entry in entries))


def measure_full_dispatch(api: GitHub, run_id: int, expected_head: str) -> dict[str, Any]:
    """Measure an explicit full-mode control; it never qualifies PR admission."""
    run = api.get(f"/actions/runs/{run_id}")
    if (run.get("id") != run_id or run.get("event") != "workflow_dispatch" or
            run.get("head_sha") != expected_head or
            str(run.get("path", "")).split("@", 1)[0] != ".github/workflows/ci.yml"):
        raise ValueError("manual full CI run does not match requested source/event")
    if run.get("status") != "completed":
        raise ValueError("manual full CI run is unfinished")
    ci = occupancy(api, run)
    jobs = ci.pop("latest_attempt_jobs")
    modeled = plan([], force_full=True)
    summarize_checks(ci, jobs, modeled)
    return {
        "schema": "sou91-full-dispatch-observation/1",
        "source_event": "workflow_dispatch",
        "admission_eligible": False,
        "head_sha": expected_head,
        "modeled_full_job_ids": sum(map(len, modeled["workflows"].values())),
        "ci": ci,
        "cache_misses": None,
        "cache_misses_note": "Review exact-run cache step logs; the Actions jobs API has no hit/miss field.",
        "organization_billed_minutes": None,
    }


def measure(api: GitHub, number: int, sample_paths: list[str] | None = None,
            run_id: int | None = None) -> dict[str, Any]:
    pr = api.get(f"/pulls/{number}")
    head = pr["head"]["sha"]
    source = "actual-pr-files" if sample_paths is None else "modeled-path-override"
    if sample_paths is None:
        files = api.pages(f"/pulls/{number}/files", "")
        sample_paths = [name for item in files for name in
                        (item["filename"], item.get("previous_filename")) if name]
        if len(files) != pr.get("changed_files"):
            raise ValueError("PR file list incomplete")
    modeled = plan(sample_paths)
    runs = api.pages(f"/actions/runs?head_sha={head}&event=pull_request", "workflow_runs")
    central = (next((run for run in runs if run.get("id") == run_id), None) if run_id is not None
               else latest(runs, ".github/workflows/ci.yml", "pull_request", head))
    if central is None or central.get("head_sha") != head or central.get("event") != "pull_request" or \
            str(central.get("path", "")).split("@", 1)[0] != ".github/workflows/ci.yml":
        raise ValueError("no exact-head PR qualification run for requested ID")
    ci = occupancy(api, central)
    jobs = ci.pop("latest_attempt_jobs")
    summarize_checks(ci, jobs, modeled)

    codeql_runs = api.pages(f"/actions/runs?head_sha={head}&event=dynamic", "workflow_runs")
    codeql_run = latest(codeql_runs, "dynamic/github-code-scanning/codeql", "dynamic", head)
    codeql = None
    if codeql_run is not None:
        codeql = occupancy(api, codeql_run)
        codeql_jobs = codeql.pop("latest_attempt_jobs")
        codeql["required_analyses"] = {name: [
            {"conclusion": job.get("conclusion"), "head_sha": job.get("head_sha")}
            for job in codeql_jobs if job.get("name") == name]
            for name in modeled["codeql"]}
        codeql["required_analyses_missing_or_unsuccessful"] = [
            name for name, entries in codeql["required_analyses"].items()
            if len(entries) != 1 or entries[0]["conclusion"] != "success" or
            entries[0]["head_sha"] != head]

    complete = (ci["status"] == "completed" and ci["timings_unavailable"] == 0 and
                codeql is not None and codeql["status"] == "completed" and
                codeql["timings_unavailable"] == 0)
    combined_wall = (seconds(min(central.get("created_at") or central["run_started_at"],
                                 codeql_run.get("created_at") or codeql_run["run_started_at"]),
                             max(central["updated_at"], codeql_run["updated_at"]))
                     if complete and central.get("run_started_at") and central.get("updated_at") and
                     codeql_run.get("run_started_at") and codeql_run.get("updated_at") else None)

    return {
        "schema": "sou91-runner-observation/2",
        "pr": number, "head_sha": head, "path_source": source,
        "sample_paths": sample_paths, "modeled_selective_plan": modeled["mode"],
        "modeled_selective_job_ids": sum(map(len, modeled["workflows"].values())),
        "ci": ci, "codeql": codeql,
        "observed_runner_minutes_including_codeql": round(
            ci["runner_minutes"] + codeql["runner_minutes"], 2) if complete else None,
        "observed_wall_minutes_including_codeql": (
            round(combined_wall / 60, 2) if combined_wall is not None else None),
        "cancelled_pr_runs_at_head": sum(run.get("conclusion") == "cancelled" for run in runs),
        "cache_misses": None,
        "cache_misses_note": "Review exact-run cache step logs; the Actions jobs API has no hit/miss field.",
        "organization_billed_minutes": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--run-id", type=int, help="pin one exact-head ci.yml pull_request run")
    parser.add_argument("--full-dispatch-run-id", type=int,
                        help="measure an explicit full ci.yml workflow_dispatch run")
    parser.add_argument("--expected-head", help="exact source SHA for a full dispatch control")
    parser.add_argument("--sample-paths", type=Path, help="model paths; never claim this as actual PR files")
    args = parser.parse_args()
    if args.full_dispatch_run_id is not None:
        if args.pr is not None or args.run_id is not None or args.sample_paths is not None or not args.expected_head:
            parser.error("full dispatch needs only --full-dispatch-run-id and --expected-head")
        api = GitHub("SoupTeam/soup-wall", os.environ["GITHUB_TOKEN"])
        print(json.dumps(measure_full_dispatch(api, args.full_dispatch_run_id, args.expected_head),
                         indent=2, sort_keys=True))
        return
    if args.pr is None or args.expected_head is not None:
        parser.error("PR measurement needs --pr and cannot take --expected-head")
    paths = json.loads(args.sample_paths.read_text(encoding="utf-8")) if args.sample_paths else None
    if paths is not None and (not isinstance(paths, list) or any(not isinstance(p, str) for p in paths)):
        parser.error("sample paths must be a JSON string list")
    api = GitHub("SoupTeam/soup-wall", os.environ["GITHUB_TOKEN"])
    print(json.dumps(measure(api, args.pr, paths, args.run_id), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
