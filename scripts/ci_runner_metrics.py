#!/usr/bin/env python3
"""Read-only Actions timing inventory; never equates observed time with billing."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path

from ci_admission import GitHub, get_jobs, latest, required_names
from ci_impact import WORKFLOW_JOBS, plan


def seconds(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    return max(0.0, (datetime.fromisoformat(end.replace("Z", "+00:00")) -
                     datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds())


def measure(api: GitHub, number: int, sample_paths: list[str] | None) -> dict:
    pr = api.get(f"/pulls/{number}")
    head = pr["head"]["sha"]
    if sample_paths is None:
        files = api.pages(f"/pulls/{number}/files", "")
        sample_paths = [name for item in files for name in
                        (item["filename"], item.get("previous_filename")) if name]
    selected = plan(sample_paths)
    runs = api.pages(f"/actions/runs?head_sha={head}&event=pull_request", "workflow_runs")
    observed: dict[str, dict] = {}
    unavailable: list[str] = []
    total_seconds = 0.0
    selected_seconds = 0.0
    started: list[str] = []
    completed: list[str] = []
    for workflow in WORKFLOW_JOBS:
        run = latest(runs, ".github/workflows/" + workflow, "pull_request", head)
        if run is None:
            if selected["workflows"][workflow]:
                unavailable.append(workflow + ": no comparable run")
            continue
        jobs = get_jobs(api, run)
        timings: dict[str, float] = {}
        for job in jobs:
            elapsed = seconds(job.get("started_at"), job.get("completed_at"))
            if elapsed is not None:
                total_seconds += elapsed
                timings[job["name"]] = timings.get(job["name"], 0.0) + elapsed
        expected = required_names(workflow, selected["workflows"][workflow])
        for name in expected:
            if name in timings:
                selected_seconds += timings[name]
            else:
                unavailable.append(workflow + ": " + name)
        observed[workflow] = {
            "run_id": run["id"], "attempt": run["run_attempt"],
            "status": run["status"], "conclusion": run["conclusion"],
            "job_count": len(jobs), "runner_minutes": round(sum(timings.values()) / 60, 2),
            "job_runner_minutes": {name: round(elapsed / 60, 3)
                                   for name, elapsed in sorted(timings.items())},
        }
        if run.get("run_started_at"):
            started.append(run["run_started_at"])
        if run.get("updated_at"):
            completed.append(run["updated_at"])
    wall = seconds(min(started), max(completed)) if started and completed else None
    # The selected estimate deliberately excludes new planner jobs, cache effects,
    # missing workflow timings, and billing factors. It is not an observed saving.
    return {
        "schema": "sou91-runner-observation/1",
        "pr": number, "head_sha": head, "sample_paths": sample_paths,
        "plan_mode": selected["mode"],
        "selected_job_count": sum(map(len, selected["workflows"].values())),
        "observed_workflows": observed,
        "observed_job_runner_minutes": round(total_seconds / 60, 2),
        "observed_wall_minutes": round(wall / 60, 2) if wall is not None else None,
        "selected_job_minutes_from_observed_timings": round(selected_seconds / 60, 2),
        "timings_unavailable": unavailable,
        "cancelled_runs_at_head": sum(run.get("conclusion") == "cancelled" for run in runs),
        "cache_misses": None,
        "organization_billed_minutes": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--sample-paths", type=Path)
    args = parser.parse_args()
    paths = json.loads(args.sample_paths.read_text(encoding="utf-8")) if args.sample_paths else None
    if paths is not None and (not isinstance(paths, list) or any(not isinstance(p, str) for p in paths)):
        parser.error("sample paths must be a JSON string list")
    api = GitHub("SoupTeam/soup-wall", os.environ["GITHUB_TOKEN"])
    print(json.dumps(measure(api, args.pr, paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
