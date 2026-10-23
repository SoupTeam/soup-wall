#!/usr/bin/env python3
"""Trusted, read-only PR evidence verifier with one merge-SHA admission status.

Run only from the base branch in pull_request_target. Never checkout, import, or
execute PR-controlled files, logs, artifacts, or cache contents in this process.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ci_impact import WORKFLOW_JOBS, plan
from ci_activation import selective_enabled
from sou91_ruleset_patch import RULESET_ID


CONTEXT = "SOU-91 candidate admission"
SHA = re.compile(r"^[0-9a-f]{40}$")

# A job ID can expand to several required OS/backend checks. The default is
# the literal job ID; the exceptions below are reviewed against actual Actions
# job names. A missing matrix member is never replaced by workflow success.
CHECK_NAMES: dict[str, dict[str, tuple[str, ...]]] = {
    "agent-doctor.yml": {"agent-doctor-linux": ("doctor-linux",)},
    "agent-fleet.yml": {"fleet": ("Fleet API and real dual-store browser witness",)},
    "agent-windows-onboarding.yml": {"standard-user-onboarding": ("standard-user-onboarding",)},
    "benchmark.yml": {"agent-scorecard": ("Agent security scorecard",)},
    "ci.yml": {
        "documentation": ("Documentation links",),
        "python-classifier": ("Python classifier and evaluation",),
        "native-macos-resilience": ("Native macOS admission resilience",),
        "agent-lifecycle-macos": ("Agent lifecycle on macOS",),
        "saml-release-targets": tuple("SAML " + target for target in (
            "x86_64-unknown-linux-gnu", "aarch64-apple-darwin",
            "x86_64-apple-darwin", "x86_64-pc-windows-msvc")),
    },
    "identity-sandbox.yml": {
        "vendor-driver-safety": ("Keycloak driver offline safety",),
        "local-idp-evidence": ("OIDC SAML SCIM sandbox fixtures",),
    },
    "keycloak-oidc.yml": {"linux-vendor": (
        "Genuine Keycloak OIDC on Linux (sqlite)",
        "Genuine Keycloak OIDC on Linux (postgres)")},
    "keycloak-saml.yml": {"linux-vendor": (
        "Genuine Keycloak SAML on Linux (sqlite)",
        "Genuine Keycloak SAML on Linux (postgres)")},
    "license-policy.yml": {"rust-license-policy": ("Locked workspace license policy",)},
    "managed-credential-rotation.yml": {
        "formatting-preview": ("Rust formatting preview (read-only)",),
        "managed-credential-rotation": (
            "Real Console + Agent credential rotation (sqlite)",
            "Real Console + Agent credential rotation (postgres)"),
    },
    "managed-policy-demo.yml": {"managed-rollout-e2e": (
        "Signed activation and rollback on real Agent",)},
    "managed-policy-postgres.yml": {"managed-postgres": (
        "PostgreSQL migration and real Agent rollout",)},
    "managed-policy-tls.yml": {"agent-https-rollout": (
        "Real Agent verified HTTPS rollout and rollback",)},
    "monitoring.yml": {"linux-alert-recovery": (
        "Linux dependency alerts and protected durable recovery",)},
    "native-mcp-stderr.yml": {"native-platform-launch": tuple(
        "native-platform-launch (" + platform + ")" for platform in
        ("ubuntu-22.04", "macos-15", "windows-latest"))},
    "scim-directory.yml": {"interoperability": (
        "interoperability (sqlite)", "interoperability (postgres)" )},
    "supply-chain.yml": {
        "cargo-audit": ("Cargo audit",), "sbom": ("CycloneDX SBOM",),
    },
    "test-environment.yml": {
        "windows-launcher": ("Windows launcher guidance and reporting",),
        "fixture-baseline": (
            "Linux fixture baseline (linux/amd64)",
            "Linux fixture baseline (linux/arm64)"),
    },
}


def component_names(workflow: str, job_ids: list[str]) -> tuple[str, ...]:
    """Reviewed central job names; the PR cannot supply this mapping."""
    return tuple("Components / " + workflow.removesuffix(".yml") + " / " + name
                 for name in required_names(workflow, job_ids))


def required_names(workflow: str, job_ids: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    for job in job_ids:
        if job not in WORKFLOW_JOBS[workflow]:
            raise ValueError("unregistered job")
        result.extend(CHECK_NAMES.get(workflow, {}).get(job, (job,)))
    return tuple(result)


@dataclass(frozen=True)
class Verdict:
    state: str  # success, failure, pending
    reason: str


def assess_job_names(jobs: list[dict[str, Any]], expected: tuple[str, ...], merge_sha: str,
                     run: dict[str, Any] | None = None, head_sha: str | None = None) -> Verdict:
    names: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        names.setdefault(job.get("name", ""), []).append(job)
    # The reusable planner job name includes the server-supplied merge SHA.
    planners = [job for job in jobs if "Candidate " in job.get("name", "")]
    candidate = [job for job in planners if job.get("name", "").endswith("Candidate " + merge_sha)]
    if len(planners) > 1 or (planners and len(candidate) != 1):
        return Verdict("failure", "duplicate or stale merge-source planner job")
    pending: Verdict | None = None
    if not candidate:
        pending = Verdict("pending", "merge-source planner job absent from job snapshot")
    else:
        verdict = assess_job(candidate[0], run, head_sha)
        if verdict.state == "failure":
            return Verdict("failure", "merge-source planner job: " + verdict.reason)
        if verdict.state == "pending":
            pending = Verdict("pending", "merge-source planner job: " + verdict.reason)
    for name in expected:
        matches = names.get(name, [])
        if len(matches) > 1:
            return Verdict("failure", "duplicate required job: " + name)
        if not matches:
            if pending is None:
                pending = Verdict("pending", "required job absent from job snapshot: " + name)
            continue
        verdict = assess_job(matches[0], run, head_sha)
        if verdict.state == "failure":
            return Verdict("failure", "required job " + name + ": " + verdict.reason)
        if verdict.state == "pending" and pending is None:
            pending = Verdict("pending", "required job " + name + ": " + verdict.reason)
    return pending or Verdict("success", "all selected jobs succeeded")


def assess_job(job: dict[str, Any], run: dict[str, Any] | None,
               head_sha: str | None) -> Verdict:
    """A complete, source-bound job failure is final; incomplete evidence is not."""
    if run is not None:
        if job.get("run_id") != run.get("id") or job.get("run_attempt") != run.get("run_attempt"):
            return Verdict("failure", "run or attempt identity mismatch")
    if head_sha is not None and job.get("head_sha") != head_sha:
        return Verdict("failure", "head identity mismatch")
    if job.get("status") != "completed" or job.get("conclusion") is None:
        return Verdict("pending", "job evidence incomplete")
    if job.get("conclusion") != "success":
        return Verdict("failure", "completed with " + str(job["conclusion"]))
    return Verdict("success", "completed successfully")


def assess_codeql(run: dict[str, Any] | None, jobs: list[dict[str, Any]] | None,
                  expected: list[str], head_sha: str) -> Verdict:
    if run is None:
        return Verdict("pending", "CodeQL default setup run missing at PR head")
    if run.get("head_sha") != head_sha or run.get("event") != "dynamic" or \
            not str(run.get("path", "")).startswith("dynamic/github-code-scanning/codeql"):
        return Verdict("failure", "CodeQL run identity mismatch")
    if run.get("status") != "completed":
        return Verdict("pending", "CodeQL analysis unfinished")
    if run.get("conclusion") is None:
        return Verdict("pending", "CodeQL run conclusion unavailable")
    if run.get("conclusion") != "success":
        return Verdict("failure", "CodeQL default setup did not succeed")
    if jobs is None:
        return Verdict("pending", "CodeQL job evidence unavailable")
    names: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        names.setdefault(job.get("name", ""), []).append(job)
    pending: Verdict | None = None
    for name in expected:
        matches = names.get(name, [])
        if len(matches) > 1:
            return Verdict("failure", "duplicate CodeQL analysis: " + name)
        if not matches:
            if pending is None:
                pending = Verdict("pending", "CodeQL analysis absent from job snapshot: " + name)
            continue
        verdict = assess_job(matches[0], run, head_sha)
        if verdict.state == "failure":
            return Verdict("failure", "CodeQL analysis " + name + ": " + verdict.reason)
        if verdict.state == "pending" and pending is None:
            pending = Verdict("pending", "CodeQL analysis " + name + ": " + verdict.reason)
    return pending or Verdict("success", "all five CodeQL analyses succeeded at PR head")


class GitHub:
    def __init__(self, repo: str, token: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("invalid repository identity")
        self.repo = repo
        self.token = token

    def get(self, suffix: str) -> Any:
        return self._request("GET", suffix)

    def post(self, suffix: str, body: dict[str, Any]) -> Any:
        return self._request("POST", suffix, body)

    def _request(self, method: str, suffix: str, body: dict[str, Any] | None = None) -> Any:
        if not suffix.startswith("/") or ".." in suffix:
            raise ValueError("invalid API path")
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request = Request("https://api.github.com/repos/" + self.repo + suffix, data=payload,
                          method=method, headers={
                              "Authorization": "Bearer " + self.token,
                              "Accept": "application/vnd.github+json",
                              "X-GitHub-Api-Version": "2022-11-28",
                              "User-Agent": "sou91-ci-admission",
                              **({"Content-Type": "application/json"} if payload else {}),
                          })
        for attempt in range(3):
            try:
                with urlopen(request, timeout=20) as response:
                    return json.load(response)
            except HTTPError as error:
                if error.code not in {429, 500, 502, 503, 504} or attempt == 2:
                    raise RuntimeError("GitHub API returned HTTP " + str(error.code)) from error
            except URLError as error:
                if attempt == 2:
                    raise RuntimeError("GitHub API unavailable") from error
            time.sleep(2 * (attempt + 1))
        raise AssertionError("unreachable")

    def pages(self, suffix: str, key: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for page in range(1, 31):
            separator = "&" if "?" in suffix else "?"
            data = self.get(suffix + separator + urlencode({"per_page": 100, "page": page}))
            entries = data[key] if key else data
            if not isinstance(entries, list):
                raise ValueError("unexpected paginated API response")
            results.extend(entries)
            if len(entries) < 100:
                return results
        raise RuntimeError("GitHub API pagination exceeded safe limit")


def latest(runs: list[dict[str, Any]], path: str, event: str, sha: str) -> dict[str, Any] | None:
    matching = [run for run in runs if run.get("head_sha") == sha and
                run.get("event") == event and str(run.get("path", "")).split("@", 1)[0] == path]
    # Rerunning an older run keeps its original created_at. Any active attempt
    # is blocking, and completed runs are ordered by the current attempt start.
    active = [run for run in matching if run.get("status") != "completed"]
    return max(active or matching,
               key=lambda run: (run.get("run_started_at") or run.get("updated_at") or
                                run.get("created_at", ""), run.get("created_at", ""),
                                run.get("id", 0), run.get("run_attempt", 0)), default=None)


def get_jobs(api: GitHub, run: dict[str, Any]) -> list[dict[str, Any]]:
    run_id = int(run["id"])
    attempt = int(run["run_attempt"])
    return api.pages(f"/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")


def bounded_outcome(job: dict[str, Any]) -> str:
    status = job.get("status")
    conclusion = job.get("conclusion")
    safe_status = status if isinstance(status, str) and status in {
        "queued", "in_progress", "completed", "waiting", "pending",
    } else "unknown"
    safe_conclusion = conclusion if isinstance(conclusion, str) and conclusion in {
        "success", "failure", "cancelled", "skipped", "neutral", "timed_out",
        "action_required", "stale",
    } else (None if conclusion is None else "unknown")
    return safe_status + "/" + (safe_conclusion or "none")


def confirm_jobs(api: GitHub, jobs: list[dict[str, Any]], names: tuple[str, ...],
                 run: dict[str, Any], head_sha: str,
                 direct_cache: dict[int, dict[str, Any]]) -> Verdict:
    """Require independent job detail to agree with the selected attempt list."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        by_name.setdefault(job.get("name", ""), []).append(job)
    pending: Verdict | None = None
    for name in names:
        matches = by_name.get(name, [])
        if len(matches) != 1:
            # The assessor distinguishes a missing snapshot from a duplicate.
            continue
        listed = matches[0]
        job_id = listed.get("id")
        if not isinstance(job_id, int) or job_id <= 0:
            if pending is None:
                pending = Verdict("pending", "job detail unavailable: " + name)
            continue
        if job_id not in direct_cache:
            direct_cache[job_id] = api.get("/actions/jobs/" + str(job_id))
        direct = direct_cache[job_id]
        if direct.get("id") != job_id or direct.get("name") != name:
            return Verdict("failure", "job detail identity mismatch: " + name)
        verdict = assess_job(direct, run, head_sha)
        if verdict.state == "failure" and "mismatch" in verdict.reason:
            return Verdict("failure", "job detail " + name + ": " + verdict.reason)
        if (listed.get("status"), listed.get("conclusion")) != \
                (direct.get("status"), direct.get("conclusion")):
            if pending is None:
                pending = Verdict("pending", "inconsistent job " + str(job_id) +
                                  " attempt " + str(int(run["run_attempt"])) + ": " + name +
                                  " list=" + bounded_outcome(listed) +
                                  " detail=" + bounded_outcome(direct))
            continue
        if verdict.state == "failure":
            return Verdict("failure", "job detail " + name + ": " + verdict.reason)
        if verdict.state == "pending" and pending is None:
            pending = Verdict("pending", "job detail " + name + ": " + verdict.reason)
    return pending or Verdict("success", "job list and details agree")


def confirm_run(api: GitHub, run: dict[str, Any], head_sha: str) -> Verdict:
    """A rerun or replacement attempt invalidates a prior job snapshot."""
    current = api.get("/actions/runs/" + str(int(run["id"])))
    if current.get("id") != run.get("id") or current.get("head_sha") != head_sha or \
            str(current.get("path", "")).split("@", 1)[0] != \
            str(run.get("path", "")).split("@", 1)[0] or \
            current.get("event") != run.get("event"):
        return Verdict("failure", "selected workflow source identity changed")
    if current.get("run_attempt") != run.get("run_attempt") or \
            current.get("status") != "completed":
        return Verdict("pending", "selected workflow attempt changed or unfinished")
    if current.get("conclusion") is None:
        return Verdict("pending", "selected workflow conclusion unavailable")
    if current.get("conclusion") != "success":
        return Verdict("failure", "selected workflow no longer succeeded")
    return Verdict("success", "selected workflow attempt unchanged")


def run_label(run: dict[str, Any]) -> str:
    return "run " + str(int(run["id"])) + " attempt " + str(int(run["run_attempt"]))


def planner_source(api: GitHub, jobs: list[dict[str, Any]], merge_sha: str,
                   base_sha: str, head_sha: str, commits: dict[str, dict[str, Any]]) -> str:
    """Verify regenerated merge metadata against repository commit objects only."""
    planners = [job for job in jobs if "Candidate " in str(job.get("name", ""))]
    if len(planners) != 1:
        return merge_sha  # The existing assessor handles missing/duplicate planners.
    match = re.search(r"Candidate ([0-9a-f]{40})$", str(planners[0].get("name", "")))
    if match is None or match[1] == merge_sha:
        return merge_sha
    previous_sha = match[1]
    current = commits[merge_sha]
    tree = current.get("tree")
    if current.get("sha") != merge_sha or not isinstance(tree, dict) \
            or not isinstance(tree.get("sha"), str) or not SHA.fullmatch(tree["sha"]):
        return merge_sha
    if previous_sha not in commits:
        commits[previous_sha] = api.get("/git/commits/" + previous_sha)
    previous = commits[previous_sha]
    if not isinstance(previous, dict):
        return merge_sha
    parents = previous.get("parents")
    previous_tree = previous.get("tree")
    if previous.get("sha") != previous_sha or not isinstance(parents, list) \
            or not all(isinstance(parent, dict) for parent in parents) \
            or [parent.get("sha") for parent in parents] != [base_sha, head_sha] \
            or not isinstance(previous_tree, dict) or previous_tree.get("sha") != tree["sha"]:
        return merge_sha
    # GitHub can regenerate a test merge one second after the event snapshot.
    # Both ordered parents AND the complete tree must match; a same-head green
    # run alone is never sufficient. Final admission still targets merge_sha.
    return previous_sha


def inspect(api: GitHub, number: int, event_base: str, event_head: str) -> tuple[str, Verdict]:
    pr = api.get(f"/pulls/{number}")
    base_sha, head_sha = pr["base"]["sha"], pr["head"]["sha"]
    merge_sha = pr.get("merge_commit_sha")
    if not merge_sha or not SHA.fullmatch(merge_sha):
        return head_sha, Verdict("failure", "merge candidate unavailable or conflicted")
    if pr.get("state") != "open" or base_sha != event_base or head_sha != event_head:
        return merge_sha, Verdict("failure", "PR source moved during admission; re-run on current candidate")
    if pr.get("draft") is True:
        return merge_sha, Verdict("failure", "draft PR is not a merge-qualified candidate")
    commit = api.get("/git/commits/" + merge_sha)
    parents = [item["sha"] for item in commit.get("parents", [])]
    if parents != [base_sha, head_sha]:
        return merge_sha, Verdict("failure", "merge candidate parent identity mismatch")
    commits = {merge_sha: commit}
    files = api.pages(f"/pulls/{number}/files", "")
    paths: list[str] = []
    for item in files:
        paths.append(item["filename"])
        if item.get("previous_filename"):
            paths.append(item["previous_filename"])
    if len(files) != pr.get("changed_files"):
        return merge_sha, Verdict("failure", "PR file list incomplete")
    # The trusted base process independently reads current enforcement. If it
    # cannot verify activation, it demands the full registered PR suite.
    active = selective_enabled(os.environ.get("SOU91_SELECTIVE_CI"),
                               lambda: api.get(f"/rulesets/{RULESET_ID}"))
    selected = plan(paths, force_full=not active)
    actions = api.pages("/actions/runs?" + urlencode({"head_sha": head_sha,
                                                       "event": "pull_request"}), "workflow_runs")
    central = latest(actions, ".github/workflows/ci.yml", "pull_request", head_sha)
    job_cache: dict[tuple[int, int], list[dict[str, Any]]] = {}
    direct_cache: dict[int, dict[str, Any]] = {}
    selected_runs: list[tuple[str, tuple[str, ...], dict[str, Any]]] = []
    for workflow, job_ids in selected["workflows"].items():
        if not job_ids:
            continue
        run = latest(actions, ".github/workflows/" + workflow, "pull_request", head_sha)
        expected = required_names(workflow, job_ids)
        if run is None and workflow != "ci.yml":
            # Migration compatibility: components may share ci.yml's single
            # planner/run, but must still supply EVERY reviewed matrix member.
            # A green ci.yml without these exact names cannot qualify them.
            if central is not None and central.get("status") == "completed":
                key = (int(central["id"]), int(central["run_attempt"]))
                if key not in job_cache:
                    job_cache[key] = get_jobs(api, central)
                if any(job.get("name", "").startswith("Components / ") for job in job_cache[key]):
                    run = central
                    expected = component_names(workflow, job_ids)
        if run is None:
            return merge_sha, Verdict("pending", "selected workflow missing: " + workflow)
        if run.get("status") != "completed":
            return merge_sha, Verdict("pending", "selected workflow unfinished: " + workflow)
        if run.get("conclusion") is None:
            return merge_sha, Verdict("pending", "selected workflow conclusion unavailable: " + workflow)
        if run.get("conclusion") != "success":
            return merge_sha, Verdict("failure", "selected workflow did not succeed: " + workflow)
        selected_runs.append((workflow, expected, run))
    codeql_runs = api.pages("/actions/runs?" + urlencode({"head_sha": head_sha,
                                                           "event": "dynamic"}), "workflow_runs")
    codeql = latest(codeql_runs, "dynamic/github-code-scanning/codeql", "dynamic", head_sha)
    verdict = assess_codeql(codeql, None, selected["codeql"], head_sha)
    if verdict.state == "failure" or (codeql is None or codeql.get("status") != "completed"):
        return merge_sha, verdict
    for workflow, expected, run in selected_runs:
        key = (int(run["id"]), int(run["run_attempt"]))
        if key not in job_cache:
            job_cache[key] = get_jobs(api, run)
        jobs = job_cache[key]
        source_sha = planner_source(api, jobs, merge_sha, base_sha, head_sha, commits)
        planner = tuple(job["name"] for job in jobs if
                        str(job.get("name", "")).endswith("Candidate " + source_sha))
        verdict = confirm_jobs(api, jobs, (*planner, *expected), run, head_sha, direct_cache)
        if verdict.state != "success":
            return merge_sha, Verdict(verdict.state, workflow + " " + run_label(run) + ": " + verdict.reason)
        verdict = assess_job_names(jobs, expected, source_sha, run, head_sha)
        if verdict.state != "success":
            return merge_sha, Verdict(verdict.state, workflow + " " + run_label(run) + ": " + verdict.reason)
    codeql_jobs = get_jobs(api, codeql)
    verdict = confirm_jobs(api, codeql_jobs, tuple(selected["codeql"]), codeql,
                           head_sha, direct_cache)
    if verdict.state != "success":
        return merge_sha, Verdict(verdict.state, "CodeQL " + run_label(codeql) + ": " + verdict.reason)
    verdict = assess_codeql(codeql, codeql_jobs, selected["codeql"], head_sha)
    if verdict.state != "success":
        return merge_sha, Verdict(verdict.state, "CodeQL " + run_label(codeql) + ": " + verdict.reason)
    for run in {int(item["id"]): item for _, _, item in selected_runs +
                [("codeql", (), codeql)]}.values():
        verdict = confirm_run(api, run, head_sha)
        if verdict.state != "success":
            return merge_sha, verdict
    # A new same-head run or rerun can arrive while the old attempt's jobs are
    # being read. Re-list before publishing success; old green evidence cannot
    # qualify a candidate whose current attempt is still running.
    fresh_actions = api.pages("/actions/runs?" + urlencode({"head_sha": head_sha,
                                                             "event": "pull_request"}),
                              "workflow_runs")
    for workflow, _, run in selected_runs:
        run_path = str(run.get("path", "")).split("@", 1)[0]
        current_run = latest(fresh_actions, run_path,
                             "pull_request", head_sha)
        if current_run is None or (current_run.get("id"), current_run.get("run_attempt")) != \
                (run.get("id"), run.get("run_attempt")):
            return merge_sha, Verdict("pending", "selected workflow changed during inspection: " + workflow)
        if current_run.get("status") != "completed" or current_run.get("conclusion") != "success":
            return merge_sha, Verdict("pending", "selected workflow evidence changed during inspection: " + workflow)
    fresh_codeql = api.pages("/actions/runs?" + urlencode({"head_sha": head_sha,
                                                            "event": "dynamic"}),
                             "workflow_runs")
    current_codeql = latest(fresh_codeql, "dynamic/github-code-scanning/codeql",
                            "dynamic", head_sha)
    if current_codeql is None or (current_codeql.get("id"), current_codeql.get("run_attempt")) != \
            (codeql.get("id"), codeql.get("run_attempt")):
        return merge_sha, Verdict("pending", "CodeQL run changed during inspection")
    if current_codeql.get("status") != "completed" or current_codeql.get("conclusion") != "success":
        return merge_sha, Verdict("pending", "CodeQL evidence changed during inspection")
    after = api.get(f"/pulls/{number}")
    if after.get("draft") is True:
        return merge_sha, Verdict("failure", "PR converted to draft while evidence was inspected")
    if (after["base"]["sha"], after["head"]["sha"], after.get("merge_commit_sha")) != (base_sha, head_sha, merge_sha):
        return merge_sha, Verdict("failure", "PR source changed while evidence was inspected")
    return merge_sha, verdict


def completion_targets(api: GitHub, event: dict[str, Any]) -> list[dict[str, Any]]:
    """Use repository API metadata only, never upstream artifacts or PR code."""
    run = api.get("/actions/runs/" + str(int(event["workflow_run"]["id"])))
    path = str(run.get("path", "")).split("@", 1)[0]
    allowed = ((run.get("event") == "pull_request" and path == ".github/workflows/ci.yml")
               or (run.get("event") == "dynamic" and path.startswith("dynamic/github-code-scanning/codeql")))
    # The API can already describe a newer active attempt when an older
    # completion event arrives. Route it so the old green status is suspended.
    if not allowed or run.get("status") not in \
            {"queued", "requested", "waiting", "in_progress", "completed"} or \
            not SHA.fullmatch(str(run.get("head_sha", ""))):
        return []
    # Associations can be absent or lag behind a base/head transition. Union
    # them with the current open PR list, then verify every candidate by API.
    candidates = list(run.get("pull_requests") or []) + api.pages("/pulls?state=open", "")
    targets = []
    seen = set()
    for candidate in candidates:
        number = int(candidate["number"])
        if number in seen:
            continue
        seen.add(number)
        pr = api.get(f"/pulls/{number}")
        if pr.get("state") == "open" and pr["head"]["sha"] == run["head_sha"]:
            targets.append(pr)
    return targets


def suspend_candidate(api: GitHub, pr: dict[str, Any], run_id: int) -> None:
    """An in-progress selected rerun cannot inherit a previous green status."""
    current = api.get("/pulls/" + str(int(pr["number"])))
    if current.get("state") != "open" or \
            current["base"]["sha"] != pr["base"]["sha"] or \
            current["head"]["sha"] != pr["head"]["sha"] or \
            current.get("merge_commit_sha") != pr.get("merge_commit_sha"):
        return
    sha = current.get("merge_commit_sha")
    if not SHA.fullmatch(str(sha)):
        return
    print("pending: candidate " + sha + " has in-progress source run " + str(run_id), flush=True)
    api.post("/statuses/" + sha, {"state": "pending", "context": CONTEXT,
                                   "description": "Current CI or CodeQL attempt in progress"})


def admit(api: GitHub, args: argparse.Namespace, pr_event: dict[str, Any]) -> int:
    deadline = time.monotonic() + max(0, min(args.wait_seconds, 2700))
    current = api.get(f"/pulls/{args.pr}")
    if current.get("state") != "open" or \
            current["base"]["sha"] != pr_event["base"]["sha"] or \
            current["head"]["sha"] != pr_event["head"]["sha"]:
        print("stale: event no longer identifies the current PR source", flush=True)
        return 0
    status_sha = current.get("merge_commit_sha") or current["head"]["sha"]
    if not SHA.fullmatch(status_sha):
        raise RuntimeError("invalid initial status target SHA")
    print("candidate PR #" + str(args.pr) + " base=" + current["base"]["sha"] +
          " head=" + current["head"]["sha"] + " merge=" + status_sha, flush=True)
    if current.get("draft") is True:
        # Keep admission pending, never green. GitHub also forbids merging drafts.
        # A ready_for_review event starts fresh qualification; do not occupy a
        # hosted runner waiting up to 45 minutes for deliberately skipped jobs.
        if not args.dry_run:
            api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                               "description": "Draft: full qualification starts when ready for review"})
        print("pending: draft PR; qualification deferred without runner polling", flush=True)
        return 2 if args.dry_run else 0
    if not args.dry_run:
        api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                               "description": "Checking exact-source CI evidence"})
    last_reason = ""
    while True:
        try:
            sha, verdict = inspect(api, args.pr, pr_event["base"]["sha"], pr_event["head"]["sha"])
        except (RuntimeError, OSError) as error:
            print("pending: admission API evidence unavailable (" + type(error).__name__ + ")", flush=True)
            if not args.dry_run:
                api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                                   "description": "Admission API evidence unavailable"})
            return 2 if args.dry_run else 0
        except (ValueError, KeyError, TypeError) as error:
            print("failure: admission evidence unavailable (" + type(error).__name__ + ")", flush=True)
            if not args.dry_run:
                api.post("/statuses/" + status_sha, {"state": "failure", "context": CONTEXT,
                                                   "description": "Admission evidence unavailable"})
            return 1
        if not SHA.fullmatch(sha):
            raise RuntimeError("invalid status target SHA")
        refreshed = api.get(f"/pulls/{args.pr}")
        if refreshed.get("state") != "open" or \
                refreshed["base"]["sha"] != pr_event["base"]["sha"] or \
                refreshed["head"]["sha"] != pr_event["head"]["sha"] or \
                refreshed.get("merge_commit_sha") != sha:
            print("stale: PR source changed during admission", flush=True)
            return 0
        if refreshed.get("draft") is True:
            if not args.dry_run:
                api.post("/statuses/" + sha, {"state": "pending", "context": CONTEXT,
                                                "description": "Draft: full qualification starts when ready for review"})
            print("pending: PR converted to draft during admission", flush=True)
            return 2 if args.dry_run else 0
        if sha != status_sha:
            status_sha = sha
            if not args.dry_run:
                api.post("/statuses/" + sha, {"state": "pending", "context": CONTEXT,
                                                "description": "Checking exact-source CI evidence"})
        if verdict.reason != last_reason:
            print(verdict.state + ": " + verdict.reason, flush=True)
            last_reason = verdict.reason
        if verdict.state == "pending" and time.monotonic() < deadline:
            if args.dry_run:
                return 2
            time.sleep(min(3, max(0, deadline - time.monotonic())))
            continue
        if verdict.state == "pending":
            # A short focused recheck can settle API propagation. Incomplete
            # evidence remains blocking even after this bounded window.
            if not args.dry_run:
                api.post("/statuses/" + sha, {"state": "pending", "context": CONTEXT,
                                            "description": verdict.reason[:140]})
            return 2 if args.dry_run else 0
        final_state = verdict.state
        description = ("Selected jobs and all five CodeQL analyses passed" if final_state == "success"
                       else verdict.reason)[:140]
        if not args.dry_run:
            api.post("/statuses/" + sha, {"state": final_state, "context": CONTEXT,
                                            "description": description})
        return 0 if final_state == "success" else 1



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    repo = os.environ["GITHUB_REPOSITORY"]
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as event_file:
        event = json.load(event_file)
    api = GitHub(repo, os.environ["GITHUB_TOKEN"])
    if "workflow_run" in event:
        if args.pr is not None:
            parser.error("completion routing determines the current PR from repository metadata")
        run_id = int(event["workflow_run"]["id"])
        source = api.get("/actions/runs/" + str(run_id))
        source_attempt = int(source.get("run_attempt", 0))
        event_attempt = int(event["workflow_run"].get("run_attempt", 0))
        still_active = source.get("status") != "completed" or source_attempt < event_attempt
        result = 0
        for pr in completion_targets(api, event):
            if still_active:
                suspend_candidate(api, pr, run_id)
            else:
                args.pr = pr["number"]
                result = max(result, admit(api, args, pr))
        return result
    pr_event = event["pull_request"]
    if args.pr is None:
        args.pr = pr_event["number"]
    if pr_event["number"] != args.pr or pr_event["base"]["repo"]["full_name"] != repo:
        parser.error("event does not identify the requested base PR")
    return admit(api, args, pr_event)


if __name__ == "__main__":
    raise SystemExit(main())
