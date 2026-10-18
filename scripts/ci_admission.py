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


def assess_job_names(jobs: list[dict[str, Any]], expected: tuple[str, ...], merge_sha: str) -> Verdict:
    names: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        names.setdefault(job.get("name", ""), []).append(job)
    # The reusable planner job name includes the server-supplied merge SHA.
    candidate = [job for job in jobs if job.get("name", "").endswith("Candidate " + merge_sha)]
    if len(candidate) != 1 or candidate[0].get("conclusion") != "success":
        return Verdict("failure", "missing or unsuccessful merge-source planner job")
    for name in expected:
        matches = names.get(name, [])
        if len(matches) != 1:
            return Verdict("failure", "missing or duplicate required job: " + name)
        job = matches[0]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            return Verdict("failure", "required job did not succeed: " + name)
    return Verdict("success", "all selected jobs succeeded")


def assess_codeql(run: dict[str, Any] | None, jobs: list[dict[str, Any]] | None,
                  expected: list[str], head_sha: str) -> Verdict:
    if run is None:
        return Verdict("pending", "CodeQL default setup run missing at PR head")
    if run.get("head_sha") != head_sha or run.get("event") != "dynamic" or \
            not str(run.get("path", "")).startswith("dynamic/github-code-scanning/codeql"):
        return Verdict("failure", "CodeQL run identity mismatch")
    if run.get("status") != "completed":
        return Verdict("pending", "CodeQL analysis unfinished")
    if run.get("conclusion") != "success":
        return Verdict("failure", "CodeQL default setup did not succeed")
    if jobs is None:
        return Verdict("pending", "CodeQL job evidence unavailable")
    names: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        names.setdefault(job.get("name", ""), []).append(job)
    for name in expected:
        matches = names.get(name, [])
        if len(matches) != 1 or matches[0].get("conclusion") != "success" or \
                matches[0].get("status") != "completed" or matches[0].get("head_sha") != head_sha:
            return Verdict("failure", "missing, neutral, stale or unsuccessful CodeQL analysis: " + name)
    return Verdict("success", "all five CodeQL analyses succeeded at PR head")


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
    return max(matching, key=lambda run: (run.get("created_at", ""), run.get("id", 0),
                                           run.get("run_attempt", 0)), default=None)


def get_jobs(api: GitHub, run: dict[str, Any]) -> list[dict[str, Any]]:
    run_id = int(run["id"])
    attempt = int(run["run_attempt"])
    return api.pages(f"/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")


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
        verdict = assess_job_names(job_cache[key], expected, merge_sha)
        if verdict.state != "success":
            return merge_sha, Verdict(verdict.state, workflow + ": " + verdict.reason)
    verdict = assess_codeql(codeql, get_jobs(api, codeql), selected["codeql"], head_sha)
    after = api.get(f"/pulls/{number}")
    if after.get("draft") is True:
        return merge_sha, Verdict("failure", "PR converted to draft while evidence was inspected")
    if (after["base"]["sha"], after["head"]["sha"], after.get("merge_commit_sha")) != (base_sha, head_sha, merge_sha):
        return merge_sha, Verdict("failure", "PR source changed while evidence was inspected")
    return merge_sha, verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--wait-seconds", type=int, default=2700)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    repo = os.environ["GITHUB_REPOSITORY"]
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as event_file:
        event = json.load(event_file)
    pr_event = event["pull_request"]
    if pr_event["number"] != args.pr or pr_event["base"]["repo"]["full_name"] != repo:
        parser.error("event does not identify the requested base PR")
    api = GitHub(repo, os.environ["GITHUB_TOKEN"])
    deadline = time.monotonic() + max(0, min(args.wait_seconds, 2700))
    current = api.get(f"/pulls/{args.pr}")
    status_sha = current.get("merge_commit_sha") or current["head"]["sha"]
    if not SHA.fullmatch(status_sha):
        raise RuntimeError("invalid initial status target SHA")
    if current.get("draft") is True:
        # Keep admission pending, never green. GitHub also forbids merging drafts.
        # A ready_for_review event starts fresh qualification; do not occupy a
        # hosted runner waiting up to 45 minutes for deliberately skipped jobs.
        if not args.dry_run:
            api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                               "description": "Draft: full qualification starts when ready for review"})
        print("pending: draft PR; qualification deferred without runner polling", flush=True)
        return 0
    if not args.dry_run:
        api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                               "description": "Checking exact-source CI evidence"})
    last_reason = ""
    while True:
        try:
            sha, verdict = inspect(api, args.pr, pr_event["base"]["sha"], pr_event["head"]["sha"])
        except (RuntimeError, ValueError, KeyError, TypeError, OSError) as error:
            print("failure: admission evidence unavailable (" + type(error).__name__ + ")", flush=True)
            if not args.dry_run:
                api.post("/statuses/" + status_sha, {"state": "failure", "context": CONTEXT,
                                                   "description": "Admission evidence unavailable"})
            return 1
        if not SHA.fullmatch(sha):
            raise RuntimeError("invalid status target SHA")
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
            time.sleep(30)
            continue
        final_state = "failure" if verdict.state == "pending" else verdict.state
        description = ("Selected jobs and all five CodeQL analyses passed" if final_state == "success"
                       else verdict.reason)[:140]
        if not args.dry_run:
            api.post("/statuses/" + sha, {"state": final_state, "context": CONTEXT,
                                            "description": description})
        return 0 if final_state == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
