#!/usr/bin/env python3
"""Trusted, read-only PR evidence verifier with one merge-SHA admission status.

Run only from the base branch in pull_request_target. Never checkout, import, or
execute PR-controlled files, logs, artifacts, or cache contents in this process.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from http.client import HTTPException, IncompleteRead
import json
import os
import re
import socket
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from ci_impact import WORKFLOW_JOBS, plan
from ci_activation import selective_enabled
from sou91_ruleset_patch import RULESET_ID


CONTEXT = "SOU-91 candidate admission"
SHA = re.compile(r"^[0-9a-f]{40}$")
REUSE_SWITCH = "enabled-after-controls"
RECEIPT = re.compile(
    r"^https://github\.com/SoupTeam/soup-wall/actions/runs/([1-9][0-9]*)"
    r"#sou160-v1\.([1-9][0-9]*)\.([0-9a-f]{64})$"
)
GITHUB_ACTIONS_BOT_ID = 41898282
ADMISSION_WORKFLOW_ID = 388366746
HTTP_ATTEMPTS = 3
HTTP_TIMEOUT = 20
# The existing three 20-second attempts plus 2/4-second backoff, not a new
# admission polling window. One attempt's deadline includes its body reads.
HTTP_BUDGET = HTTP_ATTEMPTS * HTTP_TIMEOUT + 6
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64


class EvidenceAPIError(RuntimeError):
    def __init__(self, reason: str, method: str = "GET"):
        self.reason, self.method = reason, method
        super().__init__("GitHub evidence unavailable: " + reason)


class EvidenceFormatError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__("Invalid GitHub evidence: " + reason)


def error_reason(error: Exception) -> str:
    if isinstance(error, (EvidenceAPIError, EvidenceFormatError)):
        return error.reason
    return "malformed_json" if isinstance(error, json.JSONDecodeError) else "api_unavailable" \
        if isinstance(error, (RuntimeError, OSError)) else "invalid_evidence_schema"


def response_json(response: Any, deadline: float) -> Any:
    """Bound bytes, nesting and elapsed body time on the actual urllib socket.

    urllib's socket timeout otherwise restarts on every receive: a slow drip
    can keep json.load/read() alive indefinitely. Pin its HTTPResponse socket
    and decrease the timeout before each read1 (one underlying receive).
    Refuse unsupported response wrappers instead of falling back to an
    unbounded read. No URL/credential or body is included in errors.
    """
    header = response.getheader("Content-Length")
    if header is not None and not re.fullmatch(r"[0-9]{1,10}", header):
        raise EvidenceFormatError("response_length_invalid")
    expected = int(header) if header is not None else None
    if expected is not None and expected > MAX_RESPONSE_BYTES:
        raise EvidenceFormatError("response_too_large")
    raw = bytearray()
    if expected != 0:
        # CPython urllib returns http.client.HTTPResponse with this socket-backed
        # BufferedReader for both HTTP and HTTPS. Real loopback tests exercise
        # this access; wrappers without it are not accepted evidence readers.
        sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
        if sock is None or not callable(getattr(response, "read1", None)):
            raise EvidenceAPIError("response_reader_unavailable")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(min(HTTP_TIMEOUT, remaining))
            chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(raw)))
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise EvidenceFormatError("response_too_large")
            if expected is not None and len(raw) == expected:
                break
            if not chunk:
                if expected is not None and len(raw) != expected:
                    raise IncompleteRead(b"", expected - len(raw))
                break
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise EvidenceFormatError("json_depth_exceeded")
        elif byte in (93, 125): depth -= 1
    if time.monotonic() >= deadline:
        raise TimeoutError()
    value = json.loads(raw)
    if time.monotonic() >= deadline:
        raise TimeoutError()
    return value

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
        self.http_get_attempts = 0
        self.http_post_attempts = 0
        self.status_posts = 0

    def get(self, suffix: str) -> Any:
        return self._request("GET", suffix)

    def post(self, suffix: str, body: dict[str, Any]) -> Any:
        try:
            return self._request("POST", suffix, body)
        except (ValueError, OSError, RuntimeError, HTTPException):
            # A response failure does not establish whether the write committed.
            # Never retry or issue a compensating status write on this path.
            raise EvidenceAPIError("status_write_unconfirmed", "POST") from None

    def _request(self, method: str, suffix: str, body: dict[str, Any] | None = None,
                 *, response_headers: dict[str, str] | None = None) -> Any:
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
        attempts = HTTP_ATTEMPTS if method == "GET" else 1
        deadline = time.monotonic() + HTTP_BUDGET
        reason = "transport_unavailable"
        for attempt in range(attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                if method == "GET":
                    self.http_get_attempts += 1
                else:
                    self.http_post_attempts += 1
                    if suffix.startswith("/statuses/"):
                        self.status_posts += 1
                attempt_deadline = min(deadline, time.monotonic() + HTTP_TIMEOUT)
                with urlopen(request, timeout=min(HTTP_TIMEOUT, remaining)) as response:
                    value = response_json(response, attempt_deadline)
                    if response_headers is not None:
                        response_headers["Link"] = response.getheader("Link", "")
                    return value
            except HTTPError as error:
                reason = "http_" + str(error.code) if 100 <= error.code <= 599 else "http_error"
                error.close()
                if error.code not in {429, 500, 502, 503, 504}:
                    raise EvidenceAPIError(reason, method) from None
            except IncompleteRead:
                reason = "body_incomplete"
            except (TimeoutError, socket.timeout):
                reason = "read_timeout"
            except ConnectionResetError:
                reason = "connection_reset"
            except (URLError, HTTPException, ConnectionError, OSError):
                reason = "transport_interrupted"
            if attempt + 1 < attempts:
                delay = 2 * (attempt + 1)
                if deadline - time.monotonic() <= delay:
                    break
                time.sleep(delay)
        raise EvidenceAPIError(reason, method) from None

    def pages(self, suffix: str, key: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        count: int | None = None
        identities: set[int | str] = set()
        for page in range(1, 31):
            separator = "&" if "?" in suffix else "?"
            headers: dict[str, str] = {}
            data = self._request("GET", suffix + separator + urlencode({"per_page": 100, "page": page}),
                                 response_headers=headers)
            if key:
                if not isinstance(data, dict) or type(data.get("total_count")) is not int or \
                        not 0 <= data["total_count"] <= 3000:
                    raise EvidenceFormatError("pagination_count_invalid")
                if count is not None and count != data["total_count"]:
                    raise EvidenceAPIError("pagination_count_changed")
                count = data["total_count"]
                entries = data.get(key)
            else:
                entries = data
            if not isinstance(entries, list) or len(entries) > 100 or any(not isinstance(x, dict) for x in entries):
                raise EvidenceFormatError("pagination_shape_invalid")
            for entry in entries:
                identity = entry.get("id")
                if key or "id" in entry:
                    if type(identity) is not int or identity <= 0:
                        raise EvidenceFormatError("pagination_identity_invalid")
                elif suffix.split("?", 1)[0].endswith("/files"):
                    identity = entry.get("filename")
                    if not isinstance(identity, str) or not identity:
                        raise EvidenceFormatError("pagination_identity_invalid")
                if identity is not None:
                    if identity in identities:
                        raise EvidenceFormatError("pagination_duplicate_identity")
                    identities.add(identity)
            results.extend(entries)
            link = headers.get("Link", "")
            if len(link) > 8192:
                raise EvidenceFormatError("pagination_link_invalid")
            links = re.findall(r'<([^<>]+)>;\s*rel="(next|prev|first|last)"', link)
            residue = re.sub(r'<([^<>]+)>;\s*rel="(next|prev|first|last)"', "", link)
            if residue.strip(" ,") or len(links) > 4 or len({rel for _, rel in links}) != len(links):
                raise EvidenceFormatError("pagination_link_invalid")
            for url, rel in links:
                target = urlsplit(url)
                query = parse_qs(target.query)
                if target.scheme != "https" or target.netloc != "api.github.com" or \
                        len(url) > 4096 or (rel == "next" and
                        (query.get("page") != [str(page + 1)] or query.get("per_page") != ["100"])):
                    raise EvidenceFormatError("pagination_link_invalid")
            if count is not None and len(results) > count:
                raise EvidenceAPIError("pagination_count_changed")
            if len(entries) < 100:
                if any(rel == "next" for _, rel in links) or (count is not None and len(results) != count):
                    raise EvidenceAPIError("pagination_incomplete")
                return results
        raise EvidenceAPIError("pagination_limit_exceeded")


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


def evidence_job(job: dict[str, Any]) -> dict[str, Any]:
    """Only identities and decisions, never job logs or candidate output."""
    return {key: job.get(key) for key in
            ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion")}


def evidence_run(run: dict[str, Any]) -> dict[str, Any]:
    return {key: run.get(key) for key in
            ("id", "run_attempt", "head_sha", "path", "event", "status", "conclusion")}


def evidence_digest(evidence: dict[str, Any], verifier_sha: str) -> str:
    if not SHA.fullmatch(verifier_sha):
        raise ValueError("trusted verifier revision unavailable")
    body = json.dumps({"format": "sou160-admission-evidence/1",
                       "verifier_sha": verifier_sha, "evidence": evidence},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def inspect(api: GitHub, number: int, event_base: str, event_head: str,
            *, evidence: dict[str, Any] | None = None) -> tuple[str, Verdict]:
    pr = api.get(f"/pulls/{number}")
    base_sha, head_sha = pr["base"]["sha"], pr["head"]["sha"]
    merge_sha = pr.get("merge_commit_sha")
    if not merge_sha or not SHA.fullmatch(merge_sha):
        return head_sha, Verdict("failure", "merge candidate unavailable or conflicted")
    if pr.get("state") != "open" or base_sha != event_base or head_sha != event_head:
        return merge_sha, Verdict("failure", "PR source moved during admission; re-run on current candidate")
    if pr.get("draft") is True or (evidence is not None and pr.get("draft") is not False):
        return merge_sha, Verdict("failure", "draft or unknown PR state is not merge-qualified")
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
    ruleset: dict[str, Any] | None = None

    def read_ruleset() -> dict[str, Any]:
        nonlocal ruleset
        ruleset = api.get(f"/rulesets/{RULESET_ID}")
        return ruleset

    active = selective_enabled(os.environ.get("SOU91_SELECTIVE_CI"), read_ruleset)
    selected = plan(paths, force_full=not active)
    if evidence is not None:
        evidence.update({
            "pr": {"number": number, "state": pr.get("state"), "draft": pr.get("draft"),
                   "updated_at": pr.get("updated_at"),
                   "base": base_sha, "head": head_sha, "merge": merge_sha,
                   "parents": parents},
            "paths": paths,
            "selection": selected,
            "activation": os.environ.get("SOU91_SELECTIVE_CI"),
            "ruleset_sha256": hashlib.sha256(json.dumps(
                ruleset, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("utf-8")).hexdigest() if ruleset is not None else None,
            "runs": [],
        })
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
        planner = tuple(job["name"] for job in jobs if
                        str(job.get("name", "")).endswith("Candidate " + merge_sha))
        verdict = confirm_jobs(api, jobs, (*planner, *expected), run, head_sha, direct_cache)
        if verdict.state != "success":
            return merge_sha, Verdict(verdict.state, workflow + " " + run_label(run) + ": " + verdict.reason)
        verdict = assess_job_names(jobs, expected, merge_sha, run, head_sha)
        if verdict.state != "success":
            return merge_sha, Verdict(verdict.state, workflow + " " + run_label(run) + ": " + verdict.reason)
        if evidence is not None:
            required = set((*planner, *expected))
            evidence["runs"].append({"workflow": workflow, "run": evidence_run(run),
                                     "expected": expected,
                                     "jobs": sorted((evidence_job(job) for job in jobs
                                                     if job.get("name") in required),
                                                    key=lambda job: (str(job["name"]),
                                                                     str(job["id"])))})
    codeql_jobs = get_jobs(api, codeql)
    verdict = confirm_jobs(api, codeql_jobs, tuple(selected["codeql"]), codeql,
                           head_sha, direct_cache)
    if verdict.state != "success":
        return merge_sha, Verdict(verdict.state, "CodeQL " + run_label(codeql) + ": " + verdict.reason)
    verdict = assess_codeql(codeql, codeql_jobs, selected["codeql"], head_sha)
    if verdict.state != "success":
        return merge_sha, Verdict(verdict.state, "CodeQL " + run_label(codeql) + ": " + verdict.reason)
    if evidence is not None:
        required = set(selected["codeql"])
        evidence["runs"].append({"workflow": "CodeQL", "run": evidence_run(codeql),
                                 "expected": selected["codeql"],
                                 "jobs": sorted((evidence_job(job) for job in codeql_jobs
                                                 if job.get("name") in required),
                                                key=lambda job: (str(job["name"]),
                                                                 str(job["id"])))})
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
    if after.get("state") != "open":
        return merge_sha, Verdict("failure", "PR closed while evidence was inspected")
    if after.get("draft") is True or (evidence is not None and after.get("draft") is not False):
        return merge_sha, Verdict("failure", "PR is draft or Ready state is unknown after inspection")
    if (after["base"]["sha"], after["head"]["sha"], after.get("merge_commit_sha")) != (base_sha, head_sha, merge_sha):
        return merge_sha, Verdict("failure", "PR source changed while evidence was inspected")
    # A Ready -> Draft -> Ready transition can restore the same source and
    # final Ready state while invalidating a previous admission receipt. Bind
    # reuse to the final PR update epoch as well as the initial snapshot.
    if evidence is not None and after.get("updated_at") != evidence["pr"]["updated_at"]:
        return merge_sha, Verdict("pending", "PR update epoch changed while evidence was inspected")
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


def reusable_success(api: GitHub, number: int, base_sha: str, head_sha: str,
                     merge_sha: str, verifier_sha: str) -> bool:
    """A previous green status is only a hint; establish the same evidence anew.

    The fresh inspection retains direct job details, two run listings, run
    detail rechecks and the final PR/source check. The receipt only suppresses
    redundant status writes after complete independent verification.
    """
    if not SHA.fullmatch(verifier_sha) or api.repo != "SoupTeam/soup-wall":
        return False
    statuses = api.get("/commits/" + merge_sha + "/statuses?per_page=100")
    if not isinstance(statuses, list) or any(not isinstance(item, dict) for item in statuses):
        return False
    relevant = [item for item in statuses if item.get("context") == CONTEXT]
    if any(not isinstance(item.get("id"), int) for item in relevant):
        return False
    current = max(relevant, key=lambda item: item["id"], default=None)
    creator = current.get("creator") if current else None
    if not current or current.get("state") != "success" or \
            not isinstance(creator, dict) or creator.get("id") != GITHUB_ACTIONS_BOT_ID:
        return False
    match = RECEIPT.fullmatch(str(current.get("target_url") or ""))
    if match is None:
        return False
    previous_run = api.get("/actions/runs/" + match.group(1))
    if not isinstance(previous_run, dict) or \
            previous_run.get("id") != int(match.group(1)) or \
            previous_run.get("workflow_id") != ADMISSION_WORKFLOW_ID or \
            previous_run.get("path") != ".github/workflows/ci-admission.yml" or \
            previous_run.get("head_sha") != verifier_sha or \
            previous_run.get("event") not in {"pull_request_target", "workflow_run"} or \
            previous_run.get("run_attempt") != int(match.group(2)) or \
            previous_run.get("status") != "completed" or \
            previous_run.get("conclusion") != "success":
        return False
    evidence: dict[str, Any] = {}
    inspected_sha, verdict = inspect(api, number, base_sha, head_sha,
                                     evidence=evidence)
    return isinstance(evidence.get("pr", {}).get("updated_at"), str) and \
        inspected_sha == merge_sha and verdict.state == "success" and \
        evidence_digest(evidence, verifier_sha) == match.group(3)


def receipt_target(api: GitHub, evidence: dict[str, Any]) -> str | None:
    revision = os.environ.get("SOU160_VERIFIER_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if api.repo != "SoupTeam/soup-wall" or not SHA.fullmatch(revision) or \
            not re.fullmatch(r"[1-9][0-9]*", run_id) or \
            not re.fullmatch(r"[1-9][0-9]*", attempt) or \
            not isinstance(evidence.get("pr", {}).get("updated_at"), str):
        return None
    digest = evidence_digest(evidence, revision)
    return ("https://github.com/SoupTeam/soup-wall/actions/runs/" + run_id +
            "#sou160-v1." + attempt + "." + digest)


def admit(api: GitHub, args: argparse.Namespace, pr_event: dict[str, Any]) -> int:
    target: list[str] = []
    try:
        return _admit(api, args, pr_event, target)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        if isinstance(error, EvidenceAPIError) and error.method == "POST":
            print("failure: admission status write unconfirmed; no write retry", flush=True)
            return 1
        state = "pending" if isinstance(error, (RuntimeError, OSError)) else "failure"
        if not target and not args.dry_run:
            state = "failure"  # No verified target exists for a blocking status.
        reason = error_reason(error)
        print(state + ": admission evidence unavailable (" + reason + ")", flush=True)
        if target and not args.dry_run:
            try:
                # Only downgrade the already bound candidate, never infer or
                # publish success when a final freshness read is unavailable.
                api.post("/statuses/" + target[0], {"state": state, "context": CONTEXT,
                          "description": "Admission evidence unavailable: " + reason})
            except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError):
                print("failure: admission status write unconfirmed; no write retry", flush=True)
                return 1
        if state == "failure": return 1
        return 2 if args.dry_run else (0 if target else 1)


def _admit(api: GitHub, args: argparse.Namespace, pr_event: dict[str, Any], target: list[str]) -> int:
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
    target[:] = [status_sha]
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
    reuse_enabled = os.environ.get("SOU160_ADMISSION_REUSE") == REUSE_SWITCH
    verifier_sha = os.environ.get("SOU160_VERIFIER_SHA", "")
    if reuse_enabled and not args.dry_run:
        try:
            if reusable_success(api, args.pr, current["base"]["sha"],
                                current["head"]["sha"], status_sha, verifier_sha):
                print("success: unchanged current evidence already verified", flush=True)
                return 0
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            # A receipt or API outage never authorizes success. The ordinary
            # full verifier below installs a blocking pending status first.
            print("pending: reusable evidence unavailable (" +
                  type(error).__name__ + ")", flush=True)
    refreshed = api.get(f"/pulls/{args.pr}")
    if refreshed.get("state") != "open" or refreshed["base"]["sha"] != \
            pr_event["base"]["sha"] or refreshed["head"]["sha"] != \
            pr_event["head"]["sha"] or refreshed.get("merge_commit_sha") != status_sha:
        print("stale: PR source changed before admission status", flush=True)
        return 0
    if refreshed.get("draft") is True:
        if not args.dry_run:
            api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                               "description": "Draft: full qualification starts when ready for review"})
        return 2 if args.dry_run else 0
    if not args.dry_run:
        api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                               "description": "Checking exact-source CI evidence"})
    last_reason = ""
    while True:
        try:
            evidence: dict[str, Any] = {}
            if reuse_enabled:
                sha, verdict = inspect(api, args.pr, pr_event["base"]["sha"],
                                       pr_event["head"]["sha"], evidence=evidence)
            else:
                sha, verdict = inspect(api, args.pr, pr_event["base"]["sha"],
                                       pr_event["head"]["sha"])
        except (RuntimeError, OSError) as error:
            reason = error_reason(error)
            print("pending: admission API evidence unavailable (" + reason + ")", flush=True)
            if not args.dry_run:
                api.post("/statuses/" + status_sha, {"state": "pending", "context": CONTEXT,
                                                   "description": "Admission API evidence unavailable: " + reason})
            return 2 if args.dry_run else 0
        except (ValueError, KeyError, TypeError) as error:
            reason = error_reason(error)
            print("failure: admission evidence unavailable (" + reason + ")", flush=True)
            if not args.dry_run:
                api.post("/statuses/" + status_sha, {"state": "failure", "context": CONTEXT,
                                                   "description": "Admission evidence unavailable: " + reason})
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
            target[:] = [sha]
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
            payload = {"state": final_state, "context": CONTEXT,
                       "description": description}
            if final_state == "success" and reuse_enabled:
                target = receipt_target(api, evidence)
                if target is not None:
                    payload["target_url"] = target
            api.post("/statuses/" + sha, payload)
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
    try:
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
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        # Routing/initial PR reads may fail before a safe status target exists.
        # Fail the trusted job with a finite diagnostic, never a body/URL-bearing
        # traceback or a guessed success/status target.
        reason = "status_write_unconfirmed" if isinstance(error, EvidenceAPIError) and error.method == "POST" \
            else error_reason(error)
        print("failure: admission evidence unavailable (" + reason + ")", flush=True)
        return 1
    finally:
        # Sanitized physical HTTP attempt counts, including retries. These
        # separate verifier cost from the independently billed CI matrix.
        if all(isinstance(getattr(api, key, None), int) for key in
               ("http_get_attempts", "http_post_attempts", "status_posts")):
            print("admission requests: GET=" + str(api.http_get_attempts) +
                  " POST=" + str(api.http_post_attempts) +
                  " status_writes=" + str(api.status_posts), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
