#!/usr/bin/env python3
"""Plan one exact-source infrastructure job retry; execute only on explicit request.

Run from a clean checkout of the current PR base. This tool never writes an
admission status. GitHub's existing workflow_run verifier owns that decision.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ci_admission import GitHub, SHA, component_names, get_jobs, latest, required_names
from ci_components import blocks
from ci_impact import WORKFLOW_JOBS, plan

REPO = "SoupTeam/soup-wall"
ROOT = Path(__file__).resolve().parents[1]
MAX_LOG = 2 * 1024 * 1024
LOG_SECONDS = 20
LOG_ATTEMPTS = 3
MAX_ANNOTATIONS = 20
PLAN_FORMAT = "sou240-infra-retry-plan/1"
JOURNAL_FORMAT = "sou240-infra-retry-journal/1"
INSTALL_STEPS = {
    ("ci.yml", "all-features"): "Install Linux sandbox runtime",
    ("identity-sandbox.yml", "vendor-driver-safety"): "Install Linux sandbox runtime",
}
MIRRORS = {"archive.ubuntu.com", "security.ubuntu.com", "azure.archive.ubuntu.com"}
MIRROR_ERROR = re.compile(
    r"^E: Failed to fetch https?://([a-z0-9.-]+)/\S+\s+"
    r"(500 Internal Server Error|502 Bad Gateway|503 Service Unavailable|"
    r"504 Gateway Time-out|504 Gateway Timeout)(?: \[IP: [0-9a-fA-F:.]+ [0-9]{1,5}\])?$"
)
ALLOCATION_ERROR = re.compile(
    r"^(?:Failed to acquire a hosted runner|The job was not started because a hosted runner was unavailable)[.!]?$"
)
LOG_REDIRECT_HOST = re.compile(r"^productionresultssa[0-9]+\.blob\.core\.windows\.net$")
HOSTED_RUNNERS = frozenset({"ubuntu-22.04", "ubuntu-24.04", "ubuntu-latest",
                            "macos-15", "windows-2022", "windows-latest"})


class Refusal(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def bounded_body(response, deadline: float) -> bytes:
    header = response.getheader("Content-Length")
    if header is not None and (not re.fullmatch(r"[0-9]{1,8}", header) or int(header) > MAX_LOG):
        raise Refusal("job_log_limit")
    expected = int(header) if header is not None else None
    if expected == 0:
        return b""
    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if sock is None or not callable(getattr(response, "read1", None)):
        raise Refusal("job_log_reader_unavailable")
    data = bytearray()
    while True:
        if expected is not None and len(data) == expected:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refusal("job_log_timeout")
        sock.settimeout(min(remaining, 8))
        limit = min(65536, MAX_LOG + 1 - len(data))
        if expected is not None:
            limit = min(limit, expected - len(data))
        block = response.read1(limit)
        data.extend(block)
        if len(data) > MAX_LOG:
            raise Refusal("job_log_limit")
        if not block:
            break
    if expected is not None and len(data) != expected:
        raise Refusal("job_log_incomplete")
    return bytes(data)


class RetryGitHub(GitHub):
    """Reuse accepted bounded JSON reads; never retry the non-idempotent POST."""

    def job_log(self, job_id: int) -> bytes:
        opener = build_opener(NoRedirect())
        endpoint = f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs"
        for attempt in range(LOG_ATTEMPTS):
            deadline = time.monotonic() + LOG_SECONDS
            request = Request(endpoint, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "User-Agent": "sou240-infra-retry",
            })
            try:
                try:
                    with opener.open(request, timeout=8) as response:
                        return bounded_body(response, deadline)
                except HTTPError as error:
                    location = error.headers.get("Location", "")
                    code = error.code
                    error.close()
                    if code != 302:
                        if code in {429, 500, 502, 503, 504} and attempt + 1 < LOG_ATTEMPTS:
                            time.sleep(attempt + 1)
                            continue
                        raise Refusal("job_log_unavailable")
                target = urlsplit(location)
                if (len(location) > 8192 or target.scheme != "https" or target.port is not None or
                        target.username is not None or target.password is not None or target.fragment or
                        not LOG_REDIRECT_HOST.fullmatch(target.hostname or "")):
                    raise Refusal("job_log_redirect_invalid")
                # The signed URL is never printed, persisted, or sent the API token.
                with opener.open(Request(location, headers={"User-Agent": "sou240-infra-retry"}),
                                 timeout=max(1, min(8, deadline - time.monotonic()))) as response:
                    return bounded_body(response, deadline)
            except Refusal:
                raise
            except (HTTPError, URLError, OSError, HTTPException, TimeoutError, socket.timeout):
                if attempt + 1 < LOG_ATTEMPTS:
                    time.sleep(attempt + 1)
                    continue
                raise Refusal("job_log_unavailable") from None
        raise Refusal("job_log_unavailable")

    def rerun_job(self, job_id: int) -> None:
        request = Request(f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/rerun",
                          data=b"", method="POST", headers={
                              "Authorization": "Bearer " + self.token,
                              "Accept": "application/vnd.github+json",
                              "User-Agent": "sou240-infra-retry",
                          })
        try:
            with build_opener(NoRedirect()).open(request, timeout=20) as response:
                if response.status != 201:
                    raise Refusal("rerun_post_unconfirmed")
        except (HTTPError, URLError, OSError, HTTPException, TimeoutError, socket.timeout):
            raise Refusal("rerun_post_unconfirmed") from None


def local_base() -> str:
    """An operator must run trusted base code, never the candidate checkout."""
    try:
        root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                       cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        head = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                        cwd=ROOT, text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        raise Refusal("trusted_checkout_unavailable") from None
    if Path(root).resolve() != ROOT.resolve() or dirty or not SHA.fullmatch(head):
        raise Refusal("trusted_checkout_dirty_or_wrong_root")
    return head


def source_job_name(workflow: str, name: str, selected: dict) -> tuple[str, str]:
    matches = []
    if workflow == "ci.yml":
        for job_id in selected["workflows"]["ci.yml"]:
            if name in required_names("ci.yml", [job_id]):
                matches.append(("ci.yml", job_id))
        for source, ids in selected["workflows"].items():
            if source == "ci.yml":
                continue
            for job_id in ids:
                if name in component_names(source, [job_id]):
                    matches.append(("ci-components.yml", source.removesuffix(".yml") + "--" + job_id))
    else:
        for job_id in selected["workflows"].get(workflow, ()):
            if name in required_names(workflow, [job_id]):
                matches.append((workflow, job_id))
    if len(matches) != 1:
        raise Refusal("job_unselected_or_ambiguous")
    return matches[0]


def needs(body: str) -> tuple[str, ...]:
    raw_needs = re.findall(r"(?m)^\s+needs:.*$", body)
    values = re.findall(r"(?m)^    needs: (.+)$", body)
    if len(raw_needs) != len(values):
        raise Refusal("dependency_ambiguous")
    if not values:
        return ()
    if len(values) != 1:
        raise Refusal("dependency_ambiguous")
    raw = values[0]
    if re.fullmatch(r"[a-z][a-z0-9-]*", raw):
        return (raw,)
    if re.fullmatch(r"\[[a-z0-9, -]+\]", raw):
        return tuple(part.strip() for part in raw[1:-1].split(","))
    raise Refusal("dependency_ambiguous")


def leaf_and_body(workflow: str, job_id: str) -> str:
    try:
        source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8-sig")
        jobs = blocks(source)
    except (OSError, UnicodeError, IndexError, ValueError):
        raise Refusal("trusted_graph_unavailable") from None
    if job_id not in jobs:
        raise Refusal("job_not_in_trusted_graph")
    for other, body in jobs.items():
        if other != job_id and job_id in needs(body):
            raise Refusal("job_has_dependents")
    return jobs[job_id]


def expected_for_run(workflow: str, selected: dict) -> tuple[str, ...]:
    if workflow != "ci.yml":
        return required_names(workflow, selected["workflows"][workflow])
    names = list(required_names("ci.yml", selected["workflows"]["ci.yml"]))
    for source, ids in selected["workflows"].items():
        if source != "ci.yml":
            names.extend(component_names(source, ids))
    return tuple(names)


def classify_allocation(api, job: dict, source_body: str) -> tuple[str, str] | None:
    runner = re.findall(r"(?m)^    runs-on: (.+)$", source_body)
    if (len(runner) != 1 or runner[0] not in HOSTED_RUNNERS or
            job.get("runner_id") not in (None, 0) or job.get("steps") != []):
        return None
    annotations = api.pages(f"/check-runs/{job['id']}/annotations", "")
    if len(annotations) > MAX_ANNOTATIONS:
        raise Refusal("allocation_evidence_ambiguous")
    matches = [item for item in annotations if item.get("annotation_level") == "failure" and
               isinstance(item.get("message"), str) and len(item["message"]) <= 256 and
               ALLOCATION_ERROR.fullmatch(item["message"])]
    if len(annotations) != 1 or len(matches) != 1:
        return None
    digest = hashlib.sha256(matches[0]["message"].encode("utf-8")).hexdigest()
    return "hosted_runner_allocation", digest


def classify_mirror(api, job: dict, source: str, job_id: str) -> tuple[str, str] | None:
    name = INSTALL_STEPS.get((source, job_id))
    if name is None:
        return None
    failed = [step for step in job.get("steps", []) if step.get("conclusion") == "failure"]
    if len(failed) != 1 or failed[0].get("name") != name:
        return None
    step = failed[0]
    if any(item.get("conclusion") == "failure" for item in job["steps"] if item is not step):
        return None
    try:
        start = datetime.fromisoformat(step["started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(step["completed_at"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, ValueError):
        raise Refusal("failed_step_time_missing") from None
    if end < start or (end - start).total_seconds() > 1800:
        raise Refusal("failed_step_time_invalid")
    log = api.job_log(int(job["id"]))
    try:
        lines = log.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        raise Refusal("job_log_encoding_invalid") from None
    matched = set()
    for line in lines:
        prefix = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z) (.+)$", line)
        if not prefix:
            continue
        message = prefix[2].removeprefix("##[error]")
        result = MIRROR_ERROR.fullmatch(message)
        if not result or result[1] not in MIRRORS:
            continue
        timestamp = datetime.fromisoformat(prefix[1].replace("Z", "+00:00"))
        if start <= timestamp <= end:
            matched.add(result[2][:3])
    if len(matched) != 1:
        return None
    return "package_mirror_" + matched.pop(), hashlib.sha256(log).hexdigest()


def retry_plan(api, pr_number: int, job_id: int, trusted_base: str) -> dict:
    if pr_number <= 0 or job_id <= 0 or not SHA.fullmatch(trusted_base):
        raise Refusal("invalid_input")
    pr = api.get(f"/pulls/{pr_number}")
    base, head, merge = pr["base"]["sha"], pr["head"]["sha"], pr.get("merge_commit_sha")
    if (pr.get("state") != "open" or pr.get("draft") is not False or
            pr["base"].get("ref") != "main" or
            not all(SHA.fullmatch(str(sha)) for sha in (base, head, merge))):
        raise Refusal("candidate_not_ready")
    if trusted_base != base:
        raise Refusal("trusted_base_changed")
    parents = [item["sha"] for item in api.get("/git/commits/" + merge).get("parents", [])]
    if parents != [base, head]:
        raise Refusal("merge_parents_changed")
    files = api.pages(f"/pulls/{pr_number}/files", "")
    if len(files) != pr.get("changed_files") or any(
            item.get("status") not in {"modified", "added"} or
            not isinstance(item.get("filename"), str) or
            item.get("previous_filename") is not None or
            item["filename"].startswith(".github/workflows/") for item in files):
        raise Refusal("workflow_source_changed_or_files_incomplete")
    paths = [path for item in files for path in (item.get("filename"), item.get("previous_filename")) if path]
    selected = plan(paths)
    job = api.get("/actions/jobs/" + str(job_id))
    run_id = job.get("run_id")
    if not isinstance(run_id, int) or run_id <= 0:
        raise Refusal("job_run_identity_missing")
    run = api.get("/actions/runs/" + str(run_id))
    path = str(run.get("path", "")).split("@", 1)[0]
    if not path.startswith(".github/workflows/") or not path.endswith(".yml"):
        raise Refusal("workflow_unregistered")
    workflow = path.rsplit("/", 1)[1]
    if workflow not in WORKFLOW_JOBS or run.get("event") != "pull_request" or \
            run.get("head_sha") != head or run.get("status") != "completed" or \
            run.get("conclusion") != "failure" or run.get("run_attempt") != 1:
        raise Refusal("run_not_current_first_failure")
    associated = run.get("pull_requests")
    if (not isinstance(associated, list) or len(associated) != 1 or
            associated[0].get("number") != pr_number or
            associated[0].get("head", {}).get("sha") != head or
            associated[0].get("base", {}).get("sha") != base):
        raise Refusal("run_candidate_association_invalid")
    actions = api.pages("/actions/runs?" + urlencode({"head_sha": head, "event": "pull_request"}),
                        "workflow_runs")
    current = latest(actions, path, "pull_request", head)
    if current is None or (current.get("id"), current.get("run_attempt")) != (run_id, 1):
        raise Refusal("newer_run_or_attempt")
    source, source_job = source_job_name(workflow, job.get("name"), selected)
    source_body = leaf_and_body(source, source_job)
    jobs = get_jobs(api, run)
    listed = [entry for entry in jobs if entry.get("id") == job_id]
    if len(listed) != 1 or sum(entry.get("name") == job.get("name") for entry in jobs) != 1:
        raise Refusal("job_list_ambiguous")
    if any(listed[0].get(key) != job.get(key) for key in
           ("name", "run_id", "run_attempt", "head_sha", "status", "conclusion")):
        raise Refusal("job_list_detail_disagree")
    if (job.get("run_attempt") != 1 or job.get("head_sha") != head or
            job.get("status") != "completed" or job.get("conclusion") != "failure"):
        raise Refusal("job_not_failed_current_attempt")
    for other in jobs:
        if other.get("id") == job_id:
            continue
        if other.get("conclusion") in {"failure", "timed_out", "cancelled",
                                       "action_required", "stale"}:
            wrapper = (workflow == "ci.yml" and other.get("name") == "Components" and
                       str(job.get("name", "")).startswith("Components / "))
            if not wrapper:
                raise Refusal("another_job_requires_investigation")
    expected = expected_for_run(workflow, selected)
    if job["name"] not in expected:
        raise Refusal("job_unselected_or_ambiguous")
    by_name = {name: [entry for entry in jobs if entry.get("name") == name] for name in expected}
    if any(len(entries) != 1 for entries in by_name.values()):
        raise Refusal("selected_job_evidence_incomplete")
    lineage = []
    for name, entries in by_name.items():
        if name != job["name"] and (entries[0].get("conclusion") != "success" or
                                    entries[0].get("status") != "completed"):
            raise Refusal("other_selected_job_not_successful")
        if name != job["name"]:
            other = entries[0]
            if (type(other.get("id")) is not int or other["id"] <= 0 or
                    other.get("run_id") != run_id or other.get("run_attempt") != 1 or
                    other.get("head_sha") != head):
                raise Refusal("successful_job_lineage_invalid")
            lineage.append({"job_id": other["id"], "name": name})
    mirror_source = source
    mirror_job = source_job
    if source == "ci-components.yml":
        sources = [(name, name.removesuffix(".yml") + "--") for name in WORKFLOW_JOBS
                   if name != "ci.yml"]
        matches = [(name, source_job[len(prefix):]) for name, prefix in sources
                   if source_job.startswith(prefix)]
        if len(matches) != 1:
            raise Refusal("component_source_ambiguous")
        mirror_source, mirror_job = matches[0]
    classified = classify_allocation(api, job, source_body) or classify_mirror(
        api, job, mirror_source, mirror_job)
    if classified is None:
        raise Refusal("cause_not_reviewed_or_evidence_missing")
    category, evidence_sha = classified
    identity = {"pr": pr_number, "base": base, "head": head, "merge": merge,
                "run_id": run_id, "run_attempt": 1, "job_id": job_id,
                "job_name": job["name"], "workflow": workflow,
                "category": category, "evidence_sha256": evidence_sha,
                "successful_job_lineage": sorted(lineage, key=lambda item: item["name"])}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"))
                            .encode("utf-8")).hexdigest()
    return {"format": PLAN_FORMAT, "status": "retryable", "plan_id": digest,
            "identity": identity, "successful_jobs": len(lineage),
            "admission": "completion_driven_recheck_required"}


def journal_claim(directory: Path, plan_id: str) -> tuple[int, Path]:
    if os.name != "posix" or not re.fullmatch(r"[0-9a-f]{64}", plan_id):
        raise Refusal("private_posix_journal_required")
    try:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refusal("private_journal_directory_required")
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.fstat(directory_fd).st_ino != info.st_ino or os.fstat(directory_fd).st_dev != info.st_dev:
                raise Refusal("journal_directory_changed")
            name = "sou240-" + plan_id + ".jsonl"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            return fd, directory / name
        finally:
            os.close(directory_fd)
    except FileExistsError:
        raise Refusal("journal_already_exists") from None
    except OSError:
        raise Refusal("journal_unavailable") from None


def journal_record(fd: int, state: str, plan_id: str) -> None:
    if state not in {"reserved", "attempted", "acknowledged", "uncertain", "aborted"}:
        raise ValueError("unregistered journal state")
    record = json.dumps({"format": JOURNAL_FORMAT, "plan_id": plan_id, "state": state},
                        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if os.write(fd, record) != len(record):
        raise Refusal("journal_write_uncertain")
    os.fsync(fd)


def confirm_dispatch_freshness(api, identity: dict) -> None:
    """Fence changes after the final potentially slow log/annotation read."""
    pr = api.get(f"/pulls/{identity['pr']}")
    if (pr.get("state") != "open" or pr.get("draft") is not False or
            pr.get("base", {}).get("sha") != identity["base"] or
            pr.get("head", {}).get("sha") != identity["head"] or
            pr.get("merge_commit_sha") != identity["merge"]):
        raise Refusal("candidate_changed_before_dispatch")
    parents = [item.get("sha") for item in
               api.get("/git/commits/" + identity["merge"]).get("parents", [])]
    if parents != [identity["base"], identity["head"]]:
        raise Refusal("merge_parents_changed_before_dispatch")
    job = api.get("/actions/jobs/" + str(identity["job_id"]))
    if (job.get("run_id") != identity["run_id"] or job.get("run_attempt") != 1 or
            job.get("head_sha") != identity["head"] or
            job.get("status") != "completed" or job.get("conclusion") != "failure"):
        raise Refusal("job_changed_before_dispatch")
    run = api.get("/actions/runs/" + str(identity["run_id"]))
    path = str(run.get("path", "")).split("@", 1)[0]
    if (path != ".github/workflows/" + identity["workflow"] or
            run.get("head_sha") != identity["head"] or
            run.get("status") != "completed" or run.get("conclusion") != "failure" or
            run.get("run_attempt") != 1):
        raise Refusal("run_changed_before_dispatch")
    actions = api.pages("/actions/runs?" + urlencode({"head_sha": identity["head"],
                                                       "event": "pull_request"}),
                        "workflow_runs")
    current = latest(actions, path, "pull_request", identity["head"])
    if current is None or (current.get("id"), current.get("run_attempt")) != \
            (identity["run_id"], 1):
        raise Refusal("newer_run_or_attempt_before_dispatch")


def execute(api, pr_number: int, job_id: int, trusted_base: str,
            approved_plan_id: str, journal_dir: Path) -> dict:
    first = retry_plan(api, pr_number, job_id, trusted_base)
    if first["plan_id"] != approved_plan_id:
        raise Refusal("plan_changed_since_review")
    fd, _ = journal_claim(journal_dir, approved_plan_id)
    try:
        journal_record(fd, "reserved", approved_plan_id)
        try:
            second = retry_plan(api, pr_number, job_id, trusted_base)
            if second != first:
                raise Refusal("plan_changed_before_dispatch")
            confirm_dispatch_freshness(api, first["identity"])
        except Refusal:
            journal_record(fd, "aborted", approved_plan_id)
            raise
        journal_record(fd, "attempted", approved_plan_id)
        try:
            api.rerun_job(job_id)
        except Exception:
            journal_record(fd, "uncertain", approved_plan_id)
            raise Refusal("rerun_post_unconfirmed") from None
        journal_record(fd, "acknowledged", approved_plan_id)
    finally:
        os.close(fd)
    return {"format": PLAN_FORMAT, "status": "acknowledged", "plan_id": approved_plan_id,
            "journal_state": "acknowledged", "run_id": first["identity"]["run_id"],
            "previous_attempt": 1, "admission": "await_workflow_run_completed_event"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--plan-id")
    parser.add_argument("--journal-dir", type=Path)
    args = parser.parse_args()
    if args.execute != bool(args.plan_id) or args.execute != bool(args.journal_dir):
        parser.error("--execute requires --plan-id and --journal-dir; planning is read-only")
    if os.environ.get("GITHUB_REPOSITORY", REPO).lower() != REPO.lower() or not os.environ.get("GITHUB_TOKEN"):
        parser.error("explicit repository identity and GITHUB_TOKEN required")
    try:
        base = local_base()
        api = RetryGitHub(REPO, os.environ["GITHUB_TOKEN"])
        result = (execute(api, args.pr, args.job_id, base, args.plan_id, args.journal_dir)
                  if args.execute else retry_plan(api, args.pr, args.job_id, base))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Refusal as error:
        print(json.dumps({"format": PLAN_FORMAT, "status": "refused", "pr": args.pr,
                          "job_id": args.job_id, "reason": error.reason},
                         sort_keys=True, separators=(",", ":")))
        return 2
    except Exception:
        print(json.dumps({"format": PLAN_FORMAT, "status": "refused",
                          "pr": args.pr, "job_id": args.job_id,
                          "reason": "evidence_unavailable_or_invalid"},
                         sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
