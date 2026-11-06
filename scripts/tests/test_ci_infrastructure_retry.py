"""SOU-240: narrow infrastructure retry decisions and at-most-once dispatch."""
from __future__ import annotations

import importlib.util
from email.message import Message
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ci_infrastructure_retry", ROOT / "scripts/ci_infrastructure_retry.py")
assert SPEC and SPEC.loader
import sys
sys.path.insert(0, str(ROOT / "scripts"))
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)

BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
RUN = 1234
JOB = 5678
TARGET = "Components / identity-sandbox / Keycloak driver offline safety"


class Evidence:
    def __init__(self, cause="mirror"):
        self.pr = {"state": "open", "draft": False, "changed_files": 1,
                   "base": {"sha": BASE, "ref": "main"}, "head": {"sha": HEAD},
                   "merge_commit_sha": MERGE}
        self.selected = retry.plan(["Cargo.lock"])
        self.target = {"id": JOB, "name": TARGET, "run_id": RUN, "run_attempt": 1,
                       "head_sha": HEAD, "status": "completed", "conclusion": "failure",
                       "runner_id": 42,
                       "steps": [{"name": "Install Linux sandbox runtime", "conclusion": "failure",
                                  "started_at": "2026-11-06T00:00:00Z",
                                  "completed_at": "2026-11-06T00:00:10Z"}]}
        if cause == "allocation":
            self.target.update(runner_id=0, steps=[])
        self.run = {"id": RUN, "path": ".github/workflows/ci.yml", "event": "pull_request",
                    "head_sha": HEAD, "status": "completed", "conclusion": "failure",
                    "run_attempt": 1, "run_started_at": "2026-11-06T00:00:00Z",
                    "pull_requests": [{"number": 22, "head": {"sha": HEAD}, "base": {"sha": BASE}}]}
        self.runs = [self.run]
        expected = retry.expected_for_run("ci.yml", self.selected)
        self.jobs = [{"id": index + 10000, "name": name, "run_id": RUN,
                      "run_attempt": 1, "head_sha": HEAD, "status": "completed",
                      "conclusion": "success"} for index, name in enumerate(expected) if name != TARGET]
        self.jobs.append(self.target)
        self.log = (b"2026-11-06T00:00:04Z E: Failed to fetch "
                    b"http://archive.ubuntu.com/ubuntu/pool/test.deb 503 Service Unavailable\n")
        self.annotations = [{"annotation_level": "failure",
                             "message": "Failed to acquire a hosted runner."}]
        self.files = [{"filename": "Cargo.lock", "status": "modified"}]
        self.posts = 0
        self.post_error = None
        self.plan_calls = 0
        self.change_on_second = None
        self.log_calls = 0
        self.change_on_second_log = None

    def get(self, path):
        if path.startswith("/pulls/"):
            self.plan_calls += 1
            if self.plan_calls == 2 and self.change_on_second:
                self.change_on_second(self)
            return self.pr
        if path.startswith("/git/commits/"):
            return {"parents": [{"sha": BASE}, {"sha": HEAD if path.endswith(MERGE) else "e" * 40}]}
        if path == "/actions/jobs/" + str(JOB):
            return self.target
        if path == "/actions/runs/" + str(RUN):
            return self.run
        raise AssertionError(path)

    def pages(self, path, field):
        if path.startswith("/pulls/") and path.endswith("/files"):
            return self.files
        if path.startswith("/actions/runs?"):
            return self.runs
        if path == f"/actions/runs/{RUN}/attempts/1/jobs":
            return self.jobs
        if path == f"/check-runs/{JOB}/annotations":
            return self.annotations
        raise AssertionError(path)

    def job_log(self, job_id):
        assert job_id == JOB
        self.log_calls += 1
        if self.log_calls == 2 and self.change_on_second_log:
            self.change_on_second_log(self)
        return self.log

    def rerun_job(self, job_id):
        assert job_id == JOB
        self.posts += 1
        if self.post_error:
            raise self.post_error


class RetryPlanTests(unittest.TestCase):
    def test_reviewed_mirror_and_allocation_have_finite_plan(self):
        for cause, category in (("mirror", "package_mirror_503"),
                                ("allocation", "hosted_runner_allocation")):
            with self.subTest(cause=cause):
                api = Evidence(cause)
                result = retry.retry_plan(api, 22, JOB, BASE)
                self.assertEqual(result["identity"]["category"], category)
                self.assertEqual(result["successful_jobs"], len(retry.expected_for_run("ci.yml", api.selected)) - 1)
                self.assertNotIn("archive.ubuntu.com", json.dumps(result))
                self.assertNotIn("synthetic-token", json.dumps(result))
                self.assertEqual(api.posts, 0)

    def test_failure_and_provenance_controls(self):
        cases = {
            "assertion": lambda e: setattr(e, "log", b"2026-11-06T00:00:04Z assertion failed\n"),
            "wrong_mirror": lambda e: setattr(e, "log", e.log.replace(b"archive.ubuntu.com", b"evil.example")),
            "forged_time": lambda e: setattr(e, "log", e.log.replace(b"00:00:04Z", b"00:01:04Z")),
            "missing_log": lambda e: setattr(e, "log", b""),
            "canceled": lambda e: e.target.update(conclusion="cancelled"),
            "canceled_run": lambda e: e.run.update(conclusion="cancelled"),
            "stale_head": lambda e: e.pr["head"].update(sha="d" * 40),
            "stale_base": lambda e: e.pr["base"].update(sha="d" * 40),
            "changed_parents": lambda e: e.pr.update(merge_commit_sha="d" * 40),
            "already_rerun": lambda e: e.run.update(run_attempt=2),
            "other_failed": lambda e: e.jobs[0].update(conclusion="failure"),
            "unselected_failed": lambda e: e.jobs.append({"id": 99999, "name": "unknown job",
                                                             "conclusion": "failure"}),
            "duplicate": lambda e: e.jobs.append(dict(e.target, id=9876)),
            "changed_workflow": lambda e: e.pr.update(changed_files=2),
            "rename": lambda e: e.files[0].update(status="renamed", previous_filename="old.lock"),
            "deletion": lambda e: e.files[0].update(status="removed"),
            "other_pr": lambda e: e.run["pull_requests"][0].update(number=23),
            "newer_run": lambda e: e.runs.append(dict(e.run, id=RUN + 1,
                                                       run_started_at="2026-11-06T00:01:00Z")),
        }
        for label, change in cases.items():
            with self.subTest(label=label):
                api = Evidence()
                change(api)
                with self.assertRaises(retry.Refusal):
                    retry.retry_plan(api, 22, JOB, BASE)
                self.assertEqual(api.posts, 0)

    def test_allocation_requires_independent_annotation(self):
        api = Evidence("allocation")
        api.annotations = []
        with self.assertRaises(retry.Refusal):
            retry.retry_plan(api, 22, JOB, BASE)

    def test_nonleaf_and_unregistered_dependency_refuse(self):
        with self.assertRaises(retry.Refusal) as context:
            retry.leaf_and_body("ci.yml", "test")
        self.assertEqual(context.exception.reason, "job_has_dependents")
        with self.assertRaises(retry.Refusal):
            retry.needs("      needs: upstream\n")

    def test_successful_job_lineage_changes_plan(self):
        api = Evidence()
        first = retry.retry_plan(api, 22, JOB, BASE)
        api.jobs[0]["id"] += 1
        second = retry.retry_plan(api, 22, JOB, BASE)
        self.assertNotEqual(first["plan_id"], second["plan_id"])

    def test_component_wrapper_failure_does_not_hide_child_success(self):
        api = Evidence()
        api.jobs.append({"id": 99999, "name": "Components", "conclusion": "failure"})
        self.assertEqual(retry.retry_plan(api, 22, JOB, BASE)["status"], "retryable")

    @unittest.skipUnless(os.name == "posix", "private journal is Linux-only")
    def test_one_explicit_dispatch_and_second_operator_refused(self):
        api = Evidence()
        plan_id = retry.retry_plan(api, 22, JOB, BASE)["plan_id"]
        with tempfile.TemporaryDirectory() as parent:
            journal = Path(parent) / "private"
            journal.mkdir(mode=0o700)
            result = retry.execute(api, 22, JOB, BASE, plan_id, journal)
            self.assertEqual(result["status"], "acknowledged")
            self.assertEqual(api.posts, 1)
            with self.assertRaises(retry.Refusal):
                retry.execute(api, 22, JOB, BASE, plan_id, journal)
            self.assertEqual(api.posts, 1)
            records = [json.loads(line) for line in next(journal.iterdir()).read_text().splitlines()]
            self.assertEqual([item["state"] for item in records],
                             ["reserved", "attempted", "acknowledged"])

    @unittest.skipUnless(os.name == "posix", "private journal is Linux-only")
    def test_lost_response_is_uncertain_and_never_reposted(self):
        api = Evidence()
        plan_id = retry.retry_plan(api, 22, JOB, BASE)["plan_id"]
        api.post_error = ConnectionResetError("lost response")
        with tempfile.TemporaryDirectory() as parent:
            journal = Path(parent) / "private"
            journal.mkdir(mode=0o700)
            with self.assertRaises(retry.Refusal) as context:
                retry.execute(api, 22, JOB, BASE, plan_id, journal)
            self.assertEqual(context.exception.reason, "rerun_post_unconfirmed")
            self.assertEqual(api.posts, 1)
            with self.assertRaises(retry.Refusal):
                retry.execute(api, 22, JOB, BASE, plan_id, journal)
            self.assertEqual(api.posts, 1)
            records = [json.loads(line) for line in next(journal.iterdir()).read_text().splitlines()]
            self.assertEqual([item["state"] for item in records],
                             ["reserved", "attempted", "uncertain"])

    @unittest.skipUnless(os.name == "posix", "private journal is Linux-only")
    def test_source_changes_after_reservation_block_post(self):
        api = Evidence()
        plan_id = retry.retry_plan(api, 22, JOB, BASE)["plan_id"]
        api.plan_calls = 0
        api.change_on_second = lambda e: e.pr["head"].update(sha="d" * 40)
        with tempfile.TemporaryDirectory() as parent:
            journal = Path(parent) / "private"
            journal.mkdir(mode=0o700)
            with self.assertRaises(retry.Refusal):
                retry.execute(api, 22, JOB, BASE, plan_id, journal)
            self.assertEqual(api.posts, 0)
            records = [json.loads(line) for line in next(journal.iterdir()).read_text().splitlines()]
            self.assertEqual([item["state"] for item in records], ["reserved", "aborted"])

    @unittest.skipUnless(os.name == "posix", "private journal is Linux-only")
    def test_head_or_attempt_changes_during_final_log_read_block_post(self):
        changes = {
            "head": lambda e: e.pr["head"].update(sha="d" * 40),
            "attempt": lambda e: e.run.update(run_attempt=2),
        }
        for label, change in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as parent:
                api = Evidence()
                plan_id = retry.retry_plan(api, 22, JOB, BASE)["plan_id"]
                api.log_calls = 0
                api.change_on_second_log = change
                journal = Path(parent) / "private"
                journal.mkdir(mode=0o700)
                with self.assertRaises(retry.Refusal):
                    retry.execute(api, 22, JOB, BASE, plan_id, journal)
                self.assertEqual(api.posts, 0)
                records = [json.loads(line) for line in next(journal.iterdir()).read_text().splitlines()]
                self.assertEqual([item["state"] for item in records], ["reserved", "aborted"])

    @unittest.skipUnless(os.name == "posix", "private journal is Linux-only")
    def test_two_concurrent_operators_dispatch_once(self):
        api = Evidence()
        plan_id = retry.retry_plan(api, 22, JOB, BASE)["plan_id"]
        with tempfile.TemporaryDirectory() as parent:
            journal = Path(parent) / "private"
            journal.mkdir(mode=0o700)
            def operator():
                try:
                    return retry.execute(api, 22, JOB, BASE, plan_id, journal)["status"]
                except retry.Refusal as error:
                    return error.reason
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: operator(), range(2)))
            self.assertCountEqual(outcomes, ["acknowledged", "journal_already_exists"])
            self.assertEqual(api.posts, 1)

    @unittest.skipUnless(os.name == "posix", "private journal is Linux-only")
    def test_two_independent_processes_dispatch_once(self):
        context = multiprocessing.get_context("fork")
        counter = context.Value("i", 0)
        gate = context.Barrier(2)
        outcomes = context.Queue()
        plan_id = retry.retry_plan(Evidence(), 22, JOB, BASE)["plan_id"]
        with tempfile.TemporaryDirectory() as parent:
            journal = Path(parent) / "private"
            journal.mkdir(mode=0o700)
            def operator():
                api = Evidence()
                def posted(_):
                    with counter.get_lock():
                        counter.value += 1
                api.rerun_job = posted
                gate.wait(timeout=4)
                try:
                    outcome = retry.execute(api, 22, JOB, BASE, plan_id, journal)["status"]
                except retry.Refusal as error:
                    outcome = error.reason
                outcomes.put(outcome)
            workers = [context.Process(target=operator) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=2)
            self.assertTrue(all(worker.exitcode == 0 for worker in workers))
            self.assertCountEqual([outcomes.get(timeout=2) for _ in workers],
                                  ["acknowledged", "journal_already_exists"])
            self.assertEqual(counter.value, 1)


class TransportTests(unittest.TestCase):
    def test_real_socket_content_length_finishes_without_closed_socket_read(self):
        body = b"2026-11-06T00:00:04Z " + b"x" * 90
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for _ in range(3):
                with urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=3) as response:
                    self.assertEqual(retry.bounded_body(response, time.monotonic() + 3), body)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_declared_short_body_and_size_limit_still_refuse(self):
        response = self.Response(b"short")
        response.length = 6
        with self.assertRaises(retry.Refusal) as context:
            retry.bounded_body(response, time.monotonic() + 3)
        self.assertEqual(context.exception.reason, "job_log_incomplete")
        response = self.Response(b"")
        response.length = retry.MAX_LOG + 1
        with self.assertRaises(retry.Refusal) as context:
            retry.bounded_body(response, time.monotonic() + 3)
        self.assertEqual(context.exception.reason, "job_log_limit")

    class Response:
        def __init__(self, body):
            self.body = BytesIO(body)
            self.fp = type("Reader", (), {"raw": type("Raw", (), {
                "_sock": type("Socket", (), {"settimeout": lambda self, value: None})()
            })()})()
            self.length = len(body)

        def getheader(self, key):
            return str(self.length) if key == "Content-Length" else None

        def read1(self, size):
            return self.body.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    def test_rate_limit_and_502_reads_retry_without_forwarding_token(self):
        signed = "https://productionresultssa3.blob.core.windows.net/x?sig=private"
        events = []
        class Opener:
            def open(self, request, timeout):
                events.append(request)
                if len(events) in (1, 2):
                    code = 429 if len(events) == 1 else 502
                    raise HTTPError(request.full_url, code, "transient", Message(), BytesIO())
                if len(events) == 3:
                    headers = Message()
                    headers["Location"] = signed
                    raise HTTPError(request.full_url, 302, "redirect", headers, BytesIO())
                return TransportTests.Response(b"finite log")
        with patch.object(retry, "build_opener", return_value=Opener()), \
                patch.object(retry.time, "sleep"):
            body = retry.RetryGitHub(retry.REPO, "synthetic-token").job_log(JOB)
        self.assertEqual(body, b"finite log")
        self.assertEqual(len(events), 4)
        self.assertIsNone(events[-1].get_header("Authorization"))

    def test_post_502_is_one_uncertain_request(self):
        events = []
        class Opener:
            def open(self, request, timeout):
                events.append(request)
                raise HTTPError(request.full_url, 502, "bad gateway", Message(), BytesIO())
        with patch.object(retry, "build_opener", return_value=Opener()):
            with self.assertRaises(retry.Refusal) as context:
                retry.RetryGitHub(retry.REPO, "synthetic-token").rerun_job(JOB)
        self.assertEqual(context.exception.reason, "rerun_post_unconfirmed")
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
