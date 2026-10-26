# SPDX-License-Identifier: Apache-2.0
"""Negative acceptance guards; these do not qualify native execution."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "verify-sou156-git-object-witness.py"
SPEC = importlib.util.spec_from_file_location("sou156_native_driver", SCRIPT)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


def parser_fixture(root):
    """Tiny synthetic parser input, never native/runtime acceptance evidence."""
    cases = [{"case": name, "passed": True} for name in DRIVER.CASES]
    sessions = []
    for name in ("seed", "same-snapshot", "local-wait", "fresh"):
        directory = root / name
        directory.mkdir()
        requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        replies = [{"jsonrpc": "2.0", "id": identifier, "result": {}} for identifier in (1, 2)]
        if name == "same-snapshot":
            for case, identifier, kind in (("commit", 10, "commit"), ("plain_blob", 11, "blob"),
                    ("commit_looking_blob", 12, "blob"), ("tag_commit", 13, "tag"), ("nested_tag", 14, "tag")):
                request = {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                           "params": {"name": "git_show", "arguments": {"revision": f"{identifier:040x}"}}}
                reply = {"jsonrpc": "2.0", "id": identifier, "result": {"isError": False,
                         "content": [{"type": "text", "text": "Owned synthetic parser fixture."}]}}
                requests.append(request)
                replies.append(reply)
                request_raw, reply_raw = [json.dumps(value).encode() + b"\n" for value in (request, reply)]
                claim = {"format": DRIVER.FORMAT.decode(), "operation": "git_show",
                         "revision": request["params"]["arguments"]["revision"],
                         "target": {"requested": {"kind": kind}},
                         "schema_sha256": list(hashlib.sha256((DRIVER.ROOT /
                            "profiles/mcp/git-readonly-v1/upstream-tools-list.json").read_bytes()).digest()),
                         "request_sha256": list(DRIVER.domain_hash(b"original-request-wire", request_raw)),
                         "result_sha256": list(DRIVER.domain_hash(b"original-result-wire", reply_raw)),
                         "result_bytes": len(reply_raw), "view_sha256": [1] * 32, "view_generation": [2] * 32}
                next(row for row in cases if row["case"] == case)["claim"] = claim
        for label, frames in (("request", requests), ("response", replies)):
            for sequence, value in enumerate(frames):
                (directory / f"{label}-{sequence:02}.jsonl").write_bytes(json.dumps(value).encode() + b"\n")
        cleanup = {"failed": False, "cleanup": {"process_reaped": True, "namespace_terminated": True,
                   "owned_resources_removed": True, "runtime_failure": False}}
        (directory / "cleanup.json").write_text(json.dumps(cleanup))
        (directory / "stderr.bin").write_bytes(b"")
        sessions.append({"directory": name, "requests": len(requests), "responses": len(replies),
                         "response_bytes": sum(len(json.dumps(value).encode()) + 1 for value in replies), "cleanup": cleanup})
    sessions[-1]["local_claim"] = {"view_sha256": [1] * 32, "view_generation": [3] * 32}
    next(row for row in cases if row["case"] == "local_wait_before_write").update(
        sent_before=3, sent_after=3, original_request_written=False)
    report = {"format": "sou156-same-snapshot-component/1", "status": "pass", "skipped": 0,
              "production_authentication": "disabled", "cases": cases, "sessions": sessions,
              "repository_before": {}, "repository_after": {}}
    (root / "report.json").write_text(json.dumps(report))
    return report


class NativeEvidenceGuards(unittest.TestCase):
    def test_synthetic_parser_fixture_and_actual_frame_digest_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parser_fixture(root)
            DRIVER.verify_native(root)
            path = root / "same-snapshot/response-02.jsonl"
            raw = path.read_bytes()
            changed = raw.replace(b"Owned synthetic", b"Other synthetic")
            self.assertNotEqual(raw, changed)
            self.assertEqual(len(raw), len(changed))
            path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "claim/original frame binding mismatch"):
                DRIVER.verify_native(root)

    def test_duplicate_transcript_id_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parser_fixture(root)
            path = root / "same-snapshot/request-04.jsonl"
            row = json.loads(path.read_bytes())
            row["id"] = 10
            path.write_text(json.dumps(row) + "\n")
            with self.assertRaisesRegex(ValueError, "duplicate or missing original ID"):
                DRIVER.verify_native(root)

    def test_missing_transcript_frame_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parser_fixture(root)
            (root / "same-snapshot/response-02.jsonl").unlink()
            with self.assertRaisesRegex(ValueError, "transcript frame set incomplete"):
                DRIVER.verify_native(root)

    def test_missing_and_failed_cleanup_refuse(self):
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = parser_fixture(root)
                if missing:
                    report["sessions"][0].pop("cleanup")
                else:
                    report["sessions"][0]["cleanup"]["cleanup"]["namespace_terminated"] = False
                (root / "report.json").write_text(json.dumps(report))
                with self.assertRaisesRegex(ValueError, "owner cleanup unverified"):
                    DRIVER.verify_native(root)

    def test_missing_duplicate_reordered_and_failed_cases_refuse_before_assets(self):
        accepted_names = list(DRIVER.CASES)
        variants = [([], True), (accepted_names[:-1], True),
                    (accepted_names + [accepted_names[-1]], True),
                    (list(reversed(accepted_names)), True), (accepted_names, False)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for names, passed in variants:
                (root / "report.json").write_text(json.dumps({
                    "format": "sou156-same-snapshot-component/1", "status": "pass", "skipped": 0,
                    "production_authentication": "disabled",
                    "cases": [{"case": name, "passed": passed} for name in names]}))
                with self.assertRaisesRegex(ValueError, "missing, duplicated, reordered or failed"):
                    DRIVER.verify_native(root)

    def test_wrong_platform_refuses_before_output_or_source_access(self):
        with patch.object(DRIVER.platform, "system", return_value="Darwin"), \
             patch.object(DRIVER.BASE, "source", side_effect=AssertionError("source must not be read")):
            with self.assertRaisesRegex(ValueError, "native Linux x86-64 required"):
                DRIVER.run(None)

    def test_oversized_retained_evidence_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.jsonl"
            with path.open("wb") as output:
                output.truncate(DRIVER.LIMIT + 1)
            with self.assertRaisesRegex(ValueError, "bounded evidence file required"):
                DRIVER.read(path)


if __name__ == "__main__":
    unittest.main()
