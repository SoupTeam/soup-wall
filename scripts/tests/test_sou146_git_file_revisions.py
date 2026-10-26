# SPDX-License-Identifier: Apache-2.0
"""Independent original-schema and per-file grammar boundary regressions."""
import importlib.util
import json
import itertools
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
INSTALL = load("sou146_install", "scripts/install-sou68-git-profile.py")
CLASSIFIER = load("sou146_classifier", "rule_baseline/git_readonly_file_revisions_v1/rule_baseline.py")
LEGACY = load("sou146_legacy", "rule_baseline/git_readonly_v1/rule_baseline.py")
VERIFY = load("sou146_verify", "scripts/verify-sou146-git-file-revisions.py")

class PerFileRevisions(unittest.TestCase):
    def batch_run(self, *, expired_followup=False, complete_cleanup=True):
        clients = []
        cleanup = {"all_stopped": complete_cleanup, "observation_complete": True, "remaining": [],
                   "observed": [{"parent_process": False, "original_git_server": True}]}
        class Client:
            forced_cleanup = False
            def __init__(self):
                self.liveness_session_id = "owned-" + str(len(clients))
                self.process = SimpleNamespace(pid=len(clients) + 1, returncode=0)
                self.calls, self.closed = [], False
                clients.append(self)
            def initialize(self):
                pass
            def exchange(self, frame):
                self.calls.append(frame)
                if frame["id"] < 1000:
                    reply = {"id": frame["id"], "error": {"code": -32602, "message": "Git bounded refusal"}}
                else:
                    if expired_followup:
                        raise RuntimeError("simulated authority expired")
                    reply = {"id": frame["id"], "result": {"content": [{"type": "text", "text": "owned useful text"}]}}
                return reply, json.dumps(reply).encode() + b"\n"
            def close(self):
                self.closed = True
            def transcript(self):
                return {"sent": [json.dumps(frame) for frame in self.calls], "received": [], "exit_code": 0}
        observer = SimpleNamespace(sample=lambda: None, observed={})
        report = {"refusals": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile.json"
            profile.write_text("{}")
            stack = SimpleNamespace(root=root, poison="b" * 40, profile=profile,
                                    workspace=root, daemon_witnesses=[("owned", None, observer)])
            with mock.patch.object(VERIFY, "collector", side_effect=lambda *args: Client()), \
                 mock.patch.object(VERIFY, "DaemonProcessWitness", side_effect=lambda pid: SimpleNamespace(finish=lambda: cleanup)), \
                 mock.patch.object(VERIFY.GIT, "RepositoryWitness", side_effect=lambda path: SimpleNamespace(drain=lambda: 0, close=lambda: None)), \
                 mock.patch.object(VERIFY, "batch_worker_cleanup", return_value=cleanup), \
                 mock.patch.object(VERIFY.BASE, "snapshot", return_value={}), \
                 mock.patch.object(VERIFY.BASE, "events", return_value=[]), \
                 mock.patch.object(VERIFY, "healthy_lease", side_effect=lambda stack, client, report, label: {
                     "session_id": client.liveness_session_id, "epoch_sha256": "epoch-" + client.liveness_session_id}):
                try:
                    VERIFY.refusal_batches(stack, "a" * 40, report, "owned useful text")
                except (RuntimeError, ValueError) as error:
                    return clients, report, error
        return clients, report, None

    def test_all_64_refusals_keep_same_client_continuations_in_four_independent_batches(self):
        clients, report, error = self.batch_run()
        self.assertIsNone(error)
        self.assertEqual(len(clients), 4)
        identifiers = []
        for client, batch in zip(clients, report["refusal_batches"]):
            self.assertTrue(client.closed and batch["passed"])
            self.assertEqual(len(client.calls), 32)
            self.assertEqual(len(batch["completed_pairs"]), 16)
            self.assertEqual(batch["lease"]["session_id"], client.liveness_session_id)
            for denial, continuation in zip(client.calls[::2], client.calls[1::2]):
                identifiers.append(denial["id"])
                self.assertEqual(continuation["id"], denial["id"] + 1000)
                self.assertEqual(continuation["params"]["arguments"]["revision"], VERIFY.REFS[0])
        self.assertEqual(identifiers, list(range(100, 164)))
        self.assertEqual(len(report["refusals"]), 64)
        self.assertEqual([len([r for r in report["refusals"] if r["category"] == name])
                          for name in ("syntax", "target", "mutation")], [56, 5, 3])
        self.assertEqual(len({client.liveness_session_id for client in clients}), 4)

    def test_expired_pair_or_unconfirmed_cleanup_never_retries_or_advances_a_batch(self):
        for options in ({"expired_followup": True}, {"complete_cleanup": False}):
            clients, report, error = self.batch_run(**options)
            self.assertIsInstance(error, (RuntimeError, ValueError))
            self.assertEqual(len(clients), 1)
            self.assertTrue(clients[0].closed)
            self.assertFalse(report["refusal_batches"][0]["passed"])
            self.assertIn("collector_cleanup", report["refusal_batches"][0])

    def test_separate_identity_original_manifest_schema_and_default(self):
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        legacy = INSTALL.registry(manifest)
        selected = INSTALL.registry(manifest, file_revisions=True)
        self.assertEqual(selected["registry_id"], "git-readonly-file-revisions-v1")
        self.assertEqual(legacy["registry_id"], "git-readonly-v1")
        for old, new in zip(legacy["tools"], selected["tools"]):
            if old["name"] in INSTALL.READS:
                self.assertEqual(new["mcp_result_profile"], INSTALL.FILE_READS_FORMAT)
                new["mcp_result_profile"] = INSTALL.FORMAT
            self.assertEqual(old, new)

    def test_classifier_selects_only_exact_upstream_schema_and_file_grammar(self):
        tools = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())["result"]["tools"]
        schema = next(t["inputSchema"] for t in tools if t["name"] == "git_show")
        for value in ("HEAD:notes.txt", "HEAD:docs/機能 notes.txt", "a" * 40 + ":café.txt"):
            event = {"tool_schema": schema, "pinned_schema": schema}
            args = {"repo_path": "/workspace", "revision": value}
            self.assertIs(CLASSIFIER._bounded_git_read("git_show", args, event), True)
            self.assertIs(LEGACY._bounded_git_read("git_show", args, event), False)
            self.assertIs(CLASSIFIER._bounded_git_read("git_show", args, {"tool_schema": {}}), False)
        for value in VERIFY.INVALID:
            self.assertFalse(CLASSIFIER._file_revision(value), repr(value))

    def test_file_capability_does_not_extend_diff_or_named_references(self):
        tools = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())["result"]["tools"]
        schema = next(t["inputSchema"] for t in tools if t["name"] == "git_diff")
        for value in ("HEAD:notes.txt", "refs/heads/main", "refs/heads/main:notes.txt"):
            self.assertIs(CLASSIFIER._bounded_git_read("git_diff", {"repo_path": "/workspace", "target": value}, {"tool_schema": schema}), False)

    def test_combined_registry_capabilities_refuse_before_any_installation(self):
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        names = ("local_references", "file_revisions", "shallow_repository")
        for count in (2, 3):
            for selected in itertools.combinations(names, count):
                options = dict.fromkeys(selected, True)
                with self.subTest(selected=selected):
                    with self.assertRaisesRegex(ValueError, "not qualified"):
                        INSTALL.registry(manifest, **options)
                    with self.assertRaisesRegex(ValueError, "not qualified"):
                        INSTALL.install(Path("unused"), Path("unused"), Path("unused"), "a" * 64,
                                        Path("unused"), Path("unused"), **options)

    def test_cli_refuses_every_combined_selector_before_installation(self):
        flags = ("--local-references", "--file-revisions", "--shallow-repository")
        required = [value for name in ("destination", "workspace", "git", "bwrap", "git-launcher")
                    for value in ("--" + name, "/unused")]
        required += ["--git-sha256", "a" * 64]
        for count in (2, 3):
            for selected in itertools.combinations(flags, count):
                with self.subTest(selected=selected):
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/install-sou68-git-profile.py"),
                                             "--run", *required, *selected], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("not allowed with argument", result.stderr)
