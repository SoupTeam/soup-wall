# SPDX-License-Identifier: Apache-2.0
"""Large-result driver controls: budget binding, fixture arithmetic and grading.

Public synthetic checks only; Linux original-server coverage is the driver run.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("large_results", ROOT / "scripts/verify-large-results.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

LABELS = ["b16383", "b16384", "b16385", "k20", "k60", "k120", "t-below", "t-at", "u-at", "escaped",
          "f-below", "f-at", "multi-3x20k", "t-above", "u-above", "multi-20x20k", "f-above",
          "m2-oversized", "inject-large"]


def server_frame(identifier, text):
    """The original server's frame shape: both channels carry the same text."""
    value = {"result": {"content": [{"type": "text", "text": text}], "structuredContent": {"content": text}},
             "jsonrpc": "2.0", "id": identifier}
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


class BudgetControls(unittest.TestCase):
    def test_driver_is_bound_to_the_reviewed_source_constants(self):
        budgets = M.budgets()
        self.assertEqual(budgets["text_bytes"], 262_144)
        self.assertEqual(budgets["frame_bytes"], 1_048_576)
        self.assertIn("262144-byte per-result budget", budgets["text_message"])
        self.assertIn("1048576-byte envelope budget", budgets["frame_message"])

    def test_frame_fixtures_hit_the_envelope_exactly(self):
        probe = 9000
        overhead = len(server_frame(probe, '"')) - 4 - len(str(probe))
        frame = M.budgets()["frame_bytes"]
        for target in (frame - 1, frame, frame + 1):
            identifier = next(i for i in range(20000, 200000) if (target - overhead - len(str(i))) % 2 == 0)
            text = M.frame_text(target, overhead, identifier).decode()
            self.assertEqual(len(server_frame(identifier, text)), target)
            self.assertLessEqual(len(text.encode()), M.budgets()["text_bytes"])

    def test_text_fixtures_have_exact_sizes_and_valid_utf8(self):
        for size in (16_383, 16_384, 16_385, 262_143, 262_144, 262_145):
            self.assertEqual(len(M.lines(size)), size)
        text = M.escaped(120 * 1024)
        text.decode("utf-8")
        self.assertLessEqual(len(text), 120 * 1024)
        self.assertGreater(len(text), 120 * 1024 - 4)
        for needle in ('"', "\\", "\t", "\x01", "日本語", "🥣"):
            self.assertIn(needle, text.decode())


class GradeControls(unittest.TestCase):
    def fixture(self):
        source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False}
        phase = lambda labels: {
            "cases": [{"case": label, "passed": True} for label in labels],
            "client": {"exit_code": 0, "forced_cleanup": False,
                       "process_cleanup": {"all_stopped": True, "descendant_count": 3}},
            "daemon_cleanup": {"all_stopped": True}, "daemon_exit_code": -15,
            "cleanup_audit": {"cleanup_verified": True},
            "memory_after_initialize": {"vm_rss_kib": 30_000, "vm_hwm_kib": 30_000},
            "memory_final": {"vm_rss_kib": 39_000, "vm_hwm_kib": 39_000}}
        return {"source_before": source, "source_after": dict(source), "source_files_before": {"f": "c" * 64},
                "source_files_after": {"f": "c" * 64}, "skipped": 0, "workspace_before": {"w": 1},
                "workspace_after": {"w": 1}, "workspace_final": {"w": 1},
                "phases": {"main": phase(LABELS), "record-capped": phase(["capped-k60", "capped-k120"])},
                "actual_claude_host": {"status": "pass"}}

    def test_rejects_failed_missing_or_unbounded_evidence(self):
        valid = self.fixture()
        M.grade(copy.deepcopy(valid))
        mutations = [
            lambda r: r["phases"]["main"]["cases"].pop(),
            lambda r: r["phases"]["main"]["cases"][3].update(passed=False),
            lambda r: r["phases"]["record-capped"]["cases"].clear(),
            lambda r: r.update(workspace_after={"w": 2}),
            lambda r: r.update(skipped=1),
            lambda r: r["source_files_after"].update(f="d" * 64),
            lambda r: r["phases"]["main"]["client"].update(forced_cleanup=True),
            lambda r: r["phases"]["main"]["daemon_cleanup"].update(all_stopped=False),
            lambda r: r["phases"]["main"]["cleanup_audit"].update(cleanup_verified=False),
            lambda r: r["phases"]["main"]["memory_final"].update(vm_hwm_kib=30_000 + 97 * 1024),
            lambda r: r["actual_claude_host"].update(status="incomplete"),
        ]
        for mutate in mutations:
            report = copy.deepcopy(valid)
            mutate(report)
            with self.assertRaises(ValueError):
                M.grade(report)


if __name__ == "__main__":
    unittest.main()
