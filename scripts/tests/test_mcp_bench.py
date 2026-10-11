# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("mcp_bench", Path(__file__).resolve().parents[1] / "mcp-bench.py")
EVALUATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATE)


class MeasurementTests(unittest.TestCase):
    def test_nearest_rank_preserves_tails(self):
        result = EVALUATE.distribution(list(range(1, 101)))
        self.assertEqual((result["p50_ns"], result["p95_ns"], result["p99_ns"]), (50, 95, 99))
        self.assertEqual(result["mean_ns"], 50.5)

    def test_small_and_signed_paired_samples(self):
        result = EVALUATE.distribution([-5, 10])
        self.assertEqual((result["min_ns"], result["p50_ns"], result["p99_ns"]), (-5, -5, 10))

    def test_invalid_measurements_fail(self):
        for samples in ([], [float("nan")], [float("inf")], [True]):
            with self.assertRaises(ValueError):
                EVALUATE.distribution(samples)

    def test_expected_ask_is_interruption_not_false_block(self):
        rows = [dict(scenario="read", benign=True, expected_outcome="allow", actual_outcome="allow", executed=True),
                dict(scenario="confirmation", benign=True, expected_outcome="ask", actual_outcome="ask", executed=False),
                dict(scenario="false", benign=True, expected_outcome="allow", actual_outcome="deny", executed=False),
                dict(scenario="unsafe", benign=False, expected_outcome="deny", actual_outcome="deny", executed=False)]
        result = EVALUATE.benign_metrics(rows)
        self.assertEqual(result["benign_total"], 3)
        self.assertEqual(result["unexpected_false_blocks"], 1)
        self.assertEqual(result["benign_interruptions"], 2)
        self.assertEqual(result["unexpected_false_block_rate_expected_allow"], 0.5)

    def test_missing_denominator_is_unavailable(self):
        result = EVALUATE.benign_metrics([])
        self.assertIsNone(result["unexpected_false_block_rate_all_benign"])

    def test_sessions_retain_all_samples_below_native_call_cap(self):
        sizes = EVALUATE.session_batches(302, 5)
        self.assertEqual(sum(sizes), 302)
        self.assertEqual(sizes[-1], 2)
        self.assertTrue(all(3 * (size + 5) < 64 for size in sizes))

    def test_invalid_session_warmup_is_rejected(self):
        for count, warmup in ((0, 5), (300, 0), (300, 20)):
            with self.assertRaises(ValueError):
                EVALUATE.session_batches(count, warmup)

    def test_complete_execution_includes_warmup_and_rejects_late_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "executor.jsonl"
            responses = Path(temporary) / "results.jsonl"
            witnesses = [(b"warmup\n", b"warmup result\n"), (b"measured\n", b"measured result\n")]
            ledger.write_bytes(b"warmup\nmeasured\n")
            responses.write_bytes(b"warmup result\nmeasured result\n")
            EVALUATE.verify_complete_execution(ledger, responses, witnesses)
            ledger.write_bytes(ledger.read_bytes() + b"late forbidden call\n")
            with self.assertRaisesRegex(RuntimeError, "post-stop executor"):
                EVALUATE.verify_complete_execution(ledger, responses, witnesses)

    def test_complete_execution_rejects_missing_and_late_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "executor.jsonl"
            responses = Path(temporary) / "results.jsonl"
            witnesses = [(b"call\n", b"result\n")]
            ledger.write_bytes(b"call\n")
            for data in (b"", b"changed\n", b"result\nlate result\n"):
                responses.write_bytes(data)
                with self.assertRaisesRegex(RuntimeError, "post-stop server result"):
                    EVALUATE.verify_complete_execution(ledger, responses, witnesses)

    def test_complete_execution_accounts_for_initialization_without_ignoring_extra_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "executor.jsonl"
            responses = Path(temporary) / "results.jsonl"
            witnesses = [(b"call\n", b"result\n")]
            initialization = [b"initialize result\n", b"tools list result\n"]
            ledger.write_bytes(b"call\n")
            responses.write_bytes(b"".join(initialization) + b"result\n")
            EVALUATE.verify_complete_execution(ledger, responses, witnesses, initialization)
            responses.write_bytes(responses.read_bytes() + initialization[0])
            with self.assertRaisesRegex(RuntimeError, "post-stop server result"):
                EVALUATE.verify_complete_execution(ledger, responses, witnesses, initialization)


if __name__ == "__main__":
    unittest.main()
