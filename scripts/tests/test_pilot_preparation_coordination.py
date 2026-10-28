# SPDX-License-Identifier: Apache-2.0
"""Real-process coordination controls with explicitly simulated compilation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

WORKER = Path(__file__).resolve().parent / "fixtures/preparation_concurrency_worker.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "descriptor locks require Linux")
class PreparationConcurrency(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "git.tar.xz").write_bytes(b"simulated git archive")
        (self.root / "bwrap.tar.xz").write_bytes(b"simulated bwrap archive")
        self.processes = []
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def start(self, kind, output, witness, *, gate=None, identity="a", operation="build",
              wait=0, failure="ok", start_gate=None, ready=None, contended=None):
        command = [sys.executable, "-B", str(WORKER), kind, str(output), str(witness),
                   str(gate) if gate else "-", identity, operation, str(wait), failure]
        if start_gate is not None:
            command.extend((str(start_gate), str(ready)))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env={**os.environ,
                                                   **({"SIMULATED_CONTENDED_WITNESS": str(contended)}
                                                      if contended else {})})
        self.processes.append(process)
        return process

    def finished(self, process, expected_code=0):
        stdout, stderr = process.communicate(timeout=12)
        self.assertEqual(process.returncode, expected_code, stderr)
        self.assertEqual(len(stdout.splitlines()), 1, stdout)
        return json.loads(stdout)

    def witness_count(self, witness, expected):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if witness.exists() and len(witness.read_text().splitlines()) >= expected:
                return
            time.sleep(0.02)
        self.fail("simulated build did not reach its independent witness")

    def test_same_input_wait_reuses_one_completed_generation(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-same")
                witness = self.root / (kind + "-same-invocations")
                gate = self.root / (kind + "-release")
                blocked = self.root / (kind + "-contended")
                owner = self.start(kind, output, witness, gate=gate)
                self.witness_count(witness, 1)
                waiter = self.start(kind, output, witness, wait=5, contended=blocked)
                self.witness_count(blocked, 1)
                self.assertIsNone(waiter.poll())
                self.assertEqual(len(witness.read_text().splitlines()), 1)
                gate.touch()
                built = self.finished(owner)
                reused = self.finished(waiter)
                self.assertIn(built["status"], ("prepared-not-qualified", "built-not-qualified"))
                self.assertEqual(reused["status"], "reused")
                self.assertTrue(reused["contended"])
                self.assertEqual(reused["receipt"], built["receipt"])
                self.assertEqual(len(witness.read_text().splitlines()), 1,
                                 "two callers must invoke the simulated compiler only once")
                self.assertFalse(reused["active_protection"])

    def test_simultaneous_first_creation_selects_only_one_generation(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-simultaneous")
                witness = self.root / (kind + "-simultaneous-invocations")
                start_gate = self.root / (kind + "-simultaneous-start")
                ready = self.root / (kind + "-simultaneous-ready")
                first = self.start(kind, output, witness, wait=5,
                                   start_gate=start_gate, ready=ready)
                second = self.start(kind, output, witness, wait=5,
                                    start_gate=start_gate, ready=ready)
                self.witness_count(ready, 2)
                self.assertFalse(output.exists(), "both processes must start before mkdir")
                start_gate.touch()
                reports = [self.finished(first), self.finished(second)]
                self.assertEqual(sum(row["status"] == "reused" for row in reports), 1)
                self.assertEqual(len(witness.read_text().splitlines()), 1)
                self.assertEqual(len(list((output / "generations").iterdir())), 1)

    def test_default_busy_and_bounded_wait_expiration(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-busy")
                witness = self.root / (kind + "-busy-invocations")
                gate = self.root / (kind + "-busy-release")
                owner = self.start(kind, output, witness, gate=gate)
                self.witness_count(witness, 1)
                busy = self.finished(self.start(kind, output, witness), 3)
                self.assertEqual((busy["status"], busy["reason"]),
                                 ("busy", "preparation_in_progress"))
                expired = self.finished(self.start(kind, output, witness, wait=0.2), 3)
                self.assertEqual(expired["reason"], "bounded_wait_expired")
                self.assertEqual(len(witness.read_text().splitlines()), 1)
                gate.touch()
                self.finished(owner)

    def test_nonfinite_and_out_of_range_wait_never_creates_output(self):
        for kind in ("source", "native"):
            for wait in ("nan", "inf", "-1", "2701"):
                with self.subTest(kind=kind, wait=wait):
                    output = self.root / (kind + "-invalid-" + wait)
                    witness = self.root / (kind + "-invalid-invocations")
                    refused = self.finished(self.start(kind, output, witness, wait=wait), 2)
                    self.assertEqual(refused["reason"], "wait_seconds_out_of_bounds")
                    self.assertFalse(output.exists())
                    self.assertFalse(witness.exists())

    def test_different_input_refuses_reuse_then_explicit_rebuilds(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-identity")
                witness = self.root / (kind + "-identity-invocations")
                self.finished(self.start(kind, output, witness))
                previous = (output / "current.json").read_bytes()
                refused = self.finished(self.start(kind, output, witness, identity="b"), 2)
                self.assertEqual(refused["status"], "failed")
                self.assertIn("receipt_identity_changed", refused["reason"])
                self.assertEqual((output / "current.json").read_bytes(), previous)
                self.assertEqual(len(witness.read_text().splitlines()), 1)
                rebuilt = self.finished(self.start(kind, output, witness, identity="b",
                                                 operation="rebuild"))
                self.assertIn(rebuilt["status"], ("prepared-not-qualified", "built-not-qualified"))
                self.assertNotEqual((output / "current.json").read_bytes(), previous)
                self.assertEqual(len(witness.read_text().splitlines()), 2)

    def test_waiting_different_input_rechecks_owner_result(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-waiting-drift")
                witness = self.root / (kind + "-waiting-drift-invocations")
                gate = self.root / (kind + "-waiting-drift-release")
                owner = self.start(kind, output, witness, gate=gate)
                self.witness_count(witness, 1)
                waiter = self.start(kind, output, witness, identity="b", wait=5)
                time.sleep(0.2)
                self.assertIsNone(waiter.poll())
                gate.touch()
                built = self.finished(owner)
                refused = self.finished(waiter, 2)
                self.assertEqual(refused["status"], "failed")
                self.assertIn("receipt_identity_changed", refused["reason"])
                self.assertEqual((output / "current.json").exists(), True)
                self.assertEqual(len(witness.read_text().splitlines()), 1)
                self.assertEqual(self.finished(self.start(kind, output, witness))["receipt"],
                                 built["receipt"])

    def test_failed_rebuild_and_killed_first_owner_preserve_selection(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-failure")
                witness = self.root / (kind + "-failure-invocations")
                self.finished(self.start(kind, output, witness))
                marker = (output / "current.json").read_bytes()
                unrelated = self.root / (kind + "-unrelated")
                unrelated.write_text("keep")
                failed = self.finished(self.start(kind, output, witness, operation="rebuild",
                                                  failure="fail"), 2)
                self.assertEqual(failed["status"], "failed")
                self.assertEqual((output / "current.json").read_bytes(), marker)
                self.assertEqual(unrelated.read_text(), "keep")
                self.assertEqual(self.finished(self.start(kind, output, witness))["status"], "reused")

                fresh = self.root / (kind + "-killed")
                fresh_witness = self.root / (kind + "-killed-invocations")
                gate = self.root / (kind + "-killed-release")
                owner = self.start(kind, fresh, fresh_witness, gate=gate)
                self.witness_count(fresh_witness, 1)
                owner.kill()
                owner.communicate(timeout=5)
                self.assertFalse((fresh / "current.json").exists())
                recovered = self.finished(self.start(kind, fresh, fresh_witness))
                self.assertGreaterEqual(recovered["retained_interrupted_generations"], 1)
                self.assertEqual(len(fresh_witness.read_text().splitlines()), 2)
                self.assertTrue((fresh / "current.json").exists())

    def test_cancelled_waiter_does_not_build_or_hold_the_owner_lock(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-cancel")
                witness = self.root / (kind + "-cancel-invocations")
                gate = self.root / (kind + "-cancel-release")
                owner = self.start(kind, output, witness, gate=gate)
                self.witness_count(witness, 1)
                waiter = self.start(kind, output, witness, wait=10)
                time.sleep(0.2)
                self.assertIsNone(waiter.poll())
                waiter.send_signal(signal.SIGTERM)
                waiter.communicate(timeout=5)
                self.assertNotEqual(waiter.returncode, 0)
                gate.touch()
                self.finished(owner)
                self.assertEqual(self.finished(self.start(kind, output, witness))["status"], "reused")
                self.assertEqual(len(witness.read_text().splitlines()), 1)

    def test_replaced_lock_name_refuses_publication(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                output = self.root / (kind + "-replaced-lock")
                witness = self.root / (kind + "-replaced-lock-invocations")
                gate = self.root / (kind + "-replaced-lock-release")
                owner = self.start(kind, output, witness, gate=gate)
                self.witness_count(witness, 1)
                lock = output / ".pilot-input-preparation.lock"
                lock.rename(output / ".displaced-lock-evidence")
                gate.touch()
                failed = self.finished(owner, 2)
                self.assertIn("preparation_lock_changed", failed["reason"])
                self.assertFalse((output / "current.json").exists())
                recovered = self.finished(self.start(kind, output, witness))
                self.assertGreaterEqual(recovered["retained_interrupted_generations"], 1)

    def test_unsafe_lock_records_and_alias_do_not_start_build(self):
        for kind in ("source", "native"):
            for record in ("symlink", "hardlink", "fifo"):
                with self.subTest(kind=kind, record=record):
                    output = self.root / (kind + "-" + record)
                    output.mkdir(mode=0o700)
                    witness = self.root / (kind + "-" + record + "-invocations")
                    lock = output / ".pilot-input-preparation.lock"
                    target = self.root / (kind + "-" + record + "-target")
                    target.write_bytes(b"")
                    target.chmod(0o600)
                    if record == "symlink":
                        lock.symlink_to(target)
                    elif record == "hardlink":
                        os.link(target, lock)
                    else:
                        os.mkfifo(lock, 0o600)
                    refused = self.finished(self.start(kind, output, witness), 2)
                    self.assertEqual(refused["status"], "failed")
                    self.assertIn("preparation_lock", refused["reason"])
                    self.assertFalse(witness.exists())

            original = self.root / (kind + "-canonical")
            original.mkdir(mode=0o700)
            alias = self.root / (kind + "-alias")
            alias.symlink_to(original, target_is_directory=True)
            refused = self.finished(self.start(kind, alias,
                                                self.root / (kind + "-alias-invocations")), 2)
            self.assertEqual(refused["status"], "failed")
            self.assertFalse((self.root / (kind + "-alias-invocations")).exists())

    def test_unrelated_live_builder_uses_independent_root(self):
        for kind in ("source", "native"):
            with self.subTest(kind=kind):
                held = self.root / (kind + "-held")
                free = self.root / (kind + "-free")
                held_witness = self.root / (kind + "-held-invocations")
                free_witness = self.root / (kind + "-free-invocations")
                gate = self.root / (kind + "-held-release")
                owner = self.start(kind, held, held_witness, gate=gate)
                self.witness_count(held_witness, 1)
                other = self.finished(self.start(kind, free, free_witness))
                self.assertIn(other["status"], ("prepared-not-qualified", "built-not-qualified"))
                self.assertEqual(len(free_witness.read_text().splitlines()), 1)
                self.assertIsNone(owner.poll())
                gate.touch()
                self.finished(owner)


if __name__ == "__main__":
    unittest.main()
