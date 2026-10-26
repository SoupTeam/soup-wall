# SPDX-License-Identifier: Apache-2.0
"""Real subprocess controls for the original-server evidence driver's limits."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location(
    "sou156_confusion", Path(__file__).resolve().parents[1] /
    "reproduce-sou156-git-object-confusion.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


@unittest.skipUnless(os.name == "posix", "owned process-group controls require POSIX")
class CommandBounds(unittest.TestCase):
    def stopped(self, pidfile):
        pid = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_stdout_and_stderr_overflow_stop_live_child_and_allow_followup(self):
        for fd in (1, 2):
            with self.subTest(fd=fd), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                pidfile = root / "owned.pid"
                script = ("import os,sys;from pathlib import Path;"
                          "Path(sys.argv[1]).write_text(str(os.getpid()));"
                          "exec('while True: os.write(" + str(fd) + ",b\"x\"*4096)')")
                before = time.monotonic()
                with self.assertRaisesRegex(ValueError, "byte bound"):
                    DRIVER.command([sys.executable, "-I", "-B", "-c", script, str(pidfile)],
                                   {}, root, timeout=2, limit=8192)
                self.assertLess(time.monotonic() - before, 3)
                self.stopped(pidfile)
                self.assertEqual(DRIVER.command(
                    [sys.executable, "-I", "-B", "-c", "print('subsequent valid read')"],
                    {}, root), b"subsequent valid read\n")

    def test_deadline_stops_silent_live_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pidfile = root / "owned.pid"
            script = ("import os,sys,time;from pathlib import Path;"
                      "Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(10)")
            before = time.monotonic()
            with self.assertRaisesRegex(ValueError, "deadline"):
                DRIVER.command([sys.executable, "-I", "-B", "-c", script, str(pidfile)],
                               {}, root, timeout=0.4)
            self.assertLess(time.monotonic() - before, 3)
            self.stopped(pidfile)

    def test_bounded_duplex_input_drains_both_outputs_without_deadlock(self):
        data = b"owned" * 50_000
        script = ("import sys;data=sys.stdin.buffer.read();"
                  "sys.stderr.buffer.write(b'bounded diagnostic');"
                  "sys.stdout.buffer.write(data)")
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(DRIVER.command([sys.executable, "-I", "-B", "-c", script],
                                            {}, root, data=data), data)


if __name__ == "__main__":
    unittest.main()
