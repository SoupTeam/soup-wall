# SPDX-License-Identifier: Apache-2.0
"""Independent listener survival and refusal calibration; not WSL acceptance."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wsl_qualification as WSL


class QualificationControls(unittest.TestCase):
    def test_settings_include_only_presence_and_digests(self):
        with patch.object(WSL.Path, "read_bytes", return_value=b"private setting bytes"):
            observed = WSL.host_settings()
        self.assertEqual(len(observed), 4)
        self.assertTrue(all(len(value) == 64 for value in observed.values()))
        self.assertNotIn("private", str(observed))
        with patch.object(WSL.Path, "read_bytes", side_effect=FileNotFoundError):
            self.assertEqual(set(WSL.host_settings().values()), {"absent"})

    @unittest.skipUnless(sys.platform == "linux", "pass_fds witness requires Linux")
    def test_native_bind_error_and_unrelated_failure_are_distinguished(self):
        for message, expected in (("Address already in use (os error 98)", True),
                                  ("unrelated configuration failure", False)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "candidate"
                binary.write_text("#!/bin/sh\nprintf '%s\\n' '" + message + "' >&2\nexit 1\n")
                binary.chmod(0o700)
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                env = {"PATH": os.defpath}
                if expected:
                    report = WSL.foreign_port(binary, sys.executable, env, root, port)
                    self.assertTrue(report["foreign_process_survived"])
                    self.assertTrue(report["owned_fixture_removed"])
                else:
                    with self.assertRaisesRegex(ValueError, "foreign_port_wrong_refusal"):
                        WSL.foreign_port(binary, sys.executable, env, root, port)
                with socket.socket() as after:
                    after.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    after.bind(("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main()
