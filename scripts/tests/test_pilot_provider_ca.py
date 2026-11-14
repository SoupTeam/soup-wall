# SPDX-License-Identifier: Apache-2.0
"""Run-scoped provider CA descriptor, material and source-change controls."""
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pilot_provider_ca", ROOT / "scripts/pilot_provider_ca.py")
CA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CA)
CERT = ROOT / "crates/proxy/tests/fixtures/saml/local-idp-cert.pem"


@unittest.skipUnless(sys.platform == "linux", "Linux sealed descriptor required")
class ProviderCA(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "selected-ca.pem"
        self.original = CERT.read_bytes()
        self.source.write_bytes(self.original)
        self.source.chmod(0o600)

    def test_exact_bytes_are_sealed_and_only_explicitly_inherited(self):
        self.assertIsNone(CA.pin(None))
        selected = CA.pin(str(self.source))
        descriptor = selected.fd
        try:
            self.assertEqual(selected.sha256, hashlib.sha256(self.original).hexdigest())
            self.assertEqual(os.fstat(selected.fd).st_nlink, 0)
            self.assertEqual(fcntl.fcntl(selected.fd, fcntl.F_GET_SEALS) & CA.SEALS, CA.SEALS)
            with self.assertRaises(OSError):
                os.write(selected.fd, b"changed")
            selected.verify_source()
            code = 'import os,sys;print(os.read(int(sys.argv[1]),2097153).hex())'
            shared = subprocess.run([sys.executable, '-I', '-c', code, str(selected.fd)],
                                    env={"PATH": "/usr/bin:/bin"}, pass_fds=(selected.fd,),
                                    capture_output=True, check=True, timeout=3)
            self.assertEqual(bytes.fromhex(shared.stdout.decode()), self.original)
            excluded = subprocess.run([sys.executable, '-I', '-c', code, str(selected.fd)],
                                      env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=3)
            self.assertNotEqual(excluded.returncode, 0)
            self.source.write_bytes(b"changed source")
            with self.assertRaisesRegex(CA.Refusal, "provider_ca_source_changed"):
                selected.verify_source()
            os.lseek(selected.fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(selected.fd, len(self.original)), self.original)
        finally:
            selected.close()
            selected.close()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_invalid_material_and_unsafe_sources_refuse_without_snapshot(self):
        self.source.write_bytes(self.original + b"\n" + self.original)
        selected = CA.pin(str(self.source))
        try:
            selected.verify_source()
        finally:
            selected.close()
        for payload in (b"", b"not a certificate", b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
                        self.original + b"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
                        b" " + self.original):
            with self.subTest(payload=payload[:20]):
                self.source.write_bytes(payload)
                with self.assertRaises(CA.Refusal):
                    CA.pin(str(self.source))
        self.source.write_bytes(self.original)
        self.source.chmod(0o666)
        with self.assertRaisesRegex(CA.Refusal, "provider_ca_input_invalid"):
            CA.pin(str(self.source))
        self.source.chmod(0o600)
        link = self.root / "link.pem"
        link.symlink_to(self.source)
        with self.assertRaisesRegex(CA.Refusal, "provider_ca_input_invalid"):
            CA.pin(str(link))
        with self.assertRaisesRegex(CA.Refusal, "provider_ca_input_invalid"):
            CA.pin("relative.pem")
        self.source.write_bytes(self.original * ((CA.MAX_CA_BYTES // len(self.original)) + 1))
        with self.assertRaisesRegex(CA.Refusal, "provider_ca_input_invalid"):
            CA.pin(str(self.source))

    def test_fifo_refuses_promptly_and_replaced_source_is_detected(self):
        fifo = self.root / "fifo.pem"
        os.mkfifo(fifo, 0o600)
        test = ("import importlib.util,sys; s=importlib.util.spec_from_file_location('ca',sys.argv[1]); "
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m); "
                "\ntry: m.pin(sys.argv[2])\nexcept m.Refusal: sys.exit(0)\nsys.exit(1)")
        result = subprocess.run([sys.executable, "-I", "-c", test,
                                 str(ROOT / "scripts/pilot_provider_ca.py"), str(fifo)],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = CA.pin(str(self.source))
        replacement = self.root / "replacement.pem"
        replacement.write_bytes(self.original)
        replacement.chmod(0o600)
        replacement.replace(self.source)
        try:
            with self.assertRaisesRegex(CA.Refusal, "provider_ca_source_changed"):
                selected.verify_source()
        finally:
            selected.close()


if __name__ == "__main__":
    unittest.main()
