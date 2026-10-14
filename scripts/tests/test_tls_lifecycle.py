# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/fixtures"))
if sys.platform == "linux":
    from tls_edge import Edge, RotationError, atomic_write, private_bytes, validate_material, command


@unittest.skipUnless(sys.platform == "linux" and shutil.which("openssl") and shutil.which("caddy"),
                     "requires the selected Linux TLS runtime")
class TLSLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("tls_drill", ROOT / "scripts/tls-lifecycle.py")
        cls.drill = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.drill)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.file = self.directory / "material"
        atomic_write(self.file, b"test")

    def test_empty_material_is_rejected(self):
        atomic_write(self.file, b"")
        with self.assertRaises(RotationError):
            private_bytes(self.file)

    def test_oversized_material_is_rejected(self):
        atomic_write(self.file, b"x" * 65537)
        with self.assertRaises(RotationError):
            private_bytes(self.file)

    def test_boundary_material_is_readable(self):
        atomic_write(self.file, b"x" * 65536)
        self.assertEqual(len(private_bytes(self.file)), 65536)

    def test_symlink_material_is_rejected(self):
        link = self.directory / "link"
        link.symlink_to(self.file)
        with self.assertRaises(OSError):
            private_bytes(link)

    def test_shared_permissions_are_rejected(self):
        self.file.chmod(0o644)
        with self.assertRaises(RotationError):
            private_bytes(self.file)

    def test_hardlink_material_is_rejected(self):
        os.link(self.file, self.directory / "link")
        with self.assertRaises(RotationError):
            private_bytes(self.file)

    def test_fifo_is_rejected_without_waiting(self):
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(RotationError):
            private_bytes(fifo)

    def test_root_symlink_is_rejected(self):
        link = self.directory / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(RotationError):
            Edge(link, self.file, ROOT / "deploy/Caddyfile.rotation")

    def test_atomic_write_keeps_private_permissions(self):
        atomic_write(self.file, b"replacement")
        self.assertEqual(private_bytes(self.file), b"replacement")
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)

    def make_edge(self):
        ca, ca_key = self.drill.generate_ca(self.directory, "unit-ca")
        first = self.drill.generate_cert(self.directory, "first", ca, ca_key)
        second = self.drill.generate_cert(self.directory, "second", ca, ca_key)
        edge = Edge(self.directory / "edge", ca, ROOT / "deploy/Caddyfile.rotation")
        previous = edge.initialize(*first)
        return edge, first, second, previous

    def test_wrong_key_is_rejected_by_real_validation(self):
        edge, first, second, _ = self.make_edge()
        with self.assertRaisesRegex(RotationError, "do not match"):
            validate_material(first[0], second[1], edge.ca)

    def test_edge_body_bound_matches_gateway(self):
        edge, _, _, _ = self.make_edge()
        config = json.loads(command(["caddy", "adapt", "--config", edge.config,
                                     "--adapter", "caddyfile"], "Caddy adaptation"))
        limits = []

        def visit(value):
            if isinstance(value, dict):
                if value.get("handler") == "request_body":
                    limits.append(value["max_size"])
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(config)
        self.assertEqual(limits, [4194304])

    def test_failed_confirmation_restores_committed_configuration(self):
        edge, _, candidate, previous = self.make_edge()
        before = edge.config.read_bytes()
        with patch.object(edge, "reload"), patch.object(edge, "witness", side_effect=[
                RotationError("wrong served fingerprint"), {"fingerprint_sha256": previous["fingerprint_sha256"]}]):
            with self.assertRaisesRegex(RotationError, "restored and verified"):
                edge.rotate(*candidate)
        self.assertEqual(edge.config.read_bytes(), before)
        self.assertEqual(json.loads(private_bytes(edge.good)), previous)
        self.assertFalse(edge.journal.exists())

    def test_failed_restore_retains_recovery_journal(self):
        edge, _, candidate, _ = self.make_edge()
        before = edge.config.read_bytes()
        with patch.object(edge, "reload", side_effect=RotationError("admin unavailable")):
            with self.assertRaisesRegex(RotationError, "recovery required"):
                edge.rotate(*candidate)
        self.assertTrue(edge.journal.exists())
        self.assertEqual(edge.config.read_bytes(), before)
        with self.assertRaisesRegex(RotationError, "requires recovery"):
            edge.rotate(*candidate)

    def test_recovery_waits_for_verified_handshake(self):
        edge, _, candidate, previous = self.make_edge()
        atomic_write(edge.journal, json.dumps({"previous": previous, "candidate": {}}).encode())
        with patch.object(edge, "reload"), patch.object(edge, "witness", side_effect=RotationError("not verified")):
            with self.assertRaises(RotationError):
                edge.recover()
        self.assertTrue(edge.journal.exists())

    def test_concurrent_rotation_is_rejected(self):
        edge, _, _, _ = self.make_edge()
        other = Edge(edge.root, edge.ca, edge.template)
        with edge.locked(), self.assertRaisesRegex(RotationError, "in progress"):
            with other.locked():
                self.fail("concurrent lock was accepted")


if __name__ == "__main__":
    unittest.main()
