"""Finite private cache exchange and fail-closed publication controls."""
from __future__ import annotations

import hashlib
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_preparation_lock as coordination
import pilot_prerequisite_cache_exchange as exchange


class Exchange(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.target = self.base / "target"
        self.source.mkdir(mode=0o700)
        self.target.mkdir(mode=0o700)
        self.data = {"git": b"git original source\n" * 101,
                     "bwrap": b"bubblewrap original source\n" * 47}
        self.pins = {kind: ("1.0", kind + "-1.0", "https://example.invalid/" + kind,
                            hashlib.sha256(value).hexdigest(), 8192)
                     for kind, value in self.data.items()}
        self.inputs = {}
        for kind, value in self.data.items():
            path = self.base / (kind + ".tar.xz")
            path.write_bytes(value)
            path.chmod(0o644)  # Accepted public source archive, copied privately.
            self.inputs[kind] = path
        with coordination.hold(self.source) as claim:
            exchange.seed(self.source, self.inputs, self.pins, claim)
        self.bundle = self.base / "transfer.tar"

    def exported(self):
        with coordination.hold(self.source) as claim:
            return exchange.export(self.source, self.bundle, self.pins, claim)

    def imported(self, *, pins=None):
        with coordination.hold(self.target) as claim:
            return exchange.import_bundle(self.target, self.bundle, pins or self.pins, claim)

    def test_export_transfer_import_and_offline_consume_are_exact(self):
        before = exchange.preview(self.source, self.pins)
        self.assertTrue(before["complete"])
        self.assertEqual(before["executed"], False)
        self.assertEqual(self.exported()["status"], "exported")
        self.assertEqual(self.bundle.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.imported()["status"], "imported-not-prepared")
        self.assertTrue(exchange.preview(self.target, self.pins)["complete"])
        transferred = self.base / "transfer-again.tar"
        with coordination.hold(self.target) as claim:
            exchange.export(self.target, transferred, self.pins, claim)
        self.assertEqual(transferred.read_bytes(), self.bundle.read_bytes())
        with coordination.hold(self.target) as claim:
            for kind in self.data:
                destination = self.target / (kind + ".tar.xz")
                exchange.consume(self.target, destination, kind, self.pins, claim)
                self.assertEqual(destination.read_bytes(), self.data[kind])
        self.assertFalse((self.target / "current.json").exists())
        self.assertEqual(sorted(p.name for p in self.target.iterdir()),
                         [coordination.NAME, "bwrap.tar.xz", "download-cache", "git.tar.xz"])

    def test_export_is_create_new_and_rejects_corrupt_or_partial_cache(self):
        self.exported()
        with coordination.hold(self.source) as claim:
            with self.assertRaises(exchange.Refusal):
                exchange.export(self.source, self.bundle, self.pins, claim)
        self.bundle.unlink()
        (self.source / "download-cache" / exchange.GIT).write_bytes(b"wrong")
        with self.assertRaises(exchange.Refusal):
            self.exported()
        self.assertFalse(self.bundle.exists())

    def test_export_publication_ignores_replaced_named_temporary(self):
        original = exchange._link_inode
        for substitution in ("regular", "symlink"):
            with self.subTest(substitution=substitution):
                canary = self.base / ("canary-" + substitution)
                canary.write_bytes(b"unrelated owned canary")
                canary.chmod(0o600)
                replacement = self.base / (".exchange-" + substitution)

                def at_publication(source_fd, directory_fd, name):
                    self.assertEqual(name, self.bundle.name)
                    self.assertEqual(os.fstat(source_fd).st_nlink, 0)
                    self.assertFalse(any(p.name.startswith(".exchange-") for p in self.base.iterdir()))
                    if substitution == "regular":
                        replacement.write_bytes(b"substituted regular file")
                    else:
                        replacement.symlink_to(canary)
                    original(source_fd, directory_fd, name)

                with mock.patch.object(exchange, "_link_inode", side_effect=at_publication):
                    self.assertEqual(self.exported()["status"], "exported")
                self.assertEqual(canary.read_bytes(), b"unrelated owned canary")
                self.assertTrue(replacement.is_symlink() if substitution == "symlink" else replacement.is_file())
                self.assertEqual(self.imported()["status"], "imported-not-prepared")
                self.bundle.unlink()
                replacement.unlink()
                # The selected target cannot be imported twice; use a fresh root.
                self.target = self.base / ("target-" + substitution)
                self.target.mkdir(mode=0o700)

    def test_old_named_link_substitution_cannot_reach_export_or_seed(self):
        # The old implementation called os.link after closing its named stage.
        # This hook replaces exactly that path. Before the fix export would
        # publish the substitute and report success; seed had the same gap.
        real_link = os.link
        canary = self.base / "link-canary"
        canary.write_bytes(b"unrelated bytes")
        canary.chmod(0o600)
        interceptions = []

        def replace_then_link(source, destination, *args, **kwargs):
            interceptions.append(str(source))
            Path(source).unlink()
            Path(source).symlink_to(canary)
            return real_link(source, destination, *args, **kwargs)

        fresh = self.base / "old-link-fresh"
        fresh.mkdir(mode=0o700)
        with mock.patch.object(os, "link", side_effect=replace_then_link):
            self.exported()
            with coordination.hold(fresh) as claim:
                exchange.seed(fresh, self.inputs, self.pins, claim)
        self.assertEqual(interceptions, [])
        self.assertEqual(canary.read_bytes(), b"unrelated bytes")
        self.assertTrue(exchange.preview(fresh, self.pins)["complete"])
        self.assertEqual(self.imported()["status"], "imported-not-prepared")

    def test_existing_destination_at_publication_is_preserved(self):
        original = exchange._link_inode
        for destination_type in ("regular", "symlink"):
            with self.subTest(destination_type=destination_type):
                canary = self.base / ("existing-canary-" + destination_type)
                canary.write_bytes(b"keep this object")
                canary.chmod(0o600)

                def occupy(source_fd, directory_fd, name):
                    if destination_type == "regular":
                        self.bundle.write_bytes(b"preexisting")
                    else:
                        self.bundle.symlink_to(canary)
                    original(source_fd, directory_fd, name)

                with mock.patch.object(exchange, "_link_inode", side_effect=occupy):
                    with self.assertRaisesRegex(exchange.Refusal, "exchange_destination_exists"):
                        self.exported()
                if destination_type == "regular":
                    self.assertEqual(self.bundle.read_bytes(), b"preexisting")
                else:
                    self.assertTrue(self.bundle.is_symlink())
                    self.assertEqual(canary.read_bytes(), b"keep this object")
                self.bundle.unlink()

    def test_unsupported_unnamed_file_refuses_without_named_fallback(self):
        real_open = os.open

        def unsupported(path, flags, *args, **kwargs):
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError(errno.EOPNOTSUPP, "fixture unsupported unnamed file")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=unsupported):
            with self.assertRaisesRegex(exchange.Refusal, "exchange_filesystem_unsupported"):
                self.exported()
        self.assertFalse(self.bundle.exists())
        self.assertFalse(any(p.name.startswith(".exchange-") for p in self.base.iterdir()))

    def test_seed_and_selection_publish_pinned_inodes(self):
        fresh = self.base / "fresh"
        fresh.mkdir(mode=0o700)
        original = exchange._link_inode
        published = []

        def observe(source_fd, directory_fd, name):
            self.assertEqual(os.fstat(source_fd).st_nlink, 0)
            published.append(name)
            original(source_fd, directory_fd, name)

        with mock.patch.object(exchange, "_link_inode", side_effect=observe):
            with coordination.hold(fresh) as claim:
                exchange.seed(fresh, self.inputs, self.pins, claim)
            self.exported()
            self.imported()
        self.assertEqual(set(published), {exchange.GIT, exchange.resume.VERIFIED,
                                          self.bundle.name, exchange.SELECTED})
        self.assertTrue(exchange.preview(fresh, self.pins)["complete"])
        self.assertTrue(exchange.preview(self.target, self.pins)["complete"])

    def test_seed_and_selection_preserve_destination_occupied_at_link(self):
        original = exchange._link_inode
        fresh = self.base / "occupied-seed"
        fresh.mkdir(mode=0o700)

        def occupy_seed(source_fd, directory_fd, name):
            if name == exchange.GIT:
                (fresh / "download-cache" / name).write_bytes(b"preexisting seed")
            original(source_fd, directory_fd, name)

        with mock.patch.object(exchange, "_link_inode", side_effect=occupy_seed):
            with coordination.hold(fresh) as claim:
                with self.assertRaisesRegex(exchange.Refusal, "exchange_destination_exists"):
                    exchange.seed(fresh, self.inputs, self.pins, claim)
        self.assertEqual((fresh / "download-cache" / exchange.GIT).read_bytes(),
                         b"preexisting seed")

        self.exported()
        selection = self.target / "download-cache" / exchange.SELECTED

        def occupy_selection(source_fd, directory_fd, name):
            if name == exchange.SELECTED:
                selection.write_bytes(b"preexisting selection")
            original(source_fd, directory_fd, name)

        with mock.patch.object(exchange, "_link_inode", side_effect=occupy_selection):
            with self.assertRaisesRegex(exchange.Refusal, "exchange_destination_exists"):
                self.imported()
        self.assertEqual(selection.read_bytes(), b"preexisting selection")
        self.assertFalse(exchange.preview(self.target, self.pins)["complete"])

    def test_substituted_stage_before_selection_never_reports_success(self):
        self.exported()
        original = exchange._link_inode

        def change_stage(source_fd, directory_fd, name):
            if name == exchange.SELECTED:
                archive = self.target / "download-cache" / exchange.IMPORTED / exchange.GIT
                archive.write_bytes(b"unverified substitute")
            original(source_fd, directory_fd, name)

        with mock.patch.object(exchange, "_link_inode", side_effect=change_stage):
            with self.assertRaisesRegex(exchange.Refusal, "exchange_member_digest_mismatch"):
                self.imported()
        self.assertFalse(exchange.preview(self.target, self.pins)["complete"])

    def test_import_refuses_changed_pin_and_corrupt_member_without_selection(self):
        self.exported()
        stale = dict(self.pins)
        row = self.pins["git"]
        stale["git"] = (*row[:3], "0" * 64, row[4])
        with self.assertRaises(exchange.Refusal):
            self.imported(pins=stale)
        self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())
        data = bytearray(self.bundle.read_bytes())
        data[data.index(self.data["git"])] ^= 1
        self.bundle.write_bytes(data)
        with self.assertRaises(exchange.Refusal):
            self.imported()
        self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())

    def test_missing_extra_duplicate_traversal_and_link_members_refuse(self):
        self.exported()
        original = self.bundle.read_bytes()
        with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as tar:
            members = [(member, tar.extractfile(member).read()) for member in tar]
        for mutation in ("missing", "extra", "duplicate", "traversal", "link"):
            with self.subTest(mutation=mutation):
                self.bundle.unlink()
                with tarfile.open(self.bundle, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                    chosen = members[:-1] if mutation == "missing" else members
                    for index, (original_member, content) in enumerate(chosen):
                        member = tarfile.TarInfo("../bad" if mutation == "traversal" and index == 1 else original_member.name)
                        member.size = len(content)
                        if mutation == "link" and index == 1:
                            member.type = tarfile.SYMTYPE
                            member.linkname = "/tmp/bad"
                            member.size = 0
                        tar.addfile(member, io.BytesIO(content) if member.isreg() else None)
                    if mutation in {"extra", "duplicate"}:
                        member = tarfile.TarInfo("extra" if mutation == "extra" else "git.tar.xz")
                        member.size = 1
                        tar.addfile(member, io.BytesIO(b"x"))
                self.bundle.chmod(0o600)
                with self.assertRaises(exchange.Refusal):
                    self.imported()
                self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())

    def test_interrupted_second_pass_cannot_publish_selected_cache(self):
        self.exported()
        original = exchange._inspect_bundle
        attempts = 0

        def interrupted(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise exchange.Refusal("fixture_interrupted")
            return original(*args, **kwargs)

        with mock.patch.object(exchange, "_inspect_bundle", side_effect=interrupted):
            with self.assertRaises(exchange.Refusal):
                self.imported()
        self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())
        # A killed copier can leave an empty owner-private member.
        stage = self.target / "download-cache" / exchange.IMPORTED
        stage.mkdir(mode=0o700, exist_ok=True)
        partial = stage / exchange.GIT
        partial.write_bytes(b"")
        partial.chmod(0o600)
        self.assertEqual(self.imported()["status"], "imported-not-prepared")
        self.assertTrue(exchange.preview(self.target, self.pins)["complete"])

    def test_unsafe_destination_and_sibling_preservation(self):
        self.exported()
        sibling = self.target / "unrelated"
        sibling.write_text("retain")
        self.imported()
        self.assertEqual(sibling.read_text(), "retain")
        with self.assertRaises(exchange.Refusal):
            self.imported()  # No overwrite of selected import.
        self.assertEqual(sibling.read_text(), "retain")

    def test_import_refuses_root_with_already_selected_generation(self):
        self.exported()
        marker = self.target / "current.json"
        marker.write_text("existing selection")
        marker.chmod(0o600)
        with self.assertRaisesRegex(exchange.Refusal, "exchange_destination_not_fresh"):
            self.imported()
        self.assertEqual(marker.read_text(), "existing selection")
        self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())

    def test_stale_imported_member_blocks_both_offline_inputs(self):
        self.exported()
        self.imported()
        changed = self.target / "download-cache" / exchange.IMPORTED / exchange.GIT
        changed.write_bytes(b"changed after selection")
        self.assertFalse(exchange.preview(self.target, self.pins)["complete"])
        with coordination.hold(self.target) as claim:
            with self.assertRaisesRegex(exchange.Refusal, "exchange_member_digest_mismatch"):
                exchange.consume(self.target, self.target / "bwrap.tar.xz", "bwrap", self.pins, claim)
        self.assertFalse((self.target / "bwrap.tar.xz").exists())

    def test_unsafe_interrupted_stage_is_preserved_and_blocks_retry(self):
        self.exported()
        stage = self.target / "download-cache" / exchange.IMPORTED
        stage.parent.mkdir(mode=0o700)
        stage.mkdir(mode=0o700)
        unrelated = self.base / "unrelated"
        unrelated.write_bytes(b"retain")
        (stage / exchange.GIT).symlink_to(unrelated)
        with self.assertRaisesRegex(exchange.Refusal, "exchange_incomplete_stage_unsafe"):
            self.imported()
        self.assertEqual(unrelated.read_bytes(), b"retain")
        self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())

    def test_bundle_link_mode_and_compression_refuse_before_import(self):
        self.exported()
        self.bundle.chmod(0o644)
        with self.assertRaises(exchange.Refusal):
            self.imported()
        self.bundle.chmod(0o600)
        hardlink = self.base / "hardlink.tar"
        os.link(self.bundle, hardlink)
        with self.assertRaises(exchange.Refusal):
            self.imported()
        hardlink.unlink()
        self.bundle.unlink()
        with tarfile.open(self.bundle, mode="w:gz") as tar:
            entry = tarfile.TarInfo("manifest.json")
            entry.size = 1
            tar.addfile(entry, io.BytesIO(b"x"))
        self.bundle.chmod(0o600)
        with self.assertRaises((exchange.Refusal, tarfile.TarError)):
            self.imported()
        self.assertFalse((self.target / "download-cache" / exchange.SELECTED).exists())

    @unittest.skipUnless(os.name == "posix", "owned process lock requires Linux")
    def test_real_process_contention_and_owner_death(self):
        self.exported()
        ready = self.base / "owner-ready"
        child = subprocess.Popen([sys.executable, "-c",
            "import pathlib,sys,time\n"
            "sys.path.insert(0,sys.argv[3])\n"
            "import pilot_preparation_lock as p\n"
            "with p.hold(pathlib.Path(sys.argv[1])):\n"
            "    pathlib.Path(sys.argv[2]).write_text('ready')\n"
            "    time.sleep(30)\n",
            str(self.target), str(ready), str(Path(exchange.__file__).parent)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline and child.poll() is None:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "independent lock owner never started")
            with self.assertRaises(coordination.Busy):
                with coordination.hold(self.target, wait_seconds=0) as claim:
                    exchange.import_bundle(self.target, self.bundle, self.pins, claim)
        finally:
            child.kill()
            child.wait(timeout=3)
        self.assertEqual(self.imported()["status"], "imported-not-prepared")


if __name__ == "__main__":
    unittest.main()
