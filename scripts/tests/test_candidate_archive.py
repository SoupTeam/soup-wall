# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import candidate_archive as archive


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class CandidateArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {name: b"fixture" for name in archive.REQUIRED}
        self.files["npm-cache/_cacache/content-v2/sha512/entry"] = b"fixture-cache"
        notices = []
        for component in ("server", "sdk", "node"):
            path = "upstream-notices/" + component + "-LICENSE"
            self.files[archive.PROFILE + path] = component.encode()
            notices.append({"component": component, "path": path, "sha256": digest(component.encode())})
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/example": {
            "name": "example", "version": "1.0", "integrity": "sha512-fixture"}}}
        self.files[archive.PROFILE + "package-lock.json"] = json.dumps(lock).encode()
        self.files[archive.PROFILE + "upstream-identity.json"] = json.dumps({
            "format": "sw-mcp/filesystem-readonly-upstream/1", "upstreamNotices": notices,
            "packageLockSha256": digest(self.files[archive.PROFILE + "package-lock.json"])}).encode()
        notice = "upstream-notices/npm/node_modules/example/LICENSE"
        self.files[notice] = b"example license"
        self.files["npm-inventory.json"] = json.dumps({"format": "sw-candidate-npm-inventory/1",
            "lock_sha256": digest(self.files[archive.PROFILE + "package-lock.json"]), "packages": [{
                "lock_path": "node_modules/example", "version": "1.0", "integrity": "sha512-fixture",
                "notices": {notice: digest(self.files[notice])}}]}).encode()
        # Tiny archive fixtures test parser behavior. Native integration uses the
        # real independently pinned Node/bubblewrap archives without this patch.
        pins = {path: digest(self.files[path]) for path in archive.ARCHIVE_PINS}
        self.patch = patch.object(archive, "ARCHIVE_PINS", pins)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def pack(self, files=None, edit=None, extras=()):
        files = self.files if files is None else files
        manifest = {"schema_version": 2, "identities": {"compiler": "rustc 1.94.1 (fixture)",
            "source_commit": "a" * 40, "cargo_lock_sha256": digest(files["Cargo.lock"])},
            "files": {name: digest(data) for name, data in files.items()}}
        if edit:
            edit(manifest)
        path = self.root / "candidate.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, data in {**files, "manifest.json": json.dumps(manifest).encode()}.items():
                member = tarfile.TarInfo(archive.ROOT + "/" + name)
                member.size, member.mode = len(data), 0o755 if name.startswith("bin/") else 0o600
                tar.addfile(member, io.BytesIO(data))
            for member in extras:
                tar.addfile(member)
        return path

    def refuse(self, path, reason=None):
        with self.assertRaisesRegex((ValueError, tarfile.TarError), reason or ".*"):
            archive.extract(path, self.root / "out")
        self.assertFalse((self.root / "out").exists(), "rejected archive wrote extracted files")

    def test_complete_inventory_extracts_and_preserves_executable_mode(self):
        archive.extract(self.pack(), self.root / "out")
        self.assertEqual((self.root / "out/bin/agentfw").read_bytes(), b"fixture")
        if sys.platform != "win32":
            self.assertEqual((self.root / "out/bin/agentfw").stat().st_mode & 0o777, 0o755)

    def test_every_required_category_must_be_present(self):
        for name in sorted(archive.REQUIRED):
            with self.subTest(name=name):
                files = dict(self.files)
                if name == "Cargo.lock":
                    self.refuse(self.pack(edit=lambda m: m["files"].pop(name)), "required_components")
                else:
                    del files[name]
                    self.refuse(self.pack(files), "required_components")

    def test_notice_metadata_cannot_hide_missing_or_corrupt_notice(self):
        for mode in ("missing", "corrupt"):
            files = dict(self.files)
            name = archive.PROFILE + "upstream-notices/server-LICENSE"
            if mode == "missing":
                del files[name]
            else:
                files[name] = b"changed"
            self.refuse(self.pack(files), "notice_identity")

    def test_self_declared_changed_runtime_archive_is_refused(self):
        files = dict(self.files)
        files["node-v22.23.5-linux-x64.tar.xz"] = b"changed but correctly rehashed"
        self.refuse(self.pack(files), "pinned_archive")

    def test_duplicate_link_special_and_unsafe_members_are_refused(self):
        for name, kind in [(archive.ROOT + "/bin/agentfw", tarfile.REGTYPE),
                           (archive.ROOT + "/alias", tarfile.SYMTYPE),
                           (archive.ROOT + "/hardlink", tarfile.LNKTYPE),
                           (archive.ROOT + "/fifo", tarfile.FIFOTYPE),
                           ("/absolute", tarfile.DIRTYPE),
                           (archive.ROOT + "/../outside", tarfile.DIRTYPE),
                           ("different-root/directory", tarfile.DIRTYPE)]:
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, "bin/agentfw"
                self.refuse(self.pack(extras=[member]))

    def test_unsafe_manifest_keys_and_invalid_identities_are_refused(self):
        for field, value in [("compiler", "stable"), ("source_commit", "unknown"), ("cargo_lock_sha256", "wrong")]:
            with self.subTest(field=field):
                self.refuse(self.pack(edit=lambda m: m["identities"].update({field: value})), "manifest_identities")
        self.refuse(self.pack(edit=lambda m: m["files"].update({"../outside": "a" * 64})), "unsafe_path")

    def test_digest_mismatch_does_not_write_any_files(self):
        self.refuse(self.pack(edit=lambda m: m["files"].update({"bin/agentfw": "f" * 64})), "member_digest")

    def test_new_destination_is_required(self):
        destination = self.root / "out"
        destination.mkdir()
        with self.assertRaisesRegex(ValueError, "new_destination"):
            archive.extract(self.pack(), destination)


if __name__ == "__main__":
    unittest.main()
