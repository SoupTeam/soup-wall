# SPDX-License-Identifier: Apache-2.0
"""Git runtime identity and archive boundary regressions."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou68_install_tests", ROOT / "scripts/install-sou68-git-profile.py")
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class GitProfile(unittest.TestCase):
    def test_original_discovery_lock_and_registry_are_bound(self):
        identity = json.loads((INSTALL.ASSETS / "upstream-identity.json").read_text())
        self.assertEqual(len(identity["python"]["sha256"]), 64)
        for name, digest in identity["files"].items():
            self.assertEqual(INSTALL.sha(INSTALL.ASSETS / name), digest)
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        registry = INSTALL.registry(manifest)
        self.assertEqual(len(registry["tools"]), 12)
        original = {tool["name"]: tool for tool in manifest["result"]["tools"]}
        for tool in registry["tools"]:
            self.assertEqual(tool["schema_sha256"], hashlib.sha256(INSTALL.filesystem.canonical(original[tool["name"]]["inputSchema"])).hexdigest())
            self.assertEqual(tool.get("mcp_result_profile") == INSTALL.FORMAT, tool["name"] in INSTALL.READS)
            self.assertEqual(tool["egress"], [])
            self.assertEqual(tool["result_provenance"], "untrusted")

    def test_archive_refuses_escape_special_files_and_external_links(self):
        for name, kind, target in [("../escape", tarfile.REGTYPE, ""), ("/python/escape", tarfile.REGTYPE, ""),
                                  ("python/socket", tarfile.FIFOTYPE, ""), ("python/bin/link", tarfile.SYMTYPE, "/etc/passwd"),
                                  ("python/bin/link", tarfile.SYMTYPE, "../../../escape")]:
            with self.subTest(name=name, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "runtime.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, target
                    bundle.addfile(entry)
                destination = root / "package"
                destination.mkdir()
                with self.assertRaises(ValueError):
                    INSTALL.extract_python(archive, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_archive_keeps_original_regular_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                entry = tarfile.TarInfo("python/bin/python3.11")
                entry.size = 4
                bundle.addfile(entry, io.BytesIO(b"ELF!"))
            destination = root / "package"
            destination.mkdir()
            INSTALL.extract_python(archive, destination)
            self.assertEqual((destination / "python/bin/python3.11").read_bytes(), b"ELF!")

    def test_missing_linux_never_installs_or_passes(self):
        with patch.object(INSTALL.platform, "system", return_value="Windows"), patch.object(INSTALL.urllib.request, "urlopen") as download:
            with self.assertRaisesRegex(ValueError, "no isolation fallback"):
                INSTALL.install(Path("unused"), Path("unused"), Path("unused"), "a" * 64, Path("unused"), Path("unused"))
            download.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "independent inotify witness requires Linux")
    def test_repository_witness_calibrates_actual_open_and_empty_interval(self):
        spec = importlib.util.spec_from_file_location("sou68_witness_tests", ROOT / "scripts/verify-sou68-real-mcp.py")
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "index"
            target.write_bytes(b"synthetic index")
            witness = verify.RepositoryWitness(root)
            try:
                self.assertEqual(witness.drain(), 0)
                descriptor = os.open(target, os.O_RDONLY)
                os.close(descriptor)
                self.assertGreater(witness.drain(), 0)
                self.assertEqual(witness.drain(), 0)
            finally:
                witness.close()


if __name__ == "__main__":
    unittest.main()
