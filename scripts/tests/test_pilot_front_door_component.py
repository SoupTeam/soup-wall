# SPDX-License-Identifier: Apache-2.0
"""Installed guided-pilot component: closure, format and installed mode.

Public, local controls without a host. The native lifecycle evidence is the
separate qualify-installed-front-door.py run on Ubuntu 24.04.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = load("component_builder", "scripts/build-pilot-front-door.py")
IDENTITY = load("component_identity", "scripts/pilot_source_identity.py")
SOURCE = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
# Checkout references in listed helpers that the guided flow never reaches.
NOT_RUNTIME = {
    "scripts/fixtures/mcp_admission_demo_server.py": "standalone admission demo server",
    "target": "developer build output of the standalone admission demo",
    "scripts/agent_audit_windows_io.py": "imported only on Windows (os.name == 'nt')",
    "scripts/pilot_measurement.py": "imported only by qualify-installed-pilot.py --matched-development as a program",
}
LOAD = re.compile(r"""load\(\s*["'][^"']+["']\s*,\s*["']([^"']+\.py)["']\s*\)""")
SPEC = re.compile(r"""(?:ROOT|REPO)\s*/\s*["']scripts/([^"']+\.py)["']""")
SIBLING = re.compile(r"""with_name\(\s*["']([^"']+\.py)["']\s*\)""")
DATA = re.compile(r"""(?:ROOT|REPO)\s*/\s*["']((?:rule_baseline|profiles|scripts/fixtures|target)[^"']*)["']""")
IMPORT = re.compile(r"""^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_]*)\s+import|import\s+([A-Za-z_][A-Za-z0-9_]*))""", re.M)


def listed():
    files = set(BUILDER.SCRIPTS) | set(BUILDER.DATA_FILES)
    return files, tuple(BUILDER.DATA_DIRECTORIES)


def covered(path, files, directories):
    """Listed, inside a listed directory, or a parent of listed content (a
    reference such as ROOT / "profiles/mcp" / name)."""
    return (path in files or any(path == d or path.startswith(d + "/") or d.startswith(path + "/")
                                 for d in directories)
            or any(name.startswith(path + "/") for name in files))


class Closure(unittest.TestCase):
    def test_every_helper_and_data_reference_is_in_the_component(self):
        files, directories = listed()
        missing = []
        for script in BUILDER.SCRIPTS:
            text = (ROOT / script).read_text()
            references = {"scripts/" + name for name in LOAD.findall(text) + SPEC.findall(text) + SIBLING.findall(text)}
            for first, second in IMPORT.findall(text):
                name = first or second
                if (ROOT / "scripts" / (name + ".py")).is_file():
                    references.add("scripts/" + name + ".py")
            references |= set(DATA.findall(text))
            for reference in sorted(references):
                if covered(reference, files, directories):
                    continue
                if any(reference == key or reference.startswith(key + "/") for key in NOT_RUNTIME):
                    continue
                missing.append(script + " -> " + reference)
        self.assertEqual(missing, [])

    def test_entry_and_source_identity_are_listed(self):
        self.assertIn(BUILDER.ENTRY, BUILDER.SCRIPTS)
        self.assertIn("scripts/pilot_source_identity.py", BUILDER.SCRIPTS)
        self.assertNotIn(IDENTITY.FILE, BUILDER.paths())


class Format(unittest.TestCase):
    def setUp(self):
        self.archive, self.manifest = BUILDER.assemble(BUILDER.contents(), SOURCE)

    def test_archive_is_deterministic_canonical_and_complete(self):
        again, manifest = BUILDER.assemble(BUILDER.contents(), SOURCE)
        self.assertEqual(again, self.archive)
        value = json.loads(self.manifest)
        self.assertEqual(json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), self.manifest)
        self.assertEqual(value["schema"], "sw-pilot-front-door-component/1")
        self.assertEqual(value["entry"], "scripts/pilot.py")
        self.assertEqual(value["python"], "cpython>=3.11,<3.14")
        names = [row["path"] for row in value["files"]]
        self.assertEqual(names, sorted(set(names)))
        self.assertIn(IDENTITY.FILE, names)
        with tarfile.open(fileobj=__import__("io").BytesIO(self.archive)) as archive:
            members = archive.getmembers()
            self.assertEqual([m.name for m in members], ["manifest.json", *names])
            self.assertTrue(all(m.isreg() for m in members))
            for row, member in zip(value["files"], members[1:]):
                data = archive.extractfile(member).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
                self.assertEqual(row["mode"], "0400")
                self.assertTrue(all(part not in ("", ".", "..") for part in PurePosixPath(row["path"]).parts))
        self.assertTrue(self.archive.endswith(b"\0" * 1024))

    def test_recorded_identity_is_the_source(self):
        self.assertEqual(IDENTITY.installed_from_bytes(IDENTITY.record(SOURCE)), SOURCE)


class InstalledIdentity(unittest.TestCase):
    def test_checkout_uses_git_and_malformed_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIsNone(IDENTITY.installed(root))
            (root / IDENTITY.FILE).write_bytes(IDENTITY.record(SOURCE))
            self.assertEqual(IDENTITY.installed(root), SOURCE)
            (root / ".git").mkdir()
            self.assertIsNone(IDENTITY.installed(root))
            (root / ".git").rmdir()
            for bad in (b"{}", b"[]", b"not json", IDENTITY.record(dict(SOURCE, dirty=True)),
                        IDENTITY.record(dict(SOURCE, commit="A" * 40)),
                        IDENTITY.record(dict(SOURCE, extra=1)),
                        b'{"format":"sw-pilot-source-identity/1","format":"x","source":{}}',
                        b" " * 5000):
                (root / IDENTITY.FILE).write_bytes(bad)
                with self.assertRaises(ValueError):
                    IDENTITY.installed(root)


@unittest.skipUnless(sys.platform.startswith("linux") and sys.version_info >= (3, 11), "installed helper needs Linux")
class InstalledMode(unittest.TestCase):
    """The installed tree runs without a checkout and never builds from source."""

    def test_helpers_run_from_an_extracted_tree_outside_the_checkout(self):
        archive, _ = BUILDER.assemble(BUILDER.contents(), SOURCE)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            tree = base / "tree"
            with tarfile.open(fileobj=__import__("io").BytesIO(archive)) as handle:
                for member in handle.getmembers()[1:]:
                    target = tree / member.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(handle.extractfile(member).read())
            home = base / "home"
            home.mkdir()
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8",
                   "PYTHONPATH": str(base / "hostile")}
            words = [sys.executable, "-I", "-B", str(tree / "scripts/pilot.py")]
            result = subprocess.run([*words, "help"], cwd=home, env=env, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"agentfw pilot status", result.stdout)
            prefix = base / "prefix"
            result = subprocess.run([*words, "preview", "--prefix", str(prefix), "--json"], cwd=home, env=env,
                                    capture_output=True, timeout=300)
            report = json.loads(result.stdout.decode().splitlines()[-1])
            self.assertEqual(report["source"], {k: SOURCE[k] for k in ("commit", "tree", "dirty")})
            agent = [row for row in report["stages"] if row["stage"] == "agent"][0]
            self.assertIn("never builds from source", agent["missing"][0])
            self.assertTrue(any("never builds from source" in item for item in report["missing"]))
            self.assertFalse(prefix.exists())
            self.assertFalse(any(path.name == "__pycache__" for path in tree.rglob("*")))


if __name__ == "__main__":
    unittest.main()
