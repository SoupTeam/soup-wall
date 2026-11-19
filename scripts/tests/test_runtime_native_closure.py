# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate_inventory as inventory


class NativeClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {}
        for role in ("agentfw", "git_launcher", "sandbox_tests", "node", "npm", "bwrap", "git", "claude", "python"):
            path = self.root / role
            path.write_bytes(b"#!/usr/bin/env node\n" if role == "npm" else b"\x7fELF fixture")
            self.files[role] = {"path": str(path), "sha256": inventory.sha(path)}
        self.selection = {"files": self.files}
        self.python = self.root / "bundled-python"
        self.python.write_bytes(b"\x7fELF separate bundled interpreter")
        self.libs = {}
        for name in ("profile-libc", "bwrap-libcap", "host-python-libexpat"):
            path = self.root / name
            path.write_text("Exact selected " + name)
            self.libs[str(path)] = inventory.sha(path)
        for kind in ("filesystem", "git"):
            profile = self.root / (kind + "-profile")
            profile.mkdir()
            data = {"libraries": [{"path": next(iter(self.libs)), "sha256": next(iter(self.libs.values()))}],
                    "packageRoot": str(self.root / "package"),
                    "runtimePath": str(self.python), "runtimeSha256": inventory.sha(self.python)}
            (profile / "profile.json").write_text(json.dumps(data))
        self.reader = Mock(return_value=[{"path": path, "sha256": value} for path, value in self.libs.items()])
        self.preparation = SimpleNamespace(PILOT=SimpleNamespace(EXECUTABLE_ROLES=tuple(self.files)),
                                          GIT=SimpleNamespace(dependencies=self.reader))
        notice = self.root / "COPYRIGHT"
        notice.write_text("Retained actual system-library notices")
        self.data = {"system_libraries": {path: {"sha256": value, "license": "reviewed exact license",
                "sources": ["https://upstream.example/source"],
                "notices": {str(notice): inventory.sha(notice)}} for path, value in self.libs.items()}}

    def test_selected_executable_union_includes_supplemental_bwrap_and_host_python(self):
        self.assertEqual(inventory.verify_native_libraries(self.data, self.selection, self.root,
                                                          self.preparation), self.libs)
        paths, package = self.reader.call_args.args
        self.assertEqual(set(paths), {Path(row["path"]) for role, row in self.files.items() if role != "npm"} |
                         {self.python})
        self.assertEqual(package, self.root / "package")

    def test_omitted_selected_executable_dependency_cannot_be_cleared_by_profile_only_review(self):
        for omitted in ("bwrap-libcap", "host-python-libexpat"):
            changed = copy.deepcopy(self.data)
            changed["system_libraries"].pop(str(self.root / omitted))
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, "review_coverage"):
                inventory.verify_native_libraries(changed, self.selection, self.root, self.preparation)

    def test_selected_hash_is_rechecked_after_dependency_probe(self):
        def changed(*args):
            Path(self.files["bwrap"]["path"]).write_bytes(b"\x7fELF changed")
            return []
        self.reader.side_effect = changed
        with self.assertRaisesRegex(ValueError, "selected_binary_changed"):
            inventory.native_libraries(self.selection, self.root, self.preparation)

    def test_dependency_reader_failure_and_unknown_interpreter_do_not_clear(self):
        self.reader.side_effect = ValueError("unresolved runtime ELF dependency")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            inventory.native_libraries(self.selection, self.root, self.preparation)
        self.reader.side_effect = None
        path = Path(self.files["npm"]["path"])
        path.write_bytes(b"#!/bin/sh\n")
        self.files["npm"]["sha256"] = inventory.sha(path)
        with self.assertRaisesRegex(ValueError, "script_interpreter"):
            inventory.native_libraries(self.selection, self.root, self.preparation)

    def test_changed_system_library_and_conflicting_closure_identity_refuse(self):
        Path(next(iter(self.libs))).write_text("changed system library")
        with self.assertRaisesRegex(ValueError, "review_incomplete"):
            inventory.verify_native_libraries(self.data, self.selection, self.root, self.preparation)
        self.reader.return_value = [{"path": next(iter(self.libs)), "sha256": "f"*64}]
        with self.assertRaisesRegex(ValueError, "identity_conflict"):
            inventory.native_libraries(self.selection, self.root, self.preparation)


if __name__ == "__main__":
    unittest.main()
