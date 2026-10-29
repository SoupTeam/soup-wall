# SPDX-License-Identifier: Apache-2.0
"""Fixture input controls only; these do not run or qualify the installed pilot."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("pilot_projects", Path(__file__).resolve().parents[1] / "pilot_project_fixtures.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProjectFixtures(unittest.TestCase):
    def test_three_distinct_bounded_project_identities(self):
        self.assertEqual(set(MODULE.PROJECTS), {"docs-code", "unicode-spaces", "local-history"})
        self.assertEqual(len({MODULE.identity(name) for name in MODULE.PROJECTS}), 3)
        for name, fixture in MODULE.PROJECTS.items():
            self.assertEqual(len(MODULE.identity(name)), 64)
            self.assertLess(sum(len(value.encode()) for value in fixture["files"].values()), 16384)
            self.assertIn(fixture["read_marker"], fixture["files"][fixture["read_path"]])
            for relative in fixture["files"]:
                self.assertFalse(Path(relative).is_absolute())
                self.assertNotIn("..", Path(relative).parts)

    def test_utf8_project_bytes_are_created_exactly(self):
        for name, fixture in MODULE.PROJECTS.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                MODULE.create_files(root, name)
                self.assertEqual({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}, set(fixture["files"]))
                for relative, value in fixture["files"].items():
                    self.assertEqual((root / relative).read_bytes(), value.encode())

    def test_existing_source_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("preserve source", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                MODULE.create_files(root, "docs-code")
            self.assertEqual((root / "README.md").read_text(), "preserve source")

    def test_unicode_spaces_and_history_are_real_required_inputs(self):
        fixture = MODULE.PROJECTS["unicode-spaces"]
        self.assertIn(" ", fixture["root_name"])
        self.assertFalse(fixture["root_name"].isascii())
        self.assertIn(" ", fixture["read_path"])
        self.assertFalse(fixture["read_path"].isascii())
        self.assertEqual(MODULE.PROJECTS["local-history"]["history_messages"],
                         ["Owned documentation revision", "Owned project baseline"])


if __name__ == "__main__":
    unittest.main()
