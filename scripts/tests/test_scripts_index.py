# SPDX-License-Identifier: Apache-2.0
"""scripts/README.md lists every script and matches what the generator writes."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("scripts_index", ROOT / "scripts/scripts_index.py")
INDEX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INDEX)


class ScriptsIndex(unittest.TestCase):
    def test_the_committed_index_is_current(self):
        self.assertEqual(
            (ROOT / "scripts/README.md").read_text(encoding="utf-8"), INDEX.render(),
            "run: python3 scripts/scripts_index.py")

    def test_every_script_is_listed_once(self):
        text = INDEX.render()
        for path in sorted((ROOT / "scripts").iterdir()):
            if path.is_file() and path.suffix in INDEX.KINDS:
                self.assertEqual(text.count("| [`%s`](%s) |" % (path.name, path.name)), 1, path.name)

    def test_every_subdirectory_is_described(self):
        found = {path.name for path in (ROOT / "scripts").iterdir() if path.is_dir() and path.name != "__pycache__"}
        self.assertEqual(found, set(INDEX.DIRECTORIES))

    def test_a_description_cannot_break_the_table(self):
        self.assertEqual(INDEX.cell("a | b"), "a \\| b")


if __name__ == "__main__":
    unittest.main()
