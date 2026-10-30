# SPDX-License-Identifier: Apache-2.0
"""Owned SOU-145 project data for the existing SOU-134 execution producer.

No executor, classifier, policy or evaluator is defined here. Expected useful
bytes are deliberately ordinary project content, not a detector allowlist.
"""
import hashlib
import json


PROJECTS = {
    "docs-code": {
        "root_name": "documentation-code",
        "files": {
            "README.md": "# Small calculator\nUse src/calculator.py and tests/test_calculator.py.\n",
            "docs/guide.md": "Calculator guide: addition accepts two integers and returns their sum.\n",
            "src/calculator.py": "def add(left, right):\n    return left + right\n",
            "tests/test_calculator.py": "from calculator import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        },
        "read_path": "docs/guide.md",
        "read_marker": "Calculator guide",
        "history_messages": ["Owned project baseline"],
    },
    "unicode-spaces": {
        "root_name": "Жоба notes with spaces",
        "files": {
            "README.md": "# Project notes\nThe localized guide lives in a directory with spaces.\n",
            "құжаттар user guide/оқу notes.txt": "Localized project guide: ordinary documentation in a Unicode path.\n",
            "src/example.py": "TITLE = 'Project notes'\n",
        },
        "read_path": "құжаттар user guide/оқу notes.txt",
        "read_marker": "Localized project guide",
        "history_messages": ["Owned project baseline"],
    },
    "local-history": {
        "root_name": "local-history",
        "files": {
            "README.md": "# Local change history\nThis project has two local revisions.\n",
            "docs/history.md": "Local history guide: compare the documentation revision with its baseline.\n",
            "src/settings.py": "DEFAULT_PAGE_SIZE = 20\n",
        },
        "read_path": "docs/history.md",
        "read_marker": "Local history guide",
        "history_messages": ["Owned documentation revision", "Owned project baseline"],
    },
}


def identity(name):
    raw = json.dumps(PROJECTS[name], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def create_files(root, name):
    """Write only the fixed public data into a newly owned fixture root."""
    for relative, text in PROJECTS[name]["files"].items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
