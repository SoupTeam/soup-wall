"""Source identity of an installed guided-pilot component.

A checkout answers its identity with Git. An installed front-door component
has no `.git`; its exact source identity (commit, tree, clean, tracked files
digest) was recorded by `build-pilot-front-door.py` from a clean checkout,
listed in the component manifest and verified by `agentfw pilot` together
with every other component file before the helper starts.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

FORMAT = "sw-pilot-source-identity/1"
FILE = "source-identity.json"
MAX_BYTES = 4096


def installed(root: Path):
    """The recorded identity, or None in a Git checkout. A malformed record is
    an error, never a fallback to another identity."""
    root = Path(root)
    if (root / ".git").exists():
        return None
    path = root / FILE
    if not path.is_file():
        return None
    return installed_from_bytes(path.read_bytes())


def installed_from_bytes(raw):
    """Strictly parse a recorded identity."""
    if len(raw) > MAX_BYTES:
        raise ValueError("installed_source_identity_invalid")

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("installed_source_identity_invalid")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except ValueError:
        raise ValueError("installed_source_identity_invalid") from None
    source = value.get("source") if isinstance(value, dict) else None
    if (set(value) != {"format", "source"} or value["format"] != FORMAT or not isinstance(source, dict)
            or set(source) != {"commit", "tree", "dirty", "files_sha256"} or source["dirty"] is not False
            or not all(isinstance(source[key], str) for key in ("commit", "tree", "files_sha256"))
            or not re.fullmatch(r"[0-9a-f]{40}", source["commit"])
            or not re.fullmatch(r"[0-9a-f]{40}", source["tree"])
            or not re.fullmatch(r"[0-9a-f]{64}", source["files_sha256"])):
        raise ValueError("installed_source_identity_invalid")
    return dict(source)


def record(source) -> bytes:
    """Canonical bytes written into a component by the builder."""
    return (json.dumps({"format": FORMAT, "source": source}, sort_keys=True, separators=(",", ":")) + "\n").encode()
