#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarize the finite native SOU-194 exchange witness without archive bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def read(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--scratch", required=True, type=Path)
    args = parser.parse_args()
    scratch = args.scratch.resolve(strict=True)
    online, imported, offline = (read(scratch / (name + ".json"))
                                 for name in ("online", "import", "offline"))
    preview_online, preview_offline = (read(scratch / (name + ".json"))
                                       for name in ("preview-online", "preview-offline"))
    assert online["status"] == offline["status"] == "prepared-not-qualified"
    assert imported["status"] == "imported-not-prepared"
    assert preview_online["complete"] and preview_offline["complete"]
    assert not online["active_protection"] and not offline["active_protection"]
    assert read(scratch / "network-isolation.json")["host_namespace"] != \
        read(scratch / "network-isolation.json")["offline_namespace"]
    bundle = scratch / "transfer" / "pinned.tar"
    info = bundle.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_nlink == 1
    binaries = {}
    for name, prepared in (("online", online), ("offline", offline)):
        receipt_path = Path(prepared["receipt"])
        assert receipt_path.is_relative_to(scratch / name)
        receipt = read(receipt_path)
        assert receipt["source_commit"] == args.source
        binaries[name] = {}
        for kind in ("git", "bwrap"):
            binary = Path(prepared[kind])
            assert binary.is_relative_to(scratch / name)
            binary_hash = digest(binary)
            assert binary_hash == receipt["binaries"][kind]["sha256"]
            binaries[name][kind] = binary_hash
    return {"format": "sw-sou194-native-exchange-evidence/1",
            "source_commit": args.source,
            "bundle_sha256": digest(bundle), "bundle_bytes": info.st_size,
            "online_status": online["status"], "import_status": imported["status"],
            "offline_status": offline["status"], "network_isolation": "verified",
            "archive_inventory": imported["archives"],
            "binary_sha256": binaries, "timings": read(scratch / "timings.json"),
            "active_protection": False}


if __name__ == "__main__":
    print(json.dumps(main(), sort_keys=True))
