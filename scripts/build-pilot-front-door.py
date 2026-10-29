#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the installable guided-pilot front-door component.

    python3 -B scripts/build-pilot-front-door.py --out FILE

Run in a clean reviewed checkout. Writes one deterministic ustar archive: a
canonical `manifest.json` (schema `sw-pilot-front-door-component/1`) followed by the
complete transitive runtime files of `scripts/pilot.py`, unchanged, at their
checkout-relative paths, plus `source-identity.json` with the exact clean
source identity. Nothing is downloaded, built or executed except `git` to read
the checkout. Install it with `agentfw pilot-component install`.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_source_identity as SOURCE_IDENTITY  # noqa: E402
from pilot_provider import utility_environment  # noqa: E402

SCHEMA = "sw-pilot-front-door-component/1"
ENTRY = "scripts/pilot.py"
PYTHON = "cpython>=3.11,<3.14"
MAX_FILE = 1024 * 1024
MAX_FILES = 128
MAX_NAME = 100
# The complete transitive runtime of the guided front door: every helper it
# loads directly or through the accepted scripts, and every checkout file those
# helpers read at run time. `scripts/tests/test_pilot_front_door_component.py`
# derives the closure from the sources and fails when this list misses one.
SCRIPTS = (
    "scripts/agent-audit-report.py",
    "scripts/build-native-pilot-inputs.py",
    "scripts/install-sou62-filesystem-profile.py",
    "scripts/install-sou68-git-profile.py",
    "scripts/install-sou107-git-profile.py",
    "scripts/install-sou150-git-profile.py",
    "scripts/install-sou83-filesystem-create-profile.py",
    "scripts/mcp-admission-demo.py",
    "scripts/pilot-run.py",
    "scripts/pilot-selection-lock.py",
    "scripts/pilot.py",
    "scripts/pilot_git_profiles.py",
    "scripts/pilot_audit.py",
    "scripts/pilot_capacity.py",
    "scripts/pilot_policy.py",
    "scripts/pilot_preparation_lock.py",
    "scripts/pilot_provider.py",
    "scripts/pilot_qualification.py",
    "scripts/pilot_source_identity.py",
    "scripts/pilot_update.py",
    "scripts/switch-prepared-pilot.py",
    "scripts/prepare-installed-pilot.py",
    "scripts/prepare-native-pilot-prerequisites.py",
    "scripts/qualify-installed-pilot.py",
    "scripts/verify-sou62-real-mcp.py",
    "scripts/verify-sou62-sou63-combined.py",
    "scripts/verify-sou68-real-mcp.py",
    "scripts/verify-sou79-resource-budgets.py",
    "scripts/wsl_preflight.py",
    "scripts/wsl_qualification.py",
)
DATA_FILES = (
    "rule_baseline/git_readonly_v1/rule_baseline.py",
    "rule_baseline/git_readonly_file_revisions_v1/rule_baseline.py",
    "rule_baseline/git_readonly_local_refs_v1/rule_baseline.py",
    "rule_baseline/rule_baseline.py",
)
DATA_DIRECTORIES = (
    "profiles/mcp/filesystem-readonly-v1",
    "profiles/mcp/git-readonly-v1",
    "profiles/mcp/git-local-clone-readonly-v1",
    "profiles/mcp/git-tracked-symlinks-readonly-v1",
    "profiles/pilot/linux-readonly-v1",
)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(*words):
    return subprocess.check_output(["git", *words], cwd=ROOT, timeout=30, env=utility_environment())


def tracked(directory):
    names = [os.fsdecode(name) for name in git("ls-files", "-z", "--", directory).split(b"\0") if name]
    if not names:
        raise SystemExit("component directory has no tracked files: " + directory)
    return names


def paths():
    names = list(SCRIPTS) + list(DATA_FILES)
    for directory in DATA_DIRECTORIES:
        names.extend(tracked(directory))
    return sorted(set(names))


def valid_path(name):
    parts = PurePosixPath(name).parts
    return (len(name.encode()) <= MAX_NAME and not name.startswith("/") and parts
            and all(re.fullmatch(r"[A-Za-z0-9._-]+", part) and part not in (".", "..") for part in parts))


def tar_member(name, data):
    header = bytearray(512)
    header[0:len(name)] = name.encode()
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"%011o\0" % len(data)
    header[136:148] = b"00000000000\0"
    header[148:156] = b" " * 8
    header[156:157] = b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[148:156] = b"%06o\0 " % sum(header)
    return bytes(header) + data + b"\0" * ((512 - len(data) % 512) % 512)


def contents():
    """The listed checkout files, unchanged."""
    result = {}
    for name in paths():
        if not valid_path(name):
            raise SystemExit("unsupported component path: " + name)
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise SystemExit("component file is not a regular file: " + name)
        data = path.read_bytes()
        if len(data) > MAX_FILE:
            raise SystemExit("component file exceeds the size limit: " + name)
        result[name] = data
    return result


def assemble(files, source):
    """Deterministic archive and canonical manifest for `files` and `source`."""
    files = dict(files)
    files[SOURCE_IDENTITY.FILE] = SOURCE_IDENTITY.record(source)
    names = sorted(files)
    if len(names) > MAX_FILES:
        raise SystemExit("too many component files")
    entries = [{"mode": "0400", "path": name, "sha256": hashlib.sha256(files[name]).hexdigest(),
                "size": len(files[name])} for name in names]
    manifest = {"entry": ENTRY, "files": entries, "python": PYTHON, "schema": SCHEMA,
                "source": {"commit": source["commit"], "tree": source["tree"]}}
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    archive = tar_member("manifest.json", manifest_bytes)
    for name in names:
        archive += tar_member(name, files[name])
    archive += b"\0" * 1024
    return archive, manifest_bytes


def build():
    source = load("component_source", "qualify-installed-pilot.py").source()
    if source["dirty"]:
        raise SystemExit("refusing to build from a dirty checkout")
    archive, manifest = assemble(contents(), source)
    return archive, manifest, source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True, help="new archive file (outside the checkout)")
    args = parser.parse_args(argv)
    out = args.out.absolute()
    if out.exists() or out.is_relative_to(ROOT):
        raise SystemExit("--out must be a new file outside the checkout")
    archive, manifest, source = build()
    with out.open("xb") as stream:
        stream.write(archive)
    print(json.dumps({"action": "build", "out": str(out), "archive_sha256": hashlib.sha256(archive).hexdigest(),
                      "component": hashlib.sha256(manifest).hexdigest(), "commit": source["commit"],
                      "files": len(json.loads(manifest)["files"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
