#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicitly prepare the separately identified tracked-symlink Git profile."""
import argparse
import importlib.util
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sou150_shared_installer", ROOT / "scripts/install-sou107-git-profile.py")
SHARED = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SHARED)
FORMAT = "sw-mcp/git-tracked-symlinks-readonly/1"
SELECTION = {"format": FORMAT, "registry_id": "git-tracked-symlinks-readonly-v1",
             "identity": "profiles/mcp/git-tracked-symlinks-readonly-v1/identity.json",
             "installation": "sou150-profile-installation/1"}
sha = SHARED.sha


def identity():
    return SHARED.identity(SELECTION)


def registry(manifest):
    return SHARED.registry(manifest, SELECTION)


def install(destination, workspace, git, git_sha256, bwrap, git_launcher):
    return SHARED.install(destination, workspace, git, git_sha256, bwrap, git_launcher, selection=SELECTION)


def prepare(installation, destination, port, python=None):
    return SHARED.prepare(installation, destination, port, python, selection=SELECTION)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("destination", "workspace", "git", "bwrap", "git-launcher", "selection"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "format": FORMAT}))
        return 0
    install(args.destination, args.workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher)
    _, receipt = prepare(args.destination, args.selection, args.port)
    print(json.dumps(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
