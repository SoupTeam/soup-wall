#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install a NEW private opt-in ORIGINAL filesystem create-only MCP profile.

Never edits existing read-only installations, Agent home or user configuration.
It reuses the checksum-pinned upstream SOU-62 installer with a fresh destination
and changes only the selected registry/profile and separately owned policy.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

SOURCE = Path(__file__).resolve().with_name("install-sou62-filesystem-profile.py")
SPEC = importlib.util.spec_from_file_location("sou62_readonly_installer", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("pinned original filesystem installer missing")
readonly = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readonly)

FORMAT = "sw-mcp/filesystem-create-only/1"
INSTALLATION_FORMAT = "sou83-original-create-installation/1"
REGISTRY_ID = "filesystem-create-only-v1"
READONLY_FORMAT = readonly.FORMAT
DENY_WRITE = (
    "  - name: filesystem-profile-deny-write\n"
    "    when: { action_class: side_effecting }\n"
    "    action: deny\n"
)


def select_documents(profile, registry, policy):
    """Pure transformation preserving exact original pin and read-only defaults."""
    if profile.get("format") != READONLY_FORMAT or registry.get("registry_id") != "filesystem-readonly-v1":
        raise ValueError("not the accepted pinned original filesystem readonly profile")
    if policy.count(DENY_WRITE) != 1:
        raise ValueError("original per-install write deny not found exactly once")
    manifest = json.loads((readonly.ASSETS / "upstream-tools-list.json").read_text(encoding="utf-8"))
    original = manifest["result"]["tools"]
    tools = registry.get("tools")
    if not isinstance(tools, list) or [t.get("name") for t in tools] != [t["name"] for t in original]:
        raise ValueError("original tool/schema registry drift")
    copied_profile = dict(profile, format=FORMAT)
    selected = []
    for tool in tools:
        updated = dict(tool)
        name = updated["name"]
        expected = hashlib.sha256(readonly.canonical(
            next(t["inputSchema"] for t in original if t["name"] == name))).hexdigest()
        if updated.get("schema_sha256") != expected or updated.get("egress") != [] or updated.get("result_provenance") != "untrusted":
            raise ValueError("original registry authority/identity drift")
        if name == "write_file":
            if updated["action_class"] != "side_effecting" or "mcp_result_profile" in updated:
                raise ValueError("original write authority drift")
            updated["mcp_result_profile"] = FORMAT
        elif name in readonly.MUTATORS or name == "read_media_file":
            if "mcp_result_profile" in updated:
                raise ValueError("unsupported original mutator was selected")
        else:
            if updated.get("action_class") != "read_only" or updated.get("mcp_result_profile") != READONLY_FORMAT:
                raise ValueError("original read-only authority drift")
            updated["mcp_result_profile"] = FORMAT
        selected.append(updated)
    if sum(t["name"] == "write_file" for t in selected) != 1:
        raise ValueError("pinned original write_file absent")
    changed_policy = policy.replace(DENY_WRITE,
        "  # SOU-83 separately selected original write_file is the only supported\n"
        "  # side-effecting MCP schema. All other mutators remain unsupported\n"
        "  # in the pinned registry and profile; these are not general grants.\n")
    return copied_profile, dict(registry, registry_id=REGISTRY_ID, tools=selected), changed_policy


def rewrite_private(path, data):
    """Replace only a file just created under our new 0700 installation."""
    import stat
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_uid != os.geteuid():
            raise ValueError("installed original profile file was replaced")
        # Never truncate before confirming file type, ownership and one link.
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)


def install(destination, workspace, node, bwrap, npm):
    destination = Path(destination).absolute()
    # readonly.install rejects any existing destination and pins exact Node,
    # npm lock, dependency libraries, licenses, upstream schema and binary.
    original = readonly.install(destination, workspace, node, bwrap, npm)
    profile_file, registry_file, policy_file = (
        destination / "profile.json", destination / "registry.json", destination / "policy.yaml")
    profile, registry, policy = select_documents(
        json.loads(profile_file.read_text(encoding="utf-8")),
        json.loads(registry_file.read_text(encoding="utf-8")),
        policy_file.read_text(encoding="utf-8"))
    rewrite_private(profile_file, (json.dumps(profile, indent=2, ensure_ascii=False) + "\n").encode())
    rewrite_private(registry_file, (json.dumps(registry, indent=2, ensure_ascii=False) + "\n").encode())
    rewrite_private(policy_file, policy.encode("utf-8"))
    meta_file = destination / "installation.json"
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    meta.update(format=INSTALLATION_FORMAT, profile=profile,
                profile_sha256=readonly.sha(profile_file),
                registry_sha256=readonly.sha(registry_file),
                policy_sha256=readonly.sha(policy_file),
                original_installer_sha256=readonly.sha(SOURCE),
                selected_mutation="write_file",
                max_utf8_content_bytes=4096)
    rewrite_private(meta_file, (json.dumps(meta, indent=2, ensure_ascii=False) + "\n").encode())
    return {
        "status": "installed", "directory": str(destination),
        "profile": str(profile_file), "registry": str(registry_file), "policy": str(policy_file),
        "profile_sha256": readonly.sha(profile_file),
        "registry_sha256": readonly.sha(registry_file),
        "policy_sha256": readonly.sha(policy_file),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--bwrap", required=True, type=Path)
    parser.add_argument("--npm", type=Path, default=Path(shutil.which("npm") or "npm"))
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "format": FORMAT,
                          "requirements": "new owned destination, pinned Node x64, bwrap, npm, Linux"}))
        return 0
    try:
        print(json.dumps(install(args.destination, args.workspace, args.node, args.bwrap, args.npm)))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
