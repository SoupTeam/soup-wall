#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install the explicit SOU-62 Linux x86-64 read-only filesystem MCP profile.

This scenario-specific operator script creates a new private directory. It does
not edit an existing Agent home or client configuration. npm ci fetches only the
committed lock's original packages and disables lifecycle scripts. Runtime and
bubblewrap are supplied explicitly; the official Node binary identity is pinned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from pilot_provider import utility_environment
import pilot_filesystem_roots as FS_ROOTS
ASSETS = ROOT / "profiles/mcp/filesystem-readonly-v1"
FORMAT = "sw-mcp/filesystem-readonly/1"
NODE_VERSION = "v22.22.0"
NODE_SHA256 = "1bec56ef7cfa9a76f3e0b7c0a87f220eb73f23102b9c0b4c7529a3f7c3ce7c31"
MUTATORS = {"write_file": "side_effecting", "edit_file": "side_effecting",
            "create_directory": "side_effecting", "move_file": "destructive"}


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def tree_sha(root):
    """Match the selected Rust profile's byte-sorted, typed tree digest."""
    root = Path(root).resolve(strict=True)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            path.resolve(strict=True).relative_to(root)
            record = b"L\0" + relative + b"\0" + os.readlink(path).encode("utf-8") + b"\n"
        elif stat.S_ISREG(mode):
            record = b"F\0" + relative + b"\0" + sha(path).encode("ascii") + b"\n"
        elif stat.S_ISDIR(mode):
            record = b"D\0" + relative + b"\n"
        else:
            raise ValueError("package tree contains a special file")
        digest.update(record)
    return digest.hexdigest()


def libraries(node):
    """Record individual ELF dependencies, including the original loader alias."""
    result = subprocess.run(["ldd", str(node)], capture_output=True, text=True, check=True, timeout=15, env=utility_environment())
    if "not found" in result.stdout:
        raise ValueError("Node has an unresolved ELF dependency")
    paths = set(re.findall(r"(?:=>\s*)?(/[^\s()]+)", result.stdout))
    headers = subprocess.run(["readelf", "-l", str(node)], capture_output=True, text=True, check=True, timeout=15, env=utility_environment())
    interpreter = re.findall(r"Requesting program interpreter:\s*([^\]]+)", headers.stdout)
    if len(interpreter) != 1:
        raise ValueError("exact ELF interpreter is required")
    paths.add(interpreter[0])
    if not paths or len(paths) > 64:
        raise ValueError("unsupported ELF dependency count")
    entries = []
    for path in sorted(paths):
        if not path.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")):
            raise ValueError("ELF dependency is outside supported system library directories")
        entries.append({"path": path, "sha256": sha(path)})
    return entries


def registry(manifest, *, filesystem_roots=False):
    profile_format = FS_ROOTS.PROFILE if filesystem_roots else FORMAT
    return {"contract_version": "sw-native/1", "registry_id": FS_ROOTS.ID if filesystem_roots else "filesystem-readonly-v1", "tools": [
        {"name": tool["name"], "schema_sha256": hashlib.sha256(canonical(tool["inputSchema"])).hexdigest(),
         "action_class": MUTATORS.get(tool["name"], "read_only"),
         "result_provenance": "untrusted", "egress": [],
         **({"mcp_result_profile": profile_format} if tool["name"] not in {*MUTATORS, "read_media_file"} else {})}
        for tool in manifest["result"]["tools"]]}


def private_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def install(destination, workspace, node, bwrap, npm, *, npm_cache=None, offline=False, log=None, filesystem_roots=None):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("this profile requires Linux x86-64")
    workspace, node, bwrap = [Path(path).resolve(strict=True) for path in (workspace, node, bwrap)]
    destination = Path(destination).absolute()
    if filesystem_roots is not None:
        FS_ROOTS.verify(filesystem_roots, workspace)
        FS_ROOTS.outside([destination, node, bwrap, npm, npm_cache], filesystem_roots)
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination must be a new directory")
    if not workspace.is_dir() or workspace == Path("/"):
        raise ValueError("a reviewed read-only workspace directory is required")
    if sha(node) != NODE_SHA256:
        raise ValueError("Node binary differs from the pinned official Linux x64 v22.22.0 runtime")
    if subprocess.check_output([str(node), "--version"], text=True, timeout=10, env=utility_environment()).strip() != NODE_VERSION:
        raise ValueError("Node version mismatch")
    if "--ro-bind-fd" not in subprocess.check_output([str(bwrap), "--help"], text=True, timeout=10, env=utility_environment()):
        raise ValueError("bubblewrap with --ro-bind-fd is required; no unsafe fallback")
    identity = json.loads((ASSETS / "upstream-identity.json").read_text(encoding="utf-8"))
    if sha(ASSETS / "package-lock.json") != identity["packageLockSha256"]:
        raise ValueError("shipped npm lock identity mismatch")
    notices = identity.get("upstreamNotices", [])
    if {notice.get("component") for notice in notices} != {"server", "sdk", "node"} or len(notices) != 3:
        raise ValueError("complete original upstream license notices are required")
    for notice in notices:
        parts = PurePosixPath(notice["path"]).parts
        if len(parts) != 2 or parts[0] != "upstream-notices" or parts[1] in {".", ".."}:
            raise ValueError("unsafe original upstream notice path")
        if sha(ASSETS / notice["path"]) != notice["sha256"]:
            raise ValueError("original upstream notice identity mismatch")
    dependencies = libraries(node)
    destination.mkdir(mode=0o700)
    (destination / "upstream-notices").mkdir(mode=0o700)
    for notice in notices:
        shutil.copyfile(ASSETS / notice["path"], destination / notice["path"])
    # Keep a failed partial install for diagnosis. Never run a partially installed profile.
    package = destination / "package"
    package.mkdir(mode=0o700)
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(ASSETS / name, package / name)
    environment = utility_environment()
    environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
    cache = Path(npm_cache).resolve(strict=True) if npm_cache is not None else destination / "npm-cache"
    environment.update(HOME=str(destination), npm_config_cache=str(cache),
                       npm_config_update_notifier="false", npm_config_fund="false", npm_config_audit="false")
    subprocess.run([str(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                    *(["--offline"] if offline else [])], cwd=package,
                   env=environment, check=True, timeout=300,
                   stdout=log, stderr=subprocess.STDOUT if log is not None else None)
    if sha(package / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js") != identity["package"]["originalEntrypointSha256"]:
        raise ValueError("installed original server entrypoint identity mismatch")
    manifest = json.loads((ASSETS / "upstream-tools-list.json").read_text(encoding="utf-8"))
    if hashlib.sha256(canonical(manifest["result"])).hexdigest() != identity["discoveryResultSha256"]:
        raise ValueError("shipped original discovery identity mismatch")
    profile = {"format": FORMAT, "workspace": str(workspace), "runtimePath": str(node),
               "runtimeSha256": sha(node), "packageRoot": str(package), "packageTreeSha256": tree_sha(package),
               "bwrapPath": str(bwrap), "bwrapSha256": sha(bwrap), "libraries": dependencies}
    if filesystem_roots is not None:
        FS_ROOTS.verify(filesystem_roots, workspace)
        profile.update(format=FS_ROOTS.PROFILE, filesystemRoots=filesystem_roots,
                       workspaceIdentity=filesystem_roots['roots'][0]['identity'])
    private_json(destination / "profile.json", profile)
    private_json(destination / "registry.json", registry(manifest, filesystem_roots=filesystem_roots is not None))
    shutil.copyfile(ASSETS / "policy.yaml", destination / "policy.yaml")
    os.chmod(destination / "policy.yaml", 0o600)
    private_json(destination / "installation.json", {
        "format": "sou62-profile-installation/1", "profile": profile,
        "upstream_identity": identity, "upstream_identity_sha256": sha(ASSETS / "upstream-identity.json"),
        "profile_sha256": sha(destination / "profile.json"),
        "registry_sha256": sha(destination / "registry.json"), "policy_sha256": sha(destination / "policy.yaml"),
        "package_lock_sha256": sha(package / "package-lock.json"),
        "server_package": "@modelcontextprotocol/server-filesystem@2026.8.31",
        "node_version": NODE_VERSION, "upstream_notices": notices,
        "node_archive_url": "https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz",
        "node_archive_sha256": "9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37",
        "bwrap_version": subprocess.check_output([str(bwrap), "--version"], text=True, timeout=10, env=utility_environment()).strip()})
    return {"status": "installed", "directory": str(destination), "profile": str(destination / "profile.json"),
            "registry": str(destination / "registry.json"), "policy": str(destination / "policy.yaml"),
            "profile_sha256": sha(destination / "profile.json"), "registry_sha256": sha(destination / "registry.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="create a new profile and fetch its locked npm packages")
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--bwrap", type=Path, required=True)
    parser.add_argument("--npm", type=Path, default=Path(shutil.which("npm") or "npm"))
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "profile": FORMAT,
                          "requires": "Linux x86-64, exact official Node v22.22.0, pinned bubblewrap --ro-bind-fd, npm, fresh destination"}))
        return 0
    try:
        print(json.dumps(install(args.destination, args.workspace, args.node, args.bwrap, args.npm)))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
