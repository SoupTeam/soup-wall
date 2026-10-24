#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in private installation of the pinned original read-only Git MCP profile.

Preparation downloads are explicit. Protected startup never installs software.
The supplied Git binary requires an independently supplied digest and version.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "profiles/mcp/git-readonly-v1"
FORMAT = "sw-mcp/git-readonly/1"
LOCAL_REFS_FORMAT = "sw-mcp/git-readonly-local-refs/1"
READS = {"git_status", "git_log", "git_diff", "git_diff_staged", "git_diff_unstaged", "git_show"}
spec = importlib.util.spec_from_file_location("filesystem_installer", ROOT / "scripts/install-sou62-filesystem-profile.py")
filesystem = importlib.util.module_from_spec(spec)
spec.loader.exec_module(filesystem)
sha, private_json, tree_sha = filesystem.sha, filesystem.private_json, filesystem.tree_sha


def extract_python(archive, destination):
    """Extract only bounded, relative, regular runtime entries and internal links."""
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > 30000 or sum(m.size for m in members) > 1024**3:
            raise ValueError("Python archive exceeds limits")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "python":
                raise ValueError("unsafe Python archive path")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError("unsupported Python archive entry")
            if member.issym():
                target = PurePosixPath(member.linkname)
                resolved = (destination / member.name).parent.joinpath(member.linkname).resolve()
                if target.is_absolute() or not resolved.is_relative_to(destination / "python"):
                    raise ValueError("external Python archive link")
        bundle.extractall(destination, members=members, filter="data")


def dependencies(executables, package):
    """Pin explicit system ELF files; packaged Python libraries stay in its tree."""
    paths = set()
    for executable in executables:
        result = subprocess.run(["ldd", str(executable)], capture_output=True, text=True, check=True, timeout=15)
        if "not found" in result.stdout:
            raise ValueError("unresolved runtime ELF dependency")
        for raw in re.findall(r"(?:=>\s*)?(/[^\s()]+)", result.stdout):
            path = Path(raw)
            if path.resolve().is_relative_to(package):
                continue
            if not raw.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")):
                raise ValueError("external runtime library directory")
            paths.add(raw)
    if not 1 <= len(paths) <= 32:
        raise ValueError("runtime library count outside bound")
    return [{"path": path, "sha256": sha(path)} for path in sorted(paths)]


def registry(manifest, *, local_references=False):
    selected_format = LOCAL_REFS_FORMAT if local_references else FORMAT
    registry_id = "git-readonly-local-refs-v1" if local_references else "git-readonly-v1"
    return {"contract_version": "sw-native/1", "registry_id": registry_id, "tools": [
        {"name": tool["name"],
         "schema_sha256": hashlib.sha256(filesystem.canonical(tool["inputSchema"])).hexdigest(),
         "action_class": "read_only" if tool["name"] in READS else "destructive",
         "result_provenance": "untrusted", "egress": [],
         **({"mcp_result_profile": selected_format} if tool["name"] in READS else {})}
        for tool in manifest["result"]["tools"]]}


def install(destination, workspace, git, git_sha256, bwrap, git_launcher,
            *, python_archive=None, wheelhouse=None, allow_download=True, log=None,
            local_references=False):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Git profile requires Linux x86-64; no isolation fallback")
    workspace, git, bwrap, git_launcher = [Path(p).resolve(strict=True) for p in (workspace, git, bwrap, git_launcher)]
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink() or destination.is_relative_to(workspace):
        raise ValueError("destination must be new and outside the repository")
    if not (workspace / ".git").is_dir() or workspace == Path("/"):
        raise ValueError("standalone synthetic non-bare repository required")
    if not re.fullmatch(r"[0-9a-f]{64}", git_sha256) or sha(git) != git_sha256:
        raise ValueError("supplied Git binary digest mismatch")
    identity = json.loads((ASSETS / "upstream-identity.json").read_text())
    git_version = subprocess.check_output([str(git), "--version"], text=True, timeout=10).strip()
    if git_version != "git version " + identity["git_version"]:
        raise ValueError("Git version differs from selected runtime")
    if "--ro-bind-fd" not in subprocess.check_output([str(bwrap), "--help"], text=True, timeout=10):
        raise ValueError("bubblewrap --ro-bind-fd is required")
    for name, expected in identity["files"].items():
        if Path(name).name != name or sha(ASSETS / name) != expected:
            raise ValueError("committed upstream asset digest mismatch")
    destination.mkdir(mode=0o700)
    package = destination / "package"
    package.mkdir(mode=0o700)
    archive = destination / "python.tar.gz"
    if python_archive is not None:
        supplied = Path(python_archive).resolve(strict=True)
        if supplied.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("Python archive exceeds bound")
        if sha(supplied) != identity["python"]["sha256"]:
            raise ValueError("Python distribution digest mismatch")
        shutil.copyfile(supplied, archive)
    elif allow_download:
        request = urllib.request.Request(identity["python"]["url"], headers={"User-Agent": "Soup-Wall-SOU68"})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open("xb") as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise ValueError("Python download exceeds bound")
                output.write(chunk)
    else:
        raise ValueError("pinned Python archive is required without explicit downloads")
    if sha(archive) != identity["python"]["sha256"]:
        raise ValueError("Python distribution digest mismatch")
    extract_python(archive, package)
    python = package / "python/bin/python3.11"
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(destination), "LANG": "C.UTF-8"}
    if subprocess.check_output([str(python), "-I", "--version"], env=env, text=True, timeout=10).strip() != "Python " + identity["python"]["version"]:
        raise ValueError("Python version mismatch")
    if not allow_download and wheelhouse is None:
        raise ValueError("local wheelhouse is required without explicit downloads")
    offline_args = ["--no-index", "--find-links", str(Path(wheelhouse).resolve(strict=True))] if not allow_download else []
    subprocess.run([str(python), "-I", "-m", "pip", "--isolated", "install", "--require-hashes",
                    "--only-binary=:all:", "--no-compile", "--no-cache-dir", "--disable-pip-version-check",
                    *offline_args, "-r", str(ASSETS / "requirements.lock")], env=env, check=True, timeout=300,
                   stdout=log, stderr=subprocess.STDOUT if log is not None else None)
    # Python extension modules may depend on libraries not used by its launcher.
    elf_files = [python, git, git_launcher]
    elf_files.extend(path for path in (package / "python/lib").rglob("*.so") if path.is_file())
    profile = {"format": LOCAL_REFS_FORMAT if local_references else FORMAT,
               "workspace": str(workspace), "runtimePath": str(python),
               "runtimeSha256": sha(python), "packageRoot": str(package), "packageTreeSha256": tree_sha(package),
               "bwrapPath": str(bwrap), "bwrapSha256": sha(bwrap),
               "git": {"path": str(git), "sha256": git_sha256},
               "gitLauncher": {"path": str(git_launcher), "sha256": sha(git_launcher)},
               "libraries": dependencies(elf_files, package)}
    private_json(destination / "profile.json", profile)
    manifest = json.loads((ASSETS / "upstream-tools-list.json").read_text())
    private_json(destination / "registry.json", registry(manifest, local_references=local_references))
    shutil.copyfile(ASSETS / "policy.yaml", destination / "policy.yaml")
    os.chmod(destination / "policy.yaml", 0o600)
    shutil.copytree(ASSETS / "upstream-notices", destination / "upstream-notices")
    private_json(destination / "installation.json", {
        "format": "sou68-profile-installation/1", "profile": profile, "upstream_identity": identity,
        "git_version": git_version, "profile_sha256": sha(destination / "profile.json"),
        "registry_sha256": sha(destination / "registry.json"), "policy_sha256": sha(destination / "policy.yaml"),
        "bwrap_version": subprocess.check_output([str(bwrap), "--version"], text=True, timeout=10).strip()})
    return {"status": "installed", "profile": str(destination / "profile.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--local-references", action="store_true",
                        help="explicitly select the bounded local branch/tag reference contract")
    for name in ("destination", "workspace", "git", "bwrap", "git-launcher"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False,
                          "profile": LOCAL_REFS_FORMAT if args.local_references else FORMAT}))
        return 0
    try:
        print(json.dumps(install(args.destination, args.workspace, args.git, args.git_sha256,
                                 args.bwrap, args.git_launcher, local_references=args.local_references)))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
