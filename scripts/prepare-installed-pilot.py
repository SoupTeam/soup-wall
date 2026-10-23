#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare pinned original Linux pilot assets; never launch the protected runtime.

The default is a read-only inventory. --prepare creates a private generation and
atomically selects it only after the accepted selection and both profiles verify.
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
import stat
import subprocess
import sys
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_JSON = 65536
NODE_ARCHIVE_SHA256 = "9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37"
NODE_URL = "https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FS = load("sou111_fs", "install-sou62-filesystem-profile.py")
GIT = load("sou111_git", "install-sou68-git-profile.py")
PILOT = load("sou111_pilot", "qualify-installed-pilot.py")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def private_dir(path, create=False):
    path = Path(path).absolute()
    if create:
        path.mkdir(mode=0o700)
    require(not path.is_symlink() and path.is_dir(), "private_directory_required")
    require(path.stat().st_uid == os.getuid() and stat.S_IMODE(path.stat().st_mode) == 0o700,
            "private_owned_0700_directory_required")
    return path


def inside(path, root):
    require(Path(path).resolve(strict=True).is_relative_to(Path(root).resolve(strict=True)), "path_escape")


def bounded_file(path, limit, *, digest=None):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular_input_required")
    require(path.stat().st_size <= limit, "input_size_limit")
    if digest is not None:
        require(FS.sha(path) == digest, "input_digest_mismatch")
    return path.resolve(strict=True)


def extract_node(archive, destination):
    """Extract the pinned Node distribution without tar-owned modes or links escaping it."""
    bounded_file(archive, 128 * 1024 * 1024, digest=NODE_ARCHIVE_SHA256)
    prefix = "node-v22.22.0-linux-x64"
    with tarfile.open(archive, "r:xz") as bundle:
        members = bundle.getmembers()
        require(len(members) <= 30000 and sum(m.size for m in members) <= 1024**3,
                "node_archive_limit")
        seen, links = set(), []
        for member in members:
            parts = PurePosixPath(member.name).parts
            require(parts and parts[0] == prefix and ".." not in parts and not member.name.startswith("/"),
                    "unsafe_node_archive_path")
            relative = Path(*parts[1:])
            if relative == Path("."):
                require(member.isdir(), "unsafe_node_archive_root")
                continue
            require(relative not in seen, "duplicate_node_archive_path")
            seen.add(relative)
            target = destination / relative
            require(not any(parent in links for parent in relative.parents), "node_archive_link_parent")
            if member.issym():
                require(not PurePosixPath(member.linkname).is_absolute(), "external_node_archive_link")
                links.append(relative)
                continue
            require(member.isdir() or member.isfile(), "unsupported_node_archive_entry")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if member.isdir():
                target.mkdir(exist_ok=True, mode=0o700)
            else:
                source = bundle.extractfile(member)
                require(source is not None, "node_archive_entry_missing")
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
        for relative in links:
            member = next(item for item in members if PurePosixPath(item.name).parts[1:] == relative.parts)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            resolved = (target.parent / member.linkname).resolve(strict=True)
            require(resolved.is_relative_to(destination.resolve(strict=True)), "external_node_archive_link")
            target.symlink_to(member.linkname)


def check_native(path):
    result = subprocess.run(["ldd", str(path)], text=True, capture_output=True, timeout=15)
    require(result.returncode == 0 or "not a dynamic executable" in result.stdout + result.stderr,
            "native_dependency_probe_failed")
    require("not found" not in result.stdout + result.stderr, "native_dependency_missing")


def verify_profile(kind, directory, paths, workspace):
    inside(directory, directory.parent)
    private_dir(directory)
    receipt = json.loads(bounded_file(directory / "installation.json", MAX_JSON).read_text())
    profile = json.loads(bounded_file(directory / "profile.json", MAX_JSON).read_text())
    registry = json.loads(bounded_file(directory / "registry.json", MAX_JSON).read_text())
    installer, name = (FS, "filesystem-readonly-v1") if kind == "filesystem" else (GIT, "git-readonly-v1")
    require(receipt.get("format") == f"sou{62 if kind == 'filesystem' else 68}-profile-installation/1"
            and receipt.get("profile") == profile, "profile_receipt_mismatch")
    for label, suffix in (("profile", "json"), ("registry", "json"), ("policy", "yaml")):
        asset = bounded_file(directory / f"{label}.{suffix}", MAX_JSON)
        require(FS.sha(asset) == receipt[f"{label}_sha256"],
                "profile_asset_changed")
    require(profile.get("format") == installer.FORMAT, "profile_format_changed")
    require(profile.get("workspace") == str(workspace) and profile.get("bwrapPath") == str(paths["bwrap"])
            and profile.get("bwrapSha256") == FS.sha(paths["bwrap"]), "profile_runtime_changed")
    require(profile.get("packageRoot") == str(directory / "package")
            and not (directory / "package").is_symlink(), "profile_package_path_changed")
    require(FS.tree_sha(directory / "package") == profile.get("packageTreeSha256"), "profile_package_changed")
    require(registry == installer.registry(json.loads((installer.ASSETS / "upstream-tools-list.json").read_text()))
            and registry.get("registry_id") == name, "profile_registry_changed")
    require(FS.sha(directory / "policy.yaml") == FS.sha(installer.ASSETS / "policy.yaml"),
            "profile_policy_changed")
    runtime = Path(profile["runtimePath"])
    require(FS.sha(runtime) == profile["runtimeSha256"], "profile_runtime_changed")
    for item in profile["libraries"]:
        require(FS.sha(item["path"]) == item["sha256"], "native_dependency_changed")
    if kind == "filesystem":
        require(runtime == paths["node"], "profile_runtime_changed")
    else:
        require(runtime == directory / "package/python/bin/python3.11", "profile_runtime_changed")
        require(profile["git"] == {"path": str(paths["git"]), "sha256": FS.sha(paths["git"])}
                and profile["gitLauncher"] == {"path": str(paths["git_launcher"]),
                                              "sha256": FS.sha(paths["git_launcher"])}, "profile_runtime_changed")
    return {"profile": {"path": str(directory / "profile.json"), "sha256": receipt["profile_sha256"]},
            "registry_sha256": receipt["registry_sha256"], "package_tree_sha256": profile["packageTreeSha256"]}


def discard_unpublished(path, error):
    """Remove only the file this attempt created, preserving the original failure."""
    try:
        Path(path).unlink(missing_ok=True)
    except OSError as cleanup_error:
        raise ValueError(f"unpublished_file_cleanup_failed: {path}; original_failure={error}; "
                         f"cleanup_failure={cleanup_error}") from error


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(raw) <= MAX_JSON, "manifest_size_limit")
    created = False
    try:
        with Path(path).open("xb") as output:
            created = True
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException as error:
        if created:
            discard_unpublished(path, error)
        raise


def sync_directory(path):
    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def publish_marker(output, record):
    temporary = output / (".current-" + uuid.uuid4().hex)
    write_json(temporary, record)
    try:
        os.replace(temporary, output / "current.json")
    except BaseException as error:
        if not temporary.exists():
            # An interruption can arrive after rename completed but before its
            # caller resumes. Absence of our temporary means publication may
            # have happened; never restore the previous marker in that case.
            raise ValueError("completion_marker_publication_uncertain; "
                             "verify_current_generation_before_reuse") from error
        discard_unpublished(temporary, error)
        raise
    # Rename already selected the new generation. A failed directory sync cannot
    # safely be rolled back: report the uncertainty and retain both generations.
    try:
        sync_directory(output)
    except (OSError, KeyboardInterrupt) as error:
        raise ValueError("completion_marker_published_durability_uncertain; "
                         "verify_current_generation_before_reuse") from error


def selected_paths(args, generation):
    supplied = {role: getattr(args, role) for role in PILOT.ROLES if role not in {"node", "npm"}}
    for role, path in supplied.items():
        require(path is not None, f"missing_{role}: supply --{role.replace('_', '-')}")
        require(path.is_absolute() and path.is_file(), f"invalid_{role}_path")
    if args.node_archive:
        require(args.node is None and args.npm is None, "choose_node_archive_or_runtime")
        runtime = generation / "node"
        runtime.mkdir(mode=0o700)
        extract_node(args.node_archive, runtime)
        node, npm = runtime / "bin/node", runtime / "bin/npm"
    else:
        require(args.node is not None and args.npm is not None, "supply_node_archive_or_node_and_npm")
        node, npm = args.node, args.npm
    supplied.update(node=node, npm=npm)
    paths = {role: Path(path).resolve(strict=True) for role, path in supplied.items()}
    for role in PILOT.EXECUTABLE_ROLES:
        require(os.access(paths[role], os.X_OK), f"{role}_not_executable")
        check_native(paths[role])
    require(FS.sha(paths["node"]) == FS.NODE_SHA256, "node_binary_digest_mismatch")
    require(subprocess.check_output([str(paths["node"]), "--version"], text=True, timeout=10).strip()
            == FS.NODE_VERSION, "node_version_mismatch")
    require("--ro-bind-fd" in subprocess.check_output([str(paths["bwrap"]), "--help"], text=True, timeout=10),
            "bubblewrap_ro_bind_fd_required")
    for role in PILOT.ARTIFACT_ROLES:
        bounded_file(paths[role], 1024 * 1024)
    return paths


def verify_generation(generation, expected_commit, *, probe_native=True):
    generation = private_dir(generation)
    selection_path = bounded_file(generation / "selection.json", MAX_JSON)
    selection = PILOT.strict_json(selection_path.read_bytes())
    require(isinstance(selection, dict), "selection_invalid")
    _, paths = PILOT.validate_selection(selection, expected_commit)
    profiles = {
        "filesystem": verify_profile("filesystem", generation / "filesystem-profile", paths,
                                     generation / "filesystem-workspace"),
        "git": verify_profile("git", generation / "git-profile", paths, generation / "git-workspace"),
    }
    require(selection.get("prepared_profiles") == profiles, "selected_profile_identity_mismatch")
    require(FS.sha(paths["node"]) == FS.NODE_SHA256, "node_binary_digest_mismatch")
    if probe_native:
        for role in PILOT.EXECUTABLE_ROLES:
            check_native(paths[role])
    return selection_path, profiles


def supported_platform():
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "native_linux_x86_64_required")
    require(os.geteuid() != 0, "non_root_operator_required")
    require("microsoft" not in Path("/proc/sys/kernel/osrelease").read_text().lower(),
            "native_ubuntu_required_wsl_is_separate")
    release = Path("/etc/os-release").read_text()
    require(re.search(r'^VERSION_ID="?24\.04"?$', release, re.MULTILINE) is not None,
            "ubuntu_24_04_required")


def prepare(args):
    supported_platform()
    before = PILOT.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit,
            "candidate_source_mismatch")
    for name in ("node_archive", "python_archive", "npm_cache", "wheelhouse"):
        path = getattr(args, name)
        require(path is None or path.is_absolute(), f"absolute_{name}_required")
    require(args.output is not None and args.output.is_absolute(), "absolute_output_required")
    require(not args.output.resolve().is_relative_to(ROOT), "output_must_be_outside_checkout")
    output = private_dir(args.output, create=not args.output.exists())
    generations = output / "generations"
    if not generations.exists():
        generations.mkdir(mode=0o700)
    private_dir(generations)
    marker = output / "current.json"
    if marker.exists() and not args.rebuild:
        record = PILOT.strict_json(bounded_file(marker, MAX_JSON).read_bytes())
        require(isinstance(record, dict), "completion_marker_invalid")
        require(record.get("format") == "sw-pilot-preparation/1", "completion_marker_invalid")
        require(isinstance(record.get("generation"), str), "completion_marker_invalid")
        generation = generations / record["generation"]
        require(re.fullmatch(r"[0-9a-f]{32}", record["generation"]), "completion_marker_invalid")
        inside(generation, generations)
        selection, _ = verify_generation(generation, args.expected_commit)
        require(FS.sha(selection) == record["selection_sha256"], "completion_marker_changed")
        return {"status": "reused", "selection": str(selection), "generation": record["generation"]}
    generation = generations / uuid.uuid4().hex
    generation.mkdir(mode=0o700)
    paths = selected_paths(args, generation)
    fs_workspace, git_workspace = generation / "filesystem-workspace", generation / "git-workspace"
    fs_workspace.mkdir(mode=0o700)
    git_workspace.mkdir(mode=0o700)
    environment = {"PATH": str(paths["git"].parent), "HOME": str(generation), "LANG": "C.UTF-8"}
    subprocess.run([str(paths["git"]), "init", "-q", str(git_workspace)], env=environment,
                   check=True, timeout=15, capture_output=True)
    require((git_workspace / ".git").is_dir(), "git_workspace_not_initialized")
    npm_cache = private_dir(args.npm_cache) if args.npm_cache else None
    if args.wheelhouse:
        private_dir(args.wheelhouse)
    if not args.allow_download:
        require(npm_cache is not None and args.python_archive is not None and args.wheelhouse is not None,
                "offline_requires_npm_cache_python_archive_wheelhouse")
    for kind in ("filesystem", "git"):
        log_path = generation / (kind + "-install.log")
        with log_path.open("xb") as log:
            os.fchmod(log.fileno(), 0o600)
            try:
                if kind == "filesystem":
                    FS.install(generation / "filesystem-profile", fs_workspace, paths["node"],
                               paths["bwrap"], paths["npm"], npm_cache=npm_cache,
                               offline=not args.allow_download, log=log)
                else:
                    GIT.install(generation / "git-profile", git_workspace, paths["git"], FS.sha(paths["git"]),
                                paths["bwrap"], paths["git_launcher"], python_archive=args.python_archive,
                                wheelhouse=args.wheelhouse, allow_download=args.allow_download, log=log)
            except subprocess.CalledProcessError as error:
                raise ValueError(f"{kind}_installer_failed_exit_{error.returncode}; private_log={log_path}") from None
        require(log_path.stat().st_size <= 1024 * 1024, kind + "_installer_log_limit")
    profiles = {
        "filesystem": verify_profile("filesystem", generation / "filesystem-profile", paths, fs_workspace),
        "git": verify_profile("git", generation / "git-profile", paths, git_workspace),
    }
    selection = {"format": "sw-installed-pilot-selection/2", "source": PILOT.source(),
                 "expected_refusal": {"verdict": args.refusal_verdict, "rule": args.refusal_rule},
                 "files": {role: {"path": str(paths[role]), "sha256": FS.sha(paths[role])}
                           for role in PILOT.ROLES}, "prepared_profiles": profiles}
    selection_path = generation / "selection.json"
    write_json(selection_path, selection)
    verify_generation(generation, args.expected_commit)
    record = {"format": "sw-pilot-preparation/1", "generation": generation.name,
              "selection_sha256": FS.sha(selection_path), "status": "prepared-not-active"}
    publish_marker(output, record)
    return {"status": "prepared-not-active", "selection": str(selection_path), "generation": generation.name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="explicitly prepare and select a verified generation")
    parser.add_argument("--rebuild", action="store_true", help="prepare a new generation and retain the old one")
    parser.add_argument("--allow-download", action="store_true", help="permit locked npm/pip and pinned Python download")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--node-archive", type=Path)
    parser.add_argument("--python-archive", type=Path)
    parser.add_argument("--npm-cache", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--refusal-verdict", choices=("ask", "deny"), default="ask")
    parser.add_argument("--refusal-rule", default=PILOT.SHARED.RULE)
    for role in PILOT.ROLES:
        parser.add_argument("--" + role.replace("_", "-"), type=Path)
    args = parser.parse_args()
    if not args.prepare:
        supported = platform.system() == "Linux" and platform.machine() == "x86_64"
        if supported:
            supported = re.search(r'^VERSION_ID="?24\.04"?$', Path("/etc/os-release").read_text(),
                                  re.MULTILINE) is not None
            supported = supported and os.geteuid() != 0 and "microsoft" not in Path(
                "/proc/sys/kernel/osrelease").read_text().lower()
        missing = ["run on native Ubuntu 24.04 x86_64" if not supported else None,
                   "--output ABSOLUTE_PRIVATE_DIRECTORY" if args.output is None else None,
                   "--expected-commit FULL_REVIEWED_COMMIT" if args.expected_commit is None else None,
                   *["--" + role.replace("_", "-") + " PATH" for role in PILOT.ROLES
                     if role not in {"node", "npm"} and getattr(args, role) is None],
                   "--node-archive PINNED_TAR_XZ or --node PATH --npm PATH"
                   if args.node_archive is None and (args.node is None or args.npm is None) else None,
                   "--python-archive PINNED_TAR_GZ --npm-cache DIR --wheelhouse DIR, or --allow-download"
                   if not args.allow_download and not (args.python_archive and args.npm_cache and args.wheelhouse) else None]
        for role in PILOT.ROLES:
            path = getattr(args, role)
            if path is not None and (not path.is_absolute() or not path.is_file()):
                missing.append(f"provide existing absolute --{role.replace('_', '-')} path")
        for role in ("node_archive", "python_archive"):
            path = getattr(args, role)
            if path is not None and (not path.is_absolute() or not path.is_file()):
                missing.append(f"provide existing absolute --{role.replace('_', '-')} path")
        for role in ("npm_cache", "wheelhouse"):
            path = getattr(args, role)
            if path is not None and (not path.is_absolute() or not path.is_dir()):
                missing.append(f"provide existing absolute --{role.replace('_', '-')} directory")
        for program in ("ldd", "readelf"):
            if shutil.which(program) is None:
                missing.append(f"provide {program} in PATH for native dependency checks")
        print(json.dumps({"status": "plan", "executed": False, "missing": [item for item in missing if item],
                          "node_archive": {"url": NODE_URL, "sha256": NODE_ARCHIVE_SHA256},
                          "next": "supply listed inputs, then add --prepare; qualification is a separate command"}))
        return 0
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", args.expected_commit or ""), "full_expected_commit_required")
        print(json.dumps(prepare(args)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError, subprocess.SubprocessError,
            PILOT.Failure) as error:
        print(json.dumps({"status": "failed", "reason": str(error)[:240]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
