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

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_capacity as capacity
import pilot_git_profiles as GIT_PROFILES
import wsl_preflight
from pilot_provider import utility_environment
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
SELECTION_LOCK = load("pilot_preparation_selection_lock", "pilot-selection-lock.py")


class InstallerFailure(ValueError):
    """Finite public failure fields; installer output stays in its private log."""

    def __init__(self, kind, exit_code, private_log):
        super().__init__(kind + "_installer_failed")
        self.exit_code = exit_code
        self.private_log = private_log


class WslPreparationFailure(ValueError):
    def __init__(self, report):
        super().__init__("wsl_preparation_prerequisites_not_ready")
        self.report = report


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


def root_identity(path):
    """Pin a directory, never its changing untrusted contents or Git state."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts and path != Path("/")
            and len(str(path).encode()) <= 4096 and not any(ord(c) < 32 or ord(c) == 127 for c in str(path)),
            "canonical_existing_workspace_required")
    try:
        require(path.resolve(strict=True) == path and not path.is_symlink() and path.is_dir(),
                "canonical_existing_workspace_required")
    except FileNotFoundError:
        raise ValueError("existing_workspace_missing_or_moved") from None
    info = path.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o022,
            "owned_workspace_without_shared_write_required")
    require(path != Path.home().resolve(), "home_directory_workspace_refused")
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid}


def requested_workspaces(args):
    fs, git = getattr(args, "filesystem_workspace", None), getattr(args, "git_workspace", None)
    require((fs is None) == (git is None), "supply_both_existing_workspaces")
    if fs is None:
        return None
    return {"format": "sw-pilot-existing-workspaces/1", "capability": "read-only",
            "result_provenance": "untrusted", "roots": {
                "filesystem": root_identity(fs), "git": root_identity(git)}}


def workspace_paths(selection, generation, *, revalidate=True):
    """Old selection/2 generations keep their original generated-demo behavior."""
    binding = selection.get("prepared_workspaces")
    if binding is None:
        return {kind: generation / (kind + "-workspace") for kind in ("filesystem", "git")}
    require(set(binding) == {"format", "capability", "result_provenance", "roots"}
            and binding["format"] == "sw-pilot-existing-workspaces/1"
            and binding["capability"] == "read-only" and binding["result_provenance"] == "untrusted"
            and set(binding["roots"]) == {"filesystem", "git"}, "workspace_binding_invalid")
    roots = {}
    for kind, identity in binding["roots"].items():
        require(set(identity) == {"path", "device", "inode", "uid"}, "workspace_binding_invalid")
        if revalidate:
            require(root_identity(Path(identity["path"])) == identity, "selected_workspace_changed")
        roots[kind] = Path(identity["path"])
        require(not generation.is_relative_to(roots[kind]) and not roots[kind].is_relative_to(generation),
                "preparation_overlaps_workspace")
    return roots


def outside_workspaces(paths, roots):
    for path in paths:
        resolved = Path(path).resolve()
        require(all(not resolved.is_relative_to(root) for root in roots.values()),
                "private_assets_inside_workspace")


def validate_existing_workspaces(paths, roots, git_profile=GIT_PROFILES.DEFAULT, linked_binding=None):
    """Opt-in only: reuse native validators, never run Git against user data."""
    if git_profile == "git-linked-worktree-readonly-v1":
        import pilot_linked_worktree as linked
        linked.verify(linked_binding, roots["git"])
        root_identity(roots["filesystem"])
        return
    require(linked_binding is None, "linked_worktree_cross_profile_binding")
    result = subprocess.run([str(paths["agentfw"]), "pilot-workspaces", "--validate-selection", "--workspace", str(roots["filesystem"]),
                             "--git-workspace", str(roots["git"]),
                             "--git-profile-format", GIT_PROFILES.selected(git_profile)[0]],
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/",
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    require(result.returncode == 0, "unsupported_existing_git_layout_use_supported_standalone_repository")


def bind_profile_workspace(directory, identity):
    # Keep the accepted profile/receipt versions. The optional identity is
    # checked against the opened directory descriptor by the original sandbox.
    profile_path, receipt_path = directory / "profile.json", directory / "installation.json"
    profile = PILOT.strict_json(bounded_file(profile_path, MAX_JSON).read_bytes())
    profile["workspaceIdentity"] = {key: identity[key] for key in ("device", "inode", "uid")}
    receipt = PILOT.strict_json(bounded_file(receipt_path, MAX_JSON).read_bytes())
    for path, value in ((profile_path, profile), (receipt_path, {
            **receipt, "profile": profile, "profile_sha256": hashlib.sha256(
                (json.dumps(profile, sort_keys=True, indent=2) + "\n").encode()).hexdigest()})):
        path.unlink()
        write_json(path, value)


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
    result = subprocess.run(["ldd", str(path)], text=True, capture_output=True, timeout=15, env=utility_environment())
    require(result.returncode == 0 or "not a dynamic executable" in result.stdout + result.stderr,
            "native_dependency_probe_failed")
    require("not found" not in result.stdout + result.stderr, "native_dependency_missing")


def verify_profile(kind, directory, paths, workspace, git_profile=GIT_PROFILES.DEFAULT, *, versioned=False):
    inside(directory, directory.parent)
    private_dir(directory)
    receipt = PILOT.strict_json(bounded_file(directory / "installation.json", MAX_JSON).read_bytes())
    profile = PILOT.strict_json(bounded_file(directory / "profile.json", MAX_JSON).read_bytes())
    registry = PILOT.strict_json(bounded_file(directory / "registry.json", MAX_JSON).read_bytes())
    installer, name = (FS, "filesystem-readonly-v1") if kind == "filesystem" else (GIT, git_profile)
    if kind == "git":
        GIT_PROFILES.verify_receipt(name, receipt)
    else:
        require(receipt.get("format") == "sou62-profile-installation/1", "profile_receipt_mismatch")
    require(receipt.get("profile") == profile, "profile_receipt_mismatch")
    for label, suffix in (("profile", "json"), ("registry", "json"), ("policy", "yaml")):
        asset = bounded_file(directory / f"{label}.{suffix}", MAX_JSON)
        require(FS.sha(asset) == receipt[f"{label}_sha256"],
                "profile_asset_changed")
    require(profile.get("format") == (installer.FORMAT if kind == "filesystem" else
            GIT_PROFILES.selected(name)[0]), "profile_format_changed")
    require(profile.get("workspace") == str(workspace) and profile.get("bwrapPath") == str(paths["bwrap"])
            and profile.get("bwrapSha256") == FS.sha(paths["bwrap"]), "profile_runtime_changed")
    require(profile.get("packageRoot") == str(directory / "package")
            and not (directory / "package").is_symlink(), "profile_package_path_changed")
    require(FS.tree_sha(directory / "package") == profile.get("packageTreeSha256"), "profile_package_changed")
    expected_registry = (installer.registry(json.loads((installer.ASSETS / "upstream-tools-list.json").read_text()))
                         if kind == "filesystem" else GIT_PROFILES.registry(name))
    require(registry == expected_registry
            and registry.get("registry_id") == name, "profile_registry_changed")
    require(FS.sha(directory / "policy.yaml") == FS.sha(installer.ASSETS / "policy.yaml" if kind == "filesystem"
            else GIT_PROFILES.policy_path(name)),
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
    result = {"profile": {"path": str(directory / "profile.json"), "sha256": receipt["profile_sha256"]},
              "registry_sha256": receipt["registry_sha256"], "package_tree_sha256": profile["packageTreeSha256"]}
    if versioned:
        result.update(format=profile["format"], policy_sha256=receipt["policy_sha256"],
                      installation_sha256=FS.sha(directory / "installation.json"))
    return result


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
    capacity.recheck("before_selection")
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
    capacity.recheck("before_asset_inputs")
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
    require(subprocess.check_output([str(paths["node"]), "--version"], text=True, timeout=10, env=utility_environment()).strip()
            == FS.NODE_VERSION, "node_version_mismatch")
    require("--ro-bind-fd" in subprocess.check_output([str(paths["bwrap"]), "--help"], text=True, timeout=10, env=utility_environment()),
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
    git_profile = GIT_PROFILES.from_selection(selection)
    roots = workspace_paths(selection, generation)
    if git_profile == "git-linked-worktree-readonly-v1":
        import pilot_linked_worktree as linked
        binding = linked.verify(selection.get("linked_worktree"), roots["git"])
        installed = PILOT.strict_json(bounded_file(generation / "git-profile/profile.json", MAX_JSON).read_bytes())
        require(installed.get("linkedWorktree") == binding, "linked_worktree_profile_binding_changed")
        outside_workspaces(paths.values(), {'git_metadata': Path(binding['commonDir']['path'])})
    else:
        require("linked_worktree" not in selection, "linked_worktree_cross_profile_binding")
    versioned = selection["format"] == GIT_PROFILES.SELECTION_V3
    if "prepared_workspaces" in selection:
        outside_workspaces(paths.values(), roots)
    profiles = {
        "filesystem": verify_profile("filesystem", generation / "filesystem-profile", paths,
                                     roots["filesystem"], versioned=versioned),
        "git": verify_profile("git", generation / "git-profile", paths, roots["git"], git_profile,
                              versioned=versioned),
    }
    if "prepared_workspaces" in selection:
        for kind in profiles:
            profile = PILOT.strict_json(Path(profiles[kind]["profile"]["path"]).read_bytes())
            identity = selection["prepared_workspaces"]["roots"][kind]
            require(profile.get("workspaceIdentity") == {key: identity[key] for key in ("device", "inode", "uid")},
                    "profile_workspace_identity_mismatch")
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


def wsl_input_locations(args, paths=None, workspaces=None, dependencies=None):
    """Observe every supplied location before executing any selected input.

    Mount inspection is pure: it never calls ldd, runtime --version, a selected
    program or a namespace probe. Symlinks are resolved before the mount match.
    """
    inputs = {"source_tree": ROOT}
    for role in (*PILOT.ROLES, "node_archive", "python_archive", "npm_cache", "wheelhouse",
                 "filesystem_workspace", "git_workspace"):
        path = getattr(args, role, None)
        if path is not None:
            inputs[role] = path
    inputs.update({"selected_" + role: path for role, path in (paths or {}).items()})
    inputs.update({"workspace_" + role: path for role, path in (workspaces or {}).items()})
    inputs.update({"dependency_" + role: path for role, path in (dependencies or {}).items()})
    with Path("/proc/self/mountinfo").open("r") as stream:
        mountinfo = stream.read(4 * 1024 * 1024 + 1)
    require(len(mountinfo) <= 4 * 1024 * 1024, "wsl_mount_observation_limit")
    checks = []
    for role, path in inputs.items():
        try:
            path = Path(path)
            require(path.is_absolute(), "absolute_wsl_input_required")
            resolved = path.resolve(strict=True)
            filesystem = wsl_preflight.mount_type(resolved.as_posix(), mountinfo)
            allowed = wsl_preflight.supported_path(resolved.as_posix(), filesystem, role)
            checks.append({"id": "filesystem_" + role, "status": "ready" if allowed else "unsupported",
                           "reason": "linux_ext4" if allowed else "unsupported_filesystem_or_location",
                           "filesystem": filesystem})
        except (OSError, ValueError, IndexError):
            checks.append({"id": "filesystem_" + role, "status": "unavailable", "reason": "path_or_mount_unreadable"})
    report = {"format": "sw-wsl-preparation-input-locations/1", "scope": "locations_only_no_execution",
              "status": "ready" if all(row["status"] == "ready" for row in checks) else "unsupported",
              "checks": checks}
    if report["status"] != "ready":
        raise WslPreparationFailure(report)
    return report


def wsl_preparation_preflight(args, paths=None, *, workspaces=None, dependencies=None):
    """Explicit WSL2 preparation only; native defaults and run guards stay strict.

    The first pass observes static prerequisites before creating a generation.
    The second pass receives selected_paths' verified inputs and probes the
    existing namespace/bubblewrap prerequisites before either installer runs.
    """
    root = args.wsl_root
    require(root.is_absolute() and root.resolve(strict=True) == root,
            "canonical_existing_wsl_root_required")
    require(getattr(args, "git_profile", GIT_PROFILES.DEFAULT) == GIT_PROFILES.DEFAULT,
            "wsl_extended_git_profile_not_qualified")
    if args.output is not None:
        require(args.output.is_absolute() and args.output.resolve() == args.output
                and args.output.is_relative_to(root), "wsl_preparation_output_outside_stage")
    # Full inspect executes namespace and selected-bwrap probes after its own
    # mount checks. Guard source, caches and workspace paths as well first.
    locations = wsl_input_locations(args, paths, workspaces, dependencies) if paths is not None else None
    report = wsl_preflight.inspect(root, paths, output=args.output)
    checks = {row["id"]: row for row in report.get("checks", [])}
    required = {"wsl_kernel", "architecture", "distribution", "process_owner",
                "filesystem_stage_root", "stage_owner"}
    if args.output is not None:
        required.add("filesystem_report_output")
    static_ready = (required.issubset(checks)
                    and all(row.get("status") == "ready" for key, row in checks.items()
                            if key != "selected_runtime"))
    if not static_ready or (paths is not None and report.get("status") != "ready"):
        raise WslPreparationFailure(report)
    if locations is None:
        locations = wsl_input_locations(args)
    report["input_locations"] = locations
    return report


def prepare(args):
    GIT_PROFILES.binding(getattr(args, "git_profile", GIT_PROFILES.DEFAULT))
    if getattr(args, "wsl_root", None) is None:
        supported_platform()
    else:
        wsl_preparation_preflight(args)
    before = PILOT.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit,
            "candidate_source_mismatch")
    requested = requested_workspaces(args)
    linked_binding = None
    binding_path = getattr(args, "git_worktree_binding", None)
    if getattr(args, "git_profile", GIT_PROFILES.DEFAULT) == "git-linked-worktree-readonly-v1":
        require(requested is not None and binding_path is not None, "linked_worktree_explicit_selection_required")
        import pilot_linked_worktree as linked
        linked_binding = linked.load(binding_path, args.git_workspace)
    else:
        require(binding_path is None, "linked_worktree_cross_profile_binding")
    for name in ("node_archive", "python_archive", "npm_cache", "wheelhouse"):
        path = getattr(args, name)
        require(path is None or path.is_absolute(), f"absolute_{name}_required")
    require(args.output is not None and args.output.is_absolute(), "absolute_output_required")
    require(not args.output.resolve().is_relative_to(ROOT), "output_must_be_outside_checkout")
    if requested:
        require(args.output.resolve() == args.output, "canonical_preparation_output_required")
        for identity in requested["roots"].values():
            root = Path(identity["path"])
            require(not args.output.resolve().is_relative_to(root)
                    and not root.is_relative_to(args.output.resolve()), "preparation_overlaps_workspace")
    if linked_binding is not None:
        metadata_root = Path(linked_binding['commonDir']['path'])
        for name in ('npm_cache', 'wheelhouse', 'node_archive', 'python_archive'):
            selected_input = getattr(args, name, None)
            require(selected_input is None or not selected_input.resolve().is_relative_to(metadata_root),
                    'linked_worktree_inputs_overlap_metadata')
        require(not args.output.resolve().is_relative_to(metadata_root)
                and not metadata_root.is_relative_to(args.output.resolve()), "linked_worktree_preparation_overlaps_metadata")
    output = private_dir(args.output, create=not args.output.exists())
    with SELECTION_LOCK.hold(output, exclusive=True):
        return prepare_locked(args, output, requested, linked_binding)


def prepare_locked(args, output, requested, linked_binding=None):
    git_profile = getattr(args, "git_profile", GIT_PROFILES.DEFAULT)
    wsl = getattr(args, "wsl_root", None) is not None
    if wsl:
        wsl_input_locations(args)
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
        selection, _ = (verify_generation(generation, args.expected_commit, probe_native=False)
                        if wsl else verify_generation(generation, args.expected_commit))
        require(FS.sha(selection) == record["selection_sha256"], "completion_marker_changed")
        require(GIT_PROFILES.from_selection(PILOT.strict_json(selection.read_bytes())) == git_profile,
                "git_profile_selection_differs_use_rebuild")
        require(PILOT.strict_json(selection.read_bytes()).get("prepared_workspaces") == requested,
                "existing_workspace_selection_differs_use_rebuild")
        result = {"status": "reused", "selection": str(selection), "generation": record["generation"]}
        if wsl:
            retained = PILOT.strict_json(selection.read_bytes())
            _, paths = PILOT.validate_selection(retained, args.expected_commit)
            roots = workspace_paths(retained, generation)
            dependencies = {}
            # verify_generation(False) has already verified these profile
            # bytes and library hashes without execution. Include the actual
            # package interpreter and libraries in the mount gate as well.
            for kind in ("filesystem", "git"):
                profile = PILOT.strict_json(bounded_file(generation / (kind + "-profile") / "profile.json", MAX_JSON).read_bytes())
                dependencies[kind + "_runtime"] = Path(profile["runtimePath"])
                dependencies[kind + "_package"] = Path(profile["packageRoot"])
                for index, item in enumerate(profile["libraries"]):
                    dependencies[kind + "_library_" + str(index)] = Path(item["path"])
            result.update(platform="wsl2-linux-x86_64",
                          wsl_preflight=wsl_preparation_preflight(args, paths, workspaces=roots,
                                                                 dependencies=dependencies))
            for role in PILOT.EXECUTABLE_ROLES:
                check_native(paths[role])
        return result
    generation = generations / uuid.uuid4().hex
    generation.mkdir(mode=0o700)
    capacity.bind(generation)
    paths = selected_paths(args, generation)
    wsl_report = (wsl_preparation_preflight(args, paths)
                  if getattr(args, "wsl_root", None) is not None else None)
    fs_workspace, git_workspace = generation / "filesystem-workspace", generation / "git-workspace"
    if requested:
        roots = workspace_paths({"prepared_workspaces": requested}, generation)
        outside_workspaces([*paths.values(), *[getattr(args, name) for name in
            ("node_archive", "python_archive", "npm_cache", "wheelhouse") if getattr(args, name)]], roots)
        if linked_binding is not None:
            outside_workspaces(paths.values(), {'git_metadata': Path(linked_binding['commonDir']['path'])})
        validate_existing_workspaces(paths, roots, git_profile, linked_binding)
        fs_workspace, git_workspace = roots["filesystem"], roots["git"]
    else:
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
        capacity.recheck("before_" + kind + "_install")
        log_path = generation / (kind + "-install.log")
        with log_path.open("xb") as log:
            os.fchmod(log.fileno(), 0o600)
            try:
                if kind == "filesystem":
                    FS.install(generation / "filesystem-profile", fs_workspace, paths["node"],
                               paths["bwrap"], paths["npm"], npm_cache=npm_cache,
                               offline=not args.allow_download, log=log)
                else:
                    installer = GIT.install if git_profile == GIT_PROFILES.DEFAULT else (
                        lambda *a, **kw: GIT_PROFILES.install(git_profile, *a, **kw))
                    installer(generation / "git-profile", git_workspace, paths["git"], FS.sha(paths["git"]),
                                paths["bwrap"], paths["git_launcher"], python_archive=args.python_archive,
                                wheelhouse=args.wheelhouse, allow_download=args.allow_download, log=log,
                                **({"linked_worktree_binding": linked_binding} if linked_binding is not None else {}))
            except subprocess.CalledProcessError as error:
                # Never read the log (even a suffix): arbitrary installer output
                # can contain secrets and the failed log can exceed the size cap.
                raise InstallerFailure(kind, error.returncode,
                                       log_path.relative_to(output).as_posix()) from None
        require(log_path.stat().st_size <= 1024 * 1024, kind + "_installer_log_limit")
        if requested or (kind == "git" and git_profile != GIT_PROFILES.DEFAULT):
            identity = requested["roots"][kind] if requested else root_identity(git_workspace)
            bind_profile_workspace(generation / (kind + "-profile"), identity)
    profiles = {
        "filesystem": verify_profile("filesystem", generation / "filesystem-profile", paths, fs_workspace,
                                     versioned=True),
        "git": verify_profile("git", generation / "git-profile", paths, git_workspace, git_profile, versioned=True),
    }
    selection = {"format": GIT_PROFILES.SELECTION_V3, "source": PILOT.source(),
                 "git_selection": GIT_PROFILES.binding(git_profile),
                 "expected_refusal": {"verdict": args.refusal_verdict, "rule": args.refusal_rule},
                 "files": {role: {"path": str(paths[role]), "sha256": FS.sha(paths[role])}
                           for role in PILOT.ROLES}, "prepared_profiles": profiles}
    if linked_binding is not None:
        selection["linked_worktree"] = linked_binding
    if requested:
        selection["prepared_workspaces"] = requested
        require(requested_workspaces(args) == requested, "selected_workspace_changed")
        validate_existing_workspaces(paths, roots, git_profile, linked_binding)
    selection_path = generation / "selection.json"
    write_json(selection_path, selection)
    verify_generation(generation, args.expected_commit)
    record = {"format": "sw-pilot-preparation/1", "generation": generation.name,
              "selection_sha256": FS.sha(selection_path), "status": "prepared-not-active"}
    publish_marker(output, record)
    result = {"status": "prepared-not-active", "selection": str(selection_path), "generation": generation.name}
    if wsl_report is not None:
        result.update(platform="wsl2-linux-x86_64", wsl_preflight=wsl_report)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    capacity.add_arguments(parser)
    parser.add_argument("--prepare", action="store_true", help="explicitly prepare and select a verified generation")
    parser.add_argument("--rebuild", action="store_true", help="prepare a new generation and retain the old one")
    parser.add_argument("--allow-download", action="store_true", help="permit locked npm/pip and pinned Python download")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--wsl-root", type=Path,
                        help="Explicit opt-in WSL2 preparation in a private Linux ext4 /home stage; output must stay inside it")
    parser.add_argument("--filesystem-workspace", type=Path, help="canonical existing owned read-only root")
    parser.add_argument("--git-worktree-binding", type=Path, help="explicit private linked-worktree selection manifest")
    parser.add_argument("--git-workspace", type=Path, help="canonical existing supported standalone repository")
    parser.add_argument("--git-profile", default=GIT_PROFILES.DEFAULT, action=GIT_PROFILES.SingleProfile,
                        help="select exactly one reviewed Git registry id; combined capabilities refuse")
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
    if args.capacity_plan:
        if args.prepare or args.guard_capacity:
            parser.error("--capacity-plan is read-only; use it without --prepare or --guard-capacity")
        print(json.dumps(capacity.cli_plan("assets", args), sort_keys=True))
        return 0
    if args.guard_capacity and not args.prepare:
        parser.error("--guard-capacity requires --prepare")
    if not args.prepare:
        try:
            workspaces = requested_workspaces(args)
            git_selection = GIT_PROFILES.binding(args.git_profile)
        except (OSError, ValueError) as error:
            print(json.dumps({"status": "failed", "executed": False, "reason": str(error)[:240]}))
            return 2
        wsl_report = None
        if args.wsl_root is not None:
            try:
                wsl_report = wsl_preparation_preflight(args)
            except WslPreparationFailure as error:
                print(json.dumps({"status": "failed", "executed": False,
                                  "reason": str(error), "wsl_preflight": error.report}))
                return 2
            except (OSError, ValueError):
                print(json.dumps({"status": "failed", "executed": False,
                                  "reason": "wsl_preparation_input_invalid"}))
                return 2
            supported = True
        else:
            supported = platform.system() == "Linux" and platform.machine() == "x86_64"
        if supported and args.wsl_root is None:
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
                          "workspaces": workspaces or {"mode": "generated-demo"},
                          "git_selection": git_selection,
                          "capability": "read-only; all project content is untrusted",
                          "scope": ("WSL2 Ubuntu 24.04 x86-64; original filesystem and Git MCP only"
                                    if wsl_report is not None else
                                    "native Ubuntu 24.04 x86-64; original filesystem and Git MCP only"),
                          **({"wsl_preflight": wsl_report} if wsl_report is not None else {}),
                          "refused_scope": ["built-in host tools and project Claude/MCP/hooks configuration",
                              "writes, outside symlink targets and server network access",
                              "unselected Git layouts, worktrees, submodules, active hooks, helpers and special files"],
                          "workspace_validation": "native profile validators run only with --prepare; unsupported layouts are refused without repair",
                          "source": PILOT.source(),
                          "inputs": {role: {"path": str(getattr(args, role)),
                              "sha256": FS.sha(getattr(args, role)) if getattr(args, role).is_file() else None}
                              for role in PILOT.ROLES if getattr(args, role) is not None},
                          "profiles": {kind: {"format": installer.FORMAT if kind == "filesystem" else
                              git_selection["profile_format"],
                              "upstream_identity_sha256": FS.sha(installer.ASSETS / "upstream-identity.json"),
                              "policy_sha256": FS.sha(installer.ASSETS / "policy.yaml") if kind == "filesystem" else
                              git_selection["policy_sha256"]}
                              for kind, installer in (("filesystem", FS), ("git", GIT))},
                          "node_archive": {"url": NODE_URL, "sha256": NODE_ARCHIVE_SHA256},
                          "next": "supply listed inputs, then add --prepare; qualification is a separate command"}))
        return 0
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", args.expected_commit or ""), "full_expected_commit_required")
        with capacity.checked("assets", args):
            print(json.dumps(prepare(args)))
        return 0
    except capacity.Refusal as error:
        print(json.dumps(error.report, sort_keys=True))
        return 2
    except InstallerFailure as error:
        print(json.dumps({"status": "failed", "reason": str(error),
                          "exit_code": error.exit_code, "private_log": error.private_log}))
        return 2
    except WslPreparationFailure as error:
        print(json.dumps({"status": "failed", "reason": str(error), "wsl_preflight": error.report}))
        return 2
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError, subprocess.SubprocessError,
            PILOT.Failure) as error:
        print(json.dumps({"status": "failed", "reason": str(error)[:1500]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
