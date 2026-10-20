# SPDX-License-Identifier: Apache-2.0
"""Opt-in installed-pilot prerequisites; never evidence of active protection."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess


def kernel_kind(system, release):
    if system != "Linux":
        return "non_linux"
    release = release.lower()
    if "microsoft" not in release:
        return "native_linux"
    if "wsl2" in release or "microsoft-standard" in release:
        return "wsl2"
    return "wsl1_or_unknown"


def mount_type(path, mountinfo):
    """Use the longest component match, including nested Windows bind mounts."""
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)
    candidates = []
    selected = PurePosixPath(path)
    for line in mountinfo.splitlines():
        left, right = line.split(" - ", 1)
        fields, filesystem = left.split(), right.split()[0]
        mount = PurePosixPath(unescape(fields[4]))
        if selected == mount or mount in selected.parents:
            candidates.append((len(mount.parts), filesystem))
    if not candidates:
        raise ValueError("mount_not_observed")
    return max(candidates, key=lambda row: row[0])[1]


def supported_path(path, filesystem, role):
    path = PurePosixPath(path)
    return filesystem == "ext4" and (
        role not in ("stage_root", "report_output") or path.is_relative_to("/home")
    )


def probe(command):
    """No shell, inherited credentials, retained child text or host-setting writes."""
    try:
        result = subprocess.run(
            [str(item) for item in command], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd="/", timeout=5,
            check=False,
        )
        return "ready" if result.returncode == 0 else "incompatible"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def inspect(root, paths=None, *, output=None):
    """paths must already have passed the existing exact-selection validator."""
    report = {
        "format": "sw-wsl-preflight/1",
        "scope": "prerequisites_only",
        "active_protection": "not_measured",
        "runtime_qualification": "not_executed",
        "checks": [],
    }

    def add(name, status, reason, next_step, **evidence):
        report["checks"].append(dict(id=name, status=status, reason=reason,
                                     next_step=next_step, evidence=evidence))

    def finish():
        states = {row["status"] for row in report["checks"]}
        report["status"] = next((s for s in ("unsupported", "incompatible", "unavailable")
                                 if s in states), "ready")
        return report

    system, release = platform.system(), platform.release()
    kind = kernel_kind(system, release)
    add("wsl_kernel", "ready" if kind == "wsl2" else "unsupported", kind,
        "Run inside Ubuntu 24.04 on actual WSL2; a native Linux CI run is not WSL evidence.",
        kernel=release[:256], machine=platform.machine())
    if kind != "wsl2":
        return finish()
    add("architecture", "ready" if platform.machine() == "x86_64" else "unsupported",
        "linux_x86_64" if platform.machine() == "x86_64" else "architecture_outside_scope",
        "Use the x86-64 runtime covered by the existing installed-pilot harness.")
    try:
        distro = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                      if "=" in line and not line.startswith("#"))
        ubuntu = distro.get("ID", "").strip('"') == "ubuntu"
        version = distro.get("VERSION_ID", "").strip('"')
        add("distribution", "ready" if ubuntu and version == "24.04" else "unsupported",
            "ubuntu_24_04" if ubuntu and version == "24.04" else "distribution_outside_scope",
            "Use the Ubuntu 24.04 WSL distribution.")
        mountinfo = Path("/proc/self/mountinfo").read_text()
    except (OSError, ValueError):
        add("system_observation", "unavailable", "system_metadata_unreadable",
            "Make /etc/os-release and /proc/self/mountinfo readable in this session.")
        return finish()
    uid = os.geteuid()
    add("process_owner", "ready" if uid != 0 else "unsupported",
        "unprivileged_user" if uid != 0 else "root_session",
        "Run as the ordinary WSL user, without sudo.", uid=uid)
    selected = {"stage_root": Path(root)}
    selected.update(paths or {})
    if output is not None:
        selected["report_output"] = Path(output)
    for role, path in selected.items():
        try:
            if not path.is_absolute():
                raise ValueError("absolute_path_required")
            resolved = path.resolve(strict=role != "report_output")
            filesystem = mount_type(resolved.as_posix(), mountinfo)
            # This first qualification deliberately supports the Linux ext4 VHD.
            # Unknown, DrvFS/9p, UNC/CIFS and nested Windows mounts fail closed.
            allowed = supported_path(resolved.as_posix(), filesystem, role)
            add("filesystem_" + role, "ready" if allowed else "unsupported",
                "linux_ext4" if allowed else "unsupported_filesystem_or_location",
                "Use Linux ext4 paths; stage and evidence roots must be under /home, not /mnt or UNC.",
                filesystem=filesystem)
            if role == "stage_root":
                meta = resolved.stat()
                private = stat.S_ISDIR(meta.st_mode) and meta.st_uid == uid and meta.st_mode & 0o077 == 0
                add("stage_owner", "ready" if private else "incompatible",
                    "private_owned_directory" if private else "stage_not_private_or_owned",
                    "Create a dedicated directory under /home owned by this user with mode 0700.")
        except (OSError, ValueError, IndexError):
            add("filesystem_" + role, "unavailable", "path_or_mount_unreadable",
                "Supply an existing absolute Linux path and readable mount metadata.")
    # Never execute a selected binary from a rejected Windows mount.
    if any(row["status"] != "ready" for row in report["checks"]):
        return finish()
    if not paths:
        add("selected_runtime", "unavailable", "exact_runtime_selection_required",
            "Supply the existing pilot selection and expected commit to qualify runtime prerequisites.")
        return finish()
    report["selected_sha256"] = {}
    for role, path in paths.items():
        try:
            with Path(path).open("rb") as stream:
                report["selected_sha256"][role] = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError:
            add("identity_" + role, "unavailable", "selected_input_unreadable",
                "Restore the selected input and regenerate its exact selection.")
    if any(row["status"] != "ready" for row in report["checks"]):
        return finish()
    status = probe(["/usr/bin/unshare", "--user", "--map-root-user", "/usr/bin/true"])
    add("user_namespace", status, "namespace_probe_" + status,
        "Use an environment allowing unprivileged user namespaces; do not relax host security settings.")
    status = probe([paths["bwrap"], "--die-with-parent", "--unshare-user",
                    "--unshare-pid", "--unshare-net", "--ro-bind", "/", "/",
                    "--proc", "/proc", "--dev", "/dev", "/usr/bin/true"])
    add("bubblewrap", status, "bubblewrap_probe_" + status,
        "Use the selected supported bubblewrap executable and an environment permitting its namespaces.")
    report["resource_budgets"] = {
        "status": "not_measured",
        "advertised": False,
        "reason": "This pilot preflight does not establish cgroup delegation or active resource limits.",
    }
    return finish()
