#!/usr/bin/env python3
"""Inspect one owned preparation generation; remove it only with a matching confirmation."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MAX_ENTRIES = 200000
MAX_BYTES = 2 * 1024**3
RUNTIME_LAYOUT = {"node", "filesystem-profile", "git-profile", "filesystem-workspace", "git-workspace",
                  "filesystem-install.log", "git-install.log", "selection.json"}
NATIVE_LAYOUT = {"tmp", "git-src", "bwrap-src", "bwrap-build", "git.tar.xz", "bwrap.tar.xz",
                 "git-build.log", "bwrap-build.log", "bwrap-setup.log", "receipt.json"}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NATIVE = load("cleanup_native", "prepare-native-pilot-prerequisites.py")
PREP = load("cleanup_preparation", "prepare-installed-pilot.py")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    require(Path(path).stat().st_size <= MAX_BYTES, "input_byte_limit")
    return NATIVE.digest(path)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def json_input(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and info.st_size <= 65536, "owned_bounded_receipt_required")
    value = PREP.PILOT.strict_json(path.read_bytes())
    require(isinstance(value, dict), "object_receipt_required")
    return value


def private(path, modes=(0o700,)):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) in modes, "owned_private_directory_required")


def target_path(prefix, generation):
    require(sys.platform == "linux" and os.geteuid() != 0, "ordinary_linux_user_required")
    require(Path("/proc/self/uid_map").read_text().split() == ["0", "0", "4294967295"],
            "host_user_namespace_required")
    require(prefix.is_absolute() and prefix.resolve(strict=True) == prefix,
            "canonical_absolute_prefix_required")
    require(not prefix.is_relative_to(ROOT) and not (prefix / ".git").exists(), "source_checkout_refused")
    require(re.fullmatch(r"[0-9a-f]{32}", generation) is not None, "generation_id_required")
    private(prefix)
    private(prefix / "generations")
    target = prefix / "generations" / generation
    require(target.resolve(strict=True) == target, "generation_symlink_refused")
    private(target, (0o500, 0o700))
    return target


def no_mounts(target):
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), line.split()[4])
        require(not Path(mount).is_relative_to(target), "generation_mount_refused")


def inventory(target):
    no_mounts(target)
    root_device = target.lstat().st_dev
    rows, total = [], 0
    def unreadable(error):
        raise error
    for base, directories, files in os.walk(target, followlinks=False, onerror=unreadable):
        require(len(Path(base).relative_to(target).parts) < 64, "generation_depth_limit")
        for name in sorted(directories + files):
            path = Path(base) / name
            info = path.lstat()
            require(info.st_dev == root_device and info.st_uid == os.getuid(), "generation_owner_or_device_changed")
            require(not info.st_mode & (stat.S_ISUID | stat.S_ISGID), "privileged_entry_refused")
            relative = path.relative_to(target).as_posix()
            require(len(relative.encode()) <= 4096 and len(rows) < MAX_ENTRIES, "generation_entry_limit")
            if stat.S_ISLNK(info.st_mode):
                require(path.resolve(strict=True).is_relative_to(target), "generation_link_escape")
                identity = ["link", os.readlink(path)]
            elif stat.S_ISDIR(info.st_mode):
                require(not info.st_mode & 0o022, "shared_directory_refused")
                identity = ["directory"]
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "special_or_hardlinked_entry_refused")
                require(not info.st_mode & 0o022, "shared_file_refused")
                total += info.st_size
                require(total <= MAX_BYTES, "generation_byte_limit")
                identity = ["file", info.st_size, sha(path)]
            rows.append([relative, info.st_ino, info.st_dev, info.st_mode, *identity])
    return {"entries": len(rows), "bytes": total, "sha256": hashlib.sha256(canonical(rows)).hexdigest()}


def validate_receipt(target, marker):
    if marker["format"] == "sw-native-pilot-current/1":
        receipt_path = target / "receipt.json"
        if not receipt_path.exists():
            return None
        receipt = json_input(receipt_path)
        private(target, (0o500,))
        require(set(path.name for path in target.iterdir()).issubset(NATIVE_LAYOUT), "unexpected_native_layout")
        require(receipt.get("format") == "sw-native-pilot-prerequisites/1"
                and receipt.get("status") == "built-not-qualified"
                and re.fullmatch(r"[0-9a-f]{40}", receipt.get("source_commit", ""))
                and receipt.get("flags") == {"git": list(NATIVE.GIT_FLAGS), "bwrap": list(NATIVE.BWRAP_FLAGS)},
                "native_receipt_identity_changed")
        require(receipt.get("generation_tree_sha256") == NATIVE.tree_digest(target, completed=True),
                "native_generation_tree_changed")
        for kind, row in NATIVE.SOURCES.items():
            require(receipt["archives"][kind] == {"url": row[2], "sha256": row[3]}, "native_archive_identity_changed")
            binary = target / ("git-src/git" if kind == "git" else "bwrap-build/bwrap")
            require(receipt["binaries"][kind]["path"] == str(binary)
                    and receipt["binaries"][kind]["sha256"] == sha(binary), "native_binary_identity_changed")
        return {"format": receipt["format"], "sha256": sha(receipt_path), "source": receipt["source_commit"]}
    selection_path = target / "selection.json"
    if not selection_path.exists():
        return None
    selection = json_input(selection_path)
    require(set(path.name for path in target.iterdir()).issubset(RUNTIME_LAYOUT), "unexpected_preparation_layout")
    require(selection.get("format") == "sw-installed-pilot-selection/2"
            and re.fullmatch(r"[0-9a-f]{40}", selection.get("source", {}).get("commit", "")),
            "preparation_selection_changed")
    require(set(selection.get("files", {})) == set(PREP.PILOT.ROLES), "selection_roles_changed")
    paths = {}
    for role, value in selection["files"].items():
        path = Path(value["path"])
        require(path.is_absolute() and path.is_file() and sha(path) == value["sha256"], "selected_asset_changed")
        paths[role] = path
    profiles = {kind: PREP.verify_profile(kind, target / (kind + "-profile"), paths,
                target / (kind + "-workspace")) for kind in ("filesystem", "git")}
    require(selection.get("prepared_profiles") == profiles, "preparation_profile_identity_changed")
    return {"format": selection["format"], "sha256": sha(selection_path), "source": selection["source"]["commit"]}


def in_target(value, target):
    value = value.removesuffix(" (deleted)")
    return value == str(target) or value.startswith(str(target) + "/")


def active_use(target):
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or int(process.name) == os.getpid():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            state = (process / "stat").read_text().rsplit(")", 1)[1].split()[0]
            if state == "Z":
                continue
            for name in ("cwd", "exe", "root"):
                if in_target(os.readlink(process / name), target):
                    return True
            for name in ("cmdline", "environ"):
                with (process / name).open("rb") as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    return True
                if any(in_target(os.fsdecode(word).split("=", 1)[-1], target) for word in raw.split(b"\0")):
                    return True
            with (process / "maps").open() as stream:
                for index, line in enumerate(stream):
                    if index > 100000 or (len(line.split(None, 5)) == 6
                                          and in_target(line.split(None, 5)[5].strip(), target)):
                        return True
            for index, descriptor in enumerate((process / "fd").iterdir()):
                if index > 10000 or in_target(os.readlink(descriptor), target):
                    return True
        except FileNotFoundError:
            if process.exists():
                return True
        except (PermissionError, ProcessLookupError):
            if process.exists():
                return True
    return False


def inspect(prefix, generation):
    target = target_path(prefix, generation)
    marker = json_input(prefix / "current.json")
    require(marker.get("format") in ("sw-pilot-preparation/1", "sw-native-pilot-current/1")
            and re.fullmatch(r"[0-9a-f]{32}", marker.get("generation", "")), "recognized_current_marker_required")
    digest_key = "receipt_sha256" if marker["format"] == "sw-native-pilot-current/1" else "selection_sha256"
    require(re.fullmatch(r"[0-9a-f]{64}", marker.get(digest_key, "")), "current_marker_digest_required")
    if marker["format"] == "sw-pilot-preparation/1":
        require(marker.get("status") == "prepared-not-active", "current_marker_status_invalid")
    result = {"format": "sw-pilot-cleanup/1", "status": "plan", "prefix": str(prefix),
              "generation": generation, "confirmation": None, "classification": "current"}
    if marker["generation"] == generation:
        return result
    summary = inventory(target)
    receipt = validate_receipt(target, marker)
    if receipt is None:
        layout = NATIVE_LAYOUT if marker["format"] == "sw-native-pilot-current/1" else RUNTIME_LAYOUT
        classification = "incomplete" if set(path.name for path in target.iterdir()).issubset(layout) else "unrecognized"
        result.update(classification=classification, inventory=summary)
        return result
    if active_use(target):
        result.update(classification="active-or-uncertain", inventory=summary)
        return result
    identity = target.lstat()
    binding = {"prefix": str(prefix), "generation": generation,
               "inode": identity.st_ino, "device": identity.st_dev, "mode": identity.st_mode,
               "marker_sha256": sha(prefix / "current.json"), "inventory": summary, "receipt": receipt}
    result.update(classification="inactive", inventory=summary, receipt=receipt,
                  confirmation=hashlib.sha256(canonical(binding)).hexdigest())
    return result


def open_child(directory_fd, name):
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
    how = OpenHow(os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, 0, 0x01 | 0x04 | 0x08)
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.syscall(437, directory_fd, os.fsencode(name), ctypes.byref(how), ctypes.sizeof(how))
    require(descriptor >= 0, "directory_mount_or_link_refused")
    return descriptor


def erase(directory_fd, device, preserve=frozenset()):
    info = os.fstat(directory_fd)
    require(info.st_dev == device and info.st_uid == os.getuid(), "removal_directory_changed")
    os.fchmod(directory_fd, 0o700)
    for name in sorted(os.listdir(directory_fd), key=lambda value: value in ("receipt.json", "selection.json")):
        if name in preserve:
            continue
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(info.st_dev == device and info.st_uid == os.getuid(), "removal_entry_changed")
        if stat.S_ISDIR(info.st_mode):
            child = open_child(directory_fd, name)
            try:
                require(os.fstat(child).st_ino == info.st_ino, "removal_directory_replaced")
                erase(child, device)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            require(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), "removal_special_entry_refused")
            os.unlink(name, dir_fd=directory_fd)


def apply(prefix, generation, confirmation):
    plan = inspect(prefix, generation)
    require(plan["classification"] == "inactive" and confirmation == plan["confirmation"], "removal_confirmation_refused")
    target = target_path(prefix, generation)
    parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_fd = None
    try:
        directory_fd = open_child(parent_fd, generation)
        info = os.fstat(directory_fd)
        require(info.st_ino == target.lstat().st_ino and info.st_dev == target.lstat().st_dev,
                "removal_target_replaced")
        require(inspect(prefix, generation)["confirmation"] == confirmation, "removal_changed_since_plan")
        no_mounts(target)
        preserve = {"filesystem-workspace", "git-workspace"} if plan["receipt"]["format"] == "sw-installed-pilot-selection/2" else set()
        erase(directory_fd, info.st_dev, preserve=preserve)
        require(os.stat(generation, dir_fd=parent_fd, follow_symlinks=False).st_ino == info.st_ino,
                "removal_target_replaced")
        if not preserve:
            os.rmdir(generation, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)
    return {**plan, "status": "assets-removed-workspaces-retained" if preserve else "removed",
            "preserved": sorted(preserve), "confirmation": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    try:
        report = apply(args.prefix, args.generation, args.confirm) if args.remove else inspect(args.prefix, args.generation)
    except Exception as error:
        message = str(error)
        report = {"format": "sw-pilot-cleanup/1", "status": "refused",
                  "reason": message if re.fullmatch(r"[a-z][a-z0-9_]{0,100}", message) else "cleanup_input_or_state_invalid"}
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "refused" else 0


if __name__ == "__main__":
    raise SystemExit(main())
