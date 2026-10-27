# SPDX-License-Identifier: Apache-2.0
"""Bounded, descriptor-relative readers for owner-editable prepared-run state.

Local receipts are evidence selections, never authentication or execution proof.
No reader creates files, changes permissions, starts processes or follows links.
"""
import hashlib
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

if sys.platform.startswith("linux"):
    import fcntl

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("run_state_audit", ROOT / "scripts/pilot_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
RUN_NAME = re.compile(r"soup-wall-run-([A-Za-z0-9_-]{1,80})\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECORD = 65536


class Refusal(ValueError):
    """A finite public reason; never include an exception message or path."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def platform():
    require(sys.platform.startswith("linux") and hasattr(os, "O_NOFOLLOW"), "linux_required")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def strict(raw):
    require(AUDIT.REPORT._bounded_json_depth(raw), "invalid_record")
    try:
        return json.loads(raw, object_pairs_hook=AUDIT.REPORT._pair_object,
                          parse_constant=lambda _: require(False, "invalid_record"))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("invalid_record") from None


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def same_object(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode]


def safe_component(name):
    require(type(name) is str and name not in ("", ".", "..") and "/" not in name
            and "\\" not in name and "\0" not in name, "unsafe_name")


class Directory:
    def __init__(self, path, parent=None, name=None, state_parent=False):
        platform()
        self.path = Path(path)
        self.parent, self.name, self.fd = parent, name, None
        require(self.path.is_absolute() and ".." not in self.path.parts, "canonical_parent_required")
        try:
            if parent is None:
                self.fd = AUDIT.REPORT._open_dir_nofollow(self.path)
            else:
                safe_component(name)
                self.fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=parent.fd)
            info = os.fstat(self.fd)
            if state_parent:
                require(self.path != Path("/") and info.st_uid in (0, os.getuid())
                        and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "unsafe_state_parent")
            else:
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "private_owner_required")
            self.object = same_object(info)
            self.check()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def check(self):
        require(same_object(os.fstat(self.fd)) == self.object, "directory_changed")
        if self.parent is not None:
            self.parent.check()
            named = os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
        else:
            fd = AUDIT.REPORT._open_dir_nofollow(self.path)
            try:
                named = os.fstat(fd)
            finally:
                os.close(fd)
        require(same_object(named) == self.object, "directory_changed")

    def child(self, name):
        self.check()
        return Directory(self.path / name, self, name)

    def names(self, limit):
        self.check()
        result = []
        with os.scandir(self.fd) as entries:
            for entry in entries:
                require(len(result) < limit, "enumeration_limit")
                result.append(entry.name)
        self.check()
        return sorted(result)

    def read(self, name, limit=MAX_RECORD):
        safe_component(name)
        self.check()
        named_before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        require(stat.S_ISREG(named_before.st_mode) and named_before.st_uid == os.getuid()
                and stat.S_IMODE(named_before.st_mode) == 0o600 and named_before.st_nlink == 1,
                "private_regular_file_required")
        require(named_before.st_size <= limit, "record_size_limit")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                    "private_regular_file_required")
            require(before.st_size <= limit, "record_size_limit")
            chunks, count = [], 0
            while count <= limit:
                block = os.read(fd, min(65536, limit + 1 - count))
                if not block:
                    break
                chunks.append(block)
                count += len(block)
            body = b"".join(chunks)
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            require(len(body) == before.st_size and len(body) <= limit
                    and identity(before) == identity(os.fstat(fd)) == identity(named), "record_changed")
            self.check()
            return body, identity(before)
        finally:
            os.close(fd)

    def json(self, name, limit=MAX_RECORD):
        return strict(self.read(name, limit)[0])


def run_id(name):
    match = RUN_NAME.fullmatch(name)
    require(match is not None, "invalid_run_identity")
    return match[1]


def receipt(run):
    value = run.json("audit-run.json")
    require(type(value) is dict and set(value) == {"format", "run_id", "source_commit",
            "selection_sha256", "policy_sha256", "registry_sha256", "binary_sha256", "retention",
            "retention_sha256", "directory_device", "directory_inode"}, "audit_receipt_invalid")
    require(value["format"] == AUDIT.FORMAT and value["run_id"] == run_id(run.path.name)
            and value["retention"] == AUDIT.LIMITS
            and all(type(item) is int for item in value["retention"].values()), "audit_receipt_invalid")
    for key in ("selection_sha256", "policy_sha256", "registry_sha256", "binary_sha256", "retention_sha256"):
        require(type(value[key]) is str and SHA.fullmatch(value[key]), "audit_receipt_invalid")
    require(type(value["source_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]),
            "audit_receipt_invalid")
    require(value["retention_sha256"] == AUDIT.digest(dict(AUDIT.LIMITS, directory=str(run.path / "audit"))),
            "audit_receipt_invalid")
    with run.child("audit") as audit:
        require(type(value["directory_device"]) is int and type(value["directory_inode"]) is int
                and audit.object[:2] == [value["directory_device"], value["directory_inode"]],
                "audit_directory_changed")
    return value


def finished(run, selected):
    value = run.json("audit-finished.json")
    require(value == {"format": AUDIT.FORMAT, "run_id": selected["run_id"], "owned_processes_stopped": True}
            and value["owned_processes_stopped"] is True, "finished_record_invalid")


@contextmanager
def audit_writer_lock(run):
    """Use the accepted writer.lock inode; never create or rewrite a lock file."""
    with run.child("audit") as audit:
        raw, selected = audit.read("writer.lock", 0)
        require(raw == b"", "audit_writer_lock_invalid")
        fd = os.open("writer.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=audit.fd)
        try:
            require(identity(os.fstat(fd)) == selected, "audit_writer_lock_changed")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal("active_audit_writer") from None
            require(audit.read("writer.lock", 0)[1] == selected, "audit_writer_lock_changed")
            yield
        finally:
            os.close(fd)


def completed_inventory(run):
    """Only the accepted three-member audit-only layout can ever be removed."""
    run_generation = identity(os.fstat(run.fd))
    require(set(run.names(32)) == {"audit", "audit-run.json", "audit-finished.json"},
            "active_or_retained_state")
    selected = receipt(run)
    finished(run, selected)
    inventory, bodies = {}, {}
    for name in ("audit-run.json", "audit-finished.json"):
        body, info = run.read(name)
        inventory[name] = {"identity": info, "bytes": len(body), "sha256": sha(body)}
        bodies[name] = body
    with run.child("audit") as audit:
        audit_generation = identity(os.fstat(audit.fd))
        manifest = audit.json("manifest.json")
        require(type(manifest) is dict and set(manifest) == {"version", "limits", "generation", "next_id",
                "pruned_through", "pending_prune", "segments"} and type(manifest["version"]) is int
                and manifest["version"] == 1
                and manifest["limits"] == {k: v for k, v in AUDIT.LIMITS.items() if k != "version"}
                and type(manifest["segments"]) is list and 1 <= len(manifest["segments"]) <= 4
                and type(manifest["generation"]) is int and manifest["generation"] >= 1
                and type(manifest["pruned_through"]) is int and 0 <= manifest["pruned_through"] < 2**53
                and type(manifest["next_id"]) is int and manifest["next_id"] < 2**53
                and manifest["pending_prune"] is None, "audit_manifest_invalid")
        lock_raw, lock_identity = audit.read("writer.lock", 0)
        inventory["audit/writer.lock"] = {"identity": lock_identity, "bytes": 0, "sha256": sha(lock_raw)}
        bodies["audit/writer.lock"] = lock_raw
        allowed = {"manifest.json", "writer.lock"}
        previous = manifest["pruned_through"]
        for index, segment in enumerate(manifest["segments"]):
            require(type(segment) is dict and set(segment) == {"id", "closed", "bytes", "sha256", "partial_tail"}
                    and type(segment["id"]) is int and segment["id"] == previous + 1
                    and type(segment["closed"]) is bool and type(segment["partial_tail"]) is bool
                    and type(segment["bytes"]) is int and 0 <= segment["bytes"] <= 65536,
                    "audit_manifest_invalid")
            require(segment["closed"] or index == len(manifest["segments"]) - 1, "audit_manifest_invalid")
            name = f"segment-{segment['id']:020}.jsonl"
            body, info = audit.read(name)
            require((not segment["closed"] and segment["sha256"] is None and segment["partial_tail"] is False)
                    or (segment["closed"] and type(segment["sha256"]) is str
                        and SHA.fullmatch(segment["sha256"]) and sha(body) == segment["sha256"]
                        and len(body) == segment["bytes"]
                        and (bool(body) and not body.endswith(b"\n")) == segment["partial_tail"]), "audit_segment_corrupt")
            inventory["audit/" + name] = {"identity": info, "bytes": len(body), "sha256": sha(body)}
            bodies["audit/" + name] = body
            allowed.add(name)
            previous = segment["id"]
        require(previous + 1 == manifest["next_id"] and set(audit.names(8)) == allowed,
                "unexpected_audit_member")
        body, info = audit.read("manifest.json")
        require(strict(body) == manifest, "record_changed")
        inventory["audit/manifest.json"] = {"identity": info, "bytes": len(body), "sha256": sha(body)}
        bodies["audit/manifest.json"] = body
        require(identity(os.fstat(audit.fd)) == audit_generation, "audit_generation_changed")
    require(sum(row["bytes"] for row in inventory.values()) <= AUDIT.LIMITS["total_disk_bytes"], "audit_size_limit")
    run.check()
    require(identity(os.fstat(run.fd)) == run_generation, "run_generation_changed")
    return selected, {"run": run.object, "audit": audit.object, "run_generation": run_generation,
                      "audit_generation": audit_generation, "files": inventory}, bodies
