#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite CI build custody, not binary installation or runtime attestation.

The caller must obtain an immutable artifact ID and hashes from its explicit
successful producer dependency. Downloads stay in the current workflow run;
this module never searches names, branches, caches or a latest successful run.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time

FORMAT = "sw-ci-qualification-build/1"
CUSTODY = "sw-ci-qualification-build-custody/1"
TUPLE = "ubuntu2404-x86_64-rust1.99.1-agent-default-debug-v1"
ROLES = {"agentfw": "bin/agentfw", "library": "tests/agentfw-lib",
         "native_endpoint": "tests/native-endpoint", "replace_file": "tests/replace-file"}
TARGETS = {"agentfw": {"name": "agentfw", "kind": "bin", "test": False},
           "library": {"name": "agentfw", "kind": "lib", "test": True},
           "native_endpoint": {"name": "native_endpoint", "kind": "test", "test": True},
           "replace_file": {"name": "replace_file", "kind": "test", "test": True}}
COMMANDS = [
    ["build", "--locked", "--offline", "-p", "agentfw", "--bin", "agentfw", "--message-format=json"],
    ["test", "--locked", "--offline", "-p", "agentfw", "--lib", "--test", "native_endpoint",
     "--test", "replace_file", "--no-run", "--message-format=json"],
]
MAX_MANIFEST = 256 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_PAYLOAD = 1024 * 1024 * 1024
CHUNK = 1024 * 1024
MAX_TAIL = tarfile.RECORDSIZE + 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parents[1]
PIN = "1.99.1"
PRODUCER = "ci-builds--agent-default-ubuntu2404"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    require(len(raw) <= MAX_MANIFEST, "manifest_size_limit")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "manifest_duplicate_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("manifest_nonfinite")))


def positive(value, maximum):
    return type(value) is int and 0 < value <= maximum


def validate_manifest(value, expected):
    require(isinstance(value, dict) and set(value) == {
        "format", "tuple", "source", "runtime", "producer", "commands", "files", "metrics"},
        "manifest_shape")
    require(value["format"] == FORMAT and value["tuple"] == TUPLE, "unsupported_build_tuple")
    for key in ("source", "runtime", "producer"):
        require(value[key] == expected[key], key + "_identity_mismatch")
    require(value["commands"] == COMMANDS, "build_commands_mismatch")
    files = value["files"]
    require(isinstance(files, dict) and set(files) == set(ROLES), "build_roles_mismatch")
    total = 0
    for role, entry in files.items():
        require(isinstance(entry, dict) and set(entry) == {"path", "size", "sha256", "mode", "target"},
                "build_file_shape")
        require(entry["path"] == ROLES[role] and entry["target"] == TARGETS[role], "build_role_substitution")
        require(positive(entry["size"], MAX_FILE) and entry["mode"] == 0o555
                and type(entry["mode"]) is int and isinstance(entry["sha256"], str)
                and HEX.fullmatch(entry["sha256"]), "build_file_identity")
        total += entry["size"]
    require(total <= MAX_PAYLOAD, "build_payload_limit")
    metrics = value["metrics"]
    require(isinstance(metrics, dict) and set(metrics) == {"stages", "compiled_artifacts", "execution_seconds"}
            and isinstance(metrics["stages"], list) and len(metrics["stages"]) == len(COMMANDS)
            and type(metrics["compiled_artifacts"]) is int and metrics["compiled_artifacts"] >= 0
            and type(metrics["execution_seconds"]) in (int, float)
            and 0 <= metrics["execution_seconds"] <= 2400, "build_metrics_shape")
    for index, stage in enumerate(metrics["stages"]):
        require(isinstance(stage, dict) and set(stage) == {"stage", "compiled_artifacts", "execution_seconds"}
                and stage["stage"] == ("binary", "tests")[index]
                and type(stage["compiled_artifacts"]) is int and stage["compiled_artifacts"] >= 0
                and type(stage["execution_seconds"]) in (int, float)
                and 0 <= stage["execution_seconds"] <= 2400, "build_stage_metrics_shape")
    require(sum(stage["compiled_artifacts"] for stage in metrics["stages"]) == metrics["compiled_artifacts"],
            "build_metrics_denominator")
    return value


def metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink, info.st_uid)


def checked_file(fd, cap, *, mode=None):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and 0 < info.st_size <= cap and not info.st_mode & 0o022, "owned_regular_file_required")
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode, "file_mode_changed")
    return info


def fd_digest(fd, cap):
    before = checked_file(fd, cap)
    os.lseek(fd, 0, os.SEEK_SET)
    digest, total = hashlib.sha256(), 0
    while block := os.read(fd, CHUNK):
        total += len(block)
        require(total <= cap, "file_size_limit")
        digest.update(block)
    require(total == before.st_size and metadata(os.fstat(fd)) == metadata(before), "file_changed_while_reading")
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def open_file(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)


def member_info(name, size, mode):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.uid, info.gid, info.mtime = size, mode, 0, 0, 0
    info.uname = info.gname = ""
    return info


class _Member:
    def __init__(self, stream, size):
        self.stream, self.remaining = stream, size

    def read(self, size):
        require(type(size) is int and 0 <= size <= CHUNK, "bounded_archive_read_required")
        size = min(size, self.remaining)
        data = self.stream.read(size)
        require(len(data) == size, "archive_truncated")
        self.remaining -= size
        return data


class FiniteTar:
    """Read one 512-byte header at a time, never following PAX/GNU records.

    TarFile's general reader may allocate an extension record before callers
    can check its declared size. This finite format has only regular files.
    """
    def __init__(self, stream):
        self.stream, self.offset, self.member, self.data = stream, 0, None, None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def next(self):
        if self.member is not None:
            require(self.data.remaining == 0, "archive_member_not_consumed")
            count = (-self.member.size) % 512
            padding = self.stream.read(count)
            require(len(padding) == count and not any(padding), "archive_padding_invalid")
            self.offset += 512 + self.member.size + count
        header = self.stream.read(512)
        require(len(header) == 512, "archive_truncated")
        if not any(header):
            return None
        try:
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError):
            raise ValueError("archive_header_invalid") from None
        require(member.type == tarfile.REGTYPE, "archive_regular_files_only")
        member.offset, member.offset_data = self.offset, self.offset + 512
        self.member, self.data = member, _Member(self.stream, member.size)
        return member

    def extractfile(self, member):
        require(member is self.member, "archive_member_identity")
        return self.data


def pack(manifest, files, destination):
    """Only finite, already selected regular copies enter the archive."""
    expected = {key: manifest[key] for key in ("source", "runtime", "producer")}
    validate_manifest(manifest, expected)
    raw = canonical(manifest)
    require(len(raw) <= MAX_MANIFEST, "manifest_size_limit")
    with Path(destination).open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=1) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as bundle:
                bundle.addfile(member_info("manifest.json", len(raw), 0o444), io.BytesIO(raw))
                for role in ROLES:
                    fd = open_file(files[role])
                    try:
                        entry = manifest["files"][role]
                        before = checked_file(fd, MAX_FILE, mode=0o555)
                        require(before.st_size == entry["size"] and fd_digest(fd, MAX_FILE) == entry["sha256"],
                                "producer_file_changed")
                        with os.fdopen(os.dup(fd), "rb") as data:
                            bundle.addfile(member_info(entry["path"], entry["size"], entry["mode"]), data)
                        require(metadata(os.fstat(fd)) == metadata(before), "producer_file_changed")
                    finally:
                        os.close(fd)
        output.flush()
        os.fsync(output.fileno())
    fd = open_file(destination)
    try:
        return {"archive_sha256": fd_digest(fd, MAX_ARCHIVE), "manifest_sha256": sha(raw)}
    finally:
        os.close(fd)


def member_check(member, name, size, mode, offset):
    require(member is not None and member.name == name and member.type == tarfile.REGTYPE
            and member.mode == mode and member.size == size and not member.pax_headers
            and member.uid == member.gid == member.mtime == 0 and not member.uname and not member.gname
            and member.offset == offset and member.offset_data == offset + 512,
            "archive_entry_invalid")
    require(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
            and "\\" not in name, "archive_path_invalid")
    return offset + 512 + ((size + 511) // 512) * 512


def private_parent(destination):
    destination = Path(destination)
    require(destination.is_absolute() and destination.parent.resolve(strict=True) == destination.parent,
            "canonical_output_parent_required")
    for parent in destination.parent.parents:
        info = parent.stat()
        require(info.st_uid in (0, os.getuid()) and
                (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "output_parent_writable")
    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    require(info.st_uid in (0, os.getuid()) and
            (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "output_parent_writable")
    return fd


def write_at(directory_fd, name, raw, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(os.dup(fd), "wb") as output:
            output.write(raw)
            output.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def custody(expected, artifact_id, archive_sha256, manifest_sha256):
    require(isinstance(artifact_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id),
            "immutable_artifact_id_required")
    require(HEX.fullmatch(archive_sha256 or "") and HEX.fullmatch(manifest_sha256 or ""),
            "producer_digests_required")
    return {"format": CUSTODY, "artifact_id": artifact_id, "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256, "expected": expected}


def unpack(archive, destination, expected, artifact_id, archive_sha256, manifest_sha256):
    """No downloaded byte executes. A complete receipt is published last.

    Failed partial outputs remain owned, unpublished evidence. Existing output
    directories are never repaired, overwritten, reused or recursively removed.
    """
    receipt = custody(expected, artifact_id, archive_sha256, manifest_sha256)
    destination = Path(destination)
    source_fd = open_file(archive)
    parent_fd = root_fd = None
    children = {}
    try:
        original = checked_file(source_fd, MAX_ARCHIVE)
        require(fd_digest(source_fd, MAX_ARCHIVE) == archive_sha256, "artifact_digest_mismatch")
        parent_fd = private_parent(destination)
        parent_info = os.fstat(parent_fd)
        os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
        root_fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=parent_fd)
        root_info = os.fstat(root_fd)
        for name in ("bin", "tests"):
            os.mkdir(name, mode=0o700, dir_fd=root_fd)
            children[name] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=root_fd)
        with os.fdopen(os.dup(source_fd), "rb") as source:
            with gzip.GzipFile(fileobj=source, mode="rb") as decoded:
                with FiniteTar(decoded) as bundle:
                    member = bundle.next()
                    require(member is not None and positive(member.size, MAX_MANIFEST), "manifest_entry_missing")
                    offset = member_check(member, "manifest.json", member.size, 0o444, 0)
                    raw = bundle.extractfile(member).read(MAX_MANIFEST + 1)
                    require(len(raw) == member.size and sha(raw) == manifest_sha256, "manifest_digest_mismatch")
                    manifest = validate_manifest(strict_json(raw), expected)
                    write_at(root_fd, "manifest.json", raw, 0o444)
                    for role, path in ROLES.items():
                        entry = manifest["files"][role]
                        member = bundle.next()
                        offset = member_check(member, path, entry["size"], entry["mode"], offset)
                        directory, name = path.split("/")
                        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=children[directory])
                        try:
                            digest, total, header = hashlib.sha256(), 0, b""
                            data = bundle.extractfile(member)
                            while block := data.read(CHUNK):
                                total += len(block)
                                require(total <= entry["size"], "payload_size_mismatch")
                                header = (header + block[:64])[:64]
                                digest.update(block)
                                view = memoryview(block)
                                while view:
                                    written = os.write(fd, view)
                                    require(written > 0, "payload_write_failed")
                                    view = view[written:]
                            require(total == entry["size"] and digest.hexdigest() == entry["sha256"],
                                    "payload_digest_mismatch")
                            require(header.startswith(b"\x7fELF\x02\x01") and header[18:20] == b"\x3e\x00",
                                    "native_x86_64_elf_required")
                            os.fchmod(fd, entry["mode"])
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                    require(bundle.next() is None, "extra_archive_entry")
                    decoded.seek(offset)
                    tail = decoded.read(MAX_TAIL + 1)
                    require(1024 <= len(tail) <= MAX_TAIL and not any(tail), "archive_trailing_data")
                    require(decoded.read(1) == b"", "archive_trailing_data")
        require(metadata(os.fstat(source_fd)) == metadata(original)
                and metadata(Path(archive).lstat()) == metadata(original), "archive_changed_during_validation")
        require(destination.parent.stat().st_ino == parent_info.st_ino
                and destination.parent.stat().st_dev == parent_info.st_dev
                and destination.lstat().st_ino == root_info.st_ino, "output_path_changed")
        # Missing this marker always refuses later use, including partial write.
        for fd in children.values():
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        write_at(root_fd, "custody.json", canonical(receipt), 0o444)
        os.fchmod(root_fd, 0o555)
        os.fsync(root_fd)
        os.fsync(parent_fd)
        return receipt
    finally:
        for fd in children.values():
            os.close(fd)
        for fd in (root_fd, parent_fd, source_fd):
            if fd is not None:
                os.close(fd)


def source_builder():
    # Reuse the accepted clean-source, package-identity and bounded build rules.
    # Its separate native-pilot toolchain/selected inputs remain unchanged.
    spec = importlib.util.spec_from_file_location("ci_accepted_source_builder",
                                                 ROOT / "scripts/build-native-pilot-inputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def probe(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=True, timeout=15, env={**os.environ, "RUSTUP_AUTO_INSTALL": "0"})
    require(len(result.stdout) <= 65536, "probe_output_limit")
    return result.stdout.decode().strip()


def producer_identity(env, attempt=None):
    """GHA dependency outputs select an attempt; a retained producer is valid.

    Neither a current consumer attempt nor a self-asserted archive manifest can
    select the producer. A rerun producer publishes a new ID and attempt through
    the explicit needs edge. Downloads without a token stay in this run.
    """
    current = env.get("GITHUB_RUN_ATTEMPT", "")
    selected = current if attempt is None else attempt
    for number in (env.get("GITHUB_RUN_ID", ""), current, selected):
        require(isinstance(number, str) and re.fullmatch(r"[1-9][0-9]{0,19}", number), "invalid_run_context")
    require(int(selected) <= int(current), "future_producer_attempt")
    repository = env.get("GITHUB_REPOSITORY", "")
    workflow = env.get("GITHUB_WORKFLOW_REF", "")
    require(repository == "SoupTeam/soup-wall" and workflow.startswith(repository + "/.github/workflows/")
            and re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_WORKFLOW_SHA", "")), "invalid_workflow_context")
    filename, separator, ref = workflow[len(repository + "/.github/workflows/"):].partition("@")
    require(filename in {"ci.yml", "ci-builds.yml", "mcp-create-file.yml"} and separator
            and ref.startswith("refs/"), "unsupported_producer_workflow")
    return {"run_id": env["GITHUB_RUN_ID"], "run_attempt": int(selected), "repository": repository,
            "workflow_ref": workflow, "workflow_sha": env["GITHUB_WORKFLOW_SHA"], "producer_job": PRODUCER}


def runtime_identity(root):
    require(sys.platform == "linux" and os.uname().machine == "x86_64", "native_linux_x86_64_required")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and
            release.get("VERSION_ID", "").strip('"') == "24.04", "ubuntu2404_required")
    image = {key: os.environ.get(key, "") for key in ("ImageOS", "ImageVersion")}
    require(image["ImageOS"] == "ubuntu24" and re.fullmatch(r"[0-9]{8}\.[0-9]+(\.[0-9]+)?", image["ImageVersion"]),
            "exact_hosted_image_required")
    # Ambient build overrides are not silently incorporated into a compatible tuple.
    require(not any(value for key, value in os.environ.items() if key in {
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS"} or key.startswith(("CARGO_PROFILE_", "CARGO_TARGET_"))
        and key != "CARGO_TARGET_DIR"), "ambient_build_override")
    tools = {}
    for name in ("rustc", "cargo"):
        path = Path(probe(["rustup", "which", "--toolchain", PIN, name])).resolve(strict=True)
        version = probe([str(path), "-vV" if name == "rustc" else "--version"])
        require(version.startswith(name + " " + PIN + " "), "exact_compiler_required")
        if name == "rustc":
            require("host: x86_64-unknown-linux-gnu" in version, "compiler_host_mismatch")
        tools[name] = {"path": str(path), "sha256": source_builder().native.digest(path), "version": version}
    for name in ("cc", "c++", "ld", "ar", "ranlib", "cmake", "pkg-config", "make"):
        path = Path(shutil.which(name) or "/missing").resolve(strict=True)
        tools[name] = {"path": str(path), "sha256": source_builder().native.digest(path)}
    abi = {}
    for name in ("libc.so.6", "ld-linux-x86-64.so.2", "libgcc_s.so.1", "libstdc++.so.6", "libssl.so.3", "libcrypto.so.3"):
        path = (Path("/lib/x86_64-linux-gnu") / name).resolve(strict=True)
        abi[name] = {"path": str(path), "sha256": source_builder().native.digest(path)}
    return {"image": image, "tools": tools, "abi": abi, "target": "x86_64-unknown-linux-gnu",
            "profile": "dev/test", "features": [], "default_features": True, "flags": [],
            "source_path": str(root), "test_working_directory": str(root / "crates/agentfw")}


def expected_identity(root, env, attempt=None):
    return {"source": source_builder().source_identity(root, env.get("SOU166_EXPECTED_COMMIT", "")),
            "runtime": runtime_identity(root), "producer": producer_identity(env, attempt)}


def cargo_rows(log):
    result = []
    for line in log.read_bytes().splitlines():
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                result.append(row)
        except (ValueError, UnicodeError):
            pass
    return result


def stage_metrics(log, stage, start):
    rows = cargo_rows(log)
    return {"stage": stage, "execution_seconds": round(time.monotonic() - start, 3),
            "compiled_artifacts": sum(row.get("reason") == "compiler-artifact" and row.get("fresh") is False
                                      for row in rows)}


def build(root, output):
    require(os.environ.get("GITHUB_JOB") in {PRODUCER, "agent-default-ubuntu2404"}, "explicit_producer_job_required")
    expected = expected_identity(root, os.environ)
    require(output.is_absolute() and not output.is_relative_to(root), "external_build_output_required")
    output.mkdir(mode=0o700)  # Existing/partial generations are evidence, never repaired.
    builder = source_builder()
    for name in ("home", "tmp", "cargo-home", "target", "bin", "tests"):
        (output / name).mkdir(mode=0o700)
    registry = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry"
    require(registry.is_dir(), "locked_registry_prefetch_required")
    (output / "cargo-home/registry").symlink_to(registry.resolve(strict=True), target_is_directory=True)
    tools = expected["runtime"]["tools"]
    env = {"PATH": ":".join(dict.fromkeys([str(Path(item["path"]).parent) for item in tools.values()]
                                         + ["/usr/bin", "/bin"])),
           "HOME": str(output / "home"), "TMPDIR": str(output / "tmp"), "LANG": "C", "LC_ALL": "C",
           "CARGO_HOME": str(output / "cargo-home"), "CARGO_TARGET_DIR": str(output / "target"),
           "RUSTUP_TOOLCHAIN": PIN, "RUSTUP_AUTO_INSTALL": "0", "CARGO_BUILD_JOBS": "4",
           "RUSTC": tools["rustc"]["path"], "CC": tools["cc"]["path"], "CXX": tools["c++"]["path"],
           "AR": tools["ar"]["path"], "RANLIB": tools["ranlib"]["path"], "CMAKE": tools["cmake"]["path"]}
    if "RUSTUP_HOME" in os.environ:
        env["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    files, stages, start = {}, [], time.monotonic()
    package_root, version = builder.expected_package(root)
    for index, command in enumerate(COMMANDS):
        stage = ("binary", "tests")[index]
        log = output / ("cargo-" + stage + ".jsonl")
        began = time.monotonic()
        try:
            builder.bounded_cargo([tools["cargo"]["path"], *command], root=root, env=env,
                                  target=output / "target", log=log, stage="ci_" + stage)
        except Exception:
            if log.exists():
                sys.stderr.write(log.read_text(errors="replace"))
            raise
        stages.append(stage_metrics(log, stage, began))
        requested = {"agentfw"} if index == 0 else set(ROLES) - {"agentfw"}
        found = {}
        for row in cargo_rows(log):
            if row.get("reason") != "compiler-artifact" or not builder.package_matches(row.get("package_id"), package_root, version):
                continue
            for role in requested:
                target = row.get("target", {})
                if (target.get("name") == TARGETS[role]["name"] and TARGETS[role]["kind"] in target.get("kind", [])
                        and row.get("profile", {}).get("test") is TARGETS[role]["test"] and row.get("executable")):
                    require(role not in found and row.get("features") == [], "cargo_role_duplicate_or_features")
                    found[role] = Path(row["executable"])
        require(set(found) == requested, "cargo_build_roles_missing")
        for role, path in found.items():
            source = path.resolve(strict=True)
            require(source.is_relative_to(output / "target"), "cargo_artifact_outside_target")
            before = builder.cargo_artifact_source(source)
            require(before.st_size <= MAX_FILE, "build_file_limit")
            require(before.st_size + sum(item["size"] for item in files.values()) <= MAX_PAYLOAD, "build_payload_limit")
            destination = output / ROLES[role]
            with source.open("rb") as incoming, destination.open("xb") as outgoing:
                remaining = before.st_size
                while remaining:
                    block = incoming.read(min(CHUNK, remaining))
                    require(block, "build_file_truncated")
                    outgoing.write(block)
                    remaining -= len(block)
                require(not incoming.read(1), "build_file_grew")
                require(metadata(source.stat()) == metadata(before), "build_file_changed")
                outgoing.flush()
                os.fchmod(outgoing.fileno(), 0o555)
                os.fsync(outgoing.fileno())
            fd = open_file(destination)
            try:
                files[role] = {"path": ROLES[role], "size": checked_file(fd, MAX_FILE, mode=0o555).st_size,
                               "sha256": fd_digest(fd, MAX_FILE), "mode": 0o555, "target": TARGETS[role]}
            finally:
                os.close(fd)
    require(expected == expected_identity(root, os.environ), "producer_inputs_changed")
    manifest = {"format": FORMAT, "tuple": TUPLE, **expected, "commands": COMMANDS, "files": files,
                "metrics": {"stages": stages, "compiled_artifacts": sum(row["compiled_artifacts"] for row in stages),
                            "execution_seconds": round(time.monotonic() - start, 3)}}
    (output / "manifest.json").write_bytes(canonical(manifest))
    packing = time.monotonic()
    result = pack(manifest, {role: output / path for role, path in ROLES.items()}, output / "build.tar.gz")
    result.update({"producer_attempt": str(expected["producer"]["run_attempt"]),
                   "pack_seconds": round(time.monotonic() - packing, 3),
                   "total_execution_seconds": round(time.monotonic() - start, 3),
                   "archive_bytes": (output / "build.tar.gz").stat().st_size,
                   "payload_bytes": sum(item["size"] for item in files.values()), "metrics": manifest["metrics"]})
    return result


def read_owned_json(path, mode=0o444):
    fd = open_file(path)
    try:
        info = checked_file(fd, MAX_MANIFEST, mode=mode)
        raw = os.read(fd, MAX_MANIFEST + 1)
        require(len(raw) == info.st_size and metadata(os.fstat(fd)) == metadata(info), "context_changed")
        return strict_json(raw), raw
    finally:
        os.close(fd)


def verified_role(directory, context, role):
    """Recheck all selected bytes and the exact finite layout before each use.

    Return an open, hashed descriptor, not a re-resolved executable pathname.
    This is build custody on disposable CI runners, not runtime attestation.
    """
    expected = context["expected"]
    require(source_builder().source_identity(ROOT, expected["source"]["commit"]) == expected["source"]
            and runtime_identity(ROOT) == expected["runtime"], "consumer_inputs_changed")
    handles, snapshots, selected = [], {}, None
    try:
        root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        handles.append(root)
        def check_dir(fd, names):
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o555
                    and set(os.listdir(fd)) == set(names), "installed_layout_changed")
            snapshots[fd] = metadata(info)
        check_dir(root, {"manifest.json", "custody.json", "bin", "tests"})
        def json_at(name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root)
            handles.append(fd)
            info = checked_file(fd, MAX_MANIFEST, mode=0o444)
            raw = os.read(fd, MAX_MANIFEST + 1)
            require(len(raw) == info.st_size, "installed_json_size")
            snapshots[fd] = metadata(info)
            return strict_json(raw), raw
        receipt, _ = json_at("custody.json")
        require(receipt == custody(expected, context["artifact_id"], context["archive_sha256"], context["manifest_sha256"]),
                "installed_custody_changed")
        manifest, raw = json_at("manifest.json")
        require(sha(raw) == context["manifest_sha256"], "installed_manifest_changed")
        validate_manifest(manifest, expected)
        for name in ("bin", "tests"):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            handles.append(child)
            check_dir(child, {path.split("/")[1] for path in ROLES.values() if path.startswith(name + "/")})
            for key, path in ROLES.items():
                if not path.startswith(name + "/"):
                    continue
                fd = os.open(path.split("/")[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=child)
                handles.append(fd)
                entry = manifest["files"][key]
                require(checked_file(fd, MAX_FILE, mode=0o555).st_size == entry["size"] and
                        fd_digest(fd, MAX_FILE) == entry["sha256"], "installed_payload_changed")
                snapshots[fd] = metadata(os.fstat(fd))
                if key == role:
                    selected = fd
        require(selected is not None, "unregistered_role")
        require(all(metadata(os.fstat(fd)) == snapshot for fd, snapshot in snapshots.items())
                and metadata(Path(directory).lstat()) == snapshots[root], "installed_path_changed")
        handles.remove(selected)
        return selected
    finally:
        for fd in handles:
            os.close(fd)


FILTERS = {"library": {"create_file", "sou54_", "mcp::input::tests::", "edit_session",
                       "native::execution::transport", "replace_file"},
           "native_endpoint": {"create_file_v2"}, "replace_file": {""}}


def parse_cargo(arguments):
    """Finite original Agent operations: adding features/targets requires review."""
    if arguments == ["build", "--locked", "--offline", "-p", "agentfw", "--bin", "agentfw"]:
        return "agentfw", None
    if arguments == ["clippy", "--locked", "--offline", "-p", "agentfw", "--all-targets", "--", "-D", "warnings"]:
        return "clippy", None
    prefix = ["test", "--locked", "--offline", "-p", "agentfw"]
    require(arguments[:5] == prefix and arguments[-2:] == ["--", "--nocapture"], "unregistered_cargo_command")
    middle = arguments[5:-2]
    if middle[:1] == ["--lib"]:
        role, rest = "library", middle[1:]
    else:
        require(middle[:1] == ["--test"] and len(middle) >= 2, "unregistered_cargo_target")
        role, rest = middle[1], middle[2:]
    require(role in FILTERS and len(rest) <= 1 and (rest[0] if rest else "") in FILTERS[role], "unregistered_test_filter")
    return role, rest[0] if rest else ""


def command_context():
    directory = Path(os.environ.get("SOU166_BUNDLE", "/missing"))
    context, _ = read_owned_json(os.environ.get("SOU166_CONTEXT", "/missing"))
    require(set(context) == {"expected", "artifact_id", "archive_sha256", "manifest_sha256"}, "context_shape")
    custody(context["expected"], context["artifact_id"], context["archive_sha256"], context["manifest_sha256"])
    return directory, context


def dependency_context(env):
    require(env.get("SOU166_PRODUCER_RESULT") == "success", "successful_producer_required")
    producer = producer_identity(env, env.get("SOU166_PRODUCER_ATTEMPT"))
    require(env.get("SOU166_ARCHIVE_NAME") == "build-r" + producer["run_id"] + "-a" + str(producer["run_attempt"]) + ".tar.gz",
            "producer_archive_name_mismatch")
    return custody({}, env.get("SOU166_ARTIFACT_ID", ""), env.get("SOU166_ARCHIVE_SHA256", ""),
                   env.get("SOU166_MANIFEST_SHA256", ""))


def run_native(fd, arguments, log):
    # Owned process group with the same accepted reaper and finite log/deadline.
    import selectors
    import signal
    builder = source_builder()
    process = selector = None
    cancelled = False
    def cancel(*_):
        nonlocal cancelled
        cancelled = True
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, cancel)
        with log.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            process = subprocess.Popen(["/proc/self/fd/" + str(fd), *arguments], cwd=ROOT / "crates/agentfw",
                                       env={**os.environ, "CARGO_MANIFEST_DIR": str(ROOT / "crates/agentfw")},
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, pass_fds=(fd,), start_new_session=True)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline, size = time.monotonic() + builder.BUILD_SECONDS, 0
            while selector.get_map() or not builder.native.leader_finished(process):
                require(not cancelled and time.monotonic() <= deadline, "native_test_cancelled_or_timeout")
                if not selector.get_map():
                    time.sleep(0.1)
                for key, _ in selector.select(0.2) if selector.get_map() else ():
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(block)
                    output.write(block[:max(0, builder.native.MAX_LOG - output.tell())])
                    require(size <= builder.native.MAX_LOG, "native_test_log_limit")
            builder.native.stop_group(process)
            require(process.returncode == 0, "native_test_failed")
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            builder.native.stop_group(process)
            process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


def cargo(arguments, output):
    role, test_filter = parse_cargo(arguments)
    mode = os.environ.get("SOU166_MODE", "source")
    require(mode in {"source", "shared"}, "explicit_build_mode_required")
    # Clippy remains a real current-source compiler check in BOTH paths.
    if role == "clippy":
        mode = "source"
    start = time.monotonic()
    log = output.with_suffix(".log")
    record = {"format": "sw-ci-build-use/1", "mode": mode, "arguments": arguments, "role": role,
              "status": "failed", "compiled_artifacts": 0, "execution_seconds": None}
    try:
        if mode == "source":
            command = ["cargo", *arguments]
            command.insert(2, "--message-format=json")
            target = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            require(stat.S_ISDIR(target.lstat().st_mode), "source_target_directory_required")
            source_builder().bounded_cargo(command, root=ROOT, env=dict(os.environ), target=target,
                                          log=log, stage="source_" + role)
            record["compiled_artifacts"] = stage_metrics(log, "source", start)["compiled_artifacts"]
        else:
            directory, context = command_context()
            fd = verified_role(directory, context, role)
            try:
                record["artifact_id"] = context["artifact_id"]
                if role != "agentfw":
                    listing = output.with_suffix(".inventory.log")
                    run_native(fd, ([test_filter] if test_filter else []) + ["--list"], listing)
                    inventory = [line for line in listing.read_text().splitlines() if line.endswith(": test")]
                    require(inventory, "empty_native_test_inventory")
                    record["test_inventory_count"] = len(inventory)
                    run_native(fd, ([test_filter] if test_filter else []) + ["--nocapture"], log)
                else:
                    log.write_text("Verified immutable producer build reused; no consumer Cargo build was run.\n")
            finally:
                os.close(fd)
        if test_filter is not None:
            text = log.read_text(errors="replace")
            require(re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed;", text), "nonempty_passed_native_tests_required")
        record["status"] = "passed"
    finally:
        record["execution_seconds"] = round(time.monotonic() - start, 3)
        output.write_bytes(canonical(record))
        if log.exists():
            print(log.read_text(errors="replace"))
        print(canonical(record).decode(), end="")
    return record


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("guard")
    produce = sub.add_parser("build")
    produce.add_argument("--output", type=Path, required=True)
    consume = sub.add_parser("prepare")
    consume.add_argument("--archive", type=Path, required=True)
    consume.add_argument("--output", type=Path, required=True)
    consume.add_argument("--context", type=Path, required=True)
    execute = sub.add_parser("cargo")
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("arguments", nargs=argparse.REMAINDER)
    sub.add_parser("binary")
    args = parser.parse_args(argv)
    try:
        if args.command == "guard":
            dependency_context(os.environ)
        elif args.command == "build":
            result = build(ROOT, args.output)
            result["archive_name"] = "build-r" + os.environ["GITHUB_RUN_ID"] + "-a" + result["producer_attempt"] + ".tar.gz"
            (args.output / "build.tar.gz").rename(args.output / result["archive_name"])
            (args.output / "result.json").write_bytes(canonical(result))
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                for key in ("archive_sha256", "manifest_sha256", "producer_attempt", "archive_name"):
                    output.write(key + "=" + result[key] + "\n")
            print(canonical(result).decode())
        elif args.command == "prepare":
            began = time.monotonic()
            dependency_context(os.environ)
            require(set(os.listdir(args.archive.parent)) == {os.environ["SOU166_ARCHIVE_NAME"]}, "download_layout_mismatch")
            context = {"expected": expected_identity(ROOT, os.environ, os.environ.get("SOU166_PRODUCER_ATTEMPT")),
                       "artifact_id": os.environ.get("SOU166_ARTIFACT_ID", ""),
                       "archive_sha256": os.environ.get("SOU166_ARCHIVE_SHA256", ""),
                       "manifest_sha256": os.environ.get("SOU166_MANIFEST_SHA256", "")}
            unpack(args.archive, args.output, context["expected"], context["artifact_id"],
                   context["archive_sha256"], context["manifest_sha256"])
            with args.context.open("xb") as output:
                output.write(canonical(context))
                os.fchmod(output.fileno(), 0o444)
            with Path(str(args.context) + ".metrics.json").open("xb") as output:
                output.write(canonical({"format": "sw-ci-build-transfer/1", "status": "verified",
                                        "artifact_id": context["artifact_id"], "archive_bytes": args.archive.stat().st_size,
                                        "verification_seconds": round(time.monotonic() - began, 3)}))
        elif args.command == "cargo":
            require(args.arguments[:1] == ["--"], "explicit_original_command_required")
            cargo(args.arguments[1:], args.output)
        else:
            if os.environ.get("SOU166_MODE", "source") == "shared":
                directory, context = command_context()
                fd = verified_role(directory, context, "agentfw")
                os.close(fd)
                print(directory / ROLES["agentfw"])
            else:
                print(Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target"))) / "debug/agentfw")
        return 0
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": str(error), "command": args.command}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
