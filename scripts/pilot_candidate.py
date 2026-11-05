# SPDX-License-Identifier: Apache-2.0
"""Read-only custody checks for the existing same-source Linux candidate archive."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import stat
import tarfile

TARGET = "x86_64-unknown-linux-gnu"
PIN = "1.99.1"
FORMAT = "sw-native-pilot-agent-source-build/2"
RECEIPT = "pilot-binaries.json"
SOURCE = "pilot-source.json"
COMPONENT = "pilot-front-door.tar"
LAUNCHER = "agentfw-git-sandbox"
FILES = (LAUNCHER, COMPONENT, RECEIPT, SOURCE)
MAX_JSON = 65536
BINARY_NAMES = {"agentfw": "agentfw", "git_launcher": LAUNCHER}
COMMAND = ["cargo", "build", "--release", "--locked", "--target", TARGET,
           "-p", "agentfw", "-p", "soup-wall-bench", "-p", "llm-firewall"]


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "candidate_duplicate_json_key")
            result[key] = value
        return result
    require(len(raw) <= MAX_JSON, "candidate_json_limit")
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("candidate_nonfinite")))


def file_record(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 256 * 1024 * 1024,
            "candidate_regular_bounded_asset_required")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"sha256": digest, "size": info.st_size, "mode": stat.S_IMODE(info.st_mode)}


def validate(rows, small, expected_commit=None, expected_agent=None):
    """Shared by staging, extraction and publication_readiness's bounded reader.

    rows maps archive-relative names to actual sha256/size/mode; small contains
    the retained receipt/source and component manifest bytes, never executables.
    """
    require(set(FILES) | {"agentfw"} <= set(rows), "candidate_pilot_inputs_missing")
    receipt, source = parse(small[RECEIPT]), parse(small[SOURCE])
    require(receipt.get("format") == FORMAT and receipt.get("status") == "built-not-qualified"
            and receipt.get("toolchain") == PIN and receipt.get("target") == TARGET
            and receipt.get("lane") == "release" and receipt.get("commands") == [COMMAND],
            "candidate_build_lane_mismatch")
    require(type(source) is dict and source.get("dirty") is False
            and re.fullmatch("[0-9a-f]{40}", source.get("commit", ""))
            and re.fullmatch("[0-9a-f]{40}", source.get("tree", ""))
            and all(re.fullmatch("[0-9a-f]{64}", source.get(key, ""))
                    for key in ("files_sha256", "cargo_lock_sha256", "rust_toolchain_sha256")),
            "candidate_source_identity_invalid")
    require(receipt.get("source") == source and receipt.get("source_sha256") == rows[SOURCE]["sha256"],
            "candidate_source_receipt_mismatch")
    if expected_commit is not None:
        require(source["commit"] == expected_commit, "candidate_source_mismatch")
    tools = receipt.get("tools", {})
    require(set(tools) == {"rustc", "cargo"}, "candidate_compiler_inventory")
    for name, item in tools.items():
        require(type(item) is dict and item.get("version", "").startswith(name + " " + PIN + " ")
                and re.fullmatch("[0-9a-f]{64}", item.get("sha256", "")), "candidate_compiler_identity")
    require(set(receipt.get("binaries", {})) == set(BINARY_NAMES), "candidate_binary_roles")
    for role, name in BINARY_NAMES.items():
        require(receipt["binaries"][role] == {"path": name, **rows[name]}
                and rows[name]["mode"] == 0o755, "candidate_binary_digest_or_mode_mismatch")
    for name in (COMPONENT, RECEIPT, SOURCE):
        require(rows[name]["mode"] == 0o644, "candidate_asset_mode_mismatch")
    require(receipt.get("component") == {"path": COMPONENT, **rows[COMPONENT]},
            "candidate_component_mismatch")
    manifest = parse(small["component_manifest"])
    require(manifest.get("schema") == "sw-pilot-front-door-component/1"
            and receipt.get("component_manifest_sha256") == sha(small["component_manifest"])
            and manifest.get("source") == {key: source[key] for key in ("commit", "tree")},
            "candidate_component_source_mismatch")
    if expected_agent is not None:
        require(rows["agentfw"]["sha256"] == expected_agent, "candidate_runtime_binary_mismatch")
    return {"source": source, "receipt_sha256": rows[RECEIPT]["sha256"],
            "component_sha256": rows[COMPONENT]["sha256"], "binaries": receipt["binaries"],
            "active_protection": False}


def component_manifest(path):
    # The accepted component is deterministic ustar with manifest first; read
    # only its bounded header/body here. Agent independently verifies all bytes.
    with path.open("rb") as stream:
        return manifest_prefix(stream.read(MAX_JSON + 512))


def manifest_prefix(raw):
    require(len(raw) >= 512, "candidate_component_truncated")
    info = tarfile.TarInfo.frombuf(raw[:512], "utf-8", "strict")
    require(info.name == "manifest.json" and info.isfile() and 0 < info.size <= MAX_JSON
            and len(raw) >= 512 + info.size, "candidate_component_manifest_invalid")
    return raw[512:512 + info.size]


def validate_directory(directory, expected_commit=None):
    rows = {name: file_record(directory / name) for name in (*FILES, "agentfw")}
    small = {name: (directory / name).read_bytes() for name in (RECEIPT, SOURCE)}
    small["component_manifest"] = component_manifest(directory / COMPONENT)
    return validate(rows, small, expected_commit)
