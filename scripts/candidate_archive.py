# SPDX-License-Identifier: Apache-2.0
"""Validate the entire finite candidate inventory before writing any member."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

ROOT = "soup-wall-linux-amd64"
PROFILE = "profiles/mcp/filesystem-readonly-v1/"
REQUIRED = {"bin/agentfw", "bin/bwrap", "assets/baseline.classifier",
            "scripts/install-sou62-filesystem-profile.py", "scripts/pilot_provider.py",
            "scripts/pilot_filesystem_roots.py", "rule_baseline/rule_baseline.py",
            "Cargo.lock", "rust-toolchain.toml", "LICENSE", "NOTICE",
            "npm-inventory.json", "assets/bubblewrap-0.13.1.tar.xz", "upstream-notices/bubblewrap-COPYING",
            "node-v22.22.0-linux-x64.tar.xz",
            *(PROFILE + p for p in ("package.json", "package-lock.json", "upstream-identity.json",
                                     "upstream-tools-list.json", "policy.yaml"))}
MAX_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_MANIFEST = 4 * 1024 * 1024
ARCHIVE_PINS = {
    "node-v22.22.0-linux-x64.tar.xz": "9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37",
    "assets/bubblewrap-0.13.1.tar.xz": "0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def safe(value):
    require(isinstance(value, str) and value and not value.startswith("/")
            and "\\" not in value and ":" not in value
            and all(p not in ("", ".", "..") for p in value.split("/")), "unsafe_path")
    return value


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse(raw):
    require(len(raw) <= MAX_MANIFEST, "json_size_limit")
    return json.loads(raw, object_pairs_hook=pairs)


def extract(archive, destination):
    destination = Path(destination)
    require(not destination.exists(), "new_destination_required")
    with tarfile.open(archive, "r:gz") as tar:
        members, total, hashes, documents = {}, 0, {}, {}
        json_paths = {"manifest.json", "npm-inventory.json", PROFILE + "upstream-identity.json",
                      PROFILE + "package-lock.json"}
        for member in tar:
            name = safe(member.name)
            require(name == ROOT or name.startswith(ROOT + "/"), "archive_root_mismatch")
            require(name not in members, "duplicate_member")
            require(member.isfile() or member.isdir(), "archive_links_or_special_files")
            require(not member.mode & 0o7000, "unsafe_mode")
            total += member.size
            require(total <= MAX_BYTES and len(members) < MAX_ENTRIES, "archive_expansion_limit")
            members[name] = member
            if member.isfile():
                relative = name[len(ROOT) + 1:]
                with tar.extractfile(member) as stream:
                    if relative in json_paths:
                        require(member.size <= MAX_MANIFEST, "manifest_size_limit")
                        documents[relative] = stream.read(MAX_MANIFEST + 1)
                        hashes[relative] = hashlib.sha256(documents[relative]).hexdigest()
                    else:
                        hashes[relative] = hashlib.file_digest(stream, "sha256").hexdigest()
        manifest_name = ROOT + "/manifest.json"
        require(manifest_name in members and members[manifest_name].isfile(), "manifest_missing")
        require(members[manifest_name].size <= MAX_MANIFEST, "manifest_size_limit")
        manifest = parse(documents["manifest.json"])
        require(set(manifest) == {"schema_version", "identities", "files"}
                and manifest["schema_version"] == 2, "manifest_schema")
        ids, files = manifest["identities"], manifest["files"]
        require(isinstance(ids, dict) and re.fullmatch(r"rustc 1\.94\.1(?: .*)?", ids.get("compiler", ""))
                and re.fullmatch(r"[a-f0-9]{40}", ids.get("source_commit", ""))
                and re.fullmatch(r"[a-f0-9]{64}", ids.get("cargo_lock_sha256", "")), "manifest_identities")
        require(isinstance(files, dict) and REQUIRED <= files.keys(), "required_components_missing")
        require(any(p.startswith("npm-cache/_cacache/content-v2/") for p in files), "npm_cache_missing")
        for relative, digest in files.items():
            safe(relative)
            require(re.fullmatch(r"[a-f0-9]{64}", digest or ""), "manifest_digest_invalid")
        observed = {name[len(ROOT) + 1:] for name, m in members.items() if m.isfile()}
        require(observed == set(files) | {"manifest.json"}, "manifest_members_mismatch")
        # Files may never serve as ancestors, even if the tar orders them last.
        for name in members:
            require(all(str(parent) not in members or members[str(parent)].isdir()
                        for parent in PurePosixPath(name).parents), "file_as_directory")
        for relative, digest in files.items():
            require(hashes[relative] == digest, "member_digest_mismatch")
        require(files["Cargo.lock"] == ids["cargo_lock_sha256"], "cargo_lock_identity_mismatch")
        require(all(files[path] == digest for path, digest in ARCHIVE_PINS.items()), "pinned_archive_mismatch")
        identity = parse(documents[PROFILE + "upstream-identity.json"])
        require(identity.get("format") == "sw-mcp/filesystem-readonly-upstream/1", "upstream_identity_schema")
        require(identity.get("packageLockSha256") == files[PROFILE + "package-lock.json"], "npm_lock_identity_mismatch")
        notices = identity.get("upstreamNotices", [])
        require(len(notices) == 3 and {n.get("component") for n in notices} == {"server", "sdk", "node"}, "upstream_notices_missing")
        for notice in notices:
            path = safe(notice["path"])
            require(path.startswith("upstream-notices/") and files.get(PROFILE + path) == notice.get("sha256"), "notice_identity_mismatch")
        npm_inventory = parse(documents["npm-inventory.json"])
        lock = parse(documents[PROFILE + "package-lock.json"])
        require(npm_inventory.get("format") == "sw-candidate-npm-inventory/1"
                and npm_inventory.get("lock_sha256") == files[PROFILE + "package-lock.json"], "npm_inventory_identity")
        npm_rows = npm_inventory.get("packages", [])
        require(len(npm_rows) == len(lock["packages"]) - 1
                and {r["lock_path"] for r in npm_rows} == set(lock["packages"]) - {""}, "npm_inventory_coverage")
        for row in npm_rows:
            locked = lock["packages"][row["lock_path"]]
            require(row.get("version") == locked["version"] and row.get("integrity") == locked["integrity"]
                    and row.get("notices") and all(files.get(p) == digest for p, digest in row["notices"].items()),
                    "npm_inventory_notice_mismatch")
        # Validation is now complete. Extract into a fresh private directory.
        destination.mkdir(mode=0o700)
        for name, member in members.items():
            if name == ROOT:
                continue
            path = destination / name[len(ROOT) + 1:]
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with path.open("xb") as out, tar.extractfile(member) as source:
                    while chunk := source.read(1024 * 1024):
                        out.write(chunk)
                path.chmod(member.mode & 0o777)
    return manifest


if __name__ == "__main__":
    import sys
    try:
        extract(*sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        sys.exit(f"CRITICAL: Candidate archive refused: {error}")
