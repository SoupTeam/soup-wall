#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify selected readiness bytes before publication; never grant approval.

The existing pilot dossier and ROADMAP support evaluators retain their verdicts.
This consumer checks custody and completeness, and requires a separate operator
decision supplied by the authorized release caller. It performs no publication,
network request, build, runtime execution, or model call.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import zlib

import pilot_dossier as DOSSIER
import pilot_runtime_identity as RUNTIME
import roadmap_support as SUPPORT

VERSION = "sw-publication-readiness/1"
APPROVAL_VERSION = "sw-publication-approval/1"
RESULT_VERSION = "sw-publication-readiness-result/1"
SCOPE = "full-product"
MAX_INDEX = 128 * 1024
MAX_APPROVAL = 512 * 1024
MAX_FILES = 128
MAX_BUNDLE = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 256
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_EXPANSION = 512 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
METADATA = {"selection_sha256", "reporter_sha256", "reporter_dependencies", "reporter_accepted_sha"}


class Blocked(ValueError):
    """A finite consumer-owned diagnostic, never source report text."""


def need(condition, code):
    if not condition:
        raise Blocked(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(obj, keys, code):
    need(type(obj) is dict and set(obj) == set(keys), code)


def parse(raw):
    try:
        return DOSSIER.parse(raw)
    except (ValueError, TypeError, RecursionError):
        raise Blocked("invalid_json") from None


def read_json(path, limit):
    try:
        raw = SUPPORT.safe_file(Path(path), limit)
    except (ValueError, OSError):
        raise Blocked("unsafe_or_oversized_input") from None
    return parse(raw), sha(raw)


def candidate(value):
    fields(value, ("commit", "tree"), "candidate_fields")
    try:
        SUPPORT.source(value["commit"], "commit")
        SUPPORT.source(value["tree"], "tree")
    except ValueError:
        raise Blocked("invalid_candidate_identity") from None


def reference(value):
    try:
        DOSSIER.validate_reference(value)
    except (ValueError, TypeError, KeyError):
        raise Blocked("unsafe_evidence_reference") from None
    return value


class Snapshot:
    """Read each declared file once into a private bounded immutable input set.

    Original producers may reread a selected ZIP for several stages. Snapshotting
    prevents those reads from observing different bytes and charges unique input
    bytes once. No directory discovery or arbitrary archive extraction occurs.
    """

    def __init__(self, root, target):
        self.root = Path(root)
        self.target = Path(target)
        self.files = {}
        self.total = 0

    def add(self, ref):
        reference(ref)
        name = ref["path"]
        if name in self.files:
            need(self.files[name] == ref["sha256"], "contradictory_file_digest")
        else:
            need(len(self.files) < MAX_FILES, "bundle_file_limit")
            limit = DOSSIER.MAX_ARCHIVE if ref["member"] is not None else DOSSIER.MAX_REPORT
            try:
                raw = SUPPORT.safe_file(self.root / name, min(limit, MAX_BUNDLE - self.total))
            except (ValueError, OSError):
                raise Blocked("unsafe_missing_or_oversized_evidence") from None
            need(sha(raw) == ref["sha256"], "evidence_digest_mismatch")
            self.total += len(raw)
            need(self.total <= MAX_BUNDLE, "bundle_byte_limit")
            destination = self.target / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(raw)
            self.files[name] = ref["sha256"]
        try:
            if ref["member"] is not None:
                # Bound central-directory allocation before the existing ZIP
                # reader constructs its member list. The producer stays intact.
                from validate_candidate import preflight_zip
                archive_path = self.target / name
                with archive_path.open("rb") as archive:
                    preflight_zip(archive, MAX_ARCHIVE_ENTRIES, archive_path.stat().st_size)
            return DOSSIER.selected_bytes(self.target, ref)
        except (ValueError, OSError, KeyError):
            raise Blocked("invalid_selected_evidence") from None

    def json(self, ref):
        return parse(self.add(ref))


@contextmanager
def original_git_objects():
    """No replace-object reinterpretation during the existing offline readers."""
    key = "GIT_NO_REPLACE_OBJECTS"
    previous = os.environ.get(key)
    os.environ[key] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def validate_index(index, expected_commit, expected_manifest):
    fields(index, ("format", "candidate", "scope", "candidate_manifest_sha256",
                   "selection", "dossier", "stages"), "index_fields")
    need(index["format"] == VERSION, "unsupported_index_version")
    candidate(index["candidate"])
    need(index["candidate"]["commit"] == expected_commit, "candidate_source_mismatch")
    need(index["candidate_manifest_sha256"] == expected_manifest,
         "candidate_manifest_mismatch")
    need(index["scope"] == SCOPE, "unsupported_publication_scope")
    reference(index["selection"])
    reference(index["dossier"])
    need(index["selection"]["member"] is None and index["dossier"]["member"] is None,
         "index_documents_must_be_plain_files")
    rows = index["stages"]
    need(type(rows) is list and len(rows) == len(RUNTIME.STAGES), "required_stage_inventory")
    for row in rows:
        fields(row, ("id", "report"), "stage_fields")
        reference(row["report"])
    need(tuple(row["id"] for row in rows) == RUNTIME.STAGES, "required_stage_inventory")


def validate_approval(approval, index, index_sha):
    fields(approval, ("format", "candidate", "scope", "index_sha256",
                      "candidate_manifest_sha256", "decision", "operator", "roadmap_decisions"),
           "approval_fields")
    need(approval["format"] == APPROVAL_VERSION, "unsupported_approval_version")
    candidate(approval["candidate"])
    need(approval["candidate"] == index["candidate"], "approval_candidate_mismatch")
    need(approval["scope"] == index["scope"] == SCOPE, "approval_scope_mismatch")
    need(approval["index_sha256"] == index_sha, "approval_index_mismatch")
    need(approval["candidate_manifest_sha256"] == index["candidate_manifest_sha256"],
         "approval_manifest_mismatch")
    need(approval["decision"] == "approved", "external_operator_approval_required")
    try:
        SUPPORT.identifier(approval["operator"], "operator")
    except ValueError:
        raise Blocked("external_operator_identity_required") from None


def collect_selection(snapshot, selection):
    try:
        DOSSIER.validate_manifest(selection)
    except (ValueError, KeyError, TypeError):
        raise Blocked("invalid_dossier_selection") from None
    for name in ("support_index", "workload", "runtime_plan"):
        if name in selection:
            snapshot.add(selection[name])
    for row in selection["evidence"]:
        for name in ("file", "context", "identity_context"):
            if name in row:
                snapshot.add(row[name])


@contextmanager
def frozen_archive(path, expected_sha):
    """Stream bounded, descriptor-checked archive bytes to private disk storage."""
    path = path.absolute()
    for parent in path.parents:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and not parent.is_symlink() and
             not (getattr(info, "st_file_attributes", 0) & 0x400), "unsafe_candidate_archive")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink() and before.st_nlink == 1 and
         not (getattr(before, "st_file_attributes", 0) & 0x400), "unsafe_candidate_archive")
    need(before.st_size <= MAX_ARCHIVE_BYTES, "candidate_archive_byte_limit")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(descriptor)
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
             (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
             "candidate_archive_changed")
        with tempfile.TemporaryFile(mode="w+b") as frozen:
            digest = hashlib.sha256()
            total = 0
            while True:
                raw = os.read(descriptor, min(65536, MAX_ARCHIVE_BYTES + 1 - total))
                if not raw:
                    break
                total += len(raw)
                need(total <= MAX_ARCHIVE_BYTES, "candidate_archive_byte_limit")
                digest.update(raw)
                frozen.write(raw)
            after = os.fstat(descriptor)
            names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            need(all(getattr(opened, key) == getattr(after, key) for key in names) and
                 total == before.st_size and digest.hexdigest() == expected_sha,
                 "candidate_archive_changed")
            frozen.seek(0)
            yield frozen
    finally:
        os.close(descriptor)


def tar_binary(stream, binary_name):
    """Read ordinary tar headers with a shared decompression budget.

    PAX/GNU extension records are refused at their fixed 512-byte header, before
    any extension body can be allocated by a general-purpose tar parser.
    """
    total = 0

    def read(size):
        nonlocal total
        need(total + size <= MAX_ARCHIVE_EXPANSION, "candidate_archive_expansion_limit")
        raw = stream.read(size)
        total += len(raw)
        need(len(raw) == size, "candidate_archive_truncated")
        return raw

    names = set()
    found = None
    while True:
        header = read(512)
        if header == b"\0" * 512:
            need(read(512) == b"\0" * 512, "candidate_archive_trailer")
            while True:
                remaining = MAX_ARCHIVE_EXPANSION - total
                raw = stream.read(min(65536, remaining + 1))
                if not raw:
                    return found
                total += len(raw)
                need(total <= MAX_ARCHIVE_EXPANSION, "candidate_archive_expansion_limit")
                need(not raw.strip(b"\0"), "candidate_archive_trailer")
        need(len(names) < MAX_ARCHIVE_ENTRIES, "candidate_archive_entry_limit")
        info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        need(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
             "unsupported_candidate_archive_extension_or_link")
        name = SUPPORT.relative(info.name.rstrip("/"), "archive member")
        need(name not in names, "candidate_archive_duplicate_member")
        names.add(name)
        need(0 <= info.size <= MAX_BINARY and (info.isfile() or info.size == 0),
             "candidate_archive_member_limit")
        digest = hashlib.sha256() if info.name == binary_name else None
        if digest is not None:
            need(found is None and info.isfile(), "candidate_binary_inventory")
        remaining = info.size
        while remaining:
            block = read(min(65536, remaining))
            if digest is not None:
                digest.update(block)
            remaining -= len(block)
        if digest is not None:
            found = digest.hexdigest()
        padding = (512 - info.size % 512) % 512
        if padding:
            need(read(padding) == b"\0" * padding, "candidate_archive_padding")


def linux_binary(artifacts, manifest_path, manifest_sha, expected_binary):
    """Bind the actual retained Linux archive binary to the readiness runtime."""
    need(artifacts is not None and manifest_path is not None, "candidate_artifact_bytes_required")
    manifest, actual = read_json(manifest_path, MAX_INDEX)
    need(actual == manifest_sha, "candidate_manifest_mismatch")
    try:
        tag = manifest["tag"]
        need(type(tag) is str and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag),
             "candidate_tag_invalid")
        archive_name = "soup-wall-" + tag + "-x86_64-unknown-linux-gnu.tar.gz"
        matches = [row for row in manifest["checksums"]
                   if type(row) is str and row.endswith("  " + archive_name)]
        need(len(matches) == 1 and re.fullmatch(r"[0-9a-f]{64}  " + re.escape(archive_name), matches[0]),
             "candidate_linux_archive_missing")
        archive_path = Path(artifacts) / archive_name
        # The parent custody validator hashes all eleven artifacts. This second
        # streamed snapshot binds inspection to the same approved archive bytes.
        with frozen_archive(archive_path, matches[0][:64]) as frozen:
            with gzip.GzipFile(fileobj=frozen, mode="rb") as stream:
                binary = tar_binary(stream, archive_name[:-7] + "/agentfw")
        need(binary == expected_binary, "candidate_runtime_binary_mismatch")
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, EOFError, tarfile.TarError, zlib.error):
        raise Blocked("invalid_candidate_archive") from None


def roadmap(snapshot, selection, repo, approval):
    index = snapshot.json(selection["support_index"])
    try:
        SUPPORT.validate_index(index)
        commit = selection["candidate"]["commit"]
        need(index == DOSSIER.git_json(repo, commit, "docs/operations/roadmap-support-index.json"),
             "published_support_index_mismatch")
        need(sha(DOSSIER.git_bytes(repo, commit, "docs/ROADMAP.md")) == index["roadmap_sha256"],
             "roadmap_source_mismatch")
        for profile in index["profile_inputs"]:
            need(sha(DOSSIER.git_bytes(repo, commit, profile["path"])) == profile["sha256"],
                 "roadmap_profile_mismatch")
        for descriptor in index["evidence"]:
            snapshot.add({"path": descriptor["path"], "sha256": descriptor["sha256"],
                          "member": None, "member_sha256": None})
        decisions = SUPPORT.validate_decisions(approval["roadmap_decisions"], commit, index)
        report = SUPPORT.build(index, snapshot.target, commit, decisions)
        required = [row for row in report["criteria"] if row["phase"] != "Phase 7"]
        need(len(required) == sum(count for phase, count in SUPPORT.ROADMAP_ORDINALS.items()
                                  if phase != "Phase 7"), "roadmap_inventory_incomplete")
        accepted = 0
        evidence = {item["id"]: item for cap in report["capabilities"] for item in cap["evidence"]}
        for row in required:
            need(row["status"] == "review-recorded" and row["coverage"] and
                 all(cap["status"] == "pending-review" for cap in row["coverage"]),
                 "roadmap_acceptance_incomplete")
            records = row["review_records"]
            need(records and all(item["decision"] == "accepted" for item in records),
                 "roadmap_acceptance_incomplete")
            descriptors = {item["id"]: item for item in index["evidence"]}
            approved_caps = {descriptors[item["evidence_id"]]["capability"] for item in records}
            need(approved_caps == set(row["capabilities"]), "roadmap_capability_review_incomplete")
            if row["phase"] == "Phase 4":
                need(all(evidence[item["evidence_id"]]["observed"]["execution"] == "live-model"
                         for item in records), "live_model_acceptance_missing")
            accepted += 1
        return {"required": len(required), "accepted": accepted}
    except Blocked:
        raise
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        raise Blocked("invalid_roadmap_acceptance") from None


def verify(index_path, root, repo, candidate_commit, manifest_sha256, approval_path,
           artifacts=None, manifest_path=None):
    """Return a content-free admission decision; supplied approvals stay external."""
    result = {"format": RESULT_VERSION, "status": "blocked", "blockers": [],
              "candidate": None, "index_sha256": None, "dossier_status": "unverified",
              "stages": [{"id": stage, "status": "unverified"} for stage in RUNTIME.STAGES],
              "roadmap": {"required": 34, "accepted": 0}}
    try:
        try:
            SUPPORT.source(candidate_commit, "candidate")
            SUPPORT.digest(manifest_sha256, "manifest")
        except ValueError:
            raise Blocked("invalid_expected_identity") from None
        index, index_sha = read_json(index_path, MAX_INDEX)
        validate_index(index, candidate_commit, manifest_sha256)
        result.update(candidate=index["candidate"], index_sha256=index_sha)
        approval, _ = read_json(approval_path, MAX_APPROVAL)
        validate_approval(approval, index, index_sha)
        # An attachment cannot supply its own external decision document.
        approval_absolute = Path(approval_path).absolute()
        try:
            approval_absolute.relative_to(Path(root).absolute())
        except ValueError:
            pass
        else:
            raise Blocked("approval_must_be_external_to_bundle")
        with tempfile.TemporaryDirectory(prefix="publication-readiness-") as temporary, original_git_objects():
            snapshot = Snapshot(root, temporary)
            selection = snapshot.json(index["selection"])
            stored = snapshot.json(index["dossier"])
            collect_selection(snapshot, selection)
            need(selection["candidate"] == index["candidate"], "dossier_candidate_mismatch")
            need(DOSSIER.git_tree(repo, candidate_commit) == index["candidate"]["tree"],
                 "candidate_tree_mismatch")
            rebuilt = DOSSIER.build(selection, snapshot.target, Path(repo))
            result["dossier_status"] = rebuilt["status"]
            if rebuilt["status"] != "READY":
                result["blockers"].append("dossier_not_ready")
            need(set(stored) - METADATA == set(rebuilt) and
                 {key: value for key, value in stored.items() if key not in METADATA} == rebuilt,
                 "dossier_recomputed_verdict_mismatch")
            if selection["format"] != "sw-pilot-dossier-selection/2":
                result["blockers"].append("scoped_readiness_required")
            if result["blockers"]:
                return result
            entries = [row for row in selection["evidence"] if row["role"] == "candidate"]
            need(tuple(row["stage"] for row in entries) == RUNTIME.STAGES,
                 "selection_stage_inventory")
            for row, entry in zip(index["stages"], entries):
                need(row["report"] == entry["file"], "stage_report_binding_mismatch")
                snapshot.add(row["report"])
            result["stages"] = [{"id": stage, "status": "verified"} for stage in RUNTIME.STAGES]
            linux_binary(artifacts, manifest_path, manifest_sha256, selection["identities"]["agentfw"])
            result["roadmap"] = roadmap(snapshot, selection, Path(repo), approval)
            result["status"] = "admitted"
    except Blocked as exc:
        result["blockers"].append(str(exc))
    except (ValueError, OSError, KeyError, TypeError, IndexError, RecursionError, subprocess.SubprocessError):
        result["blockers"].append("readiness_verification_failed")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("index", "root", "repo", "approval", "artifacts", "manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = verify(args.index, args.root, args.repo, args.candidate,
                    args.manifest_sha256, args.approval, args.artifacts, args.manifest)
    if args.json:
        print(json.dumps(report, sort_keys=True, allow_nan=False))
    else:
        print("Publication readiness: " + report["status"])
        for code in report["blockers"]:
            print("- " + code)
    return 0 if report["status"] == "admitted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
