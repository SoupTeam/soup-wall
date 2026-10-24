#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private retention selection and explicit sanitized prepared-run audit export.

Storage and segment verification belong to SOU-84. This module only selects that
store and projects its bounded export through the existing SOU-75 allowlist.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepared_audit_report", ROOT / "scripts/agent-audit-report.py")
REPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REPORT)
FORMAT = "sw-prepared-pilot-audit/1"
LIMITS = {"version": 1, "segment_size_bytes": 65536, "segment_count": 4,
          "total_disk_bytes": 512000, "max_record_bytes": 65536}
MAX_SUMMARY = 128 * 1024
MAX_DECISIONS = 128


def require(value):
    if not value:
        raise ValueError("pilot_audit_identity_invalid")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def private_json(path, snapshot=False):
    """Bounded descriptor-based owner/type/identity read, including ancestors."""
    require(path.is_absolute() and ".." not in path.parts)
    parent = REPORT._open_dir_nofollow(path.parent)
    fd = None
    try:
        p = os.fstat(parent)
        require(p.st_uid == os.getuid() and stat.S_IMODE(p.st_mode) == 0o700)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= 65536)
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        stable = (len(raw) <= 65536 and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino))
        if snapshot and not stable:
            raise REPORT.ReportError("retention changed during export; retry")
        require(stable)
        require(len(raw) == before.st_size and REPORT._bounded_json_depth(raw))
        return json.loads(raw, object_pairs_hook=REPORT._pair_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite metadata")))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def selection(private, source_commit, selection_sha256, policy_sha256, registry_sha256, binary_sha256):
    directory = private / "audit"
    directory.mkdir(mode=0o700)
    info = directory.stat()
    config = dict(LIMITS, directory=str(directory))
    receipt = {"format": FORMAT, "run_id": private.name.removeprefix("soup-wall-run-"),
               "source_commit": source_commit, "selection_sha256": selection_sha256,
               "policy_sha256": policy_sha256, "registry_sha256": registry_sha256,
               "binary_sha256": binary_sha256, "retention": LIMITS,
               "retention_sha256": digest(config), "directory_device": info.st_dev,
               "directory_inode": info.st_ino}
    # This random run-directory name identifies only this isolated daemon history.
    # It is not a native receipt or an authentication claim.
    return config, receipt


def state(private):
    """Current manifest metadata only; never a claim that no execution occurred."""
    try:
        manifest = private_json(private / "audit" / "manifest.json")
        segments = manifest["segments"]
        require(manifest["version"] == 1 and type(segments) is list and 1 <= len(segments) <= 4)
        pruned = manifest["pruned_through"]
        require(type(pruned) is int and 0 <= pruned <= 2**53 - 1)
        return {"state": "manifest_observed", "pruned_through": pruned,
                "retained_segments": len(segments),
                "partial_tail": any(s.get("partial_tail") is True for s in segments),
                "verification": "export_required"}
    except (OSError, ValueError, KeyError, TypeError):
        return {"state": "unavailable", "verification": "unknown"}


def verify_cleanup(private):
    """A completed ordinary run retains only bounded evidence, never credentials."""
    require({entry.name for entry in private.iterdir()} ==
            {"audit", "audit-run.json", "audit-finished.json"})
    receipt = private_json(private / "audit-run.json")
    require(private_json(private / "audit-finished.json") ==
            {"format": FORMAT, "run_id": receipt["run_id"], "owned_processes_stopped": True})
    return receipt["run_id"]


def selected_manifest(directory):
    value = private_json(directory / "manifest.json", snapshot=True)
    require(value.get("version") == 1 and value.get("limits") ==
            {key: limit for key, limit in LIMITS.items() if key != "version"})


def export_run(private, output, expected_run):
    """Export this run only; raw intermediate bytes never enter the summary."""
    require(output.is_absolute() and not output.is_relative_to(private))
    receipt = private_json(private / "audit-run.json")
    require(receipt.get("format") == FORMAT and receipt.get("run_id") == expected_run
            and expected_run == private.name.removeprefix("soup-wall-run-")
            and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", expected_run) is not None
            and receipt.get("retention") == LIMITS)
    for name in ("selection_sha256", "policy_sha256", "registry_sha256", "binary_sha256", "retention_sha256"):
        require(type(receipt.get(name)) is str and re.fullmatch(r"[0-9a-f]{64}", receipt[name]) is not None)
    require(type(receipt.get("source_commit")) is str
            and re.fullmatch(r"[0-9a-f]{40}", receipt["source_commit"]) is not None)
    directory = private / "audit"
    require(receipt["retention_sha256"] == digest(dict(LIMITS, directory=str(directory))))
    fd = REPORT._open_dir_nofollow(directory)
    try:
        info = os.fstat(fd)
        require((info.st_dev, info.st_ino) == (receipt["directory_device"], receipt["directory_inode"]))
    finally:
        os.close(fd)
    selected_manifest(directory)
    # SOU-84 validates manifest, closed hashes, active files, concurrent changes
    # and finite export limits. Missing/rotated/partial evidence remains explicit.
    with tempfile.TemporaryDirectory(prefix="pilot-audit-export-", dir=private) as temporary:
        raw = Path(temporary) / "retained.private.jsonl"
        retained = REPORT.export_retained(directory, raw)
        projected = REPORT._read_report(raw)
    require(private_json(private / "audit-run.json") == receipt)
    selected_manifest(directory)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and
            (info.st_dev, info.st_ino) == (receipt["directory_device"], receipt["directory_inode"]))
    events = projected["events"]
    # Keep only fixed labels/enums, local correlation aliases and booleans. Even
    # hashed arbitrary tool/rule names and raw native identifiers are omitted.
    fields = ("id", "timestamp", "event", "verdict", "stage", "mode", "released", "correlation", "evidence_missing")
    references = [{key: event[key] for key in fields} for event in events[:MAX_DECISIONS]]
    notices = list(retained["notices"])
    if not events:
        notices.append("no_decision_records")
    if any(any("No linked" in reason or "ambiguous" in reason or "unavailable" in reason
               or "truncated" in reason for reason in event["evidence_missing"]) for event in events):
        notices.append("decision_evidence_incomplete")
    if len(events) > MAX_DECISIONS:
        notices.append("decision_reference_limit")
    try:
        finished = private_json(private / "audit-finished.json")
        require(finished == {"format": FORMAT, "run_id": expected_run, "owned_processes_stopped": True})
        lifecycle = "owned_processes_stopped"
    except FileNotFoundError:
        lifecycle = "active_or_interrupted"
        notices.append("run_not_confirmed_stopped")
    summary = {"format": "sw-prepared-pilot-audit-summary/1", "run_id": expected_run,
               **{key: receipt[key] for key in ("source_commit", "selection_sha256", "policy_sha256",
                  "registry_sha256", "binary_sha256", "retention_sha256")},
               "retention": LIMITS, "lifecycle": lifecycle,
               "evidence_source": "local_owner_editable_audit",
               "completeness": "incomplete" if notices or projected["meta"]["source_status"] != "complete" else "selected_history_only",
               "notices": sorted(set(notices)), "gaps": retained["gaps"],
               "source_records": retained["records"], "projected_decisions": len(events),
               "decisions": references, "missing_records_prove_no_execution": False,
               "allow_proves_execution": False}
    body = json.dumps(summary, sort_keys=True, ensure_ascii=True).encode() + b"\n"
    require(len(body) <= MAX_SUMMARY)
    REPORT._private_output(output, body)
    return {"status": "exported", "completeness": summary["completeness"],
            "decisions": len(references), "notices": summary["notices"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = export_run(args.run_directory, args.output, args.run_id)
    except Exception:
        result = {"status": "failed", "reason": "pilot_audit_export_unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "exported" else 1


if __name__ == "__main__":
    raise SystemExit(main())
