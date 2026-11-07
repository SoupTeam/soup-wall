# SPDX-License-Identifier: Apache-2.0
"""Explicit, exact-material maintainer decisions; never a scanner or SPDX waiver.

This file validates a supplied decision. It cannot establish that its author had
authority, that legal advice occurred, or that a native runtime was qualified.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

FORMAT = "sw-pilot-runtime-reviews/1"
MAX_FILE = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
LICENSE_TEXTS = {
    "MPL-2.0": {"3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"},
    "LGPL-3.0-or-later": {
        "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
        "ade78d04982d69972d444a8e14a94f87a2334dd3855cc80348ea8e240aa0df2d",
    },
}
CONDITIONS = {
    "BlueOak-1.0.0": {"notice"},
    "PSF-2.0": {"notice", "modifications"},
    "MPL-2.0": {"notice", "source", "source_instructions"},
    "LGPL-3.0-or-later": {"notice", "source", "recombination", "recipient_rights"},
    "SEE LICENSE IN LICENSE": {"notice", "documentation_attribution"},
}


def require(value, reason):
    if not value:
        raise ValueError("runtime_reviews:" + reason)


def exact(value, fields, reason):
    require(isinstance(value, dict) and set(value) == set(fields.split()), reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def file_sha(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 <= path.stat().st_size <= MAX_FILE,
            "evidence_file_invalid")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bound(root, relative, expected):
    require(isinstance(relative, str) and "\\" not in relative and ":" not in relative, "evidence_path")
    parts = PurePosixPath(relative).parts
    require(parts and not relative.startswith("/") and
            all(part not in {".", ".."} for part in parts) and
            str(PurePosixPath(relative)) == relative, "evidence_path")
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "evidence_digest")
    current = root
    for part in parts:
        current = current / part
        require(not current.is_symlink(), "evidence_symlink")
    require(current.resolve().is_relative_to(root.resolve()) and file_sha(current) == expected,
            "evidence_changed")
    return current


def component(notice):
    return {key: notice.get(key) for key in ("ecosystem", "name", "version", "origin")}


def context(report):
    # The preparation reader verifies the source, complete selected trees and
    # every executable before and after scanning. Bind that exact selection and
    # observed identity/notice material, not just package names or counts.
    return {"source": report["source"], "selection_sha256": report["selection_sha256"],
            "material_sha256": digest({key: report[key] for key in
                ("binaries", "lock_sha256", "notices") } | {
                    key: {report["scan_input_labels"][path]: value for path, value in report[key].items()}
                    for key in ("packages", "scan_input_sha256")})}


def cargo_findings(data):
    require(isinstance(data, dict) and isinstance(data.get("database"), dict) and
            isinstance(data["database"].get("advisory-count"), int) and
            data["database"]["advisory-count"] > 0 and
            data.get("lockfile", {}).get("dependency-count", 0) > 0 and
            data.get("vulnerabilities", {}).get("found") is False and
            data["vulnerabilities"].get("list") == [] and
            isinstance(data.get("warnings"), dict), "cargo_vulnerabilities_or_incomplete")
    findings = []
    for kind, rows in data["warnings"].items():
        require(isinstance(rows, list), "cargo_warning_schema")
        require(not rows or kind == "unmaintained", "cargo_warning_not_reviewable")
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get("package"), dict) and
                    isinstance(row.get("advisory"), dict), "cargo_warning_schema")
            package = row["package"]
            require(isinstance(package.get("name"), str) and isinstance(package.get("version"), str) and
                    row["advisory"].get("informational") == "unmaintained", "cargo_warning_schema")
            findings.append({"scanner": "cargo_audit", "package": {"ecosystem": "crates.io",
                "name": package["name"], "version": package["version"]},
                "source": "Cargo.lock", "advisory": row["advisory"]})
    return findings


def osv_findings(findings, root, installed_input):
    result = []
    for row in findings:
        source = Path(row["source"]).resolve()
        if source == Path(installed_input).resolve():
            label = "installed-python"
        else:
            require(source.is_relative_to(root.resolve()), "advisory_source")
            label = source.relative_to(root.resolve()).as_posix()
        result.append({"scanner": "osv", "package": row["package"], "source": label,
                       "advisory": row["advisory"]})
    return result


def finding_identity(row):
    advisory = row["advisory"]
    require(isinstance(advisory.get("id"), str) and advisory["id"] and
            isinstance(advisory.get("aliases", []), list) and
            all(isinstance(alias, str) and alias for alias in advisory.get("aliases", [])) and
            len(set(advisory.get("aliases", []))) == len(advisory.get("aliases", [])), "advisory_identity")
    return {key: row[key] for key in ("scanner", "package", "source")} | {
        "id": advisory["id"], "aliases": sorted(advisory.get("aliases", [])),
        "advisory_sha256": digest(advisory)}


class Review:
    def __init__(self, data, path, report, expected_commit, generation):
        exact(data, "format binding decision scope requirements licenses advisories", "schema")
        require(data["format"] == FORMAT, "format")
        exact(data["binding"], "source selection_sha256 material_sha256", "binding_schema")
        source = report["source"]
        require(source.get("commit") == expected_commit and
                re.fullmatch(r"[0-9a-f]{40}", source.get("tree", "")) and
                source.get("dirty") is False, "clean_expected_source_required")
        require(data["binding"] == context(report), "binding_mismatch")
        decision = data["decision"]
        exact(decision, "authority recorded_by method checked_at rationale", "decision_schema")
        require(decision["authority"] == "user-delegated-project-maintainer" and
                decision["method"] == "AI-assisted project-maintainer disposition" and
                all(isinstance(decision[key], str) and decision[key].strip()
                    for key in ("recorded_by", "rationale")), "decision_invalid")
        checked = datetime.fromisoformat(decision["checked_at"].replace("Z", "+00:00"))
        require(checked.tzinfo is not None and checked <= datetime.now(timezone.utc), "decision_timestamp")
        scope = data["scope"]
        exact(scope, "platform profiles distribution constraints", "scope_schema")
        require(scope["platform"] == "linux-x86_64" and
                scope["profiles"] == ["filesystem-readonly-v1", "git-readonly-v1"] and
                scope["distribution"] in {"internal", "private-handoff"} and
                isinstance(scope["constraints"], list) and scope["constraints"] and
                all(isinstance(item, str) and item.strip() for item in scope["constraints"]), "scope_invalid")
        self.root = Path(path).resolve().parent
        self.data = data
        self.requirements = {}
        self.used = set()
        copied = {}
        copied_bytes = 0
        require(isinstance(data["requirements"], list) and len(data["requirements"]) <= 256,
                "requirements_schema")
        for item in data["requirements"]:
            exact(item, "id kind files installed_files explanation sources", "requirement_schema")
            require(isinstance(item["id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", item["id"]) and
                    item["id"] not in self.requirements, "duplicate_requirement")
            require(item["kind"] in {"notice", "modifications", "source", "source_instructions",
                    "recombination", "recipient_rights", "documentation_attribution", "advisory_evidence"} and
                    isinstance(item["explanation"], str) and item["explanation"].strip() and
                    isinstance(item["sources"], list) and item["sources"] and
                    all(isinstance(url, str) and url.startswith("https://") for url in item["sources"]),
                    "requirement_invalid")
            require(isinstance(item["files"], dict) and item["files"] and
                    len(item["files"]) <= 4096 and isinstance(item["installed_files"], dict) and
                    len(item["installed_files"]) <= 4096, "requirement_files")
            for name, value in item["files"].items():
                if name in copied:
                    require(copied[name] == value, "conflicting_evidence_digest")
                else:
                    actual = bound(self.root, name, value)
                    copied[name] = value
                    copied_bytes += actual.stat().st_size
                    require(len(copied) <= 10000 and copied_bytes <= MAX_EVIDENCE_BYTES,
                            "evidence_limit")
            for name, value in item["installed_files"].items():
                require(Path(name).is_absolute() and Path(name).resolve().is_relative_to(Path(generation).resolve())
                        and value in item["files"].values(), "installed_source_copy_mismatch")
                bound(Path(generation), Path(name).relative_to(generation).as_posix(), value)
            if item["kind"] == "source":
                require(item["installed_files"], "installed_source_files_required")
            self.requirements[item["id"]] = item
        require(isinstance(data["licenses"], list) and len(data["licenses"]) <= 256 and
                isinstance(data["advisories"], list) and len(data["advisories"]) <= 1024, "rows_schema")

    def requirements_for(self, ids):
        require(isinstance(ids, list) and ids and len(ids) == len(set(ids)) and
                all(isinstance(item, str) and item in self.requirements for item in ids),
                "requirements_missing_or_duplicate")
        self.used.update(ids)
        return [self.requirements[item] for item in ids]

    def licenses(self, notices):
        pending = {digest(component(row)): row for row in notices
                   if row.get("policy_disposition_required")}
        require(len(pending) == sum(bool(row.get("policy_disposition_required")) for row in notices),
                "duplicate_component")
        seen, dispositions = set(), []
        for item in self.data["licenses"]:
            exact(item, "component material_sha256 expression disposition requirements rationale", "license_schema")
            exact(item["component"], "ecosystem name version origin", "component_schema")
            key = digest(item["component"])
            require(key not in seen and key in pending, "duplicate_or_unused_license")
            seen.add(key)
            notice = pending[key]
            require(notice.get("files") and notice.get("attribution", {}).get("status") != "rejected" and
                    item["material_sha256"] == digest(notice) and
                    item["expression"] == notice.get("effective_license") and
                    item["expression"] in CONDITIONS and
                    item["disposition"] == "accepted_with_conditions" and
                    isinstance(item["rationale"], str) and item["rationale"].strip(), "license_material_mismatch")
            requirements = self.requirements_for(item["requirements"])
            require(CONDITIONS[item["expression"]] <= {r["kind"] for r in requirements},
                    "license_conditions_missing")
            bundled_notices = {value for r in requirements if r["kind"] == "notice"
                               for value in r["files"].values()}
            require(set(notice["files"].values()) <= bundled_notices, "notice_copy_missing")
            require(LICENSE_TEXTS.get(item["expression"], set()) <= bundled_notices,
                    "full_license_text_missing")
            dispositions.append(item)
        require(seen == set(pending), "unreviewed_license")
        return dispositions

    def advisories(self, findings):
        observed = {}
        for finding in findings:
            identity = finding_identity(finding)
            key = digest(identity)
            require(key not in observed, "duplicate_observed_finding")
            observed[key] = finding
        seen, dispositions = set(), []
        for item in self.data["advisories"]:
            exact(item, "finding disposition requirements rationale", "advisory_schema")
            exact(item["finding"], "scanner package source id aliases advisory_sha256", "advisory_binding_schema")
            exact(item["finding"]["package"], "ecosystem name version", "advisory_package_schema")
            key = digest(item["finding"])
            require(key not in seen and key in observed, "duplicate_stale_or_unused_advisory")
            seen.add(key)
            finding = observed[key]
            allowed = {"not_applicable"}
            if finding["package"]["ecosystem"] == "crates.io":
                affected = [row for row in finding["advisory"].get("affected", [])
                            if row.get("package", {}).get("ecosystem") == "crates.io"
                            and row["package"].get("name") == finding["package"]["name"]]
                if affected and all(row.get("database_specific", {}).get("informational") ==
                                    "unmaintained" for row in affected):
                    allowed.add("accepted_maintenance_risk")
            if finding["scanner"] == "cargo_audit":
                allowed = {"accepted_maintenance_risk"}
            require(item["disposition"] in allowed and isinstance(item["rationale"], str) and
                    item["rationale"].strip(), "advisory_disposition_invalid")
            evidence = self.requirements_for(item["requirements"])
            require("advisory_evidence" in {r["kind"] for r in evidence}, "advisory_evidence_required")
            dispositions.append(item)
        require(seen == set(observed), "unreviewed_advisory")
        return dispositions

    def finish(self):
        require(self.used == set(self.requirements), "unused_requirement")
        return {"format": FORMAT, "binding": self.data["binding"],
                "decision": self.data["decision"], "scope": self.data["scope"],
                "requirements": self.data["requirements"],
                "license_dispositions": self.data["licenses"],
                "advisory_dispositions": self.data["advisories"]}
