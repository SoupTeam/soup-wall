#!/usr/bin/env python3
"""Build a bounded, offline, private ROADMAP evidence inventory (SOU-80).

This is an acceptance aid. Evidence bytes and self-reported outcomes are never
authority to approve a criterion, a phase, or a product release.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


VERSION = "sw-roadmap-support/1"
EVIDENCE_VERSION = "sw-support-evidence/1"
DECISION_VERSION = "sw-support-decisions/1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
MAX_INDEX = 512 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
MAX_FILES = 128
MAX_CAPABILITIES = 128
MAX_CRITERIA = 64
MAX_DEPTH = 18
ROADMAP_ORDINALS = {"Foundation": 6, "Phase 1": 4, "Phase 2": 6, "Phase 3": 3,
                    "Phase 4": 4, "Phase 5": 5, "Phase 6": 6, "Phase 7": 4}


class Invalid(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def exact(value: object, keys: set[str], label: str) -> dict:
    require(type(value) is dict and set(value) == keys, f"{label}: unexpected or missing fields")
    return value


def word(value: object, label: str, limit: int = 160) -> str:
    require(type(value) is str and 0 < len(value) <= limit, f"{label}: invalid text")
    require(all(ord(c) >= 32 and ord(c) != 127 for c in value), f"{label}: control character")
    return value


def identifier(value: object, label: str) -> str:
    require(type(value) is str and len(value) <= 80 and ID.fullmatch(value) is not None,
            f"{label}: invalid identifier")
    return value


def digest(value: object, label: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    require(type(value) is str and DIGEST.fullmatch(value) is not None, f"{label}: invalid SHA-256")
    return value


def source(value: object, label: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    require(type(value) is str and SHA.fullmatch(value) is not None, f"{label}: invalid source SHA")
    return value


def nonnegative(value: object, label: str) -> int:
    require(type(value) is int and 0 <= value <= 1_000_000, f"{label}: invalid count")
    return value


def relative(value: object, label: str) -> str:
    require(type(value) is str and 0 < len(value) <= 240, f"{label}: invalid path")
    require("\\" not in value and ":" not in value and "\x00" not in value,
            f"{label}: unsafe path")
    parts = PurePosixPath(value).parts
    require(not value.startswith("/") and 0 < len(parts) <= 8 and
            all(p not in ("", ".", "..") for p in parts) and
            str(PurePosixPath(value)) == value, f"{label}: unsafe path")
    return value


def pairs_unique(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def bounded_tree(value: object, depth: int = 0) -> None:
    require(depth <= MAX_DEPTH, "JSON nesting limit exceeded")
    if type(value) is dict:
        require(len(value) <= 512, "JSON object member limit exceeded")
        for key, child in value.items():
            require(type(key) is str and len(key) <= 256, "JSON key limit exceeded")
            bounded_tree(child, depth + 1)
    elif type(value) is list:
        require(len(value) <= 4096, "JSON array limit exceeded")
        for child in value:
            bounded_tree(child, depth + 1)
    elif type(value) is str:
        require(len(value) <= 65536, "JSON string limit exceeded")
    else:
        require(value is None or type(value) in (bool, int, float), "invalid JSON value")


def safe_file(path: Path, limit: int) -> bytes:
    """Read a regular, singly linked file without following existing symlink parents."""
    absolute = path.absolute()
    for parent in reversed(absolute.parents):
        if parent == parent.parent:
            continue
        mode = parent.lstat().st_mode
        require(stat.S_ISDIR(mode) and not parent.is_symlink() and
                not (getattr(parent.lstat(), "st_file_attributes", 0) & 0x400),
                "unsafe input directory")
    info = absolute.lstat()
    require(stat.S_ISREG(info.st_mode) and not absolute.is_symlink() and info.st_nlink == 1,
            "input must be a regular, singly linked file")
    require(not (getattr(info, "st_file_attributes", 0) & 0x400), "reparse input refused")
    require(info.st_size <= limit, "input byte limit exceeded")
    fd = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                "input changed during open")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        require(remaining > 0, "input byte limit exceeded")
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_json(path: Path, limit: int) -> tuple[dict, str]:
    raw = safe_file(path, limit)
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_unique,
                         parse_constant=lambda _x: (_ for _ in ()).throw(Invalid("non-finite JSON number")))
    except Invalid:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise Invalid("invalid UTF-8 JSON") from exc
    bounded_tree(obj)
    require(type(obj) is dict, "JSON root must be an object")
    return obj, hashlib.sha256(raw).hexdigest()


IDENTITY_FIELDS = {"implementation", "policy", "registry", "runtime", "server"}


def validate_identity(value: object, label: str) -> dict:
    obj = exact(value, IDENTITY_FIELDS, label)
    for key in IDENTITY_FIELDS:
        digest(obj[key], f"{label}.{key}", optional=True)
    return obj


def validate_index(obj: dict) -> dict:
    exact(obj, {"version", "roadmap_sha256", "criteria", "capabilities", "evidence",
                "profile_inputs"}, "index")
    require(obj["version"] == VERSION, "unsupported index version")
    digest(obj["roadmap_sha256"], "roadmap_sha256")
    criteria, caps, evidence = obj["criteria"], obj["capabilities"], obj["evidence"]
    require(type(criteria) is list and 1 <= len(criteria) <= MAX_CRITERIA, "criteria count limit")
    require(type(caps) is list and 1 <= len(caps) <= MAX_CAPABILITIES, "capability count limit")
    require(type(evidence) is list and len(evidence) <= MAX_FILES, "evidence count limit")
    seen: set[str] = set()
    for row in criteria:
        exact(row, {"id", "phase", "title", "capabilities"}, "criterion")
        identifier(row["id"], "criterion.id")
        require(row["id"] not in seen, "duplicate criterion ID")
        seen.add(row["id"])
        require(row["phase"] in ("Foundation", *(f"Phase {i}" for i in range(1, 8))), "invalid phase")
        word(row["title"], "criterion.title", 240)
        require(type(row["capabilities"]) is list and len(row["capabilities"]) <= MAX_CAPABILITIES,
                "criterion capability list limit")
        require(all(type(capability) is str for capability in row["capabilities"]),
                "criterion capability must be an ID")
        require(len(set(row["capabilities"])) == len(row["capabilities"]), "duplicate criterion capability")
    criterion_ids = seen.copy()
    expected_ids = {("foundation" if phase == "Foundation" else phase.lower().replace(" ", "-")) +
                    f".{ordinal}" for phase, length in ROADMAP_ORDINALS.items()
                    for ordinal in range(1, length + 1)}
    require(criterion_ids == expected_ids and len(criteria) == len(expected_ids),
            "ROADMAP criterion set is incomplete or renamed")
    for row in criteria:
        expected_phase = ("Foundation" if row["id"].startswith("foundation.") else
                          "Phase " + row["id"].split(".")[0].split("-")[1])
        require(row["phase"] == expected_phase, "criterion phase mismatch")
    seen.clear()
    for row in caps:
        exact(row, {"id", "title", "platform", "architecture", "host", "transport",
                    "server", "profile", "support", "fail_mode", "limits", "identity"}, "capability")
        identifier(row["id"], "capability.id")
        require(row["id"] not in seen, "duplicate capability ID")
        seen.add(row["id"])
        for key in ("title", "host", "transport", "server", "profile", "fail_mode", "limits"):
            word(row[key], f"capability.{key}", 280)
        require(row["platform"] in ("linux", "macos", "windows"), "invalid platform")
        require(row["architecture"] in ("x86_64", "aarch64"), "invalid architecture")
        require(row["support"] in ("supported", "conditional", "unsupported"), "invalid support")
        validate_identity(row["identity"], "capability.identity")
    cap_ids = seen.copy()
    for row in criteria:
        require(set(row["capabilities"]) <= cap_ids, "unknown criterion capability")
    inputs = obj["profile_inputs"]
    require(type(inputs) is list and len(inputs) <= MAX_FILES, "profile input count limit")
    seen_paths = set()
    for row in inputs:
        exact(row, {"capability", "path", "identity_field", "sha256"}, "profile input")
        require(type(row["capability"]) is str and row["capability"] in cap_ids,
                "unknown profile input capability")
        relative(row["path"], "profile input path")
        require(row["path"] not in seen_paths, "duplicate profile input path")
        seen_paths.add(row["path"])
        require(type(row["identity_field"]) is str and row["identity_field"] in IDENTITY_FIELDS,
                "invalid profile identity field")
        digest(row["sha256"], "profile input SHA-256")
        cap = next(c for c in caps if c["id"] == row["capability"])
        require(cap["identity"][row["identity_field"]] == row["sha256"],
                "profile input/identity mismatch")
    seen.clear()
    for row in evidence:
        exact(row, {"id", "capability", "path", "sha256", "format", "kind", "source",
                    "platform", "architecture", "host", "transport", "server", "profile", "identity"},
              "evidence descriptor")
        identifier(row["id"], "evidence.id")
        require(row["id"] not in seen, "duplicate evidence ID")
        seen.add(row["id"])
        require(type(row["capability"]) is str and row["capability"] in cap_ids,
                "unknown evidence capability")
        relative(row["path"], "evidence.path")
        digest(row["sha256"], "evidence.sha256")
        require(row["format"] in ("sou54-followup/1", "sou56-https-get/1", "sw-self-test/1",
                                  "sou63-component/1", EVIDENCE_VERSION), "unsupported report version")
        require(row["kind"] in ("component", "integrated-candidate"), "invalid evidence kind")
        source(row["source"], "evidence.source", optional=True)
        require(row["platform"] in ("linux", "macos", "windows") and
                row["architecture"] in ("x86_64", "aarch64"), "invalid evidence platform")
        for key in ("host", "transport", "server", "profile"):
            word(row[key], f"evidence.{key}")
        validate_identity(row["identity"], "evidence.identity")
        cap = next(c for c in caps if c["id"] == row["capability"])
        require(all(row[k] == cap[k] for k in ("platform", "architecture", "host", "transport", "server", "profile")),
                "evidence/profile mismatch in index")
        require(row["identity"] == cap["identity"], "evidence/identity mismatch in index")
        require(cap["support"] != "unsupported", "unsupported capability cannot have positive evidence")
    return obj


def validate_profile_inputs(index: dict, source_root: Path) -> None:
    for row in index["profile_inputs"]:
        path = source_root.joinpath(*PurePosixPath(row["path"]).parts)
        require(hashlib.sha256(safe_file(path, MAX_REPORT)).hexdigest() == row["sha256"],
                "profile input changed since index review")


def counts(passed: object, failed: object, skipped: object, expected: object) -> dict:
    p, f, s, e = (nonnegative(v, k) for v, k in
                  ((passed, "passed"), (failed, "failed"), (skipped, "skipped"), (expected, "expected")))
    return {"passed": p, "failed": f, "skipped": s, "expected": e,
            "complete": e > 0 and p == e and f == 0 and s == 0}


def project_report(obj: dict, fmt: str) -> dict:
    """Extract only allowlisted identities and counts; never copy raw report text."""
    if fmt == "sou54-followup/1":
        require(obj.get("schema_version") == "sou54-complete-followup/1", "report version mismatch")
        env, run = obj["environment"], obj["stdio"]
        source_id = source(obj["runtime_source"], "runtime source")
        require(env["source"] == source_id and env["architecture"] == "aarch64", "source/platform mismatch")
        result = counts(run["passed"], run["failed"], run["skips"], run["cases_expected"])
        require(run["cases_run"] == result["passed"] + result["failed"] + result["skipped"],
                "run denominator mismatch")
        return {"source": source_id, "platform": "linux", "architecture": "aarch64",
                "implementation": digest(obj["runtime_input_sha256"], "input manifest"),
                "runtime": digest(env["binary_sha256"]["agentfw"], "binary"), "counts": result,
                "execution": "scripted-host", "version": obj["schema_version"]}
    if fmt == "sou56-https-get/1":
        source_id = source(obj["exact_build_runtime_source"], "runtime source")
        env, run = obj["environment"], obj["runtime"]
        require(env["source"] == source_id and env["binary_build_source"] == source_id and
                env["architecture"] == "aarch64", "source/platform mismatch")
        result = counts(run["passed"], run["failed"], run["skips"], run["cases_expected"])
        require(run["cases_run"] == result["passed"] + result["failed"] + result["skipped"],
                "run denominator mismatch")
        return {"source": source_id, "platform": "linux", "architecture": "aarch64",
                "implementation": digest(env["source_manifest_sha256"], "input manifest"),
                "runtime": digest(obj["binary_sha256"], "binary"), "counts": result,
                "execution": "scripted-host", "version": "sou56-https-get/1"}
    if fmt == "sw-self-test/1":
        require(obj.get("schema_version") == fmt, "report version mismatch")
        profile, ids, summary = obj["profile"], obj["identities"], obj["summary"]
        p, f, incomplete = (nonnegative(summary[k], k) for k in ("passed", "failed", "incomplete"))
        unavailable, unsupported = (nonnegative(summary[k], k) for k in ("unavailable", "unsupported"))
        expected = len(obj["scenarios"])
        require(expected <= 128 and p + f + incomplete + unavailable + unsupported == expected,
                "scenario denominator mismatch")
        require(type(obj["scenarios"]) is list and len({s["id"] for s in obj["scenarios"]}) == expected,
                "duplicate or malformed self-test scenario")
        actual_status = {name: sum(s["status"] == name for s in obj["scenarios"])
                         for name in ("passed", "failed", "incomplete", "unavailable", "unsupported")}
        require(actual_status == {"passed": p, "failed": f, "incomplete": incomplete,
                                  "unavailable": unavailable, "unsupported": unsupported},
                "self-test scenario/status mismatch")
        result = counts(p, f + incomplete + unavailable + unsupported, 0, expected)
        require(obj["result"] == "passed" and obj["exit_code"] == 0 or not result["complete"],
                "contradictory self-test result")
        return {"source": None, "platform": profile["os"], "architecture": profile["arch"],
                "implementation": None, "policy": digest(ids["policy"]["sha256"], "policy"),
                "registry": digest(ids["registry"]["sha256"], "registry"),
                "runtime": digest(ids["agent"]["sha256"], "binary"), "counts": result,
                "execution": "scripted-host", "version": fmt,
                "profile": profile["id"]}
    if fmt == "sou63-component/1":
        require("workspace" in obj and "platform" in obj, "report version mismatch")
        work = obj["workspace"]
        result = counts(work["passed"], work["failed"], work["ignored"],
                        work["passed"] + work["failed"] + work["ignored"])
        return {"source": None, "platform": "macos", "architecture": "aarch64",
                "implementation": None, "runtime": None, "counts": result,
                "execution": "component-test", "version": fmt}
    exact(obj, {"version", "source", "platform", "architecture", "host", "transport", "server",
                "profile", "identity", "execution", "outcome", "counts"}, "evidence report")
    require(obj["version"] == EVIDENCE_VERSION, "report version mismatch")
    source(obj["source"], "report.source")
    require(obj["platform"] in ("linux", "macos", "windows") and
            obj["architecture"] in ("x86_64", "aarch64"), "invalid report platform")
    for k in ("host", "transport", "server", "profile"):
        word(obj[k], f"report.{k}")
    validate_identity(obj["identity"], "report.identity")
    require(obj["execution"] in ("scripted-host", "original-host", "live-model"),
            "invalid execution class")
    require(obj["outcome"] in ("passed", "failed", "incomplete"), "invalid report outcome")
    c = exact(obj["counts"], {"passed", "failed", "skipped", "expected"}, "report counts")
    result = counts(c["passed"], c["failed"], c["skipped"], c["expected"])
    require(result["passed"] + result["failed"] + result["skipped"] == result["expected"],
            "report denominator mismatch")
    require(obj["outcome"] == "passed" or not result["complete"], "contradictory outcome")
    return {"source": obj["source"], "platform": obj["platform"],
            "architecture": obj["architecture"], "identity": obj["identity"], "counts": result,
            "execution": obj["execution"], "version": obj["version"],
            "host": obj["host"], "transport": obj["transport"], "server": obj["server"],
            "profile": obj["profile"]}


def evaluate(descriptor: dict, root: Path, target: str, cap: dict) -> dict:
    base = {"id": descriptor["id"], "path": descriptor["path"], "expected_sha256": descriptor["sha256"],
            "format": descriptor["format"], "kind": descriptor["kind"], "status": "invalid",
            "reason": "Evidence could not be validated", "observed": None}
    path = root.joinpath(*PurePosixPath(descriptor["path"]).parts)
    if not path.exists() and not path.is_symlink():
        return {**base, "status": "missing", "reason": "Report file is absent"}
    try:
        obj, actual = load_json(path, MAX_REPORT)
        require(actual == descriptor["sha256"], "SHA-256 mismatch")
        observation = project_report(obj, descriptor["format"])
        require(observation["source"] == descriptor["source"], "source identity mismatch")
        require(observation["platform"] == descriptor["platform"] and
                observation["architecture"] == descriptor["architecture"], "platform identity mismatch")
        for key in IDENTITY_FIELDS:
            if descriptor["identity"][key] is not None:
                measured = observation["identity"].get(key) if "identity" in observation else observation.get(key)
                require(measured == descriptor["identity"][key], f"{key} identity mismatch")
        for key in ("host", "transport", "server", "profile"):
            if key in observation:
                require(observation[key] == descriptor[key], f"{key} identity mismatch")
        observed = {"sha256": actual, "source": observation["source"],
                    "platform": observation["platform"], "architecture": observation["architecture"],
                    "counts": observation["counts"], "execution": observation["execution"],
                    "version": observation["version"], "identity": descriptor["identity"]}
        if not observation["counts"]["complete"]:
            status, reason = "incomplete", "Failed, skipped, zero-denominator or incomplete checks"
        elif observation["source"] is None:
            status, reason = "unbound", "Report does not bind execution to one clean source commit"
        elif observation["source"] != target:
            status, reason = "historical", "Validated component evidence is from another source revision"
        elif cap["platform"] != observation["platform"] or cap["architecture"] != observation["architecture"]:
            status, reason = "mismatch", "Target platform or architecture differs"
        elif descriptor["kind"] == "component":
            status, reason = "component", "Exact-source component check; integrated acceptance remains open"
        elif any(descriptor["identity"][k] is None for k in IDENTITY_FIELDS):
            status, reason = "unbound", "Integrated report lacks required exact identities"
        else:
            status, reason = "pending-review", "Mechanically matching candidate; operator review required"
        return {**base, "status": status, "reason": reason, "observed": observed}
    except (Invalid, KeyError, TypeError, IndexError, OSError) as exc:
        return {**base, "reason": str(exc) if isinstance(exc, Invalid) else "Malformed or unsafe report"}


def validate_decisions(obj: dict, target: str, index: dict) -> list[dict]:
    exact(obj, {"version", "source", "decisions"}, "decisions")
    require(obj["version"] == DECISION_VERSION and obj["source"] == target,
            "decision source/version mismatch")
    rows = obj["decisions"]
    require(type(rows) is list and len(rows) <= 128, "decision count limit")
    evidence_ids = {e["id"] for e in index["evidence"]}
    criterion_ids = {c["id"] for c in index["criteria"]}
    seen = set()
    bindings = set()
    for row in rows:
        exact(row, {"decision_id", "criterion_id", "evidence_id", "evidence_sha256", "decision"}, "decision")
        identifier(row["decision_id"], "decision ID")
        require(row["decision_id"] not in seen, "duplicate decision ID")
        seen.add(row["decision_id"])
        require(type(row["criterion_id"]) is str and type(row["evidence_id"]) is str and
                row["criterion_id"] in criterion_ids and row["evidence_id"] in evidence_ids,
                "unknown decision binding")
        binding = (row["criterion_id"], row["evidence_id"])
        require(binding not in bindings, "duplicate decision binding")
        bindings.add(binding)
        digest(row["evidence_sha256"], "decision evidence digest")
        require(row["decision"] in ("accepted", "rejected"), "invalid decision")
    return rows


def build(index: dict, root: Path, target: str, decisions: list[dict]) -> dict:
    evidence = {e["id"]: evaluate(e, root, target,
                                   next(c for c in index["capabilities"] if c["id"] == e["capability"]))
                for e in index["evidence"]}
    cap_rows = []
    for cap in index["capabilities"]:
        descriptors = [e for e in index["evidence"] if e["capability"] == cap["id"]]
        related = [evidence[e["id"]] for e in descriptors]
        if cap["support"] == "unsupported":
            status, blocker = "unsupported", cap["fail_mode"]
        elif not related:
            status, blocker = "missing", "No retained report is indexed for this capability"
        else:
            target_blockers = [evidence[e["id"]] for e in descriptors if e["source"] == target and
                               evidence[e["id"]]["status"] in
                               ("invalid", "incomplete", "missing", "mismatch", "unbound")]
            priority = (("invalid", "incomplete", "missing", "mismatch", "unbound") if target_blockers else
                        ("pending-review", "component", "historical", "unbound", "mismatch", "incomplete", "invalid", "missing"))
            selected = target_blockers or related
            status = next((s for s in priority if any(r["status"] == s for r in selected)), "missing")
            blocker = next(r["reason"] for r in related if r["status"] == status)
        cap_rows.append({**cap, "status": status, "blocker": blocker, "evidence": related})
    cap_by_id = {c["id"]: c for c in cap_rows}
    for decision in decisions:
        item = evidence[decision["evidence_id"]]
        descriptor = next(e for e in index["evidence"] if e["id"] == decision["evidence_id"])
        criterion = next(c for c in index["criteria"] if c["id"] == decision["criterion_id"])
        require(descriptor["capability"] in criterion["capabilities"] and
                cap_by_id[descriptor["capability"]]["status"] == "pending-review" and
                item["status"] == "pending-review" and
                item["observed"]["sha256"] == decision["evidence_sha256"],
                "decision does not bind matching candidate evidence and criterion")
    criterion_rows = []
    for criterion in index["criteria"]:
        linked = [cap_by_id[c] for c in criterion["capabilities"]]
        approved = []
        for decision in decisions:
            if decision["criterion_id"] != criterion["id"]:
                continue
            approved.append({"decision_id": decision["decision_id"], "decision": decision["decision"],
                             "evidence_id": decision["evidence_id"]})
        review_status = ("review-rejected" if any(r["decision"] == "rejected" for r in approved) else
                         "review-recorded" if approved else "open")
        criterion_rows.append({**criterion, "status": review_status,
                               "review_records": approved,
                               "blockers": [f"{c['title']}: {c['blocker']}" for c in linked] or
                               ["No indexed evidence maps to this full ROADMAP criterion"],
                               "coverage": [{"id": c["id"], "status": c["status"]} for c in linked]})
    return {"version": VERSION, "target_source": target, "scope": "private offline acceptance aid",
            "notice": "Integrity and self-reported outcomes are not execution authentication or human approval. No phase completion is inferred.",
            "criteria": criterion_rows, "capabilities": cap_rows,
            "summary": {s: sum(c["status"] == s for c in cap_rows) for s in
                        ("unsupported", "missing", "invalid", "incomplete", "mismatch", "unbound",
                         "historical", "component", "pending-review")}}


def render(report: dict, css: str, js: str) -> str:
    payload = json.dumps(report, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    script = "const REPORT=" + payload + ";\n" + js
    csp = ("default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; "
           "img-src 'none'; font-src 'none'; object-src 'none'; "
           f"style-src 'sha256-{base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()}'; "
           f"script-src 'sha256-{base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()}'")
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" "
            "content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" "
            f"content=\"{csp}\"><title>Roadmap evidence · private</title><style>{css}</style>"
            "<main><header><p class=\"eyebrow\">SOUP WALL / PRIVATE EVIDENCE</p>"
            "<h1>Roadmap support matrix</h1><p id=\"intro\"></p></header>"
            "<section class=\"controls\" aria-label=\"Filters\"><label>Phase <select id=\"phase\"></select></label>"
            "<label>Platform <select id=\"platform\"></select></label>"
            "<label>Status <select id=\"status\"></select></label></section>"
            "<p id=\"summary\" aria-live=\"polite\"></p>"
            "<nav class=\"pager\" aria-label=\"Criterion pages\"><button id=\"prev\" type=\"button\">Previous</button>"
            "<span id=\"page-label\" aria-live=\"polite\"></span>"
            "<button id=\"next\" type=\"button\">Next</button></nav>"
            "<section id=\"cards\" aria-label=\"Criteria\"></section>"
            "<footer>Local report. Hashes show integrity, not authenticity. Review records are operator supplied.</footer>"
            f"</main><script>{script}</script></html>")


def write_private(directory: Path, name: str, data: bytes) -> None:
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        (directory / name).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="full clean candidate commit SHA")
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--roadmap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new private output directory")
    parser.add_argument("--decisions", type=Path, help="optional, explicit operator decision JSON")
    args = parser.parse_args(argv)
    try:
        source(args.source, "target source")
        index = validate_index(load_json(args.index, MAX_INDEX)[0])
        require(hashlib.sha256(safe_file(args.roadmap, MAX_REPORT)).hexdigest() == index["roadmap_sha256"],
                "ROADMAP changed since index review")
        validate_profile_inputs(index, args.roadmap.absolute().parent.parent)
        root = args.evidence_dir.absolute()
        require(root.is_dir() and not root.is_symlink(), "invalid evidence directory")
        decision_rows = validate_decisions(load_json(args.decisions, MAX_INDEX)[0], args.source, index) if args.decisions else []
        report = build(index, root, args.source, decision_rows)
        assets = Path(__file__).with_name("roadmap_support_assets")
        css = safe_file(assets / "report.css", 128 * 1024).decode("utf-8")
        js = safe_file(assets / "report.js", 128 * 1024).decode("utf-8")
        require(args.output.parent.is_dir() and not args.output.parent.is_symlink() and
                not (getattr(args.output.parent.lstat(), "st_file_attributes", 0) & 0x400),
                "output parent must be a regular private directory")
        args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        try:
            json_data = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode()
            html_data = render(report, css, js).encode()
            require(len(json_data) <= MAX_OUTPUT and len(html_data) <= MAX_OUTPUT,
                    "private output byte limit exceeded")
            write_private(args.output, "report.json", json_data)
            write_private(args.output, "index.html", html_data)
        except Exception:
            for name in ("report.json", "index.html"):
                (args.output / name).unlink(missing_ok=True)
            args.output.rmdir()
            raise
        print(f"Private report: {args.output / 'index.html'}")
        print("No ROADMAP criterion or phase was automatically approved.")
        return 0
    except (Invalid, OSError, UnicodeError) as exc:
        print(f"roadmap-support: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
