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

# SOU-228 installed Linux reports. One producer format carries two report
# shapes, so the reviewed index selects the variant and the adapter verifies it.
INSTALLED_REPORT = "sw-installed-front-door-qualification/1"
FRONT_DOOR_FORMAT = "sw-installed-front-door/standard/1"
SCOPE_FORMAT = "sw-installed-front-door/linux-v1-scope/1"
CLEAN_USER_FORMAT = "sw-installed-front-door/clean-user/1"
# Native binaries are rebuilt in every run and byte equality is not claimed:
# these rows pin their own runtime digest while the capability leaves it null.
PER_RUN_FORMATS = (FRONT_DOOR_FORMAT, SCOPE_FORMAT, CLEAN_USER_FORMAT)
COMPANION_ROLES = {FRONT_DOOR_FORMAT: ("installed-pilot", "demo"), SCOPE_FORMAT: ("installed-pilot", "demo"),
                   CLEAN_USER_FORMAT: ("walkthrough", "ask", "user-session", "user-session-after-cleanup")}
STANDARD_CASES = ("component-install", "preview-zero-effect", "prepare-and-reuse", "existing-selection-status",
                  "status-configured", "useful", "status-after-run", "cancel")
SCOPE_CASES = ("scope-selected-through-preview-and-prepare", "excluded-option-preview",
               "standard-cases-ran-under-scope", "excluded-capability-refused", "tampered-scope-refused",
               "unselected-claims-nothing", "status-never-claims-more", "owned-cleanup")
INSTALLED_PILOT_CASES = ("exact-installed-inputs", "sandbox-positive", "witness-calibration", "read-and-history",
                         "inspect-and-diff", "untrusted-input-refusal", "independent-conversation",
                         "parallel-cancellation", "collector-recovery", "daemon-fresh-conversation",
                         "bad-input-controls", "final-cleanup")
DEMO_CASES = ("plan", "occupied-port", "stale-source", "changed-selection", "provider-unavailable",
              "useful-refusal", "ask", "default", "cancel", "daemon-loss", "host-crash", "timeout")
CLEAN_USER_TASKS = ("read-contract", "review-pending-diff", "trace-local-history", "inspect-last-commit")
CLEAN_USER_CASES = ("component-install",
                    *(project + ":" + task for project in ("catalog-service", "release-ledger")
                      for task in (*CLEAN_USER_TASKS, "denied-calls")),
                    "documented-walkthrough", "ask-once-replay", "update-rollback", "remove-preserves-user-data")
MAINTENANCE_REFUSALS = ("entered-updated-b", "entered-rolled-back-a")
INPUT_ROLES = {"agentfw", "bwrap", "claude", "git", "git_launcher", "node_archive", "python", "sandbox_tests"}
SCOPE_ID = "linux-v1"
UNVERIFIED_RECEIPT_ABSENT = "build receipt: not recorded by this report"
UNVERIFIED_RECEIPT_BYTES = "build receipt: only its SHA-256 is retained; the receipt bytes are absent"
UNVERIFIED_WITNESS = "independent witness: refusal, receiver and cleanup witnesses are measurement-driver records"
UNVERIFIED_SEALED = "independent witness: sealed process provenance is not verifiable offline"
UNVERIFIED_GENERATION = "companion generation: linked by binary identity only, not by a selection digest"
UNVERIFIED_DRIVER = "custody: the measurement driver differs from the tested product source"


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
    # A file may become a FIFO between lstat and open: do not block before
    # the descriptor type/identity checks can reject the replacement.
    fd = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
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
        per_run = type(row) is dict and row.get("format") in PER_RUN_FORMATS
        exact(row, {"id", "capability", "path", "sha256", "format", "kind", "source",
                    "platform", "architecture", "host", "transport", "server", "profile", "identity",
                    *(("companions",) if per_run else ())},
              "evidence descriptor")
        identifier(row["id"], "evidence.id")
        require(row["id"] not in seen, "duplicate evidence ID")
        seen.add(row["id"])
        require(type(row["capability"]) is str and row["capability"] in cap_ids,
                "unknown evidence capability")
        relative(row["path"], "evidence.path")
        digest(row["sha256"], "evidence.sha256")
        require(row["format"] in ("sou54-followup/1", "sou56-https-get/1", "sw-self-test/1",
                                  "sou63-component/1", EVIDENCE_VERSION, *PER_RUN_FORMATS),
                "unsupported report version")
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
        if per_run:
            require(row["kind"] == "integrated-candidate" and row["source"] is not None,
                    "per-run evidence must be integrated and source-bound")
            validate_companions(row["companions"], row["format"], row["path"])
            require(cap["identity"]["runtime"] is None and row["identity"]["runtime"] is not None,
                    "per-run runtime digest must be pinned on the evidence row only")
            require(all(row["identity"][k] == cap["identity"][k] for k in IDENTITY_FIELDS - {"runtime"}),
                    "evidence/identity mismatch in index")
        else:
            require(row["identity"] == cap["identity"], "evidence/identity mismatch in index")
        require(cap["support"] != "unsupported", "unsupported capability cannot have positive evidence")
    return obj


def validate_companions(rows: object, fmt: str, main_path: str) -> None:
    roles = COMPANION_ROLES[fmt]
    require(type(rows) is list and len(rows) <= len(roles), "companion count limit")
    seen_roles, seen_paths = set(), {main_path}
    for row in rows:
        exact(row, {"role", "path", "sha256"}, "companion")
        require(row["role"] in roles and row["role"] not in seen_roles, "unknown or duplicate companion role")
        seen_roles.add(row["role"])
        relative(row["path"], "companion path")
        require(row["path"] not in seen_paths, "duplicate companion path")
        seen_paths.add(row["path"])
        digest(row["sha256"], "companion SHA-256")


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


def clean_source(value: object, label: str, commit: str | None = None, tree: str | None = None,
                 extra: tuple[str, ...] = ()) -> tuple[str, str]:
    obj = exact(value, {"commit", "tree", "dirty", *extra}, label)
    source(obj["commit"], label + ".commit")
    source(obj["tree"], label + ".tree")
    require(obj["dirty"] is False, label + ": source was not clean")
    for key in extra:
        digest(obj[key], label + "." + key)
    require(commit is None or (obj["commit"], obj["tree"]) == (commit, tree), label + ": source identity mismatch")
    return obj["commit"], obj["tree"]


def case_outcomes(rows: object, expected: tuple[str, ...], label: str, key: str,
                  words: tuple[str, ...]) -> list[str]:
    """Return the non-passed case IDs of a fixed, ordered, unique inventory."""
    require(type(rows) is list and all(type(row) is dict for row in rows) and
            [row.get(key) for row in rows] == list(expected), label + ": case inventory mismatch")
    require(all(row.get("status") in words for row in rows), label + ": invalid case status")
    return [row[key] for row in rows if row["status"] != "passed"]


def same_binaries(selected: object, inputs: dict, roles: tuple[str, ...], label: str) -> None:
    require(type(selected) is dict and all(selected.get(role) == inputs[role] for role in roles),
            label + ": selected binaries differ from the qualified inputs")


def demo_outcomes(demo: dict, commit: str, tree: str, label: str) -> list[str]:
    require(demo.get("format") == "sw-pilot-demo/1" and demo.get("provider") == "owned-scripted-loopback" and
            demo.get("live_model_effectiveness") == "not_tested", label + ": version or claim field mismatch")
    rows = demo.get("cases")
    require(type(rows) is list and all(type(row) is dict for row in rows) and
            [row.get("case") for row in rows] == list(DEMO_CASES), label + ": case inventory mismatch")
    require(all(type(row.get("status")) is str for row in rows), label + ": invalid case status")
    unfinished = [row["case"] for row in rows if row["status"] != "passed"]
    require(demo.get("status") in ("passed", "failed") and (demo["status"] == "passed") == (not unfinished),
            label + ": status contradicts case outcomes")
    for key in ("source", "source_before"):
        clean_source(demo[key], label + "." + key, commit, tree, ("files_sha256",))
    if demo["status"] == "passed":
        clean_source(demo["source_after"], label + ".source_after", commit, tree, ("files_sha256",))
        require(demo.get("fixture_cleanup", {}).get("complete") is True, label + ": fixture cleanup incomplete")
    return unfinished


def front_door_companions(companions: dict, commit: str, tree: str, inputs: dict,
                          required: bool) -> tuple[list[int], str | None, str | None]:
    """Installed acceptance and first-use demo on the generation the front door prepared."""
    pilot, demo = companions.get("installed-pilot"), companions.get("demo")
    require(not required or (pilot is not None and demo is not None),
            "index omits a companion report required by a passed front-door report")
    tally, policy, architecture = [0, 0, 0], None, None
    if pilot is None:
        tally[2] += len(INSTALLED_PILOT_CASES)
    else:
        pilot = pilot[0]
        require(pilot.get("format") == "sw-installed-pilot/1" and pilot.get("required") == len(INSTALLED_PILOT_CASES)
                and pilot.get("pilot_readiness") == "not_certified", "installed-pilot: version or claim field mismatch")
        open_cases = case_outcomes(pilot.get("cases"), INSTALLED_PILOT_CASES, "installed-pilot", "id",
                                   ("passed", "failed", "incomplete", "unsupported"))
        statuses = [row["status"] for row in pilot["cases"]]
        reported = exact(pilot.get("counts"), {"passed", "failed", "incomplete", "unsupported"}, "installed-pilot counts")
        require(reported == {word: statuses.count(word) for word in reported}, "installed-pilot: counts disagree with cases")
        require(pilot.get("status") in ("passed", "failed", "incomplete") and
                (pilot["status"] == "passed") == (not open_cases) and
                type(pilot.get("remaining_blockers")) is list and
                [row.get("case") for row in pilot["remaining_blockers"]] == open_cases,
                "installed-pilot: status contradicts case outcomes")
        clean_source(pilot["source_before"], "installed-pilot.source_before", commit, tree, ("files_sha256",))
        if pilot["status"] == "passed":
            clean_source(pilot["source_after"], "installed-pilot.source_after", commit, tree, ("files_sha256",))
        environment = pilot.get("environment", {})
        require(environment.get("os") == "Linux", "installed-pilot: not a native Linux host")
        architecture = environment.get("machine") if environment.get("machine") in ("x86_64", "aarch64") else None
        selected = pilot.get("selected_sha256")
        same_binaries(selected, inputs, ("agentfw", "bwrap", "claude", "git", "git_launcher", "python", "sandbox_tests"),
                      "installed-pilot")
        policy = digest(selected.get("policy"), "installed-pilot policy")
        tally[0] += len(INSTALLED_PILOT_CASES) - len(open_cases)
        tally[1] += len(open_cases)
    if demo is None:
        tally[2] += len(DEMO_CASES)
    else:
        demo = demo[0]
        unfinished = demo_outcomes(demo, commit, tree, "demo")
        if pilot is not None:
            require(demo.get("selected_sha256") == pilot["selected_sha256"], "demo: generation differs from installed-pilot")
        else:
            same_binaries(demo.get("selected_sha256"), inputs, ("agentfw",), "demo")
        tally[0] += len(DEMO_CASES) - len(unfinished)
        tally[1] += len(unfinished)
    return tally, policy, architecture


SCOPE_FACTS = {
    "excluded-option-preview": {"refused": ["capability-git-profiles"]},
    "standard-cases-ran-under-scope": {"live_scope_mode": "enforce"},
    "excluded-capability-refused": {"reason": "scope_excludes_capability", "selected_started": 0,
                                    "network_connections": 0, "prefix_unchanged": True},
    "tampered-scope-refused": {"reason": "scope_document_changed", "selected_started": 0},
    "unselected-claims-nothing": {"protection": "not-configured"},
    "status-never-claims-more": {"acceptance": "not-claimed", "enforce_only_when_observed_live": True},
    "owned-cleanup": {"sources_preserved": True, "receiver_effects": 0},
}


def project_front_door(obj: dict, fmt: str, companions: dict) -> dict:
    require("clean_user" not in obj, "a clean-user report is not front-door evidence")
    require(obj.get("provider") == "owned-scripted-loopback" and obj.get("live_model_effectiveness") == "not_tested"
            and obj.get("skipped") == 0, "unsupported provider or claim field")
    require(obj.get("status") in ("passed", "failed"), "invalid report status")
    passed = obj["status"] == "passed"
    require(passed == (obj.get("error") is None), "report status contradicts its error")
    rows = obj.get("cases")
    inventory = STANDARD_CASES + SCOPE_CASES
    require(type(rows) is list and all(type(row) is dict for row in rows), "front-door case inventory mismatch")
    names = [row.get("case") for row in rows]
    require(names == list(inventory[:len(names)]) and all(row.get("passed") is True for row in rows),
            "front-door case inventory mismatch")
    require(not passed or len(names) == len(inventory), "passed report lacks required cases")
    nested = obj.get("pilot_scope_qualification")
    # Only the reviewed pilot-scope focus is inventoried; an honest early failure may precede it.
    require(nested is not None or (not passed and len(names) <= len(STANDARD_CASES)), "unsupported front-door focus")
    total = len(inventory) + len(INSTALLED_PILOT_CASES) + len(DEMO_CASES)
    if "source_before" not in obj:
        # A refusal before the clean-source check records nothing to bind.
        require(not passed and not names, "front-door report lacks its source")
        return {"source": None, "platform": "linux", "architecture": None,
                "identity": {key: None for key in IDENTITY_FIELDS}, "counts": counts(0, 1, total, total),
                "execution": "scripted-host", "version": fmt, "unverified": [UNVERIFIED_RECEIPT_ABSENT]}
    commit, tree = clean_source(obj.get("source_before"), "source_before")
    if passed or "source_after" in obj:
        clean_source(obj.get("source_after"), "source_after", commit, tree)
    require((obj.get("platform") or {}).get("kind") == "linux", "front door did not run on native Linux")
    inputs = exact(obj.get("inputs_sha256"), INPUT_ROLES, "inputs_sha256")
    for role in INPUT_ROLES:
        digest(inputs[role], "input " + role)
    component = None
    if passed or "component" in obj:
        component = exact(obj.get("component"), {"component", "archive_sha256", "files", "commit"}, "component")
        digest(component["component"], "component")
        digest(component["archive_sha256"], "component archive")
        require(component["commit"] == commit, "component was built from another source")
    by_case = dict(zip(names, rows))
    if "component-install" in by_case:
        require(component is not None and by_case["component-install"].get("component") == component["component"],
                "installed component differs from the built component")
    if "preview-zero-effect" in by_case:
        require(by_case["preview-zero-effect"].get("selected_started") == 0 and
                by_case["preview-zero-effect"].get("inet_connects") == 0, "preview reported effects")
    for name in ("useful", "cancel"):
        if name in by_case:
            row = by_case[name]
            require((row.get("process_cleanup") or {}).get("all_stopped") is True and
                    (row.get("live_status") or {}).get("protection") == "observed-live", name + ": cleanup or live status")
    if "cancel" in by_case:
        require(by_case["cancel"].get("reason") == "pilot_cancelled", "cancel: not reported as cancelled")
    nested_passed = False
    if nested is not None:
        require(nested.get("format") == "sw-installed-pilot-scope-qualification/1" and
                nested.get("expected") == list(SCOPE_CASES), "scope qualification version or inventory mismatch")
        open_cases = case_outcomes(nested.get("cases"), SCOPE_CASES, "scope qualification", "id",
                                   ("passed", "incomplete"))
        require(all(type(row.get("attempted")) is bool and (row["status"] != "passed" or row["attempted"])
                    for row in nested["cases"]), "scope qualification: unattempted case passed")
        nested_passed = nested.get("status") == "passed"
        require(nested.get("status") in ("passed", "incomplete") and nested_passed == (not open_cases),
                "scope qualification status contradicts case outcomes")
        require((len(names) == len(inventory)) == nested_passed, "scope rows disagree with the scope qualification")
        clean_source(nested.get("source"), "scope qualification source", commit, tree)
        if nested_passed:
            clean_source(nested.get("source_after"), "scope qualification source_after", commit, tree)
    tally, policy, architecture = front_door_companions(companions, commit, tree, inputs, passed)
    observation = {"source": commit, "tree": tree, "platform": "linux", "architecture": architecture,
                   "identity": {"implementation": component["archive_sha256"] if component else None,
                                "policy": policy, "registry": None, "runtime": inputs["agentfw"], "server": None},
                   "counts": counts(len(names) + tally[0], (0 if passed else 1) + tally[1],
                                    len(inventory) - len(names) + tally[2], total),
                   "execution": "scripted-host", "version": fmt,
                   "unverified": [UNVERIFIED_RECEIPT_ABSENT, UNVERIFIED_WITNESS, UNVERIFIED_GENERATION]}
    if fmt != SCOPE_FORMAT:
        return observation
    # The scope variant must observe linux-v1 selected and conforming while the runs were live.
    scopes = []
    for name in ("useful", "cancel"):
        if name in by_case:
            live = exact(by_case[name]["live_status"].get("scope"), {"document_sha256", "id", "mode", "qualification",
                                                                     "reasons", "selected", "shadow", "state"},
                         name + " live scope")
            require(live["id"] == SCOPE_ID and live["selected"] is True and live["state"] == "conforming" and
                    live["mode"] == "enforce" and live["reasons"] == [],
                    "Linux-v1 scope was not selected and conforming during the run")
            require(type(live["qualification"]) is str and live["qualification"].startswith("unqualified") and
                    "READY" not in live["qualification"].replace("NOT_READY", ""), "scope status claims qualification")
            scopes.append(digest(live["document_sha256"], "scope document"))
    require(len(set(scopes)) <= 1 and (scopes or not passed), "scope document identity is absent or inconsistent")
    if nested is not None:
        for row in nested["cases"]:
            if row["status"] == "passed":
                expected = SCOPE_FACTS.get(row["id"], {})
                if row["id"] == "scope-selected-through-preview-and-prepare":
                    expected = {"document_sha256": scopes[0][:12] if scopes else None}
                require(all(row.get(key) == value for key, value in expected.items()),
                        row["id"] + ": recorded facts do not match the scope control")
    if scopes:
        observation["profile"] = SCOPE_ID + "@" + scopes[0]
    observation["scope"] = {"id": SCOPE_ID, "selected": bool(scopes), "state": "conforming" if scopes else None,
                            "document_sha256": scopes[0] if scopes else None}
    return observation


CLEAN_USER_CLAIMS = {"full_product_acceptance": "not_established", "novice_human_evidence": "not_measured",
                     "live_model_effectiveness": "not_tested", "paid_api_calls": 0,
                     "runtime_review_status": "author candidate; not merge approval",
                     "scope": "two-new-projects-one-clean-user-environment"}
CLEAN_USER_GO = "GO for this measured preprovisioned path only"


def project_clean_user(obj: dict, companions: dict) -> dict:
    require("pilot_scope_qualification" not in obj and "pilot_scope" not in obj,
            "a Linux-v1 scope report is not clean-user evidence")
    require(obj.get("provider") == "owned-scripted-loopback" and obj.get("skipped") == 0,
            "unsupported provider or claim field")
    status = obj.get("status")
    require(status in ("passed", "failed", "incomplete"), "invalid report status")
    empty = {key: None for key in IDENTITY_FIELDS}
    base = {"platform": "linux", "execution": "scripted-host", "version": CLEAN_USER_FORMAT,
            "unverified": [UNVERIFIED_RECEIPT_BYTES, UNVERIFIED_WITNESS, UNVERIFIED_SEALED]}
    if "clean_user" not in obj:
        # An honest early refusal (for example, a wrong platform) precedes the inventory.
        require(status != "passed", "passed report lacks its clean-user inventory")
        return {**base, "source": None, "architecture": None, "identity": empty,
                "counts": counts(0, 1, len(CLEAN_USER_CASES), len(CLEAN_USER_CASES))}
    for key, value in CLEAN_USER_CLAIMS.items():
        require(obj.get(key) == value, "unsupported or forged claim field: " + key)
    inventory = obj["clean_user"]
    require(type(inventory) is dict and inventory.get("required") == list(CLEAN_USER_CASES),
            "clean-user required inventory mismatch")
    rows = inventory.get("cases")
    open_cases = case_outcomes(rows, CLEAN_USER_CASES, "clean-user", "id", ("passed", "failed", "incomplete"))
    require(all(type(row.get("attempted")) is bool and (row["attempted"] or row["status"] == "incomplete")
                for row in rows), "clean-user: unattempted case has an outcome")
    passed = status == "passed"
    require(passed == (not open_cases) and inventory.get("status", status) == status,
            "report status contradicts case outcomes")
    require(obj.get("remaining_blockers") == open_cases, "remaining blockers contradict case outcomes")
    decision = obj.get("decision")
    require(decision == CLEAN_USER_GO if passed else type(decision) is str and decision.startswith("NO-GO"),
            "decision text contradicts case outcomes")
    commit, tree = clean_source(obj.get("source_before"), "source_before")
    driver, driver_tree = clean_source(obj.get("driver_source"), "driver_source")
    require(obj.get("runtime_source") == commit, "runtime source differs from the qualified source")
    if passed or "source_after" in obj:
        clean_source(obj.get("source_after"), "source_after", commit, tree)
    build = None
    if passed or "build_source" in obj:
        clean_source(obj.get("build_source"), "build_source", commit, tree,
                     ("cargo_lock_sha256", "files_sha256", "rust_toolchain_sha256"))
        build = obj["build_source"]
        digest(obj.get("source_build_receipt_sha256"), "build receipt")
    inputs = exact(obj.get("inputs_sha256"), INPUT_ROLES, "inputs_sha256")
    for role in INPUT_ROLES:
        digest(inputs[role], "input " + role)
    environment = obj.get("environment")
    require(type(environment) is dict and environment.get("ordinary_user") is True and
            environment.get("effective_capabilities") == 0 and
            environment.get("unassisted_stock_host_acceptance") == "not_established",
            "environment is not the ordinary-user precondition")
    by_case = {row["id"]: row for row in rows if row["status"] == "passed"}
    component = None
    if passed or "component" in obj:
        # The clean-user driver keeps the raw build result; its private output path is never projected.
        component = exact(obj.get("component"), {"action", "component", "archive_sha256", "files", "commit", "out"},
                          "component")
        require(component["action"] == "build", "component was not built by this run")
        digest(component["component"], "component")
        digest(component["archive_sha256"], "component archive")
        require(component["commit"] == commit, "component was built from another source")
    if "component-install" in by_case:
        row = by_case["component-install"]
        require(component is not None and row.get("archive_sha256") == component["archive_sha256"] and
                row.get("component_sha256") == component["component"], "installed component differs from the build")
    policies = set()
    for project in ("catalog-service", "release-ledger"):
        if all(project + ":" + task in by_case for task in (*CLEAN_USER_TASKS, "denied-calls")):
            facts = (obj.get("projects") or {}).get(project) or {}
            clean_source(facts.get("selected_source"), project + " selected source", commit, tree, ("files_sha256",))
            require(build is not None and facts["selected_source"]["files_sha256"] == build["files_sha256"],
                    project + ": selected files differ from the built source")
            same_binaries(facts.get("selected_sha256"), inputs, ("agentfw", "bwrap", "claude", "git", "git_launcher",
                                                                  "python", "sandbox_tests"), project)
            policies.add(digest(facts["selected_sha256"].get("policy"), project + " policy"))
        for task in CLEAN_USER_TASKS:
            row = by_case.get(project + ":" + task)
            if row is not None:
                require(row.get("original_result_useful") is True, row["id"] + ": original result not useful")
                digest(row.get("expected_sha256"), row["id"] + " expected")
                digest(row.get("observed_text_sha256"), row["id"] + " observed")
        row = by_case.get(project + ":denied-calls")
        if row is not None:
            require(row.get("forbidden_files") == 0 and row.get("forbidden_network_connections") == 0 and
                    row.get("forbidden_original_dispatches") == 0 and row.get("positive_receiver") is True and
                    row.get("unchanged_user_files") is True and row.get("useful_continuation") is True and
                    (row.get("process_cleanup") or {}).get("all_stopped") is True,
                    row["id"] + ": denied-call witnesses do not match the control")
    require(len(policies) <= 1, "projects selected different policies")
    architecture = None
    if "documented-walkthrough" in by_case:
        walk = companions.get("walkthrough")
        require(walk is not None, "index omits the walkthrough companion")
        row = by_case["documented-walkthrough"]
        require(row.get("original_report_sha256") == walk[1], "walkthrough companion hash differs from the report")
        require(demo_outcomes(walk[0], commit, tree, "walkthrough") == [] and row.get("cases") == len(DEMO_CASES) and
                row.get("original_inventory_preserved") is True, "walkthrough companion is not a complete passed demo")
        summary = (obj.get("walkthrough") or {}).get("cases")
        require(type(summary) is list and [(c.get("case"), c.get("status")) for c in summary] ==
                [(c["case"], c["status"]) for c in walk[0]["cases"]], "walkthrough summary differs from its companion")
        same_binaries(walk[0].get("selected_sha256"), inputs, ("agentfw",), "walkthrough")
        if walk[0].get("required_platform") == "native Ubuntu 24.04 x86_64, non-root":
            architecture = "x86_64"
    if "ask-once-replay" in by_case:
        ask = companions.get("ask")
        require(ask is not None, "index omits the Ask companion")
        require(by_case["ask-once-replay"].get("original_report_sha256") == ask[1], "Ask companion hash differs from the report")
        ask = ask[0]
        require(ask.get("contract_version") == "sw-pilot-ask-acceptance/1" and ask.get("status") == "pass" and
                ask.get("qualification_scope") == "two_profile_correctness_probe_not_performance" and
                ask.get("physical_human_presence_proven") is False and ask.get("paid_api_calls") == 0,
                "Ask companion version or claim field mismatch")
        clean_source(ask.get("source"), "Ask source", commit, tree)
        clean_source(ask.get("source_after"), "Ask source_after", commit, tree)
        cases = ask.get("cases")
        require(type(cases) is list and sorted(c.get("profile") for c in cases) == ["filesystem", "git"] and
                all(c.get("passed") is True and (c.get("cleanup") or {}).get("all_stopped") is True for c in cases),
                "Ask companion cases incomplete")
        same_binaries(ask.get("selected_sha256"), inputs, ("agentfw", "bwrap", "claude", "git", "git_launcher"), "Ask")
    refusals = []
    for row in obj.get("cases") or []:
        require(type(row) is dict and row.get("status") in ("completed", "failed"), "invalid run row")
        live = (row.get("live_status") or {}).get("scope")
        require(live is None or (type(live) is dict and live.get("selected") is False and
                                 live.get("state") == "unselected"),
                "a clean-user run recorded a selected scope")
        if row["status"] == "failed":
            expected_refusal = (row.get("case") in MAINTENANCE_REFUSALS and row.get("exit") == 1 and
                                row.get("reason") == "maintenance_entered" and
                                (row.get("process_cleanup") or {}).get("all_stopped") is True)
            require(expected_refusal or not passed, "unexpected failed run in a passed report")
            if expected_refusal:
                refusals.append(row["case"])
        elif passed:
            require(row.get("exit") == 0 and (row.get("process_cleanup") or {}).get("all_stopped") is True,
                    "completed run did not exit cleanly")
    if "update-rollback" in by_case:
        row = by_case["update-rollback"]
        update = obj.get("coordinated_update") or {}
        preserved = update.get("maintenance_preserved_across_update_and_rollback")
        require(component is not None and row.get("restored_component") == component["component"] and
                row.get("update_source") == "synthetic identity-only component control" and
                update.get("status") == "passed" and type(preserved) is list and
                [item.get("case") for item in preserved] == list(MAINTENANCE_REFUSALS) and
                all(item.get("host_executions") == 0 and item.get("provider_requests") == 0 and
                    item.get("reason") == "maintenance_entered" for item in preserved),
                "update and rollback did not preserve the maintenance refusals")
        require(refusals == list(MAINTENANCE_REFUSALS), "expected maintenance refusals are missing or relabelled")
    if passed:
        archival = obj.get("run_archival") or {}
        completed = sum(row.get("status") == "completed" for row in obj["cases"])
        require(archival.get("status") == "passed" and archival.get("local_audit_proves_execution") is False and
                archival.get("completed_runs_archived") == archival.get("expected_completed_runs") == completed,
                "run archival totals disagree")
    if "remove-preserves-user-data" in by_case:
        row = by_case["remove-preserves-user-data"]
        removal = obj.get("removal") or {}
        installs = removal.get("installations")
        require(row.get("user_files_preserved") is True and row.get("selections_preserved") is True and
                type(installs) is list and
                sorted((item.get("installation"), item.get("status")) for item in installs) ==
                [("bootstrap", "removed"), ("direct", "removed")] and
                sorted((item.get("installation"), item.get("status")) for item in obj.get("removal_maintenance") or []) ==
                [("bootstrap", "entered"), ("direct", "entered")] and
                (obj.get("initial_process_observation") or {}).get("unavailable") == [] and
                (obj.get("after_cleanup_process_observation") or {}).get("unavailable") == [],
                "removal did not confirm both installations with complete process visibility")
    if "ci_user_session" in obj:
        session = exact(obj["ci_user_session"], {"authorizes_removal", "observation", "report_sha256"}, "ci_user_session")
        companion = companions.get("user-session")
        require(companion is not None, "index omits the user-session companion")
        require(session["authorizes_removal"] is False and session["report_sha256"] == companion[1] and
                session["observation"] == companion[0], "user-session companion differs from the report")
    for role, statuses in (("user-session", ("already-visible", "quiesced-empty-ci-user-session")),
                           ("user-session-after-cleanup", ("observed",))):
        if role in companions:
            value = companions[role][0]
            require(value.get("status") in statuses and value.get("authorization") is False and
                    value.get("native_removal_guard_changed") is False and
                    value.get("installed_host_executed") in (False, None), role + ": witness state mismatch")
            clean_source(value.get("driver_source"), role + " driver source", driver, driver_tree)
    unverified = list(base["unverified"]) + ([UNVERIFIED_DRIVER] if driver != commit else [])
    return {**base, "unverified": unverified, "source": commit, "tree": tree, "driver_source": driver,
            "architecture": architecture,
            "identity": {"implementation": component["archive_sha256"] if component else None,
                         "policy": next(iter(policies), None), "registry": None, "runtime": inputs["agentfw"],
                         "server": None},
            "counts": counts(len(CLEAN_USER_CASES) - len(open_cases),
                             sum(row["status"] == "failed" for row in rows),
                             sum(row["status"] == "incomplete" for row in rows), len(CLEAN_USER_CASES)),
            "refusals": len(refusals), "scope": {"id": SCOPE_ID, "selected": False, "state": "unselected",
                                                 "document_sha256": None}}


def project_report(obj: dict, fmt: str, companions: dict | None = None) -> dict:
    """Extract only allowlisted identities and counts; never copy raw report text."""
    if fmt in PER_RUN_FORMATS:
        require(obj.get("format") == INSTALLED_REPORT, "report version mismatch")
        if fmt == CLEAN_USER_FORMAT:
            return project_clean_user(obj, companions or {})
        return project_front_door(obj, fmt, companions or {})
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
        companions = {}
        for row in descriptor.get("companions", []):
            companion = root.joinpath(*PurePosixPath(row["path"]).parts)
            if not companion.exists() and not companion.is_symlink():
                return {**base, "status": "missing", "reason": "Companion report " + row["role"] + " is absent"}
            value, observed = load_json(companion, MAX_REPORT)
            require(observed == row["sha256"], "companion " + row["role"] + " SHA-256 mismatch")
            companions[row["role"]] = (value, observed)
        observation = project_report(obj, descriptor["format"], companions)
        # An honest early installed refusal may record no source; it can only be incomplete.
        require(observation["source"] == descriptor["source"] or
                (descriptor["format"] in PER_RUN_FORMATS and observation["source"] is None),
                "source identity mismatch")
        # An installed report may not record its architecture; that stays unbound, never matched.
        # Legacy formats keep exact platform identity.
        unrecorded = (None,) if descriptor["format"] in PER_RUN_FORMATS else ()
        require(observation["platform"] == descriptor["platform"] and
                observation["architecture"] in (descriptor["architecture"], *unrecorded), "platform identity mismatch")
        # A per-run refusal before any source was recorded measures no identity; it is never complete.
        early = descriptor["format"] in PER_RUN_FORMATS and observation["source"] is None
        require(not early or not observation["counts"]["complete"], "complete report lacks its source")
        for key in IDENTITY_FIELDS:
            if descriptor["identity"][key] is not None and not early:
                measured = observation["identity"].get(key) if "identity" in observation else observation.get(key)
                require(measured == descriptor["identity"][key], f"{key} identity mismatch")
        for key in ("host", "transport", "server", "profile"):
            if key in observation:
                require(observation[key] == descriptor[key], f"{key} identity mismatch")
        observed = {"sha256": actual, "source": observation["source"],
                    "platform": observation["platform"], "architecture": observation["architecture"],
                    "counts": observation["counts"], "execution": observation["execution"],
                    "version": observation["version"], "identity": descriptor["identity"]}
        for key in ("tree", "driver_source", "unverified", "refusals", "scope"):
            if key in observation:
                observed[key] = observation[key]
        if companions:
            observed["companions"] = [{"role": role, "sha256": value[1]} for role, value in companions.items()]
        if not observation["counts"]["complete"]:
            status, reason = "incomplete", "Failed, skipped, zero-denominator or incomplete checks"
        elif observation["source"] is None:
            status, reason = "unbound", "Report does not bind execution to one clean source commit"
        elif observation["source"] != target:
            status, reason = "historical", ("Validated component evidence is from another source revision"
                                            if descriptor["kind"] == "component" else
                                            "Validated integrated evidence is from another source commit")
        elif observation["architecture"] is None:
            status, reason = "unbound", "Report does not record the architecture it ran on"
        elif cap["platform"] != observation["platform"] or cap["architecture"] != observation["architecture"]:
            status, reason = "mismatch", "Target platform or architecture differs"
        elif descriptor["kind"] == "component":
            status, reason = "component", "Exact-source component check; integrated acceptance remains open"
        elif observation.get("unverified"):
            status, reason = "unbound", "Unverified: " + "; ".join(observation["unverified"])
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
