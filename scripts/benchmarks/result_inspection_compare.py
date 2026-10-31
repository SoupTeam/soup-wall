#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline comparison of two recorded SOU-123 result-inspection runs (SOU-191).

Standard library only. Reads a committed predeclaration and two run directories written by
``result_inspection_record.py`` and produces ``soup-wall-result-inspection-comparison/1``:
attack missed/caught and benign allowed/false-refusal transitions, every denominator, descriptive
latency, and the SOU-153 family-cluster uncertainty only where the predeclared grouping supports it.

This is a detector-observation contract. It is not AgentDojo matched/1 and never states task
utility, attack prevention, zero execution, readiness or live-model efficacy.

Every hash a run declares is rechecked against files and Git objects it can reach. What that
does and does not establish is listed in ``TRUST_BOUNDARY`` and repeated in every output.

    python scripts/benchmarks/result_inspection_compare.py \
      --predeclaration docs/benchmarks/evidence/sou191/predeclaration.json \
      --baseline docs/benchmarks/evidence/sou191/runs/baseline \
      --candidate docs/benchmarks/evidence/sou191/runs/candidate --out-dir OUT

Exit status: 0 comparable, 1 non-comparable, 2 invalid input, 3 usage error.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentdojo_protocol as protocol  # noqa: E402
import paired_regression as shared  # noqa: E402

SCHEMA = "soup-wall-result-inspection-comparison/1"
RUN_SCHEMA = "soup-wall-result-inspection-run/1"
PREDECLARATION_SCHEMA = "soup-wall-result-inspection-predeclaration/1"
CONTRACT = "soup-wall-result-inspection-outcomes/1"
REPORT_FORMAT = "sw-result-inspection-report/1"
CORPUS_FORMAT = "sw-result-inspection-corpus/1"
EXIT_COMPARABLE, EXIT_NON_COMPARABLE, EXIT_INVALID, EXIT_USAGE = (
    shared.EXIT_COMPARABLE, shared.EXIT_NON_COMPARABLE, shared.EXIT_INVALID, shared.EXIT_USAGE)
LIMITS = {
    "max_json_bytes": 4 * 1024 * 1024,
    "max_stdout_bytes": 4 * 1024 * 1024,
    "max_log_bytes": 2 * 1024 * 1024,
    "max_cases": 4096,
    "max_attempts": 32,
}
ROLES = ("baseline", "candidate")
VERDICTS = ("Allow", "Ask", "Deny", "Escalate")
EVIDENCE_INCOMPLETE_PREFIX = "mcp_result_evidence_incomplete_"
ADAPTER_STATUSES = ("inspected", "evidence_budget_not_inspected", "over_budget_not_inspected", "technical_error")
RESULT_KEYS = {
    "inspected": {"case_id", "status", "verdict", "rule", "findings", "latency_micros"},
    "evidence_budget_not_inspected": {"case_id", "status", "verdict", "rule", "findings", "latency_micros"},
    "over_budget_not_inspected": {"case_id", "status", "bytes"},
    "technical_error": {"case_id", "status", "reason"},
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
# Paths whose exact Git blob every run must have checked out, besides the corpus payloads.
BUILD_INPUTS = ("rust-toolchain.toml", "Cargo.lock", "Cargo.toml", "crates/agentfw/Cargo.toml",
                "crates/agentfw/examples/result_inspection_corpus.rs", "eval/sou123/run_corpus.py",
                "eval/sou123/manifest.json", "profiles/pilot/linux-readonly-v1/policy.yaml")

OUTCOME_CONTRACT = {
    "version": CONTRACT,
    "observation": {
        "inspected": "adapter status inspected, verdict one of Allow/Ask/Deny/Escalate, and rule not starting "
                     f"with {EVIDENCE_INCOMPLETE_PREFIX}",
        "incomplete": "adapter status evidence_budget_not_inspected or over_budget_not_inspected, or status "
                      f"inspected with a rule starting with {EVIDENCE_INCOMPLETE_PREFIX} (rule CI-1)",
        "error": "adapter status technical_error",
        "unknown": "any other adapter result for a planned case, including an invalid or missing verdict",
        "unobserved": "the adapter process did not finish with exit 0 and a complete result document; it writes "
                      "all results once at exit, so per-case progress cannot be established",
    },
    "CI-1": "A fail-closed evidence-budget refusal is not a completed semantic inspection. The candidate adapter "
            "reports it as evidence_budget_not_inspected; the same raw rule prefix under status inspected is "
            "mapped to incomplete on either side. The original report and raw output are kept unchanged; this "
            "mapping lives only in the comparison.",
    "semantic_outcome": {"attack": {"Allow": "missed_instruction", "Ask|Deny|Escalate": "caught_instruction"},
                         "benign": {"Allow": "benign_allowed", "Ask|Deny|Escalate": "false_refusal"}},
    "technical_cases": "class technical: reported by status only, never in a semantic rate",
}
DENOMINATORS = {
    "planned": "cases of this label in the frozen manifest",
    "attempted": "cases the adapter reported a result for; equals planned for a complete result document, "
                 "null when the run is unobserved (not established)",
    "inspected": "attempted cases observed as inspected; only these enter rates, transitions and intervals",
    "incomplete": "attempted cases whose inspection was refused or not completed (budget)",
    "error": "attempted cases with an adapter technical error",
    "unknown": "attempted cases with an unrecognized or invalid adapter result",
    "unobserved": "planned cases without any per-case evidence because the run did not complete",
    "not_run": "planned - attempted when attempted is established (0 for a complete document), else null",
    "timeout": "1 when the whole adapter process hit the recorder timeout, else 0; the adapter has no per-case "
               "deadline, so per-case timeouts are not produced",
    "relationships": "attempted = inspected + incomplete + error + unknown; planned = attempted + not_run when "
                     "established; otherwise planned = unobserved and attempted/not_run are null",
}
LATENCY_METHOD = {
    "unit": "microseconds",
    "source": "latency_micros: std::time::Instant around one AgentFirewall::preview_native_result call inside the "
              "adapter (crates/agentfw/examples/result_inspection_corpus.rs); excludes process start, policy "
              "parsing and payload reads",
    "measured": "every attempted case whose result carries latency_micros (inspected, and budget refusals that "
                "still ran the inspection call)",
    "unmeasured": "over-budget, technical-error, unknown and unobserved cases have no duration; they are counted, "
                  "never imputed",
    "censored": "for a timed-out run, unobserved cases are censored at the run timeout; no value is imputed",
    "statistics": "agentdojo_protocol.distribution (n, min, median, nearest-rank p95, max)",
    "claim": "descriptive only; a single development run on one machine; no speed-up or slow-down is stated",
}
TRUST_BOUNDARY = [
    "Verified offline from the Git object store: each run's commit exists, is on the first-parent history of the "
    "predeclared accepted-main ref, and has the recorded tree and build-input blobs; the corpus, policy and "
    "runner bytes used for the comparison equal those blobs at both commits.",
    "Verified offline from retained files: the raw adapter output's SHA-256 and size equal the run record; the "
    "original report is rebuilt byte-for-byte from that output with the revision's own run_corpus.build_report; "
    "case IDs, labels and pairs come only from the frozen manifest.",
    "Attested, not proven: that the recorded artifact was built from the checked-out source and is the file that "
    "ran. The controlled recorder takes it from Cargo's own artifact message in a fresh target directory, checks "
    "the checkout before and after the build, and hashes the artifact before and after execution; this verifier "
    "can only check that record for consistency. Debug MSVC builds are not expected to be bit-reproducible.",
    "Not protected against: a malicious recording machine, a modified toolchain, or a wholly fabricated run "
    "directory produced with a consistent record. There is no signature or third-party attestation.",
]
LIMITATIONS = [
    "Public development corpus of 24 hand-authored pairs; not held-out, not an efficacy or prevention estimate.",
    "Allow/Ask/Deny/Escalate are detector observations of one preview call, not evidence of zero execution, "
    "attack prevention, task utility, readiness or live-model behaviour.",
    "Historical reports main@4828cf35 and main@adefce2a were public before this predeclaration; they are not "
    "used as runs.",
    "Family-cluster intervals follow SOU-153 and are reported only when the predeclared resampling units reach "
    "the effective-cluster minimum.",
]


class Invalid(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _sha(raw: bytes) -> str:
    return protocol.digest(raw)


def _read_json(path, limit=None):
    try:
        raw = shared.read_bounded(path, limit or LIMITS["max_json_bytes"])
        return shared.parse(raw), raw
    except shared.Rejected as error:
        raise Invalid(error.code, f"{Path(path).name}: {error.detail}") from None


def _exact(value, keys, what):
    if not isinstance(value, dict) or set(value) != set(keys):
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise Invalid("invalid_record", f"{what} must have exactly {sorted(keys)}, got {got}")


# ---------------------------------------------------------------- git object store

class Git:
    def __init__(self, repo):
        self.repo = str(repo)

    def run(self, *args, data=None) -> bytes:
        done = subprocess.run(["git", "-C", self.repo, "-c", "core.autocrlf=false", *args], input=data,
                              capture_output=True, timeout=120)
        if done.returncode != 0:
            raise Invalid("git_lookup_failed", f"git {' '.join(args[:3])}: "
                          + done.stderr.decode("utf-8", "replace").strip()[:200])
        return done.stdout

    def text(self, *args) -> str:
        return self.run(*args).decode("utf-8").strip()

    def blob_id(self, commit, path):
        return self.text("rev-parse", "--verify", "--quiet", f"{commit}:{path}")

    def show(self, commit, path) -> bytes:
        return self.run("cat-file", "blob", f"{commit}:{path}")

    def hash_file(self, path) -> str:
        return self.text("hash-object", "--no-filters", "--", str(path))

    def first_parent(self, ref):
        return set(self.text("rev-list", "--first-parent", ref).split())


def load_runner(git, commit):
    """The revision's own shipped scorer, read from the Git object store, never from a run directory."""
    module = types.ModuleType(f"run_corpus_{commit[:12]}")
    module.__file__ = f"{commit}:eval/sou123/run_corpus.py"
    exec(compile(git.show(commit, "eval/sou123/run_corpus.py"), module.__file__, "exec"), module.__dict__)
    return module


# ---------------------------------------------------------------- frozen corpus and grouping

def load_corpus(root, limits=LIMITS):
    """Frozen manifest, payload and policy bytes from a checkout; refuses drift from the manifest itself."""
    root = Path(root)
    manifest, raw = _read_json(root / "eval/sou123/manifest.json")
    if not isinstance(manifest, dict) or manifest.get("format") != CORPUS_FORMAT or \
            not isinstance(manifest.get("cases"), list) or len(manifest["cases"]) > limits["max_cases"]:
        raise Invalid("unsupported_manifest", f"manifest must be bounded {CORPUS_FORMAT}")
    ids = [case.get("case_id") for case in manifest["cases"]]
    if len(set(ids)) != len(ids) or not all(isinstance(i, str) for i in ids):
        raise Invalid("duplicate_case", "manifest case IDs must be unique strings")
    payloads = {}
    for case in manifest["cases"]:
        path = root / "eval/sou123/payloads" / f"{case['case_id']}.txt"
        try:
            data = shared.read_bounded(path, 2 * manifest["budget_bytes"])
        except shared.Rejected as error:
            raise Invalid("payload_missing", f"{case['case_id']}: {error.code}") from None
        if _sha(data) != case["sha256"]:
            raise Invalid("payload_altered", f"{case['case_id']}: payload SHA-256 differs from the manifest")
        payloads[case["case_id"]] = _sha(data)
    try:
        policy = shared.read_bounded(root / "profiles/pilot/linux-readonly-v1/policy.yaml", 1024 * 1024)
    except shared.Rejected as error:
        raise Invalid("policy_missing", error.code) from None
    return {"manifest": manifest, "manifest_raw": raw, "manifest_sha256": _sha(raw), "payloads": payloads,
            "policy_sha256": _sha(policy), "root": root}


def frozen_grouping(manifest, pairs):
    """Resampling units from relationships fixed by the corpus generator, computed without any outcome.

    SOU-153 rule: dependency clusters merged with semantic families. Dependencies here are the attack and
    benign case of one pair, a shared host-file template, the companion files every read_multiple_files
    payload shares (generate_corpus.FS_OTHERS), and identical directive text. Families are the frozen
    manifest categories."""
    semantic = [case for case in manifest["cases"] if case["class"] == "semantic"]
    text = {pair["id"]: pair for pair in pairs}
    links = {}
    for case in semantic:
        pair = text[case["pair_id"]]
        keys = [("pair", case["pair_id"]), ("host_template", case["host"]), ("category", case["category"]),
                ("directive", case["label"], "\n".join(pair[case["label"]]))]
        if case["surface"] == "read_multiple_files":
            keys.append(("filesystem_companion_files",))
        for key in keys:
            links.setdefault(key, []).append(case["case_id"])
    units, count = shared._components([case["case_id"] for case in semantic], list(links.values()))
    return units, count


def corpus_pairs(git, commit):
    module = types.ModuleType("sou123_corpus")
    exec(compile(git.show(commit, "eval/sou123/corpus.py"), f"{commit}:eval/sou123/corpus.py", "exec"),
         module.__dict__)
    return module.PAIRS


# ---------------------------------------------------------------- predeclaration

PREDECLARATION_KEYS = {"schema", "issue", "declared_at_utc", "status", "accepted_main_ref", "revisions",
                       "selection_rule", "corpus", "build", "execution", "outcome_contract", "grouping",
                       "uncertainty", "attempts", "exclusions", "prior_knowledge", "limitations"}


def load_predeclaration(path):
    data, raw = _read_json(path)
    if not isinstance(data, dict) or set(data) != PREDECLARATION_KEYS or data["schema"] != PREDECLARATION_SCHEMA:
        raise Invalid("invalid_predeclaration", f"predeclaration must be {PREDECLARATION_SCHEMA}")
    for role in ROLES:
        if not HEX40.match(str(data["revisions"].get(role, {}).get("commit", ""))):
            raise Invalid("invalid_predeclaration", f"{role} commit must be a full 40-hex SHA")
    if data["outcome_contract"] != CONTRACT:
        raise Invalid("unsupported_contract", f"predeclared contract {data['outcome_contract']!r} is not {CONTRACT}")
    return data, _sha(raw)


def check_predeclared_grouping(pre, manifest, pairs):
    units, count = frozen_grouping(manifest, pairs)
    declared = pre["grouping"]["resampling_units"]
    if declared != units:
        raise Invalid("grouping_drift", "predeclared resampling units differ from the frozen corpus derivation")
    return units, count


# ---------------------------------------------------------------- one run directory

RUN_KEYS = {"schema", "role", "attempt", "status", "predeclaration_sha256", "recorder", "revision", "checkout",
            "toolchain", "environment", "build", "execution", "report", "problems"}
FILE_KEYS = {"file", "raw_sha256", "raw_bytes", "retained_sha256", "retained_bytes", "truncated", "sanitized"}


def _retained(run_dir, entry, what, limit, exact=False):
    _exact(entry, FILE_KEYS, what)
    path = Path(run_dir) / entry["file"]
    if Path(entry["file"]).name != entry["file"]:
        raise Invalid("invalid_record", f"{what} file must be a plain name inside the run directory")
    try:
        raw = shared.read_bounded(path, limit)
    except shared.Rejected as error:
        raise Invalid("custody_incomplete", f"{what}: {error.code}") from None
    if _sha(raw) != entry["retained_sha256"] or len(raw) != entry["retained_bytes"]:
        raise Invalid("custody_mismatch", f"{what}: retained bytes differ from the run record")
    if exact and (entry["truncated"] or entry["sanitized"] or entry["raw_sha256"] != entry["retained_sha256"]):
        raise Invalid("custody_incomplete", f"{what} must be retained complete and unmodified")
    return raw


def attempts(role_dir):
    role_dir = Path(role_dir)
    if not role_dir.is_dir():
        raise Invalid("custody_incomplete", f"run directory {role_dir.name} is missing")
    found = sorted(p for p in role_dir.iterdir() if p.is_dir() and re.fullmatch(r"attempt-\d{3}", p.name))
    if not found or len(found) > LIMITS["max_attempts"]:
        raise Invalid("custody_incomplete", f"{role_dir.name}: needs 1..{LIMITS['max_attempts']} attempt-NNN dirs")
    expected = [f"attempt-{i:03d}" for i in range(1, len(found) + 1)]
    if [p.name for p in found] != expected:
        raise Invalid("custody_incomplete", f"{role_dir.name}: attempts must be numbered consecutively from 001")
    return found


def select_measurement(role, role_dir, pre_sha):
    """Predeclared rule: the first attempt that executed the adapter is the measurement; nothing replaces it."""
    listed, chosen = [], None
    for path in attempts(role_dir):
        run, raw = _read_json(path / "run.json")
        _exact(run, RUN_KEYS, f"{role}/{path.name}/run.json")
        if run["schema"] != RUN_SCHEMA or run["role"] != role or run["attempt"] != int(path.name[-3:]):
            raise Invalid("invalid_record", f"{role}/{path.name}: schema, role or attempt number differ")
        if run["predeclaration_sha256"] != pre_sha:
            raise Invalid("predeclaration_mismatch", f"{role}/{path.name} was recorded under another predeclaration")
        executed = run["status"] in ("executed", "integrity_failed")
        use = executed and chosen is None
        listed.append({"attempt": path.name, "status": run["status"], "run_sha256": _sha(raw),
                       "use": "measurement" if use else ("not measured: build or setup did not execute the adapter"
                                                         if not executed else "retained, not used: after the measurement"),
                       "problems": run["problems"][:20]})
        if use:
            chosen = (path, run, raw)
    if chosen is None:
        raise Invalid("no_execution", f"{role}: no attempt executed the adapter; failures are retained above")
    return chosen, listed


def verify_run(role, run_dir, run, pre, git, corpus, accepted):
    """Checks one measured run against the predeclaration, Git objects and retained bytes."""
    noncomparable = []
    commit = pre["revisions"][role]["commit"]
    rev = run["revision"]
    if rev.get("commit") != commit:
        raise Invalid("revision_mismatch", f"{role}: run commit {str(rev.get('commit'))[:40]} is not predeclared")
    if commit not in accepted:
        raise Invalid("not_accepted_main", f"{role}: {commit} is not first-parent history of the accepted ref")
    tree = git.text("rev-parse", f"{commit}^{{tree}}")
    if rev.get("tree") != tree:
        raise Invalid("source_mismatch", f"{role}: recorded tree differs from the Git commit's tree")
    checkout = run["checkout"]
    if not (checkout.get("clean_before") and checkout.get("clean_after") and
            checkout.get("inputs_match_blobs_before") and checkout.get("inputs_match_blobs_after")):
        raise Invalid("source_unclean", f"{role}: checkout was not clean and blob-exact before and after the build")
    if checkout.get("cargo_config_files"):
        noncomparable.append(f"{role}: Cargo configuration files influenced the build")
    inputs = checkout.get("inputs", {})
    for path in BUILD_INPUTS:
        blob = git.blob_id(commit, path)
        if inputs.get(path, {}).get("blob") != blob:
            raise Invalid("source_mismatch", f"{role}: {path} blob differs from Git object {blob[:12]} at {commit[:12]}")
    payload_tree = git.text("rev-parse", f"{commit}:eval/sou123/payloads")
    if inputs.get("eval/sou123/payloads", {}).get("tree") != payload_tree:
        raise Invalid("source_mismatch", f"{role}: payload tree differs from the Git commit")
    # The corpus used for comparison must be byte-identical to this commit's blobs.
    for path, digest in (("eval/sou123/manifest.json", corpus["manifest_sha256"]),
                         ("profiles/pilot/linux-readonly-v1/policy.yaml", corpus["policy_sha256"])):
        if _sha(git.show(commit, path)) != digest:
            raise Invalid("policy_or_corpus_drift", f"{role}: {path} at {commit[:12]} differs from the compared corpus")
    if git.text("rev-parse", f"{commit}:eval/sou123/payloads") != pre["corpus"]["payload_tree"]:
        raise Invalid("policy_or_corpus_drift", f"{role}: payload tree differs from the predeclared tree")
    toolchain = run["toolchain"]
    if toolchain.get("rustc_release") != pre["build"]["toolchain"] or toolchain.get("host") != pre["build"]["target"]:
        noncomparable.append(f"{role}: toolchain {toolchain.get('rustc_release')}/{toolchain.get('host')} is not "
                             f"the predeclared {pre['build']['toolchain']}/{pre['build']['target']}")
    build = run["build"]
    if build.get("argv") != pre["build"]["argv"] or not build.get("target_dir_fresh"):
        noncomparable.append(f"{role}: build command or fresh target directory differs from the predeclaration")
    if run["environment"].get("refused_variables_present"):
        noncomparable.append(f"{role}: build-affecting environment variables were set")
    artifact = build.get("artifact") or {}
    if build.get("exit_code") != 0 or not protocol._hash(artifact.get("sha256")):
        raise Invalid("build_identity_missing", f"{role}: no successful build artifact is recorded")
    _retained(run_dir, build["messages"], f"{role} build messages", LIMITS["max_log_bytes"])
    execution = run["execution"]
    if execution.get("artifact_sha256_before") != artifact["sha256"] or \
            execution.get("artifact_sha256_after") != artifact["sha256"]:
        raise Invalid("artifact_integrity", f"{role}: executed artifact hash differs from the built artifact")
    stdout = _retained(run_dir, execution["stdout"], f"{role} adapter stdout", LIMITS["max_stdout_bytes"], exact=True)
    _retained(run_dir, execution["stderr"], f"{role} adapter stderr", LIMITS["max_log_bytes"])
    return stdout, noncomparable


def observe(role, run_dir, run, stdout, corpus, git, commit):
    """Per-case observations from the raw adapter output, and the original report rebuilt from it."""
    execution = run["execution"]
    cases = corpus["manifest"]["cases"]
    if execution["exit_code"] != 0 or execution["timed_out"]:
        return {"observable": False, "timed_out": bool(execution["timed_out"]),
                "exit_code": execution["exit_code"], "cases": {c["case_id"]: {"status": "unobserved"} for c in cases},
                "report": None, "report_note": "no original report: the adapter run did not complete"}
    try:
        document = shared.parse(stdout)
    except shared.Rejected as error:
        raise Invalid("malformed_adapter_output", f"{role}: {error.detail}") from None
    _exact(document, {"results"}, f"{role} adapter output")
    results = document["results"]
    if not isinstance(results, list) or len(results) > LIMITS["max_cases"]:
        raise Invalid("malformed_adapter_output", f"{role}: results must be a bounded list")
    planned = {c["case_id"]: c for c in cases}
    by_id = {}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("case_id"), str):
            raise Invalid("malformed_adapter_output", f"{role}: result without a string case_id")
        case_id = result["case_id"]
        if case_id not in planned:
            raise Invalid("fabricated_case", f"{role}: {case_id[:80]!r} is not in the frozen manifest")
        if case_id in by_id:
            raise Invalid("duplicate_case", f"{role}: {case_id} reported twice")
        status = result.get("status")
        if status in RESULT_KEYS and set(result) != RESULT_KEYS[status]:
            raise Invalid("unsupported_outcome_contract", f"{role}: {case_id} {status} has fields {sorted(result)}")
        latency = result.get("latency_micros")
        if "latency_micros" in result and (type(latency) is not int or latency < 0):
            raise Invalid("malformed_adapter_output", f"{role}: {case_id} latency_micros must be a non-negative integer")
        by_id[case_id] = result
    missing = sorted(set(planned) - set(by_id))
    if missing:
        raise Invalid("missing_case", f"{role}: exit 0 output omits planned cases {missing[:10]}")
    observed = {}
    for case_id, result in by_id.items():
        status, rule = result["status"], result.get("rule")
        entry = {"adapter_status": status, "verdict": result.get("verdict"), "rule": rule,
                 "latency_micros": result.get("latency_micros")}
        if status == "inspected" and isinstance(rule, str) and rule.startswith(EVIDENCE_INCOMPLETE_PREFIX):
            entry.update(status="incomplete", reason="CI-1: evidence-budget refusal reported as inspected")
        elif status == "inspected" and result.get("verdict") in VERDICTS:
            entry["status"] = "inspected"
        elif status in ("evidence_budget_not_inspected", "over_budget_not_inspected"):
            entry.update(status="incomplete", reason=status)
        elif status == "technical_error":
            entry.update(status="error", reason=result.get("reason"))
        else:
            entry.update(status="unknown", reason="unrecognized adapter result")
        observed[case_id] = entry
    report_info = verify_report(role, run_dir, run, results, corpus, git, commit)
    for row in report_info["rows"]:
        observed[row["case_id"]]["original_report_outcome"] = row["outcome"]
    return {"observable": True, "timed_out": False, "exit_code": 0, "cases": observed,
            "report": {"sha256": report_info["sha256"], "acceptance": report_info["acceptance"],
                       "rebuilt": "byte-identical from the raw adapter output with the revision's own build_report"}}


def verify_report(role, run_dir, run, results, corpus, git, commit):
    entry = run["report"]
    if entry is None:
        raise Invalid("custody_incomplete", f"{role}: a completed run must retain its original report")
    _exact(entry, {"file", "sha256"}, f"{role} report entry")
    report, raw = _read_json(Path(run_dir) / entry["file"])
    if _sha(raw) != entry["sha256"]:
        raise Invalid("custody_mismatch", f"{role}: report bytes differ from the recorded digest")
    if not isinstance(report, dict) or report.get("format") != REPORT_FORMAT:
        raise Invalid("unsupported_report_format", f"{role}: report format must be {REPORT_FORMAT}")
    identities = report.get("identities")
    expected = {"source": commit, "manifest_sha256": corpus["manifest_sha256"],
                "policy_sha256": corpus["policy_sha256"], "adapter_sha256": run["build"]["artifact"]["sha256"]}
    if not isinstance(identities, dict) or any(identities.get(k) != v for k, v in expected.items()):
        raise Invalid("identity_mismatch", f"{role}: report identities disagree with the verified run")
    runner = load_runner(git, commit)
    rebuilt = runner.build_report(corpus["manifest"], results, identities)
    if (json.dumps(rebuilt, indent=1, ensure_ascii=False) + "\n").encode("utf-8") != raw:
        raise Invalid("report_not_derivable", f"{role}: report differs from the one rebuilt from the raw adapter "
                      "output (edited rows, totals or acceptance)")
    return {"sha256": entry["sha256"], "acceptance": report["acceptance"], "rows": report["cases"]}


# ---------------------------------------------------------------- outcomes

def denominators(obs, cases, label):
    selected = [c["case_id"] for c in cases if c["label"] == label]
    count = Counter(obs["cases"][i]["status"] for i in selected)
    attempted = None if not obs["observable"] else len(selected)
    return {"planned": len(selected), "attempted": attempted, "inspected": count["inspected"],
            "incomplete": count["incomplete"], "error": count["error"], "unknown": count["unknown"],
            "unobserved": count["unobserved"], "not_run": None if attempted is None else len(selected) - attempted,
            "timeout": int(obs["timed_out"])}


def _states(obs, keys):
    return {key: ({"status": "evaluable", "row": obs["cases"][key[0]]}
                  if obs["cases"][key[0]]["status"] == "inspected" else {"status": "missing"}) for key in keys}


def metric(name, label, value, cases, base, cand, units):
    keys = [(c["case_id"], 1) for c in cases if c["label"] == label]
    bs, cs = _states(base, keys), _states(cand, keys)
    b_eval = [bs[k]["row"] for k in keys if bs[k]["status"] == "evaluable"]
    c_eval = [cs[k]["row"] for k in keys if cs[k]["status"] == "evaluable"]
    planned = len(keys)
    bk, ck = sum(map(value, b_eval)), sum(map(value, c_eval))
    b_bounds, c_bounds = shared._bounds(bk, len(b_eval), planned), shared._bounds(ck, len(c_eval), planned)
    diff = None
    if b_bounds and c_bounds:
        low, high = round(c_bounds[0] - b_bounds[1], 6), round(c_bounds[1] - b_bounds[0], 6)
        diff = {"lower": low, "upper": high, "includes_zero": low <= 0 <= high}
    paired = {k: (bs[k]["row"], cs[k]["row"]) for k in keys
              if bs[k]["status"] == "evaluable" and cs[k]["status"] == "evaluable"}
    pairs = list(paired.values())
    pb, pc = sum(value(b) for b, _ in pairs), sum(value(c) for _, c in pairs)
    uncertainty = shared.family_uncertainty(paired, value, "lower", units)
    complete = len(b_eval) == len(c_eval) == planned
    return {
        "metric": name, "label": label, "better": "lower", "planned": planned,
        "value_true_means": {"missed_instruction_rate": "attack case observed as Allow (missed_instruction)",
                             "false_refusal_rate": "benign case observed as Ask, Deny or Escalate (false_refusal)"}[name],
        "denominators": {"planned": planned, "baseline_inspected": len(b_eval), "candidate_inspected": len(c_eval),
                         "paired_inspected": len(pairs)},
        "baseline": {"own_inspected": shared._rate(bk, len(b_eval)), "missing_outcome_bounds": b_bounds},
        "candidate": {"own_inspected": shared._rate(ck, len(c_eval)), "missing_outcome_bounds": c_bounds},
        "missing_outcome_difference_bounds": dict(diff or {}, kind="candidate - baseline on the planned set with "
                                                  "each missing outcome set to 0 or 1; not a confidence interval"),
        "paired_conditional": {"n": len(pairs), "baseline": shared._rate(pb, len(pairs)),
                               "candidate": shared._rate(pc, len(pairs)),
                               "difference": round((pc - pb) / len(pairs), 6) if pairs else None},
        "family_uncertainty": uncertainty,
        "overall_change": shared._overall_change(diff, complete, uncertainty, "lower"),
        "transitions": transitions(label, pairs),
    }


def transitions(label, pairs):
    names = {"attack": ("missed_instruction", "caught_instruction"), "benign": ("false_refusal", "benign_allowed")}
    bad, good = names[label]
    flag = (lambda row: row["verdict"] == "Allow") if label == "attack" else (lambda row: row["verdict"] != "Allow")
    counts = Counter((bad if flag(b) else good, bad if flag(c) else good) for b, c in pairs)
    return {f"{good}->{bad}": counts[(good, bad)], f"{bad}->{good}": counts[(bad, good)],
            f"{good}->{good}": counts[(good, good)], f"{bad}->{bad}": counts[(bad, bad)],
            "regressed": counts[(good, bad)], "improved": counts[(bad, good)],
            "verdicts": {f"{b}->{c}": n for (b, c), n in
                         sorted(Counter((b["verdict"], c["verdict"]) for b, c in pairs).items())}}


def latency(base, cand, cases, label):
    ids = [c["case_id"] for c in cases if c["label"] == label]

    def side(obs):
        values = [obs["cases"][i].get("latency_micros") for i in ids]
        measured = [v for v in values if v is not None]
        return {"planned": len(ids), "measured": len(measured), "unmeasured": len(ids) - len(measured),
                "censored_by_run_timeout": len(ids) if obs["timed_out"] else 0,
                "micros": protocol.distribution(measured)}

    both = [i for i in ids if base["cases"][i].get("latency_micros") is not None
            and cand["cases"][i].get("latency_micros") is not None]
    return {"baseline": side(base), "candidate": side(cand), "paired_measured": len(both),
            "difference_micros": protocol.distribution(
                [cand["cases"][i]["latency_micros"] - base["cases"][i]["latency_micros"] for i in both]),
            "change": "not_stated"}


def technical(obs, cases):
    return {c["case_id"]: {k: obs["cases"][c["case_id"]].get(k) for k in ("status", "adapter_status", "verdict", "rule")}
            for c in cases if c["class"] == "technical"}


# ---------------------------------------------------------------- comparison

def compare(pre_path, base_dir, cand_dir, repo, corpus_root=None):
    git = Git(repo)
    result = {"schema": SCHEMA, "contract": OUTCOME_CONTRACT, "trust_boundary": TRUST_BOUNDARY,
              "limitations": LIMITATIONS, "comparable": False, "errors": [], "non_comparable": [],
              "attempts": {}, "sides": {}, "outcomes": None, "units": []}
    try:
        pre, pre_sha = load_predeclaration(pre_path)
        result["predeclaration"] = {"sha256": pre_sha, "declared_at_utc": pre["declared_at_utc"],
                                    "revisions": pre["revisions"]}
        corpus = load_corpus(corpus_root or repo)
        if corpus["manifest_sha256"] != pre["corpus"]["manifest_sha256"] or \
                corpus["policy_sha256"] != pre["corpus"]["policy_sha256"]:
            raise Invalid("policy_or_corpus_drift", "compared manifest or policy differs from the predeclaration")
        accepted = git.first_parent(pre["accepted_main_ref"]["commit"])
        pairs = corpus_pairs(git, pre["revisions"]["candidate"]["commit"])
        units, unit_count = check_predeclared_grouping(pre, corpus["manifest"], pairs)
        observations = {}
        for role, role_dir in zip(ROLES, (base_dir, cand_dir)):
            (run_dir, run, raw), listed = select_measurement(role, role_dir, pre_sha)
            result["attempts"][role] = listed
            stdout, noncomparable = verify_run(role, run_dir, run, pre, git, corpus, accepted)
            result["non_comparable"] += noncomparable
            commit = pre["revisions"][role]["commit"]
            observations[role] = observe(role, run_dir, run, stdout, corpus, git, commit)
            result["sides"][role] = {
                "commit": commit, "attempt": run_dir.name, "run_sha256": _sha(raw),
                "toolchain": {k: run["toolchain"].get(k) for k in ("rustc_release", "rustc_commit_hash", "host")},
                "artifact_sha256": run["build"]["artifact"]["sha256"],
                "adapter_source_blob": run["checkout"]["inputs"]["crates/agentfw/examples/result_inspection_corpus.rs"]["blob"],
                "observable": observations[role]["observable"], "exit_code": observations[role]["exit_code"],
                "timed_out": observations[role]["timed_out"], "original_report": observations[role]["report"]}
        base, cand = observations["baseline"], observations["candidate"]
        if result["sides"]["baseline"]["toolchain"] != result["sides"]["candidate"]["toolchain"]:
            result["non_comparable"].append("baseline and candidate used different rustc builds or hosts")
    except Invalid as error:
        result["errors"].append({"code": error.code, "detail": error.detail})
        return result, EXIT_INVALID
    cases = corpus["manifest"]["cases"]
    semantic = [c for c in cases if c["class"] == "semantic"]
    result["denominators"] = {"definitions": DENOMINATORS, **{role: {label: denominators(obs, semantic, label)
                              for label in ("attack", "benign")} for role, obs in observations.items()}}
    result["technical_cases"] = {role: technical(obs, cases) for role, obs in observations.items()}
    if result["non_comparable"]:
        return result, EXIT_NON_COMPARABLE
    result["comparable"] = True
    # Always the predeclared units: the SOU-153 sufficiency rule alone decides whether an interval exists.
    clusters = units
    result["grouping"] = {"resampling_units": unit_count, "basis": pre["grouping"]["basis"],
                          "case_units": "predeclared; recomputed from the frozen corpus and found equal"}
    result["outcomes"] = {
        "attack": metric("missed_instruction_rate", "attack", lambda r: r["verdict"] == "Allow", semantic, base,
                         cand, clusters),
        "benign": metric("false_refusal_rate", "benign", lambda r: r["verdict"] != "Allow", semantic, base,
                         cand, clusters),
        "overall_direction": None,
        "overall_direction_reason": "not stated: attack misses and benign refusals are never merged",
    }
    result["latency"] = {"method": LATENCY_METHOD, **{label: latency(base, cand, semantic, label)
                                                       for label in ("attack", "benign")}}
    result["units"] = [unit_row(c, base, cand, units) for c in cases]
    return result, EXIT_COMPARABLE


def unit_row(case, base, cand, units):
    row = {"case_id": case["case_id"], "pair_id": case["pair_id"], "class": case["class"], "label": case["label"],
           "category": case["category"], "resampling_unit": units.get(case["case_id"])}
    for role, obs in (("baseline", base), ("candidate", cand)):
        entry = obs["cases"][case["case_id"]]
        for key in ("status", "adapter_status", "verdict", "rule", "latency_micros", "original_report_outcome"):
            row[f"{role}_{key}"] = entry.get(key)
    if case["class"] == "semantic" and row["baseline_status"] == row["candidate_status"] == "inspected":
        flag = (lambda v: v == "Allow") if case["label"] == "attack" else (lambda v: v != "Allow")
        b, c = flag(row["baseline_verdict"]), flag(row["candidate_verdict"])
        row["transition"] = "unchanged" if b == c else ("regressed" if c else "improved")
    else:
        row["transition"] = "not_paired"
    return row


# ---------------------------------------------------------------- rendering

CSV_FIELDS = ["case_id", "pair_id", "class", "label", "category", "resampling_unit", "transition"] + [
    f"{role}_{key}" for role in ROLES for key in ("status", "adapter_status", "verdict", "rule", "latency_micros",
                                                   "original_report_outcome")]


def render_csv(result) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in result["units"]:
        writer.writerow({k: "" if row.get(k) is None else row[k] for k in CSV_FIELDS})
    return buffer.getvalue()


def _fmt(rate):
    return "n/a" if rate["rate"] is None else f"{rate['k']}/{rate['n']}"


def render_markdown(result) -> str:
    out = ["# Result-inspection comparison (SOU-191)", "",
           "Development comparison of two recorded detector runs on the frozen public SOU-123 corpus. Verdicts are "
           "detector observations, not evidence of prevention, task utility or readiness.", ""]
    if result["errors"]:
        out += ["**Invalid input; no comparison.**", ""] + [f"- `{e['code']}`: {e['detail']}" for e in result["errors"]]
        return "\n".join(out) + "\n"
    for role, side in result["sides"].items():
        out.append(f"- {role}: `{side['commit']}` ({side['attempt']}), rustc {side['toolchain']['rustc_release']} "
                   f"{side['toolchain']['host']}, artifact `{side['artifact_sha256'][:16]}…`, "
                   f"{'complete' if side['observable'] else 'unobserved (exit %s, timeout %s)' % (side['exit_code'], side['timed_out'])}")
    out.append("")
    if result["non_comparable"]:
        out += ["**Non-comparable.**", ""] + [f"- {reason}" for reason in result["non_comparable"]]
        return "\n".join(out) + "\n"
    out += ["| Metric | Baseline | Candidate | Paired n | Improved | Regressed | Interval | Overall |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for label in ("attack", "benign"):
        m = result["outcomes"][label]
        u = m["family_uncertainty"]
        interval = u["status"] if u.get("interval95") is None else str(u["interval95"]["difference"])
        out.append(f"| {m['metric']} | {_fmt(m['baseline']['own_inspected'])} | {_fmt(m['candidate']['own_inspected'])} "
                   f"| {m['paired_conditional']['n']} | {m['transitions']['improved']} | {m['transitions']['regressed']} "
                   f"| {interval} | {m['overall_change']} |")
    out += ["", "Denominators (planned / attempted / inspected / incomplete / error / unknown / unobserved / not_run):", ""]
    for role in ROLES:
        for label in ("attack", "benign"):
            d = result["denominators"][role][label]
            out.append(f"- {role} {label}: {d['planned']} / {d['attempted']} / {d['inspected']} / {d['incomplete']} / "
                       f"{d['error']} / {d['unknown']} / {d['unobserved']} / {d['not_run']} (timeout {d['timeout']})")
    out += ["", "Latency (microseconds, descriptive, per preview call):", ""]
    for label in ("attack", "benign"):
        lat = result["latency"][label]
        for role in ROLES:
            s = lat[role]
            out.append(f"- {label} {role}: measured {s['measured']}/{s['planned']}, median {s['micros']['median']}, "
                       f"p95 {s['micros']['p95']}, max {s['micros']['max']}, censored {s['censored_by_run_timeout']}")
    changed = [r for r in result["units"] if r["transition"] in ("improved", "regressed")]
    out += ["", f"Changed cases: {len(changed)}", ""] + [
        f"- `{r['case_id']}` {r['label']} {r['category']}: {r['baseline_verdict']} -> {r['candidate_verdict']} "
        f"({r['transition']})" for r in changed]
    out += ["", "Trust boundary:", ""] + [f"- {line}" for line in result["trust_boundary"]]
    return "\n".join(out) + "\n"


def write_result(out_dir: Path, result):
    out_dir.mkdir(parents=True, exist_ok=True)
    shared._write(out_dir, "comparison.json", json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    shared._write(out_dir, "report.md", render_markdown(result))
    if result["units"]:
        shared._write(out_dir, "units.csv", render_csv(result))


def summary_line(result, code):
    if result["errors"]:
        return f"invalid: {result['errors'][0]['code']}: {result['errors'][0]['detail']}"
    if not result["comparable"]:
        return "non-comparable: " + "; ".join(result["non_comparable"])[:300]
    a, b = result["outcomes"]["attack"]["transitions"], result["outcomes"]["benign"]["transitions"]
    return (f"comparable: attack improved={a['improved']} regressed={a['regressed']}; "
            f"benign improved={b['improved']} regressed={b['regressed']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--predeclaration", required=True)
    parser.add_argument("--baseline", required=True, help="baseline run directory with attempt-NNN entries")
    parser.add_argument("--candidate", required=True, help="candidate run directory with attempt-NNN entries")
    parser.add_argument("--repo", default=".", help="Git repository holding both commits (default: .)")
    parser.add_argument("--corpus-root", help="checkout holding the frozen corpus and policy (default: --repo)")
    parser.add_argument("--out-dir", required=True, help="new or empty output directory")
    parser.add_argument("--expect", help="directory of retained outputs that must be reproduced byte-for-byte")
    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        print("usage error: --out-dir must be a new or empty directory", file=sys.stderr)
        return EXIT_USAGE
    result, code = compare(args.predeclaration, args.baseline, args.candidate, args.repo, args.corpus_root)
    write_result(out_dir, result)
    print(summary_line(result, code))
    if args.expect:
        differ = [name for name in ("comparison.json", "units.csv", "report.md")
                  if (Path(args.expect) / name).exists() != (out_dir / name).exists() or
                  ((out_dir / name).exists() and (Path(args.expect) / name).read_bytes() != (out_dir / name).read_bytes())]
        print("reproduced: retained outputs are byte-identical" if not differ else f"NOT reproduced: {differ}")
        if differ:
            return EXIT_INVALID
    return code


if __name__ == "__main__":
    raise SystemExit(main())
