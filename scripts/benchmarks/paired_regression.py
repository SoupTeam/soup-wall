# SPDX-License-Identifier: Apache-2.0
"""Offline paired development-regression comparison of two matched AgentDojo runs (SOU-153).

Standard library only. Reads two ``soup-wall-agentdojo-matched/1`` run reports, each with the
frozen schema 2 plan it was produced against, and compares the enforced trajectories of the
same planned units. It never runs tasks, models or evaluators and never changes the producer:
every plan and run is first validated with ``agentdojo_protocol``.

The result separates four questions and never merges them into a readiness verdict:

* input validity   - bounded size and record counts, strict JSON, producer contract checks;
* comparability    - identical case set, task identities, attack, model, runtime and run
                     settings, and the checkable input links verified against supplied source
                     bytes; remaining gaps (per-case semantic input, families) are listed;
* completeness     - planned, attempted, evaluable and paired-evaluable units per side;
* outcome change   - paired transitions on units evaluable in both runs (conditional on that
                     subset) and missing-outcome bounds on the fixed planned set.

Exit codes: 0 = comparison report written (conditionally comparable with listed gaps, or verified;
                regressions and partial coverage included);
            1 = non-comparable inputs; 2 = invalid or rejected inputs; 3 = usage error.

usage:
  python scripts/benchmarks/paired_regression.py --baseline-plan P0 --baseline-run R0 \
      --candidate-plan P1 --candidate-run R1 [--inputs SOURCE.json] [--families FAMILIES.json] \
      --out-dir FRESH_DIR
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import tempfile

import agentdojo_live as adapter
import agentdojo_protocol as protocol

SCHEMA = "soup-wall-paired-regression/1"
INPUTS_SCHEMA = "soup-wall-paired-regression-inputs/1"
FAMILIES_SCHEMA = "soup-wall-paired-regression-families/1"
DEFAULT_LIMITS = {
    "max_file_bytes": 8 * 1024 * 1024,
    "max_plan_cases": 5_000,
    "max_planned_units": 20_000,
    "max_run_rows": 40_000,
    "max_source_files": 5_000,
    "max_injection_cases": 5_000,
}
EXIT_COMPARABLE, EXIT_NON_COMPARABLE, EXIT_INVALID, EXIT_USAGE = 0, 1, 2, 3
# Run-level context that can change outcomes without being part of the frozen plan. Both sides
# must record it and it must be identical; a missing field is never assumed to be irrelevant.
RUN_CONTEXT = ("settings", "selection", "budget", "model", "provider", "provider_url_sha256",
               "python_version", "dependency_lock_sha256", "dependency_versions")
# Revision pins shown side by side. They are producer declarations, not attestations.
RUN_PINS = ("mode", "agent_binary_sha256", "policy_sha256", "native_registry_sha256",
            "native_semantics_registry_sha256", "adapter_source_sha256", "cli_source_sha256",
            "protocol_source_sha256")
CASE_FIELDS = ("user_task_id", "injection_task_id", "injection_vectors", "injections_sha256")
UNKNOWN = {"availability": "unavailable",
           "reason": "matched/1 rows carry Boolean evaluator outputs only; the producer reports no "
                     "unknown outcome. Ask (approval_required) is reported separately and is not unknown."}
TIMEOUTS = {"count": None, "availability": "undistinguished",
            "reason": "the producer wraps provider transport errors, including timeouts, in AdapterError "
                      "with reason provider_failure; reason and error_type are kept verbatim per stopped unit"}
LIMITATIONS = [
    "Development comparison of recorded runs; not held-out efficacy, general safety or pilot readiness evidence.",
    "Revision pins and the run's source inventory hash are producer declarations; this tool checks their "
    "consistency, not which binary or policy actually executed.",
    "Input binding is partial: run-to-plan, source-to-inventory and injection-to-plan links are checked; the "
    "binding of a case's full semantic input (user task and environment content) is not.",
    "Paired differences are conditional on units evaluable in both runs; with partial coverage only the "
    "missing-outcome bounds on the planned set account for missing outcomes; they are not confidence intervals.",
    "Without declared semantic families, correlated variants are grouped by known plan dependencies only.",
    "Unknown outcomes are unavailable in this producer contract; timeouts are not distinguishable.",
    "Checkpoint scope: family-aware uncertainty and latency distributions are not computed yet.",
]


class Rejected(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _error(code, role, detail):
    return {"code": code, "role": role, "detail": detail}


# ---------------------------------------------------------------- bounded strict reading

def read_bounded(path, limit: int) -> bytes:
    """Refuse oversized files from their size before reading, then read at most ``limit + 1`` bytes."""
    try:
        size = os.stat(path).st_size
        if size > limit:
            raise Rejected("file_too_large", f"{size} bytes exceeds the {limit}-byte limit")
        with open(path, "rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as error:
        raise Rejected("unreadable_input", type(error).__name__) from None
    if len(raw) > limit:
        raise Rejected("file_too_large", f"file grew beyond the {limit}-byte limit while reading")
    return raw


def parse(raw: bytes):
    """Strict JSON: duplicate fields, NaN/Infinity, invalid UTF-8 and runaway nesting are rejected."""
    try:
        return protocol.strict_json(raw)
    except protocol.ProtocolError as error:
        raise Rejected("malformed_json", str(error)) from None
    except (RecursionError, ValueError) as error:
        raise Rejected("malformed_json", type(error).__name__) from None


def check_plan_shape(plan, limits) -> None:
    """Contract identity, record bounds and duplicate case IDs before the producer validator runs."""
    if not isinstance(plan, dict) or plan.get("schema_version") != protocol.PLAN_SCHEMA \
            or plan.get("protocol") != protocol.PROTOCOL:
        raise Rejected("incompatible_producer_contract",
                       f"plan must be schema_version {protocol.PLAN_SCHEMA} of {protocol.PROTOCOL}")
    entries = [entry for entry in plan["sets"].values() if isinstance(entry, dict)] \
        if isinstance(plan.get("sets"), dict) else []
    cases = [case for entry in entries if isinstance(entry.get("cases"), list) for case in entry["cases"]]
    if len(cases) > limits["max_plan_cases"]:
        raise Rejected("too_many_records", f"{len(cases)} plan cases exceed {limits['max_plan_cases']}")
    units = sum(len(entry["cases"]) * entry["repetitions"] for entry in entries
                if isinstance(entry.get("cases"), list) and type(entry.get("repetitions")) is int
                and entry["repetitions"] > 0)
    if units > limits["max_planned_units"]:
        raise Rejected("too_many_records", f"{units} planned units exceed {limits['max_planned_units']}")
    seen, duplicates = set(), set()
    for case in cases:
        case_id = case.get("case_id") if isinstance(case, dict) else None
        if isinstance(case_id, str):
            if case_id in seen:
                duplicates.add(case_id)
            seen.add(case_id)
    if duplicates:
        raise Rejected("duplicate_case_id", f"duplicate case IDs {sorted(duplicates)[:10]}")


def check_run_shape(run, plan_raw: bytes, limits) -> None:
    if not isinstance(run, dict) or run.get("schema_version") != protocol.RUN_SCHEMA \
            or run.get("protocol") != protocol.PROTOCOL:
        raise Rejected("incompatible_producer_contract",
                       f"run must be schema_version {protocol.RUN_SCHEMA} of {protocol.PROTOCOL}")
    rows = run.get("cases")
    if isinstance(rows, list) and len(rows) > limits["max_run_rows"]:
        raise Rejected("too_many_records", f"{len(rows)} run rows exceed {limits['max_run_rows']}")
    if run.get("plan_sha256") != protocol.digest(plan_raw):
        raise Rejected("plan_hash_mismatch", "run plan_sha256 differs from the SHA-256 of the supplied plan bytes")


def load_side(role, plan_path, run_path, limits, inputs, errors):
    """Read and validate one side; append errors and return the side or None."""
    raw = {}
    for kind, path in (("plan", plan_path), ("run", run_path)):
        name = f"{role}_{kind}"
        try:
            raw[kind] = read_bounded(path, limits["max_file_bytes"])
        except Rejected as error:
            errors.append(_error(error.code, name, error.detail))
            inputs.append({"role": name, "file": Path(path).name, "sha256": None, "bytes": None})
            continue
        inputs.append({"role": name, "file": Path(path).name, "sha256": protocol.digest(raw[kind]),
                       "bytes": len(raw[kind])})
    if len(raw) != 2:
        return None
    try:
        plan = parse(raw["plan"])
        check_plan_shape(plan, limits)
    except Rejected as error:
        errors.append(_error(error.code, f"{role}_plan", error.detail))
        return None
    try:
        run = parse(raw["run"])
        check_run_shape(run, raw["plan"], limits)
    except Rejected as error:
        errors.append(_error(error.code, f"{role}_run", error.detail))
        return None
    plan_errors = protocol.validate_plan(plan)
    if plan_errors:
        errors.extend(_error("plan_contract_violation", f"{role}_plan", e) for e in plan_errors[:20])
        return None
    run_errors, summary = protocol.validate_run(plan, protocol.digest(raw["plan"]), run, role)
    if run_errors:
        errors.extend(_error("run_contract_violation", f"{role}_run", e) for e in run_errors[:20])
        return None
    return {"role": role, "plan": plan, "run": run, "summary": summary, "set": run["plan_set"],
            "plan_sha256": protocol.digest(raw["plan"]), "run_sha256": protocol.digest(raw["run"])}


# ---------------------------------------------------------------- source bundle and families

def source_inventory_sha256(files: dict) -> str:
    """The producer's ``verify_checkout`` inventory hash over ``src/`` files.

    Same composition as ``agentdojo_live.verify_checkout``: SHA-256 of each file's exact bytes,
    keyed by its repository path in Git index (byte) order, serialized with the producer's own
    ``encoded`` and hashed with its ``digest``.
    """
    names = sorted(files, key=lambda name: name.encode("utf-8"))
    return adapter.digest(adapter.encoded({name: adapter.digest(files[name].encode("utf-8")) for name in names}))


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def load_inputs(path, limits):
    raw = read_bounded(path, limits["max_file_bytes"])
    bundle = parse(raw)
    keys = {"schema", "provenance", "upstream", "files", "injections"}
    if not isinstance(bundle, dict) or set(bundle) != keys or bundle["schema"] != INPUTS_SCHEMA:
        raise Rejected("invalid_inputs_bundle", f"inputs must be {INPUTS_SCHEMA} with fields {sorted(keys)}")
    provenance, upstream, files, injections = (bundle[key] for key in ("provenance", "upstream", "files", "injections"))
    if not isinstance(provenance, dict) or set(provenance) != {"kind", "description"} or \
            not _text(provenance["kind"]) or not _text(provenance["description"]):
        raise Rejected("invalid_inputs_bundle", "provenance needs text kind and description")
    if not isinstance(upstream, dict) or set(upstream) != {"revision", "benchmark_version", "suite"} or \
            not all(_text(value) for value in upstream.values()):
        raise Rejected("invalid_inputs_bundle", "upstream needs text revision, benchmark_version and suite")
    if not isinstance(files, dict) or not isinstance(injections, dict):
        raise Rejected("invalid_inputs_bundle", "files and injections must be objects")
    if len(files) > limits["max_source_files"] or len(injections) > limits["max_injection_cases"]:
        raise Rejected("too_many_records", "inputs bundle exceeds the file or injection record limit")
    for name, content in files.items():
        # The producer lists ``git ls-files src`` without -z, so only plain ASCII paths are reproducible.
        if not name.startswith("src/") or not name.isascii() or "\\" in name or ".." in name.split("/") \
                or not isinstance(content, str):
            raise Rejected("invalid_inputs_bundle", f"source file {name[:80]!r} must be an ASCII src/ path with text")
    for case_id, mapping in injections.items():
        if not isinstance(mapping, dict) or not all(isinstance(v, str) for v in mapping.values()):
            raise Rejected("invalid_inputs_bundle", f"injections for {case_id[:80]!r} must map vectors to strings")
    return bundle, protocol.digest(raw)


def load_families(path, limits):
    raw = read_bounded(path, limits["max_file_bytes"])
    data = parse(raw)
    keys = {"schema", "provenance", "plan_set", "families"}
    if not isinstance(data, dict) or set(data) != keys or data["schema"] != FAMILIES_SCHEMA:
        raise Rejected("invalid_families", f"families must be {FAMILIES_SCHEMA} with fields {sorted(keys)}")
    provenance = data["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {"kind", "assigned_by", "basis"} or \
            not all(_text(value) for value in provenance.values()):
        raise Rejected("invalid_families", "provenance needs text kind, assigned_by and basis")
    families = data["families"]
    if not isinstance(families, dict) or not families or len(families) > limits["max_plan_cases"]:
        raise Rejected("invalid_families", "families must be a non-empty bounded object")
    for family_id, cases in families.items():
        if not _text(family_id) or not isinstance(cases, list) or not cases or \
                not all(isinstance(case_id, str) for case_id in cases):
            raise Rejected("invalid_families", f"family {family_id[:80]!r} must list case IDs")
    return data, protocol.digest(raw)


def verify_binding(bundle, side) -> dict:
    """Problems per verifiable link between one side's plan/run and the supplied source bytes."""
    plan, run = side["plan"], side["run"]
    source, injected = [], []
    inventory = source_inventory_sha256(bundle["files"])
    if inventory != plan["upstream"]["source_inventory_sha256"]:
        source.append("source inventory recomputed from the bundle differs from the plan")
    if inventory != run["upstream"].get("source_inventory_sha256"):
        source.append("source inventory recomputed from the bundle differs from the inventory recorded by the run")
    for key in ("revision", "benchmark_version", "suite"):
        if bundle["upstream"][key] != plan["upstream"][key]:
            source.append(f"bundle upstream {key} differs from the plan")
    all_ids = {case["case_id"] for entry in plan["sets"].values() for case in entry["cases"]}
    extra = sorted(set(bundle["injections"]) - all_ids)
    if extra:
        injected.append(f"bundle has injections for cases outside the plan {extra[:5]}")
    for case in plan["sets"][side["set"]]["cases"]:
        mapping = bundle["injections"].get(case["case_id"])
        if case["injection_task_id"] is None:
            if mapping:
                injected.append(f"{case['case_id']}: benign case has injections in the bundle")
        elif mapping is None:
            injected.append(f"{case['case_id']}: injection strings missing from the bundle")
        elif protocol.injections_sha256(mapping) != case["injections_sha256"]:
            injected.append(f"{case['case_id']}: recomputed injections_sha256 differs from the plan")
        elif sorted(mapping) != case["injection_vectors"]:
            injected.append(f"{case['case_id']}: injection vectors differ from the plan")
    return {"source_to_inventory": source, "injections_to_plan": injected}


CASE_SEMANTIC_INPUT = {
    "status": "unverified",
    "reason": "no producer record binds a case's user task and environment content to that case ID; the "
              "inventory hash covers the source as a whole, and a matching string is not a binding"}


def input_binding(bundle, base, cand) -> dict:
    """Each link with its own status. Only verifiable links are checked; none implies the others."""
    links = {"run_to_plan": {"status": "verified",
                             "method": "each run's plan_sha256 equals the SHA-256 of its supplied plan bytes"},
             "case_semantic_input": dict(CASE_SEMANTIC_INPUT)}
    if bundle is None:
        for link in ("source_to_inventory", "injections_to_plan"):
            links[link] = {"status": "not_supplied"}
        return {"status": "declared_unverified", "links": links,
                "detail": "no source bundle: task, environment and injection identities are plan declarations"}
    problems = {role: verify_binding(bundle, side) for role, side in (("baseline", base), ("candidate", cand))}
    methods = {"source_to_inventory": "bundle src/ bytes reproduce the plan's and the run's recorded "
                                      "source_inventory_sha256 with the producer's verify_checkout composition",
               "injections_to_plan": "injection strings of every attacked case reproduce its planned "
                                     "injections_sha256 and vectors"}
    for link, method in methods.items():
        found = {role: problems[role][link] for role in problems if problems[role][link]}
        links[link] = {"status": "mismatch" if found else "verified", "method": method, "problems": found}
    mismatch = any(links[link]["status"] == "mismatch" for link in methods)
    return {"status": "mismatch" if mismatch else "partially_verified", "links": links,
            "provenance": bundle["provenance"],
            "residual_trust": ["the run's inventory hash is the producer's own runtime record",
                               "run-level settings, model and runtime are compared between sides only"]}


# ---------------------------------------------------------------- comparability

def _diff_keys(left, right, prefix=""):
    if isinstance(left, dict) and isinstance(right, dict):
        keys = sorted(set(left) | set(right))
        return [k for key in keys for k in _diff_keys(left.get(key), right.get(key), f"{prefix}{key}.")]
    return [] if left == right else [prefix.rstrip(".")]


def _reason(code, detail):
    return {"code": code, "detail": detail}


def comparability_reasons(base, cand) -> list[dict]:
    reasons = []
    bp, cp, br, cr = base["plan"], cand["plan"], base["run"], cand["run"]
    if base["set"] != cand["set"]:
        reasons.append(_reason("plan_set_mismatch", f"baseline {base['set']} vs candidate {cand['set']}"))
    for key, code in (("upstream", "upstream_mismatch"), ("attack", "attack_mismatch")):
        if bp[key] != cp[key]:
            reasons.append(_reason(code, f"differs in {_diff_keys(bp[key], cp[key])}"))
    for key in ("model", "runtime"):
        if bp["identities"][key] != cp["identities"][key]:
            reasons.append(_reason(f"{key}_identity_mismatch",
                                   f"differs in {_diff_keys(bp['identities'][key], cp['identities'][key])}"))
    missing = sorted({f"{role}:{field}" for role, run in (("baseline", br), ("candidate", cr))
                      for field in RUN_CONTEXT if field not in run})
    if missing:
        reasons.append(_reason("run_settings_unavailable", f"run context not recorded: {missing}"))
    differing = [field for field in RUN_CONTEXT if field in br and field in cr and br[field] != cr[field]]
    if differing:
        reasons.append(_reason("run_settings_mismatch",
                               f"differs in {[k for f in differing for k in _diff_keys({f: br[f]}, {f: cr[f]})]}"))
    if base["set"] == cand["set"]:
        be, ce = bp["sets"][base["set"]], cp["sets"][cand["set"]]
        if be["repetitions"] != ce["repetitions"]:
            reasons.append(_reason("repetitions_mismatch", f"{be['repetitions']} vs {ce['repetitions']}"))
        bcases = {case["case_id"]: case for case in be["cases"]}
        ccases = {case["case_id"]: case for case in ce["cases"]}
        if sorted(set(bcases) - set(ccases)):
            reasons.append(_reason("case_missing_in_candidate", f"{sorted(set(bcases) - set(ccases))[:10]}"))
        if sorted(set(ccases) - set(bcases)):
            reasons.append(_reason("case_added_in_candidate", f"{sorted(set(ccases) - set(bcases))[:10]}"))
        changed = []
        for case_id in sorted(set(bcases) & set(ccases)):
            fields = [f for f in CASE_FIELDS if bcases[case_id][f] != ccases[case_id][f]]
            if (bcases[case_id]["injection_task_id"] is None) != (ccases[case_id]["injection_task_id"] is None):
                fields.append("expected_label")
            if fields:
                changed.append(f"{case_id} ({', '.join(fields)})")
        if changed:
            reasons.append(_reason("case_changed", f"{changed[:10]}"))
    return reasons


def pins(side):
    candidate = side["plan"]["identities"]["candidate"]
    return {"plan_sha256": side["plan_sha256"], "run_report_sha256": side["run_sha256"],
            "plan_id": side["plan"]["plan_id"], "plan_version": side["plan"]["plan_version"],
            "source_revision": candidate["source_revision"], "adapter": candidate["adapter"],
            "plan_agent_binary_sha256": candidate["agent_binary_sha256"],
            "plan_native_semantics_registry_sha256": candidate["native_semantics_registry_sha256"],
            "plan_policy_sha256": side["plan"]["identities"]["policy_sha256"],
            "run": {key: side["run"].get(key) for key in RUN_PINS}}


# ---------------------------------------------------------------- grouping

class _Union:
    def __init__(self, items):
        self.parent = {item: item for item in items}

    def find(self, item):
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def join(self, left, right):
        left, right = self.find(left), self.find(right)
        if left != right:
            self.parent[max(left, right)] = min(left, right)


def _components(case_ids, links):
    union = _Union(case_ids)
    for members in links:
        for other in members[1:]:
            union.join(members[0], other)
    groups = {}
    for case_id in case_ids:
        groups.setdefault(union.find(case_id), []).append(case_id)
    ordered = sorted(groups.values(), key=lambda members: min(members))
    return {case_id: f"g{index + 1:03d}" for index, members in enumerate(ordered) for case_id in members}, len(ordered)


def grouping(cases, families):
    """Dependency clusters from shared plan identities; resampling units also merge declared families."""
    case_ids = [case["case_id"] for case in cases]
    by_key = {}
    for case in cases:
        keys = [("user_task", case["user_task_id"])]
        if case["injection_task_id"] is not None:
            keys += [("injection_task", case["injection_task_id"]), ("injection_payload", case["injections_sha256"])]
        for key in keys:
            by_key.setdefault(key, []).append(case["case_id"])
    dependency, dependency_count = _components(case_ids, list(by_key.values()))
    result = {
        "dependency_clusters": {
            "basis": "connected components of cases sharing user_task_id, injection_task_id or a non-empty "
                     "injections_sha256 (repetitions of a case always share its cluster)",
            "semantics": "known statistical dependencies only; not semantic families",
            "count": dependency_count},
        "semantic_families": {"status": "unavailable",
                              "reason": "the producer contract has no family field; supply --families"},
        "resampling_units": None,
    }
    family_of = {}
    if families is not None:
        family_of = {case_id: family_id for family_id, members in families["data"]["families"].items()
                     for case_id in members}
        result["semantic_families"] = {
            "status": "declared", "sha256": families["sha256"], "provenance": families["data"]["provenance"],
            "count": len(families["data"]["families"]),
            "verification": "every compared case is in exactly one family; expected labels come from the plan only"}
        links = list(by_key.values()) + [members for members in families["data"]["families"].values()]
        units, count = _components(case_ids, links)
        result["resampling_units"] = {"basis": "dependency clusters merged with declared semantic families",
                                      "count": count, "status": "uncertainty not computed in checkpoint"}
    else:
        units = None
    return result, dependency, family_of, units


def family_problems(families, case_ids, set_name) -> list[str]:
    data = families["data"]
    problems = []
    if data["plan_set"] != set_name:
        problems.append(f"families declare plan_set {data['plan_set']!r}, compared set is {set_name!r}")
    listed = Counter(case_id for members in data["families"].values() for case_id in members)
    repeated = sorted(case_id for case_id, count in listed.items() if count > 1)
    unknown = sorted(set(listed) - set(case_ids))
    uncovered = sorted(set(case_ids) - set(listed))
    for label, ids in (("in more than one family", repeated), ("not in the plan set", unknown),
                       ("without a family", uncovered)):
        if ids:
            problems.append(f"cases {label}: {ids[:10]}")
    return problems


# ---------------------------------------------------------------- completeness and outcomes

def unit_states(side):
    """Per planned (case_id, repetition): evaluable (enforced row), incomplete (stopped there) or not_run."""
    entry = side["plan"]["sets"][side["set"]]
    rows = {(row["case_id"], row["repetition"], row["defended"]): row for row in side["summary"]["rows"]}
    failure = side["summary"]["failure"]
    states = {}
    for case in entry["cases"]:
        for repetition in range(1, entry["repetitions"] + 1):
            key = (case["case_id"], repetition)
            enforced, undefended = rows.get((*key, True)), rows.get((*key, False))
            if enforced is not None:
                state = {"status": "evaluable", "row": enforced}
            elif failure is not None and (failure["case_id"], failure["repetition"]) == key:
                state = {"status": "incomplete", "reason": failure["reason"], "error_type": failure["error_type"],
                         "stopped_mode": "enforced" if failure["defended"] else "undefended"}
            else:
                state = {"status": "not_run"}
            state["undefended"] = undefended
            state["attacked"] = case["injection_task_id"] is not None
            states[key] = state
    return states


def denominators(states):
    result = {}
    for domain, keep in (("all", lambda s: True), ("attacked", lambda s: s["attacked"]),
                         ("benign", lambda s: not s["attacked"])):
        selected = [s for s in states.values() if keep(s)]
        count = Counter(s["status"] for s in selected)
        result[domain] = {"planned": len(selected), "attempted": count["evaluable"] + count["incomplete"],
                          "evaluable": count["evaluable"], "incomplete": count["incomplete"],
                          "not_run": count["not_run"]}
    return result


def failures(states):
    stopped = [{"case_id": key[0], "repetition": key[1], "reason": s["reason"], "error_type": s["error_type"],
                "stopped_mode": s["stopped_mode"], "undefended_row_retained": s["undefended"] is not None}
               for key, s in states.items() if s["status"] == "incomplete"]
    return {"stopped_units": stopped, "by_reason": dict(Counter(s["reason"] for s in stopped)),
            "not_run_units": sum(s["status"] == "not_run" for s in states.values()), "timeouts": dict(TIMEOUTS)}


def _rate(k, n):
    return {"k": k, "n": n, "rate": round(k / n, 6) if n else None}


def _bounds(k, evaluable, planned):
    """Rate on the fixed planned denominator with every missing outcome set to 0 or to 1."""
    if not planned:
        return None
    return [round(k / planned, 6), round((k + planned - evaluable) / planned, 6)]


def _metric(name, better, value, keys, base_states, cand_states, paired):
    base_eval = [base_states[key]["row"] for key in keys if base_states[key]["status"] == "evaluable"]
    cand_eval = [cand_states[key]["row"] for key in keys if cand_states[key]["status"] == "evaluable"]
    planned = len(keys)
    bk, ck = sum(map(value, base_eval)), sum(map(value, cand_eval))
    b_bounds, c_bounds = _bounds(bk, len(base_eval), planned), _bounds(ck, len(cand_eval), planned)
    diff = None
    if b_bounds and c_bounds:
        # candidate - baseline over the same fixed planned units: lowest candidate minus highest
        # baseline, and highest candidate minus lowest baseline.
        low, high = round(c_bounds[0] - b_bounds[1], 6), round(c_bounds[1] - b_bounds[0], 6)
        diff = {"lower": low, "upper": high, "includes_zero": low <= 0 <= high}
    if diff is None:
        overall = "not_established: zero planned units"
    elif diff["includes_zero"]:
        overall = "not_established: missing-outcome bounds include zero"
    else:
        overall = "not_established: sign fixed under missing outcomes, but no uncertainty is computed"
    pairs = [(base_states[key]["row"], cand_states[key]["row"]) for key in paired]
    pb, pc = sum(value(b) for b, _ in pairs), sum(value(c) for _, c in pairs)
    up, down = ("improved", "regressed") if better == "higher" else ("regressed", "improved")
    transitions = {up: sum(not value(b) and value(c) for b, c in pairs),
                   down: sum(value(b) and not value(c) for b, c in pairs),
                   "unchanged_true": sum(value(b) and value(c) for b, c in pairs),
                   "unchanged_false": sum(not value(b) and not value(c) for b, c in pairs)}
    return {
        "metric": name, "better": better, "planned_units": planned,
        "value_true_means": {"missed_attack_rate": "attack succeeded (injection evaluator true)",
                             "benign_utility_rate": "user task completed (utility evaluator true)",
                             "attacked_utility_rate": "user task completed under attack",
                             "benign_interruption_rate": "any Deny or Ask on a benign trajectory"}[name],
        "denominators": {"planned": planned, "baseline_evaluable": len(base_eval),
                         "candidate_evaluable": len(cand_eval), "paired_evaluable": len(pairs)},
        "baseline": {"own_evaluable": _rate(bk, len(base_eval)), "missing_outcome_bounds": b_bounds},
        "candidate": {"own_evaluable": _rate(ck, len(cand_eval)), "missing_outcome_bounds": c_bounds},
        "missing_outcome_difference_bounds": dict(
            diff or {}, kind="candidate - baseline on the fixed planned set with every missing outcome set to "
                             "0 or 1; bounds for missing data, not a confidence interval"),
        "paired_conditional": {
            "subset": "complete-case intersection: units evaluable in both runs; a different subset from the "
                      "planned set, so not comparable with the missing-outcome bounds",
            "n": len(pairs), "status": "computed" if pairs else "zero_denominator",
            "baseline": _rate(pb, len(pairs)), "candidate": _rate(pc, len(pairs)),
            "difference": round((pc - pb) / len(pairs), 6) if pairs else None},
        "overall_change": overall,
        "transitions": transitions,
    }


def _interrupted(row):
    return bool(row["deny"] or row["approval_required"])


def decisions(states, keys):
    rows = [states[key]["row"] for key in keys if states[key]["status"] == "evaluable"]
    return {"evaluable": len(rows), "deny_observed": sum(r["deny"] > 0 for r in rows),
            "ask_observed": sum(r["approval_required"] > 0 for r in rows),
            "interrupted": sum(_interrupted(r) for r in rows)}


def outcomes(base_states, cand_states):
    keys = list(base_states)
    attacked = [key for key in keys if base_states[key]["attacked"]]
    benign = [key for key in keys if not base_states[key]["attacked"]]
    paired = [key for key in keys
              if base_states[key]["status"] == "evaluable" and cand_states[key]["status"] == "evaluable"]
    paired_attacked = [key for key in paired if key in set(attacked)]
    paired_benign = [key for key in paired if key in set(benign)]
    interruption = _metric("benign_interruption_rate", "lower", _interrupted, benign, base_states,
                           cand_states, paired_benign)
    drift = [f"{key[0]}#{key[1]}" for key in keys
             if base_states[key]["undefended"] is not None and cand_states[key]["undefended"] is not None
             and (base_states[key]["undefended"]["utility"], base_states[key]["undefended"]["injection_success"])
             != (cand_states[key]["undefended"]["utility"], cand_states[key]["undefended"]["injection_success"])]
    return {
        "arm": "enforced trajectories; evaluator outcomes as recorded, including after policy refusals",
        "security": _metric("missed_attack_rate", "lower", lambda r: r["injection_success"] is True,
                            attacked, base_states, cand_states, paired_attacked),
        "utility": _metric("benign_utility_rate", "higher", lambda r: r["utility"] is True,
                           benign, base_states, cand_states, paired_benign),
        "utility_under_attack": _metric("attacked_utility_rate", "higher", lambda r: r["utility"] is True,
                                        attacked, base_states, cand_states, paired_attacked),
        "benign_interruption": interruption,
        "policy_decisions": {
            "note": "Ask and Deny are observed policy decisions; neither is an unknown outcome",
            "baseline": {"attacked": decisions(base_states, attacked), "benign": decisions(base_states, benign)},
            "candidate": {"attacked": decisions(cand_states, attacked), "benign": decisions(cand_states, benign)}},
        "unknown": dict(UNKNOWN),
        "undefended_arm_drift": {
            "note": "undefended outcomes should not depend on the candidate revision; differences indicate "
                    "harness, provider or environment drift",
            "compared": sum(base_states[k]["undefended"] is not None and cand_states[k]["undefended"] is not None
                            for k in keys),
            "differing_units": drift},
        "overall_direction": None,
        "overall_direction_reason": "not stated: see each metric's overall_change; this checkpoint computes "
                                    "no uncertainty, and paired differences are conditional on the evaluable subset",
    }


def _unit_view(state):
    view = {"status": state["status"]}
    if state["status"] == "evaluable":
        row = state["row"]
        view.update(utility=row["utility"], injection_success=row["injection_success"], deny=row["deny"],
                    approval_required=row["approval_required"])
    elif state["status"] == "incomplete":
        view.update(reason=state["reason"], error_type=state["error_type"])
    return view


# ---------------------------------------------------------------- driver

def compare(baseline_plan, baseline_run, candidate_plan, candidate_run, inputs_path=None, families_path=None,
            limits=None):
    """Return ``(result, exit_code)``. Never raises for bad inputs; they become explicit statuses."""
    limits = dict(DEFAULT_LIMITS, **(limits or {}))
    errors, inputs = [], []
    result = {"schema": SCHEMA, "execution": {"status": "completed"}, "inputs": inputs, "limits": limits,
              "input_validity": None, "comparability": {"status": "not_assessed", "reasons": [], "gaps": []},
              "completeness": {"status": "not_assessed"}, "grouping": None, "outcomes": None, "units": None,
              "unknown": dict(UNKNOWN), "latency": {"status": "not_computed_in_checkpoint"},
              "uncertainty": {"status": "not_computed_in_checkpoint"},
              "readiness_verdict": None, "limitations": LIMITATIONS}
    base = load_side("baseline", baseline_plan, baseline_run, limits, inputs, errors)
    cand = load_side("candidate", candidate_plan, candidate_run, limits, inputs, errors)
    bundle = families = None
    for role, path, loader in (("inputs", inputs_path, load_inputs), ("families", families_path, load_families)):
        if path is None:
            continue
        try:
            data, sha = loader(path, limits)
            inputs.append({"role": role, "file": Path(path).name, "sha256": sha, "bytes": os.stat(path).st_size})
            if role == "inputs":
                bundle = data
            else:
                families = {"data": data, "sha256": sha}
        except Rejected as error:
            errors.append(_error(error.code, role, error.detail))
            inputs.append({"role": role, "file": Path(path).name, "sha256": None, "bytes": None})
    result["input_validity"] = {"status": "invalid" if errors else "valid", "errors": errors}
    if errors:
        result["comparability"] = {"status": "non_comparable", "gaps": [], "reasons": [
            _reason("invalid_input", "inputs failed validation; see input_validity")]}
        return result, EXIT_INVALID

    reasons = comparability_reasons(base, cand)
    binding = input_binding(bundle, base, cand)
    if binding["status"] == "declared_unverified":
        reasons.append(_reason("input_identity_unverified", binding["detail"]))
    elif binding["status"] == "mismatch":
        reasons.append(_reason("input_binding_failed", "supplied source bytes do not reproduce the declared identities"))
    if families is not None and base["set"] in base["plan"]["sets"]:
        ids = [case["case_id"] for case in base["plan"]["sets"][base["set"]]["cases"]]
        problems = family_problems(families, ids, base["set"])
        if problems:
            reasons.append(_reason("semantic_families_mismatch", "; ".join(problems)))
    # Gaps do not block the diagnostic report, but a comparison with any gap is never verified.
    gaps = [_reason("case_semantic_input_unverified", binding["links"]["case_semantic_input"]["reason"])]
    if families is None:
        gaps.append(_reason("semantic_families_unavailable",
                            "no --families: correlated variants are grouped only by known plan dependencies"))
    if bundle is not None and bundle["provenance"]["kind"] == "synthetic":
        gaps.append(_reason("synthetic_inputs", "source bundle provenance is synthetic: inputs and outcomes were "
                                                "generated to test the tool's accounting, not recorded executions"))
    status = "non_comparable" if reasons else "conditionally_comparable" if gaps else "verified_comparable"
    result["comparability"] = {"status": status, "reasons": reasons, "gaps": [] if reasons else gaps,
                               "statuses": {
                                   "non_comparable": "a comparability check failed; no outcomes",
                                   "conditionally_comparable": "all checks passed; outcomes are diagnostics "
                                                               "qualified by the listed gaps",
                                   "verified_comparable": "no gaps; unreachable for matched/1 until per-case "
                                                          "semantic input binding exists"},
                               "input_binding": binding,
                               "pins": {"baseline": pins(base), "candidate": pins(cand),
                                        "differs": _diff_keys(pins(base), pins(cand)),
                                        "note": "pins are producer declarations checked for run/plan consistency"}}
    base_states, cand_states = unit_states(base), unit_states(cand)
    per_side = {"baseline": denominators(base_states), "candidate": denominators(cand_states)}
    result["completeness"] = {
        "status": "per_side_only",
        "definitions": {
            "planned": "case x repetition units in the frozen plan set",
            "attempted": "units whose execution started: evaluable or stopped there",
            "evaluable": "units with an enforced trajectory and recorded evaluator outcomes",
            "incomplete": "the unit where the run stopped; evaluators were not reported",
            "not_run": "planned units never started",
            "paired_evaluable": "units evaluable in both runs"},
        **per_side,
        "failures": {"baseline": failures(base_states), "candidate": failures(cand_states)}}
    if reasons:
        return result, EXIT_NON_COMPARABLE

    keys = list(base_states)
    both = Counter((base_states[k]["status"] == "evaluable", cand_states[k]["status"] == "evaluable") for k in keys)
    result["completeness"].update(
        status="complete" if both[(True, True)] == len(keys) else "partial",
        paired={"planned": len(keys), "paired_evaluable": both[(True, True)],
                "evaluable_baseline_only": both[(True, False)], "evaluable_candidate_only": both[(False, True)],
                "evaluable_neither": both[(False, False)]})
    cases = base["plan"]["sets"][base["set"]]["cases"]
    result["grouping"], dependency, family_of, units = grouping(cases, families)
    by_id = {case["case_id"]: case for case in cases}
    result["outcomes"] = outcomes(base_states, cand_states)
    result["units"] = [{
        "case_id": key[0], "repetition": key[1],
        "expected_label": "attack" if base_states[key]["attacked"] else "benign",
        "user_task_id": by_id[key[0]]["user_task_id"], "injection_task_id": by_id[key[0]]["injection_task_id"],
        "injections_sha256": by_id[key[0]]["injections_sha256"], "input_identity": binding["status"],
        "dependency_cluster": dependency[key[0]], "semantic_family": family_of.get(key[0]),
        "resampling_unit": units[key[0]] if units else None,
        "baseline": _unit_view(base_states[key]), "candidate": _unit_view(cand_states[key])} for key in keys]
    return result, EXIT_COMPARABLE


def write_result(out_dir: Path, result) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    destination = out_dir / "comparison.json"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=out_dir, delete=False, suffix=".tmp") as handle:
        handle.write(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    os.replace(handle.name, destination)
    return destination


def summary_line(result, code) -> str:
    status = result["comparability"]["status"]
    reasons = ", ".join(r["code"] for r in result["comparability"]["reasons"]) or "none"
    gaps = ", ".join(g["code"] for g in result["comparability"].get("gaps", [])) or "none"
    text = f"exit {code}: comparability={status} validity={result['input_validity']['status']} " \
           f"completeness={result['completeness']['status']} reasons=[{reasons}] gaps=[{gaps}]"
    for error in result["input_validity"]["errors"][:5]:
        text += f"\n  {error['role']}: {error['code']}: {error['detail']}"
    return text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    for name in ("baseline-plan", "baseline-run", "candidate-plan", "candidate-run"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--inputs", help=f"{INPUTS_SCHEMA} source bundle binding both plans to source bytes")
    parser.add_argument("--families", help=f"{FAMILIES_SCHEMA} declared semantic families")
    parser.add_argument("--out-dir", required=True, help="new or empty directory for comparison.json")
    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        print("usage error: --out-dir must be a new or empty directory", file=sys.stderr)
        return EXIT_USAGE
    result, code = compare(args.baseline_plan, args.baseline_run, args.candidate_plan, args.candidate_run,
                           args.inputs, args.families)
    destination = write_result(out_dir, result)
    print(summary_line(result, code))
    print(f"wrote {destination}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
