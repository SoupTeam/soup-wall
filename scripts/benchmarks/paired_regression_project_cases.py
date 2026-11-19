# SPDX-License-Identifier: Apache-2.0
"""Bind one reviewed project annotation to an exact public development pair."""
from __future__ import annotations

import agentdojo_protocol as protocol

SCHEMA = "soup-wall-project-development-cases/1"
CASE_KEYS = {"case_id", "user_task_id", "injection_task_id", "expected_label",
             "semantic_family", "injections_sha256", "sources"}


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def exact(value, keys, message):
    require(isinstance(value, dict) and set(value) == keys, message)
    return value


def verify(manifest, pinned_sha256, bundle, bundle_sha256, sides, max_cases):
    """Verify source bytes and original plan/report identities. Never infer execution."""
    exact(manifest, {"schema", "plan_set", "provenance", "inputs_sha256", "upstream", "sides", "cases"},
          "invalid project manifest fields")
    require(manifest["schema"] == SCHEMA and manifest["plan_set"] == "development",
            "project case binding is development-only")
    require(bundle is not None and bundle["case_manifest"] is None and manifest["inputs_sha256"] == bundle_sha256,
            "project manifest needs its original public source bundle")
    provenance = exact(manifest["provenance"], {"kind", "basis"}, "invalid project provenance")
    require(provenance["kind"] == "project-development-ai-assisted"
            and isinstance(provenance["basis"], str) and 0 < len(provenance["basis"]) <= 240,
            "invalid project provenance")
    exact(manifest["sides"], {"baseline", "candidate"}, "invalid project source sides")
    planned = []
    for side in sides:
        run, plan = side["run"], side["plan"]
        require(side["set"] == "development" and manifest["upstream"] == plan["upstream"],
                "project manifest and development plan differ")
        expect = {"plan_sha256": side["plan_sha256"], "run_sha256": side["run_sha256"],
                  "source_revision": plan["identities"]["candidate"]["source_revision"],
                  "producer_sha256": run["cli_source_sha256"]}
        require(manifest["sides"][side["role"]] == expect, "project manifest plan/report/producer identity differs")
        planned.append({c["case_id"]: c for c in plan["sets"]["development"]["cases"]})
    require(planned[0] == planned[1], "project comparison plans differ")

    rows = manifest["cases"]
    require(isinstance(rows, list) and 0 < len(rows) <= max_cases, "invalid project development case inventory")
    records = {}
    for row in rows:
        exact(row, CASE_KEYS, "invalid project case fields")
        cid = row["case_id"]
        require(isinstance(cid, str) and cid in planned[0] and cid not in records,
                "unknown or duplicate project development case")
        case = planned[0][cid]
        label = "benign" if case["injection_task_id"] is None else "attack"
        require(row["expected_label"] == label and all(row[k] == case[k] for k in
                ("user_task_id", "injection_task_id", "injections_sha256")),
                f"{cid}: case identities, injection hash or expected label differ")
        family = row["semantic_family"]
        require(isinstance(family, str) and 0 < len(family) <= 128 and family == family.strip()
                and all(32 <= ord(c) != 127 for c in family), f"{cid}: invalid semantic family")
        roles = {"user_task", "environment"} | ({"injection_task"} if label == "attack" else set())
        exact(row["sources"], roles, f"{cid}: project source roles differ")
        for ref in row["sources"].values():
            exact(ref, {"path", "sha256"}, f"{cid}: invalid project source reference")
            path = ref["path"]
            require(isinstance(path, str) and path in bundle["files"]
                    and protocol.digest(bundle["files"][path].encode("utf-8")) == ref["sha256"],
                    f"{cid}: project source path or digest differs")
        identity = {"upstream": manifest["upstream"], "attack": sides[0]["plan"]["attack"],
                    "case": case, "expected_label": label, "sources": row["sources"]}
        records[cid] = {"case_input_sha256": protocol.digest(protocol.canonical(identity)),
                        "expected_label": label, "semantic_family": family}
    require(set(records) == set(planned[0]), "project manifest omits a development case")
    return records, {"manifest_sha256": pinned_sha256, "provenance": provenance}
