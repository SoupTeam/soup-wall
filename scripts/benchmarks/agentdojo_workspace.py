# SPDX-License-Identifier: Apache-2.0
"""Operator-owned semantics for the pinned original AgentDojo workspace.

No model metadata is authoritative. Resource IDs below are logical benchmark
objects, never filesystem paths or executor grants.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import agentdojo_live as adapter

PROFILE = "agentdojo-workspace/1"
PROFILE_PATH = Path(__file__).resolve().parents[2] / "crates/agentfw/profiles/agentdojo-workspace-v1.json"
PROFILE_BYTES = PROFILE_PATH.read_bytes()


def snapshot():
    raw = PROFILE_BYTES
    value = json.loads(raw)
    if value["profile"] != PROFILE or value["upstream_revision"] != adapter.REVISION:
        raise adapter.AdapterError("Workspace profile identity mismatch")
    return value, adapter.digest(raw)


def declaration(row):
    return {key: copy.deepcopy(row[key]) for key in
            ("name", "schema_sha256", "action_class", "result_provenance", "egress")} | {
                "workspace_profile": PROFILE}


def validate_declaration(tool):
    profile, _ = snapshot()
    row = next((r for r in profile["tools"] if r["name"] == tool["name"]), None)
    if row is None or tool != declaration(row):
        raise adapter.AdapterError("Workspace declaration differs from reviewed profile")


def registry_bytes(functions):
    """Verify every original schema before producing an explicit opt-in registry."""
    profile, _ = snapshot()
    functions = list(functions)
    actual = {f.name: f for f in functions}
    if len(actual) != len(functions) or set(actual) != {row["name"] for row in profile["tools"]}:
        raise adapter.AdapterError("Original workspace function inventory changed")
    for row in profile["tools"]:
        schema = actual[row["name"]].parameters.model_json_schema()
        raw = json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        if adapter.digest(raw) != row["schema_sha256"] or schema != row["schema"]:
            raise adapter.AdapterError("Original workspace schema changed")
    return adapter.encoded({"contract_version": "sw-native/1", "registry_id": PROFILE,
                            "tools": [declaration(row) for row in profile["tools"]]})
