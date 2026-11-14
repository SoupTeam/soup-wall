# SPDX-License-Identifier: Apache-2.0
"""Optional producer binding to an upstream-owned, tracked case manifest."""
from __future__ import annotations

from pathlib import PurePosixPath
import subprocess

import agentdojo_protocol as protocol

SCHEMA = "soup-wall-paired-regression-cases/1"
MANIFEST_LIMIT = 256 * 1024
CASE_LIMIT = 512
KEYS = {"case_id", "user_task_id", "injection_task_id", "expected_label",
        "semantic_family", "user_task_file", "environment_file"}


class Invalid(ValueError):
    pass


def check(ok, message):
    if not ok:
        raise Invalid(message)


def source_path(value, inventory):
    check(type(value) is str and len(value) <= 240 and value in inventory and value.startswith("src/")
          and "\\" not in value and not {"..", "."}.intersection(PurePosixPath(value).parts),
          "manifest source path is outside the verified inventory")
    return value


def validate(raw, plan, inventory):
    check(len(raw) <= MANIFEST_LIMIT, "case manifest exceeds its byte limit")
    try:
        manifest = protocol.strict_json(raw)
    except (ValueError, RecursionError) as error:
        raise Invalid("invalid case manifest JSON") from error
    check(type(manifest) is dict and set(manifest) == {"schema", "suite", "cases"} and
          manifest["schema"] == SCHEMA and manifest["suite"] == plan["upstream"]["suite"],
          "manifest schema or suite differs from the frozen plan")
    planned = {row["case_id"]: row for entry in plan["sets"].values() for row in entry["cases"]}
    rows = manifest["cases"]
    check(type(rows) is list and 0 < len(rows) <= CASE_LIMIT, "invalid case manifest inventory")
    seen = set()
    for row in rows:
        check(type(row) is dict and set(row) == KEYS, "case manifest fields changed")
        key = row["case_id"]
        check(type(key) is str and key not in seen and key in planned, "unknown or duplicate case manifest ID")
        case = planned[key]
        label = "benign" if case["injection_task_id"] is None else "attack"
        check(row["user_task_id"] == case["user_task_id"] and row["injection_task_id"] == case["injection_task_id"]
              and row["expected_label"] == label, "case manifest identity or label differs from the frozen plan")
        family = row["semantic_family"]
        check(type(family) is str and 0 < len(family) <= 128 and family.strip() == family and
              all(ord(char) >= 32 and ord(char) != 127 for char in family), "case manifest lacks a semantic family")
        source_path(row["user_task_file"], inventory)
        source_path(row["environment_file"], inventory)
        seen.add(key)
    check(seen == set(planned), "case manifest does not cover the frozen inventory")
    return len(seen)


def verify(checkout, path, plan):
    result = subprocess.run(
        ["git", "-C", str(checkout), "ls-files", "src"], check=True, capture_output=True, timeout=15)
    check(len(result.stdout) <= MANIFEST_LIMIT, "source inventory byte limit")
    inventory = set(result.stdout.decode("ascii").splitlines())
    selected = checkout / source_path(path, inventory)
    with selected.open("rb") as source:
        raw = source.read(MANIFEST_LIMIT + 1)
    return {"path": path, "sha256": protocol.digest(raw), "case_count": validate(raw, plan, inventory)}
