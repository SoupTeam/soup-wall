#!/usr/bin/env python3
"""Prepare, never apply, a reviewable additive SOU-91 main ruleset update."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path


CONTEXT = "SOU-91 candidate admission"
RULESET_ID = 24846282
EXISTING = {"Documentation links", "test", "all-features", "agent-windows-security"}


def prepare(current: dict) -> dict:
    if current.get("name") != "main" or current.get("target") != "branch" or \
            current.get("enforcement") != "active":
        raise ValueError("unexpected main ruleset identity or enforcement")
    if current.get("conditions", {}).get("ref_name", {}).get("include") != ["refs/heads/main"]:
        raise ValueError("unexpected protected ref")
    rules = current.get("rules", [])
    status_rules = [rule for rule in rules if rule.get("type") == "required_status_checks"]
    scanning_rules = [rule for rule in rules if rule.get("type") == "code_scanning"]
    review_rules = [rule for rule in rules if rule.get("type") == "pull_request"]
    if len(status_rules) != 1 or len(scanning_rules) != 1 or len(review_rules) != 1:
        raise ValueError("required status, review or CodeQL rule missing")
    status = status_rules[0]["parameters"]
    existing = status["required_status_checks"]
    if not status.get("strict_required_status_checks_policy") or \
            not EXISTING <= {entry["context"] for entry in existing}:
        raise ValueError("existing strict checks would be weakened")
    integrations = {entry.get("integration_id") for entry in existing if entry["context"] in EXISTING}
    if len(integrations) != 1 or None in integrations:
        raise ValueError("existing check integration identity is inconsistent")
    tools = scanning_rules[0]["parameters"].get("code_scanning_tools", [])
    if not any(tool.get("tool") == "CodeQL" and
               tool.get("alerts_threshold") == "errors" and
               tool.get("security_alerts_threshold") == "high_or_higher" for tool in tools):
        raise ValueError("CodeQL severity thresholds differ from reviewed baseline")
    if review_rules[0]["parameters"].get("required_approving_review_count", 0) < 1:
        raise ValueError("review requirement is absent")
    new_check = {"context": CONTEXT, "integration_id": integrations.pop()}
    if not any(entry["context"] == CONTEXT for entry in existing):
        existing.append(new_check)
    elif new_check not in existing:
        raise ValueError("aggregate check uses an unexpected integration identity")
    # REST update accepts these writable fields. Unknown rules are preserved.
    return {key: current[key] for key in
            ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
            if key in current}


def admission_is_required(current: dict) -> bool:
    """Confirm the live ruleset enforces the new status without weakening old gates."""
    if current.get("id") != RULESET_ID or current.get("source_type") != "Repository" or \
            current.get("source") != "SoupTeam/soup-wall":
        return False
    try:
        # prepare validates the old status, review and CodeQL rules, and
        # rejects a mismatched integration. Work on a copy: prepare is additive.
        prepare(deepcopy(current))
    except (KeyError, TypeError, ValueError):
        return False
    status = next(rule["parameters"] for rule in current["rules"]
                  if rule.get("type") == "required_status_checks")
    checks = status["required_status_checks"]
    existing_ids = {entry["integration_id"] for entry in checks
                    if entry["context"] in EXISTING}
    return len(existing_ids) == 1 and sum(
        entry.get("context") == CONTEXT and entry.get("integration_id") in existing_ids
        for entry in checks) == 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    payload = prepare(json.loads(args.current.read_text(encoding="utf-8")))
    if args.output.exists():
        parser.error("output must be a new file")
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
