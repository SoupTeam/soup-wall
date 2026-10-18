#!/usr/bin/env python3
"""Fail-closed activation readback for selective SOU-91 PR scheduling.

Only repository maintainers can set the variable and install the required
ruleset context. A missing setting, missing read permission or API outage keeps
the full suite. The privileged admission process repeats this check from base.
"""

from __future__ import annotations

import json
import os
from typing import Callable
from urllib.request import Request, urlopen

from sou91_ruleset_patch import RULESET_ID, admission_is_required


ACTIVATION_VALUE = "enabled-after-negative-controls"
REPOSITORY = "SoupTeam/soup-wall"


def selective_enabled(setting: str | None, read_ruleset: Callable[[], dict]) -> bool:
    if setting != ACTIVATION_VALUE:
        return False
    try:
        return admission_is_required(read_ruleset())
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        return False


def read_live_ruleset() -> dict:
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or not os.environ.get("GITHUB_TOKEN"):
        raise RuntimeError("repository identity or read token unavailable")
    request = Request(
        f"https://api.github.com/repos/{REPOSITORY}/rulesets/{RULESET_ID}",
        headers={
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sou91-ci-impact",
        },
    )
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def live_selective_enabled() -> bool:
    return selective_enabled(os.environ.get("SOU91_SELECTIVE_CI"), read_live_ruleset)
