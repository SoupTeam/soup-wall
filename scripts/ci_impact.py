#!/usr/bin/env python3
"""Deterministic, fail-broad CI selection for a candidate's changed paths.

The gate runs this file from the trusted base branch. PR jobs may run their copy
for scheduling, but a changed copy cannot relax the trusted gate's selection.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from ci_activation import live_selective_enabled


CI_JOBS = (
    "documentation", "test", "python-classifier", "native-macos-resilience",
    "agent-lifecycle-macos", "all-features", "agent-windows-security",
    "saml-release-targets", "redis-integration", "postgres-integration",
    "docker-build",
)

# This is the reviewed registration surface. A new workflow must be registered
# here and in the gate's expected job-name table before selective CI can use it.
WORKFLOW_JOBS: dict[str, tuple[str, ...]] = {
    "agent-doctor.yml": ("agent-doctor-linux",),
    "agent-fleet.yml": ("fleet",),
    "agent-windows-self-test.yml": ("standard-user-self-test",),
    "benchmark.yml": ("agent-scorecard",),
    "ci.yml": CI_JOBS,
    "console-recovery.yml": ("owned-recovery",),
    "gate-ci.yml": ("validate-gate-matrix",),
    "gateway-sdk.yml": ("official-sdk",),
    "identity-sandbox.yml": ("vendor-driver-safety", "local-idp-evidence"),
    "keycloak-oidc.yml": ("linux-vendor",),
    "keycloak-saml.yml": ("linux-vendor",),
    "license-policy.yml": ("rust-license-policy",),
    "managed-credential-rotation.yml": ("formatting-preview", "managed-credential-rotation"),
    "managed-group-rollout.yml": ("group-rollout",),
    "managed-policy-demo.yml": ("managed-rollout-e2e",),
    "managed-policy-postgres.yml": ("managed-postgres",),
    "managed-policy-tls.yml": ("agent-https-rollout",),
    "mcp-create-file.yml": ("linux-create-file",),
    "mcp-https-get.yml": ("linux-https-get",),
    "mcp-https-post.yml": ("linux-https-post",),
    "mcp-profile-author.yml": ("author-cli",),
    "mcp-profile-lifecycle.yml": ("linux-foundation",),
    "mcp-real-filesystem.yml": ("required-linux-sandbox-and-real-host",),
    "mcp-real-git.yml": ("required-linux-git",),
    "mcp-windows-connection.yml": ("standard-user-acceptance",),
    "mcp-windows-create.yml": ("native-windows-standard-user", "linux-read-create-https-regressions"),
    "mcp-windows-read.yml": ("native-windows-standard-user",),
    "monitoring.yml": ("linux-alert-recovery",),
    "native-mcp-stderr.yml": ("required-linux-native-stderr", "native-platform-launch"),
    "provenance-memory.yml": ("required-linux-native-mcp-budget",),
    "scim-directory.yml": ("interoperability",),
    "sou79-resource-budgets.yml": ("required-disposable-delegated-linux",),
    "sou86-crash-supervision.yml": ("required-disposable-linux-crash-supervision",),
    "supply-chain.yml": ("cargo-audit", "sbom"),
    "test-environment.yml": ("windows-launcher", "fixture-baseline"),
    "tls-lifecycle.yml": ("linux",),
}

AGENT_WORKFLOWS = frozenset({
    "agent-doctor.yml", "agent-windows-self-test.yml", "console-recovery.yml",
    "managed-credential-rotation.yml", "managed-group-rollout.yml",
    "managed-policy-demo.yml", "managed-policy-postgres.yml",
    "managed-policy-tls.yml", "mcp-create-file.yml", "mcp-https-get.yml", "mcp-https-post.yml",
    "mcp-profile-author.yml", "mcp-profile-lifecycle.yml",
    "mcp-real-filesystem.yml", "mcp-real-git.yml", "mcp-windows-connection.yml",
    "mcp-windows-create.yml", "mcp-windows-read.yml", "native-mcp-stderr.yml",
    "provenance-memory.yml", "sou79-resource-budgets.yml",
    "sou86-crash-supervision.yml", "tls-lifecycle.yml",
})
GATEWAY_WORKFLOWS = frozenset({
    "gateway-sdk.yml",
    "agent-fleet.yml", "console-recovery.yml", "identity-sandbox.yml",
    "keycloak-oidc.yml", "keycloak-saml.yml", "managed-credential-rotation.yml",
    "managed-group-rollout.yml", "managed-policy-demo.yml",
    "managed-policy-postgres.yml", "managed-policy-tls.yml",
    "scim-directory.yml", "tls-lifecycle.yml",
})
RUNTIME_SHARED = frozenset({
    "benchmark.yml", "license-policy.yml", "monitoring.yml",
    "supply-chain.yml", "test-environment.yml",
})

AGENT_CI = frozenset({
    "documentation", "test", "python-classifier", "native-macos-resilience",
    "agent-lifecycle-macos", "all-features", "agent-windows-security",
})
GATEWAY_CI = frozenset({
    "documentation", "test", "python-classifier", "all-features",
    "saml-release-targets", "redis-integration", "postgres-integration",
    "docker-build",
})
PYTHON_CI = frozenset({"documentation", "python-classifier"})


def classify(path: str) -> str:
    """Unknown or CI-sensitive paths deliberately select full qualification."""
    if not path or path.startswith("/") or "\\" in path or ".." in path.split("/"):
        return "full"
    if path.startswith(".github/") or path.startswith("scripts/ci_"):
        return "full"
    if path in {"Cargo.lock", "Cargo.toml", "rust-toolchain", "rust-toolchain.toml", "LICENSE", "SECURITY.md"}:
        return "full"
    if path.startswith(("crates/core/", "crates/adapter/")):
        return "full"
    if path.startswith(("docs/operations/", "docs/benchmarks/")):
        return "full"
    if path.startswith(("crates/agent/", "crates/agentfw/", "rule_baseline/", "profiles/mcp/")):
        return "agent"
    if path.startswith(("crates/proxy/", "deploy/")):
        return "gateway"
    if path.startswith(("eval/", "experiments/")):
        return "python"
    if path.startswith("docs/") and path.endswith(".md"):
        return "docs"
    if path in {"README.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"}:
        return "docs"
    return "full"


def plan(paths: list[str], *, force_full: bool = False) -> dict[str, object]:
    categories = {classify(path) for path in paths}
    if force_full or not paths or "full" in categories:
        selected = {name: list(jobs) for name, jobs in WORKFLOW_JOBS.items()}
        mode = "full"
    else:
        selected: dict[str, list[str]] = {name: [] for name in WORKFLOW_JOBS}
        ci_jobs = {"documentation"}
        active: set[str] = set()
        if "agent" in categories:
            ci_jobs.update(AGENT_CI)
            active.update(AGENT_WORKFLOWS | RUNTIME_SHARED)
        if "gateway" in categories:
            ci_jobs.update(GATEWAY_CI)
            active.update(GATEWAY_WORKFLOWS | RUNTIME_SHARED)
        if "python" in categories:
            ci_jobs.update(PYTHON_CI)
            active.add("benchmark.yml")
        selected["ci.yml"] = [job for job in CI_JOBS if job in ci_jobs]
        for name in active:
            selected[name] = list(WORKFLOW_JOBS[name])
        mode = "+".join(sorted(categories))
    return {
        "schema": "sou91-ci-plan/1",
        "mode": mode,
        "paths": sorted(set(paths)),
        "workflows": selected,
        "codeql": [
            "Analyze (actions)", "Analyze (c-cpp)",
            "Analyze (javascript-typescript)", "Analyze (python)",
            "Analyze (rust)",
        ],
    }


def scheduled_plan(paths: list[str] | None, event_name: str,
                   activation_verified: bool) -> dict[str, object]:
    """Production scheduler: full until both operator switch and ruleset pass."""
    return plan(paths or [], force_full=paths is None or event_name != "pull_request"
                or not activation_verified)


def candidate_paths() -> list[str] | None:
    """Read the exact PR merge tree, refusing a stale or non-merge checkout."""
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        return None
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    parents = subprocess.check_output(["git", "rev-list", "--parents", "-n", "1", "HEAD"], text=True).split()
    if len(parents) != 3 or parents[0] != head:
        return None
    if parents[1] != pr["base"]["sha"] or parents[2] != pr["head"]["sha"]:
        return None
    raw = subprocess.check_output(["git", "diff", "--name-only", "--no-renames", "-z", parents[1], head])
    return [entry.decode("utf-8", "surrogateescape") for entry in raw.split(b"\0") if entry]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", choices=sorted(WORKFLOW_JOBS))
    parser.add_argument("--paths-json", type=Path, help="offline planner input, never used by a production gate")
    args = parser.parse_args()
    paths = json.loads(args.paths_json.read_text(encoding="utf-8")) if args.paths_json else candidate_paths()
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request" and paths is None and not args.paths_json:
        parser.error("PR checkout is not the exact head/base merge candidate")
    if paths is not None and (not isinstance(paths, list) or any(not isinstance(path, str) for path in paths)):
        parser.error("paths must be a JSON string list")
    # Offline path inputs exercise the impact model without claiming that the
    # repository has activated it. Real PR runs require a live ruleset readback.
    result = (plan(paths) if args.paths_json else
              scheduled_plan(paths, os.environ.get("GITHUB_EVENT_NAME", ""),
                             live_selective_enabled() if paths is not None else False))
    if args.workflow:
        result = {"schema": result["schema"], "mode": result["mode"], "jobs": result["workflows"][args.workflow]}
    json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
