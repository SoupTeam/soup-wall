#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit SOU-98 policy selection; preparation does not claim runtime activation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "profiles/pilot/linux-readonly-v1"
KINDS = {
    "filesystem": ("filesystem-readonly-v1", "rule_baseline/rule_baseline.py"),
    "git": ("git-readonly-v1", "rule_baseline/git_readonly_v1/rule_baseline.py"),
}


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_assets():
    manifest = read(ASSETS / "manifest.json")
    if manifest["format"] != "sw-pilot-policy/1":
        raise ValueError("unsupported preset version")
    for name, expected in manifest["files"].items():
        path = (ROOT / name).resolve(strict=True)
        if not path.is_relative_to(ROOT) or sha(path) != expected:
            raise ValueError("reviewed preset dependency changed: " + name)
    return manifest


def prepare(kind, installation, destination, port, python=None):
    """Create a new dedicated config, never overwrite a home or scenario policy.

    Existing Agent startup/selected-profile validators remain authoritative for
    runtime, sandbox, registry and resource checks. This receipt is NOT active.
    """
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Linux x86-64 required; unsupported platform is not a pass")
    if kind not in KINDS or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("unsupported profile kind or port")
    manifest = verify_assets()
    installation = Path(installation).resolve(strict=True)
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("selection destination must be new")
    installed = read(installation / "installation.json")
    for name in ("profile", "registry", "policy"):
        suffix = "yaml" if name == "policy" else "json"
        if sha(installation / f"{name}.{suffix}") != installed[f"{name}_sha256"]:
            raise ValueError("installed " + name + " identity changed")
    profile = read(installation / "profile.json")
    registry = read(installation / "registry.json")
    profile_name, classifier = KINDS[kind]
    if sha(installation / "policy.yaml") != sha(ROOT / "profiles/mcp" / profile_name / "policy.yaml"):
        raise ValueError("installation scenario policy is not the accepted version")
    expected_format = f"sw-mcp/{kind}-readonly/1"
    if profile.get("format") != expected_format:
        raise ValueError("unsupported runtime profile format")
    if registry.get("registry_id") != profile_name:
        raise ValueError("registry belongs to another profile")
    # The reviewed original registry is derived from full pinned upstream schemas;
    # result provenance or action authority cannot be supplied by a caller.
    import importlib.util
    installer_path = ROOT / "scripts" / (
        "install-sou62-filesystem-profile.py" if kind == "filesystem" else "install-sou68-git-profile.py")
    spec = importlib.util.spec_from_file_location("pilot_installer", installer_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    upstream = read(ROOT / "profiles/mcp" / profile_name / "upstream-tools-list.json")
    if registry != module.registry(upstream):
        raise ValueError("registry differs from accepted tool/resource authority")
    if profile != installed["profile"]:
        raise ValueError("profile differs from installation receipt")
    workspace = Path(profile["workspace"]).resolve(strict=True)
    if not workspace.is_dir() or workspace == Path(workspace.anchor):
        raise ValueError("reviewed non-root workspace directory required")
    python = Path(python or sys.executable).resolve(strict=True)
    destination.mkdir(mode=0o700, parents=True)
    policy = destination / "policy.yaml"
    shutil.copyfile(ASSETS / "policy.yaml", policy)
    os.chmod(policy, 0o600)
    config = {
        "port": port, "enforce": True, "max_record_bytes": 1048576,
        "policy": str(policy),
        "native": {"registry_path": str(installation / "registry.json"),
                   "registry_sha256": sha(installation / "registry.json")},
    }
    environment = {
        "AGENTFW_MCP_SERVER_PROFILE": str(installation / "profile.json"),
        "AGENTFW_CLASSIFIER": "rule-baseline",
        "AGENTFW_RULE_BASELINE": str(ROOT / classifier),
        "AGENTFW_CLASSIFIER_PYTHON": str(python),
        "AGENTFW_WORKSPACE": str(workspace),
    }
    receipt = {
        "format": "sw-pilot-selection/1", "status": "prepared-not-active",
        "preset": manifest["preset"], "kind": kind,
        "policy_sha256": sha(policy), "profile_sha256": sha(installation / "profile.json"),
        "registry_sha256": config["native"]["registry_sha256"],
        "classifier_sha256": sha(ROOT / classifier),
        "python_sha256": sha(python), "manifest_sha256": sha(ASSETS / "manifest.json"),
        "environment": environment,
        "scope": "Linux x86-64; selected original stdio server; isolated collector; no real-server Ask approval",
    }
    for filename, value in (("config.json", config), ("selection.json", receipt)):
        path = destination / filename
        with path.open("x", encoding="utf-8") as stream:
            os.chmod(path, 0o600)
            json.dump(value, stream, indent=2)
            stream.write("\n")
    return config, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=KINDS)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    try:
        _, receipt = prepare(args.kind, args.installation, args.destination, args.port, args.python)
        print(json.dumps(receipt, indent=2))
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"status": "refused", "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
