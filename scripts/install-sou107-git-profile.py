#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicitly install the original Git server with the local-clone profile.

Downloads use the existing accepted installer and pins. No repository mutation,
network tool capability, implicit activation or v1 installation replacement.
"""
import argparse
import importlib.util
import json
import os
import platform
from pathlib import Path
import shutil
import struct

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-mcp/git-local-clone-readonly/1"
spec = importlib.util.spec_from_file_location("git_v1_installer", ROOT / "scripts/install-sou68-git-profile.py")
V1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V1)
sha, write = V1.sha, V1.private_json


def replace_owned_json(path, value):
    """Replace only a file in the fresh installation created by this invocation."""
    temporary = path.with_name(path.name + ".sou107-new")
    write(temporary, value)
    os.replace(temporary, path)


def identity():
    data = json.loads((ROOT / "profiles/mcp/git-local-clone-readonly-v1/identity.json").read_text())
    if data["format"] != FORMAT:
        raise ValueError("local clone profile identity mismatch")
    for relative, digest in data["files"].items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or sha(path) != digest:
            raise ValueError("accepted local clone dependency mismatch")
    return data


def registry(manifest):
    value = V1.registry(manifest)
    value["registry_id"] = "git-local-clone-readonly-v1"
    for tool in value["tools"]:
        if "mcp_result_profile" in tool:
            tool["mcp_result_profile"] = FORMAT
    return value


def require_static_git(path):
    # Landlock must not grant EXECUTE to the ELF loader: executing a loader
    # directly could load an otherwise forbidden helper image as ordinary data.
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
            raise ValueError("local clone Git requires a static Linux x86-64 ELF")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if not 64 <= offset <= 4096 or size != 56 or not 1 <= count <= 64:
            raise ValueError("local clone Git ELF program headers unsupported")
        stream.seek(offset)
        table = stream.read(size * count)
        if len(table) != size * count:
            raise ValueError("local clone Git ELF program headers truncated")
        types = [struct.unpack_from("<I", table, n * size)[0] for n in range(count)]
        if 3 in types or 1 not in types:
            raise ValueError("local clone Git must have no ELF interpreter; build pinned Git with LDFLAGS=-static")


def install(destination, workspace, git, git_sha256, bwrap, git_launcher):
    selected = identity()
    require_static_git(git)
    V1.install(destination, workspace, git, git_sha256, bwrap, git_launcher, static_git=True)
    destination = Path(destination).absolute()
    profile = json.loads((destination / "profile.json").read_text())
    profile["format"] = FORMAT
    replace_owned_json(destination / "profile.json", profile)
    manifest = json.loads((V1.ASSETS / "upstream-tools-list.json").read_text())
    replace_owned_json(destination / "registry.json", registry(manifest))
    shutil.copyfile(ROOT / "profiles/pilot/linux-readonly-v1/policy.yaml", destination / "policy.yaml")
    os.chmod(destination / "policy.yaml", 0o600)
    receipt = json.loads((destination / "installation.json").read_text())
    receipt.update(format="sou107-profile-installation/1", profile=profile,
                   selection_identity=selected, profile_sha256=sha(destination / "profile.json"),
                   registry_sha256=sha(destination / "registry.json"), policy_sha256=sha(destination / "policy.yaml"))
    replace_owned_json(destination / "installation.json", receipt)
    return {"status": "prepared-not-active", "profile": str(destination / "profile.json"), "format": FORMAT}


def prepare(installation, destination, port, python=None):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("local clone profile requires Linux x86-64")
    selected = identity()
    installation, destination = Path(installation).resolve(strict=True), Path(destination).absolute()
    if destination.exists() or destination.is_symlink() or type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("new selection destination and bounded port required")
    receipt = json.loads((installation / "installation.json").read_text())
    profile = json.loads((installation / "profile.json").read_text())
    manifest = json.loads((V1.ASSETS / "upstream-tools-list.json").read_text())
    if receipt.get("format") != "sou107-profile-installation/1" or receipt.get("selection_identity") != selected:
        raise ValueError("local clone installation identity mismatch")
    if profile != receipt["profile"] or profile["format"] != FORMAT:
        raise ValueError("local clone runtime profile mismatch")
    for filename, key in (("profile.json", "profile_sha256"), ("registry.json", "registry_sha256"), ("policy.yaml", "policy_sha256")):
        if sha(installation / filename) != receipt[key]:
            raise ValueError("local clone installed bytes changed")
    if json.loads((installation / "registry.json").read_text()) != registry(manifest):
        raise ValueError("local clone registry authority mismatch")
    policy = ROOT / "profiles/pilot/linux-readonly-v1/policy.yaml"
    if sha(installation / "policy.yaml") != sha(policy):
        raise ValueError("local clone pilot policy changed")
    workspace = Path(profile["workspace"])
    if not workspace.is_dir() or workspace.is_symlink() or workspace == Path("/"):
        raise ValueError("local clone workspace unavailable")
    destination.mkdir(mode=0o700)
    shutil.copyfile(policy, destination / "policy.yaml")
    os.chmod(destination / "policy.yaml", 0o600)
    classifier = ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"
    config = {"port": port, "enforce": True, "max_record_bytes": 1048576,
              "policy": str(destination / "policy.yaml"), "native": {
                  "registry_path": str(installation / "registry.json"), "registry_sha256": sha(installation / "registry.json")}}
    import sys
    selection = {"status": "prepared-not-active", "format": FORMAT, "workspace": str(workspace),
                 "profile_sha256": sha(installation / "profile.json"), "registry_sha256": sha(installation / "registry.json"),
                 "policy_sha256": sha(policy), "classifier_sha256": sha(classifier), "environment": {
                     "AGENTFW_MCP_SERVER_PROFILE": str(installation / "profile.json"),
                     "AGENTFW_CLASSIFIER_PYTHON": str(Path(python or sys.executable).resolve(strict=True)),
                     "AGENTFW_CLASSIFIER": "rule-baseline",
                     "AGENTFW_RULE_BASELINE": str(classifier),
                     "AGENTFW_WORKSPACE": str(workspace)}}
    write(destination / "config.json", config)
    write(destination / "selection.json", selection)
    return config, selection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("destination", "workspace", "git", "bwrap", "git-launcher", "selection"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "format": FORMAT})); return 0
    install(args.destination, args.workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher)
    _, receipt = prepare(args.destination, args.selection, args.port)
    print(json.dumps(receipt)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
