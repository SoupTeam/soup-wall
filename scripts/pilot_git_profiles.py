# SPDX-License-Identifier: Apache-2.0
"""Finite selections of reviewed original Git contracts; never a capability union.

The declaration selects existing installers and validators. Repository text and
installed profile bytes cannot choose or broaden a declaration.
"""
from __future__ import annotations

import hashlib
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = "git-readonly-v1"
ASSETS = "profiles/mcp/git-readonly-v1"
SELECTION_V2 = "sw-installed-pilot-selection/2"
SELECTION_V3 = "sw-installed-pilot-selection/3"
PROFILES = {
    DEFAULT: ("sw-mcp/git-readonly/1", None, None),
    "git-readonly-file-revisions-v1": ("sw-mcp/git-readonly-file-revisions/1", "file_revisions", None),
    "git-readonly-local-refs-v1": ("sw-mcp/git-readonly-local-refs/1", "local_references", None),
    "git-readonly-shallow-v1": ("sw-mcp/git-readonly-shallow/1", "shallow_repository", None),
    "git-local-clone-readonly-v1": ("sw-mcp/git-local-clone-readonly/1", None,
                                     "profiles/mcp/git-local-clone-readonly-v1/identity.json"),
    "git-tracked-symlinks-readonly-v1": ("sw-mcp/git-tracked-symlinks-readonly/1", None,
                                          "profiles/mcp/git-tracked-symlinks-readonly-v1/identity.json"),
}
DAEMON_EXECUTION = frozenset({"git-readonly-file-revisions-v1", "git-tracked-symlinks-readonly-v1"})
FAILURES = frozenset({"git_profile_unsupported_select_one_reviewed_variant", "git_profile_binding_changed",
                      "legacy_selection_git_profile_extension_refused", "git_profile_binding_required",
                      "git_profile_selection_differs_use_rebuild", "selected_git_classifier_changed",
                      "profile_selection_identity_changed", "profile_upstream_identity_changed"})


class SingleProfile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, "_git_profile_seen", False):
            parser.error("--git-profile accepts exactly one reviewed variant; repeated/combined selection refused")
        setattr(namespace, "_git_profile_seen", True)
        setattr(namespace, self.dest, values)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selected(name=DEFAULT):
    require(isinstance(name, str) and name in PROFILES,
            "git_profile_unsupported_select_one_reviewed_variant")
    return PROFILES[name]


def load(filename):
    spec = importlib.util.spec_from_file_location("selected_git_installer", ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy_path(name):
    return ROOT / ("profiles/pilot/linux-readonly-v1/policy.yaml" if selected(name)[2]
                   else ASSETS + "/policy.yaml")


def classifier_path(name):
    selected(name)
    variant = {"git-readonly-file-revisions-v1": "git_readonly_file_revisions_v1",
               "git-readonly-local-refs-v1": "git_readonly_local_refs_v1"}.get(name, "git_readonly_v1")
    return ROOT / "rule_baseline" / variant / "rule_baseline.py"


def registry(name):
    _, flag, identity = selected(name)
    module = load("install-sou150-git-profile.py" if name == "git-tracked-symlinks-readonly-v1"
                  else "install-sou107-git-profile.py" if identity else "install-sou68-git-profile.py")
    manifest = json.loads((ROOT / ASSETS / "upstream-tools-list.json").read_bytes())
    return module.registry(manifest, **({flag: True} if flag else {}))


def binding(name=DEFAULT):
    format_, _, identity = selected(name)
    files = ["scripts/pilot_git_profiles.py", "scripts/install-sou62-filesystem-profile.py",
             "scripts/install-sou68-git-profile.py", str(classifier_path(name).relative_to(ROOT)),
             ASSETS + "/upstream-tools-list.json", ASSETS + "/upstream-identity.json",
             ASSETS + "/requirements.lock", str(policy_path(name).relative_to(ROOT))]
    if identity:
        module = load("install-sou150-git-profile.py" if name == "git-tracked-symlinks-readonly-v1"
                      else "install-sou107-git-profile.py")
        module.identity()  # Accepted dependency pins remain authoritative.
        files.extend([identity, "scripts/install-sou107-git-profile.py"])
        if name == "git-tracked-symlinks-readonly-v1":
            files.append("scripts/install-sou150-git-profile.py")
    value = registry(name)
    return {"format": "sw-pilot-git-selection/1", "id": name, "profile_format": format_,
            "execution": "daemon-owned-original" if name in DAEMON_EXECUTION else "original-collector",
            "registry_id": value["registry_id"],
            "registry_sha256": hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "policy_sha256": sha(policy_path(name)), "classifier_sha256": sha(classifier_path(name)),
            "files": {path: sha(ROOT / path) for path in sorted(set(files))}}


def from_selection(selection):
    if selection.get("format") == SELECTION_V2:
        require("git_selection" not in selection, "legacy_selection_git_profile_extension_refused")
        return DEFAULT
    require(selection.get("format") == SELECTION_V3, "selection_version")
    value = selection.get("git_selection")
    require(isinstance(value, dict), "git_profile_binding_required")
    name = value.get("id")
    require(value == binding(name), "git_profile_binding_changed")
    return name


def install(name, destination, workspace, git, git_sha256, bwrap, launcher, **inputs):
    _, flag, identity = selected(name)
    if identity:
        module = load("install-sou150-git-profile.py" if name == "git-tracked-symlinks-readonly-v1"
                      else "install-sou107-git-profile.py")
        return module.install(destination, workspace, git, git_sha256, bwrap, launcher, **inputs)
    return load("install-sou68-git-profile.py").install(
        destination, workspace, git, git_sha256, bwrap, launcher,
        **inputs, **({flag: True} if flag else {}))


def verify_receipt(name, receipt):
    _, _, identity = selected(name)
    require(receipt.get("upstream_identity") == json.loads((ROOT / ASSETS / "upstream-identity.json").read_bytes()),
            "profile_upstream_identity_changed")
    expected = "sou150-profile-installation/1" if name == "git-tracked-symlinks-readonly-v1" else (
        "sou107-profile-installation/1" if identity else "sou68-profile-installation/1")
    require(receipt.get("format") == expected, "profile_receipt_mismatch")
    if identity:
        require(receipt.get("selection_identity") == json.loads((ROOT / identity).read_bytes()),
                "profile_selection_identity_changed")
