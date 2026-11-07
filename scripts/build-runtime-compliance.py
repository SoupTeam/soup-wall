#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Copy actual selected notices/source to a fresh private compliance directory.

No installation, network access, legal decision or native qualification occurs.
The emitted proposal intentionally contains UNREVIEWED dispositions.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_inventory as inventory
import runtime_reviews as reviews

ROOT = inventory.ROOT
ASSETS = ROOT / "profiles/mcp/runtime-compliance-v1"
MAX_FILES = 10000
MAX_BYTES = 128 * 1024 * 1024


def require(value, reason):
    if not value:
        raise ValueError("runtime_compliance:" + reason)


class Bundle:
    def __init__(self, output):
        self.output = output
        self.files = {}
        self.total = 0

    def copy(self, source, relative, expected):
        require(relative not in self.files, "duplicate_destination")
        require(reviews.file_sha(source) == expected, "source_changed")
        target = self.output / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with Path(source).open("rb") as src, target.open("xb") as dst:
            shutil.copyfileobj(src, dst, length=65536)
        os.chmod(target, 0o600)
        require(reviews.file_sha(target) == expected, "copy_changed")
        self.files[relative] = expected
        self.total += target.stat().st_size
        require(len(self.files) <= MAX_FILES and self.total <= MAX_BYTES, "bundle_limit")
        return relative

    def source_tree(self, directory, site):
        require(directory.is_dir() and not directory.is_symlink() and
                directory.resolve().is_relative_to(site.resolve()), "source_directory")
        copies, installed = {}, {}
        for current, children, names in os.walk(directory, followlinks=False):
            current = Path(current)
            require(len(current.relative_to(directory).parts) <= 32, "source_depth")
            for name in children:
                require(not (current / name).is_symlink(), "source_symlink")
            for name in sorted(names):
                source = current / name
                require(not source.is_symlink() and source.is_file(), "source_file")
                if name.endswith((".pyc", ".pyo")):
                    continue
                relative = "python-source/" + source.relative_to(site).as_posix()
                digest = reviews.file_sha(source)
                if relative not in self.files:
                    self.copy(source, relative, digest)
                copies[relative] = digest
                installed[str(source)] = digest
        require(copies, "source_empty")
        return copies, installed


def build(report, generation, output):
    require(not output.exists() and output.parent.is_dir() and
            not output.parent.is_symlink(), "fresh_output_required")
    output.mkdir(mode=0o700)
    bundle = Bundle(output)
    asset_files = {}
    for name in ("LGPL-3.0.txt", "GPL-3.0.txt", "MPL-2.0.txt", "SOURCE-AND-RIGHTS.txt", "provenance.json"):
        source = ASSETS / name
        asset_files[bundle.copy(source, "licenses/" + name, reviews.file_sha(source))] = reviews.file_sha(source)
    provenance = inventory.read_json(ASSETS / "provenance.json")
    for name, source in provenance["sources"].items():
        require(reviews.file_sha(ASSETS / name) == source["sha256"], "license_asset_changed")
    all_notice_copies = {}
    per_notice = {}
    for index, notice in enumerate(report["notices"]):
        files = {}
        for ordinal, (source, digest) in enumerate(sorted(notice["files"].items())):
            relative = "notices/%03d/%03d-%s" % (index, ordinal, Path(source).name)
            bundle.copy(source, relative, digest)
            files[relative] = digest
            all_notice_copies[relative] = digest
        per_notice[index] = files
    profile = inventory.read_json(generation / "git-profile/profile.json")
    site = Path(profile["packageRoot"]) / "python/lib/python3.11/site-packages"
    requirements, licenses = [], []
    common = {name: value for name, value in asset_files.items()}
    for index, notice in enumerate(report["notices"]):
        if not notice.get("policy_disposition_required"):
            continue
        expression = notice.get("effective_license")
        require(expression in reviews.CONDITIONS, "unsupported_license_needs_independent_review")
        ids = []
        copies, installed = {}, {}
        documentation = {}
        if expression == "SEE LICENSE IN LICENSE":
            require(notice["name"] == "@modelcontextprotocol/server-filesystem",
                    "unreviewed_documentation_layout")
            fs = inventory.read_json(generation / "filesystem-profile/profile.json")
            original = Path(fs["packageRoot"]) / notice["origin"]["path"] / "README.md"
            relative = bundle.copy(original, "documentation/filesystem-server-README.md",
                                   reviews.file_sha(original))
            documentation[relative] = reviews.file_sha(original)
        if expression in {"MPL-2.0", "LGPL-3.0-or-later"}:
            origin = notice["origin"]
            if notice["name"] == "certifi" and origin["owner"] is None:
                copies, installed = bundle.source_tree(site / "certifi", site)
            elif notice["name"] == "certifi" and origin["owner"] == "pip":
                copies, installed = bundle.source_tree(site / "pip/_vendor/certifi", site)
            elif notice["name"] == "autocommand" and origin["owner"] == "setuptools":
                # Preserve the containing Python application and its vendor
                # modules so a compatible edited library can be recombined.
                copies, installed = bundle.source_tree(site / "setuptools", site)
                for directory in sorted(site.glob("setuptools-*.dist-info")):
                    extra, actual = bundle.source_tree(directory, site)
                    copies.update(extra); installed.update(actual)
                hack = site / "_distutils_hack"
                if hack.exists():
                    extra, actual = bundle.source_tree(hack, site)
                    copies.update(extra); installed.update(actual)
            else:
                raise ValueError("runtime_compliance:unreviewed_source_layout")
        for kind in sorted(reviews.CONDITIONS[expression]):
            key = "%03d-%s" % (index, kind)
            ids.append(key)
            files = (per_notice[index] | common) if kind == "notice" else common.copy()
            if kind == "source":
                files.update(copies)
            if kind == "documentation_attribution":
                files.update(documentation)
            requirements.append({"id": key, "kind": kind, "files": files,
                "installed_files": installed if kind == "source" else {},
                "explanation": "Review the exact retained material and instructions before accepting this condition.",
                "sources": ["https://blueoakcouncil.org/license/1.0.0"] if expression == "BlueOak-1.0.0"
                    else ["https://www.mozilla.org/en-US/MPL/2.0/"] if expression == "MPL-2.0"
                    else ["https://www.gnu.org/licenses/lgpl-3.0.html"] if expression == "LGPL-3.0-or-later"
                    else ["https://docs.python.org/3/license.html"] if expression == "PSF-2.0"
                    else ["https://github.com/modelcontextprotocol/servers/blob/a40bc270fb5ece62673f8a1196f57116d885c5eb/LICENSE"]})
        licenses.append({"component": reviews.component(notice), "material_sha256": reviews.digest(notice),
            "expression": expression, "disposition": "UNREVIEWED", "requirements": ids, "rationale": ""})
    proposal = {"format": reviews.FORMAT, "binding": reviews.context(report),
        "decision": {"authority": "UNREVIEWED", "recorded_by": "", "method": "", "checked_at": "", "rationale": ""},
        "scope": {"platform": "linux-x86_64",
            "profiles": ["filesystem-readonly-v1", "git-readonly-v1"], "distribution": "private-handoff",
            "constraints": ["Supply this complete compliance bundle.",
                "Native license/security and source qualification remain separate gates."]},
        "requirements": requirements, "licenses": licenses, "advisories": []}
    receipt = {"format": "sw-runtime-compliance-files/1", "source": report["source"],
        "selection_sha256": report["selection_sha256"], "files": bundle.files,
        "bytes": bundle.total, "scope": "Package notices and identified Python source; no native clearance asserted."}
    for name, data in (("runtime-reviews-proposal.json", proposal), ("compliance-files.json", receipt)):
        with (output / name).open("x", encoding="utf-8") as stream:
            os.chmod(output / name, 0o600)
            json.dump(data, stream, indent=2)
            stream.write("\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    require(args.selection.name == "selection.json", "selection_required")
    spec = importlib.util.spec_from_file_location("compliance_preparation", ROOT / "scripts/prepare-installed-pilot.py")
    prep = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prep)
    prep.verify_generation(args.selection.parent, args.expected_commit, probe_native=False)
    report = inventory.read_json(args.inventory)
    selection = inventory.read_json(args.selection)
    require(report["source"] == selection["source"] and
            report["source"]["commit"] == args.expected_commit and report["source"]["dirty"] is False and
            report["selection_sha256"] == inventory.sha(args.selection), "source_or_selection_mismatch")
    notices, _, _ = inventory.installed_graphs(args.selection.parent, inventory.lock_graphs())
    require(notices == report["notices"], "observed_material_changed")
    require(report["lock_sha256"] == {path: inventory.sha(path) for path in inventory.lock_graphs()},
            "lock_changed")
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(not output.is_relative_to(args.selection.parent.resolve()) and
            not output.is_relative_to(ROOT.resolve()), "output_must_be_external")
    result = build(report, args.selection.parent, output)
    prep.verify_generation(args.selection.parent, args.expected_commit, probe_native=False)
    print(json.dumps({"status": "material_copied_decisions_unreviewed", "files": len(result["files"]),
                      "bytes": result["bytes"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
