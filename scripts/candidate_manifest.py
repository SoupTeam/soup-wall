# SPDX-License-Identifier: Apache-2.0
"""Record candidate bytes and redistributed npm license metadata, without publication."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def npm_notices(root):
    profile = root / "profiles/mcp/filesystem-readonly-v1"
    lock = json.loads((profile / "package-lock.json").read_text())
    records = []
    for relative, item in sorted(lock["packages"].items()):
        if not relative:
            continue
        path = profile / relative
        metadata = json.loads((path / "package.json").read_text())
        if metadata["version"] != item["version"]:
            raise ValueError("installed_npm_version_mismatch")
        target = root / "upstream-notices/npm" / relative
        target.mkdir(parents=True)
        files = [path / "package.json", *[p for p in path.iterdir() if p.is_file()
                 and p.name.lower().startswith(("license", "licence", "copying", "notice", "copyright"))]]
        for file in files:
            shutil.copyfile(file, target / file.name)
        records.append({"ecosystem": "npm", "name": metadata["name"], "version": item["version"],
                        "integrity": item["integrity"], "license": metadata.get("license"),
                        "lock_path": relative,
                        "notices": {p.relative_to(root).as_posix(): sha(p) for p in target.iterdir()}})
    (root / "npm-inventory.json").write_text(json.dumps({"format": "sw-candidate-npm-inventory/1",
        "lock_sha256": sha(profile / "package-lock.json"), "packages": records}, indent=2) + "\n")


def finalize(root):
    def git(*args):
        return subprocess.check_output(["git", *args], text=True, timeout=15).strip()
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("candidate_symlink_refused")
        if path.is_file() and path.name != "manifest.json":
            files[path.relative_to(root).as_posix()] = sha(path)
    manifest = {"schema_version": 2, "identities": {
        "compiler": subprocess.check_output(["rustc", "--version"], text=True, timeout=15).strip(),
        "compiler_verbose": subprocess.check_output(["rustc", "-vV"], text=True, timeout=15).strip(),
        "source_commit": git("rev-parse", "HEAD"), "source_tree": git("rev-parse", "HEAD^{tree}"),
        "cargo_lock_sha256": sha(root / "Cargo.lock"),
        "target": "x86_64-unknown-linux-gnu", "python_requirement": ">=3.11, standard library only",
        "sandbox_version": "0.13.1", "sandbox_sha256": sha(root / "bin/bwrap")}, "files": files}
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--finalize", action="store_true")
    args = parser.parse_args()
    (finalize if args.finalize else npm_notices)(args.root)
