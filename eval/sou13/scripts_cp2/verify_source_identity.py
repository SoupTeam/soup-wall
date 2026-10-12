#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that this checkout's SOU-13 source equals the frozen source (digests only; read-only).

  python scripts_cp2/verify_source_identity.py --freeze <private-root>/data/freeze.json \
      --dev-manifest <private-root>/handoff/dev_review_package/MANIFEST.json [--private-root <private-root>]

  1. CP1: sou13.build.source_hashes(this checkout) equals freeze.json `source_sha256_lf_normalised` exactly.
  2. CP2 dev package: raw-byte SHA-256 of the shipped tools, schemas and requirements equal MANIFEST.json.
  3. Optional: every source module and schema of this checkout is byte-identical to the same path under
     --private-root. Only source.py/schema files are hashed there; data and sealed folders are never listed.
     New public-only files (privacy gate, gold addendum and export tooling, this script) are reported as
     `repo_only`.

Only digests and paths are printed. Exit status 1 on any mismatch.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sou13.build import source_hashes  # noqa: E402

# dev review package path -> repository path
DEV_PACKAGE_FILES = {
    'tools/compute.py': 'sou13cp2/compute.py',
    'tools/hashing.py': 'sou13/hashing.py',
    'tools/semantics.py': 'sou13cp2/semantics.py',
    'schema/cp2_case.schema.json': 'schema/cp2_case.schema.json',
    'schema/case.schema.cp1-fix1.json': 'schema/case.schema.cp1-fix1.json',
    'requirements-cp2.txt': 'requirements-cp2.txt',
}
SOURCE_GLOBS = ('sou13/*.py', 'sou13cp2/*.py', 'scripts/*.py', 'scripts_cp2/*.py', 'schema/*.json',
                'requirements-cp2.txt')
PUBLIC_ONLY = frozenset({'scripts_cp2/check_release_privacy.py', 'scripts_cp2/validate_gold_addendum.py',
                         'scripts_cp2/verify_source_identity.py', 'schema/gold_addendum.schema.json',
                         'scripts_cp2/draft_gold_addendum.py', 'scripts_cp2/build_gold_dev_export.py',
                         'scripts_cp2/verify_gold_export.py', 'scripts_cp2/submission_from_review_queue.py',
                         'schema/gold_reviewer_submission.schema.json',
                         'schema/gold_owner_decisions.schema.json', 'schema/gold_export_authorization.schema.json'})


def raw_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cp1_errors(freeze_path):
    frozen = json.loads(Path(freeze_path).read_text(encoding='utf-8'))['source_sha256_lf_normalised']
    current = source_hashes(ROOT)
    e = [f'cp1: {rel} differs from the freeze' for rel in sorted(frozen) if rel in current and current[rel] != frozen[rel]]
    e += [f'cp1: {rel} missing' for rel in sorted(set(frozen) - set(current))]
    e += [f'cp1: {rel} added to a frozen source glob' for rel in sorted(set(current) - set(frozen))]
    return e, len(frozen)


def dev_package_errors(manifest_path):
    pinned = json.loads(Path(manifest_path).read_text(encoding='utf-8'))['files_sha256']
    e = []
    for package_rel, rel in DEV_PACKAGE_FILES.items():
        if package_rel not in pinned:
            e.append(f'dev package: {package_rel} is not pinned by the manifest')
        elif raw_sha(ROOT / rel) != pinned[package_rel]:
            e.append(f'dev package: {rel} differs from pinned {package_rel}')
    return e


def private_tree_report(private_root):
    private_root = Path(private_root)
    repo = {p.relative_to(ROOT).as_posix() for g in SOURCE_GLOBS for p in ROOT.glob(g) if p.is_file()}
    private = {p.relative_to(private_root).as_posix() for g in SOURCE_GLOBS for p in private_root.glob(g)
               if p.is_file()}
    identical = sorted(r for r in repo & private if raw_sha(ROOT / r) == raw_sha(private_root / r))
    differs = sorted(r for r in repo & private if r not in identical)
    repo_only = sorted(repo - private)
    errors = [f'private tree: {r} differs' for r in differs]
    errors += [f'private tree: {r} exists only in this checkout' for r in repo_only if r not in PUBLIC_ONLY]
    errors += [f'private tree: {r} is missing from this checkout' for r in sorted(private - repo)]
    return {'identical': len(identical), 'differs': differs, 'repo_only': repo_only,
            'private_only': sorted(private - repo)}, errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--freeze', type=Path, required=True)
    ap.add_argument('--dev-manifest', type=Path, required=True)
    ap.add_argument('--private-root', type=Path)
    args = ap.parse_args(argv)
    errors, cp1_count = cp1_errors(args.freeze)
    errors += dev_package_errors(args.dev_manifest)
    report = {'cp1_frozen_source_files': cp1_count, 'dev_package_pinned_files': len(DEV_PACKAGE_FILES)}
    if args.private_root:
        report['private_tree'], private_errors = private_tree_report(args.private_root)
        errors += private_errors
    print(json.dumps({'result': 'FAIL' if errors else 'PASS', **report, 'errors': errors}, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
