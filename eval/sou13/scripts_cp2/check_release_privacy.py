#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Conservative pre-publication privacy gate for SOU-13. Read-only: no network, no mutation, no sealed reads.

Two modes:
  --root DIR   scan every file below DIR (scratch or release folders)
  --git REPO   scan every file a commit could contain: tracked changes against HEAD, staged and intent-to-add
               paths, and untracked files that are not ignored. Content is read from the working tree.

Every rule fails closed: an unreadable, binary or oversized file is an issue, not a pass.

  * restricted path components, names and suffixes (sealed/custodian folders, keys, signatures)
  * raw dataset/review/archive types (.jsonl, .csv, .zip) need explicit manual approval
  * private-key markers
  * literal CP2 case ids (S13C2- followed by 32 hex digits); real ids are data, never source
  * owner absolute paths (drive-letter user or SOU13 folders, the /mnt data mount, home directories)
  * label rows (per_action_targets next to a case id) in non-code, non-schema files
  * family ids outside the public taxonomy, unless registered for that specific file with a provenance and
    owner confirmation; this blocks restricted test-family identities without the gate ever reading them
  * --deny-digests JSON...: files byte-identical (raw or LF-normalised) to any pinned private data file or
    custodian commitment listed in freeze.json / a dev package MANIFEST.json (digests only are read)
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]

BAD_COMPONENTS = {
    'cp2_sealed', 'restricted_test_custodian', 'sealed_test',
    'restricted', 'test_gold', 'local-notes-private',
    '__pycache__', '.pytest_cache', '.git',
}
BAD_NAMES = {
    'allowed_signers', 'test_labels.jsonl', 'candidates_test.jsonl',
    'test_candidates.jsonl', 'test_families.json', 'test_review_queue.csv',
    'sou13_owner', 'sou13_owner.pub',
}
BAD_SUFFIXES = {'.sig', '.pem', '.p12', '.pfx', '.key', '.pyc'}
RAW_DATA_SUFFIXES = ('.jsonl', '.csv', '.zip')
BAD_SNIPPETS = [
    re.compile(rb'-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----'),
    re.compile(rb'-----BEGIN ' + rb'PRIVATE KEY-----'),
]
CASE_ID = re.compile(rb'S13C2-[0-9A-F]{32}')
# Assembled from pieces so that this file does not match its own rule.
OWNER_PATH = re.compile(rb'(?i)\b[a-z]:[\\/]+(?:users|sou13)'
                        rb'|/mnt' + rb'/data\b|/home' + rb'/[a-z]|/Users' + rb'/[A-Za-z]')
LABEL_ROW = re.compile(rb'"per_action_targets"')
ANY_CASE_ID = re.compile(rb'S13(?:V03|C2)-[0-9A-Z-]{4,}')
FAMILY_ID = re.compile(r'fam\.(?:read|write|delete|send_data|change_permissions|mixed|no_effect|unknown|shell)'
                       r'\.[a-z0-9_]+')
# Family ids that are not in the public taxonomy, each allowed ONLY in the files named here (and in this
# registry). Every entry needs a recorded provenance; an entry with confirmed=False still fails the gate
# everywhere until the owner confirms it is not a restricted test family. Never add a global exception.
REGISTRY_FILE = 'scripts_cp2/check_release_privacy.py'
FILE_SCOPED_FAMILY_IDS = {
    'fam.delete.syn_new': dict(files=('tests_cp2/test_near_duplicates.py',), confirmed=True,
                               provenance='case-id retirement test key in a temporary root'),
    'fam.delete.syn_old': dict(files=('tests_cp2/test_near_duplicates.py',), confirmed=True,
                               provenance='case-id retirement test key in a temporary root'),
    'fam.delete.syn_one': dict(files=('tests_cp2/test_near_duplicates.py',), confirmed=True,
                               provenance="in-test family with identity ('synthetic-c', 'drop_one')"),
    'fam.delete.syn_two': dict(files=('tests_cp2/test_near_duplicates.py',), confirmed=True,
                               provenance="in-test family with identity ('synthetic-d', 'drop_pair')"),
    'fam.unknown.syn_bridge': dict(files=('tests_cp2/test_near_duplicates.py',), confirmed=True,
                                   provenance="in-test family with identity ('synthetic-b', 'bridge_invoke')"),
    'fam.unknown.syn_rpc': dict(files=('tests_cp2/test_near_duplicates.py',), confirmed=True,
                                provenance="in-test family with identity ('synthetic-a', 'call_proc')"),
    'fam.read.extra_probe': dict(files=('tests_cp2/test_freeze.py', 'tests_cp2/test_splits.py'), confirmed=True,
                                 provenance="in-test family with identity ('synthetic-extra', 'probe_status')"),
    # Historical regression fixture: the test asserts this id is ABSENT from the frozen manifest.
    'fam.unknown.unadmitted_tidy': dict(
        files=('tests_cp2/test_review_integration.py',), confirmed=True,
        provenance='pre-freeze family of the unadmitted CP1 DEV-09 identity (unregistered-tidy/tidy_workspace), '
                   'train, cp1_shared; replaced by fam.unknown.workspace_tidy before the final freeze, split '
                   'unchanged, test split unaffected. Owner-confirmed 2026-10-11 from the dev-only '
                   'CP2_REVIEW_INTEGRATION.md; verified absent from the frozen public split view pinned by '
                   'the dev package manifest (36 families), where workspace_tidy is train.'),
}
CODE_SUFFIXES = ('.py', '.ps1', '.sh', '.rs')
MAX_BYTES = 2_000_000
DATA_DIGEST_SUFFIXES = ('.jsonl', '.csv', '.json', '.md', '.txt', '.zip')


def public_family_ids():
    """Public taxonomy ids from the source in this checkout (public mode: no restricted file is read)."""
    sys.dont_write_bytecode = True  # importing must not create __pycache__ inside the tree being scanned
    sys.path.insert(0, str(HERE))
    from sou13cp2 import restricted
    from sou13cp2.taxonomy import families
    if restricted.available():
        raise SystemExit('refusing to run: restricted materials are present in this checkout')
    return frozenset(f['family_id'] for f in families())


def deny_digests(paths):
    """Data-file digests from freeze.json / MANIFEST.json style documents. Code and schema digests are skipped:
    the published source is meant to equal them."""
    out = set()
    for p in paths:
        doc = json.loads(Path(p).read_text(encoding='utf-8'))
        for rel, digest in (doc.get('files_sha256') or {}).items():
            if rel.endswith(DATA_DIGEST_SUFFIXES) and not rel.startswith(('schema/', 'requirements')):
                out.add(digest)
        for key, digest in (doc.get('test_commitments') or {}).items():
            if key.endswith('sha256'):
                out.add(digest)
    return out


def _path_issues(rel):
    parts = [x.lower() for x in Path(rel).parts]
    name = parts[-1]
    if set(parts) & BAD_COMPONENTS or name in BAD_NAMES or Path(name).suffix in BAD_SUFFIXES:
        return [f'{rel}: restricted path/type']
    issues = []
    if name in {'anchor.json', 'anchor-v3.json', 'anchor-v2.json'}:
        issues.append(f'{rel}: freeze anchor belongs to out-of-repo trust workflow')
    if name.endswith(RAW_DATA_SUFFIXES):
        issues.append(f'{rel}: raw dataset/export/review artifact requires manual approval')
    return issues


def _in_files(rel, files):
    rel = rel.replace('\\', '/')
    return any(rel == f or rel.endswith('/' + f) for f in files)


def _content_issues(rel, data, families, digests):
    issues = []
    if digests:
        lf = data.replace(b'\r\n', b'\n')
        if {hashlib.sha256(data).hexdigest(), hashlib.sha256(lf).hexdigest()} & digests:
            issues.append(f'{rel}: byte-identical to a pinned private data file or custodian commitment')
    if b'\x00' in data:
        return issues + [f'{rel}: binary content cannot be reviewed by this gate']
    if any(pattern.search(data) for pattern in BAD_SNIPPETS):
        issues.append(f'{rel}: private-key marker')
    if CASE_ID.search(data):
        issues.append(f'{rel}: literal CP2 case id')
    if OWNER_PATH.search(data):
        issues.append(f'{rel}: owner absolute path')
    lower = rel.lower()
    if (not lower.endswith(CODE_SUFFIXES) and '/schema/' not in f'/{lower}'
            and LABEL_ROW.search(data) and ANY_CASE_ID.search(data)):
        issues.append(f'{rel}: label row (per_action_targets with a case id)')
    if families is not None:
        found = set(FAMILY_ID.findall(data.decode('utf-8', errors='replace'))) - families
        unknown, unconfirmed = [], []
        for fid in sorted(found):
            entry = FILE_SCOPED_FAMILY_IDS.get(fid)
            if entry is None or not _in_files(rel, entry['files'] + (REGISTRY_FILE,)):
                unknown.append(fid)
            elif not entry['confirmed']:
                unconfirmed.append(fid)
        if unknown:
            issues.append(f'{rel}: family ids outside the public taxonomy {unknown[:5]}')
        if unconfirmed:
            issues.append(f'{rel}: family ids awaiting owner provenance confirmation {unconfirmed}')
    return issues


def inspect_files(base, rels, families=None, digests=frozenset()):
    issues = []
    for rel in sorted(set(rels)):
        p = Path(base) / rel
        if not p.exists():
            continue  # a deletion carries no content
        if p.is_symlink() or not p.is_file():
            issues.append(f'{rel}: not a regular file')
            continue
        path_issues = _path_issues(rel)
        issues += path_issues
        if any(i.endswith('restricted path/type') for i in path_issues):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                issues.append(f'{rel}: larger than {MAX_BYTES} bytes; review manually')
                continue
            issues += _content_issues(rel, p.read_bytes(), families, digests)
        except OSError as exc:
            issues.append(f'{rel}: cannot scan ({exc})')
    return issues


def inspect(root, families=None, digests=frozenset()):
    root = Path(root)
    rels = [p.relative_to(root).as_posix() for p in sorted(root.rglob('*')) if p.is_file() or p.is_symlink()]
    return inspect_files(root, rels, families, digests)


def _git(repo, *args):
    out = subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True).stdout
    return [x for x in out.decode('utf-8').split('\0') if x]


def git_prospective(repo):
    """Every path a commit of the current working state could contain."""
    names = set(_git(repo, 'diff', '--name-only', '-z', 'HEAD'))
    names |= set(_git(repo, 'diff', '--name-only', '-z', '--cached'))
    names |= set(_git(repo, 'ls-files', '--others', '--exclude-standard', '-z'))
    return sorted(names)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--root', type=Path)
    mode.add_argument('--git', type=Path, metavar='REPO')
    parser.add_argument('--deny-digests', nargs='*', default=[], metavar='JSON')
    parser.add_argument('--no-family-check', action='store_true',
                        help='skip the public-taxonomy family-id check (scratch folders without source)')
    args = parser.parse_args(argv)
    families = None if args.no_family_check else public_family_ids()
    digests = deny_digests(args.deny_digests)
    if args.git:
        base, files = args.git, git_prospective(args.git)
        failures = inspect_files(base, files, families, digests)
    else:
        base = args.root or Path('.')
        files = [p for p in base.rglob('*') if p.is_file()]
        failures = inspect(base, families, digests)
    print(json.dumps({'privacy_gate': 'FAIL' if failures else 'PASS', 'mode': 'git' if args.git else 'root',
                      'scanned_root': str(Path(base).resolve()), 'files_scanned': len(files),
                      'deny_digests_loaded': len(digests), 'family_check': families is not None,
                      'issues': failures}, indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
