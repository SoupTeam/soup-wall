#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare eight mapped, owned Git cases. This never runs a daemon or grants release.

The native consumer must independently authenticate original execution and exact
returned bytes; this public plan and its hashes are not execution authority.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SHA = '3a7fd3091990d8425df42914321336dd25bdf9ff34f677450935a0c26c674e33'
PAIRS = ('g01', 'g03', 'g07', 'g09')
REQUIRED_CONTROLS = ('original_text_equality', 'private_call_profile_channel_custody',
                     'baseline_refused_verified_benign_delivered', 'matched_attacks_refused',
                     'copied_proof_refused', 'stale_proof_refused', 'foreign_proof_refused',
                     'independent_signatures_retained', 'independent_directives_retained',
                     'operator_ask_retained', 'operator_deny_retained',
                     'source_readonly', 'owned_cleanup')
SPEC = importlib.util.spec_from_file_location('sou157_original_generator', ROOT / 'eval/sou123/generate_corpus.py')
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def inventory():
    raw = (ROOT / 'eval/sou123/manifest.json').read_bytes()
    require(sha(raw) == MANIFEST_SHA, 'frozen_manifest_changed')
    cases = [c for c in json.loads(raw)['cases'] if c['pair_id'] in PAIRS]
    require(len(cases) == 8 and len({c['case_id'] for c in cases}) == 8, 'finite_inventory_changed')
    for case in cases:
        require(case['tool'] == 'git_show' and case['arguments'] ==
                {'repo_path': '/tmp/sou123/repo', 'revision': 'HEAD'}, 'unexpected_original_invocation')
        raw = (ROOT / 'eval/sou123/payloads' / (case['case_id'] + '.txt')).read_bytes()
        require(len(raw) == case['size_bytes'] and sha(raw) == case['sha256'], 'frozen_payload_changed')
    return cases


def mapped_case(case):
    original = case['arguments']
    mapped = {**original, 'repo_path': '/workspace'}
    return {'case_id': case['case_id'], 'label': case['label'], 'tool': case['tool'],
            'original_arguments': original, 'mapped_arguments': mapped,
            'original_arguments_sha256': sha(canonical(original)),
            'mapped_arguments_sha256': sha(canonical(mapped)),
            'expected_original_text_sha256': case['sha256'],
            'expected_original_text_bytes': case['size_bytes'],
            'exact_frozen_invocation': False, 'mapping': 'repo_path_only',
            'live_custody': False, 'original_returned_bytes_verified': False}


def compare_original_text(case, returned):
    """Equality gate only, NOT a source authenticator or a verdict grader."""
    require(isinstance(returned, bytes), 'original_text_must_be_bytes')
    expected = (ROOT / 'eval/sou123/payloads' / (case['case_id'] + '.txt')).read_bytes()
    require(sha(expected) == case['sha256'], 'frozen_payload_changed')
    return {'case_id': case['case_id'], 'comparable': returned == expected,
            'actual_text_sha256': sha(returned), 'actual_text_bytes': len(returned),
            'expected_text_sha256': case['sha256'], 'live_custody': False,
            'production_authority': False}


def prepare_repositories(output, git, expected_git_sha):
    """No replacement, deletion, downloads, captured-result injection, or inference."""
    output = Path(output)
    git = Path(git).resolve(strict=True)
    require(git.is_file() and sha(git.read_bytes()) == expected_git_sha, 'pinned_git_mismatch')
    cases = inventory()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Explicit deterministic author metadata from the original generator; ignore
    # ambient Git config/index/template/hooks/signing variables for owned fixtures.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GEN.git_env(SimpleNamespace(git=str(git))))
    for key in list(env):
        if key.startswith('GIT_') and key not in (
                'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL',
                'GIT_AUTHOR_DATE', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE'):
            del env[key]
    empty = output / 'empty-template'
    empty.mkdir()
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_TEMPLATE_DIR=str(empty.resolve()),
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    rows = []
    for case in cases:
        pair = next(p for p in GEN.corpus.PAIRS if p['id'] == case['pair_id'])
        repo = output / case['case_id']
        GEN.git_repository(SimpleNamespace(git=str(git)), pair, pair[case['label']], 0, repo, env)
        head = subprocess.check_output([str(git), '-C', str(repo), 'rev-parse', 'HEAD'],
                                       env=env, timeout=15).decode().strip()
        expected = (ROOT / 'eval/sou123/payloads' / (case['case_id'] + '.txt')).read_bytes()
        row = mapped_case(case)
        row.update(repository=str(repo.resolve()), commit=head,
                   commit_matches_frozen_header=expected.startswith(f'commit {head}\n'.encode()))
        # Retain mismatches instead of rewriting commit headers or payloads.
        row['status'] = 'prepared_unqualified' if row['commit_matches_frozen_header'] else 'non_comparable_commit'
        rows.append(row)
    return {'format': 'sou157-mapped-git-preparation/1', 'manifest_sha256': MANIFEST_SHA,
            'git_sha256': expected_git_sha,
            'git_version': subprocess.check_output([str(git), '--version'], env=env, timeout=15).decode().strip(),
            'cases': rows, 'model_calls': 0, 'native_executions': 0, 'production_authority': False,
            'task_complete': False, 'frozen_false_refusals': 10,
            'required_native_controls': {name: 'not_executed' for name in REQUIRED_CONTROLS}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template-profile', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux', 'native_preparation_requires_linux')
    require(re.fullmatch('[0-9a-f]{40}', args.expected_commit), 'source_identity_required')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip() == args.expected_commit,
            'source_identity_mismatch')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT), 'source_not_clean')
    raw = args.template_profile.read_bytes()
    require(sha(raw) == args.profile_sha256, 'profile_identity_mismatch')
    profile = json.loads(raw)
    require(profile['format'] == 'sw-mcp/git-readonly/1', 'default_profile_required')
    os.umask(0o077)
    report = prepare_repositories(args.output, profile['git']['path'], profile['git']['sha256'])
    report.update(source_commit=args.expected_commit, template_profile_sha256=sha(raw),
                  generator_sha256=sha((ROOT/'eval/sou123/generate_corpus.py').read_bytes()),
                  corpus_definition_sha256=sha((ROOT/'eval/sou123/corpus.py').read_bytes()))
    for row in report['cases']:
        selected = dict(profile)
        repo = Path(row['repository'])
        st = repo.stat()
        selected.update(workspace=str(repo), workspaceIdentity={'device': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid})
        path = args.output / (row['case_id'] + '.profile.json')
        path.write_bytes(canonical(selected) + b'\n')
        row['operator_test_config'] = {'native': {'git_execution': {
            'profile_path': str(path.resolve()), 'profile_sha256': sha(path.read_bytes()), 'server_id': 'git'}}}
    (args.output / 'preparation.json').write_bytes(canonical(report) + b'\n')
    print(json.dumps({'status': 'prepared_unqualified', 'cases': len(report['cases']), 'native_executions': 0}))
    return int(any(not r['commit_matches_frozen_header'] for r in report['cases']))


if __name__ == '__main__':
    raise SystemExit(main())
