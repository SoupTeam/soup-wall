#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in owned-loopback SOU-175 reproduction; no GitHub calls/status writes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '37b82bea3bfcab31941d9e142c15e37e64b258a8'
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'scripts/tests')]
import ci_admission
import test_ci_admission_transport as fixture


def sha(raw): return hashlib.sha256(raw).hexdigest()


def measure(module, actions, *, post=False):
    server = fixture.OwnedHTTP(actions)
    started = time.monotonic()
    try:
        with server.client(module, real_backoff=True) as api:
            try:
                value = api.post('/statuses/' + 'a' * 40, {'state': 'pending'}) if post else \
                    api.get('/actions/runs/1/attempts/1/jobs')
                outcome = 'complete_response' if value == {'jobs': [{'id': 7}], 'total_count': 1} else 'unexpected'
                error = None
            except Exception as caught:
                outcome, error = 'refused', type(caught).__name__
            return {'outcome': outcome, 'exception_type': error,
                    'get_attempts': api.http_get_attempts, 'post_attempts': api.http_post_attempts,
                    'backoff_seconds': list(server.delays),
                    'elapsed_seconds': round(time.monotonic() - started, 3),
                    'real_body_io': True, 'real_backoff': True,
                    'real_github_requests': 0, 'fixture_status_writes': len(server.posts)}
    finally: server.close()


def run():
    original = subprocess.run(['git', 'show', BASELINE + ':scripts/ci_admission.py'], cwd=ROOT,
                              check=True, capture_output=True).stdout
    baseline = types.ModuleType('sou175_accepted_baseline')
    sys.modules[baseline.__name__] = baseline
    exec(compile(original, '<accepted-ci-admission>', 'exec'), baseline.__dict__)
    complete = {'jobs': [{'id': 7}], 'total_count': 1}
    cases = {
        'old_broken_body': measure(baseline, [('cut', complete), ('ok', complete)]),
        'new_broken_body_recovery': measure(ci_admission, [('cut', complete), ('ok', complete)]),
        'new_persistent_outage': measure(ci_admission, [('cut', complete)] * 3),
        'new_http_503_recovery': measure(ci_admission, [(503, b''), ('ok', complete)]),
        'new_unauthorized': measure(ci_admission, [(403, b'')]),
        'new_malformed_complete_response': measure(ci_admission, [('ok', b'{broken')]),
        'new_uncertain_post': measure(ci_admission, [('cut', complete)], post=True),
    }
    assert cases['old_broken_body']['exception_type'] == 'IncompleteRead' and cases['old_broken_body']['get_attempts'] == 1
    assert cases['new_broken_body_recovery']['outcome'] == cases['new_http_503_recovery']['outcome'] == 'complete_response'
    assert cases['new_broken_body_recovery']['get_attempts'] == 2
    assert cases['new_persistent_outage']['get_attempts'] == 3 and cases['new_persistent_outage']['outcome'] == 'refused'
    assert cases['new_uncertain_post']['post_attempts'] == 1 and cases['new_uncertain_post']['outcome'] == 'refused'
    assert cases['new_unauthorized']['get_attempts'] == cases['new_malformed_complete_response']['get_attempts'] == 1
    # Compose actual HTTP recovery with all existing selected-source gates.
    for name, options in [('candidate_recovery', {}), ('candidate_outage', {'persistent': True}),
                          ('changed_head_after_recovery', {'mutate': lambda a: a.pr['head'].update(sha='d' * 40)})]:
        probe = fixture.CandidateTransport()
        started = time.monotonic()
        try:
            server, code, _ = probe.exercise(**options)
            states = [p['state'] for p in server.posts]
            cases[name] = {'exit_code': code, 'fixture_status_states': states,
                'get_attempts': sum(method == 'GET' for method, _ in server.requests),
                'post_attempts': sum(method == 'POST' for method, _ in server.requests),
                'backoff_seconds': list(server.delays), 'real_backoff': False, 'real_body_io': True,
                'elapsed_seconds': round(time.monotonic() - started, 3), 'real_github_requests': 0}
            if name == 'candidate_recovery': assert states == ['pending', 'success']
            else: assert 'success' not in states
        finally: probe.doCleanups()
    current = (ROOT / 'scripts/ci_admission.py').read_bytes()
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    committed = subprocess.run(['git', 'show', 'HEAD:scripts/ci_admission.py'], cwd=ROOT, check=True, capture_output=True).stdout
    return {'format': 'sw-ci-admission-transport-qualification/1', 'status': 'passed',
            'scope': 'owned-loopback-real-urllib; synthetic API candidates; no trusted GitHub qualification',
            'source_commit': commit, 'client_matches_commit': current == committed,
            'baseline_commit': BASELINE, 'baseline_client_sha256': sha(original), 'client_sha256': sha(current),
            'cases': cases, 'real_github_requests': 0, 'real_github_status_writes': 0,
            'trusted_same_source_qualification': 'reviewer_owned_not_claimed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'executed': False, 'format': 'sw-ci-admission-transport-qualification/1'}));return 0
    if not args.output or not args.output.is_absolute() or args.output.exists():
        parser.error('--output must name a new absolute file in an existing private directory')
    report = run()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream: json.dump(report, stream, sort_keys=True, indent=2);stream.write('\n')
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']),
                      'client_sha256': report['client_sha256'], 'real_github_status_writes': 0}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
