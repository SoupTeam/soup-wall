# SPDX-License-Identifier: Apache-2.0
"""Offline SOU-129 reconciliation of explicitly selected pilot evidence.

No execution, policy decision, CI admission or release approval. Reuses the
SOU-106 gate and SOU-80 bounded readers/support definitions.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import math
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import zipfile
import zlib

from roadmap_support import (Invalid, require, exact, source, digest, identifier,
                             relative, word, safe_file, load_json, pairs_unique,
                             bounded_tree, validate_index, write_private)
from pilot_qualification import matched_gate, Failure, canonical
import pilot_runtime_identity as RUNTIME

VERSION = 'sw-pilot-dossier/1'
SCOPE = 'internal-readonly-original-filesystem-git-scripted-provider'
AREAS = ('install-start', 'useful-workflows', 'refusal-zero-effects', 'ask',
         'daemon-loss', 'cancellation-cleanup', 'linux-platform', 'wsl-platform')
OWNERS = dict(zip(AREAS, ('SOU-116', 'SOU-106', 'SOU-106', 'SOU-112',
                         'SOU-116', 'SOU-116', 'SOU-115', 'TL/platform-owner')))
IDENTITIES = ('policy', 'filesystem_profile', 'git_profile', 'filesystem_registry',
              'git_registry', 'filesystem_classifier', 'git_classifier',
              'agentfw', 'claude', 'node', 'git', 'bwrap')
MAX_REPORT = 2 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), 'nonfinite_json')
    return parsed


def parse(raw):
    require(len(raw) <= MAX_REPORT, 'report_byte_limit')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs_unique, parse_float=finite_float,
                           parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite_json')))
        bounded_tree(value)
        require(type(value) is dict, 'object_required')
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Invalid('invalid_report_json') from exc


def validate_reference(ref):
    exact(ref, {'path', 'sha256', 'member', 'member_sha256'}, 'file_reference')
    path = relative(ref['path'], 'path')
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', path) is not None, 'unsafe_display_path')
    digest(ref['sha256'], 'file_sha256')
    if ref['member'] is None:
        require(ref['member_sha256'] is None, 'unexpected_member_hash')
    else:
        member = relative(ref['member'], 'member')
        require(re.fullmatch(r'[A-Za-z0-9_./-]+', member) is not None, 'unsafe_display_member')
        digest(ref['member_sha256'], 'member_sha256')
    return ref


def selected_bytes(root, ref):
    """No directory discovery or extraction; archive and selected member pinned."""
    validate_reference(ref)
    path = ref['path']
    raw = safe_file(root / path, MAX_ARCHIVE if ref['member'] is not None else MAX_REPORT)
    require(sha(raw) == ref['sha256'], 'file_hash_mismatch')
    if ref['member'] is None:
        require(ref['member_sha256'] is None, 'unexpected_member_hash')
        return raw
    member = relative(ref['member'], 'member')
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', member) is not None, 'unsafe_display_member')
    digest(ref['member_sha256'], 'member_sha256')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= 256, 'archive_member_limit')
            names = set()
            total = 0
            for info in infos:
                name = info.filename.rstrip('/') if info.is_dir() else info.filename
                relative(name, 'archive_path')
                require(info.filename not in names, 'duplicate_archive_member')
                names.add(info.filename)
                mode = info.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR) and not info.flag_bits & 1,
                        'archive_link_or_encryption')
                require(info.file_size <= MAX_REPORT, 'archive_member_size_limit')
                total += info.file_size
                require(total <= MAX_ARCHIVE, 'archive_expansion_limit')
            require(member in names, 'missing_archive_member')
            raw = archive.read(member)
    except (zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError, zlib.error, EOFError) as exc:
        raise Invalid('invalid_archive') from exc
    require(sha(raw) == ref['member_sha256'], 'member_hash_mismatch')
    return raw


def git_tree(repo, commit):
    source(commit, 'commit')
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    size = subprocess.run(['git', '-C', str(repo), 'cat-file', '-s', commit],
                          capture_output=True, timeout=15, env=env)
    require(size.returncode == 0 and int(size.stdout) <= 65536, 'source_object_unavailable')
    result = subprocess.run(['git', '-C', str(repo), 'cat-file', '-p', commit],
                            capture_output=True, timeout=15, env=env)
    require(result.returncode == 0, 'source_object_unavailable')
    lines = result.stdout.splitlines()
    require(lines and lines[0].startswith(b'tree '), 'source_not_commit')
    tree = lines[0][5:].decode('ascii')
    source(tree, 'tree')
    return tree


def git_bytes(repo, commit, path):
    relative(path, 'published_path')
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    ref = commit + ':' + path
    size = subprocess.run(['git', '-C', str(repo), 'cat-file', '-s', ref],
                          capture_output=True, timeout=15, env=env)
    require(size.returncode == 0 and int(size.stdout) <= MAX_REPORT, 'published_object_unavailable')
    data = subprocess.run(['git', '-C', str(repo), 'cat-file', 'blob', ref],
                          capture_output=True, timeout=15, env=env)
    require(data.returncode == 0, 'published_object_unavailable')
    return data.stdout


def git_json(repo, commit, path):
    return parse(git_bytes(repo, commit, path))


def git_files_digest(repo, commit):
    """Recompute the existing clean-checkout files digest from bounded Git blobs."""
    source(commit, 'commit')
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    listing = subprocess.check_output(['git', '-C', str(repo), 'ls-tree', '-rzl', commit],
                                      timeout=15, env=env)
    require(len(listing) <= 4 * 1024 * 1024, 'source_inventory_bound')
    entries = [row.split(b'\t', 1) for row in listing.split(b'\0') if row]
    require(0 < len(entries) <= 10000, 'source_inventory_bound')
    total, hashes = 0, {}
    process = subprocess.Popen(['git', '-C', str(repo), 'cat-file', '--batch'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=env)
    try:
        for header, raw_name in entries:
            mode, kind, oid, size = header.split()
            size = int(size); total += size
            require(mode in (b'100644', b'100755') and kind == b'blob' and
                    0 <= size <= 8 * 1024 * 1024 and total <= 128 * 1024 * 1024,
                    'unsupported_or_oversized_source_file')
            name = raw_name.decode('utf-8')
            require(name not in hashes, 'duplicate_source_file')
            process.stdin.write(oid + b'\n'); process.stdin.flush()
            require(process.stdout.readline(100).strip() == oid + b' blob ' + str(size).encode(),
                    'source_blob_unavailable')
            digest_ = hashlib.sha256(); remaining = size
            while remaining:
                block = process.stdout.read(min(remaining, 65536))
                require(block, 'source_blob_truncated')
                digest_.update(block); remaining -= len(block)
            require(process.stdout.read(1) == b'\n', 'source_blob_truncated')
            hashes[name] = digest_.hexdigest()
        process.stdin.close()
        require(process.wait(timeout=15) == 0, 'source_blob_unavailable')
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=15)
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
    return sha(canonical(hashes))


def report_source(value):
    require(type(value) is dict and value.get('dirty') is False, 'unclean_or_absent_source')
    source(value.get('commit'), 'report_commit')
    source(value.get('tree'), 'report_tree')
    return {k: value[k] for k in ('commit', 'tree')}


def identities(report, kind):
    selected = report.get('selected_sha256', {})
    profiles = report.get('profiles', {})
    if kind == 'installed':
        setup = next(r for r in report['cases'] if r['id'] == 'exact-installed-inputs')
        profiles = setup.get('evidence', {}).get('profiles', {})
    if kind == 'matched':
        selected = report['identity'].get('selected', {})
        profiles = report['identity'].get('profiles', {})
        require(report['identity'].get('policy_sha256') == selected.get('policy'), 'conflicting_policy_identity')
    values = {key: selected.get(key) for key in IDENTITIES}
    if kind == 'ask':
        policies = {r.get('policy_sha256') for r in report['cases']}
        values['policy'] = next(iter(policies)) if len(policies) == 1 else None
    for name in ('filesystem', 'git'):
        profile = profiles.get(name, {})
        values[name + '_profile'] = profile.get('profile_sha256')
        values[name + '_registry'] = profile.get('registry_sha256')
        values[name + '_classifier'] = profile.get('classifier_sha256', selected.get(name + '_classifier'))
        if profile.get('classifier_sha256') is not None and selected.get(name + '_classifier') is not None:
            require(profile['classifier_sha256'] == selected[name + '_classifier'], 'conflicting_classifier_identity')
    for key, value in values.items():
        digest(value, key, optional=True)
    return values


def count(passed, required):
    require(type(passed) is int and type(required) is int and 0 <= passed <= required <= 10000,
            'invalid_denominator')
    return {'passed': passed, 'required': required}


def observation(area, passed, required, details=None):
    counts = count(passed, required)
    return {'area': area, 'observed_status': 'pass' if required and passed == required else
            'fail' if required else 'incomplete', 'counts': counts, 'details': details or {}}


def project(report, workload):
    """Read original outcomes, never replace their runtime assertions."""
    version = report.get('format', report.get('contract_version'))
    observations = []
    if version == 'sw-installed-pilot-matched/1':
        kind = 'matched'
        require(report.get('live_model_effectiveness') == 'not_measured', 'scope_mismatch')
        before = report_source(report['identity']['source'])
        gate = matched_gate(workload, report)
        require(gate == report['gate'], 'stored_gate_disagrees_with_existing_gate')
        metrics = gate['metrics']
        observations.append(observation('useful-workflows', metrics['benign_completed'],
            metrics['benign_required'], {'false_interruptions': metrics['false_interruptions'],
            'failed_cases': [c['id'] for c in workload['cases'] if c['kind'] == 'benign' and
                any(r['status'] != 'passed' for r in report['rows'] if r['case'] == c['id'])]}))
        refusal_cases = [c for c in workload['cases'] if c['kind'] == 'refusal']
        passed = sum(all(r['status'] == 'passed' for r in report['rows'] if r['case'] == c['id'])
                     for c in refusal_cases)
        if metrics['forbidden_effects'] or metrics['forbidden_result_delivery_count']:
            passed = 0
        observations.append(observation('refusal-zero-effects', passed, len(refusal_cases),
            {k: metrics[k] for k in ('forbidden_effects', 'denied_execution_count',
                                     'forbidden_result_delivery_count')}))
    elif version == 'sw-installed-pilot/1':
        kind = 'installed'
        from pilot_qualification import CASES, finish
        import copy
        require(report.get('live_model_effectiveness') == 'not_measured', 'scope_mismatch')
        before = report_source(report['source_before'])
        checked = finish(copy.deepcopy(report))
        require(checked['status'] == report['status'] and checked['counts'] == report['counts'],
                'installed_summary_mismatch')
        require([row['id'] for row in report['cases']] == list(CASES), 'installed_case_denominator_changed')
        by = {row['id']: row for row in report['cases']}
        cleanup = by['final-cleanup']
        if cleanup['status'] == 'passed':
            proof = cleanup['evidence']
            require(proof.get('all_owned_processes_stopped') is True and proof.get('forced_cleanup') is False
                    and proof.get('private_installation_removed') is True
                    and proof.get('source_and_inputs_unchanged') is True, 'installed_cleanup_missing')
        for name in ('read-and-history', 'inspect-and-diff', 'untrusted-input-refusal', 'independent-conversation'):
            if by[name]['status'] != 'passed':
                continue
            evidence = by[name]['evidence']
            host = evidence.get('host', {})
            require(host.get('actual_host') is True and host.get('timed_out') is False
                    and host.get('exit_code') == 0 and host.get('process_cleanup', {}).get('all_stopped') is True
                    and host.get('process_cleanup', {}).get('remaining') == [], 'installed_host_witness_missing')
            for key in ('workspace_snapshot_sha256', 'repository_snapshot_sha256', 'unrelated_file_sha256'):
                digest(evidence.get(key), key)
            require(type(evidence.get('receiver_deliveries')) is int and evidence['receiver_deliveries'] == 0
                    and evidence.get('unrelated_process_alive') is True, 'installed_integrity_missing')
        refusal = by['untrusted-input-refusal']
        if refusal['status'] == 'passed':
            proof = refusal['evidence']
            require(proof.get('fifo', {}).get('reader_seen') is False
                    and type(proof.get('fifo', {}).get('bytes_written')) is int
                    and proof['fifo']['bytes_written'] == 0
                    and type(proof.get('opens_during_refused_mutator')) is int
                    and proof['opens_during_refused_mutator'] == 0, 'installed_zero_effects_missing')
        for area, names in [('install-start', ('exact-installed-inputs', 'bad-input-controls', 'sandbox-positive', 'witness-calibration')),
                            ('useful-workflows', ('read-and-history', 'inspect-and-diff')),
                            ('refusal-zero-effects', ('untrusted-input-refusal',)),
                            ('daemon-loss', ('collector-recovery', 'daemon-fresh-conversation')),
                            ('cancellation-cleanup', ('parallel-cancellation', 'final-cleanup'))]:
            observations.append(observation(area, sum(by[n]['status'] == 'passed' for n in names),
                                            len(names), {'cases': list(names)}))
    elif version == 'sw-existing-pilot-acceptance/1':
        kind = 'existing'
        require(report.get('provider') == 'owned-scripted-loopback' and
                report.get('live_model_effectiveness') == 'not_tested', 'scope_mismatch')
        before = report_source(report['source'])
        from pilot_project_fixtures import PROJECTS, identity as project_identity
        name = report.get('project_fixture')
        require(name in PROJECTS and report.get('project_fixture_sha256') == project_identity(name)
                and report.get('ordinary_project_required_cases') == 9, 'project_input_identity_missing')
        expected = ('moved-root', 'replaced-root', 'changed-selection', 'unsupported-git',
                    'initial', 'operator-edit', 'cancel', 'daemon-loss', 'recovery')
        rows = report['cases']
        require([r['case'] for r in rows] == list(expected[:len(rows)])
                and len(rows) <= len(expected), 'project_case_denominator_changed')
        require(report['status'] != 'passed' or len(rows) == len(expected), 'project_inventory_incomplete')
        if report['status'] == 'passed':
            require(all(report.get(key) is True for key in ('fresh_run_authority',
                    'external_roots_outside_prefix', 'cleanup_external_roots_untouched')),
                    'project_global_integrity_missing')
        instances = [row.get('native_instance') for row in rows
                     if row['case'] in expected[4:] and row['status'] == 'passed']
        require(all(type(value) is str and 0 < len(value) <= 128 for value in instances)
                and len(set(instances)) == len(instances), 'project_fresh_authority_missing')

        for row in rows:
            require(row['status'] in ('passed', 'failed', 'incomplete', 'unsupported'), 'invalid_project_status')
            if row['status'] != 'passed':
                continue
            digest(row.get('trace_sha256'), 'project_trace')
            if row['case'] in expected[:4]:
                require(type(row.get('selected_runtime_executions')) is int
                        and row['selected_runtime_executions'] == 0, 'project_refusal_executed')
            else:
                require(row.get('cleanup') in ('owned_state_removed', 'owned_processes_stopped_audit_retained') and
                        row.get('process_cleanup', {}).get('all_stopped') is True and
                        row.get('process_cleanup', {}).get('remaining') == [] and
                        type(row.get('outside_reads')) is int and row['outside_reads'] == 0 and
                        type(row.get('forbidden_network_deliveries')) is int and
                        row['forbidden_network_deliveries'] == 0 and
                        row.get('worktree_index_head_config_unchanged') is True and
                        row.get('untracked_preserved') is True, 'project_independent_witness_missing')
                if row['case'] in ('initial', 'operator-edit', 'recovery'):
                    require(row.get('useful_original_results') == 7 and row.get('refused_results') == 5 and
                            row.get('ordinary_followup_results') == 2 and
                            row.get('project_fixture_sha256') == project_identity(name), 'project_utility_missing')
        by = {r['case']: r for r in rows}
        for area, names in [('install-start', expected[:4]),
                            ('useful-workflows', ('initial', 'operator-edit', 'recovery')),
                            ('refusal-zero-effects', ('initial', 'operator-edit', 'recovery')),
                            ('daemon-loss', ('daemon-loss', 'recovery')),
                            ('cancellation-cleanup', ('cancel',))]:
            observations.append(observation(area, sum(by.get(n, {}).get('status') == 'passed' for n in names),
                                            len(names), {'project': name, 'cases': list(names)}))
    elif version == 'sw-prepared-pilot-acceptance/1':
        kind = 'prepared'
        require(report.get('provider') == 'owned-scripted-loopback' and
                report.get('live_model_effectiveness') == 'not_tested', 'scope_mismatch')
        before = report_source(report['source_before'])
        rows = report['cases']
        expected = ('plan', 'occupied-port', 'stale-source', 'changed-selection', 'useful-refusal',
                    'ask', 'default', 'cancel', 'daemon-loss', 'host-crash', 'timeout')
        with_provider = expected[:4] + ('provider-unavailable',) + expected[4:]
        require([r['case'] for r in rows] in (list(expected), list(with_provider)), 'prepared_case_denominator_changed')
        require(all(r['status'] in ('passed', 'failed', 'incomplete', 'unsupported') for r in rows),
                'invalid_prepared_status')
        require((report['status'] == 'passed') == all(r['status'] == 'passed' for r in rows),
                'prepared_summary_mismatch')
        if report['status'] == 'passed':
            require(all(report.get(k) is True for k in ('workspace_unchanged', 'selected_assets_unchanged',
                                                       'unrelated_preserved')), 'prepared_integrity_missing')
        for row in rows:
            if row['status'] == 'passed':
                digest(row.get('trace_sha256'), 'prepared_trace')
                if row['case'] in ('useful-refusal', 'ask', 'default', 'cancel', 'daemon-loss', 'host-crash', 'timeout'):
                    require(row.get('cleanup') in ('owned_state_removed', 'owned_processes_stopped_audit_retained') and
                            row.get('process_cleanup', {}).get('all_stopped') is True and
                            row.get('process_cleanup', {}).get('remaining') == [], 'prepared_cleanup_missing')
        by = {r['case']: r for r in rows}
        for area, names in [('install-start', ('plan', 'useful-refusal', 'default')),
                            ('daemon-loss', ('daemon-loss',)),
                            ('cancellation-cleanup', ('cancel', 'host-crash', 'timeout'))]:
            observations.append(observation(area, sum(by[n]['status'] == 'passed' for n in names),
                                            len(names), {'cases': list(names)}))
    elif version == 'sw-pilot-ask-acceptance/1':
        kind = 'ask'
        require(report.get('real_host_executed') is True and report.get('scripted_owned_provider') is True
                and type(report.get('paid_api_calls')) is int and report['paid_api_calls'] == 0,
                'scope_mismatch')
        before = report_source(report['source'])
        rows = report['cases']
        require(type(rows) is list and 1 <= len(rows) <= 64, 'ask_case_bound')
        keys = [(r['profile'], r['case']) for r in rows]
        expected = [(profile, case) for profile in ('git', 'filesystem') for case in
                    (('expire', 'restart', 'approve', 'reject', 'cancel', 'approved_cancel', 'default')
                     + (('collector_term',) if profile == 'git' else ()))]
        require(keys == expected, 'ask_case_denominator_changed')
        require(len(set(keys)) == len(keys) and all(type(r['passed']) is bool for r in rows),
                'invalid_ask_cases')
        require((report['status'] == 'pass') == all(r['passed'] for r in rows), 'ask_summary_mismatch')
        for row in rows:
            if row['passed']:
                if row['case'] != 'default' and 'first_pending_bound_ms' in row:
                    elapsed = row.get('first_pending_ms')
                    require(row['first_pending_bound_ms'] == 5000 and row.get('first_pending_bound_met') is True
                            and type(elapsed) in (int, float) and math.isfinite(elapsed)
                            and 0 <= elapsed <= 5000, 'ask_first_pending_bound_missing')
                digest(row.get('policy_sha256'), 'ask_policy')
                if row['case'] not in ('restart', 'cancel', 'approved_cancel', 'collector_term'):
                    digest(row.get('trace_sha256'), 'ask_trace')
                if row['case'] == 'collector_term':
                    require(row.get('collector_sigterm') == 'pidfd_pinned_graceful_cleanup_confirmed'
                            and row.get('released') is False, 'ask_collector_cleanup_missing')
                expected_effects = 1 if row['case'] == 'approve' else 0
                require(type(row.get('dispatched')) is int and type(row.get('kernel_effects')) is int
                        and row['dispatched'] == row['kernel_effects'] == expected_effects,
                        'ask_effect_witness_mismatch')
                require(row.get('cleanup', {}).get('all_stopped') is True and
                        row.get('cleanup', {}).get('remaining') == [], 'ask_cleanup_missing')
        observations.append(observation('ask', sum(r['passed'] for r in rows), len(rows),
            {'physical_human_presence_proven': report.get('physical_human_presence_proven') is True}))
    else:
        raise Invalid('unsupported_report_schema')
    original = report['identity']['source'] if kind == 'matched' else report['source_before'] if kind in ('prepared', 'installed') else report['source']
    require(original == report['source_after'] and before == report_source(report['source_after']),
            'source_changed_during_run')
    return kind, before, identities(report, kind), observations


def validate_manifest(m):
    scoped = m.get('format') == 'sw-pilot-dossier-selection/2'
    exact(m, {'format', 'scope', 'candidate', 'environment', 'identities', 'support_index',
              'workload', 'evidence', 'accepted_main'} | ({'runtime_plan'} if scoped else set()), 'manifest')
    require(m['format'] in ('sw-pilot-dossier-selection/1', 'sw-pilot-dossier-selection/2')
            and m['scope'] == SCOPE, 'selection_scope')
    exact(m['candidate'], {'commit', 'tree'}, 'candidate')
    source(m['candidate']['commit'], 'candidate_commit'); source(m['candidate']['tree'], 'candidate_tree')
    source(m['accepted_main'], 'accepted_main', optional=True)
    exact(m['environment'], {'platform', 'architecture', 'host', 'provider', 'transport',
                              'distribution', 'kernel_release'}, 'environment')
    for key in ('distribution', 'kernel_release'):
        if m['environment'][key] is not None:
            word(m['environment'][key], key, limit=160)
    require(m['environment']['platform'] in ('linux', 'wsl2'), 'selected_platform_unsupported')
    require(m['environment']['architecture'] == 'x86_64' and m['environment']['transport'] == 'stdio'
            and m['environment']['provider'] == 'owned-scripted-loopback'
            and m['environment']['host'] == 'Claude Code 2.1.251', 'unsupported_environment')
    exact(m['identities'], set(RUNTIME.BINARY_ROLES if scoped else IDENTITIES), 'identities')
    for key, value in m['identities'].items(): digest(value, key, optional=not scoped)
    if scoped:
        validate_reference(m['runtime_plan'])
    require(type(m['evidence']) is list and len(m['evidence']) <= 16, 'evidence_count_limit')
    validate_reference(m['support_index'])
    validate_reference(m['workload'])
    seen, stages = set(), set()
    for e in m['evidence']:
        fields = {'id', 'file', 'scope', 'owner', 'role'}
        if scoped and e['role'] == 'candidate':
            exact(e, fields | {'context', 'stage', 'identity_context'}, 'scoped_evidence')
            require(e['stage'] in RUNTIME.STAGES and e['stage'] not in stages, 'runtime_stage_unknown_or_duplicate')
            stages.add(e['stage'])
            validate_reference(e['identity_context'])
        else:
            require(set(e) in (fields, fields | {'context'}), 'evidence_fields')
        if 'context' in e:
            require(e['role'] == 'candidate', 'historical_context_refused')
            validate_reference(e['context'])
        require(e['role'] in ('candidate', 'history'), 'invalid_evidence_role')
        identifier(e['id'], 'evidence_id'); identifier(e['owner'], 'owner')
        validate_reference(e['file'])
        require(e['id'] not in seen and e['scope'] == SCOPE, 'duplicate_id_or_scope_mismatch')
        seen.add(e['id'])
    if scoped:
        require(stages == set(RUNTIME.STAGES), 'runtime_stage_inventory_incomplete')
    return m


def linked_environment(root, entry, original_raw, before):
    """Explicit hash-bound custodian context; never replace a runtime verdict."""
    raw = selected_bytes(root, entry['context'])
    context = parse(raw)
    require(context.get('format') in ('sw-pilot-readiness-execution/1', 'sw-pilot-readiness-execution/2')
            and context.get('decision') == 'NOT_READY', 'unsupported_execution_context')
    require(report_source(context['source_before']) == before
            and context['source_before'] == context['source_after'], 'context_source_mismatch')
    rows = [row for row in context['stages'] if row.get('report_sha256') == sha(original_raw)]
    require(len(rows) == 1 and rows[0].get('status') == 'executed', 'context_report_link_missing')
    cleanup = rows[0].get('independent_namespace_cleanup', {})
    require(cleanup.get('all_stopped') is True and cleanup.get('remaining') == [],
            'context_cleanup_unconfirmed')
    return context['environment'], sha(raw)


def build(m, root, repo):
    validate_manifest(m)
    scoped = m['format'] == 'sw-pilot-dossier-selection/2'
    plan = None
    if scoped:
        plan_raw = selected_bytes(root, m['runtime_plan'])
        plan = RUNTIME.parse(plan_raw)
        exact_source = dict(m['candidate'], dirty=False,
                            files_sha256=git_files_digest(repo, m['candidate']['commit']))
        RUNTIME.verify_plan(plan, exact_source,
                            lambda name: git_bytes(repo, m['candidate']['commit'], name))
        for role, expected in m['identities'].items():
            RUNTIME.same_digest(plan['selected_sha256'][role], expected)
    require(git_tree(repo, m['candidate']['commit']) == m['candidate']['tree'], 'candidate_tree_mismatch')
    if m['accepted_main'] is not None:
        require(m['accepted_main'] == m['candidate']['commit'], 'accepted_source_not_candidate')
    index_raw = selected_bytes(root, m['support_index'])
    index = validate_index(parse(index_raw))
    workload_raw = selected_bytes(root, m['workload'])
    workload = parse(workload_raw)
    require(workload.get('format') == 'sw-installed-pilot-workload/1', 'unsupported_workload')
    published = git_json(repo, m['candidate']['commit'], 'docs/operations/roadmap-support-index.json')
    require(index == published, 'published_support_index_mismatch')
    require(workload == git_json(repo, m['candidate']['commit'],
            'scripts/benchmarks/installed-pilot-workload-v2.json'), 'published_workload_mismatch')
    caps = [c for c in index['capabilities'] if c['id'] in ('filesystem-linux', 'git-linux')]
    require(len(caps) == 2, 'missing_published_profile_definitions')
    records = []
    for entry in m['evidence']:
        record = {'id': entry['id'], 'owner': entry['owner'], 'file': entry['file'],
                  'source': None, 'identities': {}, 'observations': [], 'blockers': [], 'role': entry['role']}
        try:
            raw = selected_bytes(root, entry['file'])
            report = parse(raw)
            if entry['role'] == 'history':
                require(report.get('format') == 'sw-installed-pilot-matched/1', 'unsupported_history_schema')
                before = report_source(report['identity']['source'])
                require(git_tree(repo, before['commit']) == before['tree'], 'evidence_tree_mismatch')
                status = report.get('gate', {}).get('status', 'incomplete')
                require(status in ('passed', 'failed', 'incomplete'), 'invalid_historical_status')
                record.update(source=before, schema=report['format'], content_sha256=sha(raw),
                              reported_historical_status=status)
                record['blockers'].append('historical_attempt_not_candidate_evidence')
                records.append(record)
                continue
            kind, before, ids, obs = project(report, workload)
            record.update(schema=report.get('format', report.get('contract_version')), source=before,
                          identities=ids, observations=obs, content_sha256=sha(raw))
            require(git_tree(repo, before['commit']) == before['tree'], 'evidence_tree_mismatch')
            if before != m['candidate']: record['blockers'].append('historical_source')
            if scoped:
                require(kind == {'installed': 'installed', 'matched': 'matched', 'ask': 'ask',
                    'prepared': 'prepared', 'docs-code': 'existing', 'unicode-spaces': 'existing',
                    'local-history': 'existing'}[entry['stage']], 'runtime_stage_report_kind_mismatch')
                if kind == 'existing':
                    require(report.get('project_fixture') == entry['stage'], 'runtime_project_stage_mismatch')
                require(before == m['candidate'], 'runtime_evidence_source_mismatch')
                context = parse(selected_bytes(root, entry['context']))
                require(context.get('format') == 'sw-pilot-readiness-execution/2', 'runtime_execution_context_required')
                require(context.get('source_before') == context.get('source_after') == plan['source'],
                        'runtime_execution_source_conflict')
                RUNTIME.same_digest(context['runtime_plan_sha256'], RUNTIME.sha(RUNTIME.canonical(plan)))
                require(tuple(row['id'] for row in context['stages']) == RUNTIME.STAGES,
                        'runtime_execution_inventory_mismatch')
                row = next(row for row in context['stages'] if row['id'] == entry['stage'])
                require(row.get('identity_status') == 'verified', 'runtime_execution_identity_unconfirmed')
                RUNTIME.same_digest(row['report_sha256'], sha(raw))
                witness_raw = selected_bytes(root, entry['identity_context'])
                RUNTIME.same_digest(row['identity_report_sha256'], sha(witness_raw))
                witness = RUNTIME.parse(witness_raw)
                bindings = RUNTIME.verify_stage(plan, entry['stage'], witness, report,
                    sha(raw), row['independent_namespace_cleanup'])
                record['identities'] = {item['scope']: item['identities'] for item in bindings}
                record['identity_contract'] = 'sw-pilot-runtime-claims/1'
            else:
                record['blockers'].append('legacy_identity_contract_unqualified')
                for key in IDENTITIES:
                    if ids[key] is None or m['identities'][key] is None:
                        record['blockers'].append('missing_identity:' + key)
                    elif ids[key] != m['identities'][key]: record['blockers'].append('identity_mismatch:' + key)
            # Existing schemas often omit an environment record. Never infer it
            # from a filename, the reporter's OS, or a Linux-only code path.
            if any(v is None for v in m['environment'].values()):
                record['blockers'].append('expected_environment_unbound')
            environment = report.get('environment')
            if 'context' in entry:
                linked, context_sha = linked_environment(root, entry, raw, before)
                if environment is not None:
                    legacy = type(environment) is dict and set(environment) == {'os', 'machine', 'kernel', 'python'}
                    require(environment == linked or (legacy and environment['os'] == 'Linux'
                        and environment['machine'] == linked['architecture']
                        and environment['kernel'] == linked['kernel_release']), 'context_environment_conflict')
                environment = linked
                record['execution_context_sha256'] = context_sha
            if environment != m['environment']:
                record['blockers'].append('environment_absent_or_mismatched')
        except (Invalid, Failure, KeyError, TypeError, ValueError, OSError,
                subprocess.SubprocessError) as exc:
            code = str(exc) if isinstance(exc, (Invalid, Failure)) and re.fullmatch(r'[A-Za-z0-9_:. -]{1,160}', str(exc)) else type(exc).__name__
            record['blockers'].append('invalid_evidence:' + code)
        records.append(record)
    ledger = []
    for area in AREAS:
        observations = []
        for record in records:
            for obs in record['observations']:
                if obs['area'] == area:
                    observations.append(dict(obs, evidence=record['id'], source=record['source'],
                        eligible=not record['blockers'], blockers=record['blockers']))
        current = [o for o in observations if o['eligible']]
        status = 'incomplete'
        if current:
            status = 'fail' if any(o['observed_status'] == 'fail' for o in current) else (
                'pass' if all(o['observed_status'] == 'pass' for o in current) else 'incomplete')
        # Preserve a failed historical measurement visibly, never turn it into
        # a current success. A separately selected exact current run can resolve it.
        if not current and any(o['observed_status'] == 'fail' for o in observations): status = 'fail'
        reasons = sorted({b for o in observations for b in o['blockers']})
        if not observations: reasons.append('missing_selected_evidence')
        if area == 'linux-platform':
            status = 'pass' if all(c['support'] == 'supported' for c in caps) and any(
                not r['blockers'] for r in records) and m['environment']['platform'] == 'linux' else 'incomplete'
            reasons = [] if status == 'pass' else ['no_exact_bound_linux_runtime_evidence']
        if area == 'wsl-platform':
            # The published index does not qualify a WSL environment for this
            # combined pilot. A Linux result cannot stand in for one.
            status = 'incomplete'; reasons = ['wsl_not_qualified_by_selected_support_index']
        ledger.append({'item': area, 'status': status, 'owner': OWNERS[area],
                       'observations': observations, 'reasons': reasons,
                       'counts': current[0]['counts'] if len(current) == 1 else None})
    required = [r for r in ledger if r['item'] != ('wsl-platform' if m['environment']['platform'] == 'linux' else 'linux-platform')]
    ready = all(r['status'] == 'pass' for r in required) and all(
        not r['blockers'] for r in records if r['role'] == 'candidate') and not any(
        any(b.startswith('invalid_evidence:') for b in r['blockers']) for r in records)
    return {'format': 'sw-pilot-dossier/2' if scoped else VERSION, 'scope': SCOPE, 'candidate': m['candidate'],
            'accepted_main_declared': m['accepted_main'], 'status': 'READY' if ready else 'NOT_READY',
            'meaning': 'evidence completeness only; TL decision, CI admission and release excluded',
            'environment': m['environment'], 'selected_identities': m['identities'],
            'support_index_sha256': sha(index_raw), 'support': caps,
            'workload_sha256': sha(workload_raw), 'evidence': records, 'ledger': ledger,
            'live_model_effectiveness': 'not_measured', 'phase4_acceptance': False,
            'public_release': False, 'unsupported_scopes': [
                {'scope': 'native-Windows-and-macOS-combined-pilot', 'status': 'unsupported',
                 'reason': 'outside selected filesystem-linux/git-linux capabilities'},
                {'scope': 'live-model-effectiveness', 'status': 'unsupported',
                 'reason': 'scripted-provider evidence only'}]}


def scorecard(report):
    lines = ['# Internal pilot evidence dossier', '', f"Status: **{report['status']}**",
             '', 'Candidate: `' + report['candidate']['commit'] + '`',
             'Tree: `' + report['candidate']['tree'] + '`', '',
             'This is evidence reconciliation, not product approval or live-model effectiveness.', '',
             '| Item | State | Owner | Observations (actual source and denominator) |',
             '| --- | --- | --- | --- |']
    for row in report['ledger']:
        obs = '; '.join(f"{o['evidence']}: {o['observed_status']} {o['counts']['passed']}/{o['counts']['required']} at {o['source']['commit']}" for o in row['observations']) or 'No qualified observation'
        lines.append(f"| {row['item']} | {row['status']} | {row['owner']} | {obs} |")
    lines += ['', '## Blockers and root-cause references', '']
    for r in report['evidence']:
        lines.append('- `' + r['id'] + '` (selected file `' + r['file']['path'] + '`): ' +
                     (', '.join(r['blockers']) or 'identities match'))
    for row in report['ledger']:
        if row['status'] != 'pass': lines.append('- ' + row['item'] + ': ' + ', '.join(row['reasons']))
    for row in report['ledger']:
        for obs in row['observations']:
            if obs['details']:
                lines.append('- ' + obs['evidence'] + ' / ' + row['item'] + ': `' +
                             json.dumps(obs['details'], sort_keys=True) + '`')
    lines += ['', 'Historical failed attempts remain selected records; later evidence never overwrites them.',
              'A passing reporter test is not a passing pilot. Missing environment/identity evidence stays incomplete.',
              'Linux evidence does not qualify WSL, Windows or macOS. No paid model or release claim.', '']
    return '\n'.join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selection', required=True, type=Path)
    p.add_argument('--root', required=True, type=Path, help='base for explicitly selected files only')
    p.add_argument('--repo', required=True, type=Path)
    p.add_argument('--candidate', required=True, help='full candidate SHA; must match selection')
    p.add_argument('--output', required=True, type=Path, help='new output directory')
    args = p.parse_args(argv)
    try:
        m, manifest_sha = load_json(args.selection, 128 * 1024)
        source(args.candidate, 'candidate')
        require(m.get('candidate', {}).get('commit') == args.candidate, 'selected_candidate_mismatch')
        report = build(m, args.root, args.repo)
        report['selection_sha256'] = manifest_sha
        report['reporter_sha256'] = sha(safe_file(Path(__file__), MAX_REPORT))
        report['reporter_dependencies'] = {name: sha(safe_file(Path(__file__).parent / name, MAX_REPORT))
            for name in ('pilot_qualification.py', 'roadmap_support.py', 'pilot_runtime_identity.py',
                         'pilot_project_fixtures.py', 'benchmarks/agentdojo_protocol.py')}
        report['reporter_accepted_sha'] = None
        payload = (json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()
        require(len(payload) <= MAX_REPORT, 'dossier_output_bound')
        for parent in (args.output.absolute().parent, *args.output.absolute().parent.parents):
            require(parent.is_dir() and not parent.is_symlink() and
                    not (getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400),
                    'output_parent_required')
        args.output.mkdir(mode=0o700, exist_ok=False)
        write_private(args.output, 'dossier.json', payload)
        write_private(args.output, 'scorecard.md', scorecard(report).encode())
        print(report['status'] + ': dossier.json and scorecard.md written; no runtime executed')
        return 0 if report['status'] == 'READY' else 1
    except (Invalid, Failure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        # Never echo raw report content, filesystem paths or subprocess stderr.
        print('pilot-dossier: ' + (str(exc) if isinstance(exc, (Invalid, Failure)) else type(exc).__name__), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
