# SPDX-License-Identifier: Apache-2.0
"""SOU-106 extension of the installed-pilot driver, not a separate host engine."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import platform
import tempfile
import time
from pilot_qualification import Failure, canonical, digest, matched_gate, new_report, require, sha

WORKLOAD = Path(__file__).parent / 'benchmarks/installed-pilot-workload-v2.json'


def load_workload(root):
    raw = WORKLOAD.read_bytes()
    require(len(raw) < 131072, 'workload_byte_bound')
    workload = json.loads(raw)
    require(workload['format'] == 'sw-installed-pilot-workload/1', 'workload_version')
    for kind, expected in workload['assets'].items():
        path = root / f'profiles/mcp/{kind}-readonly-v1/upstream-tools-list.json'
        require(digest(json.loads(path.read_bytes())) == expected['manifest_canonical_sha256'], 'original_schema_manifest_drift')
        tools = json.loads(path.read_bytes())['result']['tools']
        require({t['name']: digest(t['inputSchema']) for t in tools} == expected['schemas'], 'original_schema_drift')
    return workload


def run_matched(api, args):
    workload = load_workload(api.ROOT)
    args.output = args.output.resolve()
    require(not args.output.exists() and not args.output.is_relative_to(api.ROOT), 'new_external_output_required')
    args.output.mkdir(mode=0o700, parents=True)
    report = {'format': 'sw-installed-pilot-matched/1', 'workload_sha256': digest(workload),
              'workload_file_sha256': sha(WORKLOAD), 'required_pairs': len(workload['cases']),
              'required_arms': 2 * len(workload['cases']), 'conditions': workload['conditions'],
              'engineering_budgets': workload['engineering_budgets'], 'identity': {}, 'rows': [],
              'source_unchanged': False, 'cleanup': False, 'failures': [], 'live_model_effectiveness': 'not_measured', 'network_delivery': 'not_exercised_no_network_operations_in_workload'}
    for case in workload['cases']:
        for arm in ('control', 'protected'):
            report['rows'].append({'case': case['id'], 'arm': arm, 'status': 'incomplete',
                'reason': 'not_executed', 'operation_sha256': digest(case['batches']), 'identity': report['identity']})
    # Freeze the exact input before even reading candidate selection.
    api.owned_bytes(args.output / 'workload.json', canonical(workload) + b'\n')
    pilot = private = None
    paths = {}
    before = None
    previous_tools = api.TOOLS
    started = time.monotonic()
    try:
        require(args.selection.stat().st_size <= 65536, 'selection_byte_limit')
        selection = api.strict_json(args.selection.read_bytes())
        before, paths = api.validate_selection(selection, args.expected_commit)
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'linux_x86_64_required')
        api.TOOLS = {kind: tuple(sorted({tool for case in workload['cases'] for batch in case['batches']
            for server, tool, _ in batch if server == kind})) for kind in ('filesystem', 'git')}
        private = tempfile.TemporaryDirectory(prefix='sou106-pilot-')
        old_report = new_report()
        old_report['selected_sha256'] = {k: sha(v) for k,v in paths.items()}
        pilot = api.Pilot(Path(private.name), args.output, paths, old_report, selection['expected_refusal'])
        pilot.offline_inputs = getattr(args, "offline_inputs", None)
        version = api.subprocess.check_output([str(paths['claude']), '--version'], env=pilot.env, cwd=pilot.private, timeout=15, text=True).strip()
        package = json.loads((api.ROOT / 'profiles/mcp/filesystem-readonly-v1/claude-host/package.json').read_bytes())
        require(version == package['dependencies']['@anthropic-ai/claude-code'] + ' (Claude Code)', 'selected_host_version_changed')
        report['claude_version'] = version
        pilot.matched_workload = True
        pilot.retained_limit = 192  # Fixed 40-host bound; no unbounded log inventory.
        report['source_and_selection_verification_ms'] = round((time.monotonic() - started) * 1000, 3)
        asset_started = time.monotonic()
        prepared = pilot.prepare()
        report['asset_install_and_daemon_prepare_ms'] = round((time.monotonic() - asset_started) * 1000, 3)
        report['external_build_time'] = 'not_measured_prebuilt_selected_binaries'
        report['preparation_ms'] = round((time.monotonic() - started) * 1000, 3)
        report['identity'].update(source=before, selected=old_report['selected_sha256'], profiles=pilot.installed,
            registry_sha256=pilot.registry_sha256, policy_sha256=pilot.policy_sha256,
            model_script_sha256=digest(workload), driver_sha256=sha(Path(api.__file__)), extension_sha256=sha(__file__))
        report['preparation'] = prepared
        report['sandbox'] = pilot.sandbox()
        for case in workload['cases']:
            for arm in ('control', 'protected'):
                row = next(r for r in report['rows'] if r['case'] == case['id'] and r['arm'] == arm)
                execute_case(api, pilot, case, row)
                # Retain partial outcomes after each arm; the final gate is never inferred from this checkpoint.
                (args.output / 'progress.json').write_bytes(canonical(report) + b'\n')
                print(json.dumps({'case': case['id'], 'arm': arm, 'status': row['status'], 'reason': row.get('reason')}), flush=True)
                require(time.monotonic() - started <= 3000, 'overall_measurement_deadline')
                require(row.get('reason') != 'actual_host_incomplete', 'actual_host_unavailable_remaining_cases_incomplete')
    except (Exception, KeyboardInterrupt) as error:
        report['failures'].append(error.code if isinstance(error, Failure) else 'runtime_' + type(error).__name__.lower())
        if isinstance(error, KeyboardInterrupt):
            for row in report['rows']:
                if row['status'] == 'incomplete':
                    row['cancelled'] = True
    finally:
        try:
            if pilot:
                report['cleanup_evidence'] = pilot.cleanup()
                report['cleanup'] = True
            if private:
                private.cleanup()
            if before:
                report['source_after'] = api.source()
                report['source_unchanged'] = before == report['source_after'] and all(sha(p) == report['identity']['selected'][k] for k,p in paths.items())
        except Exception as error:
            report['failures'].append('cleanup_' + type(error).__name__.lower())
            report['cleanup'] = False
        api.TOOLS = previous_tools
    report['arm_counts'] = {state: sum(r['status'] == state for r in report['rows']) for state in ('passed', 'failed', 'incomplete')}
    try:
        report['gate'] = matched_gate(workload, report)
    except (Failure, ValueError, KeyError, TypeError) as error:
        report['gate'] = {'status': 'failed', 'failures': [error.code if isinstance(error, Failure) else 'invalid_gate_evidence']}
        api.owned_bytes(args.output / 'report.json', canonical(report) + b'\n')
        api.owned_bytes(args.output / 'scorecard.md', b'# Installed pilot development scorecard\n\nGate: failed. Invalid or incomplete evidence; see report.json. No effectiveness claim.\n')
        print(json.dumps(report['gate']))
        return 1
    if report['failures']:
        report['gate']['status'] = 'failed'
        report['gate']['failures'].extend(report['failures'])
    # Deliberately corrupt the pair list. This is labeled a gate fixture, never runtime evidence.
    broken = copy.deepcopy(report)
    broken['rows'].pop()
    try:
        matched_gate(workload, broken)
        raise Failure('broken_result_not_rejected')
    except Failure as error:
        require(error.code == 'missing_duplicate_or_reordered_pair', 'unexpected_gate_control')
        report['negative_gate_control'] = {'kind': 'deliberately-broken-result-fixture', 'reason': error.code, 'passed': True}
    require(len(canonical(report)) <= 2 * 1024 * 1024, 'matched_report_bound')
    api.owned_bytes(args.output / 'report.json', canonical(report) + b'\n')
    metrics = report['gate']['metrics']
    lines = ['# Installed pilot development scorecard', '', f"Gate: **{report['gate']['status']}**.", '',
             f"Supported benign workflows: {metrics['benign_completed']}/{metrics['benign_required']}.",
             f"Refusal variants required: {metrics['refusal_required']}; observed forbidden effects: {metrics['forbidden_effects']}.",
             f"Technical failures: {metrics['technical_failures']}; incomplete arms: {metrics['incomplete_arms']}.",
             '', 'Scripted provider only. No live-model effectiveness, consumption or Phase 4 acceptance claim.',
             '', '| Metric | Samples | p50 ms | p95 ms |', '|---|---:|---:|---:|']
    distributions = {'Benign protected minus control': metrics['benign_overhead_ms'],
                     'Refusal workflow protected minus control': metrics['refusal_workflow_overhead_ms']}
    for name in ('host_start_ms', 'first_batch_ms', 'steady_state_ms'):
        distributions.update({name + ':' + arm: value for arm,value in metrics[name].items()})
    for name, value in distributions.items():
        lines.append(f"| {name} | {value['n']} | {value['median']} | {value['p95']} |")
    lines += ['', f"Workload: `{report['workload_file_sha256']}`.",
              'Fresh host per arm; OS cache uncontrolled; control-first ordering may bias observed overhead.',
              'First-batch and steady-state timings include host/provider processing. Parallel calls share completion observation.',
              'Missing evidence remains failed/incomplete. See report.json for identities and failure inventory.']
    api.owned_bytes(args.output / 'scorecard.md', ('\n'.join(lines) + '\n').encode())
    print(json.dumps({'status': report['gate']['status'], 'metrics': metrics}))
    return 0 if report['gate']['status'] == 'passed' else 1


def execute_case(api, pilot, case, row):
    direct = row['arm'] == 'control'
    # Restore only explicitly owned fixture files/index. Never recursively remove a computed path.
    names = ['notes.txt', 'owned-new.txt', 'owned-unicode.txt', 'owned-a.txt', 'owned-b.txt']
    saved = {pilot.workspace / name: (pilot.workspace / name).read_bytes() if (pilot.workspace / name).exists() else None for name in names}
    index = pilot.git_workspace / '.git/index'
    saved[index] = index.read_bytes()
    before = {'filesystem': api.BASE.snapshot(pilot.workspace), 'git': api.BASE.snapshot(pilot.git_workspace)}
    row['input_sha256'] = digest(before)
    backups = {}
    if direct and case['kind'] == 'refusal':
        for number, (path, content) in enumerate(saved.items()):
            if content is not None:
                backup = pilot.private / (case['id'] + '-restore-' + str(number))
                os.link(path, backup)
                backups[path] = backup
    watch = None
    observed = {}
    try:
        if case['kind'] == 'refusal':
            kind = case['batches'][case['refused_batch']][0][0]
            watch = api.GIT.RepositoryWitness(pilot.workspace if kind == 'filesystem' else pilot.git_workspace / '.git')
        def boundary(batch, results):
            if case['kind'] != 'refusal':
                return
            if batch == case['refused_batch']:
                watch.drain()
            if batch == case['refused_batch'] + 1:
                observed['original_opens'] = watch.drain()
                after = {'filesystem': api.BASE.snapshot(pilot.workspace), 'git': api.BASE.snapshot(pilot.git_workspace)}
                observed['snapshot_before_sha256'] = digest(before)
                observed['snapshot_after_sha256'] = digest(after)
                observed['snapshot_evidence'] = pilot.retain_json(case['id'] + '-' + row['arm'] + '-snapshots.json', {'before': before, 'after': after})
                observed['effect_observed'] = any((p.read_bytes() if p.exists() else None) != value for p,value in saved.items())
        evidence, results = pilot.host(case['id'] + '-' + row['arm'], case['batches'], before_batch=boundary, direct=direct)
        row.update(actual_host=True, cleanup=evidence['process_cleanup']['all_stopped'],
                   latencies_ms=evidence['latencies_ms'], host_start_ms=evidence['host_start_ms'],
                   host_elapsed_ms=evidence['elapsed_ms'],
                   host_evidence=evidence['provider_result_evidence'], **observed)
        flat = [op for batch in case['batches'] for op in batch]
        normalized = {}
        for i, (kind, _, _) in enumerate(flat):
            item = results[f'toolu_pilot_{i}']
            if not item['is_error']:
                value = api.host_text(item, kind)
                normalized[str(i)] = value.replace(str(pilot.workspace_for(kind)), '/workspace')
        if case['kind'] == 'benign':
            row['false_interruption'] = any(r['is_error'] for r in results.values())
            require(not row['false_interruption'], 'supported_benign_interrupted')
            require(all(normalized.values()), 'empty_useful_result')
            for i, (_, tool, arguments) in enumerate(flat):
                require(useful_result(api, tool, arguments, normalized[str(i)]), 'source_expected_content_missing')
            row.update(all_results_useful=True, useful_continuation=True, normalized_results_sha256=digest(normalized))
            pilot.preserve()
        else:
            start = sum(len(b) for b in case['batches'][:case['refused_batch']])
            stop = start + len(case['batches'][case['refused_batch']])
            refused = [results[f'toolu_pilot_{i}'] for i in range(start,stop)]
            row['useful_continuation'] = all(not results[f'toolu_pilot_{i}']['is_error'] for i in range(stop,len(flat)))
            require(row['useful_continuation'], 'refusal_broke_useful_continuation')
            if direct:
                require(all(not r['is_error'] for r in refused) and observed.get('effect_observed') is True
                        and observed.get('original_opens', 0) > 0, 'original_effect_not_calibrated')
            else:
                row['explicit_refusal'] = all(r['is_error'] is True and 'explicitly unsupported in the read-only profile' in str(r['content']) for r in refused)
                require(row['explicit_refusal'], 'expected_profile_refusal_missing')
                require(observed.get('effect_observed') is False and observed.get('original_opens') == 0, 'forbidden_execution_or_effect')
                row['denied_execution_count'] = stop - start
                row['forbidden_result_delivery_count'] = sum(not r['is_error'] for r in refused)
                row['denied_result_delivery_count'] = stop - start
                pilot.preserve()
        row.update(status='passed', reason=None)
    except (Exception, KeyboardInterrupt) as error:
        row.update(status='incomplete' if isinstance(error, KeyboardInterrupt) else 'failed',
                   reason=error.code if isinstance(error, Failure) else 'runtime_' + type(error).__name__.lower(), **observed)
        if pilot.hosts and pilot.hosts[-1].get('provider_result_evidence', {}).get('file') == case['id'] + '-' + row['arm'] + '-provider-results.json':
            row['partial_host_evidence'] = pilot.hosts[-1]
        if isinstance(error, KeyboardInterrupt):
            row['cancelled'] = True
            raise
    finally:
        if watch:
            watch.close()
        if direct and case['kind'] == 'refusal':
            restore_control_files(saved, backups)
            require(api.BASE.snapshot(pilot.workspace) == before['filesystem'] and api.BASE.snapshot(pilot.git_workspace) == before['git'], 'control_fixture_restore_failed')


def restore_control_files(saved, backups):
    """Restore only caller-created owned fixture paths, including original inodes."""
    for path, content in saved.items():
        if content is None:
            if path.exists():
                path.unlink()
        else:
            os.replace(backups[path], path)
            # POSIX rename is a no-op when both names already refer to
            # the same inode. Remove that remaining owned hard link.
            if backups[path].exists():
                backups[path].unlink()
            path.write_bytes(content)


def useful_result(api, tool, arguments, value):
    """Source-based witnesses from the accepted owned fixtures, not model text."""
    if tool in ('read_text_file', 'read_file'):
        expected = api.BASE.TEXT if arguments['path'].endswith('guide.txt') else api.NOTES
        if 'head' in arguments:
            expected = '\n'.join(expected.split('\n')[:arguments['head']])
        elif 'tail' in arguments:
            expected = '\n'.join(expected.split('\n')[-arguments['tail']:])
        return value == expected
    if tool == 'read_multiple_files':
        return api.BASE.TEXT in value and api.NOTES in value
    if tool in ('list_directory', 'list_directory_with_sizes'):
        return 'guide.txt' in value and 'notes.txt' in value
    if tool == 'search_files':
        return '/workspace/notes.txt' in value and ('excludePatterns' not in arguments or '/workspace/source.txt' not in value)
    expected = dict((name, marker) for name, _, marker in api.GIT.READS)
    return tool in expected and expected[tool] in value
