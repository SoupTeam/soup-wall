# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ask_series', ROOT / 'scripts/qualify-ask-series.py')
SERIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERIES)


def case(profile, index, ms, passed=True):
    return {'profile': profile, 'case': 'approve', 'sample_index': index, 'passed': passed, 'approved': True,
            'released': True, 'dispatched': 1, 'kernel_effects': 1, 'decision_to_result_ms': ms,
            'verified_inputs_resume': {'immutable_files': 0, 'leased_files': 5, 'rehashed_files': 9}}


def qualification(fs_ms, git_ms, status='pass', passed=True):
    cases = [case('git', i, ms, passed) for i, ms in enumerate(git_ms)]
    cases += [case('filesystem', i, ms) for i, ms in enumerate(fs_ms)]
    return {'status': status, 'cases': cases}


def stage(profile, name, ms):
    return {'event': SERIES.STAGE_EVENT, 'profile': 'sw-mcp/%s-readonly/1' % profile, 'stage': name, 'elapsed_ms': ms}


class PlanAndMath(unittest.TestCase):
    def test_plan_declaration(self):
        self.assertEqual(SERIES.parse_plan('cold,warm,cold'), ['cold', 'warm', 'cold'])
        for bad in ('warm,cold', 'cold,hot', '', 'cold,' + ','.join(['warm'] * 6)):
            with self.assertRaises(ValueError):
                SERIES.parse_plan(bad)

    def test_nearest_rank_keeps_worst(self):
        values = list(range(1, 21))
        self.assertEqual(SERIES.nearest_rank(values, .5), 10)
        self.assertEqual(SERIES.nearest_rank(values, .95), 19)
        self.assertEqual(SERIES.distribution(values)['worst'], 20)
        self.assertEqual(SERIES.distribution([])['p95'], None)


class Watching(unittest.TestCase):
    def test_only_real_events_from_harness_logs_are_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            launch = Path(directory) / 'sou112-private-x' / 'a'
            launch.mkdir(parents=True)
            good = json.dumps(stage('git', 'package_tree', 12.5))
            escaped = json.dumps({'write': good})
            (launch / 'host.stderr.private').write_bytes(
                (escaped + '\n' + good + '\n{"event":"unrelated"}\npartial').encode())
            (launch / 'trace.private').write_text(good + '\n')
            sink = io.StringIO()
            watcher = SERIES.Watcher(str(Path(directory) / '**' / '*.private'), sink)
            watcher.sweep()
            rows = [json.loads(line) for line in sink.getvalue().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['event']['stage'], 'package_tree')
            with (launch / 'host.stderr.private').open('ab') as stream:
                stream.write(b' tail\n' + good.encode() + b'\n')
            watcher.sweep()
            self.assertEqual(len(sink.getvalue().splitlines()), 2)


class ReadingEvents(unittest.TestCase):
    def test_tab_separated_rows_group_by_source_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.tsv'
            lines = []
            for source in ('/x/a/host.stderr.private', '/x/b/host.stderr.private'):
                for _ in range(2):
                    lines.append(source + '\t' + json.dumps(stage('git', 'package_tree', 10)))
            lines.append('/x/a/trace.private\t' + json.dumps({'write': 'timing'}))
            path.write_text('\n'.join(lines) + '\n')
            rows = SERIES.read_events(path)
            self.assertEqual([r['launch'] for r in rows], [0, 0, 1, 1])
            passes = SERIES.stage_distributions(rows)['asset_verification_by_pass']['git']['package_tree']
            self.assertEqual(sorted(passes), ['pass_1', 'pass_2'])
            self.assertEqual(passes['pass_1']['n'], 2)


def diagnostics(first=100, second=80, approval=50):
    timings = [{'event': SERIES.STAGE_EVENT, 'stage': 'runtime_and_libraries', 'elapsed_ms': 5},
               {'event': SERIES.STAGE_EVENT, 'stage': 'package_tree', 'elapsed_ms': first},
               {'event': SERIES.STAGE_EVENT, 'stage': 'selected_profile', 'elapsed_ms': 1},
               {'event': SERIES.STAGE_EVENT, 'stage': 'runtime_and_libraries', 'elapsed_ms': 4},
               {'event': SERIES.STAGE_EVENT, 'stage': 'package_tree', 'elapsed_ms': second}]
    total = 0
    for stage_name in ('profile_and_assets', 'classifier', 'result_inspection'):
        total += approval
        timings.append({'event': 'mcp_real_approval_timing', 'stage': stage_name, 'stage_ms': approval, 'post_observed_ms': total})
    return {'diagnostic_timings': timings}


class Diagnostics(unittest.TestCase):
    def cases(self):
        rows = qualification([2000] * 20, [2300] * 20)['cases']
        for index, row in enumerate(rows):
            row['verified_inputs_resume'] = diagnostics(first=100 + index)
        return rows

    def test_first_pending_is_the_sum_of_pass_one_and_passes_are_kept_apart(self):
        samples = SERIES.diagnostic_samples(self.cases())
        self.assertEqual(len(samples), 40)
        first = samples[0]
        self.assertEqual(first['first_pending_asset_verification_ms'], 5 + first['assets_ms']['package_tree/pass_1'] + 1)
        self.assertEqual(first['assets_ms']['package_tree/pass_2'], 80)
        self.assertEqual(first['post_observed_ms'], 150)

    def test_distributions_per_profile_with_stage_and_pass(self):
        out = SERIES.diagnostic_distributions(SERIES.diagnostic_samples(self.cases()))
        git = out['git']
        self.assertEqual(git['trials_with_diagnostics'], 20)
        self.assertEqual(git['asset_verification_ms']['package_tree']['pass_2']['p95'], 80)
        self.assertEqual(git['approval_stage_ms']['classifier']['worst'], 50)
        self.assertEqual(git['post_observed_total_ms']['p50'], 150)

    def test_failed_and_malformed_trials_are_not_counted_as_diagnostics(self):
        rows = self.cases()
        rows[0]['passed'] = False
        rows[1]['verified_inputs_resume'] = {'diagnostic_timings': 'broken'}
        rows[2]['verified_inputs_resume']['diagnostic_timings'][1]['elapsed_ms'] = float('nan')
        samples = SERIES.diagnostic_samples(rows)
        self.assertEqual(len(samples), 38)
        bad = [s for s in samples if s['sample_index'] == rows[2]['sample_index'] and s['profile'] == rows[2]['profile']][0]
        self.assertNotIn('package_tree/pass_1', bad['assets_ms'])
        self.assertEqual(bad['assets_ms']['package_tree/pass_2'], 80)
        self.assertIsNone(bad['first_pending_asset_verification_ms'])

    def test_pool_aggregates_diagnostics_only_for_effective_kinds(self):
        summary = SERIES.run_summary({'status': 'pass', 'cases': self.cases()}, 20, [])
        runs = [{'index': 1, 'effective_kind': 'cold', 'validated': True, 'summary': summary},
                {'index': 2, 'effective_kind': 'cold_unavailable', 'validated': True, 'summary': summary}]
        pooled = SERIES.pool(runs, 20)
        self.assertEqual(pooled['cold']['diagnostics']['git']['trials_with_diagnostics'], 20)
        self.assertEqual(pooled['warm']['diagnostics'], {})


class Summaries(unittest.TestCase):
    def test_stage_passes_and_first_pass_proxy(self):
        rows = []
        for launch in (0, 1):
            for number, extra in enumerate((0, 100)):
                rows.append({'launch': launch, 'event': stage('git', 'package_tree', 1000 + extra + launch)})
                rows.append({'launch': launch, 'event': stage('git', 'runtime_and_libraries', 50 + extra)})
        out = SERIES.stage_distributions(rows)
        passes = out['asset_verification_by_pass']['git']['package_tree']
        self.assertEqual(passes['pass_1']['n'], 2)
        self.assertEqual(passes['pass_2']['worst'], 1101)
        proxy = out['first_pass_asset_verification_total_ms_proxy']['git']
        self.assertEqual((proxy['n'], proxy['worst']), (2, 1051))

    def test_run_summary_reports_blocker_without_dropping_trials(self):
        data = qualification([2000] * 20, [2300] * 14 + [4500] * 6, status='performance_blocker')
        summary = SERIES.run_summary(data, 20, [])
        self.assertFalse(summary['latency']['git']['target_met'])
        self.assertEqual(len(summary['trials']['git']['continuation_ms_by_trial']), 20)
        self.assertEqual(summary['latency']['git']['failed'], 0)

    def test_failed_trials_stay_in_denominator(self):
        data = qualification([2000] * 20, [2300] * 20, passed=False)
        summary = SERIES.run_summary(data, 20, [])
        self.assertEqual((summary['latency']['git']['successful'], summary['latency']['git']['failed']), (0, 20))

    def test_pool_counts_only_effective_kinds(self):
        good = SERIES.run_summary(qualification([2000] * 20, [2300] * 20), 20, [])
        runs = [{'index': 1, 'effective_kind': 'cold', 'validated': True, 'summary': good},
                {'index': 2, 'effective_kind': 'cold_unavailable', 'validated': True, 'summary': good},
                {'index': 3, 'effective_kind': 'warm', 'validated': True, 'summary': good}]
        pooled = SERIES.pool(runs, 20)
        self.assertEqual(pooled['cold']['runs_counted'], [1])
        self.assertEqual(pooled['warm']['git']['planned'], 20)
        self.assertEqual(pooled['cold']['git']['continuation_ms']['n'], 20)

    def test_series_status_is_incomplete_for_unavailable_cold_or_unvalidated(self):
        good = SERIES.run_summary(qualification([2000] * 20, [2300] * 20), 20, [])
        ok = {'effective_kind': 'cold', 'validated': True, 'summary': good}
        self.assertEqual(SERIES.series_status(['cold'], [ok], 20), 'complete')
        self.assertEqual(SERIES.series_status(['cold'], [dict(ok, effective_kind='cold_unavailable')], 20), 'incomplete')
        self.assertEqual(SERIES.series_status(['cold'], [dict(ok, validated=False)], 20), 'incomplete')
        self.assertEqual(SERIES.series_status(['cold', 'warm'], [ok], 20), 'incomplete')

    def test_series_status_requires_successful_execution_not_only_a_valid_report(self):
        good = SERIES.run_summary(qualification([2000] * 20, [2300] * 20), 20, [])
        ok = {'effective_kind': 'cold', 'validated': True, 'exit_code': 0, 'failure': None, 'summary': good}
        self.assertEqual(SERIES.series_status(['cold'], [ok], 20), 'complete')
        failed = dict(ok, exit_code=17, failure='owned_harness_failed_after_report')
        self.assertEqual(SERIES.series_status(['cold'], [failed], 20), 'incomplete')
        self.assertEqual(SERIES.series_status(['cold'], [dict(ok, failure='timeout')], 20), 'incomplete')
        self.assertEqual(SERIES.series_status(['cold'], [dict(ok, validation_error='qualification_source_mismatch')], 20),
                         'incomplete')

    def test_pool_gates_on_validation_and_keeps_unqualified_attempts_visible(self):
        good = SERIES.run_summary(qualification([2000] * 20, [2300] * 20), 20, [])
        slow = SERIES.run_summary(qualification([2000] * 20, [2300] * 14 + [4500] * 6), 20, [])
        valid = {'index': 1, 'effective_kind': 'cold', 'validated': True, 'exit_code': 0, 'failure': None, 'summary': good}
        stale = {'index': 2, 'effective_kind': 'cold', 'validated': False, 'validation_error': 'qualification_source_mismatch',
                 'exit_code': 0, 'failure': None, 'summary': good}
        failed = {'index': 3, 'effective_kind': 'cold', 'validated': True, 'exit_code': 17,
                  'failure': 'owned_harness_failed_after_report', 'summary': slow}
        pooled = SERIES.pool([valid, stale, failed], 20)['cold']
        self.assertEqual(pooled['runs_counted'], [1])
        self.assertEqual(pooled['git']['planned'], 20)
        self.assertEqual(pooled['git']['continuation_ms']['n'], 20)
        self.assertEqual(pooled['git']['unqualified_totals'], {'planned': 40, 'successful': 40, 'failed': 0, 'incomplete': 0})
        self.assertEqual([r['reason'] for r in pooled['unqualified_runs']],
                         ['report_not_valid_for_this_source', 'execution_failed'])
        self.assertFalse(pooled['all_attempts_qualified'])
        only_stale = SERIES.pool([stale], 20)['cold']
        self.assertFalse(only_stale['git']['p95_target_met'])
        self.assertEqual(only_stale['git']['continuation_ms']['n'], 0)

    def test_first_trial_is_reported_apart_from_repetitions_and_cold_is_not_claimed(self):
        good = SERIES.run_summary(qualification([2000] * 20, [5000] + [2300] * 19), 20, [])
        run = {'index': 1, 'effective_kind': 'cold', 'validated': True, 'exit_code': 0, 'failure': None, 'summary': good}
        git = SERIES.pool([run], 20)['cold']['git']
        self.assertEqual(git['initial_trial_ms'], [{'run': 1, 'ms': 5000}])
        self.assertEqual(git['repeat_trials_ms']['n'], 19)
        self.assertEqual(git['repeat_trials_ms']['worst'], 2300)
        self.assertEqual(SERIES.pool([run], 20)['cold']['label'], 'post_cache_drop_setup_rewarmed')


class Orchestration(unittest.TestCase):
    def run_series(self, plan, drop_ok=True, fail_second=False, fail_after_report=False):
        calls = []

        class Failure(Exception):
            def __init__(self, reason, exit_code=None):
                super().__init__(reason)
                self.reason, self.exit_code = reason, exit_code

        def build(command, *, cwd, env, log, seconds, stage):
            calls.append(stage)
            out = Path(command[command.index('--output') + 1])
            out.mkdir(parents=True)
            private = Path(env['TMPDIR']) / 'sou112-private-t'
            private.mkdir()
            (private / 'host.stderr.private').write_text(json.dumps(stage_event()) + '\n')
            if fail_second and len(calls) == 2:
                raise Failure('series_2_timeout', None)
            (out / 'qualification.json').write_text(json.dumps(qualification([2000] * 20, [2400] * 20)))
            if fail_after_report and len(calls) == 2:
                raise Failure('owned_harness_failed_after_report', 17)

        def stage_event():
            return stage('git', 'package_tree', 1500)

        def fake_validate(report, source, selected, samples, candidate):
            return None

        stub = types.SimpleNamespace(
            require=lambda ok, code: None if ok else (_ for _ in ()).throw(ValueError(code)),
            source=lambda root, commit: {'commit': commit, 'tree': 't', 'dirty': False},
            sha=lambda path: 'h' + Path(path).name,
            json_file=lambda path: json.loads(Path(path).read_text()),
            validate_build=lambda *a: None, validate_report=fake_validate,
            NATIVE=types.SimpleNamespace(build=build, Failure=Failure))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tools = {}
            for name in SERIES.TOOLS:
                tools[name] = base / name
                tools[name].write_text('x')
            offline = base / 'offline'
            for sub in ('npm-cache', 'wheelhouse'):
                (offline / sub).mkdir(parents=True)
            (offline / 'python.tar.gz').write_text('x')
            args = types.SimpleNamespace(plan=plan, samples=20, output=base / 'out', private_root=base / 'private',
                                         expected_commit='a' * 40, offline_inputs=offline, receipt=None,
                                         require_verified_reuse=False, fail_on_blocker=False, run_timeout=60,
                                         qualifier=base / 'q.py', **tools)
            original = (SERIES.comparison, SERIES.drop_caches)
            SERIES.comparison = lambda: stub
            SERIES.drop_caches = lambda: {'requested': True, 'performed': drop_ok, 'error': None,
                                          'cached_kb_before': 9, 'cached_kb_after': 1}
            try:
                code = SERIES.execute(args)
            finally:
                SERIES.comparison, SERIES.drop_caches = original
            return code, json.loads((base / 'out' / 'summary.json').read_text()), \
                json.loads((base / 'out' / 'manifest.json').read_text()), (base / 'out' / 'runs').exists()

    def test_complete_series_records_plan_before_trials(self):
        code, summary, manifest, _ = self.run_series('cold,warm')
        self.assertEqual((code, summary['status']), (0, 'complete'))
        self.assertEqual(manifest['plan'], ['cold', 'warm'])
        self.assertFalse(manifest['cold_ask_trials_claimed'])
        self.assertEqual(manifest['cold_scope'], 'pre_run_cache_drop_only')
        self.assertEqual(summary['runs'][0]['cold_scope'], 'pre_run_cache_drop_only_setup_rewarmed')
        self.assertEqual(summary['attempts']['qualified_runs'], [1, 2])
        self.assertEqual(summary['pooled']['warm']['runs_counted'], [2])
        stages = summary['runs'][0]['summary']['stages']
        self.assertEqual(stages['events_seen'][SERIES.STAGE_EVENT], 1)

    def test_cold_without_proven_cache_drop_is_not_counted(self):
        code, summary, _, _ = self.run_series('cold,warm', drop_ok=False)
        self.assertEqual((code, summary['status']), (1, 'incomplete'))
        self.assertEqual(summary['pooled']['cold']['runs_counted'], [])
        self.assertEqual(summary['runs'][0]['effective_kind'], 'cold_unavailable')

    def test_failed_attempt_is_retained_and_series_incomplete(self):
        code, summary, _, _ = self.run_series('cold,warm', fail_second=True)
        self.assertEqual((code, summary['status']), (1, 'incomplete'))
        self.assertEqual(len(summary['runs']), 2)
        self.assertIn('timeout', summary['runs'][1]['failure'])

    def test_report_left_by_a_failed_subprocess_never_qualifies(self):
        code, summary, _, _ = self.run_series('cold,warm', fail_after_report=True)
        self.assertEqual((code, summary['status']), (1, 'incomplete'))
        second = summary['runs'][1]
        self.assertEqual((second['exit_code'], second['failure']), (17, 'owned_harness_failed_after_report'))
        self.assertFalse(second['validated'])
        self.assertEqual(second['validation_error'], 'report_left_by_failed_execution_not_trusted')
        self.assertIn('latency', second['summary'])
        self.assertEqual(summary['pooled']['warm']['runs_counted'], [])
        self.assertEqual(summary['pooled']['warm']['unqualified_runs'][0]['reason'], 'execution_failed')
        self.assertEqual(summary['pooled']['warm']['git']['unqualified_totals']['successful'], 20)
        self.assertEqual(summary['attempts']['unqualified_runs'], [{'index': 2, 'kind': 'warm', 'reason': 'execution_failed'}])


if __name__ == '__main__':
    unittest.main()
