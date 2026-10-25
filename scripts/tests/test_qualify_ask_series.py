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
        runs = [{'index': 1, 'effective_kind': 'cold', 'summary': good},
                {'index': 2, 'effective_kind': 'cold_unavailable', 'summary': good},
                {'index': 3, 'effective_kind': 'warm', 'summary': good}]
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


class Orchestration(unittest.TestCase):
    def run_series(self, plan, drop_ok=True, fail_second=False):
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


if __name__ == '__main__':
    unittest.main()
