# SPDX-License-Identifier: Apache-2.0
"""SOU-203 controls. Synthetic fixtures are labeled SYNTHETIC and are never native measurements;
genuine cases read the retained SOU-141 evidence unchanged."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_performance', ROOT / 'scripts/native_performance.py')
NP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NP)
EVIDENCE = ROOT / 'docs/operations/evidence/sou-141'
FINAL = (EVIDENCE / 'native-final-ask-series-summary.json', EVIDENCE / 'native-final-ask-series-manifest.json')
EARLIER = (EVIDENCE / 'native-ask-series-summary.json', EVIDENCE / 'native-ask-series-manifest.json')
ASK_REPORT = ROOT / 'docs/operations/evidence/sou-124/native-attempt2-baseline.json'
ASSETS = ('runtime_and_libraries', 'package_tree', 'selected_profile')
APPROVAL = ('profile_and_assets', 'policy_boundary', 'classifier', 'daemon_redemption', 'original_dispatch',
            'original_response', 'result_inspection')


def git(repo, *words):
    return subprocess.check_output(['git', '-C', str(repo), '-c', 'user.name=sou203-synthetic',
                                    '-c', 'user.email=synthetic@example.invalid', '-c', 'core.autocrlf=false',
                                    *words], timeout=30).decode().strip()


class Synthetic:
    """SYNTHETIC sw-ask-series/1 fixtures produced through the producer's own summary functions."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sou203-synthetic-')
        self.repo = Path(self.tmp.name) / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        for name in NP.HARNESS:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'# SYNTHETIC harness placeholder\n')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'synthetic source')
        self.git = NP.Git(self.repo)
        commit = git(self.repo, 'rev-parse', 'HEAD')
        self.source = {'commit': commit, 'tree': git(self.repo, 'rev-parse', 'HEAD^{tree}'), 'dirty': False,
                       'files_sha256': self.git.files_sha256(commit)}
        self.count = 0

    def close(self):
        self.tmp.cleanup()

    def cases(self, run, samples, offset, substitute=False):
        rows = []
        for profile in NP.PROFILES:
            for i in range(samples):
                value = 1000.0 + offset + (300.0 if profile == 'git' else 0.0) + i * 1.5 + run * 0.25
                timings = [{'event': 'mcp_asset_verification_timing', 'stage': s, 'elapsed_ms': e}
                           for s, e in zip(ASSETS, (60.0 + i, 500.0 + i, 0.5))]
                timings += [{'event': 'mcp_asset_verification_timing', 'stage': s, 'elapsed_ms': e}
                            for s, e in zip(ASSETS[:2], (10.0, 400.0 + i))]
                timings += [{'event': 'mcp_real_approval_timing', 'stage': s, 'stage_ms': 5.0 + k,
                             'post_observed_ms': 900.0 + i + k} for k, s in enumerate(APPROVAL)]
                if substitute:
                    value = sum(t['elapsed_ms'] for t in timings[:3])
                rows.append({'case': 'approve', 'profile': profile, 'sample_index': i, 'passed': True,
                             'approved': True, 'released': True, 'dispatched': 1, 'kernel_effects': 1,
                             'decision_to_result_ms': value,
                             'verified_inputs_resume': {'immutable_files': 0, 'leased_files': 1, 'rehashed_files': 2,
                                                        'observer': 'collector mcp_verified_inputs_resume',
                                                        'scope': 'completed_original_approval',
                                                        'diagnostic_timings': timings}})
        return rows

    def series(self, plan=('cold', 'warm'), samples=20, offset=0.0, mutate_cases=None, substitute=False,
               runs_recorded=None, mem=16000000):
        runs = []
        for index, kind in enumerate(plan[:runs_recorded], start=1):
            cases = self.cases(index, samples, offset, substitute)
            if mutate_cases:
                cases = mutate_cases(index, cases)
            qualification = {'status': 'pass', 'cases': cases, 'latency': NP.LATENCY.summarize(cases, samples)}
            record = {'index': index, 'declared_kind': kind, 'effective_kind': kind, 'validated': True,
                      'exit_code': 0, 'failure': None, 'wall_seconds': 60.0,
                      'conditions_before': {'cpu_count': 4, 'loadavg': ['1.0', '1.0', '1.0'],
                                            'meminfo': {'MemTotal_kb': mem, 'Cached_kb': 300000},
                                            'pressure': {'cpu': ['some avg10=1.00'], 'io': None, 'memory': None}}}
            if kind == 'cold':
                record['cache_drop'] = {'requested': True, 'performed': True, 'error': None,
                                        'cached_kb_before': 5000000, 'cached_kb_after': 300000}
                record['cold_scope'] = 'pre_run_cache_drop_only_setup_rewarmed'
            record['summary'] = NP.SERIES.run_summary(qualification, samples, [])
            runs.append(record)
        plan = list(plan)
        summary = {'format': NP.SERIES_FORMAT, 'status': NP.SERIES.series_status(plan, runs, samples),
                   'platform_kind': 'native_linux', 'plan': plan, 'runs_recorded': len(runs),
                   'samples_per_profile': samples, 'source': dict(self.source),
                   'pooled': NP.SERIES.pool(runs, samples), 'attempts': NP.SERIES.attempt_ledger(plan, runs),
                   'runs': runs,
                   'performance_blockers': [{'run': r['index'], 'kind': r['effective_kind'], 'profile': p,
                                             'p95_ms': r['summary']['latency'][p]['p95_ms']}
                                            for r in runs for p in NP.PROFILES
                                            if not r['summary']['latency'][p]['target_met']]}
        manifest = {'format': NP.SERIES_FORMAT, 'plan': plan, 'samples_per_profile': samples,
                    'platform_kind': 'native_linux', 'source': dict(self.source), 'kernel': '6.0.0-synthetic',
                    'machine': 'x86_64', 'metric': NP.LATENCY_METRIC, 'target_ms': 3000,
                    'cold_ask_trials_claimed': False, 'cold_scope': 'pre_run_cache_drop_only',
                    'declared_at': '2026-11-01T00:00:00Z',
                    'selected_sha256': {t: format(i + 1, 'x') * 64 for i, t in enumerate(NP.SERIES.TOOLS)}}
        return summary, manifest

    def write(self, value, commit=True, raw=None):
        self.count += 1
        path = self.repo / 'evidence' / f'synthetic-{self.count:02d}.json'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw if raw is not None else json.dumps(value, indent=2, sort_keys=True).encode() + b'\n')
        if commit:
            git(self.repo, 'add', str(path.relative_to(self.repo)))
            git(self.repo, 'commit', '-q', '-m', 'synthetic evidence')
        return path

    def receipt(self, manifest, release=False):
        build = ['cargo', 'build', '--locked', '-p', 'agentfw', '--bins'] + (['--release'] if release else [])
        return self.write({'format': NP.RECEIPT_FORMAT, 'source': manifest['source'], 'commands': [build],
                           'binaries': {r: {'sha256': manifest['selected_sha256'][r]}
                                        for r in ('agentfw', 'git_launcher')}})

    def observe(self, role='baseline', receipt=None, **options):
        summary, manifest = self.series(**options)
        summary_path, manifest_path = self.write(summary), self.write(manifest)
        receipt_path = self.receipt(manifest, release=receipt == 'release') if receipt else None
        return NP.normalize(role, summary_path, manifest_path, receipt_path, self.git)


def verified_host(observation, host='synthetic-host-1'):
    observation['environment']['host_instance'] = {'status': 'verified', 'id': host}
    return observation


class SyntheticCase(unittest.TestCase):
    def setUp(self):
        self.s = Synthetic()

    def tearDown(self):
        self.s.close()

    def rejected(self, code, call):
        with self.assertRaises(NP.Rejected) as caught:
            call()
        self.assertEqual(caught.exception.code, code, caught.exception.detail)
        return caught.exception

    def normalize_mutated(self, mutate, manifest_mutate=None):
        summary, manifest = self.s.series()
        mutate(summary)
        if manifest_mutate:
            manifest_mutate(manifest)
        return NP.normalize('baseline', self.s.write(summary), self.s.write(manifest), None, self.s.git)


class Positive(SyntheticCase):
    def test_valid_normalization_binds_source_custody_and_every_trial(self):
        o = self.s.observe()
        self.assertEqual(o['contract'], NP.OBSERVATION)
        self.assertEqual(o['input']['custody']['status'], 'committed_blob')
        self.assertEqual(o['provenance']['source']['status'], 'verified_git_objects')
        self.assertEqual(o['provenance']['workload']['status'], 'verified_git_objects')
        self.assertEqual(o['provenance']['binaries']['status'], 'declared_only')
        self.assertEqual(o['provenance']['build']['status'], 'not_retained')
        self.assertEqual(len(o['trials']), 80)
        self.assertEqual(len({t['id'] for t in o['trials']}), 80)
        self.assertTrue(all(t['status'] == 'measured' for t in o['trials']))
        self.assertIn('pooled', o['reproduction']['checked'])
        self.assertEqual(o['trials'][0]['condition'], 'post_cache_drop_setup_rewarmed')

    def test_percentiles_and_stage_costs(self):
        o = self.s.observe()
        side = NP.stratum_side(o, ('filesystem', 'warm'))
        values = sorted(1000.0 + i * 1.5 + 2 * 0.25 for i in range(20))
        self.assertEqual(side['primary'], {'n': 20, 'p50': values[9], 'p95': values[18],
                                                   'min': values[0], 'max': values[19]})
        self.assertEqual(side['stages']['asset/package_tree/pass_1']['p95'], 500.0 + 18)
        self.assertEqual(side['stages']['approval/classifier']['p50'], 7.0)
        self.assertEqual(side['endpoints']['first_pending_asset_verification_ms']['p50'], 60.0 + 9 + 500.0 + 9 + 0.5)
        self.assertEqual(side['primary_highest'][0], {'trial': 'r02/filesystem/019', 'value': values[19]})
        self.assertEqual(side['engineering_targets']['continuation_p95_le_3000_ms'], 'met')

    def test_compatible_two_reports_with_verified_controls(self):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev', offset=50.0))
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'compatible', result['reasons'])
        stratum = next(s for s in result['strata'] if s['profile'] == 'git' and s['condition'] == 'warm')
        self.assertEqual(stratum['marginal_differences']['primary']['p50'], 50.0)
        self.assertEqual(stratum['marginal_differences']['kind'],
                         'difference_of_marginal_percentiles_not_percentile_of_paired_differences')
        self.assertIsNone(stratum['paired_differences'])  # no paired design across reports
        self.assertEqual(result['pairing']['reason'], 'not_requested_no_paired_design')
        self.assertIsNone(result['global_pooled_comparison'])

    def test_stratified_only_keeps_unmatched_stratum(self):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev', plan=('cold',)))
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'stratified-only')
        warm = [s for s in result['strata'] if s['condition'] == 'warm']
        self.assertEqual({tuple(s['reasons']) for s in warm}, {('stratum_unmatched',)})
        self.assertTrue(all('marginal_differences' not in s for s in warm))
        self.assertIn('global_comparison_mixes_conditions', [r['code'] for r in result['reasons']])

    def test_identity_control_on_synthetic_has_zero_paired_differences(self):
        o = self.s.observe(receipt='dev')
        result = NP.compare(o, copy.deepcopy(o), requested_pairing=True)
        self.assertEqual(result['classification'], 'compatible', result['reasons'])
        self.assertTrue(result['identity_control']['all_zero'])
        self.assertEqual(result['identity_control']['paired_trials'], 80)
        self.assertTrue(all(s['paired_differences']['all_zero'] for s in result['strata']))

    def test_identity_control_does_not_bypass_missing_provenance(self):
        o = self.s.observe()  # no receipt: binaries declared only, build profile not retained
        result = NP.compare(o, copy.deepcopy(o), requested_pairing=True)
        self.assertEqual(result['classification'], 'incomplete')
        codes = {r['code'] for r in result['reasons']}
        self.assertTrue({'binary_identity_unverified', 'build_profile_unverified'} <= codes)
        self.assertTrue(result['identity_control']['all_zero'])
        self.assertTrue(all('marginal_differences' not in s for s in result['strata']))
        summary, _ = self.s.series()
        summary['source'] = dict(summary['source'], commit='e' * 40)  # not in the repository: unverified
        unverified = NP.normalize('baseline', self.s.write(summary), None, None, self.s.git)
        result = NP.compare(unverified, copy.deepcopy(unverified))
        self.assertEqual(result['classification'], 'incomplete')
        self.assertIn('source_unverified', [r['code'] for r in result['reasons']])

    def test_deterministic_json_and_csv(self):
        summary, manifest = self.s.series()
        paths = [str(self.s.write(summary)), str(self.s.write(manifest))]
        outputs = []
        for name in ('a', 'b'):
            out = Path(self.s.tmp.name) / name
            code = NP.main(['--baseline', paths[0], '--baseline-manifest', paths[1], '--candidate', paths[0],
                            '--candidate-manifest', paths[1], '--repository', str(self.s.repo), '--out-dir', str(out)])
            self.assertEqual(code, 1)
            outputs.append({p.name: p.read_bytes() for p in sorted(out.iterdir())})
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(sorted(outputs[0]), ['comparison.json', 'report.md', 'strata.csv', 'trials.csv'])
        self.assertNotIn(self.s.tmp.name.encode(), outputs[0]['comparison.json'])

    def test_crlf_checkout_copy_is_bound_to_committed_lf_bytes(self):
        summary, _ = self.s.series()
        committed = self.s.write(summary)
        copy_path = self.s.write(None, commit=False, raw=committed.read_bytes().replace(b'\n', b'\r\n'))
        o = NP.normalize('baseline', copy_path, None, None, self.s.git)
        self.assertEqual(o['input']['custody']['normalization'], 'crlf_to_lf_checkout')
        self.assertEqual(o['input']['custody']['status'], 'committed_blob')

    def test_status_accounting_failed_timed_out_and_not_run(self):
        def fail_one(run, cases):
            if run == 1:
                cases[0]['passed'] = False
            return cases
        summary, manifest = self.s.series(plan=('cold', 'warm', 'cold'), runs_recorded=2, mutate_cases=fail_one)
        summary['runs'][1]['failure'] = 'series_2_timeout; inspect private log'
        summary['runs'][1]['exit_code'] = 124
        for p in NP.PROFILES:
            trials = summary['runs'][1]['summary']['trials'][p]
            trials['continuation_ms_by_trial'], trials['reuse'] = trials['continuation_ms_by_trial'][:5], trials['reuse'][:5]
            summary['runs'][1]['summary']['latency'][p] = NP.latency_from_trials(trials['continuation_ms_by_trial'], 20)
        summary['runs'][1]['summary'].pop('diagnostic_samples')
        summary['runs'][1]['summary'].pop('diagnostics')
        summary['runs'][0]['validated'] = False  # the failed trial makes the producer refuse validation
        summary['pooled'] = NP.SERIES.pool(summary['runs'], 20)
        summary['attempts'] = NP.SERIES.attempt_ledger(summary['plan'], summary['runs'])
        summary['status'] = NP.SERIES.series_status(summary['plan'], summary['runs'], 20)
        summary['performance_blockers'] = [{'run': r['index'], 'kind': r['effective_kind'], 'profile': p,
                                            'p95_ms': r['summary']['latency'][p]['p95_ms']}
                                           for r in summary['runs'] for p in NP.PROFILES
                                           if not r['summary']['latency'][p]['target_met']]
        o = NP.normalize('baseline', self.s.write(summary), self.s.write(manifest), None, self.s.git)
        counts = NP.summary_of(o)['status_counts']
        self.assertEqual(counts, {'measured': 39 + 10, 'failed': 1, 'timed_out': 30, 'incomplete': 0, 'not_run': 40})
        self.assertEqual(len(o['trials']), 120)
        side = NP.stratum_side(o, ('filesystem', 'post_cache_drop_setup_rewarmed'))
        self.assertEqual(side['planned'], 40)
        self.assertEqual(side['excluded_unqualified_run_trials'], 40)
        self.assertEqual(side['attempted'], 20)
        self.assertEqual(side['status_counts_all_runs'], {'measured': 19, 'failed': 1, 'timed_out': 0,
                                                          'incomplete': 0, 'not_run': 20})
        self.assertEqual(side['engineering_targets']['continuation_p95_le_3000_ms'], 'not_evaluable_no_qualified_run')

    def test_strata_csv_keeps_unqualified_and_failed_trials_visible(self):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev', offset=25.0))
        for t in cand['trials']:
            if t['run'] == 2:
                t['run_qualified'] = False
        cand['trials'][0].update(status='failed', reason='producer_trial_failed')
        result = NP.compare(base, cand)
        rows = list(NP.csv.DictReader(NP.io.StringIO(NP.strata_csv(result))))
        row = next(r for r in rows if r['role'] == 'candidate' and r['condition'] == 'warm' and r['stratum'] == 'filesystem')
        self.assertEqual((row['planned'], row['attempted'], row['excluded_unqualified_run_trials'],
                          row['all_runs_measured'], row['qualified_run_trials']), ('20', '20', '20', '20', '0'))
        row = next(r for r in rows if r['role'] == 'candidate' and r['condition'] != 'warm' and r['stratum'] == 'filesystem')
        self.assertEqual((row['all_runs_failed'], row['qualified_failed'], row['qualified_measured']), ('1', '1', '19'))
        self.assertIn('| 19 / 1 / 0 / 0 / 0 |', NP.render_markdown(result))

    def test_insufficient_independent_groups_gives_descriptive_only(self):
        o = self.s.observe()
        result = NP.compare(o, copy.deepcopy(o))
        self.assertEqual(result['inference']['status'], 'descriptive_only')
        self.assertIsNone(result['inference']['intervals'])
        self.assertTrue(result['inference']['reasons'][0].startswith('independent_clusters_below_minimum'))
        self.assertEqual(result['inference']['independent_clusters_per_stratum'], [1])


class Negative(SyntheticCase):
    def test_tampered_trial_value(self):
        def tamper(s):
            s['runs'][0]['summary']['trials']['git']['continuation_ms_by_trial'][3]['decision_to_result_ms'] += 1
        self.rejected('published_distribution_not_reproduced', lambda: self.normalize_mutated(tamper))

    def test_duplicate_trial(self):
        def duplicate(s):
            t = s['runs'][0]['summary']['trials']['git']
            t['continuation_ms_by_trial'][4] = dict(t['continuation_ms_by_trial'][3])
        self.rejected('duplicate_trial_id', lambda: self.normalize_mutated(duplicate))

    def test_missing_trial(self):
        def drop(s):
            t = s['runs'][1]['summary']['trials']['filesystem']
            del t['continuation_ms_by_trial'][7], t['reuse'][7]
        self.rejected('missing_required_trial', lambda: self.normalize_mutated(drop))

    def test_unexpected_trial_id(self):
        def unexpected(s):
            s['runs'][0]['summary']['trials']['git']['continuation_ms_by_trial'][19]['sample_index'] = 99
        self.rejected('unexpected_trial_id', lambda: self.normalize_mutated(unexpected))

    def test_omitted_outlier(self):
        def omit(s):
            t = s['runs'][0]['summary']['trials']['git']
            worst = max(range(20), key=lambda i: t['continuation_ms_by_trial'][i]['decision_to_result_ms'])
            del t['continuation_ms_by_trial'][worst], t['reuse'][worst]
        self.rejected('missing_required_trial', lambda: self.normalize_mutated(omit))

        def shrink(s):
            t = s['runs'][0]['summary']['trials']['git']['continuation_ms_by_trial']
            worst = max(t, key=lambda r: r['decision_to_result_ms'])
            worst['decision_to_result_ms'] = 1.0
        self.rejected('published_distribution_not_reproduced', lambda: self.normalize_mutated(shrink))

    def test_nonfinite_latency(self):
        summary, _ = self.s.series()
        raw = json.dumps(summary).replace('"decision_to_result_ms": 1000.25', '"decision_to_result_ms": NaN', 1)
        self.assertIn('NaN', raw)
        path = self.s.write(None, raw=raw.encode())
        self.rejected('nonfinite_number', lambda: NP.normalize('baseline', path, None, None, self.s.git))
        path = self.s.write(None, raw=raw.replace('NaN', '1e400').encode())
        self.rejected('nonfinite_number', lambda: NP.normalize('baseline', path, None, None, self.s.git))

    def test_negative_duration(self):
        def negative(s):
            s['runs'][0]['summary']['trials']['git']['continuation_ms_by_trial'][0]['decision_to_result_ms'] = -1.0
        self.rejected('negative_duration', lambda: self.normalize_mutated(negative))

    def test_duplicate_json_key_and_malformed_json(self):
        path = self.s.write(None, raw=b'{"format": "sw-ask-series/1", "format": "sw-ask-series/1"}')
        self.rejected('duplicate_json_key', lambda: NP.normalize('baseline', path, None, None, self.s.git))
        path = self.s.write(None, raw=b'{"format": ')
        self.rejected('malformed_json', lambda: NP.normalize('baseline', path, None, None, self.s.git))

    def test_structurally_malformed_report(self):
        self.rejected('report_shape_invalid', lambda: self.normalize_mutated(
            lambda s: s['runs'][0].update(summary='not-an-object')))
        self.rejected('published_distribution_not_reproduced', lambda: self.normalize_mutated(
            lambda s: s.pop('pooled')))

    def test_unsupported_contract_version(self):
        self.rejected('unsupported_report_format', lambda: self.normalize_mutated(
            lambda s: s.update(format='sw-ask-series/2')))

    def test_incompatible_source_evidence(self):
        def corrupt(s):
            s['source']['files_sha256'] = 'f' * 64
        self.rejected('source_identity_contradiction', lambda: self.normalize_mutated(
            corrupt, lambda m: m['source'].update(files_sha256='f' * 64)))
        self.rejected('manifest_summary_mismatch', lambda: self.normalize_mutated(corrupt))

    def test_invalid_digest(self):
        self.rejected('invalid_digest', lambda: self.normalize_mutated(
            lambda s: None, lambda m: m['selected_sha256'].update(agentfw='abc')))

    def test_true_cold_claim_and_cold_evidence_contradiction(self):
        self.rejected('true_cold_claim_unsupported', lambda: self.normalize_mutated(
            lambda s: None, lambda m: m.update(cold_ask_trials_claimed=True)))
        self.rejected('cold_evidence_contradiction', lambda: self.normalize_mutated(
            lambda s: s['runs'][0]['cache_drop'].update(cached_kb_after=5000000, performed=False)))

    def test_true_cold_versus_setup_rewarmed_strata_never_merge(self):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev'))
        for trial in cand['trials']:
            if trial['condition'] == 'post_cache_drop_setup_rewarmed':
                trial['condition'] = 'true_cold'  # SYNTHETIC: this producer can never establish it
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'stratified-only')
        cold = [s for s in result['strata'] if s['condition'] in ('true_cold', 'post_cache_drop_setup_rewarmed')]
        self.assertTrue(cold and all(not s['comparable'] and s['reasons'] == ['stratum_unmatched'] for s in cold))

    def test_endpoint_substitution(self):
        summary, manifest = self.s.series(substitute=True)
        path = self.s.write(summary)
        self.rejected('endpoint_substitution', lambda: NP.normalize('baseline', path, None, None, self.s.git))
        self.rejected('endpoint_substitution', lambda: self.normalize_mutated(
            lambda s: None, lambda m: m.update(metric='first_pending_asset_verification_ms')))

    def classify(self, change, code, expected='non-comparable'):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev', offset=25.0))
        change(cand)
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], expected)
        self.assertIn(code, [r['code'] for r in result['reasons']])
        self.assertTrue(all(not s['comparable'] and 'marginal_differences' not in s for s in result['strata']))
        return result

    def test_unit_mismatch(self):
        self.classify(lambda o: o['endpoints'].__setitem__('continuation_ms',
                                                           dict(o['endpoints']['continuation_ms'], unit='s')),
                      'unit_mismatch')

    def test_incompatible_observation_endpoints(self):
        self.classify(lambda o: o['endpoints'].__setitem__(
            'continuation_ms', dict(o['endpoints']['continuation_ms'], clock='collector_monotonic')),
            'endpoint_mismatch')

    def test_trace_on_versus_trace_off(self):
        self.classify(lambda o: o['trace'].update(requested={'mode': 'off'}), 'trace_state_mismatch')

    def test_contradictory_trace_state(self):
        base = self.s.observe()
        cand = copy.deepcopy(base)
        cand['trace']['observed'] = {'mode': 'off'}
        cand['input']['evidence_sha256'] = '0' * 64
        self.rejected('trace_state_contradiction', lambda: NP.compare(base, cand))

    def test_debug_versus_release(self):
        # Same summary bytes on purpose: only the receipts differ, so this must not be an identity control.
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='release'))
        self.assertEqual(base['input']['custody']['original_sha256'], cand['input']['custody']['original_sha256'])
        self.assertEqual(cand['provenance']['build']['profile'], 'release')
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'non-comparable')
        self.assertIn('build_profile_mismatch', [r['code'] for r in result['reasons']])

    def test_different_hosts_and_environment(self):
        self.classify(lambda o: verified_host(o, 'synthetic-host-2'), 'host_instance_mismatch')
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev', mem=16000004))
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'incomplete')  # a MemTotal difference proves no host difference
        self.assertEqual([r['code'] for r in result['reasons']], ['mem_total_differs_materiality_unassessed'])
        cand['environment']['cpu_count'] = [8]
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'non-comparable')
        self.assertIn('cpu_count_differs', [r['code'] for r in result['reasons']])

    def test_harness_change_is_non_comparable(self):
        self.classify(lambda o: o['provenance']['workload'].update(
            harness_sha256_at_source={n: '0' * 64 for n in NP.HARNESS}), 'workload_or_harness_changed')

    def test_unsupported_or_incomplete_provenance(self):
        base = self.s.observe('baseline')
        summary, _ = self.s.series(offset=10.0)
        cand = NP.normalize('candidate', self.s.write(summary), None, None, self.s.git)  # no manifest
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'incomplete')
        codes = [r['code'] for r in result['reasons']]
        for code in ('binary_identity_unverified', 'build_profile_unverified', 'host_instance_unverified'):
            self.assertIn(code, codes)
        self.rejected('build_receipt_needs_manifest', lambda: NP.normalize(
            'candidate', self.s.write(summary), None, self.s.write({}), self.s.git))

    def test_uncommitted_evidence_is_not_custody(self):
        summary, manifest = self.s.series()
        o = NP.normalize('candidate', self.s.write(summary, commit=False), None, None, self.s.git)
        self.assertEqual(o['input']['custody']['status'], 'unverified_not_in_repository_history')

    def test_invalid_sample_pairing(self):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev', offset=25.0))
        result = NP.compare(base, cand, requested_pairing=True)
        self.assertEqual(result['classification'], 'incomplete')
        self.assertIn('pairing_design_absent', [r['code'] for r in result['reasons']])
        base['design']['pairing_design'] = cand['design']['pairing_design'] = 'synthetic-design'
        cand['trials'] = cand['trials'][:-1]
        result = NP.compare(base, cand, requested_pairing=True)
        self.assertEqual(result['classification'], 'non-comparable')
        self.assertIn('pairing_trial_set_mismatch', [r['code'] for r in result['reasons']])

    def test_incomplete_denominator_blocks_stratum_comparison(self):
        base = verified_host(self.s.observe('baseline', receipt='dev'))
        cand = verified_host(self.s.observe('candidate', receipt='dev'))
        cand['trials'][0].update(status='failed', reason='producer_trial_failed')
        result = NP.compare(base, cand)
        self.assertEqual(result['classification'], 'stratified-only')
        broken = next(s for s in result['strata'] if not s['comparable'])
        self.assertEqual(broken['reasons'], ['candidate_incomplete_denominator'])

    def test_output_destination_and_input_bounds(self):
        out = Path(self.s.tmp.name) / 'busy'
        out.mkdir()
        (out / 'keep.txt').write_text('x')
        summary, _ = self.s.series()
        path = str(self.s.write(summary))
        self.assertEqual(NP.main(['--baseline', path, '--candidate', path, '--repository', str(self.s.repo),
                                  '--out-dir', str(out)]), 3)
        self.assertEqual((out / 'keep.txt').read_text(), 'x')
        big = self.s.write(None, commit=False, raw=b' ' * (NP.LIMITS['report_bytes'] + 1))
        self.rejected('input_too_large', lambda: NP.normalize('baseline', big, None, None, self.s.git))
        deep = self.s.write(None, commit=False, raw=b'{"a":' * 40 + b'1' + b'}' * 40)
        self.rejected('json_too_deep', lambda: NP.normalize('baseline', deep, None, None, self.s.git))

    def test_symlink_input_refused(self):
        summary, _ = self.s.series()
        target = self.s.write(summary)
        link = target.with_name('link.json')
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('symlinks unavailable on this host')
        self.rejected('symlink_input_refused', lambda: NP.normalize('baseline', link, None, None, self.s.git))

    def test_rejected_cli_writes_no_comparison(self):
        summary, _ = self.s.series()
        summary['runs'][0]['summary']['trials']['git']['continuation_ms_by_trial'][0]['decision_to_result_ms'] += 5
        path = str(self.s.write(summary))
        out = Path(self.s.tmp.name) / 'rejected'
        self.assertEqual(NP.main(['--baseline', path, '--candidate', path, '--repository', str(self.s.repo),
                                  '--out-dir', str(out)]), 2)
        result = json.loads((out / 'comparison.json').read_text())
        self.assertEqual(result['status'], 'rejected')
        self.assertNotIn('strata', result)
        self.assertFalse((out / 'trials.csv').exists())


class AskQualification(SyntheticCase):
    """SYNTHETIC qualify-pilot-ask.py reports built from the producer's own latency summary."""

    def report(self, mutate=None):
        cases = self.s.cases(1, 20, 0.0)
        if mutate:
            mutate(cases)
        return {'contract_version': NP.ASK_FORMAT, 'status': 'pass', 'real_host_executed': True,
                'scripted_owned_provider': True, 'paid_api_calls': 0, 'workspace_unchanged': True,
                'trace_requested': NP.LATENCY.trace_request(), 'source': dict(self.s.source),
                'source_after': dict(self.s.source),
                'selected_sha256': {t: 'a' * 64 for t in NP.SERIES.TOOLS}, 'cases': cases,
                'latency': NP.LATENCY.summarize(cases, 20)}

    def test_normalization_with_diagnostics_and_full_source(self):
        o = NP.normalize('baseline', self.s.write(self.report()), None, None, self.s.git)
        self.assertEqual(o['provenance']['source']['status'], 'verified_git_objects')
        self.assertEqual(NP.summary_of(o)['status_counts']['measured'], 40)
        self.assertIsNotNone(o['trials'][0]['endpoints']['first_pending_asset_verification_ms'])
        self.assertEqual(o['trace']['requested_status'], 'producer_declared')

    def test_failed_and_missing_cases_stay_counted(self):
        def change(cases):
            cases[0]['released'] = False
            del cases[-1]
        report = self.report(change)
        report['status'] = 'failed'
        o = NP.normalize('baseline', self.s.write(report), None, None, self.s.git)
        self.assertEqual(NP.summary_of(o)['status_counts'],
                         {'measured': 38, 'failed': 1, 'timed_out': 0, 'incomplete': 1, 'not_run': 0})
        self.assertFalse(o['runs'][0]['qualified'])
        side = NP.stratum_side(o, ('filesystem', 'undeclared'))
        self.assertEqual((side['planned'], side['excluded_unqualified_run_trials'], side['status_counts_all_runs']['failed']),
                         (20, 20, 1))

    def test_ask_negative_controls(self):
        report = self.report()
        report['cases'][18]['decision_to_result_ms'] += 1  # the filesystem p95 rank
        path = self.s.write(report)
        self.rejected('published_distribution_not_reproduced', lambda: NP.normalize('b', path, None, None, self.s.git))
        # An Ask report publishes only counts, p50 and p95: a change at another rank is not detectable from its own
        # aggregates. Per-trial integrity then rests on custody, so an uncommitted copy can never be compatible.
        report = self.report()
        report['cases'][2]['decision_to_result_ms'] += 1
        o = NP.normalize('b', self.s.write(report, commit=False), None, None, self.s.git)
        self.assertEqual(o['input']['custody']['status'], 'unverified_not_in_repository_history')
        result = NP.compare(o, copy.deepcopy(o))
        self.assertEqual(result['classification'], 'incomplete')
        self.assertIn('custody_unverified', [r['code'] for r in result['reasons']])
        report = self.report(lambda cases: cases.pop(5))
        path = self.s.write(report)
        self.rejected('missing_required_trial', lambda: NP.normalize('b', path, None, None, self.s.git))
        report = self.report()
        report['cases'][1] = dict(report['cases'][0])  # after the producer summary, which refuses duplicates
        path = self.s.write(report)
        self.rejected('duplicate_trial_id', lambda: NP.normalize('b', path, None, None, self.s.git))
        path = self.s.write(self.report())
        self.rejected('input_not_applicable', lambda: NP.normalize('b', path, path, None, self.s.git))
        report = self.report()
        report['source'] = report['source_after'] = dict(self.s.source, tree='0' * 40)
        path = self.s.write(report)
        self.rejected('source_identity_contradiction', lambda: NP.normalize('b', path, None, None, self.s.git))


@unittest.skipUnless(NP.Git(ROOT).tree_of('4b99b6efee6bfd3e603b207d841015d179962977'),
                     'SOU-141 source commit not in this clone')
class Genuine(unittest.TestCase):
    """The retained SOU-141 native series, read unchanged."""

    @classmethod
    def setUpClass(cls):
        cls.final = NP.normalize('baseline', *FINAL)
        cls.earlier = NP.normalize('candidate', *EARLIER)

    def test_final_series_custody_source_and_reproduction(self):
        o = self.final
        self.assertEqual(o['input']['custody']['status'], 'committed_blob')
        self.assertEqual(o['input']['custody']['introduced_by'], '020e2c1fed0a9923a0ece396f895fe4beae9fdd4')
        self.assertEqual(o['provenance']['source']['status'], 'verified_git_objects')
        self.assertEqual(o['provenance']['binaries']['status'], 'declared_only')
        self.assertEqual(o['provenance']['build']['status'], 'not_retained')
        self.assertIn('attempts', o['reproduction']['checked'])
        published = json.loads(FINAL[0].read_text())['pooled']
        for kind, condition in (('cold', 'post_cache_drop_setup_rewarmed'), ('warm', 'warm')):
            for profile in NP.PROFILES:
                side = NP.stratum_side(o, (profile, condition))
                expected = published[kind][profile]['continuation_ms']
                self.assertEqual(side['primary']['n'], expected['n'])
                self.assertEqual(round(side['primary']['p95'], 3), expected['p95'])
                self.assertEqual(round(side['primary']['max'], 3), expected['worst'])
                self.assertEqual(side['status_counts']['measured'], 40)

    def test_same_report_identity_control(self):
        result = NP.compare(self.final, NP.normalize('candidate', *FINAL), requested_pairing=True)
        self.assertEqual(result['basis'], 'identity_control')
        # Source is verified, but binaries and build profile are not: the control does not make them compatible.
        self.assertEqual(result['classification'], 'incomplete')
        self.assertEqual({r['code'] for r in result['reasons']}, {'binary_identity_unverified', 'build_profile_unverified'})
        control = result['identity_control']
        self.assertEqual(len(control['strata']), 4)
        self.assertEqual(control['paired_trials'], 160)
        self.assertTrue(control['all_zero'])

    def test_historical_cross_revision_is_not_a_speedup(self):
        result = NP.compare(self.final, self.earlier)
        self.assertEqual(result['classification'], 'incomplete')
        codes = {r['code'] for r in result['reasons']}
        self.assertEqual(codes, {'mem_total_differs_materiality_unassessed', 'build_profile_unverified',
                                 'binary_identity_unverified', 'host_instance_unverified'})
        memory = next(d for d in result['dimensions'] if d['dimension'] == 'memory')
        self.assertEqual((memory['status'], memory['baseline'], memory['candidate']), ('unverified', [16373452], [16373448]))
        self.assertTrue(all('marginal_differences' not in s for s in result['strata']))

    def test_native_versus_wsl2_is_non_comparable(self):
        wsl = NP.normalize('candidate', EVIDENCE / 'wsl2-ask-series.json')
        result = NP.compare(self.final, wsl)
        self.assertEqual(result['classification'], 'non-comparable')
        platform = next(d for d in result['dimensions'] if d['dimension'] == 'platform')
        self.assertEqual((platform['baseline'], platform['candidate']), ('native_linux', 'wsl2'))

    def test_deliberately_broken_genuine_copy_is_rejected(self):
        value = json.loads(FINAL[0].read_text())
        value['runs'][2]['summary']['trials']['git']['continuation_ms_by_trial'][5]['decision_to_result_ms'] -= 100
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'broken.json'
            path.write_text(json.dumps(value))
            with self.assertRaises(NP.Rejected) as caught:
                NP.normalize('baseline', path)
        self.assertEqual(caught.exception.code, 'published_distribution_not_reproduced')
        self.assertIn('runs[2].summary.latency.git', caught.exception.detail)

    def test_genuine_ask_qualification_report(self):
        o = NP.normalize('baseline', ASK_REPORT)
        self.assertEqual(o['input']['producer_format'], NP.ASK_FORMAT)
        self.assertEqual(o['input']['custody']['status'], 'committed_blob')
        self.assertEqual(o['provenance']['source']['status'], 'commit_tree_verified_files_not_declared')
        self.assertEqual(o['trace']['requested_status'], 'not_retained')
        self.assertEqual(o['reproduction']['checked'], ['latency'])
        published = json.loads(ASK_REPORT.read_text())['latency']
        for profile in NP.PROFILES:
            side = NP.stratum_side(o, (profile, 'undeclared'))
            self.assertEqual(side['primary']['p95'], published[profile]['p95_ms'])
            self.assertEqual(side['engineering_targets']['continuation_p95_le_3000_ms'], 'not_met')
        result = NP.compare(o, self.final)
        self.assertEqual(result['classification'], 'non-comparable')
        self.assertIn('producer_format_mismatch', [r['code'] for r in result['reasons']])
        result = NP.compare(o, NP.normalize('candidate', ASK_REPORT))
        self.assertEqual(result['classification'], 'incomplete')
        self.assertIn('source_contents_unverified', [r['code'] for r in result['reasons']])
        self.assertTrue(result['identity_control']['all_zero'])

    def test_committed_evidence_bundle_reproduces_byte_for_byte(self):
        spec = importlib.util.spec_from_file_location('native_performance_evidence',
                                                      ROOT / 'scripts/native_performance_evidence.py')
        bundle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bundle)
        self.assertEqual(bundle.check(), 0)


SOU106 = ROOT / 'docs/operations/evidence/sou106'


@unittest.skipUnless(NP.Git(ROOT).tree_of('ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc'),
                     'SOU-106 source commit not in this clone')
class InstalledHost(unittest.TestCase):
    """Genuine retained SOU-106 installed-host reports; negatives mutate a private copy."""

    @classmethod
    def setUpClass(cls):
        cls.measured = NP.normalize('baseline', SOU106 / 'measured-report.json')
        cls.raw = json.loads((SOU106 / 'measured-report.json').read_text())

    def mutated(self, change):
        value = copy.deepcopy(self.raw)
        change(value)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'measured-report-copy.json'
            path.write_text(json.dumps(value))
            return NP.normalize('baseline', path)

    def rejected(self, code, change):
        with self.assertRaises(NP.Rejected) as caught:
            self.mutated(change)
        self.assertEqual(caught.exception.code, code, caught.exception.detail)
        return caught.exception

    def test_genuine_measured_report(self):
        o = self.measured
        self.assertEqual(o['input']['producer_format'], NP.INSTALLED_FORMAT)
        self.assertEqual(o['input']['custody']['status'], 'committed_blob')
        self.assertEqual(o['provenance']['source']['status'], 'verified_git_objects')
        self.assertEqual(o['provenance']['workload']['status'], 'verified_git_objects')
        self.assertEqual(o['provenance']['binaries']['status'], 'declared_only')
        self.assertTrue(any(c.startswith('gate (') for c in o['reproduction']['checked']))
        self.assertEqual(NP.summary_of(o)['status_counts'],
                         {'measured': 38, 'failed': 2, 'timed_out': 0, 'incomplete': 0, 'not_run': 0})
        self.assertEqual(sorted({t['id'] for t in o['trials']}), sorted(t['id'] for t in o['trials']))
        self.assertEqual(o['primary_endpoint'], 'host_start_ms')
        self.assertEqual(o['report_endpoints']['preparation_ms']['value'], 11845.533)
        self.assertEqual(o['report_endpoints']['observable_ask_latency']['value'], 'not_applicable')
        self.assertIn('No status is security or protection effectiveness evidence', o['outcome_semantics'])
        self.assertEqual(o['within_report_pairing']['use'], 'reported only; never used to pair two reports')
        side = NP.stratum_side(o, ('protected/benign', 'fresh_host_per_arm_os_cache_uncontrolled'))
        self.assertEqual((side['planned'], side['status_counts']['failed'], side['complete_denominator']), (12, 2, False))
        published = self.raw['gate']['metrics']['host_start_ms']['control']
        control = [t['endpoints']['host_start_ms'] for t in o['trials'] if t['arm'] == 'control']
        self.assertEqual((len(control), max(control), min(control)), (published['n'], published['max'], published['min']))
        self.assertEqual(side['stages']['call/first_batch_ms']['n'], 12)

    def test_identity_control_and_historical_comparisons(self):
        result = NP.compare(self.measured, NP.normalize('candidate', SOU106 / 'measured-report.json'))
        self.assertEqual(result['classification'], 'incomplete')
        self.assertEqual(result['identity_control']['paired_trials'], 38)
        self.assertTrue(result['identity_control']['all_zero'])
        earlier = NP.normalize('baseline', SOU106 / 'attempt-2.json')
        self.assertIn('gate: the gate code at the source commit differs from the accepted primitive',
                      earlier['reproduction']['not_reproduced'])
        result = NP.compare(earlier, self.measured)
        self.assertEqual(result['classification'], 'non-comparable')
        self.assertIn('workload_or_harness_changed', [r['code'] for r in result['reasons']])
        first = NP.normalize('baseline', SOU106 / 'attempt-1.json')
        self.assertEqual(NP.summary_of(first)['status_counts'],
                         {'measured': 10, 'failed': 15, 'timed_out': 0, 'incomplete': 0, 'not_run': 15})
        self.assertFalse(first['runs'][0]['qualified'])
        self.assertIn('host_elapsed_ms', first['not_retained'])
        codes = [r['code'] for r in NP.compare(first, self.measured)['reasons']]
        self.assertIn('trial_design_mismatch', codes)

    def test_shared_text_is_family_specific(self):
        result = NP.compare(self.measured, NP.normalize('candidate', SOU106 / 'measured-report.json'))
        shared = json.dumps({k: v for k, v in result.items() if k not in ('observations', 'strata', 'dimensions')})
        shared += json.dumps(self.measured['not_retained']) + NP.render_markdown(result)
        # Ask-specific assertions never appear; "observable Ask latency: not_applicable" is this family's own statement.
        for term in ('Ask series', 'Ask qualification', 'Trace-on', 'qualifier', 'continuation', '3000', '5000', 'strace', 'first-pending', 'sw-ask-series'):
            self.assertNotIn(term, shared)
        self.assertEqual(result['observer_semantics']['baseline']['trace'],
                         'no trace or observer mode is recorded by this producer')
        self.assertIn('never independently observed protection', ' '.join(result['scope']))
        self.assertIn('repeated_trials_are_dependent: Installed host', ' '.join(result['inference']['reasons']))
        ask = NP.compare(NP.normalize('baseline', *FINAL), NP.normalize('candidate', *FINAL))
        self.assertIn('strace seccomp-bpf', ask['observer_semantics']['baseline']['trace'])
        self.assertEqual(ask['engineering_targets']['sw-ask-series/1']['continuation_p95_ms'], 3000)

    def test_installed_host_never_compares_with_ask(self):
        ask = NP.normalize('candidate', *FINAL)
        result = NP.compare(self.measured, ask)
        self.assertEqual(result['classification'], 'non-comparable')
        codes = {r['code'] for r in result['reasons']}
        self.assertTrue({'endpoint_mismatch', 'producer_format_mismatch'} <= codes)

    def first_passed(self, value, arm='control'):
        return next(r for r in value['rows'] if r['status'] == 'passed' and r['arm'] == arm)

    def test_negative_controls(self):
        self.rejected('published_distribution_not_reproduced',
                      lambda v: self.first_passed(v).update(host_start_ms=self.first_passed(v)['host_start_ms'] + 1))
        self.rejected('duplicate_trial_id', lambda v: v['rows'].__setitem__(1, copy.deepcopy(v['rows'][0])))
        self.rejected('missing_required_trial', lambda v: v['rows'].pop())
        self.rejected('unexpected_trial_id', lambda v: v['rows'][-1].update(case='synthetic-unplanned-case'))
        self.rejected('trial_order_invalid', lambda v: v['rows'].insert(0, v['rows'].pop(1)))
        self.rejected('workload_identity_contradiction', lambda v: v['rows'][0].update(operation_sha256='0' * 64))
        self.rejected('negative_duration', lambda v: self.first_passed(v).update(host_start_ms=-1.0))
        self.rejected('call_denominator_mismatch', lambda v: self.first_passed(v)['latencies_ms'].pop('toolu_pilot_0'))
        # Endpoints are never substituted: host start and every call lie inside the host lifetime (same clock).
        self.rejected('endpoint_substitution', lambda v: self.first_passed(v).update(
            host_start_ms=self.first_passed(v)['host_elapsed_ms']))
        self.rejected('endpoint_substitution', lambda v: self.first_passed(v)['latencies_ms'].update(
            toolu_pilot_0=self.first_passed(v)['host_elapsed_ms'] + 1))
        self.rejected('true_cold_claim_unsupported', lambda v: v['conditions'].update(os_cache='dropped, cold'))

        def identity(v, **change):
            v['identity'].update(change)
            for row in v['rows']:
                row['identity'] = v['identity']
        self.rejected('harness_identity_contradiction', lambda v: identity(v, driver_sha256='0' * 64))
        self.rejected('policy_identity_contradiction', lambda v: identity(v, policy_sha256='0' * 64))
        self.rejected('paired_identity_drift', lambda v: v['rows'][3].update(identity={}))
        with self.assertRaises(NP.Rejected) as caught:
            NP.normalize('baseline', SOU106 / 'measured-report.json', SOU106 / 'measured-report.json')
        self.assertEqual(caught.exception.code, 'input_not_applicable')

    def test_failed_arm_status_mapping(self):
        def timeout(v):
            self.first_passed(v, 'protected').update(status='failed', reason='host_deadline_exceeded')
        # On the measured report the published gate no longer reproduces after the change.
        self.assertTrue(self.rejected('published_distribution_not_reproduced', timeout).detail.startswith('gate'))
        # attempt-2's gate is not reproducible (older gate code), so the status mapping itself is visible.
        value = json.loads((SOU106 / 'attempt-2.json').read_text())
        timeout(value)
        value['rows'][-1].update(status='incomplete', reason='not_executed')
        value['rows'][-3].update(status='incomplete', reason='not_executed', cancelled=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'attempt-2-copy.json'
            path.write_text(json.dumps(value))
            o = NP.normalize('baseline', path)
        states = {t['id']: t['status'] for t in o['trials']}
        self.assertEqual(sum(s == 'timed_out' for s in states.values()), 1)
        self.assertEqual(states['r01/' + value['rows'][-1]['case'] + '/protected'], 'not_run')
        self.assertEqual(states['r01/' + value['rows'][-3]['case'] + '/' + value['rows'][-3]['arm']], 'incomplete')
        self.assertEqual(len(o['trials']), 40)
        self.assertEqual(o['input']['custody']['status'], 'unverified_not_in_repository_history')


class Preparation(SyntheticCase):
    """SYNTHETIC sw-native-pilot-prerequisites/1 receipts: no genuine receipt is retained in the repository."""

    def receipt(self, **change):
        value = {'format': NP.PREPARATION_FORMAT, 'source_commit': self.s.source['commit'],
                 'status': 'built-not-qualified',
                 'stages': {'git': {'status': 'reused', 'seconds': 0.75, 'checkpoint_sha256': 'c' * 64},
                            'bwrap': {'status': 'built', 'seconds': 41.5}},
                 'binaries': {'git': {'sha256': 'a' * 64}, 'bwrap': {'sha256': 'b' * 64}},
                 # SYNTHETIC values for the remaining accepted receipt fields.
                 'archives': {'git': {'url': 'https://example.invalid/git.tar.xz', 'sha256': 'd' * 64},
                              'bwrap': {'url': 'https://example.invalid/bwrap.tar.xz', 'sha256': 'e' * 64}},
                 'tools': {}, 'execution_inputs': {}, 'flags': {'git': [], 'bwrap': []},
                 'generation_tree_sha256': 'f' * 64}
        value.update(change)
        return value

    def test_valid_receipt(self):
        o = NP.normalize('baseline', self.s.write(self.receipt()), None, None, self.s.git)
        self.assertEqual(o['primary_endpoint'], 'stage_seconds')
        self.assertEqual(o['endpoints']['stage_seconds']['unit'], 's')
        self.assertEqual(o['provenance']['source']['status'], 'commit_verified_tree_not_declared')
        self.assertEqual([(t['id'], t['condition'], t['endpoints']['stage_seconds']) for t in o['trials']],
                         [('r01/git', 'reused_verified_checkpoint', 0.75), ('r01/bwrap', 'built_from_source', 41.5)])
        result = NP.compare(o, copy.deepcopy(o))
        self.assertEqual(result['classification'], 'incomplete')
        self.assertIn('source_unverified', [r['code'] for r in result['reasons']])
        self.assertTrue(result['identity_control']['all_zero'])

    def test_shared_text_is_family_specific(self):
        prep = NP.normalize('baseline', self.s.write(self.receipt()), None, None, self.s.git)
        result = NP.compare(prep, copy.deepcopy(prep))
        shared = json.dumps({k: v for k, v in result.items() if k not in ('observations', 'strata', 'dimensions')})
        shared += json.dumps(prep['not_retained']) + NP.render_markdown(result)
        for term in ('Ask series', 'Ask qualification', 'Trace-on', 'qualifier', 'continuation', '3000', '5000', 'strace', 'first-pending', 'sw-ask-series'):
            self.assertNotIn(term, shared)
        self.assertEqual(result['observer_semantics']['baseline']['trace'],
                         'not applicable: preparation runs no Ask or MCP observer')
        self.assertEqual(result['strata'][0]['baseline']['unit'], 's')

    def test_built_and_reused_stages_never_merge(self):
        base = NP.normalize('baseline', self.s.write(self.receipt()), None, None, self.s.git)
        built = self.receipt(stages={'git': {'status': 'built', 'seconds': 300.0},
                                     'bwrap': {'status': 'built', 'seconds': 40.0}})
        cand = NP.normalize('candidate', self.s.write(built), None, None, self.s.git)
        git = [s for s in NP.compare(base, cand)['strata'] if s['profile'] == 'git']
        self.assertEqual(sorted(s['condition'] for s in git), ['built_from_source', 'reused_verified_checkpoint'])
        self.assertTrue(all(s['reasons'] == ['stratum_unmatched'] for s in git))

    def test_preparation_never_compares_with_ask(self):
        prep = NP.normalize('baseline', self.s.write(self.receipt()), None, None, self.s.git)
        result = NP.compare(prep, self.s.observe('candidate'))
        self.assertEqual(result['classification'], 'non-comparable')
        codes = {r['code'] for r in result['reasons']}
        self.assertTrue({'unit_mismatch', 'endpoint_mismatch', 'producer_format_mismatch'} <= codes)
        installed = NP.normalize('candidate', SOU106 / 'measured-report.json')  # genuine, read from this clone
        result = NP.compare(prep, installed)
        self.assertEqual(result['classification'], 'non-comparable')
        codes = {r['code'] for r in result['reasons']}
        self.assertTrue({'unit_mismatch', 'endpoint_mismatch', 'producer_format_mismatch'} <= codes)

    def test_negative_controls(self):
        def check(code, value):
            path = self.s.write(value)
            self.rejected(code, lambda: NP.normalize('baseline', path, None, None, self.s.git))
        check('receipt_stage_contradiction', self.receipt(stages={'git': {'status': 'failed', 'seconds': 3.0},
                                                                  'bwrap': {'status': 'built', 'seconds': 1.0}}))
        check('missing_required_trial', self.receipt(stages={'git': {'status': 'built', 'seconds': 3.0}}))
        check('negative_duration', self.receipt(stages={'git': {'status': 'built', 'seconds': -3.0},
                                                        'bwrap': {'status': 'built', 'seconds': 1.0}}))
        check('nonfinite_or_missing_duration', self.receipt(stages={'git': {'status': 'built'},
                                                                    'bwrap': {'status': 'built', 'seconds': 1.0}}))
        check('invalid_digest', self.receipt(binaries={'git': {'sha256': 'x'}, 'bwrap': {'sha256': 'b' * 64}}))
        check('source_identity_malformed', self.receipt(source_commit='abc'))
        truncated = self.receipt()
        del truncated['generation_tree_sha256']
        check('report_shape_invalid', truncated)
        check('report_shape_invalid', self.receipt(extra_claim='cold'))
        check('no_performance_endpoints', {'format': NP.PREPARATION_MARKER, 'generation': 'g1',
                                           'selection_sha256': 'a' * 64, 'status': 'prepared-not-active'})


if __name__ == '__main__':
    unittest.main()
