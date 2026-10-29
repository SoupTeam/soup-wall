# SPDX-License-Identifier: Apache-2.0
"""Synthetic contract/adversarial controls; never original-server runtime evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import pilot_runtime_identity as r
import pilot_dossier as d
import pilot_project_fixtures as projects
import test_pilot_dossier as legacy
import test_sou145_readiness as previous


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScopedDossierTests(unittest.TestCase):
    setUp = legacy.DossierTests.setUp
    put = legacy.DossierTests.put
    add = legacy.DossierTests.add
    matched = legacy.DossierTests.matched
    full_fixture = legacy.DossierTests.full_fixture
    result = legacy.DossierTests.result

    def fixture(self):
        self.full_fixture()
        old = {entry['id']: json.loads((self.root / entry['file']['path']).read_bytes()) for entry in self.m['evidence']}
        self.source = dict(self.m['candidate'], dirty=False, files_sha256='c' * 64)
        git_files = patch.object(d, 'git_files_digest', return_value=self.source['files_sha256'])
        git_files.start(); self.addCleanup(git_files.stop)
        paths = {}
        for role in ('agentfw', 'git_launcher', 'claude', 'node', 'git', 'bwrap', 'python', 'npm',
                     'sandbox_tests', 'filesystem_classifier', 'git_classifier', 'policy'):
            path = self.root / role
            if role == 'policy':
                raw = (ROOT / 'scripts/benchmarks/pilot-readiness-policies/baseline.yaml').read_bytes()
            elif role.endswith('_classifier'):
                raw = (ROOT / ('rule_baseline/rule_baseline.py' if role.startswith('filesystem') else
                               'rule_baseline/git_readonly_v1/rule_baseline.py')).read_bytes()
            else:
                raw = ('Synthetic executable bytes: ' + role).encode()
            path.write_bytes(raw); paths[role] = path
        self.paths = paths
        selected = {'format': 'sw-installed-pilot-selection/3', 'source': self.source,
                    'files': {name: {'path': str(path), 'sha256': r.file_sha(path)} for name, path in paths.items()}}
        selection = self.root / 'selected.json'; selection.write_bytes(r.canonical(selected))
        self.plan = r.freeze(self.source, paths, selection)
        self.objects_bytes = patch.object(d, 'git_bytes', side_effect=lambda repo, commit, path: (ROOT / path).read_bytes())
        self.objects_bytes.start(); self.addCleanup(self.objects_bytes.stop)
        self.m.update(format='sw-pilot-dossier-selection/2', runtime_plan=self.put('runtime-plan.json', self.plan),
                      identities={role: self.plan['selected_sha256'][role] for role in r.BINARY_ROLES}, evidence=[])
        gen = load('identity_fixture_generation', 'prepare-installed-pilot.py')
        self.registries = {}
        for kind, installer in [('filesystem', gen.FS), ('git', gen.GIT)]:
            value = installer.registry(json.loads((installer.ASSETS / 'upstream-tools-list.json').read_bytes()))
            raw = (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()
            r.same_digest(r.sha(raw), self.plan['template']['profiles'][kind]['registry_sha256'])
            self.registries[kind] = raw
        original = previous.NewDossierLinks(); original.setUp()
        installed = copy.deepcopy(original.installed)
        installed.update(source_before=self.source, source_after=self.source,
                         selected_sha256=self.plan['selected_sha256'], environment=self.m['environment'])
        prepared = old['prepared']
        control = copy.deepcopy(next(row for row in prepared['cases'] if row['case'] == 'changed-selection'))
        control['case'] = 'provider-unavailable'; prepared['cases'].insert(4, control)
        self.reports = {'installed': installed, 'matched': old['matched'], 'ask': old['ask'], 'prepared': prepared}
        for stage in ('docs-code', 'unicode-spaces', 'local-history'):
            project = original.existing()
            project.update(source=self.source, source_after=self.source, project_fixture=stage,
                           project_fixture_sha256=projects.identity(stage), selected_sha256=self.plan['selected_sha256'])
            for case in project['cases']:
                if 'project_fixture_sha256' in case:
                    case['project_fixture_sha256'] = projects.identity(stage)
            self.reports[stage] = project
        self.context = {'format': 'sw-pilot-readiness-execution/2', 'decision': 'NOT_READY',
            'source_before': self.source, 'source_after': self.source, 'environment': self.m['environment'],
            'runtime_plan_sha256': r.sha(r.canonical(self.plan)), 'stages': []}
        self.witnesses = {}
        for stage in r.STAGES:
            report = self.reports[stage]
            observations = [self.observation(stage, scope) for scope in self.plan['template']['stages'][stage]['scopes']]
            report['runtime_identity'] = {'format': 'sw-pilot-runtime-claims/1', 'stage': stage,
                'plan_sha256': self.context['runtime_plan_sha256'], 'claims': [
                    {'scope': row['scope'], 'sha256': row['sha256']} for row in observations]}
            if stage == 'matched':
                report['identity'].update(selected=self.plan['selected_sha256'], policy_sha256=self.plan['policies']['baseline']['sha256'], profiles={})
                report['identity']['registry_sha256'] = observations[0]['inputs']['registry']['sha256']
                for row in report['rows']:
                    row['identity'] = report['identity']
                report['gate'] = d.matched_gate(self.work, report)
            else:
                report['selected_sha256'] = self.plan['selected_sha256']
            if stage == 'ask':
                report['classifier_sha256'] = self.plan['classifier_sha256']['git']
            for key in ('profiles', 'profile_sha256'):
                report.pop(key, None)
            if stage == 'installed':
                next(row for row in report['cases'] if row['id'] == 'exact-installed-inputs')['evidence']['profiles'] = {}
            if stage == 'ask':
                for case in report['cases']:
                    observation = next(row for row in observations if row['scope'] == case['profile'] + ':' + case['case'])
                    case.update(policy_sha256=observation['inputs']['policy']['sha256'],
                                configuration_sha256=observation['inputs']['configuration']['sha256'])
            witness = {'format': 'sw-pilot-runtime-custody/1', 'stage': stage, 'source': self.source,
                'plan_sha256': self.context['runtime_plan_sha256'], 'report_sha256': None,
                'cleanup': {'all_stopped': True, 'remaining': []}, 'observations': observations}
            self.witnesses[stage] = witness
        self.refresh()

    def observation(self, stage, scope):
        declared = self.plan['template']['stages'][stage]['scopes'][scope]
        paths = {'selection': str(self.root / 'selected.json'), 'policy': str(self.paths['policy']),
                 'registry': str(self.root / stage / 'registry.json'), 'configuration': str(self.root / stage / 'config.yaml'),
                 'binaries': {name: str(self.paths[name]) for name in r.BINARY_ROLES},
                 'profiles': {kind: str(self.root / stage / (kind + '-profile')) for kind in ('filesystem', 'git')},
                 'classifiers': {kind: str(self.paths[declared['classifiers'][kind] + '_classifier']) for kind in ('filesystem', 'git')}}
        data = {'paths': paths, 'selection': self.plan['selection'], 'policy': self.plan['policies'][declared['policy']],
                'binaries': {name: self.plan['selected_sha256'][name] for name in r.BINARY_ROLES},
                'classifiers': {kind: self.plan['classifier_sha256'][declared['classifiers'][kind]] for kind in ('filesystem', 'git')},
                'profiles': {}, 'registry': None, 'configuration': None}
        tools = []
        for kind in ('filesystem', 'git'):
            profile = {'format': self.plan['template']['profiles'][kind]['format'], 'workspace': str(self.root / stage / 'workspace'),
                'runtimePath': paths['binaries']['node'] if kind == 'filesystem' else paths['profiles'][kind] + '/package/python/bin/python3.11',
                'runtimeSha256': data['binaries']['node'], 'packageRoot': paths['profiles'][kind] + '/package',
                'packageTreeSha256': 'e' * 64, 'bwrapPath': paths['binaries']['bwrap'],
                'bwrapSha256': data['binaries']['bwrap'], 'libraries': [{'path': '/lib/synthetic.so', 'sha256': 'd' * 64}]}
            if kind == 'git':
                profile.update(git={'path': paths['binaries']['git'], 'sha256': data['binaries']['git']},
                               gitLauncher={'path': paths['binaries']['git_launcher'], 'sha256': data['binaries']['git_launcher']})
            profile_blob = r.blob(r.canonical(profile))
            policy = self.plan['template']['profiles'][kind]['policy']
            policy_blob = r.blob((ROOT / policy['path']).read_bytes())
            registry_blob = r.blob(self.registries[kind])
            receipt = {'profile': profile, 'profile_sha256': profile_blob['sha256'],
                       'policy_sha256': policy_blob['sha256'], 'registry_sha256': registry_blob['sha256']}
            data['profiles'][kind] = {'profile': profile_blob, 'policy': policy_blob, 'registry': registry_blob,
                'installation': r.blob(r.canonical(receipt)), 'verified_runtime_sha256': profile['runtimeSha256'],
                'verified_package_sha256': profile['packageTreeSha256'], 'verified_libraries': profile['libraries']}
            tools.extend(json.loads(self.registries[kind])['tools'])
        if declared['configuration'] != 'selection':
            registry_id = 'installed-development-pilot-v1' if declared['configuration'] == 'installed' else (
                'sou99-original-launcher' if declared['configuration'] == 'ask' else 'prepared-pilot-v1')
            data['registry'] = r.blob(r.canonical({'contract_version': 'sw-native/1', 'registry_id': registry_id, 'tools': tools}))
            native = {'registry_path': paths['registry'], 'registry_sha256': data['registry']['sha256']}
            config = {'port': 12345, 'enforce': True, 'policy': paths['policy'], 'native': native}
            if declared['configuration'] == 'installed':
                config['max_record_bytes'] = 1048576
            elif declared['configuration'] == 'ask':
                native['liveness'] = {'default_lease_seconds': 4, 'max_lease_seconds': 60, 'maintenance_interval_ms': 100}
            else:
                native['liveness'] = {'default_lease_seconds': 4, 'max_lease_seconds': 4, 'maintenance_interval_ms': 250}
                config.update(bind='127.0.0.1', audit_retention={'version': 1, 'segment_size_bytes': 65536,
                    'segment_count': 4, 'total_disk_bytes': 512000, 'max_record_bytes': 65536, 'directory': '/owned/audit'})
            if declared['approval_ttl_seconds'] is not None:
                native['approval'] = {'ttl_seconds': declared['approval_ttl_seconds']}
            data['configuration'] = r.blob(r.canonical(config))
        row = {'scope': scope, 'inputs': data, 'complete': True}
        row['sha256'] = r.sha(r.canonical({'scope': scope, 'inputs': data}))
        return row

    def refresh(self):
        self.m['evidence'], self.context['stages'] = [], []
        for stage in r.STAGES:
            report_ref = self.put(stage + '.json', self.reports[stage])
            self.witnesses[stage]['report_sha256'] = report_ref['sha256']
            witness_ref = self.put(stage + '-identities.json', self.witnesses[stage])
            self.context['stages'].append({'id': stage, 'status': 'executed', 'report_sha256': report_ref['sha256'],
                'identity_status': 'verified',
                'identity_report_sha256': witness_ref['sha256'], 'independent_namespace_cleanup': {'all_stopped': True, 'remaining': []}})
            self.m['evidence'].append({'id': stage, 'owner': 'synthetic', 'scope': d.SCOPE, 'role': 'candidate',
                                      'stage': stage, 'file': report_ref, 'identity_context': witness_ref})
        ref = self.put('execution.json', self.context)
        for entry in self.m['evidence']:
            entry['context'] = ref

    def test_complete_scoped_synthetic_fixture_can_be_ready(self):
        self.fixture()
        result = self.result()
        self.assertEqual(result['status'], 'READY', [(v['id'], v['blockers']) for v in result['evidence']])
        self.assertEqual([len(row['identities']) for row in result['evidence']], [1, 1, 17, 13, 6, 6, 6])

    def test_reviewed_policy_bytes_and_original_ttls_are_unchanged(self):
        self.fixture()
        installed = load('scoped_policy_fixture', 'qualify-installed-pilot.py')
        self.assertEqual(r.unblob(self.plan['policies']['baseline']), installed.PILOT_POLICY.encode())
        self.assertEqual(self.plan['policies']['baseline']['sha256'], 'dba24a1b419040d5f5dad62dfd485db6637c9359f37b9642f458101793062dbc')
        for name, scope in self.plan['template']['stages']['ask']['scopes'].items():
            self.assertEqual(scope['approval_ttl_seconds'], 20 if name.endswith(':expire') else 30)

    def test_all_identities_do_not_hide_a_real_failed_project_case(self):
        self.fixture()
        self.reports['docs-code']['cases'][4].update(status='failed', reason='useful_original_result_failed')
        self.reports['docs-code']['status'] = 'failed'
        self.refresh()
        out = self.result()
        self.assertEqual(out['status'], 'NOT_READY')
        self.assertTrue(all(not e['blockers'] for e in out['evidence']))
        self.assertEqual(next(x for x in out['ledger'] if x['item'] == 'useful-workflows')['status'], 'fail')

    def test_all_identities_do_not_hide_incomplete_cleanup(self):
        self.fixture()
        self.witnesses['ask']['cleanup']['all_stopped'] = False
        self.refresh()
        self.assertEqual(self.result()['status'], 'NOT_READY')

    def test_report_tampering_cannot_reuse_original_custody(self):
        self.fixture()
        entry = self.m['evidence'][0]
        report = copy.deepcopy(self.reports['installed']); report['status'] = 'failed'
        entry['file'] = self.put('altered.json', report)
        self.assertEqual(self.result()['status'], 'NOT_READY')

    def test_missing_cross_stage_duplicate_or_unfinished_scopes_are_rejected(self):
        self.fixture()
        original = copy.deepcopy(self.witnesses['ask'])
        for change in (lambda w: w['observations'].pop(),
                       lambda w: w['observations'].append(copy.deepcopy(w['observations'][0])),
                       lambda w: w.update(stage='matched'),
                       lambda w: w['observations'][0].update(complete=False),
                       lambda w: w.update(format='sw-pilot-runtime-custody/99')):
            self.witnesses['ask'] = copy.deepcopy(original); change(self.witnesses['ask']); self.refresh()
            self.assertEqual(self.result()['status'], 'NOT_READY')

    def test_self_declared_digest_cannot_override_actual_policy_or_classifier_bytes(self):
        self.fixture()
        row = self.witnesses['ask']['observations'][0]
        for key in ('policy', 'configuration'):
            altered = copy.deepcopy(row)
            altered['inputs'][key] = r.blob(b'{}')
            with self.assertRaises(ValueError):
                r.verify_capture(self.plan, 'ask', altered)
        altered = copy.deepcopy(row); altered['inputs']['classifiers']['filesystem'] = '0' * 64
        with self.assertRaises(ValueError): r.verify_capture(self.plan, 'ask', altered)

    def test_stale_or_changed_predeclared_plan_cannot_be_posthoc_authority(self):
        self.fixture()
        for change in (lambda p: p['source'].update(commit='f' * 40),
                       lambda p: p['template']['stages']['ask']['scopes']['git:approve'].update(policy='baseline'),
                       lambda p: p['selected_sha256'].update(agentfw='0' * 64)):
            plan = copy.deepcopy(self.plan); change(plan)
            with self.assertRaises(ValueError): r.verify_plan(plan, self.source, lambda p: (ROOT / p).read_bytes())

    def test_missing_stage_cannot_be_omitted_from_required_inventory(self):
        self.fixture(); self.m['evidence'].pop()
        with self.assertRaises(ValueError): d.validate_manifest(self.m)

    def test_conflicting_original_claims_cannot_override_custody(self):
        self.fixture()
        report = self.reports['matched']
        for key in ('policy_sha256', 'registry_sha256'):
            original = report['identity'][key]
            report['identity'][key] = '0' * 64; self.refresh()
            self.assertEqual(self.result()['status'], 'NOT_READY')
            report['identity'][key] = original

    def test_unsupported_selection_or_wrong_source_files_digest_is_rejected(self):
        self.fixture()
        plan = copy.deepcopy(self.plan)
        selected = r.selection_input(plan['selection']); selected['format'] = 'sw-installed-pilot-selection/99'
        plan['selection'] = r.blob(r.canonical(selected))
        with self.assertRaisesRegex(ValueError, 'unsupported_runtime_selection'):
            r.verify_plan(plan, self.source, lambda p: (ROOT / p).read_bytes())
        self.source['files_sha256'] = '0' * 64
        self.m['runtime_plan'] = self.put('runtime-plan.json', self.plan)
        with self.assertRaisesRegex(ValueError, 'runtime_plan_source_mismatch'):
            self.result()

    def test_actual_input_reader_rejects_duplicate_keys_and_nonfinite_json(self):
        for raw in (b'{"scope":"ask","scope":"installed"}', b'{"value":NaN}', b'[]'):
            with self.assertRaises(ValueError): r.parse(raw)

    def test_conflicting_context_source_or_incomplete_identity_status_is_not_ready(self):
        self.fixture()
        original = copy.deepcopy(self.context)
        for mutate in (lambda c: c.update(source_before=dict(self.source, files_sha256='0' * 64),
                                         source_after=dict(self.source, files_sha256='0' * 64)),
                       lambda c: c['stages'][0].update(identity_status='incomplete')):
            context = copy.deepcopy(original); mutate(context)
            ref = self.put('execution.json', context)
            for entry in self.m['evidence']: entry['context'] = ref
            self.assertEqual(self.result()['status'], 'NOT_READY')


class GitSourceDigestTests(unittest.TestCase):
    def test_recomputed_source_digest_uses_exact_git_blob_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL).strip()
            git('init', '-q')
            files = {'normal': b'original bytes\n', 'caf\u00e9.txt': b'owned unicode filename\n'}
            for name, raw in files.items(): (root / name).write_bytes(raw)
            git('add', '.'); git('-c', 'user.name=Contract', '-c', 'user.email=contract@example.invalid',
                                 'commit', '-qm', 'synthetic source control')
            commit = git('rev-parse', 'HEAD').decode()
            (root / 'normal').write_bytes(b'changed checkout bytes')
            self.assertEqual(d.git_files_digest(root, commit),
                             d.sha(d.canonical({name: r.sha(raw) for name, raw in files.items()})))


@unittest.skipUnless(sys.platform == 'linux', 'kernel SO_PEERCRED requires native Linux')
class KernelCustodyTests(unittest.TestCase):
    def test_foreign_pid_cross_stage_and_unsupported_operation_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            owner = r.Custodian({'format': 'synthetic-peer-control'}, Path(tmp) / 'identity.sock', None)
            self.addCleanup(owner.close)
            owner.begin('ask')
            def request(*, foreign=False):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(owner.address))
                    if not foreign:
                        client.sendall(r.canonical({'operation': 'unknown', 'stage': 'ask'}))
                    # No payload on the foreign connection: this tests refusal
                    # before a request exists, without a reset/broken-pipe race.
                    client.shutdown(socket.SHUT_WR)
                    return r._message(client)
            owner.pid = 0
            refused = request(foreign=True)
            self.assertEqual(refused['status'], 'failed')
            self.assertEqual(refused['reason'], 'identity_foreign_producer')
            owner.pid = os.getpid(); owner.stage = 'installed'
            self.assertEqual(request()['reason'], 'identity_cross_stage_request')
            owner.stage = 'ask'
            self.assertEqual(request()['reason'], 'identity_operation_unsupported')


class DescriptorLifetimeTests(unittest.TestCase):
    def test_changed_or_restored_input_is_rejected_but_owned_unlink_is_supported(self):
        for mode in ('changed', 'restored', 'replaced', 'unlinked'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'input.json'; path.write_bytes(b'{"owned":true}')
                owner = object.__new__(r.Custodian)
                owner.opened, owner.active, owner.rows = [], {}, [{'scope': 'one', 'complete': False}]
                owner.read(path); owner.active['one'], owner.opened = owner.opened, []
                if mode == 'unlinked': path.unlink()
                elif mode == 'replaced':
                    replacement = path.with_suffix('.new'); replacement.write_bytes(path.read_bytes())
                    replacement.replace(path)
                else:
                    path.write_bytes(b'{"owned":false}')
                    if mode == 'restored': path.write_bytes(b'{"owned":true}')
                if mode == 'unlinked':
                    owner.finish_capture('one'); self.assertTrue(owner.rows[0]['complete'])
                else:
                    with self.assertRaisesRegex(ValueError, 'identity_input_changed'):
                        owner.finish_capture('one')
                    self.assertFalse(owner.rows[0]['complete'])

    def test_replaced_executable_or_classifier_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'asset'; path.write_bytes(b'owned executable' * 10000)
            owner = object.__new__(r.Custodian)
            owner.opened, owner.active, owner.rows = [], {}, [{'scope': 'asset', 'complete': False}]
            self.assertEqual(owner.read(path, asset=True), r.file_sha(path))
            owner.active['asset'], owner.opened = owner.opened, []
            replacement = path.with_suffix('.new'); replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
            with self.assertRaisesRegex(ValueError, 'identity_input_changed'):
                owner.finish_capture('asset')
            self.assertFalse(owner.rows[0]['complete'])


if __name__ == '__main__': unittest.main()
