# SPDX-License-Identifier: Apache-2.0
"""Coordinator and measurement controls; never substituted for runtime evidence."""
import importlib.util
from pathlib import Path
import unittest
import math

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ASK = load('sou145_ask_controls', 'qualify-pilot-ask.py')
RUN = load('sou145_coordinator', 'qualify-sou145-readiness.py')


class ReadinessControls(unittest.TestCase):
    def test_original_first_pending_bound_is_conservative_and_not_a_wait_change(self):
        for value, expected in [(0, True), (5000, True), (5000.001, False),
                                (None, False), (True, False), (-1, False),
                                (math.inf, False), (math.nan, False)]:
            row = {'case': 'approve', 'passed': True, 'first_pending_ms': value}
            ASK.enforce_pending_bound([row])
            self.assertEqual(row['passed'], expected)
            self.assertTrue(row['runtime_controls_passed'])
            self.assertEqual(row['first_pending_bound_ms'], 5000)
        row = {'case': 'reject', 'passed': False, 'first_pending_ms': 1}
        ASK.enforce_pending_bound([row])
        self.assertFalse(row['passed'])
        default = {'case': 'default', 'passed': True}
        ASK.enforce_pending_bound([default])
        self.assertEqual(default, {'case': 'default', 'passed': True})

    def test_all_seven_producers_use_one_selection_and_distinct_outputs(self):
        paths = {name: Path('/owned/' + name) for name in
                 ('agentfw', 'git_launcher', 'claude', 'node', 'npm', 'bwrap', 'git')}
        commands = RUN.commands(Path('/owned/selection.json'), 'a' * 40,
                                Path('/usr/bin/strace'), Path('/owned/offline'), Path('/owned/results'), paths)
        self.assertEqual(tuple(row[0] for row in commands), RUN.STAGES)
        self.assertEqual(len({str(row[2]) for row in commands}), 7)
        for stage, command, report in commands:
            self.assertIn('--output', command)
            self.assertIn('/owned/results/' + stage, command)
            if stage == 'ask':
                self.assertIn('--complete-inventory', command)
                self.assertIn('--require-five-second-pending', command)
            else:
                self.assertIn('/owned/selection.json', command)
                self.assertIn('a' * 40, command)
            if stage != 'prepared':
                self.assertIn('--offline-inputs', command)
        matched = next(row[1] for row in commands if row[0] == 'matched')
        self.assertIn('--matched-development', matched)
        for project in ('docs-code', 'unicode-spaces', 'local-history'):
            command = next(row[1] for row in commands if row[0] == project)
            self.assertEqual(command[command.index('--project-fixture') + 1], project)


class NewDossierLinks(unittest.TestCase):
    def setUp(self):
        import json
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        import pilot_dossier
        import pilot_project_fixtures
        self.dossier = pilot_dossier
        self.projects = pilot_project_fixtures
        self.installed = json.loads((ROOT / 'docs/operations/evidence/sou-122/installed-pilot-qualification-report.json').read_text())

    def test_original_installed_inventory_is_read_without_rescoring_runtime(self):
        result = self.dossier.project(self.installed, {})
        self.assertEqual(result[0], 'installed')
        self.assertEqual(len(result[3]), 5)
        self.installed['cases'][-1]['evidence']['forced_cleanup'] = True
        with self.assertRaisesRegex(ValueError, 'installed_cleanup_missing'):
            self.dossier.project(self.installed, {})

    def test_installed_zero_effect_claim_requires_independent_observation(self):
        row = next(r for r in self.installed['cases'] if r['id'] == 'untrusted-input-refusal')
        row['evidence']['fifo']['reader_seen'] = True
        with self.assertRaisesRegex(ValueError, 'installed_zero_effects_missing'):
            self.dossier.project(self.installed, {})

    def existing(self):
        source = self.installed['source_before']
        digest = self.projects.identity('docs-code')
        rows = []
        names = ('moved-root', 'replaced-root', 'changed-selection', 'unsupported-git',
                 'initial', 'operator-edit', 'cancel', 'daemon-loss', 'recovery')
        for case in names:
            row = {'case': case, 'status': 'passed', 'trace_sha256': 'a' * 64}
            if len(rows) < 4:
                row['selected_runtime_executions'] = 0
            else:
                row.update(native_instance='owned-instance-' + case, cleanup='owned_state_removed', process_cleanup={'all_stopped': True, 'remaining': []},
                           outside_reads=0, forbidden_network_deliveries=0,
                           worktree_index_head_config_unchanged=True, untracked_preserved=True)
                if case in ('initial', 'operator-edit', 'recovery'):
                    row.update(useful_original_results=7, refused_results=5,
                               ordinary_followup_results=2, project_fixture_sha256=digest)
            rows.append(row)
        return {'format': 'sw-existing-pilot-acceptance/1', 'status': 'passed',
                'provider': 'owned-scripted-loopback', 'live_model_effectiveness': 'not_tested',
                'source': source.copy(), 'source_after': source.copy(), 'cases': rows,
                'project_fixture': 'docs-code', 'project_fixture_sha256': digest,
                'ordinary_project_required_cases': 9, 'fresh_run_authority': True,
                'external_roots_outside_prefix': True, 'cleanup_external_roots_untouched': True}

    def test_three_project_adapter_keeps_all_denominators_and_missing_identities(self):
        r = self.existing()
        kind, source, identities, observations = self.dossier.project(r, {})
        self.assertEqual(kind, 'existing')
        self.assertTrue(all(value is None for value in identities.values()))
        self.assertEqual([o['counts']['required'] for o in observations], [4, 3, 3, 2, 1])
        self.assertTrue(all(o['observed_status'] == 'pass' for o in observations))
        r['cases'].pop()
        with self.assertRaisesRegex(ValueError, 'project_inventory_incomplete'):
            self.dossier.project(r, {})
        r['status'] = 'failed'
        observations = self.dossier.project(r, {})[3]
        self.assertTrue(any(o['observed_status'] == 'fail' for o in observations))

    def test_project_cleanup_or_utility_cannot_be_replaced_by_pass_label(self):
        for key, value in [('outside_reads', 1), ('untracked_preserved', False), ('useful_original_results', 6)]:
            r = self.existing()
            r['cases'][4][key] = value
            with self.assertRaises(ValueError):
                self.dossier.project(r, {})
        r = self.existing(); r['source_after']['commit'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'source_changed_during_run'):
            self.dossier.project(r, {})


if __name__ == '__main__':
    unittest.main()
