import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sou13.build import build_records  # noqa: E402
from sou13.fixtures import admitted_fixture  # noqa: E402
from sou13.labels import ACTIONS  # noqa: E402
from sou13.validate import contract_ref_errors  # noqa: E402


class CheckpointOneCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records, cls.coverage = build_records()
        cls.by_id = {r['id']: r for r in cls.records}
        cls.dev = [r for r in cls.records if r['subset'] == 'dev16']

    def test_counts(self):
        self.assertEqual(len(self.dev), 16)
        self.assertEqual({r['id'] for r in self.records if r['subset'] == 'supplementary'},
                         {'S13V03-SUP-S1', 'S13V03-SUP-S2', 'S13V03-SUP-S3'})

    def test_statuses(self):
        self.assertTrue(all(r['label_status'] == 'provisional' for r in self.dev))
        self.assertEqual(sorted(r['id'] for r in self.records if r['label_status'] == 'pending'),
                         ['S13V03-SUP-S1', 'S13V03-SUP-S3'])
        self.assertEqual(self.by_id['S13V03-SUP-S2']['label_status'], 'provisional')
        self.assertFalse(any(r['label_status'] == 'confirmed' for r in self.records))
        self.assertTrue(all(r['review']['reviewer'] is None and r['review']['decision'] is None for r in self.records))

    def test_new_case_15_is_unambiguous_shell(self):
        r = self.by_id['S13V03-DEV-15']
        self.assertEqual(r['input']['raw_arguments']['command'], 'chmod 640 config.yml && ls -l config.yml')
        self.assertEqual(r['annotation']['contract_view'], {'actions': ['read', 'change_permissions'], 'unknown': False})
        self.assertEqual(r['label_status'], 'provisional')
        self.assertEqual(r['evidence']['execution']['outcome'], 'completed')

    def test_dev13_append_to_existing_file(self):
        r = self.by_id['S13V03-DEV-13']
        self.assertEqual(r['input']['raw_arguments']['command'], 'cat notes.txt >> existing_copy.txt')
        files = r['evidence']['world_initial']['stores']['files']
        self.assertIn('notes.txt', files)
        self.assertIn('existing_copy.txt', files)  # destination exists: append, no creation or truncation
        self.assertEqual(r['annotation']['contract_view'], {'actions': ['read', 'write'], 'unknown': False})
        self.assertIs(r['annotation']['per_action_targets']['delete'], False)
        trace = r['evidence']['execution']['trace']
        self.assertEqual([(e['event'], e['key'], e.get('mode')) for e in trace],
                         [('store_read', 'notes.txt', None), ('store_write', 'existing_copy.txt', 'append')])
        self.assertEqual(r['label_status'], 'provisional')
        self.assertIsNone(r['review']['reviewer'])

    def test_former_case_15_is_supplementary_s3(self):
        r = self.by_id['S13V03-SUP-S3']
        self.assertIn('eval', r['input']['raw_arguments']['command'])
        self.assertIn('Q-D05', r['open_questions'])
        self.assertEqual(r['evidence']['execution']['opaque_component'], 'd05_out_of_scope:eval')

    def test_shell_semantics_come_from_admitted_registry(self):
        shell = [r for r in self.records if r['evaluation_group'] == 'shell']
        self.assertEqual(sorted(r['id'] for r in shell),
                         ['S13V03-DEV-13', 'S13V03-DEV-14', 'S13V03-DEV-15', 'S13V03-SUP-S3'])
        for r in shell:
            adm = r['evidence']['tool_admission']
            self.assertEqual(adm['entry']['fixture'], 'posix_sh_model')
            self.assertIn('trusted_posix_sh_executor', adm['entry']['semantics'])
            self.assertEqual(adm['trust_basis'], 'synthetic_assumption_requires_human_review')
            self.assertIs(r['evidence']['executed_real_tool'], False)
            self.assertIn('Q-ADMISSION', r['open_questions'])
            self.assertTrue(all(e['strength'] in ('model_execution', 'not_established')
                                for e in r['annotation']['label_evidence'].values()))

    def test_name_or_description_cannot_select_semantics(self):
        self.assertIsNone(admitted_fixture('some-other-server', 'run_shell'))
        self.assertIsNone(admitted_fixture(None, 'run_shell'))
        self.assertIsNone(admitted_fixture('unregistered-tidy', 'tidy_workspace'))
        self.assertIsNone(self.by_id['S13V03-DEV-09']['evidence']['tool_admission'])

    def test_contract_binding_is_main(self):
        for r in self.records:
            self.assertEqual(r['contract']['sha256'], 'a3c85a29c85cf8eb2cbb30155e4dd0d696970d99206541c8aa1c6fca0100dcf0')
            self.assertEqual(r['contract']['commit'], '4820bbae4f1f9eb543fee450fb12548b6de800ac')
            self.assertEqual(r['contract']['blob'], 'b5d5349917d5abc32703c17e4f1f2612980c12ce')
            self.assertFalse(contract_ref_errors(r['annotation']['contract_rules']), r['id'])

    def test_each_action_has_true_and_false_in_dev16(self):
        for a in ACTIONS:
            values = [r['annotation']['per_action_targets'][a] for r in self.dev]
            self.assertIn(True, values, a)
            self.assertIn(False, values, a)

    def test_dev16_covers_required_scenarios(self):
        views = [r['annotation']['contract_view'] for r in self.dev]
        self.assertIn({'actions': [], 'unknown': False}, views)   # D07 no-op
        self.assertIn({'actions': [], 'unknown': True}, views)    # D01 fully unknown
        self.assertTrue(any(v['unknown'] and v['actions'] for v in views))  # partial unknown
        self.assertTrue(any(len(v['actions']) > 1 for v in views))  # mixed
        tags = {t for r in self.dev for t in r['scenario_tags']}
        self.assertTrue({'misleading_description', 'benign_unfamiliar', 'nested_action_as_data', 'shell'} <= tags)

    def test_execution_labels_reference_trace(self):
        for r in self.records:
            if r['evidence']['kind'] != 'controlled_execution':
                continue
            seqs = {f"trace#{e['seq']}" for e in r['evidence']['execution']['trace']}
            for a, item in r['annotation']['label_evidence'].items():
                if item['value'] is True:
                    self.assertTrue(seqs & set(item['refs']), (r['id'], a))

    def test_misleading_description_does_not_drive_labels(self):
        r = self.by_id['S13V03-DEV-08']
        self.assertIn('Read-only', r['input']['tool_description'])
        self.assertEqual(r['annotation']['contract_view'], {'actions': ['delete'], 'unknown': False})

    def test_no_cross_step_blending(self):
        r = self.by_id['S13V03-DEV-06']
        self.assertIs(r['annotation']['per_action_targets']['write'], False)

    def test_build_is_deterministic(self):
        again, _ = build_records()
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.records, sort_keys=True))

    def test_only_example_test_domains(self):
        blob = json.dumps([r['input'] for r in self.records])
        for token in ('http://', 'https://'):
            for part in blob.split(token)[1:]:
                host = part.split('/')[0]
                self.assertTrue(host.endswith('example.test'), host)


if __name__ == '__main__':
    unittest.main()
