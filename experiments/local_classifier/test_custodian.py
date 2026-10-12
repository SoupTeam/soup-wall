# SPDX-License-Identifier: Apache-2.0
"""Separated-custodian regressions using synthetic unit fixtures, never SOU-13 data."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from experiments.local_classifier.custodian import load_part, main
from experiments.local_classifier.pilot import digest, toy_data


class CustodianPilot(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dev = self.root / 'development.json'
        self.dev_approval = self.root / 'development-review.json'
        self.test = self.root / 'custodian' / 'heldout.json'
        self.test.parent.mkdir()
        self.test_approval = self.test.with_name('heldout-review.json')
        self.model = self.root / 'model'
        self.ledger = self.root / 'custodian-ledger'
        self.ledger.mkdir()
        self.run = self.root / 'run.json'
        self.baseline = self.root / 'rule_baseline.py'
        self.baseline.write_text('def classify(call):\n    return {"actions": [], "unknown": True}\n', encoding='utf-8')
        data = toy_data()
        test = [r for r in data['cases'] if r['split'] == 'holdout']
        self.test_data = {'format': 'soup-wall/classifier-holdout-dataset/1',
                          'cases': json.loads(json.dumps(test).replace('gamma', 'delta'))}
        for row in self.test_data['cases']:
            row['id'] += '-custodian'
            row['family'] += '-custodian'
        for row in data['cases']:
            if row['split'] == 'holdout':
                row['split'] = 'validation'
        data['format'] = 'soup-wall/classifier-development-dataset/1'
        self.dev_data = data
        self.save(self.dev, data)
        self.save(self.test, self.test_data)
        self.review = {'format': 'soup-wall/classifier-development-approval/1',
                       'approval_reference': 'UNIT TEST ONLY, NO DATA APPROVAL',
                       'source': 'isolated toy fixture', 'license': 'Apache-2.0',
                       'dataset_sha256': digest(self.dev), 'split_manifest_sha256': 'f' * 64,
                       'holdout_id': 'unit-test-custodian-set'}
        self.save(self.dev_approval, self.review)
        self.refresh_test_approval()

    def save(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    def refresh_test_approval(self):
        self.test_review = dict(self.review, format='soup-wall/classifier-holdout-approval/1',
                                dataset_sha256=digest(self.test),
                                development_approval_sha256=digest(self.dev_approval))
        self.save(self.test_approval, self.test_review)

    def train(self):
        return main(['train', '--development-dataset', str(self.dev),
                     '--development-approval', str(self.dev_approval), '--output-dir', str(self.model),
                     '--epochs', '2', '--dimensions', '32'])

    def evaluation_args(self):
        self.save(self.run, {'format': 'soup-wall/classifier-run-authorization/1',
                            'run_id': 'unit-test-only', 'holdout_id': self.review['holdout_id'],
                            'approval_reference': 'UNIT TEST ONLY', 'dataset_sha256': digest(self.test),
                            'model_sha256': digest(self.model / 'model.json'),
                            'baseline_sha256': digest(self.baseline)})
        return ['evaluate', '--development-dataset', str(self.dev),
                '--development-approval', str(self.dev_approval), '--model-dir', str(self.model),
                '--holdout-dataset', str(self.test), '--holdout-approval', str(self.test_approval),
                '--baseline-path', str(self.root), '--run-authorization', str(self.run),
                '--run-ledger-dir', str(self.ledger)]

    def test_train_never_opens_heldout_and_validation_does_not_supervise(self):
        self.test.unlink()
        self.test_approval.unlink()
        self.assertEqual(self.train(), 0)
        artifact = (self.model / 'model.json').read_bytes()
        report = json.loads((self.model / 'training.json').read_text())
        self.assertFalse(report['official_heldout_run'])
        self.assertEqual(report['development_approval_sha256'], digest(self.dev_approval))
        for row in self.dev_data['cases']:
            if row['split'] == 'validation':
                row['labels'] = {key: False for key in row['labels']}
        self.save(self.dev, self.dev_data)
        self.review['dataset_sha256'] = digest(self.dev)
        self.save(self.dev_approval, self.review)
        self.model = self.root / 'second-model'
        self.train()
        self.assertEqual((self.model / 'model.json').read_bytes(), artifact)

    def test_train_rejects_holdout_option_without_opening_it(self):
        with patch('sys.stderr'), patch('experiments.local_classifier.custodian.train_model') as train:
            with self.assertRaises(SystemExit):
                main(['train', '--development-dataset', str(self.dev),
                      '--development-approval', str(self.dev_approval), '--output-dir', str(self.model),
                      '--holdout-dataset', str(self.root / 'must-not-open.json')])
            train.assert_not_called()

    def test_development_loader_rejects_hidden_rows_and_wrong_approval(self):
        self.dev_data['cases'].append(self.test_data['cases'][0])
        self.save(self.dev, self.dev_data)
        self.review['dataset_sha256'] = digest(self.dev)
        self.save(self.dev_approval, self.review)
        with self.assertRaises(ValueError):
            load_part(self.dev, self.dev_approval, 'development')
        for value in ('bad', '', 'A' * 64):
            self.review['split_manifest_sha256'] = value
            self.save(self.dev_approval, self.review)
            with self.assertRaises(ValueError):
                load_part(self.dev, self.dev_approval, 'development')

    def test_custodian_evaluates_once_and_copied_artifacts_cannot_repeat(self):
        self.train()
        args = self.evaluation_args()
        self.assertEqual(main(args), 0)
        report = json.loads((self.model / 'evaluation.json').read_text())
        self.assertTrue(report['official_heldout_run'])
        self.assertEqual(report['candidate']['calls'], len(self.test_data['cases']))
        self.assertEqual(len(list(self.ledger.glob('*.reserved.json'))), 1)
        self.assertEqual(len(list(self.ledger.glob('*.reserved.result.json'))), 1)
        copied = self.root / 'copied-model'
        shutil.copytree(self.model, copied, ignore=shutil.ignore_patterns('.holdout-*', 'evaluation.json'))
        args[args.index('--model-dir') + 1] = str(copied)
        with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
            with self.assertRaises(FileExistsError):
                main(args)
            evaluate.assert_not_called()

    def test_mismatched_split_review_and_run_identity_never_infer(self):
        self.train()
        original = copy.deepcopy(self.test_review)
        for key in ('development_approval_sha256', 'split_manifest_sha256', 'holdout_id'):
            self.test_review = dict(original, **{key: 'e' * 64})
            self.save(self.test_approval, self.test_review)
            args = self.evaluation_args()
            with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
                with self.assertRaises(ValueError):
                    main(args)
                evaluate.assert_not_called()
            self.assertEqual(list(self.ledger.iterdir()), [])
        self.save(self.test_approval, original)
        args = self.evaluation_args()
        run = json.loads(self.run.read_text())
        run['holdout_id'] = 'different-set'
        self.save(self.run, run)
        with self.assertRaises(ValueError):
            main(args)
        self.assertEqual(list(self.ledger.iterdir()), [])

    def test_family_case_and_description_only_duplicates_are_blocked(self):
        self.train()
        original = copy.deepcopy(self.test_data)
        public = self.dev_data['cases'][0]
        mutations = [{'family': public['family']}, {'id': public['id']},
                     {'input': dict(public['input'], tool_description='Different misleading description')}]
        for mutation in mutations:
            self.test_data = copy.deepcopy(original)
            self.test_data['cases'][0].update(mutation)
            self.save(self.test, self.test_data)
            self.refresh_test_approval()
            args = self.evaluation_args()
            with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
                with self.assertRaises(ValueError):
                    main(args)
                evaluate.assert_not_called()
            self.assertEqual(list(self.ledger.iterdir()), [])

    def test_interrupted_inference_consumes_shared_attempt(self):
        self.train()
        args = self.evaluation_args()
        with patch('experiments.local_classifier.custodian.evaluate', side_effect=RuntimeError('unit failure')):
            with self.assertRaises(RuntimeError):
                main(args)
        self.assertEqual(len(list(self.ledger.glob('*.reserved.json'))), 1)
        self.assertFalse((self.model / 'evaluation.json').exists())
        with self.assertRaises(FileExistsError):
            main(args)

    def additional_args(self):
        directory = self.root / 'generic'
        directory.mkdir()
        source = directory / 'rule_baseline.py'
        source.write_text('def classify(call):\n    return {"actions": ["delete"], "unknown": False}\n',
                          encoding='utf-8')
        args = self.evaluation_args() + ['--additional-classifier', 'generic_rule_v1=' + str(directory)]
        authorization = json.loads(self.run.read_text())
        authorization['additional_classifiers'] = {'generic_rule_v1': digest(source)}
        self.save(self.run, authorization)
        return args, source

    def test_three_candidates_share_one_reservation_and_cannot_repeat_after_copy(self):
        self.train()
        args, source = self.additional_args()
        self.assertEqual(main(args), 0)
        report = json.loads((self.model / 'evaluation.json').read_text())
        self.assertEqual(report['additional_classifier_sha256'], {'generic_rule_v1': digest(source)})
        for result in (report['candidate'], report['baseline'], report['additional_classifiers']['generic_rule_v1']):
            self.assertEqual(result['calls'], len(self.test_data['cases']))
            self.assertEqual(result['per_label']['delete']['eligible_known'],
                             report['baseline']['per_label']['delete']['eligible_known'])
        self.assertEqual(len(list(self.ledger.glob('*.reserved.json'))), 1)
        copied = self.root / 'copied-three-way'
        shutil.copytree(self.model, copied, ignore=shutil.ignore_patterns('.holdout-*', 'evaluation.json'))
        args[args.index('--model-dir') + 1] = str(copied)
        with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
            with self.assertRaises(FileExistsError):
                main(args)
            evaluate.assert_not_called()

    def test_unapproved_or_changed_third_candidate_never_predicts_or_consumes_run(self):
        self.train()
        args, source = self.additional_args()
        original = json.loads(self.run.read_text())
        variants = [None, {}, {'generic_rule_v1': '0' * 64},
                    dict(original['additional_classifiers'], unrequested='f' * 64)]
        for mapping in variants:
            authorization = dict(original)
            if mapping is None:
                del authorization['additional_classifiers']
            else:
                authorization['additional_classifiers'] = mapping
            self.save(self.run, authorization)
            with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
                with self.assertRaises(ValueError):
                    main(args)
                evaluate.assert_not_called()
            self.assertEqual(list(self.ledger.iterdir()), [])
        self.save(self.run, original)
        source.write_bytes(source.read_bytes() + b'\n')
        with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
            with self.assertRaises(ValueError):
                main(args)
            evaluate.assert_not_called()
        self.assertEqual(list(self.ledger.iterdir()), [])

    def test_training_rejects_additional_classifiers_without_opening_them(self):
        with patch('sys.stderr'), patch('experiments.local_classifier.custodian.load_baseline') as load:
            with self.assertRaises(SystemExit):
                main(['train', '--development-dataset', str(self.dev),
                      '--development-approval', str(self.dev_approval), '--output-dir', str(self.model),
                      '--additional-classifier', 'generic_rule_v1=must-not-open'])
            load.assert_not_called()

    def test_failure_in_third_candidate_evaluation_consumes_whole_experiment(self):
        self.train()
        args, _ = self.additional_args()
        with patch('experiments.local_classifier.custodian.evaluate',
                   side_effect=[{}, {}, RuntimeError('synthetic third-participant failure')]):
            with self.assertRaises(RuntimeError):
                main(args)
        self.assertEqual(len(list(self.ledger.glob('*.reserved.json'))), 1)
        self.assertFalse((self.model / 'evaluation.json').exists())
        with self.assertRaises(FileExistsError):
            main(args)

    def test_changed_model_or_training_provenance_is_rejected_before_reservation(self):
        self.train()
        args = self.evaluation_args()
        training_path = self.model / 'training.json'
        original_training = training_path.read_bytes()
        training = json.loads(original_training)
        training['development_approval_sha256'] = 'c' * 64
        self.save(training_path, training)
        with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
            with self.assertRaises(ValueError):
                main(args)
            evaluate.assert_not_called()
        training_path.write_bytes(original_training)
        model_path = self.model / 'model.json'
        model_path.write_bytes(model_path.read_bytes() + b'\n')
        with patch('experiments.local_classifier.custodian.evaluate') as evaluate:
            with self.assertRaises(ValueError):
                main(args)
            evaluate.assert_not_called()
        self.assertEqual(list(self.ledger.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
