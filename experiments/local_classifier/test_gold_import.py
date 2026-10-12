# SPDX-License-Identifier: Apache-2.0
"""Conversion on isolated UNIT TEST ONLY exports; no actual release or test."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from experiments.local_classifier import gold_import as importer
from experiments.local_classifier.custodian import load_part
from experiments.local_classifier.model import ACTIONS


class GoldDevelopmentImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        self.root = self.parent / 'gold'
        self.root.mkdir()
        self.receipt = self.parent / 'receipt.json'
        self.inputs, self.labels = {}, {}
        for index, split in enumerate(importer.SPLITS, 1):
            cid = 'S13C2-' + format(index, '032X')
            inp = {'server_id': f'synthetic-unit-{index}', 'tool_name': f'unit_tool_{index}',
                   'tool_description': 'UNIT TEST ONLY', 'tool_schema': {'type': 'object'},
                   'raw_arguments': {'value': index}}
            hashes = {'input_sha256': importer.canonical(inp)}
            targets = {a: False for a in ACTIONS}
            targets['read'] = True
            targets['send_data'] = None if split == 'train' else split == 'calibration'
            self.inputs[split] = [{'id': cid, 'split': split, 'input_profile': 'UNIT TEST ONLY',
                                  'input': inp, 'hashes': hashes}]
            self.labels[split] = [{'id': cid, 'split': split, 'label_status': 'confirmed',
                                  'family_id': f'unit-family-{index}', 'leakage_group_id': f'unit-group-{index}',
                                  'hashes': hashes, 'per_action_targets': targets,
                                  'known_mask': {a: int(targets[a] is not None) for a in ACTIONS},
                                  'unknown': split == 'train'}]
        self.auth = {'status': 'approved', 'permitted_use': {'training_use_authorized': True,
                     'splits': list(importer.SPLITS), 'license_id': 'UNIT TEST ONLY',
                     'terms_reference': 'Synthetic fixture; no actual use approval'}}
        self.manifest = {'export_kind': 'sou13_gold_dev_export', 'format_version': 1,
                         'status': 'AUTHORIZED_DEVELOPMENT_EXPORT', 'splits': list(importer.SPLITS),
                         'counts': dict.fromkeys(importer.SPLITS, 1),
                         'source': {'public_view_sha256': 'a' * 64}, 'files_sha256': {}}
        self.seal()

    def tearDown(self):
        self.tmp.cleanup()

    def seal(self):
        for split in importer.SPLITS:
            for kind, value in (('labels', self.labels[split]), ('model_inputs', self.inputs[split])):
                path = self.root / kind / (split + '.jsonl')
                path.parent.mkdir(exist_ok=True)
                path.write_text(''.join(json.dumps(row) + '\n' for row in value), encoding='utf-8')
        path = self.root / 'authorization' / 'EXPORT_AUTHORIZATION.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(self.auth), encoding='utf-8')
        self.manifest['files_sha256'] = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in self.root.rglob('*') if p.is_file()
                                         and p.name != 'GOLD_EXPORT_MANIFEST.json'}
        self.write_manifest()

    def write_manifest(self):
        data = json.dumps(self.manifest).encode()
        (self.root / 'GOLD_EXPORT_MANIFEST.json').write_bytes(data)
        self.digest = hashlib.sha256(data).hexdigest()
        # Synthetic assertion for conversion tests; not a real verification/sign-off.
        self.receipt.write_text(json.dumps({'result': 'PASS', 'self_consistency': 'PASS',
                               'anchored_integrity': 'PASS', 'manifest_sha256': self.digest}), encoding='utf-8')

    def prepare(self):
        return importer.prepare(self.root, self.receipt, self.digest, 'UNIT TEST ONLY',
                                'unit-heldout', expected_cases=3)

    def test_preserves_null_mixed_actions_original_inputs_and_groups(self):
        data, approval, provenance = self.prepare()
        rows = json.loads(data)['cases']
        self.assertIsNone(rows[0]['labels']['send_data'])
        self.assertTrue(rows[0]['labels']['unknown'])
        self.assertTrue(rows[-1]['labels']['send_data'])
        self.assertEqual(rows[0]['family'], self.labels['train'][0]['leakage_group_id'])
        self.assertEqual(rows[0]['input'], self.inputs['train'][0]['input'])
        self.assertEqual(approval['dataset_sha256'], hashlib.sha256(data).hexdigest())
        self.assertFalse(provenance['training_started'])
        self.assertFalse(provenance['test_opened'])

    def test_unverified_or_wrong_receipt_is_refused(self):
        for change in ({'result': 'UNVERIFIED'}, {'anchored_integrity': 'UNVERIFIED'},
                       {'manifest_sha256': 'b' * 64}):
            self.seal()
            receipt = json.loads(self.receipt.read_text(encoding='utf-8')) | change
            self.receipt.write_text(json.dumps(receipt), encoding='utf-8')
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare()

    def test_changed_manifest_or_member_is_refused(self):
        (self.root / 'GOLD_EXPORT_MANIFEST.json').write_text('{}', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.prepare()
        self.seal()
        (self.root / 'labels' / 'train.jsonl').write_text('{}', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.prepare()

    def test_missing_use_permission_is_refused(self):
        self.auth['permitted_use']['training_use_authorized'] = False
        self.seal()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_cp1_test_or_pending_rows_are_refused(self):
        original = copy.deepcopy(self.labels['train'][0])
        for change in ({'id': 'historical-cp1'}, {'split': 'test'}, {'label_status': 'pending'}):
            self.labels['train'][0] = original | change
            self.seal()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare()

    def test_mask_and_target_types_cannot_turn_null_into_a_negative(self):
        self.labels['train'][0]['known_mask']['send_data'] = 1
        self.seal()
        with self.assertRaises(ValueError):
            self.prepare()
        self.labels['train'][0]['known_mask']['send_data'] = 0
        self.labels['validation'][0]['per_action_targets']['delete'] = 'false'
        self.seal()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_alias_group_cannot_cross_splits(self):
        self.labels['validation'][0]['leakage_group_id'] = self.labels['train'][0]['leakage_group_id']
        self.seal()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_duplicate_input_ids_and_wrong_release_count_are_refused(self):
        with self.assertRaises(ValueError):
            importer.prepare(self.root, self.receipt, self.digest, 'UNIT TEST ONLY', 'unit-heldout')
        self.inputs['train'].append(copy.deepcopy(self.inputs['train'][0]))
        self.seal()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_outside_member_is_refused_even_with_receipt_assertion(self):
        self.manifest['files_sha256']['../outside.txt'] = '0' * 64
        self.write_manifest()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_cli_output_loads_for_training_and_never_overwrites(self):
        output = self.parent / 'converted'
        arguments = ['--gold-export', str(self.root), '--verification-report', str(self.receipt),
                     '--expect-manifest-sha256', self.digest, '--review-reference', 'UNIT TEST ONLY',
                     '--holdout-id', 'unit-heldout', '--expected-cases', '3', '--output-dir', str(output)]
        self.assertEqual(importer.main(arguments), 0)
        splits, review, _ = load_part(output / 'development.json', output / 'development-review.json', 'development')
        self.assertEqual({key: len(value) for key, value in splits.items()}, dict.fromkeys(importer.SPLITS, 1))
        self.assertEqual(review['split_manifest_sha256'], 'a' * 64)
        with self.assertRaises(FileExistsError):
            importer.main(arguments)


if __name__ == '__main__':
    unittest.main()
