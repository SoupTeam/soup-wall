import copy
import unittest

from sou13.hashing import sha
from sou13.labels import ACTIONS
from sou13cp2 import ROOT
from sou13cp2.records import load_cp1_records, record_errors
from _util import base, by_id, mutant
from _testsupport import CP1_DATA, requires


@requires(CP1_DATA)
class LiftPreservesCp1(unittest.TestCase):
    def setUp(self):
        self.fams, self.manifest, self.records = base()
        self.fam_by_id = {f['family_id']: f for f in self.fams}
        self.originals = {r['id']: r for _, r in load_cp1_records(ROOT)}

    def errors(self, r):
        return record_errors(r, self.fam_by_id, self.manifest)

    def test_all_cp1_fields_and_digests_unchanged(self):
        for r in self.records:
            orig = self.originals[r['id']]
            self.assertEqual(r['source_material']['cp1_record_sha256'], sha(orig))
            self.assertEqual(r['hashes'], orig['hashes'])
            if r['source_material']['kind'] == 'cp1_record_revised':  # SUP-S1 only (technical review 2026-10-10)
                self.assertEqual(r['id'], 'S13V03-SUP-S1')
                continue
            self.assertEqual({k: r[k] for k in orig}, orig)

    def test_tri_state_null_and_status_preserved(self):
        nulls = sum(r['annotation']['per_action_targets'][a] is None for r in self.records
                    if r['annotation']['per_action_targets'] for a in ACTIONS)
        self.assertGreater(nulls, 0)
        self.assertEqual(sorted(r['id'] for r in self.records if r['label_status'] == 'pending'),
                         ['S13V03-SUP-S1', 'S13V03-SUP-S3'])
        self.assertFalse(any(r['label_status'] == 'confirmed' for r in self.records))
        self.assertIsNone(by_id(self.records, 'S13V03-SUP-S2')['annotation']['per_action_targets'])

    def test_clean_records_pass(self):
        for r in self.records:
            self.assertEqual(self.errors(r), [], r['id'])

    def test_edited_cp1_label_detected(self):
        r = by_id(self.records, 'S13V03-DEV-01')
        r['annotation']['per_action_targets']['write'] = None  # null without unknown, and CP1 content changed
        errors = self.errors(r)
        self.assertTrue(any('null label requires unknown=true' in e for e in errors), errors)
        self.assertTrue(any('cp1_record_sha256' in e for e in errors), errors)

    def test_confirmed_rejected_in_phase1(self):
        r = by_id(self.records, 'S13V03-DEV-02')
        r['label_status'] = 'confirmed'
        self.assertTrue(any('never confirms' in e for e in self.errors(r)))

    def test_hash_mismatch_detected(self):
        r = by_id(self.records, 'S13V03-DEV-03')
        r['input']['raw_arguments']['document_id'] = 'other.md'
        self.assertTrue(any('hash mismatch' in e for e in self.errors(r)))

    def test_wrong_template_detected(self):
        r = copy.deepcopy(by_id(self.records, 'S13V03-DEV-14'))
        r['template_id'] = 'tpl.shell.posix_sh.cat_append_existing'
        errors = self.errors(r)
        self.assertTrue(any('effect profile' in e for e in errors), errors)

    def test_identity_outside_family_detected(self):
        r = mutant(by_id(self.records, 'S13V03-DEV-01'), 'MUT-ID', input_changes={'tool_name': 'fetch_other'})
        self.assertTrue(any('not an admitted alias' in e for e in self.errors(r)))

    def test_v02_material_cannot_be_gold(self):
        r = by_id(self.records, 'S13V03-DEV-04')
        r['source_material'] = {'kind': 'sou13_pilot_v02', 'ref': 'S13-INF-CLUSTEROPS-01'}
        self.assertTrue(any('analysis input only' in e for e in self.errors(r)))


if __name__ == '__main__':
    unittest.main()
