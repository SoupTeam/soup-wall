"""Integration of the 2026-10-10 technical review: DEV-09, S1, S3, DEV-06, S2, provenance, exports, assignment."""
import copy
import json
import unittest

from sou13.labels import ACTIONS
from sou13cp2 import ROOT
from _testsupport import CP1_DATA, CP2_PUBLIC, requires
from sou13cp2.exports import pilot
from sou13cp2.pipeline import FULL_MANIFEST_FILE, assemble
from sou13cp2.records import record_errors
from sou13cp2.revisions import revision_errors
from sou13cp2.splits import build_manifest, freeze, manifest_errors
from sou13cp2.records import CP2_FIELDS

APPROVAL = dict(approved_by='TEST-ONLY', approved_at='2026-10-10T00:00:00+05:00', decision_ref='unit test')


@requires(CP1_DATA, CP2_PUBLIC)
class ReviewIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fams, cls.manifest, cp1, new = assemble()
        cls.records = cp1 + new
        cls.by_id = {r['id']: r for r in cls.records}
        cls.by_fam = {f['family_id']: f for f in cls.fams}

    def r(self, rid):
        return copy.deepcopy(self.by_id[rid])

    # ---- DEV-09 ----
    def test_dev09_is_admission_test_outside_accuracy_and_pilot(self):
        r = self.r('S13V03-DEV-09')
        self.assertEqual(r['evaluation']['role'], 'admission_rejection_test')
        self.assertFalse(r['evaluation']['in_semantic_accuracy'] or r['evaluation']['in_pilot_export'])
        self.assertEqual(r['evaluation']['expected_admission'], 'rejected')
        fam = self.by_fam[r['family_id']]
        ident = [r['input']['server_id'], r['input']['tool_name']]
        self.assertIn(ident, fam['rejected_identities'])
        self.assertTrue(all(ident not in f['identities'] for f in self.fams))  # not admitted anywhere

    def test_dev09_replacement_is_admitted_opaque_neutral(self):
        reps = [r for r in self.records if r['family_id'] == 'fam.unknown.workspace_tidy'
                and r['source_material']['kind'] == 'new_cp2_case']
        self.assertEqual(len(reps), 1)
        rep = reps[0]
        self.assertEqual(rep['input']['server_id'], 'synthetic-workspace')
        self.assertFalse(rep['input']['server_id'].startswith('unregistered'))
        self.assertTrue(all(rep['annotation']['per_action_targets'][a] is None for a in ACTIONS))
        self.assertTrue(rep['annotation']['unknown'])
        self.assertEqual(rep['label_status'], 'provisional')
        self.assertEqual(rep['evaluation']['role'], 'classification')
        self.assertEqual(rep['split'], 'train')

    def test_admission_identity_cannot_be_used_for_classification(self):
        r = self.r('S13V03-DEV-09')
        r['evaluation'] = {'role': 'classification', 'in_semantic_accuracy': True, 'in_pilot_export': True,
                           'reason': 'tampered'}
        errors = record_errors(r, self.by_fam, self.manifest)
        self.assertTrue(any('not an admitted alias' in e for e in errors), errors)
        self.assertTrue(any('evaluation metadata is not the documented one' in e for e in errors), errors)

    # ---- SUP-S1 ----
    def test_s1_revision(self):
        r = self.r('S13V03-SUP-S1')
        a = r['annotation']
        self.assertIs(a['per_action_targets']['read'], True)
        self.assertIsNone(a['per_action_targets']['send_data'])
        self.assertEqual(a['known_mask']['send_data'], 0)
        self.assertTrue(a['unknown'])
        self.assertNotIn('forbidden_actions', a)
        self.assertEqual(a['label_evidence']['send_data']['basis'], 'opaque_component')
        self.assertFalse(any(v is False for v in a['per_action_targets'].values()))  # no unsupported negative
        self.assertEqual(r['label_status'], 'pending')
        self.assertEqual(r['source_material']['kind'], 'cp1_record_revised')
        self.assertEqual(revision_errors(r, CP2_FIELDS), [])

    def test_s1_undeclared_change_detected(self):
        r = self.r('S13V03-SUP-S1')
        r['annotation']['per_action_targets']['write'] = False  # not in the revision list
        r['annotation']['known_mask']['write'] = 1
        self.assertTrue(any('does not reconstruct the CP1 record' in e for e in revision_errors(r, CP2_FIELDS)))

    # ---- SUP-S3 ----
    def test_s3_set_valued_oracle_keeps_gold(self):
        r = self.r('S13V03-SUP-S3')
        self.assertEqual(r['source_material']['kind'], 'sou13_v03_cp1_record')  # gold labels unchanged
        self.assertIs(r['annotation']['per_action_targets']['read'], True)
        self.assertTrue(all(r['annotation']['per_action_targets'][a] is None for a in ACTIONS if a != 'read'))
        ev = r['evaluation']
        self.assertEqual(ev['role'], 'set_valued_oracle')
        self.assertEqual(sorted(o['name'] for o in ev['accepted_outputs']), ['full_abstention', 'retain_recognized'])
        self.assertTrue(all(o['unknown'] for o in ev['accepted_outputs']))
        self.assertEqual(ev['retained_recognized_actions'], ['read'])
        self.assertEqual(r['label_status'], 'pending')
        self.assertFalse(ev['in_semantic_accuracy'] or ev['in_pilot_export'])

    # ---- preserved findings ----
    def test_dev06_and_s2_preserved(self):
        d6 = self.r('S13V03-DEV-06')['annotation']['per_action_targets']
        self.assertEqual((d6['read'], d6['send_data'], d6['write']), (True, True, False))
        s2 = self.r('S13V03-SUP-S2')
        self.assertEqual((s2['expected_outcome'], s2['technical_error']), ('technical_error', 'classifier_invalid'))
        self.assertEqual(s2['evaluation']['role'], 'technical_error_check')
        self.assertFalse(pilot(s2))

    def test_technical_review_provenance_never_confirms(self):
        cp1 = [r for r in self.records if r['source_material']['kind'] != 'new_cp2_case']
        self.assertEqual(len(cp1), 19)
        for r in cp1:
            self.assertEqual(len(r['technical_reviews']), 1, r['id'])
            t = r['technical_reviews'][0]
            self.assertEqual(t['review_kind'], 'ai_assisted_technical_review_not_human_confirmation')
            self.assertFalse(t['confirms_labels'])
            self.assertIsNone(r['review']['reviewer'])  # CP1 review block is never filled from this review
        self.assertFalse(any(r['label_status'] == 'confirmed' for r in self.records))

    def test_pilot_export_excludes_disputed_and_technical_rows(self):
        excluded = {r['id'] for r in self.records if not pilot(r)}
        for rid in ('S13V03-DEV-09', 'S13V03-SUP-S1', 'S13V03-SUP-S2', 'S13V03-SUP-S3'):
            self.assertIn(rid, excluded)
        self.assertTrue(all(r['label_status'] == 'provisional' and r['evaluation']['role'] == 'classification'
                            for r in self.records if pilot(r)))

    # ---- split assignment ----
    def test_label_and_status_revisions_do_not_move_frozen_families(self):
        frozen = freeze(build_manifest(self.fams), self.fams, **APPROVAL)
        changed = copy.deepcopy(self.fams)
        for f in changed:  # simulate further review outcomes: statuses/eligibility change, identities do not
            if f['family_id'] in ('fam.unknown.offline_summary', 'fam.shell.posix_sh', 'fam.delete.queue_ack'):
                f['pending_reasons'], f['coverage_eligible'] = ['Q-CP2-REVIEW-ADOPTION'], False
        self.assertEqual(manifest_errors(frozen, changed), [])

    def test_only_the_dev09_family_changed_in_the_draft_manifest(self):
        stored = json.loads((ROOT / FULL_MANIFEST_FILE).read_text(encoding='utf-8'))
        self.assertNotIn('fam.unknown.unadmitted_tidy', stored['family_split'])
        self.assertEqual(stored['family_split']['fam.unknown.workspace_tidy'], 'train')
        self.assertEqual(len(stored['family_split']), 45)  # + fam.unknown.firmware_flash (near-duplicate audit)


if __name__ == '__main__':
    unittest.main()
