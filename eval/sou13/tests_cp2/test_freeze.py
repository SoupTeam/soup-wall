"""Authoritative FROZEN manifests (temporary copies only; the repository manifest stays DRAFT)."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from sou13cp2 import ROOT
from sou13cp2.pipeline import FULL_MANIFEST_FILE, authoritative_manifest
from sou13cp2.splits import (SplitError, _sign, amend, build_manifest, family_fingerprint, freeze, is_frozen,
                             manifest_errors)
from sou13cp2.taxonomy import PLANNED_FAMILIES, _finalise, families
from _testsupport import FULL_MANIFEST, requires

APPROVAL = dict(approved_by='TEST-ONLY approver', approved_at='2026-10-10T00:00:00+05:00',
                decision_ref='unit-test, not a real approval')


def _by(fams, fid):
    return next(f for f in fams if f['family_id'] == fid)


class FreezeIsExplicit(unittest.TestCase):
    def setUp(self):
        self.fams = families()
        self.draft = build_manifest(self.fams)

    def test_a_draft_cannot_be_amended(self):
        self.assertFalse(is_frozen(self.draft))
        with self.assertRaises(SplitError):
            amend(self.draft, self.fams, add=[], approved_by='x', reason='y')

    @requires(FULL_MANIFEST)
    def test_repository_manifest_is_frozen_valid_and_authoritative(self):
        # The owner froze the full split manifest; it is never regenerated (it was asserted DRAFT before the freeze).
        stored = json.loads((ROOT / FULL_MANIFEST_FILE).read_text(encoding='utf-8'))
        self.assertTrue(is_frozen(stored))
        self.assertEqual((stored['status'], stored['frozen']), ('FROZEN', True))
        record = stored['freeze_record']
        self.assertTrue(record and all(record.get(k) for k in ('approved_by', 'approved_at', 'decision_ref')))
        self.assertEqual(manifest_errors(stored, self.fams), [])
        self.assertEqual(authoritative_manifest(ROOT, self.fams), stored)

    def test_freeze_requires_approval_fields(self):
        for missing in ('approved_by', 'approved_at', 'decision_ref'):
            args = dict(APPROVAL, **{missing: ''})
            with self.assertRaises(SplitError):
                freeze(self.draft, self.fams, **args)

    def test_freeze_refuses_invalid_manifest(self):
        bad = copy.deepcopy(self.draft)
        bad['family_split']['fam.read.http_get'] = 'validation'
        with self.assertRaises(SplitError):
            freeze(_sign(bad), self.fams, **APPROVAL)

    def test_amend_on_draft_refused(self):
        with self.assertRaises(SplitError):
            amend(self.draft, self.fams, add=[], approved_by='x', reason='y')


class FrozenIsAuthoritative(unittest.TestCase):
    def setUp(self):
        self.fams = families()
        self.frozen = freeze(build_manifest(self.fams), self.fams, **APPROVAL)

    def test_frozen_valid(self):
        self.assertEqual(manifest_errors(self.frozen, self.fams), [])

    def test_status_and_label_changes_move_nothing(self):
        # regression of the pre-freeze finding: one pending decision reshuffled 28 families in the DRAFT rebuild
        changed = copy.deepcopy(self.fams)
        f = _by(changed, 'fam.delete.queue_ack')
        f['pending_reasons'], f['coverage_eligible'] = ['Q-CP2-ACK'], False
        f['open_questions'] = sorted(set(f['open_questions']) | {'Q-CP2-ACK'})
        f['planned_cases'] -= 1  # case-count change is not leakage-relevant either
        draft_moves = [k for k, v in build_manifest(changed)['family_split'].items()
                       if self.frozen['family_split'][k] != v]
        self.assertTrue(draft_moves, 'the DRAFT rebuild is expected to reshuffle (that is why freezing matters)')
        self.assertEqual(family_fingerprint(f), self.frozen['family_fingerprints'][f['family_id']])
        self.assertEqual(manifest_errors(self.frozen, changed), [])

    def test_pipeline_uses_frozen_manifest_without_regenerating(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / FULL_MANIFEST_FILE
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps(self.frozen), encoding='utf-8')
            self.assertEqual(authoritative_manifest(tmp, self.fams, salt='a-different-salt'), self.frozen)

    def test_new_family_requires_amend_and_moves_nobody(self):
        new = _finalise(copy.deepcopy(PLANNED_FAMILIES[0]) | {
            'family_id': 'fam.read.extra_probe', 'identities': [['synthetic-extra', 'probe_status']],
            'descriptions': ['Probe something new.'], 'honest_description': 'Probe something new.',
            'misleading_description': None,
            'templates': [dict(PLANNED_FAMILIES[0]['templates'][0], variant='only', arg_keys=['probe'],
                               schema={'type': 'object', 'properties': {'probe': {'type': 'number'}},
                                       'required': ['probe'], 'additionalProperties': False})]})
        grown = self.fams + [new]
        self.assertTrue(any('new family not in the frozen manifest' in e for e in manifest_errors(self.frozen, grown)))
        amended = amend(self.frozen, grown, add=['fam.read.extra_probe'], approved_by='x', reason='unit test')
        self.assertEqual(manifest_errors(amended, grown), [])
        for fid, split in self.frozen['family_split'].items():
            self.assertEqual(amended['family_split'][fid], split)
        self.assertIn(amended['family_split']['fam.read.extra_probe'], ('train', 'validation', 'calibration'))
        with self.assertRaises(SplitError):
            amend(amended, grown, add=['fam.read.extra_probe'], approved_by='x', reason='again')

    def test_changed_family_requires_acknowledgement(self):
        changed = copy.deepcopy(self.fams)
        _by(changed, 'fam.write.flag_set')['descriptions'].append('Flip a configuration switch.')
        self.assertTrue(any('leakage-relevant attributes changed' in e for e in manifest_errors(self.frozen, changed)))
        acked = amend(self.frozen, changed, acknowledge_changed=['fam.write.flag_set'], approved_by='x', reason='y')
        self.assertEqual(manifest_errors(acked, changed), [])
        self.assertEqual(acked['family_split'], self.frozen['family_split'])

    def test_change_creating_cross_split_link_is_refused(self):
        changed = copy.deepcopy(self.fams)
        val = next(f for f in changed if self.frozen['family_split'][f['family_id']] == 'validation')
        train = next(f for f in changed if self.frozen['family_split'][f['family_id']] == 'train'
                     and f['descriptions'])
        val['descriptions'].append(train['descriptions'][0])
        with self.assertRaises(SplitError):
            amend(self.frozen, changed, acknowledge_changed=[val['family_id']], approved_by='x', reason='y')

    def test_removed_family_is_an_error(self):
        fewer = [f for f in self.fams if f['family_id'] != 'fam.write.flag_set']
        self.assertTrue(any('removed from the taxonomy' in e for e in manifest_errors(self.frozen, fewer)))

    def test_editing_frozen_assignment_is_detected_even_if_resigned(self):
        m = copy.deepcopy(self.frozen)
        m['family_split']['fam.write.flag_set'] = 'calibration'
        errors = manifest_errors(_sign(m), self.fams)
        self.assertTrue(any('frozen assignment validation changed' in e or 'changed to' in e for e in errors), errors)
        m2 = copy.deepcopy(m)
        m2['freeze_record']['frozen_assignment']['fam.write.flag_set'] = 'calibration'
        self.assertTrue(any('altered after freeze' in e for e in manifest_errors(_sign(m2), self.fams)))


if __name__ == '__main__':
    unittest.main()
