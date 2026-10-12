"""Phase 2 candidate records: evidence integrity, status rules, coverage gate, leakage and sealing."""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from sou13cp2 import ROOT
from sou13cp2.coverage import gate, split_coverage
from sou13cp2.exports import model_input, public_leak_errors
from sou13cp2.leakage import leakage_errors, record_item, taxonomy_items
from sou13cp2.pipeline import CANDIDATES_FILE, SEALED_CANDIDATES, load_records, validate
from sou13cp2.records import record_errors
from _util import mutant
from _testsupport import (CP1_DATA, CP2_PUBLIC, OPEN_QUESTIONS, RESTRICTED_FAMILIES, SEALED_CANDIDATES_ART,
                          requires, requires_owner_anchor)

# Full-mode suites: the expected totals (252 records, a 'test' coverage slot) include the sealed test split.
FULL = (CP1_DATA, CP2_PUBLIC, RESTRICTED_FAMILIES, SEALED_CANDIDATES_ART)


@requires(*FULL)
class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from sou13cp2.splits import build_manifest
        from sou13cp2.taxonomy import families
        cls.fams = families()
        cls.manifest = build_manifest(cls.fams)
        cls.records = load_records(ROOT, cls.fams, cls.manifest)
        cls.by_fam = {f['family_id']: f for f in cls.fams}

    def new(self, split=None, family_prefix=''):
        return copy.deepcopy(next(r for r in self.records if r['source_material']['kind'] == 'new_cp2_case'
                                  and (split is None or r['split'] == split)
                                  and r['family_id'].startswith('fam.' + family_prefix)))

    def errors(self, r):
        return record_errors(r, self.by_fam, self.manifest)


@requires(*FULL)
class CandidateIntegrity(Base):
    def test_counts(self):
        # 245 + the admitted replacement of DEV-09 + 6 cases of fam.unknown.firmware_flash (near-duplicate audit)
        self.assertEqual(len(self.records), 252)
        self.assertEqual(sum(r['source_material']['kind'] == 'new_cp2_case' for r in self.records), 233)
        self.assertFalse(any(r['label_status'] == 'confirmed' for r in self.records))
        self.assertTrue(all(r['review']['reviewer'] is None for r in self.records))

    def test_every_new_record_valid(self):
        for r in self.records:
            if r['source_material']['kind'] == 'new_cp2_case':
                self.assertEqual(self.errors(r), [], r['id'])

    def test_ids_do_not_reveal_family(self):
        for r in self.records:
            if r['source_material']['kind'] == 'new_cp2_case':
                self.assertRegex(r['id'], r'^S13C2-[0-9A-F]{32}$')  # 128-bit random ids (audit F1)
                self.assertEqual(sorted(model_input(r)), ['hashes', 'id', 'input', 'input_profile', 'split'])

    def test_flipped_label_detected(self):
        r = self.new('validation', 'read.')
        r['annotation']['per_action_targets']['write'] = True
        errors = self.errors(r)
        self.assertTrue(any('derived from the execution' in e for e in errors), errors)

    def test_swapped_semantics_detected(self):
        r = self.new('test', 'delete.')
        r['evidence']['program'] = [{'op': 'read', 'store': 'x', 'key': 'y'}]
        self.assertTrue(any('not the registry program' in e for e in self.errors(r)))

    def test_tampered_trace_detected(self):
        r = self.new('calibration', 'send_data.')
        r['evidence']['execution']['trace'] = []
        self.assertTrue(any('differs from re-execution' in e for e in self.errors(r)))

    def test_confirmed_rejected(self):
        r = self.new('train')
        r['label_status'] = 'confirmed'
        self.assertTrue(any('never confirms' in e for e in self.errors(r)))

    def test_fabricated_review_rejected(self):
        r = self.new('train')
        r['review'].update({'reviewer': '@someone', 'decision': 'accept', 'reviewed_at': '2026-10-10T12:00:00+05:00'})
        self.assertTrue(any('review fields filled' in e for e in self.errors(r)))

    def test_pending_family_must_stay_pending(self):
        r = copy.deepcopy(next(x for x in self.records if x['family_id'] == 'fam.mixed.record_archive'))
        self.assertEqual(r['label_status'], 'pending')
        r['label_status'] = 'provisional'
        self.assertTrue(any('must be pending' in e for e in self.errors(r)))

    def test_foreign_description_detected(self):
        donor = self.new('test', 'send_data.')
        r = mutant(self.new('validation', 'read.'), 'MUT-FOREIGN-DESC',
                   input_changes={'tool_description': donor['input']['tool_description']})
        self.assertTrue(any('not a declared description' in e for e in self.errors(r)))
        leak = leakage_errors(taxonomy_items(self.fams, self.manifest) + [record_item(x) for x in self.records + [r]])
        self.assertTrue(any(e.startswith('LEAK description=') for e in leak), leak)

    def test_new_record_moved_to_other_split_leaks(self):
        r = self.new('validation')
        r = mutant(r, 'MUT-MOVED', split='test', input_changes={'raw_arguments': r['input']['raw_arguments']})
        leak = leakage_errors(taxonomy_items(self.fams, self.manifest) + [record_item(x) for x in self.records + [r]])
        self.assertTrue(any(e.startswith('LEAK family=') for e in leak))
        self.assertTrue(any(e.startswith('LEAK input_sha256=') for e in leak))


@requires(*FULL)
class CoverageGate(Base):
    def test_actual_gate_passes(self):
        self.assertEqual(gate(split_coverage(self.records, self.fams)), {'validation': [], 'calibration': [], 'test': []})

    def test_removing_a_stratum_fails_the_gate(self):
        fam = next(f for f, s in self.manifest['family_split'].items() if s == 'validation' and f.startswith('fam.delete.'))
        kept = [r for r in self.records if r['family_id'] != fam]
        fails = gate(split_coverage(kept, self.fams))['validation']
        self.assertTrue(any("missing strata ['delete']" in f for f in fails), fails)

    def test_too_few_positives_fails_the_gate(self):
        kept = [r for r in self.records if not (r['split'] == 'calibration' and r['annotation']['per_action_targets']
                                                and r['annotation']['per_action_targets']['delete'] is True)]
        fails = gate(split_coverage(kept, self.fams))['calibration']
        self.assertTrue(any(f.startswith('delete: known_positive=0') for f in fails), fails)

    def test_pending_records_do_not_count(self):
        recs = copy.deepcopy(self.records)
        for r in recs:
            if r['split'] == 'test':
                r['label_status'] = 'pending'
        self.assertTrue(gate(split_coverage(recs, self.fams))['test'])


class SealingOnDisk(unittest.TestCase):
    """Adversarial checks on a temporary copy of the project (the real artefacts are never modified)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / 'proj'
        shutil.copytree(ROOT, cls.root, ignore=shutil.ignore_patterns('__pycache__', '.git'))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @requires(CP1_DATA, CP2_PUBLIC, OPEN_QUESTIONS)
    @requires_owner_anchor()  # frozen manifest: validation authenticates it first
    def test_clean_copy_passes(self):
        report = validate(self.root, run_cp1=False, rebuild=False)
        self.assertEqual(report['errors'], [])

    @requires(CP2_PUBLIC, SEALED_CANDIDATES_ART)
    @requires_owner_anchor()  # the record checks run only after the anchor check
    def test_test_records_in_public_candidates_rejected(self):
        cand, sealed = self.root / CANDIDATES_FILE, self.root / SEALED_CANDIDATES
        original = cand.read_bytes()
        try:
            cand.write_bytes(original + sealed.read_bytes().splitlines(keepends=True)[0])
            report = validate(self.root, run_cp1=False, rebuild=False)
            # The manifest is FROZEN: validation authenticates the anchored artefacts first and stops there, so the
            # owner-signed anchor is the control that rejects a sealed record appended to the public candidates.
            self.assertEqual(report['result'], 'FAIL')
            self.assertTrue(any(f'{CANDIDATES_FILE} differs from the owner-signed anchor' in e
                                for e in report['errors']), report['errors'][:5])
        finally:
            cand.write_bytes(original)

    @requires(SEALED_CANDIDATES_ART)
    def test_test_labels_in_any_public_file_rejected(self):
        sealed = self.root / SEALED_CANDIDATES
        leaked = self.root / 'cp2' / 'reports' / 'notes_for_team.json'
        row = json.loads(sealed.read_text(encoding='utf-8').splitlines()[0])
        leaked.write_text(json.dumps({'id': row['id'], 'labels': row['annotation']['per_action_targets']}),
                          encoding='utf-8')
        try:
            records = [json.loads(x) for x in sealed.read_text(encoding='utf-8').splitlines()]
            errors = public_leak_errors(self.root, records)
            self.assertTrue(any('notes_for_team.json: contains test record ids' in e for e in errors), errors)
        finally:
            leaked.unlink()


if __name__ == '__main__':
    unittest.main()
