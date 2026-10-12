# SPDX-License-Identifier: Apache-2.0
"""Gold-label addendum interface on SYNTHETIC rows only. No real case, label or approval is created here.

Case ids are assembled at run time; every approval is marked TEST-ONLY. These tests define what a future,
separately approved addendum must satisfy; they do not issue one."""
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sou13.cases import CONTRACT
from sou13.hashing import file_sha, sha
from sou13cp2.schemas import validator
from sou13gold.addendum import (SCHEMA, AddendumError, addendum_sha, apply_addenda, chain_errors, gold_rows,
                                label_core)
from scripts_cp2 import validate_gold_addendum as cli

H = {k: sha(k) for k in ('in', 'args', 'def', 'split', 'export')}
TARGETS = {'read': True, 'write': False, 'delete': False, 'send_data': None, 'change_permissions': False}
MASK = {'read': 1, 'write': 1, 'delete': 1, 'send_data': 0, 'change_permissions': 1}


def case(n):
    return 'S13C2-' + format(n, '032X')


def row(n, split='train', status='provisional'):
    core = {'per_action_targets': dict(TARGETS), 'known_mask': dict(MASK), 'unknown': True}
    return {'id': case(n), 'split': split, 'label_status': status,
            'hashes': {'input_sha256': sha(['in', n]), 'arguments_sha256': sha(['args', n]),
                       'definition_sha256': sha(['def', n])},
            'label_sha256': sha({'id': case(n), **core}), **core}


ROWS = [row(1), row(2, 'validation'), row(3, 'calibration', 'pending'), row(4, 'test')]
BASE = {'dataset_version': '0.4-cp2-phase1-draft', 'export_manifest_sha256': H['export'],
        'split_manifest_sha256': H['split'], 'contract_sha256': CONTRACT['sha256']}
REVIEWER = {'decision_id': 'TEST-REV-1', 'approver': 'TEST-ONLY reviewer', 'role': 'independent_reviewer',
            'approved_at': '2026-10-11', 'statement': 'TEST-ONLY: not an approval'}
OWNER = dict(REVIEWER, decision_id='TEST-OWN-1', role='dataset_owner', approver='TEST-ONLY owner')


UNSET = object()


def entry(r, to='confirmed', adjudication='independent_human', decisions=('TEST-REV-1',), change=None,
          reviewer=UNSET):
    if reviewer is UNSET:  # by default the reviewer independently arrived at the labels being confirmed
        reviewer = copy.deepcopy(change if change is not None else label_core(r)) if to == 'confirmed' else None
    return {'case_id': r['id'], 'split': r['split'],
            'evidence': {'label_sha256': r['label_sha256'], **r['hashes']},
            'from_status': r['label_status'], 'to_status': to, 'label_change': change, 'reviewer_labels': reviewer,
            'decision_ids': list(decisions), 'adjudication': adjudication, 'rationale': 'TEST-ONLY'}


def addendum(entries, version=1, previous=None, status='approved', approvals=(REVIEWER,)):
    return {'addendum_kind': 'sou13_gold_label_addendum', 'addendum_version': version,
            'previous_addendum_sha256': previous, 'status': status, 'created_at': '2026-10-11', 'base': dict(BASE),
            'scope': {'splits': ['train', 'validation', 'calibration']}, 'approvals': [dict(a) for a in approvals],
            'entries': entries}


class Schema(unittest.TestCase):
    def test_schema_is_valid_draft_2020_12(self):
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema(validator(SCHEMA).schema)

    def test_test_split_cannot_be_in_scope(self):
        a = addendum([entry(ROWS[0])])
        a['scope']['splits'].append('test')
        self.assertTrue(any(e.startswith('schema:') for e in chain_errors([a], ROWS, BASE)))


class Confirmation(unittest.TestCase):
    def test_independent_confirmation_is_accepted(self):
        self.assertEqual(chain_errors([addendum([entry(ROWS[0]), entry(ROWS[2])])], ROWS, BASE), [])

    def test_owner_provenance_can_never_confirm(self):
        for adjudication in ('owner_inspected', 'owner_batch', 'owner_rule_propagated'):
            with self.subTest(adjudication=adjudication):
                errors = chain_errors([addendum([entry(ROWS[0], adjudication=adjudication)])], ROWS, BASE)
                self.assertTrue(any('cannot confirm' in e for e in errors), errors)

    def test_confirmation_needs_an_independent_reviewer_approval(self):
        a = addendum([entry(ROWS[0], decisions=('TEST-OWN-1',))], approvals=(OWNER,))
        self.assertTrue(any('independent_reviewer approval' in e for e in chain_errors([a], ROWS, BASE)))

    def test_unrecorded_decision_id_is_rejected(self):
        a = addendum([entry(ROWS[0], decisions=('TEST-REV-1', 'TEST-REV-9'))])
        self.assertTrue(any('not recorded in approvals' in e for e in chain_errors([a], ROWS, BASE)))

    def test_owner_rule_may_record_provisional_review_without_confirming(self):
        a = addendum([entry(ROWS[2], to='provisional', adjudication='owner_rule_propagated',
                            decisions=('TEST-OWN-1',))], approvals=(OWNER,))
        self.assertEqual(chain_errors([a], ROWS, BASE), [])


class EvidenceBinding(unittest.TestCase):
    def test_changed_evidence_or_label_digest_is_rejected(self):
        for path in (('evidence', 'label_sha256'), ('evidence', 'input_sha256'), ('evidence', 'definition_sha256')):
            with self.subTest(path=path):
                e = entry(ROWS[0])
                e[path[0]][path[1]] = sha('other')
                self.assertTrue(chain_errors([addendum([e])], ROWS, BASE))

    def test_unknown_case_wrong_split_and_test_rows_are_rejected(self):
        ghost = entry(row(99))
        wrong = dict(entry(ROWS[0]), split='validation')
        test = entry(ROWS[3])
        test['split'] = 'calibration'  # schema-valid, but the bound row is a test row
        for e, needle in ((ghost, 'no such development case'), (wrong, 'does not match case split'),
                          (test, 'outside the public addendum interface')):
            with self.subTest(needle=needle):
                self.assertTrue(any(needle in x for x in chain_errors([addendum([e])], ROWS, BASE)))

    def test_base_mismatch_is_rejected(self):
        for key in BASE:
            with self.subTest(key=key):
                other = dict(BASE, **{key: sha('different')})
                # an unknown export version is refused before any comparison (see DatasetVersion)
                needle = 'not supported' if key == 'dataset_version' else f'base.{key}'
                self.assertTrue(any(needle in e for e in chain_errors([addendum([entry(ROWS[0])])],
                                                                      ROWS, other)))

    def test_label_change_keeps_nulls_masked(self):
        bad = {'per_action_targets': dict(TARGETS), 'known_mask': dict(MASK, send_data=1), 'unknown': True}
        errors = chain_errors([addendum([entry(ROWS[0], change=bad)])], ROWS, BASE)
        self.assertTrue(any('known_mask.send_data must be 0' in e for e in errors), errors)

    def test_from_status_must_be_current(self):
        e = entry(ROWS[0])
        e['from_status'] = 'pending'
        self.assertTrue(any('current status is provisional' in x for x in chain_errors([addendum([e])], ROWS, BASE)))


class Chain(unittest.TestCase):
    def setUp(self):
        self.first = addendum([entry(ROWS[0])])
        second_entry = entry(ROWS[0], to='excluded')
        second_entry['from_status'] = 'confirmed'
        self.second = addendum([second_entry], version=2, previous=addendum_sha(self.first))

    def test_valid_chain_tracks_status(self):
        self.assertEqual(chain_errors([self.first, self.second], ROWS, BASE), [])

    def test_gap_wrong_predecessor_and_base_change_are_rejected(self):
        gap = dict(copy.deepcopy(self.second), addendum_version=3)
        broken = dict(copy.deepcopy(self.second), previous_addendum_sha256=sha('x'))
        rebased = copy.deepcopy(self.second)
        rebased['base']['split_manifest_sha256'] = sha('y')
        for a, needle in ((gap, 'no gaps'), (broken, 'does not chain'), (rebased, 'base changed')):
            with self.subTest(needle=needle):
                self.assertTrue(any(needle in e for e in chain_errors([self.first, a], ROWS, BASE)))


class NoSilentPromotion(unittest.TestCase):
    def test_confirmation_without_reviewer_labels_is_rejected(self):
        errors = chain_errors([addendum([entry(ROWS[0], reviewer=None)])], ROWS, BASE)
        self.assertTrue(any("independent reviewer's own labels" in e for e in errors), errors)

    def test_reviewer_disagreement_blocks_confirmation(self):
        other = dict(label_core(ROWS[0]), unknown=False)
        errors = chain_errors([addendum([entry(ROWS[0], reviewer=other)])], ROWS, BASE)
        self.assertTrue(any('reviewer_labels differ' in e for e in errors), errors)

    def test_reviewer_labels_must_keep_nulls_masked(self):
        bad = copy.deepcopy(label_core(ROWS[0]))
        bad['known_mask']['send_data'] = 1
        errors = chain_errors([addendum([entry(ROWS[0], reviewer=bad)])], ROWS, BASE)
        self.assertTrue(any('reviewer_labels: known_mask.send_data' in e for e in errors), errors)

    def test_labels_cannot_change_without_confirmation(self):
        change = dict(copy.deepcopy(label_core(ROWS[2])), unknown=False)
        e = entry(ROWS[2], to='provisional', adjudication='owner_rule_propagated', decisions=('TEST-OWN-1',),
                  change=change)
        errors = chain_errors([addendum([e], approvals=(OWNER,))], ROWS, BASE)
        self.assertTrue(any('only together with an independent confirmation' in x for x in errors), errors)

    def test_reviewer_labels_only_accompany_a_confirmation(self):
        e = entry(ROWS[2], to='provisional', adjudication='owner_rule_propagated', decisions=('TEST-OWN-1',),
                  reviewer=label_core(ROWS[2]))
        errors = chain_errors([addendum([e], approvals=(OWNER,))], ROWS, BASE)
        self.assertTrue(any('recorded only for a confirmation' in x for x in errors), errors)

    def test_frozen_confirmed_status_alone_is_not_gold(self):
        rows = copy.deepcopy(ROWS)
        rows[1]['label_status'] = 'confirmed'  # hypothetical: frozen data carries no confirmed label
        view = apply_addenda(rows, [addendum([entry(rows[0])])], BASE)
        self.assertEqual([v['id'] for v in gold_rows(view)], [case(1)])


class DatasetVersion(unittest.TestCase):
    def test_unsupported_export_version_is_rejected(self):
        other = dict(BASE, dataset_version='0.5-unreviewed')
        a = addendum([entry(ROWS[0])])
        a['base'] = dict(other)
        self.assertTrue(any('not supported' in e for e in chain_errors([a], ROWS, other)))

    def test_addendum_for_another_version_is_rejected(self):
        a = addendum([entry(ROWS[0])])
        a['base']['dataset_version'] = '0.5-unreviewed'
        errors = chain_errors([a], ROWS, BASE)
        self.assertTrue(any('not supported' in e for e in errors), errors)
        self.assertTrue(any('base.dataset_version does not match' in e for e in errors), errors)

    def test_empty_chain_is_an_error(self):
        self.assertEqual(chain_errors([], ROWS, BASE), ['no addendum given'])


class GoldView(unittest.TestCase):
    def test_view_is_separate_and_frozen_rows_are_untouched(self):
        rows = copy.deepcopy(ROWS)
        change = {'per_action_targets': dict(TARGETS, send_data=True), 'known_mask': dict(MASK, send_data=1),
                  'unknown': False}
        a = addendum([entry(rows[0], change=change)])
        view = {v['id']: v for v in apply_addenda(rows, [a], BASE)}
        self.assertEqual(rows, ROWS)
        self.assertNotIn(case(4), view)  # test rows never enter the public gold view
        v = view[case(1)]
        self.assertEqual((v['frozen_label_status'], v['status'], v['gold']), ('provisional', 'confirmed', True))
        self.assertEqual(v['labels'], change)
        self.assertEqual(v['addenda'][0]['sha256'], addendum_sha(a))
        self.assertEqual((view[case(2)]['status'], view[case(2)]['gold']), ('provisional', False))
        self.assertIsNone(view[case(2)]['gold_label_sha256'])
        self.assertEqual([g['id'] for g in gold_rows(list(view.values()))], [case(1)])

    def test_draft_or_invalid_addenda_are_not_applied(self):
        with self.assertRaises(AddendumError):
            apply_addenda(ROWS, [addendum([entry(ROWS[0])], status='draft')], BASE)
        with self.assertRaises(AddendumError):
            apply_addenda(ROWS, [addendum([entry(ROWS[0], adjudication='owner_rule_propagated')])], BASE)


class Cli(unittest.TestCase):
    """End-to-end on a synthetic export directory written to a temporary folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.exports = Path(self.tmp.name) / 'exports'
        files = {}
        for prefix in ('', 'non_pilot/'):
            for split in ('train', 'validation', 'calibration'):
                rel = f'{prefix}labels/{split}.jsonl'
                keep = [r for r in ROWS if r['split'] == split and (r['label_status'] == 'pending') == bool(prefix)]
                p = self.exports / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(''.join(json.dumps(r) + '\n' for r in keep), encoding='utf-8')
                files[rel] = file_sha(p)
        (self.exports / 'EXPORT_MANIFEST.json').write_text(
            json.dumps({'export_kind': 'sou13_cp2_label_separated_exports', 'cp2_version': BASE['dataset_version'],
                        'files_sha256': files}), encoding='utf-8')
        self.base = dict(BASE, export_manifest_sha256=file_sha(self.exports / 'EXPORT_MANIFEST.json'))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, a):
        path = Path(self.tmp.name) / 'addendum.json'
        path.write_text(json.dumps(a), encoding='utf-8')
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(['--exports', str(self.exports), '--split-manifest-sha256', BASE['split_manifest_sha256'],
                             '--addendum', str(path)])
        return code, json.loads(out.getvalue())

    def test_pass_reads_pending_rows_and_prints_no_labels(self):
        a = addendum([entry(ROWS[0]), entry(ROWS[2])])
        a['base'] = dict(self.base)
        code, report = self.run_cli(a)
        self.assertEqual((code, report['errors']), (0, []))
        self.assertEqual(report['development_rows'], 3)
        self.assertNotIn('per_action_targets', json.dumps(report))

    def test_tampered_label_file_fails(self):
        p = self.exports / 'labels' / 'train.jsonl'
        p.write_text(p.read_text(encoding='utf-8') + '\n', encoding='utf-8')
        a = addendum([entry(ROWS[0])])
        a['base'] = dict(self.base)
        code, report = self.run_cli(a)
        self.assertEqual(code, 1)
        self.assertTrue(any('digest differs' in e for e in report['errors']))


if __name__ == '__main__':
    unittest.main()
