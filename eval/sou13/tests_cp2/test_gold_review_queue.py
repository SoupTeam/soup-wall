# SPDX-License-Identifier: Apache-2.0
"""Review-queue transcription into a reviewer submission, on a SYNTHETIC world only (see _goldworld.py).

The queue format is the one the development review package ships (sou13cp2.exports.QUEUE_FIELDS +
sou13.build.REVIEW_FIELDS). No real queue, reviewer decision or label is used."""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import _goldworld as W
from sou13.build import REVIEW_FIELDS
from sou13cp2 import ROOT
from sou13cp2.exports import QUEUE_FIELDS
from sou13gold.addendum import AddendumError, apply_addenda_strict
from sou13gold.draft import draft_addendum, submission_binding_errors
from sou13gold.review_queue import transcribe

REVIEWER = 'Synthetic Reviewer'


def fmt(v):
    return 'null' if v is None else str(v).lower()


def queue(rows, decisions=None, cases=W.GOLD):
    """A completed queue: every listed case `agree` on every action and unknown, accepted, evidence confirmed;
    `decisions` overrides review columns per case number."""
    by_id = {r['id']: r for r in rows}
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=QUEUE_FIELDS + REVIEW_FIELDS, lineterminator='\n')
    w.writeheader()
    for n in cases:
        r = by_id[W.case(n)]
        line = {k: '' for k in QUEUE_FIELDS + REVIEW_FIELDS}
        line.update({'case_id': r['id'], 'split': r['split'], 'label_status': r['label_status'],
                     **{f'proposed_{a}': fmt(r['per_action_targets'][a]) for a in W.ACTIONS},
                     'proposed_unknown': fmt(r['unknown']), 'reviewer_name': REVIEWER,
                     **{f'{a}_decision': 'agree' for a in W.ACTIONS}, 'unknown_decision': 'agree',
                     'evidence_confirmed_Y_N': 'Y', 'overall_decision_accept_revise_pending': 'accept',
                     'review_timestamp': '2026-10-11'})
        line.update((decisions or {}).get(n, {}))
        w.writerow(line)
    return '﻿' + buf.getvalue()  # the package writes queues with a BOM


def has(errors, needle):
    return any(needle in e for e in errors)


class Transcription(unittest.TestCase):
    def setUp(self):
        self.rows, _ = W.rows_and_inputs()
        self.by_id = {r['id']: r for r in self.rows}

    def run_transcribe(self, text):
        return transcribe(text, self.rows, REVIEWER, 'SYN-REV-1', '2026-10-11')

    def test_agreement_transcribes_the_frozen_labels_and_drafts_a_valid_addendum(self):
        sub, report = self.run_transcribe(queue(self.rows))
        self.assertEqual(report['accepted_cases'], len(W.GOLD))
        self.assertEqual(report['accepted_with_reviewer_changes'], 0)
        for c in sub['cases']:
            self.assertEqual(c['reviewer_labels'], W.labels_of(self.by_id[c['case_id']]))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        exports = W.write_exports(Path(tmp.name) / 'e', self.rows, W.rows_and_inputs()[1])
        base = W.base_for(exports)
        a = draft_addendum(self.rows, base, [], sub, W.decisions(self.rows))[0]
        self.assertEqual(submission_binding_errors([a], [sub], self.rows), [])
        self.assertEqual(len([v for v in apply_addenda_strict(self.rows, [a], base) if v['gold']]), len(W.GOLD))

    def test_explicit_reviewer_values_are_kept_and_need_a_label_change_to_be_drafted(self):
        sub, report = self.run_transcribe(queue(self.rows, {1: {'write_decision': 'null'}}))
        self.assertEqual(report['accepted_with_reviewer_changes'], 1)
        labels = {c['case_id']: c['reviewer_labels'] for c in sub['cases']}[W.case(1)]
        self.assertEqual((labels['per_action_targets']['write'], labels['known_mask']['write']), (None, 0))
        with self.assertRaises(AddendumError) as ctx:
            self.draft(sub)
        self.assertTrue(has(ctx.exception.errors, 'differ from the current labels'))

    def draft(self, sub):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        exports = W.write_exports(Path(tmp.name) / 'e', self.rows, W.rows_and_inputs()[1])
        return draft_addendum(self.rows, W.base_for(exports), [], sub, W.decisions(self.rows))

    def test_pending_revise_and_unconfirmed_rows_are_left_out_not_promoted(self):
        text = queue(self.rows, {1: {'overall_decision_accept_revise_pending': 'pending'},
                                 2: {'overall_decision_accept_revise_pending': 'revise'},
                                 4: {'overall_decision_accept_revise_pending': ''},
                                 5: {'evidence_confirmed_Y_N': 'N'}})
        sub, report = self.run_transcribe(text)
        self.assertEqual([c['case_id'] for c in sub['cases']], [W.case(3)])
        self.assertEqual(report['left_out'], {'revise': 1, 'pending': 1, 'blank_or_other': 1,
                                              'evidence_not_confirmed': 1})

    def test_blank_or_unrecognised_decisions_on_an_accepted_row_fail(self):
        for value in ('', 'yes', 'maybe'):
            with self.subTest(value=value), self.assertRaises(AddendumError) as ctx:
                self.run_transcribe(queue(self.rows, {2: {'delete_decision': value}}))
            self.assertTrue(has(ctx.exception.errors, 'delete_decision decision'))

    def test_unknown_decision_cannot_be_null(self):
        with self.assertRaises(AddendumError) as ctx:
            self.run_transcribe(queue(self.rows, {2: {'unknown_decision': 'null'}}))
        self.assertTrue(has(ctx.exception.errors, 'unknown_decision must be true or false'))

    def test_agreement_with_values_other_than_the_frozen_labels_fails(self):
        with self.assertRaises(AddendumError) as ctx:
            self.run_transcribe(queue(self.rows, {1: {'proposed_read': 'false'}}))
        self.assertTrue(has(ctx.exception.errors, 'differ from the frozen label row'))

    def test_reviewer_name_and_cases_must_match(self):
        for override, needle in (({'reviewer_name': 'Someone Else'}, 'reviewer name differs'),
                                 ({'split': 'validation'}, 'split differs'),
                                 ({'case_id': W.case(99)}, 'not a development case')):
            with self.subTest(needle=needle), self.assertRaises(AddendumError) as ctx:
                self.run_transcribe(queue(self.rows, {1: override}))
            self.assertTrue(has(ctx.exception.errors, needle))

    def test_missing_review_columns_fail(self):
        text = queue(self.rows).replace('unknown_decision', 'unknown_choice')
        with self.assertRaises(AddendumError) as ctx:
            self.run_transcribe(text)
        self.assertTrue(has(ctx.exception.errors, 'missing columns'))

    def test_nothing_accepted_fails(self):
        text = queue(self.rows, {n: {'overall_decision_accept_revise_pending': 'pending'} for n in W.GOLD})
        with self.assertRaises(AddendumError):
            self.run_transcribe(text)


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.rows, inputs = W.rows_and_inputs()
        self.exports = W.write_exports(self.dir / 'exports', self.rows, inputs)
        self.queue = W.write(self.dir / 'queue.csv', queue(self.rows))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *extra, decision='SYN-REV-1', out='out/reviewer_submission.json'):
        from scripts_cp2 import submission_from_review_queue as cli
        argv = ['--queue', self.queue, '--exports', self.exports, '--reviewer', REVIEWER, '--decision-id', decision,
                '--submitted-at', '2026-10-11', '--out', out if Path(str(out)).is_absolute() else self.dir / out,
                *extra]
        buf = io.StringIO()
        from contextlib import redirect_stdout
        with redirect_stdout(buf):
            code = cli.main([str(x) for x in argv])
        return code, json.loads(buf.getvalue())

    def test_writes_a_schema_valid_submission_and_prints_no_labels(self):
        code, report = self.run_cli('--expect-cases', len(W.GOLD))
        self.assertEqual((code, report['result'], report['accepted_cases']), (0, 'WRITTEN', len(W.GOLD)))
        self.assertNotIn('per_action_targets', json.dumps(report))
        sub = json.loads((self.dir / 'out' / 'reviewer_submission.json').read_text(encoding='utf-8'))
        self.assertEqual(sub['decision_id'], 'SYN-REV-1')

    def test_count_mismatch_placeholder_overwrite_and_repository_are_refused(self):
        code, report = self.run_cli('--expect-cases', 179)
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'expected exactly 179'))
        code, report = self.run_cli(decision='TBD-REV-1')
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'placeholder'))
        self.assertEqual(self.run_cli()[0], 0)
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        self.assertTrue(has(report['errors'], 'refusing to overwrite'))
        code, report = self.run_cli(out=ROOT / 'never-written-submission.json')
        self.assertEqual(code, 1)
        self.assertFalse((ROOT / 'never-written-submission.json').exists())


if __name__ == '__main__':
    unittest.main()
