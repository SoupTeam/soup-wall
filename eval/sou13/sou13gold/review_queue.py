# SPDX-License-Identifier: Apache-2.0
"""Transcribe an independent reviewer's completed CP2 review queue into a reviewer submission (deterministic).

The queue is the CSV the development review package ships for decisions (sou13cp2.exports.review_queue:
QUEUE_FIELDS + sou13.build.REVIEW_FIELDS). Per case the reviewer writes, for each action and for `unknown`,
either `agree` (the proposed value shown in the same row) or an explicit `true` / `false` / `null`, plus
`evidence_confirmed_Y_N` and `overall_decision_accept_revise_pending`.

This is a transcription, not an inference:
  * only rows with overall decision `accept` and evidence confirmed `Y` become submission cases; `revise`,
    `pending` and blank rows are counted and left out (they cannot be confirmed);
  * `agree` resolves to the proposed value of that row, and only when that proposed value equals the frozen
    label row of the export: agreement with anything else is an error;
  * a blank or unrecognised action or unknown decision on an accepted row is an error, never a default;
  * known_mask follows from the reviewer's targets (1 exactly when the target is not null);
  * the reviewer name must be the same on every accepted row and equal the name given by the caller;
  * the decision id and the submission date come from the caller's recorded decision; nothing is invented.
"""
import csv
import io

from sou13.labels import ACTIONS

from .addendum import DEV_SPLITS, AddendumError, person

ACCEPT, EVIDENCE_YES = 'accept', 'y'
VALUES = {'true': True, 'false': False, 'null': None}


def _value(raw, proposed, where, field):
    v = (raw or '').strip().lower()
    if v == 'agree':
        v = (proposed or '').strip().lower()
        if v not in VALUES:
            raise AddendumError([f'{where}: {field} is `agree` but the proposed value {proposed!r} is not '
                                 f'true/false/null'])
    if v not in VALUES:
        raise AddendumError([f'{where}: {field} decision {raw!r} is not agree/true/false/null'])
    return VALUES[v]


def transcribe(queue_text, rows, reviewer, decision_id, submitted_at):
    """(submission, report). Raises AddendumError on any blank, unrecognised or inconsistent decision."""
    rows_by_id = {r['id']: r for r in rows}
    reader = csv.DictReader(io.StringIO(queue_text.lstrip('﻿')))
    required = (['case_id', 'split'] + [f'proposed_{a}' for a in ACTIONS] + ['proposed_unknown', 'reviewer_name']
                + [f'{a}_decision' for a in ACTIONS]
                + ['unknown_decision', 'evidence_confirmed_Y_N', 'overall_decision_accept_revise_pending'])
    missing = [c for c in required if c not in (reader.fieldnames or [])]
    if missing:
        raise AddendumError([f'review queue: missing columns {missing}'])
    errors, cases, seen = [], [], set()
    left_out = {'revise': 0, 'pending': 0, 'blank_or_other': 0, 'evidence_not_confirmed': 0}
    for line in reader:
        cid = (line['case_id'] or '').strip()
        where = f'review queue ({cid})'
        if cid in seen:
            errors.append(f'{where}: case listed twice')
            continue
        seen.add(cid)
        overall = (line['overall_decision_accept_revise_pending'] or '').strip().lower()
        if overall != ACCEPT:
            left_out[overall if overall in ('revise', 'pending') else 'blank_or_other'] += 1
            continue
        if (line['evidence_confirmed_Y_N'] or '').strip().lower() != EVIDENCE_YES:
            left_out['evidence_not_confirmed'] += 1
            continue
        row = rows_by_id.get(cid)
        if row is None or row['split'] not in DEV_SPLITS:
            errors.append(f'{where}: not a development case of the export')
            continue
        if (line['split'] or '').strip() != row['split']:
            errors.append(f'{where}: split differs from the export')
        if person(line['reviewer_name'] or '') != person(reviewer):
            errors.append(f'{where}: reviewer name differs from the reviewer of the recorded decision')
        try:
            proposed = {a: _value(line[f'proposed_{a}'], None, where, f'proposed_{a}') for a in ACTIONS}
            proposed_unknown = _value(line['proposed_unknown'], None, where, 'proposed_unknown')
            if proposed != row['per_action_targets'] or proposed_unknown != row['unknown']:
                errors.append(f'{where}: proposed values in the queue differ from the frozen label row')
                continue
            targets = {a: _value(line[f'{a}_decision'], line[f'proposed_{a}'], where, f'{a}_decision')
                       for a in ACTIONS}
            unknown = _value(line['unknown_decision'], line['proposed_unknown'], where, 'unknown_decision')
        except AddendumError as exc:
            errors += exc.errors
            continue
        if unknown is None:
            errors.append(f'{where}: unknown_decision must be true or false')
            continue
        cases.append({'case_id': cid, 'split': row['split'],
                      'reviewer_labels': {'per_action_targets': targets,
                                          'known_mask': {a: int(targets[a] is not None) for a in ACTIONS},
                                          'unknown': unknown}})
    if errors:
        raise AddendumError(errors)
    if not cases:
        raise AddendumError(['review queue: no accepted case with confirmed evidence'])
    cases.sort(key=lambda c: c['case_id'])
    submission = {'submission_kind': 'sou13_gold_reviewer_submission', 'reviewer': reviewer,
                  'decision_id': decision_id, 'submitted_at': submitted_at, 'cases': cases}
    agreed = sum(c['reviewer_labels']['per_action_targets'] == rows_by_id[c['case_id']]['per_action_targets']
                 and c['reviewer_labels']['unknown'] == rows_by_id[c['case_id']]['unknown'] for c in cases)
    report = {'queue_rows': len(seen), 'accepted_cases': len(cases),
              'accepted_by_split': {s: sum(c['split'] == s for c in cases) for s in DEV_SPLITS},
              'accepted_equal_to_frozen_labels': agreed, 'accepted_with_reviewer_changes': len(cases) - agreed,
              'left_out': left_out}
    return submission, report
