# SPDX-License-Identifier: Apache-2.0
"""Draft the next gold addendum (schema/gold_addendum.schema.json) from recorded decisions.
Deterministic; nothing is inferred.

Inputs:
  * development label rows (sou13cp2.exports.label_row) and the base computed from the export files;
  * the approved, export-grade addenda already issued (the chain this one extends);
  * one independent reviewer submission (schema/gold_reviewer_submission.schema.json): the reviewer's own
    label vector per case;
  * one owner decision record (schema/gold_owner_decisions.schema.json): approval records copied verbatim and
    the per-case transitions.

Every entry is bound to the frozen row's label digest and input/argument/definition digests, and its
from_status is the case's status after the existing chain. A confirmation takes `reviewer_labels` only from
the reviewer's submission, never from frozen or provisional labels. When the reviewer's labels differ from the
current labels, the owner must record an explicit, equal `label_change`; otherwise drafting fails.

PROPOSED batch attestation (pending maintainer review): the owner decisions may carry one `batch_attestation`
copied from the independent reviewer's recorded decision (decision id, reviewed artifact digests, scope statement,
the reviewer's stated case count, exclusions, explicitly stated labels). Drafting derives the case set from the
export (scope `all_cp2_development_cases`: every CP2 development row), requires its size to equal the stated
count, records the case-set digest over the frozen label digests and confirms each case with adjudication
`independent_human_batch`, without reviewer_labels or label changes. No per-case review is claimed and no
reviewer submission is needed for those cases.

The addendum carries the owner's declared status. `approved` is emitted only when the extended chain passes
every export-grade rule (sou13gold.addendum.strict_errors); a `draft` lists what still blocks approval.
"""
import copy

from sou13.hashing import sha

from .addendum import (BATCH_ADJUDICATION, BATCH_SCOPE_ALL_CP2, CONFIRMING_ADJUDICATION, CONFIRMING_ROLE, CP2_ID_PREFIX,
                       DEV_SPLITS, AddendumError, addendum_sha, batch_case_set_sha256, chain_errors, chain_records,
                       chain_state, mask_errors, person, schema_errors, strict_errors)

SUBMISSION_SCHEMA = 'schema/gold_reviewer_submission.schema.json'
DECISIONS_SCHEMA = 'schema/gold_owner_decisions.schema.json'


def _schema(doc, rel, label):
    from sou13cp2.schemas import errors
    return [f'{label}: schema: {e}' for e in errors(doc, rel)]


def submission_errors(submission, rows_by_id, approvals):
    """Shape of one reviewer submission, its recorded independent_reviewer decision and its cases."""
    e = _schema(submission, SUBMISSION_SCHEMA, 'reviewer submission')
    if e:
        return e
    approval = approvals.get(submission['decision_id'])
    if approval is None or approval.get('role') != CONFIRMING_ROLE:
        e.append(f'reviewer submission: decision {submission["decision_id"]} is not a recorded '
                 f'{CONFIRMING_ROLE} approval')
    elif person(approval['approver']) != person(submission['reviewer']):
        e.append('reviewer submission: reviewer differs from the approver of its decision')
    seen = set()
    for c in submission['cases']:
        cid, where = c['case_id'], f'reviewer submission ({c["case_id"]})'
        if cid in seen:
            e.append(f'{where}: case listed twice')
        seen.add(cid)
        row = rows_by_id.get(cid)
        if row is None or row['split'] not in DEV_SPLITS:
            e.append(f'{where}: no such development case')
        elif row['split'] != c['split']:
            e.append(f'{where}: split {c["split"]} differs from the case split {row["split"]}')
        e += mask_errors(where, c['reviewer_labels'])
    return e


def submission_binding_errors(addenda, submissions, rows):
    """Errors unless every confirmation in the chain carries exactly the labels that one supplied submission of
    the reviewer decision it cites gives for that case. The supplied submissions are checked as in drafting."""
    rows_by_id = {r['id']: r for r in rows}
    records = chain_records(addenda)
    e = []
    for n, s in enumerate(submissions):
        e += [f'submission {n}: {x}' for x in submission_errors(s, rows_by_id, records)]
    for a in addenda:
        for entry in a.get('entries', []):
            if entry['to_status'] != 'confirmed' or entry['adjudication'] == BATCH_ADJUDICATION:
                continue
            labels = [c['reviewer_labels'] for s in submissions if s.get('decision_id') in entry['decision_ids']
                      for c in s.get('cases', []) if c.get('case_id') == entry['case_id']]
            if labels != [entry['reviewer_labels']]:
                e.append(f'v{a["addendum_version"]} entry ({entry["case_id"]}): reviewer_labels are not the labels '
                         f'of exactly one supplied submission of the cited reviewer decision')
    return e


def _batch(decisions, rows_by_id, status, transitions):
    """(attestation, entries, errors) for the owner's recorded batch attestation, if any."""
    b = decisions.get('batch_attestation')
    if b is None:
        return None, [], []
    e = []
    if b['scope_kind'] != BATCH_SCOPE_ALL_CP2:
        return None, [], [f'batch attestation: unsupported scope {b["scope_kind"]!r}']
    scope = sorted(cid for cid, r in rows_by_id.items() if cid.startswith(CP2_ID_PREFIX) and r['split'] in DEV_SPLITS)
    if len(scope) != b['expected_case_count']:
        e.append(f'batch attestation: the reviewer stated {b["expected_case_count"]} case(s); the export has '
                 f'{len(scope)} CP2 development case(s)')
    clash = set(scope) & {t['case_id'] for t in transitions}
    if clash:
        e.append(f'batch attestation: {len(clash)} case(s) also have an individual transition')
    entries = [{'case_id': cid, 'split': rows_by_id[cid]['split'],
                'evidence': {'label_sha256': rows_by_id[cid]['label_sha256'],
                             **{k: rows_by_id[cid]['hashes'][k] for k in ('input_sha256', 'arguments_sha256',
                                                                          'definition_sha256')}},
                'from_status': status[cid], 'to_status': 'confirmed', 'label_change': None, 'reviewer_labels': None,
                'decision_ids': [b['decision_id']], 'adjudication': BATCH_ADJUDICATION,
                'rationale': b['scope_statement']} for cid in scope]
    attestation = {'decision_id': b['decision_id'],
                   'reviewed_artifacts': sorted(b['reviewed_artifacts'], key=lambda x: (x['name'], x['sha256'])),
                   'scope_kind': b['scope_kind'], 'scope_statement': b['scope_statement'],
                   'case_count': b['expected_case_count'],
                   'case_set_sha256': batch_case_set_sha256((cid, rows_by_id[cid]['label_sha256']) for cid in scope),
                   'excluded': dict(b['excluded']),
                   'label_assertions': sorted(({**x, 'actions': sorted(x['actions'])} for x in b['label_assertions']),
                                              key=lambda x: x['question_id'])}
    return attestation, entries, e


def draft_addendum(rows, base, previous, submission, decisions):
    """(addendum, report). Raises AddendumError on missing or inconsistent evidence. `submission` may be None
    when no case is confirmed individually."""
    rows_by_id = {r['id']: r for r in rows}
    e = _schema(decisions, DECISIONS_SCHEMA, 'owner decisions')
    if e:
        raise AddendumError(e)
    if previous:
        prior = strict_errors(previous, rows, base)
        if prior:
            raise AddendumError([f'existing chain: {x}' for x in prior])
    approvals = {a.get('decision_id'): a for a in decisions['approvals']}
    if submission is not None:
        e += submission_errors(submission, rows_by_id, approvals)
    if e:
        raise AddendumError(e)
    reviewed = {c['case_id']: c['reviewer_labels'] for c in submission['cases']} if submission else {}
    status, labels = chain_state(previous, rows)
    scope = [s for s in DEV_SPLITS if s in decisions['scope']['splits']]
    entries, seen = [], set()
    for t in decisions['transitions']:
        cid, where = t['case_id'], f'transition ({t["case_id"]})'
        if cid in seen:
            e.append(f'{where}: case listed twice')
            continue
        seen.add(cid)
        row = rows_by_id.get(cid)
        if row is None or row['split'] not in DEV_SPLITS:
            e.append(f'{where}: no such development case')
            continue
        if row['split'] != t['split'] or row['split'] not in scope:
            e.append(f'{where}: split {t["split"]} does not match case split {row["split"]} or scope')
            continue
        change = copy.deepcopy(t.get('label_change'))
        reviewer = None
        if t['to_status'] == 'confirmed':
            if cid not in reviewed:
                e.append(f'{where}: confirmation without the independent reviewer\'s own labels for this case')
                continue
            if submission is None or submission['decision_id'] not in t['decision_ids']:
                e.append(f'{where}: confirmation does not reference the reviewer decision {submission["decision_id"]}')
            if t['adjudication'] != CONFIRMING_ADJUDICATION:
                e.append(f'{where}: {t["adjudication"]} cannot confirm a label')
            reviewer = copy.deepcopy(reviewed[cid])
            if change is None and reviewer != labels[cid]:
                e.append(f'{where}: the reviewer\'s labels differ from the current labels; record an explicit '
                         f'label_change equal to them, or resolve the disagreement first')
            elif change is not None and change == labels[cid]:
                e.append(f'{where}: label_change repeats the current labels')
            elif change is not None and change != reviewer:
                e.append(f'{where}: label_change differs from the reviewer\'s labels')
        elif change is not None:
            e.append(f'{where}: labels may change only together with an independent confirmation')
        entries.append({'case_id': cid, 'split': row['split'],
                        'evidence': {'label_sha256': row['label_sha256'], **{k: row['hashes'][k] for k in
                                     ('input_sha256', 'arguments_sha256', 'definition_sha256')}},
                        'from_status': status[cid], 'to_status': t['to_status'], 'label_change': change,
                        'reviewer_labels': reviewer, 'decision_ids': sorted(t['decision_ids']),
                        'adjudication': t['adjudication'], 'rationale': t['rationale']})
    attestation, batch_entries, batch_errors = _batch(decisions, rows_by_id, status, decisions['transitions'])
    e += batch_errors
    if not entries and not batch_entries:
        e.append('owner decisions: no transition and no batch attestation')
    if e:
        raise AddendumError(e)
    entries += batch_entries
    addendum = {'addendum_kind': 'sou13_gold_label_addendum', 'addendum_version': len(previous) + 1,
                'previous_addendum_sha256': addendum_sha(previous[-1]) if previous else None,
                'status': decisions['status'], 'created_at': decisions['created_at'], 'base': dict(base),
                'scope': {'splits': scope},
                'approvals': sorted(decisions['approvals'], key=lambda a: str(a.get('decision_id'))),
                'entries': sorted(entries, key=lambda x: x['case_id'])}
    if attestation is not None:
        addendum['batch_attestations'] = [attestation]
    chain = list(previous) + [addendum]
    e = schema_errors(addendum) or chain_errors(chain, rows, base)
    if e:
        raise AddendumError(e)
    blockers = strict_errors(list(previous) + [dict(addendum, status='approved')], rows, base)
    if addendum['status'] == 'approved' and blockers:
        raise AddendumError(blockers)
    transitions = {}
    for x in addendum['entries']:
        k = f'{x["from_status"]}->{x["to_status"]}'
        transitions[k] = transitions.get(k, 0) + 1
    report = {'addendum_version': addendum['addendum_version'], 'status': addendum['status'],
              'entries': len(entries), 'transitions': dict(sorted(transitions.items())),
              'reviewed_cases_without_transition': len(set(reviewed) - seen),
              'batch_confirmations': len(batch_entries),
              'ready_for_approval': not blockers, 'blocking': blockers, 'addendum_sha256': addendum_sha(addendum),
              'reviewer_submission_sha256': sha(submission) if submission else None}
    return addendum, report
