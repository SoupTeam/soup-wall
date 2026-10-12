# SPDX-License-Identifier: Apache-2.0
"""Validate hash-chained gold-label addenda against frozen development label rows; build a separate gold view.

Inputs are exported label rows (`sou13cp2.exports.label_row`: id, split, label_status, hashes, label_sha256 and
the label core) and addendum documents (schema/gold_addendum.schema.json). Rules beyond the schema:

  * base: every addendum names the export manifest, split manifest and contract digests it was reviewed
    against; they must equal the digests the caller computed from the actual files.
  * chain: versions are 1..n without gaps; each addendum names the SHA-256 of its predecessor; the base
    cannot change inside a chain (a new base starts a new chain).
  * binding: each entry names an existing case in its scope and split, and repeats the row's label_sha256 and
    input/argument/definition digests. Any mismatch means the decision was made about different evidence.
  * transitions: from_status must equal the case's current status (frozen status, then earlier addenda).
  * confirmation: `confirmed` requires adjudication `independent_human` and a referenced approval with role
    `independent_reviewer`. Owner inspection, owner batch review and owner-rule propagation keep their own
    provenance and can never confirm a label. Every referenced decision id must be recorded in `approvals`.
  * dataset version: base.dataset_version must be listed in SUPPORTED_DATASET_VERSIONS (an explicit,
    reviewed compatibility table) and equal the version of the export being validated.
  * no silent promotion: confirming needs the independent reviewer's own label vector (`reviewer_labels`),
    which must equal the labels being confirmed (the frozen labels, or `label_change`). A provisional label
    cannot become gold by approval alone. Labels change only together with such a confirmation, and
    reviewer_labels is null for every other transition.
  * label vectors: known_mask[a] == 1 exactly when the target is non-null; nulls are never coerced to false.
  * test split: outside this interface (schema scope, and every bound row must be a development row).

`apply_addenda` refuses draft addenda and returns new objects; the given rows are never mutated. Every view
row carries `gold` (True only for `confirmed`); `gold_rows` returns the confirmed subset.
"""
import copy

from sou13.hashing import sha

ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
DEV_SPLITS = ('train', 'validation', 'calibration')
EVIDENCE_HASHES = ('input_sha256', 'arguments_sha256', 'definition_sha256')
BASE_KEYS = ('dataset_version', 'export_manifest_sha256', 'split_manifest_sha256', 'contract_sha256')
SCHEMA = 'schema/gold_addendum.schema.json'
CONFIRMING_ADJUDICATION = 'independent_human'
CONFIRMING_ROLE = 'independent_reviewer'
# Export versions an addendum may target. Adding a version needs a reviewed statement that case ids, label-row
# digests and the label_sha256 binding are unchanged (or a migration); an unknown version is always rejected.
SUPPORTED_DATASET_VERSIONS = {
    '0.4-cp2-phase1-draft': 'CP2 development export (label_row / label_sha256 as in sou13cp2.exports)',
}


class AddendumError(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors[:5]) + (f' (+{len(errors) - 5} more)' if len(errors) > 5 else ''))
        self.errors = errors


def addendum_sha(addendum):
    """Canonical-JSON SHA-256 (sou13.hashing.sha), the value a successor records as previous_addendum_sha256."""
    return sha(addendum)


def schema_errors(addendum):
    from sou13cp2.schemas import errors  # jsonschema Draft 2020-12, as for CP2 records
    return [f'schema: {e}' for e in errors(addendum, SCHEMA)]


def mask_errors(where, labels):
    e = []
    for a in ACTIONS:
        known = labels['per_action_targets'][a] is not None
        if labels['known_mask'][a] != int(known):
            e.append(f'{where}: known_mask.{a} must be {int(known)} for target {labels["per_action_targets"][a]!r}')
    return e


def label_core(row):
    return {'per_action_targets': row['per_action_targets'], 'known_mask': row['known_mask'], 'unknown': row['unknown']}


def dataset_version_errors(base):
    version = base.get('dataset_version')
    if version not in SUPPORTED_DATASET_VERSIONS:
        return [f'dataset version {version!r} is not supported by this addendum interface '
                f'(supported: {sorted(SUPPORTED_DATASET_VERSIONS)})']
    return []


def addendum_errors(addendum, rows_by_id, base, current_status, current_labels):
    """Errors for one addendum given the case statuses and labels before it (empty list = valid)."""
    e = schema_errors(addendum)
    if e:
        return e
    v = addendum['addendum_version']
    e += [f'v{v}: {x}' for x in dataset_version_errors(addendum['base'])]
    for k in BASE_KEYS:
        if addendum['base'][k] != base.get(k):
            e.append(f'v{v}: base.{k} does not match the files being validated')
    approvals = {}
    for a in addendum['approvals']:
        if a['decision_id'] in approvals:
            e.append(f'v{v}: approval {a["decision_id"]} recorded twice')
        approvals[a['decision_id']] = a
    if addendum['status'] == 'approved' and not approvals:
        e.append(f'v{v}: an approved addendum records no approvals')
    scope = set(addendum['scope']['splits'])
    seen = set()
    for i, entry in enumerate(addendum['entries']):
        cid = entry['case_id']
        where = f'v{v} entry {i} ({cid})'
        if cid in seen:
            e.append(f'{where}: case listed twice')
        seen.add(cid)
        row = rows_by_id.get(cid)
        if row is None:
            e.append(f'{where}: no such development case')
            continue
        if row['split'] not in DEV_SPLITS:
            e.append(f'{where}: test-split cases are outside the public addendum interface')
            continue
        if entry['split'] != row['split'] or row['split'] not in scope:
            e.append(f'{where}: split {entry["split"]} does not match case split {row["split"]} or scope')
        if entry['evidence']['label_sha256'] != row['label_sha256']:
            e.append(f'{where}: label_sha256 does not match the frozen label row')
        for k in EVIDENCE_HASHES:
            if entry['evidence'][k] != row['hashes'][k]:
                e.append(f'{where}: {k} does not match the frozen record')
        if entry['from_status'] != current_status[cid]:
            e.append(f'{where}: from_status {entry["from_status"]} but current status is {current_status[cid]}')
        missing = [d for d in entry['decision_ids'] if d not in approvals]
        if missing:
            e.append(f'{where}: decision ids not recorded in approvals {missing}')
        if entry['to_status'] == 'confirmed':
            if entry['adjudication'] != CONFIRMING_ADJUDICATION:
                e.append(f'{where}: {entry["adjudication"]} cannot confirm a label (independent adjudication needed)')
            if not any(approvals.get(d, {}).get('role') == CONFIRMING_ROLE for d in entry['decision_ids']):
                e.append(f'{where}: confirmation needs a referenced {CONFIRMING_ROLE} approval')
        confirming = entry['to_status'] == 'confirmed'
        if entry['label_change'] is not None:
            if not confirming:
                e.append(f'{where}: labels may change only together with an independent confirmation')
            e += mask_errors(f'{where} label_change', entry['label_change'])
        if confirming:
            result = entry['label_change'] if entry['label_change'] is not None else current_labels[cid]
            if entry['reviewer_labels'] is None:
                e.append(f"{where}: confirmation needs the independent reviewer's own labels (reviewer_labels)")
            else:
                e += mask_errors(f'{where} reviewer_labels', entry['reviewer_labels'])
                if entry['reviewer_labels'] != result:
                    e.append(f'{where}: reviewer_labels differ from the labels being confirmed; resolve first')
        elif entry['reviewer_labels'] is not None:
            e.append(f'{where}: reviewer_labels are recorded only for a confirmation')
        if entry['from_status'] == entry['to_status'] and entry['label_change'] is None:
            e.append(f'{where}: entry changes neither status nor labels')
    return e


def chain_errors(addenda, rows, base):
    """Errors for an ordered addendum chain against the frozen development label rows."""
    rows_by_id = {r['id']: r for r in rows}
    if len(rows_by_id) != len(rows):
        return ['label rows contain duplicate case ids']
    if not addenda:
        return ['no addendum given']
    version_errors = dataset_version_errors(base)
    if version_errors:
        return [f'export: {x}' for x in version_errors]
    status = {cid: r['label_status'] for cid, r in rows_by_id.items()}
    labels = {cid: label_core(r) for cid, r in rows_by_id.items()}
    e, previous = [], None
    for n, addendum in enumerate(addenda, 1):
        if addendum.get('addendum_version') != n:
            e.append(f'addendum {n}: version {addendum.get("addendum_version")} (expected {n}, no gaps)')
        expected_prev = None if previous is None else addendum_sha(previous)
        if addendum.get('previous_addendum_sha256') != expected_prev:
            e.append(f'addendum {n}: previous_addendum_sha256 does not chain to addendum {n - 1}')
        if previous is not None and addendum.get('base') != previous.get('base'):
            e.append(f'addendum {n}: base changed inside a chain')
        errs = addendum_errors(addendum, rows_by_id, base, status, labels)
        e += errs
        if not errs:
            for entry in addendum['entries']:
                status[entry['case_id']] = entry['to_status']
                if entry['label_change'] is not None:
                    labels[entry['case_id']] = entry['label_change']
        previous = addendum
    return e


def apply_addenda(rows, addenda, base):
    """Gold view: one new object per development row. Raises AddendumError on any invalid or draft addendum."""
    errors = chain_errors(addenda, rows, base)
    errors += [f'addendum {a.get("addendum_version")}: status {a.get("status")} cannot be applied'
               for a in addenda if a.get('status') != 'approved']
    if errors:
        raise AddendumError(errors)
    view = {}
    for r in rows:
        if r['split'] not in DEV_SPLITS:
            continue
        view[r['id']] = {'id': r['id'], 'split': r['split'], 'frozen_label_status': r['label_status'],
                         'frozen_label_sha256': r['label_sha256'], 'status': r['label_status'],
                         'labels': copy.deepcopy(label_core(r)), 'addenda': []}
    for a in addenda:
        a_sha = addendum_sha(a)
        for entry in a['entries']:
            v = view[entry['case_id']]
            v['status'] = entry['to_status']
            if entry['label_change'] is not None:
                v['labels'] = copy.deepcopy(entry['label_change'])
            v['addenda'].append({'version': a['addendum_version'], 'sha256': a_sha,
                                 'decision_ids': list(entry['decision_ids']), 'adjudication': entry['adjudication'],
                                 'to_status': entry['to_status']})
    for v in view.values():
        # Gold only through an addendum entry: a frozen status alone never makes a row gold.
        v['gold'] = v['status'] == 'confirmed' and bool(v['addenda']) and v['addenda'][-1]['to_status'] == 'confirmed'
        v['gold_label_sha256'] = sha({'id': v['id'], **v['labels']}) if v['gold'] else None
    return [view[k] for k in sorted(view)]


def gold_rows(view):
    """Only independently confirmed rows. Provisional or pending rows are never gold, whatever their labels."""
    return [v for v in view if v['gold']]
