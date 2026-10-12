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

PROPOSED batch attestation (pending maintainer review; additive, the per-case mode above is unchanged): an
independent reviewer's explicit batch approval of an exact artifact may confirm cases with adjudication
`independent_human_batch` instead of per-case reviewer labels. Its invariants (`batch_errors`):

  * the attestation's decision is a recorded independent_reviewer approval of the same addendum, and each batch
    entry cites exactly one attestation;
  * a batch entry confirms only: no label_change, no reviewer_labels (it never claims per-case review), and the
    case's current labels must still be its frozen labels;
  * the confirmed cases are exactly the attested set: their count equals case_count and the canonical SHA-256 of
    the sorted [{id, label_sha256}] equals case_set_sha256; for scope `all_cp2_development_cases` they are all
    and only the CP2 (S13C2-) development rows, and excluded.cp1_cases equals the remaining development rows;
  * every label the reviewer stated explicitly (`label_assertions`, by question) holds for each confirmed case
    carrying that question, and the number of such cases equals the stated count; otherwise those cases stay
    blocked;
  * the reviewed artifact digests must include the anchored development package (`batch_artifact_errors`,
    checked where the anchor is available: strict validation and the export).

`apply_addenda` refuses draft addenda and returns new objects; the given rows are never mutated. Every view
row carries `gold` (True only for `confirmed`); `gold_rows` returns the confirmed subset.

Export grade (`strict_errors`, `apply_addenda_strict`), on the schema above without additional fields:

  * every addendum in the chain is `approved` (drafts stay valid under `chain_errors` but are never exported);
  * a decision id names one record across the whole chain; placeholder values (TODO, TBD, EXAMPLE, <...>) are
    rejected;
  * an independent_reviewer approver is never also a dataset_owner approver in the chain;
  * gold eligibility: only rows evaluated as plain classification (no technical-error, admission or
    set-valued-oracle role) can be confirmed.

No addendum approval, whatever its role, authorises model training: that needs the separate export
authorization (sou13gold.export).

Release blockers (`release_questions`, `release_blocker_errors`) are release-level, not per-case adjudication:
every frozen open question of a gold row, and Q-CP2-DECL-EVIDENCE for every gold row with a false action label
(a closed-world negative; outside the development sign-off, later clarified for a limited scope, see
docs/benchmarks/sou13/GOLD_DEV_EXPORT.md), must cite decision ids that are recorded
approvals. The export authorization names them
(`release_blockers_resolved`). This is traceability metadata: the code checks only that each cited id exists as
a recorded approval, never that the decision's content resolves the question. That remains a mandatory human
release check. A question without a cited, recorded decision blocks the release; the alternative is to exclude
the affected cases or leave them non-gold. Where a recorded decision already covers a question (for example
the development sign-off for Q-FUTURE), it is cited; no new adjudication is required by the code.
"""
import copy
import re

from sou13.hashing import sha

ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
DEV_SPLITS = ('train', 'validation', 'calibration')
EVIDENCE_HASHES = ('input_sha256', 'arguments_sha256', 'definition_sha256')
BASE_KEYS = ('dataset_version', 'export_manifest_sha256', 'split_manifest_sha256', 'contract_sha256')
SCHEMA = 'schema/gold_addendum.schema.json'
CONFIRMING_ADJUDICATION = 'independent_human'
CONFIRMING_ROLE = 'independent_reviewer'
BATCH_ADJUDICATION = 'independent_human_batch'
BATCH_SCOPE_ALL_CP2 = 'all_cp2_development_cases'
CP2_ID_PREFIX = 'S13C2-'
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
        batch = entry['adjudication'] == BATCH_ADJUDICATION
        if entry['to_status'] == 'confirmed':
            if entry['adjudication'] not in (CONFIRMING_ADJUDICATION, BATCH_ADJUDICATION):
                e.append(f'{where}: {entry["adjudication"]} cannot confirm a label (independent adjudication needed)')
            if not any(approvals.get(d, {}).get('role') == CONFIRMING_ROLE for d in entry['decision_ids']):
                e.append(f'{where}: confirmation needs a referenced {CONFIRMING_ROLE} approval')
        elif batch:
            e.append(f'{where}: {BATCH_ADJUDICATION} is used only to confirm')
        confirming = entry['to_status'] == 'confirmed'
        if entry['label_change'] is not None:
            if not confirming:
                e.append(f'{where}: labels may change only together with an independent confirmation')
            elif batch:
                e.append(f'{where}: a batch attestation approves the frozen labels as they are; a label change needs '
                         f'a per-case confirmation')
            e += mask_errors(f'{where} label_change', entry['label_change'])
        if confirming and batch:
            if entry['reviewer_labels'] is not None:
                e.append(f'{where}: a batch confirmation records no reviewer_labels (it claims no per-case review)')
            if current_labels[cid] != label_core(row):
                e.append(f'{where}: a batch attestation covers only frozen labels; this case was relabelled earlier')
            if not cid.startswith(CP2_ID_PREFIX):
                e.append(f'{where}: batch attestations cover CP2 development cases only')
        elif confirming:
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
    return e + batch_errors(addendum, rows_by_id, approvals)


def batch_case_set_sha256(cases):
    """Canonical SHA-256 of the sorted [{id, label_sha256}] of (case id, label digest) pairs."""
    return sha(sorted(({'id': i, 'label_sha256': h} for i, h in cases), key=lambda x: x['id']))


def assertion_holds(row, assertion):
    """The frozen labels equal what the reviewer stated: listed actions true, unknown as stated, and every other
    action false when unknown is false (SOU-10 D01: the action list is complete) or at least not true otherwise."""
    t = row['per_action_targets']
    for a in ACTIONS:
        if a in assertion['actions']:
            if t[a] is not True:
                return False
        elif (t[a] is not False) if assertion['unknown'] is False else (t[a] is True):
            return False
    return row['unknown'] == assertion['unknown']


def batch_errors(addendum, rows_by_id, approvals):
    """Errors for the batch attestations of one addendum and the entries confirmed under them."""
    v = addendum['addendum_version']
    e, attestations = [], {}
    for a in addendum.get('batch_attestations', []):
        d, where = a['decision_id'], f'v{v} batch attestation {a["decision_id"]}'
        if d in attestations:
            e.append(f'{where}: recorded twice')
        attestations[d] = a
        if approvals.get(d, {}).get('role') != CONFIRMING_ROLE:
            e.append(f'{where}: not a recorded {CONFIRMING_ROLE} approval of this addendum')
    covered = {d: [] for d in attestations}
    for entry in addendum['entries']:
        if entry['adjudication'] != BATCH_ADJUDICATION or entry['to_status'] != 'confirmed':
            continue
        cited = [d for d in entry['decision_ids'] if d in attestations]
        if len(cited) != 1:
            e.append(f'v{v} entry ({entry["case_id"]}): a batch confirmation must cite exactly one batch attestation '
                     f'of this addendum')
        elif entry['case_id'] in rows_by_id:
            covered[cited[0]].append(entry)
    dev = {cid for cid, r in rows_by_id.items() if r['split'] in DEV_SPLITS}
    cp2 = {cid for cid in dev if cid.startswith(CP2_ID_PREFIX)}
    for d, a in attestations.items():
        where, entries = f'v{v} batch attestation {d}', covered[d]
        ids = {x['case_id'] for x in entries}
        if len(entries) != a['case_count']:
            e.append(f'{where}: confirms {len(entries)} case(s); the reviewer attested {a["case_count"]}')
        attested = batch_case_set_sha256((x['case_id'], x['evidence']['label_sha256']) for x in entries)
        if attested != a['case_set_sha256']:
            e.append(f'{where}: the confirmed cases or their label digests differ from the attested case set')
        if a['scope_kind'] == BATCH_SCOPE_ALL_CP2:
            if ids != cp2:
                e.append(f'{where}: covers {len(ids & cp2)} of {len(cp2)} CP2 development cases and {len(ids - cp2)} '
                         f'other case(s); the attested scope is all CP2 development cases')
            if a['excluded']['cp1_cases'] != len(dev - cp2):
                e.append(f'{where}: states {a["excluded"]["cp1_cases"]} excluded CP1 case(s); the export has '
                         f'{len(dev - cp2)} non-CP2 development row(s)')
        for s in a['label_assertions']:
            q = s['question_id']
            carrying = [x for x in entries if q in (rows_by_id[x['case_id']].get('open_questions') or ())]
            if len(carrying) != s['case_count']:
                e.append(f'{where}: {len(carrying)} confirmed case(s) carry {q}; the reviewer stated {s["case_count"]}')
            for x in carrying:
                if not assertion_holds(rows_by_id[x['case_id']], s):
                    e.append(f'{where}: {q}: the frozen labels of {x["case_id"]} differ from the labels the reviewer '
                             f'stated; the case stays blocked')
    return e


def batch_artifact_errors(addenda, package_manifest_sha256):
    """Errors unless every batch attestation lists the anchored development package among its reviewed artifacts."""
    e = []
    for a in addenda:
        for att in a.get('batch_attestations', []):
            if package_manifest_sha256 not in {x['sha256'] for x in att['reviewed_artifacts']}:
                e.append(f'v{a["addendum_version"]} batch attestation {att["decision_id"]}: the anchored development '
                         f'package is not among the reviewed artifacts')
    return e


def confirmation_channels(view):
    """Gold rows by the adjudication of their final confirmation (per-case and batch kept separate)."""
    out = {}
    for v in view:
        if v['gold']:
            k = v['addenda'][-1]['adjudication']
            out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


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


# ---- export grade ----------------------------------------------------------------------------------------------
DATASET_OWNER_ROLE = 'dataset_owner'
LICENSE_ROLE = 'license_owner'
DECL_EVIDENCE_QUESTION = 'Q-CP2-DECL-EVIDENCE'
GOLD_ELIGIBLE_ROLE = 'classification'
PLACEHOLDER = re.compile(r'(?i)(?<![A-Za-z0-9])(?:TODO|TBD|PLACEHOLDER|EXAMPLE|CHANGEME|FIXME|XXX)(?![A-Za-z0-9])'
                         r'|[<>{}]')


def person(name):
    """Normalised approver name for the independence check (case and whitespace insensitive)."""
    return ' '.join(str(name).casefold().split())


def placeholder_errors(where, approval):
    return [f'{where}: approval {approval.get("decision_id")} field {k} is a placeholder, not a recorded decision'
            for k in ('decision_id', 'approver', 'statement') if PLACEHOLDER.search(str(approval.get(k, '')))]


def eligibility_errors(where, row):
    """A confirmed (gold) label must be a plain classification label: the gold view carries only the action
    targets, the mask and `unknown`, which cannot express technical-error, admission or set-valued outcomes."""
    e = []
    ev = row.get('evaluation')
    if not isinstance(ev, dict) or ev.get('role') != GOLD_ELIGIBLE_ROLE:
        e.append(f'{where}: evaluation role {ev.get("role") if isinstance(ev, dict) else None!r} is not '
                 f'{GOLD_ELIGIBLE_ROLE!r}; only classification rows can be gold')
    if row.get('expected_outcome') != 'classification' or row.get('technical_error') is not None:
        e.append(f'{where}: expected outcome is not a plain classification')
    if 'forbidden_actions' in row:
        e.append(f'{where}: set-valued oracle rows cannot be gold')
    return e


def required_questions(row, labels):
    """Questions a release must have resolved before `row` can be gold with `labels`."""
    q = set(row.get('open_questions') or ())
    if any(v is False for v in labels['per_action_targets'].values()):
        q.add(DECL_EVIDENCE_QUESTION)
    return q


def chain_state(addenda, rows):
    """(status, labels) per case after applying the entries of `addenda` (assumed valid)."""
    status = {r['id']: r['label_status'] for r in rows}
    labels = {r['id']: label_core(r) for r in rows}
    for a in addenda:
        for entry in a.get('entries', []):
            status[entry['case_id']] = entry['to_status']
            if entry['label_change'] is not None:
                labels[entry['case_id']] = entry['label_change']
    return status, labels


def chain_records(addenda):
    """Every approval recorded in the chain, by decision id."""
    return {x['decision_id']: x for a in addenda for x in a.get('approvals', [])}


def strict_errors(addenda, rows, base):
    """Export-grade errors: `chain_errors` plus approval integrity, independence and gold eligibility."""
    e = chain_errors(addenda, rows, base)
    if e:
        return e
    rows_by_id = {r['id']: r for r in rows}
    records, reviewers, owners = {}, set(), set()
    for a in addenda:
        v = a['addendum_version']
        if a.get('status') != 'approved':
            e.append(f'v{v}: status {a.get("status")} cannot back an export')
        for x in a['approvals']:
            d = x['decision_id']
            e += placeholder_errors(f'v{v}', x)
            if d in records and records[d] != x:
                e.append(f'v{v}: decision id {d} names a different record than in an earlier addendum')
            records.setdefault(d, x)
            if x['role'] == CONFIRMING_ROLE:
                reviewers.add(person(x['approver']))
            elif x['role'] == DATASET_OWNER_ROLE:
                owners.add(person(x['approver']))
        for entry in a['entries']:
            if entry['to_status'] == 'confirmed':
                e += eligibility_errors(f'v{v} entry ({entry["case_id"]})', rows_by_id[entry['case_id']])
    if reviewers & owners:
        e.append(f'independence: {len(reviewers & owners)} approver(s) act both as {CONFIRMING_ROLE} and as '
                 f'{DATASET_OWNER_ROLE}')
    return e


def release_questions(view, rows):
    """{question id: gold case ids} that the release must resolve (see the module docstring)."""
    by_id = {r['id']: r for r in rows}
    out = {}
    for v in view:
        if v['gold']:
            for q in required_questions(by_id[v['id']], v['labels']):
                out.setdefault(q, []).append(v['id'])
    return {q: sorted(ids) for q, ids in sorted(out.items())}


def release_blocker_errors(questions, resolved, records):
    """Errors unless every release question cites decision ids that are recorded approvals (presence only: the
    content of a decision is never checked here; whether it resolves the question is a human release check).

    questions: `release_questions`; resolved: {question id: [decision ids]} as declared in the export
    authorization; records: the approvals recorded in the chain and the authorization, by decision id."""
    e = []
    for q, ids in questions.items():
        cited = resolved.get(q) or []
        if not cited:
            e.append(f'release blocker {q}: no recorded decision cited for {len(ids)} gold case(s); cite one, or '
                     f'exclude the cases or leave them non-gold')
        missing = sorted(d for d in cited if d not in records)
        if missing:
            e.append(f'release blocker {q}: cited decision ids {missing} are not recorded approvals')
    return e


def apply_addenda_strict(rows, addenda, base):
    """Gold view for an export: raises AddendumError unless every export-grade rule holds."""
    errors = strict_errors(addenda, rows, base)
    if errors:
        raise AddendumError(errors)
    return apply_addenda(rows, addenda, base)


def gold_set(view):
    """(canonical SHA-256, per-split counts) of the confirmed rows: what an export authorization approves."""
    gold = sorted(({'id': v['id'], 'split': v['split'], 'gold_label_sha256': v['gold_label_sha256']}
                   for v in view if v['gold']), key=lambda x: x['id'])
    return sha(gold), {s: sum(g['split'] == s for g in gold) for s in DEV_SPLITS}
