"""Checkpoint 1 validator (stdlib only). Reports structural and evidence consistency,
NOT human correctness of the gold labels."""
import csv
import io
import json
import re
from pathlib import Path

from .build import (DATA_FILES, FREEZE, INPUT_PROFILE, QUEUE, REVIEW_FIELDS, ROOT, SHELL_FIXTURE, build_records,
                    check_arguments, definition_hash, fmt, input_errors, source_hashes)
from .cases import CONTRACT, CONTRACT_REFS, SOU13_CONVENTION
from .fixtures import admission_record, admitted_fixture
from .hashing import file_sha, sha
from .labels import ACTIONS, invariant_errors

STATUSES = {'provisional', 'pending', 'confirmed'}  # SOU-13 convention, not a SOU-10 contract field
EXPECTED_SUPPLEMENTARY = {'S13V03-SUP-S1', 'S13V03-SUP-S2', 'S13V03-SUP-S3'}
BASIS_BY_VALUE = {
    True: {'controlled_execution_trace'},
    False: {'controlled_execution_absence', 'environment_channel_disabled'},
    None: {'opaque_component', 'no_established_semantics'},
}
STRENGTHS = {'execution', 'model_execution', 'environment_declaration', 'not_established'}
CONTRACT_KEYS = ('version', 'sha256', 'commit', 'blob')
DECISIONS = {'', 'accept', 'revise', 'pending'}
LABEL_DECISIONS = {'', 'true', 'false', 'null', 'agree'}
REQUIRED_FIELDS = ('id', 'dataset_version', 'split', 'subset', 'evaluation_group', 'scenario_tags', 'input_profile',
                   'input', 'hashes', 'expected_outcome', 'technical_error', 'annotation', 'evidence',
                   'evidence_strength', 'label_status', 'open_questions', 'review', 'contract', 'provenance')


def read_jsonl(path):
    return [json.loads(x) for x in Path(path).read_text(encoding='utf-8').splitlines() if x.strip()]


def open_question_ids(root):
    """IDs of OPEN questions only (### headings); closed questions are listed in a table."""
    text = (Path(root) / 'docs' / 'OPEN_QUESTIONS.md').read_text(encoding='utf-8')
    return set(re.findall(r'^### ([A-Z][A-Za-z0-9-]*)\b', text, flags=re.M))


def contract_ref_errors(refs):
    return [ref for ref in refs if ref not in CONTRACT_REFS and not ref.startswith(SOU13_CONVENTION)]


def record_errors(r, oq_ids):
    rid = r.get('id', '?')
    e = [f'{rid}: missing {field}' for field in REQUIRED_FIELDS if field not in r]
    if e:
        return e
    inp = r['input']
    e += [f'{rid}: {msg}' for msg in input_errors(inp)]
    if e:
        return e
    if r['input_profile'] != INPUT_PROFILE:
        e.append(f'{rid}: unsupported input profile {r["input_profile"]}')
    if r['split'] != 'train':
        e.append(f'{rid}: Checkpoint 1 contains only train dev cases')
    h = r['hashes']
    if h['input_sha256'] != sha(inp) or h['arguments_sha256'] != sha(inp['raw_arguments']) or \
            h['definition_sha256'] != definition_hash(inp):
        e.append(f'{rid}: hash mismatch')
    if r['contract'] != {k: CONTRACT[k] for k in CONTRACT_KEYS}:
        e.append(f'{rid}: contract reference mismatch (expected merged main contract)')
    bad_refs = contract_ref_errors(r['annotation'].get('contract_rules', []))
    if bad_refs:
        e.append(f'{rid}: references not in the merged contract: {bad_refs}')
    # review state machine: generated labels can never be confirmed without a real review record
    st, rv = r['label_status'], r['review']
    if st not in STATUSES:
        e.append(f'{rid}: invalid label_status {st}')
    if st == 'confirmed' and not (rv.get('reviewer') and rv.get('reviewed_at') and rv.get('decision') == 'accept'
                                  and rv.get('reviewer') != rv.get('annotator')):
        e.append(f'{rid}: confirmed without a completed independent review record')
    if st != 'confirmed' and (rv.get('reviewer') or rv.get('decision')):
        e.append(f'{rid}: review fields filled but status not confirmed (record review in the queue, then version)')
    if st == 'pending' and not r['open_questions']:
        e.append(f'{rid}: pending requires open_questions')
    for q in r['open_questions']:
        if q not in oq_ids:
            e.append(f'{rid}: open question {q} is not an open question in OPEN_QUESTIONS.md')
    a, evd = r['annotation'], r['evidence']
    admitted = admitted_fixture(inp.get('server_id'), inp['tool_name'])
    if r['expected_outcome'] == 'technical_error':
        if r['technical_error'] != 'classifier_invalid' or a['per_action_targets'] is not None:
            e.append(f'{rid}: technical-error record must carry classifier_invalid and no labels')
        if not check_arguments(inp):
            e.append(f'{rid}: technical-error input does not violate its input profile/schema')
        return e
    if r['expected_outcome'] != 'classification':
        return e + [f'{rid}: bad expected_outcome']
    if check_arguments(inp):
        e.append(f'{rid}: arguments violate the input profile/schema: {check_arguments(inp)}')
    e += [f'{rid}: {msg}' for msg in invariant_errors(a['per_action_targets'], a['known_mask'], a['unknown'],
                                                     a['contract_view'], a.get('forbidden_actions'))]
    if 'forbidden_actions' in a and st != 'pending':
        e.append(f'{rid}: forbidden_actions is a SOU-13 convention without approval (SOU13-CONV-FORBIDDEN-ACTIONS); record must stay pending')
    ev = a['label_evidence']
    if set(ev) != set(ACTIONS):
        return e + [f'{rid}: label_evidence must cover five actions']
    for act in ACTIONS:
        item, val = ev[act], a['per_action_targets'][act]
        if item['value'] is not val or item['basis'] not in BASIS_BY_VALUE[val] or not item['refs'] \
                or item['strength'] not in STRENGTHS:
            e.append(f'{rid}: label_evidence[{act}] inconsistent with label')
        if item['basis'] == 'environment_channel_disabled' and st != 'pending':
            e.append(f'{rid}: environment-declared negative must stay pending')
    if evd['kind'] == 'controlled_execution':
        if admitted is None or evd['fixture_id'] != admitted or \
                evd['tool_admission'] != admission_record(inp.get('server_id'), inp['tool_name']):
            e.append(f'{rid}: executable semantics not established by the admitted-tool registry')
        if evd['executed_real_tool'] is not False:
            e.append(f'{rid}: real tools must never be executed')
        if (evd['fixture_id'] == SHELL_FIXTURE) != (r['evaluation_group'] == 'shell'):
            e.append(f'{rid}: shell cases must use the POSIX sh model and only shell cases may use it')
        ex = evd['execution']
        if ex['guard_violations'] or ex['unexplained'] or not ex['state_diff_explained'] or ex['trace_sha256'] != sha(ex['trace']):
            e.append(f'{rid}: execution evidence not clean')
        seqs = {f"trace#{t['seq']}" for t in ex['trace']}
        for act in ACTIONS:
            if ev[act]['basis'] == 'controlled_execution_trace' and not any(x in seqs for x in ev[act]['refs']):
                e.append(f'{rid}: positive {act} has no trace reference')
    elif evd['kind'] == 'no_established_semantics':
        if admitted is not None:
            e.append(f'{rid}: tool is admitted; semantics cannot be "not established"')
    else:
        e.append(f'{rid}: unsupported evidence kind {evd["kind"]}')
    return e


def queue_errors(root, records):
    e = []
    text = (Path(root) / QUEUE).read_bytes().decode('utf-8-sig')
    rows = list(csv.DictReader(io.StringIO(text)))
    by_id = {r['id']: r for r in records}
    if [row['case_id'] for row in rows] != [r['id'] for r in records]:
        return [f'{QUEUE}: case ids/order do not match data files'], 0
    filled = 0
    for row in rows:
        r = by_id[row['case_id']]
        t = r['annotation']['per_action_targets'] or {a: None for a in ACTIONS}
        if any(row[f'proposed_{a}'] != fmt(t[a]) for a in ACTIONS) or row['proposed_unknown'] != fmt(r['annotation']['unknown']) \
                or row['label_status'] != r['label_status']:
            e.append(f"{QUEUE}: proposed values differ for {row['case_id']}")
        if any(row[f] for f in REVIEW_FIELDS):
            filled += 1
            if row['overall_decision_accept_revise_pending'] not in DECISIONS or \
                    any(row[f'{a}_decision'] not in LABEL_DECISIONS for a in ACTIONS):
                e.append(f"{QUEUE}: invalid decision value for {row['case_id']}")
    return e, filled


def validate(root=ROOT, check_regeneration=True):
    root = Path(root)
    errors = []
    records = []
    for subset, rel in DATA_FILES.items():
        rows = read_jsonl(root / rel)
        errors += [f"{r['id']}: in {rel} but subset={r['subset']}" for r in rows if r['subset'] != subset]
        records += rows
    ids = [r['id'] for r in records]
    if len(ids) != len(set(ids)):
        errors.append('duplicate case id')
    dev = [r for r in records if r['subset'] == 'dev16']
    sup = {r['id'] for r in records if r['subset'] == 'supplementary'}
    if len(dev) != 16:
        errors.append(f'expected 16 dev cases, found {len(dev)}')
    if sup != EXPECTED_SUPPLEMENTARY:
        errors.append(f'supplementary set mismatch: {sorted(sup)}')
    if any(r['label_status'] != 'provisional' for r in dev):
        errors.append('every primary dev16 case must be provisional at Checkpoint 1')
    oq = open_question_ids(root)
    for r in records:
        errors += record_errors(r, oq)
    q_errors, filled = queue_errors(root, records)
    errors += q_errors
    freeze = json.loads((root / FREEZE).read_text(encoding='utf-8'))
    for rel, digest in freeze['files_sha256'].items():
        if file_sha(root / rel) != digest:
            errors.append(f'freeze mismatch: {rel}')
    if freeze['source_sha256_lf_normalised'] != source_hashes(ROOT):
        errors.append('source code changed after freeze')
    if not re.match(r'^3\.\d+\.\d+', str(freeze.get('built_with_python', ''))):
        errors.append('freeze must record built_with_python as provenance')
    if freeze['contract'] != CONTRACT:
        errors.append('contract reference changed after freeze')
    if check_regeneration:
        regenerated, _ = build_records()
        if regenerated != records:
            errors.append('stored records differ from records regenerated from fixtures/specs (evidence not reproducible)')
    coverage = {a: {fmt(v): sum(r['annotation']['per_action_targets'][a] is v for r in dev)
                    for v in (True, False, None)} for a in ACTIONS}
    return {
        'result': 'PASS' if not errors else 'FAIL',
        'errors': errors,
        'counts': {'dev16': len(dev), 'supplementary': sorted(sup),
                   'provisional': sum(r['label_status'] == 'provisional' for r in records),
                   'pending': sorted(r['id'] for r in records if r['label_status'] == 'pending'),
                   'confirmed': sum(r['label_status'] == 'confirmed' for r in records),
                   'review_rows_with_decisions': filled},
        'dev16_label_coverage': coverage,
        'dev16_evidence_strength': {r['id']: r['evidence_strength'] for r in dev},
        'note': 'Structural/evidence QA only. Labels are provisional; no independent human review recorded.',
    }
