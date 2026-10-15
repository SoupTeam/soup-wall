"""Validator for SOU-35 records: nothing stored is trusted; everything is recomputed from the declaration.

Checks: JSON Schema (sou35_case.schema.json), family/template/identity binding, digests, re-execution of the
declared program on the stored initial world, labels re-derived by the reused SOU-13 function, CP1 label
invariants, template signature, pending decisions, status rules and the human/AI/mechanical evidence split."""
import json

from . import DATASET_VERSION, ROOT, adapters
from .families import ACTIONS, case_input, technical_template_id
from .generate import BLOCKING, admission, match_template, pending_decisions

CASE_SCHEMA = ROOT / 'schema' / 'sou35_case.schema.json'


def _validator():
    import jsonschema
    return jsonschema.Draft202012Validator(json.loads(CASE_SCHEMA.read_text(encoding='utf-8')))


def schema_errors(r):
    return [f'schema {"/".join(map(str, e.absolute_path))}: {e.message}' for e in _validator().iter_errors(r)]


def _declarative_errors(r, decl):
    from sou13.labels import invariant_errors
    e = []
    ev, inp, a = r['evidence'], r['input'], r['annotation']
    if ev['program'] != decl['program'] or ev['semantics_sha256'] != adapters.sha(decl['program']):
        e.append('evidence program is not the declared program of its family')
    if ev['interpreter_sha256'] != adapters.interpreter_sha():
        e.append('interpreter changed since the record was built')
    if ev['tool_admission'] != admission(decl, inp.get('server_id'), inp['tool_name']):
        e.append('tool_admission does not match the registry identity')
    try:
        rec = adapters.execute(decl['program'], inp['raw_arguments'], ev['execution']['world_initial'])
    except Exception as exc:
        return e + [f'evidence does not re-execute cleanly: {exc}']
    if rec != ev['execution']:
        e.append('stored execution differs from re-execution')
    targets, unknown, label_ev = adapters.labels_from_execution(rec, ev['semantics_sha256'])
    if a['per_action_targets'] != targets or a['unknown'] != unknown or a['label_evidence'] != label_ev:
        e.append('labels are not the ones derived from the execution')
    e += invariant_errors(a['per_action_targets'], a['known_mask'], a['unknown'], a['contract_view'])
    tpl = match_template(decl, adapters.effect_profile_from_trace(rec['trace']), list(inp['raw_arguments']))
    if tpl is None or tpl['template_id'] != r['template_id']:
        e.append('record does not match its declared template')
    elif adapters.template_signature(inp['tool_schema'], list(inp['raw_arguments']),
                                     adapters.effect_profile_from_trace(rec['trace'])) != tpl['signature']:
        e.append('record structure does not match the template signature')
    elif [x for x in ACTIONS if targets[x]] != tpl['established_actions']:
        e.append('derived labels disagree with the declared template')
    if adapters.check_arguments(inp):
        e.append('classification input violates the admitted schema')
    pending = pending_decisions(decl['program'], inp['raw_arguments'], rec, targets)
    if r['evidence_tier']['pending_decisions'] != pending or r['open_questions'] != pending:
        e.append('pending decisions are not the recomputed ones')
    if r['label_status'] != ('pending' if BLOCKING & set(pending) else 'provisional'):
        e.append('label_status inconsistent with blocking pending decisions')
    if r['evaluation']['role'] != 'classification' or r['evaluation']['in_semantic_accuracy'] is not True:
        e.append('classification record must have role classification')
    return e


def _technical_errors(r, decl):
    e = []
    inp, a = r['input'], r['annotation']
    violations = adapters.check_arguments(inp)
    if not violations or r['evidence'].get('violations') != violations:
        e.append('technical-error evidence is not the recomputed schema violation')
    if any(a[k] is not None for k in ('per_action_targets', 'known_mask', 'unknown', 'contract_view',
                                      'label_evidence')):
        e.append('technical-error record must not carry labels')
    if r['technical_error'] != 'classifier_invalid' or r['template_id'] != technical_template_id(decl):
        e.append('technical-error record must expect classifier_invalid under the technical template')
    if r['evaluation']['role'] != 'technical_error_check':
        e.append('technical-error record must have role technical_error_check')
    return e


def record_errors(r, decls_by_id):
    rid = r.get('id', '?')
    e = schema_errors(r)
    if e:
        return [f'{rid}: {m}' for m in e]
    decl = decls_by_id.get(r['family_id'])
    if decl is None:
        return [f'{rid}: family {r["family_id"]} is not declared']
    src = r['source_material']
    if src['declaration_sha256'] != decl['_declaration_sha256']:
        e.append('declaration changed since the record was built')
    if r['dataset_version'] != DATASET_VERSION or r['exposure'] != decl['exposure']:
        e.append('dataset version or exposure differs from the declaration')
    if r['contract'] != adapters.contract():
        e.append('contract binding differs')
    cases = decl['cases'] if src['case_kind'] == 'classification' else decl['technical_error_cases']
    if src['case_index'] >= len(cases):
        return [f'{rid}: case index out of range']
    if r['input'] != case_input(decl, cases[src['case_index']]):
        e.append('input is not the declared case input')
    inp, h = r['input'], r['hashes']
    if h != {'input_sha256': adapters.sha(inp), 'arguments_sha256': adapters.sha(inp['raw_arguments']),
             'definition_sha256': adapters.definition_hash(inp)}:
        e.append('hash mismatch')
    e += adapters.input_errors(inp)
    if src['case_kind'] == 'classification':
        if r['expected_outcome'] != 'classification':
            e.append('classification case with a technical expected outcome')
        else:
            e += _declarative_errors(r, decl)
    else:
        e += _technical_errors(r, decl)
    tier = r['evidence_tier']
    if tier['ai_technical_reviews'] != len(r['technical_reviews']):
        e.append('evidence_tier AI review count differs from technical_reviews')
    if any(t['confirms_labels'] is not False for t in r['technical_reviews']):
        e.append('an AI technical review never confirms labels')
    return [f'{rid}: {m}' for m in e]


def dataset_errors(records, decls):
    by_id = {d['family_id']: d for d in decls}
    errors = [m for r in records for m in record_errors(r, by_id)]
    ids = [r['id'] for r in records]
    if len(ids) != len(set(ids)):
        errors.append('duplicate record id')
    return errors
