"""CP2 view of case records: lift CP1 records (never rewritten on disk) and validate CP2 fields.

A CP2 record = every CP1 field unchanged + family_id, template_id, alias_group_id, leakage_group_id,
exposure, source_material. Labels (true/false/null targets, known_mask, unknown, contract_view,
label_evidence, forbidden_actions), provenance and SHA-256 digests are carried over byte-for-byte and
re-checked here with the CP1 functions."""
import copy
import re
from pathlib import Path

from sou13.build import DATA_FILES, check_arguments, definition_hash, input_errors
from sou13.hashing import sha
from sou13.labels import ACTIONS, invariant_errors
from sou13.validate import read_jsonl

from . import ROOT, VERSION
from .case_ids import CaseIdError, case_id, legacy_case_id
from .catalog import get_catalog
from .generate import admission, interpreter_sha, labels_from_execution
from .leakage import record_effect_profile, record_signature
from .revisions import ROLES, evaluation_for, revise, revision_errors, technical_reviews
from .semantics import SemanticsError, execute
from .taxonomy import CP1_TEMPLATES

CP2_FIELDS = ('family_id', 'template_id', 'alias_group_id', 'leakage_group_id', 'exposure', 'source_material',
              'evaluation', 'technical_reviews')
SPLITS = ('train', 'validation', 'calibration', 'test')
STATUSES = ('provisional', 'pending', 'confirmed')
PHASE1_ALLOW_CONFIRMED = False  # no human review has been transferred; nothing may be confirmed


def load_cp1_records(root):
    out = []
    for rel in DATA_FILES.values():
        out += [(rel, r) for r in read_jsonl(Path(root) / rel)]
    return out


def lift_cp1(record, rel, fams, manifest):
    """CP1 record -> CP2 view (in memory). Raises KeyError for a CP1 id without a taxonomy mapping."""
    family_id, variant, _ = CP1_TEMPLATES[record['id']]
    fam = next(f for f in fams if f['family_id'] == family_id)
    revised, revision = revise(record)
    out = copy.deepcopy(revised if revised is not None else record)
    src = {'kind': 'sou13_v03_cp1_record', 'file': rel, 'cp1_id': record['id'], 'cp1_record_sha256': sha(record),
           'lifted_by': VERSION, 'note': 'CP1 record lifted unchanged; labels remain as in CP1 (not confirmed).'}
    if revision is not None:
        src.update({'kind': 'cp1_record_revised', 'revision': revision,
                    'note': 'CP1 record revised in CP2 only (CP1 file unchanged); see revision.changes.'})
    out.update({
        'family_id': family_id,
        'template_id': f"tpl.{family_id[len('fam.'):]}.{variant}",
        'alias_group_id': fam['alias_group_id'],
        'leakage_group_id': manifest['family_group'][family_id],
        'exposure': fam['exposure'],
        'source_material': src,
        'technical_reviews': technical_reviews().get(record['id'], []),
    })
    out['evaluation'] = evaluation_for(out)
    return out


def cp1_view_records(root, fams, manifest):
    return [lift_cp1(r, rel, fams, manifest) for rel, r in load_cp1_records(root)]


def _question_ids():
    ids = set()
    for name in ('OPEN_QUESTIONS.md', 'CP2_OPEN_QUESTIONS.md'):
        p = Path(ROOT) / 'docs' / name
        if p.exists():
            ids |= set(re.findall(r'^### ([A-Z][A-Za-z0-9-]*)\b', p.read_text(encoding='utf-8'), flags=re.M))
    return ids


KNOWN_QUESTIONS = _question_ids()
NEW_BASIS_BY_VALUE = {True: {'controlled_execution_trace'}, False: {'closed_semantics_absence'},
                      None: {'opaque_component'}}


def declarative_evidence_errors(r, fam):
    """Re-execute the registry-bound program and require the stored trace, world and labels to match."""
    e = []
    ev, inp, a = r['evidence'], r['input'], r['annotation']
    entry = get_catalog().get(r['family_id'])
    if entry is None or ev.get('kind') != 'declarative_semantics_execution':
        return ['declarative record without a catalog program']
    if sha(ev['program']) != ev['semantics_sha256']:  # audit F6: digest must match the program actually stored
        e.append('semantics_sha256 does not match the stored program')
    if ev['program'] != entry['program'] or ev['semantics_sha256'] != sha(entry['program']):
        e.append('evidence program is not the registry program of its family (semantics not selected by identity)')
    if ev['tool_admission'] != admission(fam, inp.get('server_id'), inp['tool_name']):
        e.append('tool_admission does not match the registry identity')
    if ev['executed_real_tool'] is not False or ev['fixture_code_executed'] is not False:
        e.append('declarative records never execute real tools or fixture code')
    if ev['interpreter_sha256'] != interpreter_sha():
        e.append('interpreter changed since the record was built')
    try:
        rec = execute(entry['program'], inp['raw_arguments'], ev['execution']['world_initial'])
    except SemanticsError as exc:
        return e + [f'evidence does not re-execute cleanly: {exc}']
    if rec != ev['execution']:
        e.append('stored execution differs from re-execution')
    targets, unknown, label_ev = labels_from_execution(rec, ev['semantics_sha256'])
    if a['per_action_targets'] != targets or a['unknown'] != unknown or a['label_evidence'] != label_ev:
        e.append('labels are not the ones derived from the execution')
    for act in ACTIONS:
        if a['label_evidence'][act]['basis'] not in NEW_BASIS_BY_VALUE[a['per_action_targets'][act]]:
            e.append(f'label_evidence[{act}] basis inconsistent with its value')
    return e


def record_errors(r, fams_by_id, manifest):
    rid = r.get('id', '?')
    e = [f'{rid}: missing CP2 field {k}' for k in CP2_FIELDS if k not in r]
    if e:
        return e
    fam = fams_by_id.get(r['family_id'])
    if fam is None:
        return [f'{rid}: family {r["family_id"]} is not in the taxonomy']
    tpl = next((t for t in fam['templates'] if t['template_id'] == r['template_id']), None)
    if tpl is None:
        e.append(f'{rid}: template {r["template_id"]} does not belong to {r["family_id"]}')
    if r['alias_group_id'] != fam['alias_group_id']:
        e.append(f'{rid}: alias_group_id differs from the family alias group')
    if r['exposure'] != fam['exposure']:
        e.append(f'{rid}: exposure differs from the family exposure')
    if r.get('split') not in SPLITS:
        e.append(f'{rid}: invalid split {r.get("split")}')
    if manifest['family_split'].get(r['family_id']) != r['split']:
        e.append(f'{rid}: split {r["split"]} differs from manifest split '
                 f'{manifest["family_split"].get(r["family_id"])} of {r["family_id"]}')
    if manifest['family_group'].get(r['family_id']) != r['leakage_group_id']:
        e.append(f'{rid}: leakage_group_id differs from the manifest group of its family')
    inp = r['input']
    ident = [inp.get('server_id'), inp['tool_name']]
    ev = r['evaluation']
    if not isinstance(ev, dict) or ev.get('role') not in ROLES:
        e.append(f'{rid}: evaluation.role must be one of {ROLES}')
    elif ev != evaluation_for(r):
        e.append(f'{rid}: evaluation metadata is not the documented one for this record (role/eligibility/export)')
    if isinstance(ev, dict) and ev.get('role') == 'admission_rejection_test':
        if ident not in fam.get('rejected_identities', []) or ident in fam['identities']:
            e.append(f'{rid}: admission-rejection test identity {ident} must be a rejected (non-admitted) identity')
    elif ident not in fam['identities']:
        e.append(f'{rid}: identity {ident} is not an admitted alias of {r["family_id"]}')
    if r['technical_reviews'] != technical_reviews().get(rid, []):
        e.append(f'{rid}: technical_reviews differ from the imported review record')
    if any(t.get('confirms_labels') is not False for t in r['technical_reviews']):
        e.append(f'{rid}: a technical review never confirms labels')
    # digests are recomputed, never trusted
    e += [f'{rid}: {m}' for m in input_errors(inp)]
    h = r['hashes']
    if h['input_sha256'] != sha(inp) or h['arguments_sha256'] != sha(inp['raw_arguments']) \
            or h['definition_sha256'] != definition_hash(inp):
        e.append(f'{rid}: hash mismatch')
    src = r['source_material']
    if src.get('kind') == 'sou13_v03_cp1_record':
        original = {k: v for k, v in r.items() if k not in CP2_FIELDS}
        if src.get('cp1_record_sha256') != sha(original):
            e.append(f'{rid}: CP1 fields changed after lifting (cp1_record_sha256 mismatch)')
    elif src.get('kind') == 'cp1_record_revised':
        e += [f'{rid}: {m}' for m in revision_errors(r, CP2_FIELDS)]
    elif src.get('kind') == 'new_cp2_case':
        e += [f'{rid}: {m}' for m in declarative_evidence_errors(r, fam)]
        try:  # audit F1: the id must be the persisted random id, never the predictable legacy hash
            if rid != case_id(r['family_id'], src['case_index']):
                e.append(f'{rid}: id is not the persisted case id of {r["family_id"]}|{src["case_index"]}')
        except CaseIdError as exc:
            e.append(f'{rid}: {exc}')
        if rid == legacy_case_id(r['family_id'], src['case_index']):
            e.append(f'{rid}: predictable legacy id (sha256(family|index))')
    elif src.get('kind') == 'sou13_pilot_v02':
        e.append(f'{rid}: v0.2 pilot material is analysis input only and cannot be a gold record')
    else:
        e.append(f'{rid}: unknown source_material kind {src.get("kind")}')
    if inp.get('tool_description') is not None and inp['tool_description'] not in fam['descriptions']:
        e.append(f'{rid}: tool_description is not a declared description of {r["family_id"]}')
    unknown_q = [q for q in r['open_questions'] if q not in KNOWN_QUESTIONS]
    if unknown_q:
        e.append(f'{rid}: open questions not documented in OPEN_QUESTIONS/CP2_OPEN_QUESTIONS: {unknown_q}')
    if fam['pending_reasons'] and src.get('kind') == 'new_cp2_case' and r['label_status'] != 'pending':
        e.append(f'{rid}: family has blocking questions {fam["pending_reasons"]}; record must be pending')
    # structural template match: effect profile and signature from the stored evidence
    if tpl is not None:
        if record_effect_profile(r) != tpl['effect_profile']:
            e.append(f'{rid}: trace effect profile {record_effect_profile(r)} != template {tpl["effect_profile"]}')
        if record_signature(r) != tpl['signature']:
            e.append(f'{rid}: record structure does not match template signature (near-duplicate or wrong template)')
    # labels: tri-state, known_mask, unknown, contract view (CP1 invariants)
    a = r['annotation']
    if r['expected_outcome'] == 'technical_error':
        if a['per_action_targets'] is not None or a['known_mask'] is not None or a['unknown'] is not None:
            e.append(f'{rid}: technical-error record must not carry labels')
        if not check_arguments(inp):
            e.append(f'{rid}: technical-error input does not violate its schema')
    elif r['expected_outcome'] == 'classification':
        e += [f'{rid}: {m}' for m in invariant_errors(a['per_action_targets'], a['known_mask'], a['unknown'],
                                                     a['contract_view'], a.get('forbidden_actions'))]
        ev = a.get('label_evidence') or {}
        if set(ev) != set(ACTIONS) or any(ev[x]['value'] is not a['per_action_targets'][x] for x in ACTIONS):
            e.append(f'{rid}: label_evidence must cover five actions and match the labels')
    else:
        e.append(f'{rid}: bad expected_outcome')
    st, rv = r['label_status'], r['review']
    if st not in STATUSES:
        e.append(f'{rid}: invalid label_status {st}')
    if st == 'confirmed':
        if not PHASE1_ALLOW_CONFIRMED:
            e.append(f'{rid}: Phase 1 never confirms labels (human review pending)')
        if not (rv.get('reviewer') and rv.get('reviewed_at') and rv.get('decision') == 'accept'
                and rv.get('reviewer') != rv.get('annotator')):
            e.append(f'{rid}: confirmed without a completed independent review record')
    if st != 'confirmed' and (rv.get('reviewer') or rv.get('decision')):
        e.append(f'{rid}: review fields filled but status not confirmed')
    return e
