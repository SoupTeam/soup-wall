"""Generate CP2 candidate records from the declarative catalog (deterministic; nothing real is executed).

Labels are DERIVED from the closed-semantics execution (semantics.execute): true <- effect event,
false <- program completed + typed audit clean + no event of that action, null <- stopped at an opaque
component before the action was established. The derived labels are cross-checked against the template
the taxonomy declares for the case (same author: a consistency check, not independent ground truth).
All records are PROVISIONAL (or pending), annotator = ai_assisted_synthetic_draft, never confirmed."""
import hashlib
import re

from sou13.build import INPUT_PROFILE, check_arguments, definition_hash, input_errors
from sou13.cases import CONTRACT
from sou13.hashing import sha
from sou13.labels import ACTIONS, contract_view, known_mask
from sou13.sandbox import EVENT_TO_ACTION

from . import ROOT, VERSION
from .catalog import MISLEADING_CASE, NULL_CASE, get_catalog
from .identity import effect_profile_from_trace
from .semantics import execute
from .taxonomy import DECL

DATASET_VERSION = '0.4-cp2-candidate'
STRENGTH = 'declarative_execution'
ACTION_WORDS = re.compile(r'\b(delete|drop|grant|send|rm|chmod|update|purge|revoke|deploy)\b', re.I)
ACTION_TEXT_RU = {'read': 'чтение', 'write': 'запись', 'delete': 'удаление', 'send_data': 'отправка данных',
                  'change_permissions': 'изменение прав'}


class GenerationError(ValueError):
    pass


def interpreter_sha():
    return hashlib.sha256((ROOT / 'sou13cp2' / 'semantics.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def case_id(family_id, i):
    """Opaque id from the persisted random-id map (audit F1): reveals neither family, class nor position.
    The former sha256(family_id|i) id was predictable from a (guessed) family id."""
    from .case_ids import case_id as persisted_case_id
    return persisted_case_id(family_id, i)


def admission(fam, server_id, tool_name):
    entry = {'server_id': server_id, 'tool_name': tool_name, 'family_id': fam['family_id'],
             'semantics': 'decl:' + fam['family_id'][len('fam.'):]}
    return {'registry': 'sou13cp2 declarative registry (taxonomy identities -> catalog program)', 'entry': entry,
            'entry_sha256': sha(entry),
            'semantics_selected_by': 'registry identity (server_id, tool_name); description not used',
            'trust_basis': 'synthetic_assumption_requires_human_review'}


def labels_from_execution(rec, semantics_sha):
    observed = {}
    for e in rec['trace']:
        if e['event'] in EVENT_TO_ACTION:
            observed.setdefault(EVENT_TO_ACTION[e['event']][0], []).append(e)
    completed = rec['outcome'] == 'completed'
    targets, evidence = {}, {}
    for a in ACTIONS:
        if a in observed:
            targets[a] = True
            evidence[a] = {'value': True, 'basis': 'controlled_execution_trace', 'strength': STRENGTH,
                           'refs': [f"trace#{e['seq']}" for e in observed[a]]
                           + sorted({EVENT_TO_ACTION[e['event']][1] for e in observed[a]})}
        elif completed:
            targets[a] = False
            evidence[a] = {'value': False, 'basis': 'closed_semantics_absence', 'strength': STRENGTH,
                           'refs': ['program_completed', 'typed_access_audit_clean', 'state_diff_explained',
                                    f'semantics_sha256:{semantics_sha}']}
        else:
            targets[a] = None
            evidence[a] = {'value': None, 'basis': 'opaque_component', 'strength': 'not_established',
                           'refs': [f"opaque:{rec['opaque_component']}"]}
    return targets, not completed, evidence


def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            yield k
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)


def case_input(fam, i):
    entry = get_catalog()[fam['family_id']]
    server_id, tool_name = fam['identities'][i % len(fam['identities'])]
    if entry['null_description'] and i == NULL_CASE:
        desc, desc_kind = None, 'null'
    elif entry['misleading'] and i == MISLEADING_CASE:
        desc, desc_kind = entry['misleading'], 'misleading'
    else:
        desc, desc_kind = fam['honest_description'], 'honest'
    decl = [t for t in fam['templates'] if t['evidence_kind'] == DECL]
    inp = {'server_id': server_id, 'tool_name': tool_name, 'tool_description': desc,
           'tool_schema': decl[0]['schema'], 'raw_arguments': {k: v[i] for k, v in sorted(entry['pools'].items())}}
    return inp, desc_kind


def _rationale(fam, inp, rec, targets, unknown, desc_kind):
    parts = [f"Семантика выбрана по идентичности ({inp['server_id']}, {inp['tool_name']}) из синтетического "
             f"реестра CP2 (декларативная программа семьи {fam['family_id']}), а не по имени или описанию."]
    effects = [f"#{e['seq']} {e['event']}" + (f" {e.get('table')}/{e.get('key')}" if e.get('table') else '')
               + (f" → {e['recipient']} ({e['channel']})" if e['event'] == 'send' else '') for e in rec['trace']
               if e['event'] != 'opaque_invoked']
    if effects:
        parts.append('Трасса: ' + '; '.join(effects) + '.')
    pos = [ACTION_TEXT_RU[a] for a in ACTIONS if targets[a] is True]
    if unknown:
        parts.append(f"Исполнение остановлено на несмоделированном компоненте `{rec['opaque_component']}`: "
                     + (f"установлено {', '.join(pos)}; " if pos else 'ни одно действие не установлено; ')
                     + 'остальные действия не установлены и не исключены (null), unknown=true (§3.1, D01).')
    elif pos:
        parts.append(f"Установлено: {', '.join(pos)}. Остальные действия false: программа исполнена полностью, "
                     'типизированный аудит доступа и diff состояния чисты (D03: действия ортогональны).')
    else:
        parts.append('Ни одного эффекта: программа исполнена полностью, аудит чист; доказанный no-op (D07, §3.1).')
    if desc_kind == 'misleading':
        parts.append('Описание противоречит семантике; оно недоверено и на метки не влияет (§4.1, D04).')
    elif desc_kind == 'null':
        parts.append('Описание отсутствует (null, §1.2); метки от него не зависят.')
    if any(ACTION_WORDS.search(s) for s in _strings(inp['raw_arguments'])):
        parts.append('Слова-действия в аргументах — данные, а не команды (§2 rule 3).')
    return ' '.join(parts)


def _contract_rules(rec, targets, unknown, desc_kind, inp):
    rules = []
    if any(v is True for v in targets.values()):
        rules += ['§2 table', 'D03']
    if any(e['event'] == 'http_get' for e in rec['trace']):
        rules.append('§2 rule 2')
    if unknown:
        rules += ['D01', '§3.1']
    elif not any(v is True for v in targets.values()):
        rules += ['D07', '§3.1']
    if desc_kind == 'misleading':
        rules += ['D04', '§4.1']
    if desc_kind == 'null':
        rules.append('§1.2')
    if any(ACTION_WORDS.search(s) for s in _strings(inp['raw_arguments'])):
        rules.append('§2 rule 3')
    return list(dict.fromkeys(rules))


def build_case(fam, i, manifest):
    entry = get_catalog()[fam['family_id']]
    inp, desc_kind = case_input(fam, i)
    errs = input_errors(inp) + check_arguments(inp)
    if errs:
        raise GenerationError(f"{fam['family_id']}[{i}]: invalid input {errs}")
    program = entry['program']
    rec = execute(program, inp['raw_arguments'])
    sem_sha = sha(program)
    targets, unknown, label_ev = labels_from_execution(rec, sem_sha)
    profile = effect_profile_from_trace(rec['trace'])
    tpl = [t for t in fam['templates'] if t['evidence_kind'] == DECL and t['effect_profile'] == profile]
    if len(tpl) != 1:
        raise GenerationError(f"{fam['family_id']}[{i}]: execution profile {profile} matches no declared template")
    tpl = tpl[0]
    if {a for a in ACTIONS if targets[a]} != set(tpl['established_actions']) or \
            (tpl['unknown_profile'] != 'none') != unknown:
        raise GenerationError(f"{fam['family_id']}[{i}]: derived labels disagree with template {tpl['template_id']}")
    args_strings = list(_strings(inp['raw_arguments']))
    tags = [fam['coverage_stratum']]
    tags += ['misleading_description'] if desc_kind == 'misleading' else []
    tags += ['null_description'] if desc_kind == 'null' else []
    tags += ['alias_identity'] if fam['identities'].index([inp['server_id'], inp['tool_name']]) > 0 else []
    tags += ['argument_selected_noop'] if fam['behavior_class'] in ACTIONS and not profile else []
    tags += ['action_word_in_data'] if any(ACTION_WORDS.search(s) for s in args_strings) else []
    status = 'pending' if fam['pending_reasons'] else 'provisional'
    open_questions = sorted(set(['Q-ADMISSION'] + fam['open_questions']))
    return {
        'id': case_id(fam['family_id'], i), 'dataset_version': DATASET_VERSION,
        'split': manifest['family_split'][fam['family_id']], 'subset': 'cp2_candidate',
        'evaluation_group': 'challenge' if set(tags) & {'misleading_description', 'null_description',
                                                         'action_word_in_data', 'argument_selected_noop'}
        else 'regression',
        'scenario_tags': tags, 'input_profile': INPUT_PROFILE, 'input': inp,
        'hashes': {'input_sha256': sha(inp), 'arguments_sha256': sha(inp['raw_arguments']),
                   'definition_sha256': definition_hash(inp)},
        'expected_outcome': 'classification', 'technical_error': None,
        'annotation': {'per_action_targets': targets, 'known_mask': known_mask(targets), 'unknown': unknown,
                       'contract_view': contract_view(targets, unknown), 'label_evidence': label_ev,
                       'rationale': _rationale(fam, inp, rec, targets, unknown, desc_kind),
                       'contract_rules': _contract_rules(rec, targets, unknown, desc_kind, inp)},
        'evidence': {'kind': DECL, 'semantics_id': 'decl:' + fam['family_id'][len('fam.'):], 'program': program,
                     'semantics_sha256': sem_sha, 'interpreter_sha256': interpreter_sha(),
                     'tool_admission': admission(fam, inp['server_id'], inp['tool_name']), 'execution': rec,
                     'executed_real_tool': False, 'fixture_code_executed': False},
        'evidence_strength': '+'.join(sorted({e['strength'] for e in label_ev.values()})),
        'label_status': status, 'open_questions': open_questions,
        'review': {'annotator': 'ai_assisted_synthetic_draft', 'reviewer': None, 'reviewed_at': None,
                   'decision': None, 'second_reviewer': None, 'adjudication': None},
        'contract': {k: CONTRACT[k] for k in ('version', 'sha256', 'commit', 'blob')},
        'provenance': {'origin': 'sou13_cp2_new_synthetic', 'production_data': False,
                       'prior_sou5_fixture_reused': False, 'v02_material_used': False,
                       'domains': 'example.test only', 'license': 'pending owner decision (Q-LICENSE)'},
        'family_id': fam['family_id'], 'template_id': tpl['template_id'], 'alias_group_id': fam['alias_group_id'],
        'leakage_group_id': manifest['family_group'][fam['family_id']], 'exposure': fam['exposure'],
        'source_material': {'kind': 'new_cp2_case', 'generator': VERSION, 'case_index': i,
                            'catalog_entry_sha256': sha(entry)},
    }


def generate(fams, manifest):
    from .revisions import evaluation_for
    out = []
    for fam in fams:
        if fam['family_id'] in get_catalog():
            for i in range(get_catalog()[fam['family_id']]['n_new']):
                r = build_case(fam, i, manifest)
                r['technical_reviews'] = []  # new CP2 cases have not been reviewed by anyone
                r['evaluation'] = evaluation_for(r)
                out.append(r)
    ids = [r['id'] for r in out]
    if len(ids) != len(set(ids)):
        raise GenerationError('case id collision')
    return sorted(out, key=lambda r: r['id'])
