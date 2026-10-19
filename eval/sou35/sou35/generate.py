"""Declaration -> SOU-35 candidate records (deterministic given the declaration and the id map).

Labels are MECHANICAL (tier A): derived from the frozen interpreter's audited execution by the reused SOU-13
`labels_from_execution`. They are never human-approved, never inherit a SOU-13 reviewer decision, and every
interpretation they rely on is listed in `evidence_tier.pending_decisions`."""
import secrets

from . import DATASET_VERSION, VERSION, adapters
from .families import ACTIONS, case_input, technical_template_id

# Rulings needed before SOU-35 labels relying on them can be treated as settled (none is inherited from SOU-13).
Q_DECL_EVIDENCE = 'Q-S35-DECL-EVIDENCE'          # closed-program `false` labels (SOU-13 ruling was scoped to 179 cases)
Q_INTERNAL_ACCESS = 'Q-S35-INTERNAL-ACCESS'      # internal ACL read / key enumeration is not `read`
Q_EMPTY_BATCH = 'Q-S35-EMPTY-BATCH'              # an empty foreach is a proven no-op
Q_UNMODELLED_MODE = 'Q-S35-UNMODELLED-MODE'      # an unlisted switch value is full unknown
Q_OPTIONAL_DEFAULT = 'Q-S35-OPTIONAL-DEFAULT'    # an absent `when` argument takes the else branch
Q_HUMAN_REVIEW = 'Q-S35-HUMAN-REVIEW'            # independent human semantic approval not yet given
Q_DATA_USE = 'Q-S35-DATA-USE'                    # SOU-35 data-use permission not yet granted
BLOCKING = frozenset({Q_INTERNAL_ACCESS, Q_EMPTY_BATCH, Q_UNMODELLED_MODE, Q_OPTIONAL_DEFAULT})
ALWAYS = (Q_HUMAN_REVIEW, Q_DATA_USE)


class GenerationError(ValueError):
    pass


def new_case_id():
    return 'S35-' + secrets.token_hex(16).upper()


def id_key(family_id, case_kind, i):
    return f'{family_id}|{case_kind}|{i}'


def _walk(program):
    for step in program:
        yield step
        for k in ('then', 'else', 'do'):
            if k in step:
                yield from _walk(step[k])
        for sub in step.get('cases', {}).values():
            yield from _walk(sub)


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


ACTION_WORDS = ('delete', 'drop', 'grant', 'send', 'rm ', 'chmod', 'purge', 'revoke', 'deploy', 'admin')


def pending_decisions(program, args, rec, targets):
    q = set(ALWAYS)
    if any(v is False for v in targets.values()):
        q.add(Q_DECL_EVIDENCE)
    if any(e['event'] == 'acl_change' or (e['event'] == 'store_delete' and e.get('scope') == 'prefix')
           for e in rec['trace']):
        q.add(Q_INTERNAL_ACCESS)
    for step in _walk(program):
        if step['op'] == 'foreach' and args.get(step['arg']) == []:
            q.add(Q_EMPTY_BATCH)
        if step['op'] == 'when' and step['arg'] not in args:
            q.add(Q_OPTIONAL_DEFAULT)
    if (rec.get('opaque_component') or '').startswith('unmodelled_case:'):
        q.add(Q_UNMODELLED_MODE)
    return sorted(q)


def admission(decl, server_id, tool_name):
    entry = {'server_id': server_id, 'tool_name': tool_name, 'family_id': decl['family_id'],
             'semantics': 'decl35:' + adapters.slug(decl['family_id'])}
    return {'registry': 'sou35 declarative registry (declaration identities -> declaration program)', 'entry': entry,
            'entry_sha256': adapters.sha(entry),
            'semantics_selected_by': 'registry identity (server_id, tool_name); description not used',
            'trust_basis': 'synthetic_assumption_requires_human_review'}


def match_template(decl, profile, arg_keys):
    found = [t for t in decl['_templates'] if t['effect_profile'] == profile and t['arg_keys'] == sorted(arg_keys)]
    return found[0] if len(found) == 1 else None


def _rationale(decl, inp, rec, targets, unknown, desc_kind):
    parts = [f"Semantics selected by registry identity ({inp['server_id']}, {inp['tool_name']}) -> declared program "
             f"of {decl['family_id']}; the tool name and description were not used."]
    effects = [f"#{e['seq']} {e['event']}" + (f" {e.get('table')}/{e.get('key')}" if e.get('table') else '')
               for e in rec['trace'] if e['event'] != 'opaque_invoked']
    if effects:
        parts.append('Trace: ' + '; '.join(effects) + '.')
    pos = [a for a in ACTIONS if targets[a] is True]
    if unknown:
        parts.append(f"Execution stopped at unmodelled component `{rec['opaque_component']}`: "
                     + (f"established {', '.join(pos)}; " if pos else 'no action established; ')
                     + 'the other actions are neither established nor excluded (null), unknown=true (D01, §3.1).')
    elif pos:
        parts.append(f"Established: {', '.join(pos)}. Other actions are false only in the closed synthetic program "
                     '(program completed, typed access audit and state diff clean; D03 orthogonality).')
    else:
        parts.append('No effect event: program completed with a clean audit; proven no-op in the closed synthetic '
                     'program (D07).')
    if desc_kind == 'misleading':
        parts.append('The description contradicts the semantics; it is untrusted metadata and does not affect labels '
                     '(§4.1, D04).')
    elif desc_kind == 'null':
        parts.append('The description is null (§1.2); labels do not depend on it.')
    parts.append('Mechanical synthetic evidence only; not human-approved.')
    return ' '.join(parts)


def _rules(rec, targets, unknown, desc_kind, has_action_words):
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
    if has_action_words:
        rules.append('§2 rule 3')
    return list(dict.fromkeys(rules))


def _common(decl, inp, case_kind, i, group):
    return {
        'dataset_version': DATASET_VERSION, 'split': 'unassigned', 'subset': 'sou35_candidate',
        'input_profile': 'object_arguments_fixture_profile', 'input': inp,
        'hashes': {'input_sha256': adapters.sha(inp), 'arguments_sha256': adapters.sha(inp['raw_arguments']),
                   'definition_sha256': adapters.definition_hash(inp)},
        'review': {'annotator': 'ai_assisted_synthetic_draft', 'reviewer': None, 'reviewed_at': None, 'decision': None,
                   'second_reviewer': None, 'adjudication': None},
        'contract': adapters.contract(),
        'provenance': {'origin': 'sou35_synthetic', 'production_data': False, 'artificial_toy': decl['artificial_toy'],
                       'domains': 'example.test only', 'license': 'none granted (Q-S35-DATA-USE pending)'},
        'family_id': decl['family_id'], 'alias_group_id': 'ag35.' + adapters.slug(decl['family_id']),
        'leakage_group_id': group, 'exposure': decl['exposure'],
        'source_material': {'kind': 'new_sou35_case', 'generator': VERSION, 'case_kind': case_kind, 'case_index': i,
                            'declaration_sha256': decl['_declaration_sha256']},
        'technical_reviews': [],
    }


def _tier(status, pending):
    return {'mechanical': {'status': status, 'interpreter_sha256': adapters.interpreter_sha(),
                           'compute_sha256': adapters.compute_sha()},
            'ai_technical_reviews': 0, 'human_semantic_approval': None, 'inherited_decisions': [],
            'pending_decisions': pending}


def _tags(decl, case, inp, profile_empty, unmodelled):
    tags = []
    tags += ['misleading_description'] if case['description'] == 'misleading' else []
    tags += ['null_description'] if case['description'] == 'null' else []
    tags += ['alias_identity'] if case['identity'] > 0 else []
    args = inp['raw_arguments'] if isinstance(inp['raw_arguments'], (dict, list)) else {}
    if any(w in s.lower() for s in _strings(args) for w in ACTION_WORDS):
        tags.append('action_word_in_data')
    if profile_empty and decl['behavior_class'] != 'no_effect':
        tags.append('argument_selected_noop')
    if unmodelled:
        tags.append('unmodelled_mode')
    return tags


def build_classification(decl, i, case_id, group):
    case = decl['cases'][i]
    inp = case_input(decl, case)
    program = decl['program']
    try:
        rec = adapters.execute(program, inp['raw_arguments'])
    except Exception as exc:  # SemanticsError, or a KeyError from an undefined @variable
        raise GenerationError(f'{decl["family_id"]} case {i}: {type(exc).__name__}: {exc}') from exc
    sem_sha = adapters.sha(program)
    targets, unknown, label_ev = adapters.labels_from_execution(rec, sem_sha)
    profile = adapters.effect_profile_from_trace(rec['trace'])
    tpl = match_template(decl, profile, list(inp['raw_arguments']))
    if tpl is None:
        raise GenerationError(f'{decl["family_id"]} case {i}: profile {profile} with keys '
                              f'{sorted(inp["raw_arguments"])} matches no declared template')
    if [a for a in ACTIONS if targets[a]] != tpl['established_actions'] or unknown != tpl['expected']['unknown']:
        raise GenerationError(f'{decl["family_id"]} case {i}: derived labels disagree with {tpl["template_id"]}')
    from sou13.labels import contract_view, known_mask
    pending = pending_decisions(program, inp['raw_arguments'], rec, targets)
    unmodelled = Q_UNMODELLED_MODE in pending
    tags = _tags(decl, case, inp, not profile, unmodelled)
    has_words = 'action_word_in_data' in tags
    return {
        'id': case_id, **_common(decl, inp, 'classification', i, group),
        'evaluation_group': 'challenge' if set(tags) - {'alias_identity'} else 'regression',
        'scenario_tags': tags, 'expected_outcome': 'classification', 'technical_error': None,
        'annotation': {'per_action_targets': targets, 'known_mask': known_mask(targets), 'unknown': unknown,
                       'contract_view': contract_view(targets, unknown), 'label_evidence': label_ev,
                       'rationale': _rationale(decl, inp, rec, targets, unknown, case['description']),
                       'contract_rules': _rules(rec, targets, unknown, case['description'], has_words)},
        'evidence': {'kind': adapters.DECL, 'semantics_id': 'decl35:' + adapters.slug(decl['family_id']),
                     'program': program, 'semantics_sha256': sem_sha, 'interpreter_sha256': adapters.interpreter_sha(),
                     'tool_admission': admission(decl, inp['server_id'], inp['tool_name']), 'execution': rec,
                     'executed_real_tool': False, 'fixture_code_executed': False},
        'evidence_strength': '+'.join(sorted({e['strength'] for e in label_ev.values()})),
        'label_status': 'pending' if BLOCKING & set(pending) else 'provisional',
        'open_questions': pending, 'template_id': tpl['template_id'],
        'evaluation': {'role': 'classification', 'in_semantic_accuracy': True,
                       'reason': 'mechanically derived provisional labels; not human-approved'},
        'evidence_tier': _tier('re_executed_audit_clean', pending),
    }


def build_technical(decl, i, case_id, group):
    case = decl['technical_error_cases'][i]
    inp = case_input(decl, case)
    violations = adapters.check_arguments(inp)
    if not violations:
        raise GenerationError(f'{decl["family_id"]} technical case {i} does not violate the admitted schema')
    pending = sorted(ALWAYS)
    return {
        'id': case_id, **_common(decl, inp, 'technical_error', i, group),
        'evaluation_group': 'technical_error', 'scenario_tags': ['technical_error'],
        'expected_outcome': 'technical_error', 'technical_error': 'classifier_invalid',
        'annotation': {'per_action_targets': None, 'known_mask': None, 'unknown': None, 'contract_view': None,
                       'label_evidence': None,
                       'rationale': 'Arguments violate the admitted schema/object-argument profile; the classifier must '
                                    'refuse with classifier_invalid, never a masked unknown (D06, §3.2).',
                       'contract_rules': ['D06', '§3.2']},
        'evidence': {'kind': adapters.INPUT_VALIDATION, 'violations': violations},
        'evidence_strength': 'input_validation', 'label_status': 'provisional', 'open_questions': pending,
        'template_id': technical_template_id(decl),
        'evaluation': {'role': 'technical_error_check', 'in_semantic_accuracy': False,
                       'reason': 'D06 technical failure channel; outside semantic accuracy'},
        'evidence_tier': _tier('input_validation_checked', pending),
    }


def leakage_groups(decls):
    """{family_id: 'lg35.<first slug>'} from the leakage graph over SOU-35 declarations."""
    items = [adapters.leakage_item(adapters.to_leakage_family(d)) for d in decls]
    out = {}
    for comp in adapters.components(items):
        gid = 'lg35.' + adapters.slug(comp[0][len('family:'):])
        for k in comp:
            out[k[len('family:'):]] = gid
    return out


def generate(decls, id_map):
    """Records for every case. `id_map` (private, persisted by the caller) maps id_key -> opaque id; missing keys
    are allocated with `secrets` and added to it. Ids never encode family, class or position."""
    groups = leakage_groups(decls)
    out = []
    for d in sorted(decls, key=lambda d: d['family_id']):
        for kind, n, build in (('classification', len(d['cases']), build_classification),
                               ('technical_error', len(d['technical_error_cases']), build_technical)):
            for i in range(n):
                key = id_key(d['family_id'], kind, i)
                if key not in id_map:
                    id_map[key] = new_case_id()
                out.append(build(d, i, id_map[key], groups[d['family_id']]))
    ids = [r['id'] for r in out]
    if len(ids) != len(set(ids)):
        raise GenerationError('case id collision')
    return sorted(out, key=lambda r: r['id'])
