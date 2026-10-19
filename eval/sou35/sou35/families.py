"""SOU-35 family declarations: JSON data (never Python), validated against the frozen interpreter's rules.

A declaration binds one synthetic implementation (a closed program for sou13cp2.semantics) to its admitted
identities. Real SOU-35 declarations live only in the gitignored private workspace; the public tree holds
clearly artificial toy declarations used by tests.

Interpreter facts enforced here (sou13cp2/semantics.py, sou13/build.py):
  * schema property types must be ones sou13.build.check_arguments can match: a Python int is reported as
    'number', so 'integer' would reject valid arguments; enum/items/nested properties are NOT checked;
  * `$name` references resolve top-level arguments only (no `$a.b`); `@var.field` resolves one level;
  * every classification case must satisfy check_arguments, every technical-error case must violate it.
"""
import json
from pathlib import Path

from . import ROOT, adapters

CHECKABLE_TYPES = {'string', 'number', 'boolean', 'object', 'array'}
CLASSES = ('read', 'write', 'delete', 'send_data', 'change_permissions', 'mixed', 'no_effect', 'unknown',
           'multimode')
ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
DESCRIPTION_KINDS = ('honest', 'misleading', 'null')
FAMILY_SCHEMA = ROOT / 'schema' / 'sou35_family.schema.json'


class DeclarationError(ValueError):
    pass


def load_decl(decl, origin='<declaration>'):
    errors = declaration_errors(decl)
    if errors:
        raise DeclarationError(f'{origin}: {errors}')
    return finalise(decl)


def load(path):
    return load_decl(json.loads(Path(path).read_text(encoding='utf-8')), str(path))


def load_dir(directory):
    return [load(p) for p in sorted(Path(directory).glob('*.json'))]


def _schema_validator():
    import jsonschema
    schema = json.loads(FAMILY_SCHEMA.read_text(encoding='utf-8'))
    return jsonschema.Draft202012Validator(schema)


def _refs(x):
    if isinstance(x, list):
        for v in x:
            yield from _refs(v)
    elif isinstance(x, str) and x[:1] in '$@':
        yield x


def _program_refs(program):
    """All `$`/`@` references (and `when`/`foreach` argument names) used anywhere in the program."""
    for step in program:
        for k, v in step.items():
            if k in ('then', 'else', 'do'):
                yield from _program_refs(v)
            elif k == 'cases':
                for sub in v.values():
                    yield from _program_refs(sub)
            elif k in ('arg',):
                yield '$' + v
            elif k not in ('op', 'store', 'channel', 'fn', 'as', 'equals', 'into'):
                yield from _refs(v)


def unknown_profile(effect_profile):
    opaque = adapters.opaque_token()
    acts = established(effect_profile)
    return 'none' if opaque not in effect_profile else ('partial' if acts else 'full')


def established(effect_profile):
    ev = adapters.event_action()
    return sorted({ev[e] for e in effect_profile if e in ev}, key=ACTIONS.index)


def class_errors(cls, outcomes):
    """outcomes: list of (actions tuple, unknown_profile) per behavioural template."""
    sets = [set(a) for a, _ in outcomes]
    known = all(u == 'none' for _, u in outcomes)
    if cls in ACTIONS:
        ok = known and all(s <= {cls} for s in sets) and any(s == {cls} for s in sets)
    elif cls == 'no_effect':
        ok = known and all(not s for s in sets)
    elif cls == 'mixed':  # argument-selected subsets (incl. no-op) of one multi-action behaviour
        top = max(sets, key=len)
        ok = known and len(top) >= 2 and all(s <= top for s in sets)
    elif cls == 'unknown':
        ok = all(u != 'none' for _, u in outcomes)
    elif cls == 'multimode':  # only when no narrower class fits
        ok = len(set(outcomes)) >= 2 and not any(not class_errors(c, outcomes) for c in CLASSES if c != 'multimode')
    else:
        ok = False
    return [] if ok else [f'templates {sorted(set(outcomes))} contradict behaviour class {cls}']


def declaration_errors(decl):
    errors = [f'schema: {e.message}' for e in _schema_validator().iter_errors(decl)]
    if errors:
        return errors
    fid, sch = decl['family_id'], decl['tool_schema']
    if fid.split('.')[1] != decl['behavior_class']:
        errors.append('family_id class differs from behavior_class')
    for name, prop in sch['properties'].items():
        types = prop.get('type')
        types = [types] if isinstance(types, str) else types or []
        if not types or set(types) - CHECKABLE_TYPES:
            errors.append(f'tool_schema.{name}: types {types} not checkable by the object-argument profile '
                          f'(use number instead of integer)')
    errors += [f'program: {e}' for e in adapters.program_errors(decl['program'])]
    for ref in _program_refs(decl['program']):
        if ref.startswith('$'):
            name = ref[1:]
            if '.' in name:
                errors.append(f'program: {ref}: argument field access is not supported by the interpreter')
            elif name not in sch['properties']:
                errors.append(f'program: {ref} is not a declared argument')
    idents = [tuple(i) for i in decl['identities']]
    if len(idents) != len(set(idents)):
        errors.append('duplicate identity')
    keys = [(tuple(t['effect_profile']), tuple(sorted(t['arg_keys']))) for t in decl['templates']]
    if len(keys) != len(set(keys)):
        errors.append('two templates with the same (effect_profile, arg_keys)')
    variants = [t['variant'] for t in decl['templates']]
    if len(variants) != len(set(variants)):
        errors.append('duplicate template variant')
    outcomes = []
    for t in decl['templates']:
        acts, unk = established(t['effect_profile']), unknown_profile(t['effect_profile'])
        unknown_events = [e for e in t['effect_profile'] if e not in adapters.event_action()
                          and e != adapters.opaque_token()]
        if unknown_events:
            errors.append(f'template {t["variant"]}: events outside the interpreter vocabulary {unknown_events}')
        if sorted(t['expected']['actions'], key=ACTIONS.index) != acts or t['expected']['unknown'] != (unk != 'none'):
            errors.append(f'template {t["variant"]}: expected labels disagree with its effect profile')
        outcomes.append((tuple(acts), unk))
    if outcomes:
        errors += class_errors(decl['behavior_class'], outcomes)
    for i, case in enumerate(decl['cases']):
        errors += [f'case {i}: {m}' for m in case_input_errors(decl, case, technical=False)]
    for i, case in enumerate(decl.get('technical_error_cases', [])):
        errors += [f'technical case {i}: {m}' for m in case_input_errors(decl, case, technical=True)]
    if decl['descriptions'].get('misleading') is None and any(c['description'] == 'misleading'
                                                               for c in decl['cases'] + decl.get('technical_error_cases', [])):
        errors.append('a case uses the misleading description but none is declared')
    return errors


def case_input(decl, case):
    server_id, tool_name = decl['identities'][case['identity']]
    desc = None if case['description'] == 'null' else decl['descriptions'][case['description']]
    return {'server_id': server_id, 'tool_name': tool_name, 'tool_description': desc,
            'tool_schema': decl['tool_schema'], 'raw_arguments': case['raw_arguments']}


def case_input_errors(decl, case, technical):
    if case['identity'] >= len(decl['identities']):
        return ['identity index out of range']
    if technical and not (case['raw_arguments'] is None or isinstance(case['raw_arguments'], dict)):
        # the shared CP2 record schema admits raw_arguments object|null only (array arguments are not representable)
        return ['technical-error raw_arguments must be an object or null']
    inp = case_input(decl, case)
    errors = adapters.input_errors(inp)
    violations = adapters.check_arguments(inp)
    if technical and not violations:
        errors.append('technical-error case does not violate the admitted schema')
    if not technical and violations:
        errors.append(f'arguments violate the admitted schema: {violations}')
    return errors


def finalise(decl):
    """Attach derived template ids/signatures (prefixed `_`, never part of the declaration digest)."""
    decl = dict(decl)
    cls, s = decl['behavior_class'], adapters.slug(decl['family_id'])
    templates = []
    for t in decl['templates']:
        templates.append({**t, 'template_id': f'tpl35.{cls}.{s}.{t["variant"]}',
                          'arg_keys': sorted(t['arg_keys']),
                          'established_actions': established(t['effect_profile']),
                          'unknown_profile': unknown_profile(t['effect_profile']),
                          'signature': adapters.template_signature(decl['tool_schema'], t['arg_keys'],
                                                                   t['effect_profile']),
                          'shape_signature': adapters.shape_signature(decl['tool_schema'], t['effect_profile'])})
    decl['_templates'] = templates
    decl['_declaration_sha256'] = adapters.sha({k: v for k, v in decl.items() if not k.startswith('_')})
    return decl


def technical_template_id(decl):
    return f'tpl35.{decl["behavior_class"]}.{adapters.slug(decl["family_id"])}.technical_error'


def intra_pool_errors(decls):
    """Within SOU-35: two families must not share identity features, and equal template shape with an equal
    program skeleton is a near-duplicate (same rule as against SOU-13)."""
    errors = []
    items = [adapters.leakage_item(adapters.to_leakage_family(d)) for d in decls]
    for comp in adapters.components(items):
        if len(comp) > 1:
            errors.append(f'LINKED families share identity features: {comp}')
    seen = {}
    for d in decls:
        skel = adapters.program_skeleton(d['program'])
        for t in d['_templates']:
            other = seen.get((t['shape_signature'], skel))
            if other and other != d['family_id']:
                errors.append(f'NEAR-DUPLICATE {d["family_id"]} and {other}: same template shape and program skeleton')
            seen[(t['shape_signature'], skel)] = d['family_id']
    return errors
