"""Identity features used to detect aliases, near-duplicate templates and leakage (stdlib only).

Every function here is a pure normalisation. Two items that share any normalised feature value are
linked; see docs/CP2_SPLIT_AND_LEAKAGE_POLICY.md for the edge list and the rationale for each edge."""
import re

from sou13.hashing import sha

# Tokens that carry no behavioural meaning in a tool or server name: version markers, wrappers, prefixes.
NOISE_TOKENS = frozenset({'adapter', 'wrapper', 'tool', 'api', 'svc', 'service', 'synthetic', 'unregistered',
                          'new', 'old', 'legacy', 'beta'})
_VERSION_TOKEN = re.compile(r'^v?\d+$')


def name_tokens(name):
    """Order-insensitive token set of a tool name: `fetch_url`, `FetchUrl`, `url-fetch_v2` -> ('fetch', 'url')."""
    split_camel = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name or '')
    tokens = [t for t in re.split(r'[^a-z0-9]+', split_camel.lower()) if t]
    tokens = [t for t in tokens if not _VERSION_TOKEN.match(t)]
    tokens = [re.sub(r'\d+$', '', t) or t for t in tokens]  # `url2` -> `url` (attached version digits)
    return tuple(sorted({t for t in tokens if t not in NOISE_TOKENS}))


def normalized_name(name):
    return ' '.join(name_tokens(name))


def normalized_server(server_id):
    return (server_id or '').strip().lower() or None


def normalized_description(text):
    """Lower-case word sequence; None/absent/empty descriptions never create a link."""
    if text is None:
        return None
    words = re.findall(r'[a-z0-9]+', text.lower())
    return ' '.join(words) or None


def _types(prop):
    declared = prop.get('type', []) if isinstance(prop, dict) else []
    return sorted([declared] if isinstance(declared, str) else declared)


def schema_fingerprint(schema):
    """Structure of an object schema (property names + types, required, additionalProperties); text ignored."""
    schema = schema if isinstance(schema, dict) else {}
    shape = {'properties': sorted([k.lower(), _types(v)] for k, v in schema.get('properties', {}).items()),
             'required': sorted(k.lower() for k in schema.get('required', [])),
             'additionalProperties': schema.get('additionalProperties', True)}
    return sha(shape)


def effect_event(ev):
    """One sandbox trace event -> effect-profile token (sou13/sandbox.py Effects vocabulary)."""
    kind = ev['event']
    if kind == 'store_read' and ev.get('view') == 'metadata':
        return 'store_read:metadata'
    if kind == 'store_write':
        return 'store_write:' + ev.get('mode', 'set')
    if kind == 'send':
        return 'send:' + ev['channel']
    return kind


def effect_profile_from_trace(trace):
    """Order-preserving unique effect tokens; repetition of the same effect does not make a new template."""
    out = []
    for ev in trace:
        token = effect_event(ev)
        if token not in out:
            out.append(token)
    return out


def shape_signature(schema, effect_profile, evidence_kind, disabled_actions=()):
    """Field-NAME-insensitive template shape: argument types (+ required flag) as a multiset, effect profile,
    evidence kind. Equal shapes in two families are near-duplicate CANDIDATES (renamed fields defeat
    template_signature). Shape alone never links families: unrelated tools with the same class often share it,
    so every pair must be adjudicated explicitly (taxonomy.shape_review_errors)."""
    schema = schema if isinstance(schema, dict) else {}
    req = {k.lower() for k in schema.get('required', [])}
    args = sorted([_types(v), k.lower() in req] for k, v in schema.get('properties', {}).items())
    return sha({'args': args, 'additionalProperties': schema.get('additionalProperties', True),
                'effect_profile': list(effect_profile), 'evidence_kind': evidence_kind,
                'disabled_actions': sorted(disabled_actions)})


_SEMANTIC_KEYS = ('fn', 'channel', 'equals')  # constants that change execution semantics, kept in the skeleton


def _skel(x, key=None):
    if isinstance(x, dict):
        out = {}
        for k, v in sorted(x.items()):
            if k == 'cases':  # case labels are constants; the multiset of case bodies is structure
                out[k] = sorted((_skel(b) for b in v.values()), key=repr)
            elif k in ('as', 'arg') and isinstance(v, str):
                out[k] = '$'
            else:
                out[k] = _skel(v, k)
        return out
    if isinstance(x, list):
        return [_skel(v, key) for v in x]
    if key in _SEMANTIC_KEYS or key == 'op':
        return x
    if isinstance(x, str):
        return '$' if x.startswith('$') else '@' if x.startswith('@') else 'C'
    return type(x).__name__


def program_skeleton(program):
    """Execution-program skeleton: operations, nesting and data flow ($argument / @variable / Constant) with all
    names, store/component/principal constants and argument names erased. Compute function, send channel and
    branch values are semantic and kept. Equal shape_signature AND equal skeleton = same behavioural template
    under renamed fields/constants/domain labels (owner decision 2026-10-11): never 'distinct'."""
    return None if program is None else sha(_skel(program))


def template_signature(schema, arg_keys, effect_profile, evidence_kind, disabled_actions=()):
    """Structural signature of a case template. Equal signatures in different families = near-duplicate."""
    return sha({'schema': schema_fingerprint(schema), 'arg_keys': sorted(arg_keys),
                'effect_profile': list(effect_profile), 'evidence_kind': evidence_kind,
                'disabled_actions': sorted(disabled_actions)})
