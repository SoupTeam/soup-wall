"""Leakage graph: items (taxonomy families or case records) linked by shared identity features.

An item is {'key', 'split', 'features': set[(namespace, value)], 'declared_group'}. Two items sharing any
feature are in the same leakage group. Because every connected component that spans two splits contains
at least one edge whose endpoints lie in different splits, checking each feature value for a single split
is sufficient to reject any direct or transitive cross-split link.

Edges (namespaces): family, alias_group, template_id, identity (server_id|tool_name), server,
name (order-insensitive tool-name tokens), description (normalised text, never null), template_signature
(near-duplicate template), definition_sha256, input_sha256, leakage_group (declared)."""
from collections import defaultdict

from .identity import (effect_profile_from_trace, normalized_description, normalized_name, normalized_server,
                       template_signature)

EDGE_NAMESPACES = ('family', 'alias_group', 'template_id', 'identity', 'server', 'name', 'description',
                   'template_signature', 'near_duplicate', 'definition_sha256', 'input_sha256', 'leakage_group')


class UnionFind:
    def __init__(self, keys):
        self.parent = {k: k for k in keys}

    def find(self, k):
        while self.parent[k] != k:
            self.parent[k] = self.parent[self.parent[k]]
            k = self.parent[k]
        return k

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)  # deterministic root


def components(items):
    """Connected components as sorted lists of item keys, sorted by first key."""
    keys = [it['key'] for it in items]
    if len(keys) != len(set(keys)):
        raise ValueError('duplicate item key')
    uf = UnionFind(keys)
    first_owner = {}
    for it in items:
        for feat in sorted(it['features']):
            if feat in first_owner:
                uf.union(first_owner[feat], it['key'])
            else:
                first_owner[feat] = it['key']
    groups = defaultdict(list)
    for k in keys:
        groups[uf.find(k)].append(k)
    return sorted((sorted(g) for g in groups.values()), key=lambda g: g[0])


def cross_split_errors(items):
    """Every feature value must occur in one split only."""
    where = defaultdict(lambda: defaultdict(list))
    for it in items:
        for feat in it['features']:
            where[feat][it['split']].append(it['key'])
    errors = []
    for (ns, value), by_split in sorted(where.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
        if len(by_split) > 1:
            detail = '; '.join(f'{s}: {sorted(set(k))[:3]}' for s, k in sorted(by_split.items()))
            errors.append(f'LEAK {ns}={str(value)[:80]!r} crosses splits ({detail})')
    return errors


def group_consistency_errors(items):
    """Each computed component must carry exactly one declared leakage_group_id (no silent merges)."""
    by_key = {it['key']: it for it in items}
    errors = []
    for comp in components(items):
        declared = sorted({by_key[k]['declared_group'] for k in comp})
        if len(declared) != 1:
            errors.append(f'MERGE items {comp[:4]}{"..." if len(comp) > 4 else ""} are linked but declare '
                          f'leakage groups {declared}: update the taxonomy/manifest (alias or near-duplicate)')
    return errors


def family_item(fam, split, group):
    feats = {('family', fam['family_id']), ('alias_group', fam['alias_group_id']), ('leakage_group', group)}
    idents = fam['identities'] + fam.get('rejected_identities', [])  # rejected (admission-test) identities link too
    feats |= {('identity', f'{s}|{t}') for s, t in idents}
    feats |= {('server', normalized_server(s)) for s, _ in idents if s}
    feats |= {('name', n) for n in fam['normalized_names']}
    feats |= {('description', normalized_description(d)) for d in fam['descriptions'] if normalized_description(d)}
    for t in fam['templates']:
        feats |= {('template_id', t['template_id']), ('template_signature', t['signature'])}
    # adjudicated field-renamed near-duplicates (taxonomy.SHAPE_REVIEW / restricted shape_review)
    feats |= {('near_duplicate', '|'.join(sorted((fam['family_id'], o)))) for o in fam.get('near_duplicates', [])}
    return {'key': 'family:' + fam['family_id'], 'split': split, 'features': feats, 'declared_group': group}


def record_effect_profile(r):
    ev = r['evidence']
    if ev['kind'] in ('controlled_execution', 'declarative_semantics_execution'):
        return effect_profile_from_trace(ev['execution']['trace'])
    return []


def record_signature(r):
    inp, ev = r['input'], r['evidence']
    args = inp['raw_arguments'] if isinstance(inp['raw_arguments'], dict) else {}
    disabled = ev.get('world_initial', {}).get('disabled_actions', []) if ev['kind'] == 'controlled_execution' else []
    return template_signature(inp['tool_schema'], list(args), record_effect_profile(r), ev['kind'], disabled)


def record_item(r):
    inp = r['input']
    feats = {('family', r['family_id']), ('alias_group', r['alias_group_id']), ('template_id', r['template_id']),
             ('leakage_group', r['leakage_group_id']),
             ('identity', f"{inp.get('server_id')}|{inp['tool_name']}"), ('name', normalized_name(inp['tool_name'])),
             ('template_signature', record_signature(r)),
             ('definition_sha256', r['hashes']['definition_sha256']), ('input_sha256', r['hashes']['input_sha256'])}
    if inp.get('server_id'):
        feats.add(('server', normalized_server(inp['server_id'])))
    desc = normalized_description(inp.get('tool_description'))
    if desc:
        feats.add(('description', desc))
    return {'key': 'record:' + r['id'], 'split': r['split'], 'features': feats,
            'declared_group': r['leakage_group_id']}


def taxonomy_items(fams, manifest):
    return [family_item(f, manifest['family_split'][f['family_id']], manifest['family_group'][f['family_id']])
            for f in fams]


def leakage_errors(items):
    return cross_split_errors(items) + group_consistency_errors(items)
