"""Read-only leakage analysis of the v0.2 pilot (`sou13_pilot`), which is source material only.

Nothing from v0.2 is imported as code or copied as data. The directory is passed as an argument and
only `*.jsonl` records are parsed as JSON. v0.2 records have no execution trace, so the effect profile
in the near-duplicate signature is approximated by the declared `scenario`."""
import json
from collections import Counter, defaultdict
from pathlib import Path

from sou13.hashing import sha

from .identity import normalized_description, normalized_name, normalized_server, schema_fingerprint
from .leakage import components, cross_split_errors


def load(data_dir):
    p = Path(data_dir) / 'pilot_candidates.jsonl'
    return [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]


def items(rows):
    out = []
    for r in rows:
        inp = r['input']
        args = inp.get('raw_arguments') if isinstance(inp.get('raw_arguments'), dict) else {}
        feats = {('family', r.get('family_id')), ('identity', f"{inp.get('server_id')}|{inp.get('tool_name')}"),
                 ('name', normalized_name(inp.get('tool_name'))), ('input_sha256', sha(inp)),
                 ('template_signature', sha({'schema': schema_fingerprint(inp.get('tool_schema')),
                                             'arg_keys': sorted(args), 'scenario': r.get('scenario')}))}
        if inp.get('server_id'):
            feats.add(('server', normalized_server(inp['server_id'])))
        if normalized_description(inp.get('tool_description')):
            feats.add(('description', normalized_description(inp['tool_description'])))
        out.append({'key': r['id'], 'split': r.get('split'), 'features': feats, 'declared_group': r.get('family_id')})
    return out


def analyse(data_dir):
    rows = load(data_dir)
    its = items(rows)
    errors = cross_split_errors(its)
    by_ns = Counter(e.split('=')[0].replace('LEAK ', '') for e in errors)
    comps = components(its)
    split_of = {it['key']: it['split'] for it in its}
    fam_of = {r['id']: r.get('family_id') for r in rows}
    comp_info = [{'records': len(c), 'declared_families': len({fam_of[k] for k in c}),
                  'splits': sorted({split_of[k] for k in c})} for c in comps]
    schema_by_family = defaultdict(set)
    for r in rows:
        schema_by_family[schema_fingerprint(r['input'].get('tool_schema'))].add(r.get('family_id'))
    return {
        'analysis_kind': 'sou13_cp2_v02_leakage_analysis', 'source': 'sou13_pilot v0.2 (analysis only, not gold)',
        'records': len(rows), 'declared_families': len({r.get('family_id') for r in rows}),
        'declared_splits': dict(Counter(r.get('split') for r in rows)),
        'label_basis': dict(Counter(r.get('annotation', {}).get('evidence_type') for r in rows)),
        'actual_execution_performed': dict(Counter(str(r.get('fixture_behavior', {}).get('actual_execution_performed'))
                                                   for r in rows)),
        'review_status': dict(Counter(r.get('annotation', {}).get('review_status') for r in rows)),
        'cross_split_links_by_edge': dict(sorted(by_ns.items())),
        'cross_split_link_examples': errors[:8],
        'computed_leakage_groups': len(comps),
        'computed_groups_spanning_splits': sum(len(c['splits']) > 1 for c in comp_info),
        'largest_group': max(comp_info, key=lambda c: c['records']) if comp_info else None,
        'distinct_schema_fingerprints': len(schema_by_family),
        'families_per_schema_fingerprint': sorted((len(v) for v in schema_by_family.values()), reverse=True),
        'verdict': ('v0.2 family split is NOT leakage-safe under the CP2 definition' if errors
                    else 'no cross-split links found under the CP2 definition'),
    }
