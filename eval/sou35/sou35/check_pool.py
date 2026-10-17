"""Validate a PRIVATE candidate pool and print aggregates only.

    python -m sou35.check_pool --pool private/pool --out private [--pattern T/V/C/S ...]   (patterns are owner-only)

Writes records, the opaque id map and a family-level report ONLY below eval/sou35/private/ or eval/sou35/sealed/,
and only if git confirms the target is ignored. Standard output never contains a family id, case id, identity,
argument or seed, but it is still OWNER-ONLY: once development families are public, pool-level aggregates minus
the public development data would reveal the test composition by subtraction. Publish totals only
(docs/benchmarks/sou35/DATASET_CARD.md).

Scenarios (no human ruling is assumed; both are always reported):
  as_designed   every template, every known-false label as derived
  conservative  drops cases depending on Q-S35-EMPTY-BATCH / UNMODELLED-MODE / OPTIONAL-DEFAULT and does not count
                read=false as a known negative where it depends on Q-S35-INTERNAL-ACCESS
"""
import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from . import ROOT, adapters, families, feasibility, generate, records

PRIVATE_ROOTS = (ROOT / 'private', ROOT / 'sealed')
CONSERVATIVE_DROP = frozenset({generate.Q_EMPTY_BATCH, generate.Q_UNMODELLED_MODE, generate.Q_OPTIONAL_DEFAULT})


class PrivacyError(RuntimeError):
    pass


def ensure_private_out(path):
    p = Path(path).resolve()
    if not any(p == r.resolve() or r.resolve() in p.parents for r in PRIVATE_ROOTS):
        raise PrivacyError(f'output must be inside {[str(r) for r in PRIVATE_ROOTS]}')
    probe = p / 'records' / 'candidates.jsonl'
    if subprocess.run(['git', 'check-ignore', '-q', str(probe)], cwd=ROOT).returncode != 0:
        raise PrivacyError(f'{probe} is not ignored by git; refusing to write candidate material')
    return p


def scenario_table(recs, scenario):
    """{leakage_group: (n_families, features)} after applying the scenario's ruling filter."""
    drop = CONSERVATIVE_DROP if scenario == 'conservative' else frozenset()
    feats, fams = {}, {}
    for r in recs:
        if drop & set(r['open_questions']):
            continue
        f = feasibility.record_features(r)
        if scenario == 'conservative' and generate.Q_INTERNAL_ACCESS in r['open_questions']:
            f.discard('neg:read')
        g = r['leakage_group_id']
        feats[g] = feats.get(g, frozenset()) | f
        fams.setdefault(g, set()).add(r['family_id'])
    return {g: (len(fams[g]), feats[g]) for g in feats}


def aggregate(recs, decls, patterns=()):
    """Counts only: no family id, case id, identity or argument appears in the result."""
    cls = [r for r in recs if r['expected_outcome'] == 'classification']
    labels = {a: Counter() for a in families.ACTIONS}
    for r in cls:
        for a, v in r['annotation']['per_action_targets'].items():
            labels[a][{True: 'positive', False: 'negative', None: 'null'}[v]] += 1
    dec_cases, dec_fams = Counter(), {}
    for r in recs:
        for q in r['open_questions']:
            dec_cases[q] += 1
            dec_fams.setdefault(q, set()).add(r['family_id'])
    out = {
        'families': len(decls), 'templates': sum(len(d['_templates']) for d in decls),
        'records': len(recs), 'classification': len(cls), 'technical_error': len(recs) - len(cls),
        'leakage_groups': len({r['leakage_group_id'] for r in recs}),
        'classes': dict(Counter(d['behavior_class'] for d in decls)),
        'labels': {a: dict(c) for a, c in labels.items()},
        'unknown_true': sum(r['annotation']['unknown'] is True for r in cls),
        'proven_noop': sum(not r['annotation']['unknown'] and not r['annotation']['contract_view']['actions']
                           for r in cls),
        'label_status': dict(Counter(r['label_status'] for r in recs)),
        'pending_decisions': {q: {'cases': dec_cases[q], 'families': len(dec_fams[q])} for q in sorted(dec_cases)},
        'scenario_tags': dict(Counter(t for r in recs for t in r['scenario_tags'])),
        'human_approved': sum(r['evidence_tier']['human_semantic_approval'] is not None for r in recs),
        'scenarios': {},
    }
    for sc in ('as_designed', 'conservative'):
        table = scenario_table(recs, sc)
        req = feasibility.default_requirements()
        res = {'families_per_feature': {f: sum(f in v for _, v in table.values())
                                        for f in sorted(feasibility.FULL_HELD_OUT)},
               'impossible': feasibility.necessary_condition_errors(table, req), 'patterns': {}}
        for p in patterns:
            if sum(p) != len(decls):  # never report an invalid pattern as an infeasibility result
                res['patterns']['/'.join(map(str, p))] = {'invalid': f'pattern totals {sum(p)}, pool has {len(decls)}'}
                continue
            t0 = time.perf_counter()
            c = feasibility.count_allocations(table, req, dict(zip(feasibility.SPLITS, p)))
            res['patterns']['/'.join(map(str, p))] = {'feasible_allocations': c,
                                                      'seconds': round(time.perf_counter() - t0, 3)}
        out['scenarios'][sc] = res
    return out


def run(pool_dir, out_dir, patterns=()):
    out = ensure_private_out(out_dir)
    decls = families.load_dir(pool_dir)
    if not decls:
        raise SystemExit('no declarations found')
    errors = {'intra_pool': families.intra_pool_errors(decls), 'novelty_vs_sou13_public': adapters.novelty_errors(decls)}
    id_path = out / 'ids' / 'id_map.json'
    id_map = json.loads(id_path.read_text(encoding='utf-8')) if id_path.exists() else {}
    recs = generate.generate(decls, id_map)
    errors['record_validation'] = records.dataset_errors(recs, decls)
    for sub in ('ids', 'records'):
        (out / sub).mkdir(parents=True, exist_ok=True)
    id_path.write_text(json.dumps(id_map, indent=1, sort_keys=True), encoding='utf-8')
    with (out / 'records' / 'candidates.jsonl').open('w', encoding='utf-8', newline='\n') as fh:
        for r in recs:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n')
    agg = aggregate(recs, decls, patterns)
    private_report = {'aggregate': agg, 'errors': errors,
                      'per_family': {d['family_id']: {
                          'records': sum(r['family_id'] == d['family_id'] for r in recs),
                          'pending_decisions': sorted({q for r in recs if r['family_id'] == d['family_id']
                                                       for q in r['open_questions']}),
                          'features': sorted(feasibility.family_features(
                              [r for r in recs if r['family_id'] == d['family_id']])[d['family_id']])}
                          for d in decls}}
    (out / 'report.json').write_text(json.dumps(private_report, indent=1, sort_keys=True), encoding='utf-8')
    return agg, {k: len(v) for k, v in errors.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--pool', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--pattern', action='append', default=[], help='train/validation/calibration/test family counts')
    a = ap.parse_args(argv)
    pats = [tuple(int(x) for x in p.split('/')) for p in a.pattern]
    agg, err_counts = run(Path(a.pool), Path(a.out), pats)
    print(json.dumps({'error_counts': err_counts, 'aggregate': agg}, indent=1, sort_keys=True))
    return 0 if not any(err_counts.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
