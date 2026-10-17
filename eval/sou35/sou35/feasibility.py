"""Deterministic split-feasibility check over leakage groups (replaces sou13cp2.splits.assign for SOU-35).

`splits.assign` indexes the frozen SOU-13 class/stratum tuples and balances one stratum per family; SOU-35
families are multi-label (and may be `multimode`), so coverage is checked on label FEATURES computed from the
generated records:

  pos:<action>   some case has the action true            neg:<action>  some case has the action known false
  unknown        some case has unknown=true               noop          some case is a proven no-op
  technical_error  some technical-error row               misleading    some case has a misleading description

Families linked in the leakage graph form one group and are always placed together. Requirements are never
relaxed: an unsatisfiable requirement is reported as IMPOSSIBLE (necessary-condition report) and the exact
search returns 0. Only counts are returned, never an allocation, so a report cannot reveal a test split."""
import itertools

from .families import ACTIONS

SPLITS = ('train', 'validation', 'calibration', 'test')
HELD_OUT = ('validation', 'calibration', 'test')
FULL_HELD_OUT = frozenset([f'pos:{a}' for a in ACTIONS] + [f'neg:{a}' for a in ACTIONS]
                          + ['unknown', 'noop', 'technical_error'])


def default_requirements(features=FULL_HELD_OUT):
    return {s: (frozenset(features) if s in HELD_OUT else frozenset()) for s in SPLITS}


def record_features(r, rulings_register=None):
    if rulings_register is not None:
        from . import rulings
        if not rulings.primary_scoring_admissible(r, rulings_register):
            return set()
    if r['expected_outcome'] == 'technical_error':
        return {'technical_error'}
    t, unknown = r['annotation']['per_action_targets'], r['annotation']['unknown']
    out = {f'pos:{a}' for a in ACTIONS if t[a] is True} | {f'neg:{a}' for a in ACTIONS if t[a] is False}
    if unknown:
        out.add('unknown')
    if not unknown and not any(t[a] for a in ACTIONS):
        out.add('noop')
    if 'misleading_description' in r['scenario_tags']:
        out.add('misleading')
    return out


def family_features(records, rulings_register=None):
    out = {}
    for r in records:
        out.setdefault(r['family_id'], set()).update(record_features(r, rulings_register))
    return {k: frozenset(v) for k, v in out.items()}


def group_table(records, rulings_register=None):
    """{leakage_group_id: (n_families, features)} from the records' declared leakage groups."""
    fam_feats = family_features(records, rulings_register)
    fam_group = {r['family_id']: r['leakage_group_id'] for r in records}
    table = {}
    for fid, gid in fam_group.items():
        n, feats = table.get(gid, (0, frozenset()))
        table[gid] = (n + 1, feats | fam_feats[fid])
    return table


def necessary_condition_errors(table, requirements):
    """A feature needed in k splits must be carried by at least k distinct groups (a group sits in one split)."""
    errors = []
    demand = {}
    for s, req in requirements.items():
        for f in req:
            demand.setdefault(f, []).append(s)
    for f, splits in sorted(demand.items()):
        supply = sum(f in feats for _, feats in table.values())
        if supply < len(splits):
            errors.append(f'IMPOSSIBLE {f}: required in {len(splits)} splits {sorted(splits)} but carried by '
                          f'{supply} leakage group(s)')
    return errors


def count_allocations(table, requirements, counts=None, allowed=None):
    """Exact number of assignments of whole leakage groups to splits meeting every requirement (and the per-split
    family counts when given). `allowed` maps group -> admissible splits (default: all)."""
    # Memoised dynamic programme over groups in sorted order. State = (next group, per-split load, per-split
    # covered REQUIRED features as a bitmask); paths reaching the same state contribute identical completions.
    # Groups carrying the scarcest required features go first (deterministic; order changes speed, not the count).
    required = set().union(*requirements.values())
    supply = {f: sum(f in table[g][1] for g in table) for f in required}
    gids = sorted(table, key=lambda g: (-sum(1 / supply[f] for f in table[g][1] & required if supply[f]), g))
    sizes = [table[g][0] for g in gids]
    if counts is not None and sum(counts.values()) != sum(sizes):
        return 0
    bit = {f: 1 << k for k, f in enumerate(sorted(required))}

    def mask(fs):
        return sum(bit[f] for f in fs if f in bit)

    need = tuple(mask(requirements[s]) for s in SPLITS)
    feats = [mask(table[g][1]) for g in gids]
    suffix = [0] * (len(gids) + 1)
    for i in range(len(gids) - 1, -1, -1):
        suffix[i] = suffix[i + 1] | feats[i]
    cap = tuple(counts[s] for s in SPLITS) if counts is not None else None
    choices = [tuple(SPLITS.index(s) for s in (allowed or {}).get(g, SPLITS)) for g in gids]
    memo = {}

    def rec(i, load, cov):
        if any(need[k] & ~(cov[k] | suffix[i]) for k in range(len(SPLITS))):
            return 0
        if i == len(gids):
            return int(cap is None or load == cap)
        key = (i, load, cov)
        if key not in memo:
            total = 0
            for k in choices[i]:
                if cap is not None and load[k] + sizes[i] > cap[k]:
                    continue
                nl = load[:k] + (load[k] + sizes[i],) + load[k + 1:]
                nc = cov[:k] + (cov[k] | (feats[i] & need[k]),) + cov[k + 1:]
                total += rec(i + 1, nl, nc)
            memo[key] = total
        return memo[key]

    return rec(0, (0,) * len(SPLITS), (0,) * len(SPLITS))


def feasible_test_sets(table, requirements, counts):
    """Every set of whole leakage groups that can be the test split (exactly counts['test'] families) and still
    admits at least one complete allocation of the other groups. Sorted list of sorted group-id tuples."""
    gids = sorted(table)
    out = []
    for r in range(1, len(gids) + 1):
        for combo in itertools.combinations(gids, r):
            if sum(table[g][0] for g in combo) != counts['test']:
                continue
            allowed = {g: (('test',) if g in combo else ('train', 'validation', 'calibration')) for g in gids}
            if count_allocations(table, requirements, counts, allowed):
                out.append(tuple(combo))
    return sorted(out)


def find_allocation(table, requirements, counts, allowed, order):
    """First complete allocation {group: split} visiting groups in `order` and splits in SPLITS order, or None.
    Deterministic for a given order; callers derive the order from a recorded salt."""
    sizes = {g: table[g][0] for g in table}
    load = {s: 0 for s in SPLITS}
    covered = {s: frozenset() for s in SPLITS}
    remaining = [frozenset()] * (len(order) + 1)
    for i in range(len(order) - 1, -1, -1):
        remaining[i] = remaining[i + 1] | table[order[i]][1]
    chosen = {}

    def rec(i):
        if any(not requirements[s] <= (covered[s] | remaining[i]) for s in SPLITS):
            return False
        if i == len(order):
            return all(load[s] == counts[s] for s in SPLITS)
        g = order[i]
        for s in allowed.get(g, SPLITS):
            if load[s] + sizes[g] > counts[s]:
                continue
            prev = covered[s]
            load[s] += sizes[g]
            covered[s] = prev | table[g][1]
            chosen[g] = s
            if rec(i + 1):
                return True
            load[s] -= sizes[g]
            covered[s] = prev
            del chosen[g]
        return False

    return dict(chosen) if rec(0) else None


def patterns(n_families, minimum=None):
    """Every (train, validation, calibration, test) family-count vector summing to n_families."""
    minimum = minimum or {s: 1 for s in SPLITS}
    for combo in itertools.product(range(n_families + 1), repeat=len(SPLITS)):
        if sum(combo) == n_families and all(c >= minimum[s] for c, s in zip(combo, SPLITS)):
            yield dict(zip(SPLITS, combo))


def report(records, requirements=None, candidate_patterns=None, allowed=None):
    """Counts only. `candidate_patterns`: list of family-count dicts (default: every pattern with >=1 family per
    split). A pattern is feasible iff its count is > 0."""
    requirements = default_requirements() if requirements is None else requirements
    table = group_table(records)
    n = sum(size for size, _ in table.values())
    pats = list(patterns(n)) if candidate_patterns is None else candidate_patterns
    rows = []
    for p in pats:
        c = count_allocations(table, requirements, p, allowed)
        rows.append({'pattern': '/'.join(str(p[s]) for s in SPLITS), 'feasible_allocations': c})
    return {'families': n, 'leakage_groups': len(table),
            'requirements': {s: sorted(r) for s, r in requirements.items()},
            'impossible': necessary_condition_errors(table, requirements),
            'patterns': rows, 'feasible_patterns': [r['pattern'] for r in rows if r['feasible_allocations']]}
