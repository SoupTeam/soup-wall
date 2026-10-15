"""Fresh sealed-test custody: commit -> draw -> custodian acceptance (commit-reveal, no family named publicly).

    declared          custodian named; pool digest and split rule recorded
    committed         custodian seed committed; the list of feasible test sets is fixed by its digest
    drawn             test set selected from the committed list by the seed; only a salted commitment is public
    custody_accepted  the named custodian records acceptance (person, time, decision reference)

A PUBLIC state never contains the seed, the nonce or a family id (`public_state_errors`). The PRIVATE part returned
by `commit`/`draw` must be stored by the custodian under the ignored sealed/ workspace. Nothing here runs a draw on its
own: the custodian must call `draw` explicitly with the committed seed. This module does not assert that any person
has accepted custody; `accept` only records what the custodian supplies."""
import hashlib
import json
import re
import secrets

from . import adapters, feasibility

STATES = ('declared', 'committed', 'drawn', 'custody_accepted')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
PRIVATE_KEYS = frozenset({'seed', 'nonce', 'test_families', 'test_groups'})
REQUIRED = {
    'declared': {'custody_kind', 'state', 'custodian', 'pool_digest', 'rule_digest'},
    'committed': {'feasible_sets_digest', 'n_feasible_sets', 'commitment'},
    'drawn': {'test_set_commitment', 'test_family_count'},
    'custody_accepted': {'acceptance'},
}


class CustodyError(ValueError):
    pass


def _h(*parts):
    return hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()


def new_seed():
    return secrets.token_hex(32)


def pool_digest(decls):
    return adapters.sha(sorted(d['_declaration_sha256'] for d in decls))


def rule_digest(requirements, counts):
    return adapters.sha({'requirements': {s: sorted(r) for s, r in requirements.items()}, 'counts': counts})


def _required_for(state):
    keys = set()
    for s in STATES[:STATES.index(state) + 1]:
        keys |= REQUIRED[s]
    return keys


def public_state_errors(state):
    """Structure, hex formats and absence of private material in a public custody state."""
    e = []
    if not isinstance(state, dict) or state.get('state') not in STATES:
        return ['custody state missing or unknown']
    leaked = PRIVATE_KEYS & set(state)
    if leaked:
        e.append(f'public custody state carries private material: {sorted(leaked)}')
    missing = _required_for(state['state']) - set(state)
    if missing:
        e.append(f'custody state {state["state"]} lacks {sorted(missing)}')
    for k in ('pool_digest', 'rule_digest', 'feasible_sets_digest', 'commitment', 'test_set_commitment'):
        if k in state and not (isinstance(state[k], str) and HEX64.match(state[k])):
            e.append(f'{k} is not a 64-hex sha256 commitment')
    if not (isinstance(state.get('custodian'), str) and state['custodian'].strip()):
        e.append('custodian must be named')
    return e


def _expect(state, expected):
    errs = public_state_errors(state)
    if errs:
        raise CustodyError(f'malformed custody state: {errs}')
    if state['state'] != expected:
        raise CustodyError(f'invalid custody transition: state is {state["state"]!r}, expected {expected!r}')


def declare(decls, custodian, requirements, counts):
    if not (isinstance(custodian, str) and custodian.strip()):
        raise CustodyError('a named custodian is required')
    return {'custody_kind': 'sou35_sealed_test_custody', 'state': 'declared', 'custodian': custodian,
            'pool_digest': pool_digest(decls), 'rule_digest': rule_digest(requirements, counts)}


def _feasible(table, requirements, counts):
    sets = feasibility.feasible_test_sets(table, requirements, counts)
    return sets, adapters.sha([list(s) for s in sets])


def commit(state, table, requirements, counts, seed):
    """-> (public_state, private_part). Fails if no test set can satisfy the recorded requirements (never relaxed)."""
    _expect(state, 'declared')
    if not (isinstance(seed, str) and HEX64.match(seed)):
        raise CustodyError('seed must be 64 lowercase hex characters (use new_seed())')
    if rule_digest(requirements, counts) != state['rule_digest']:
        raise CustodyError('requirements/counts differ from the declared split rule')
    sets, digest = _feasible(table, requirements, counts)
    if not sets:
        raise CustodyError('IMPOSSIBLE: no test set satisfies the declared requirements; nothing committed')
    public = dict(state, state='committed', feasible_sets_digest=digest, n_feasible_sets=len(sets),
                  commitment=_h(seed, state['pool_digest'], state['rule_digest'], digest))
    return public, {'seed': seed}


def draw(state, table, requirements, counts, seed, group_families):
    """Reveal-and-select: the seed must open the commitment and the feasible list must be unchanged.
    `group_families` maps leakage group -> family ids. -> (public_state, private_part)."""
    _expect(state, 'committed')
    if not (isinstance(seed, str) and HEX64.match(seed)) or \
            _h(seed, state['pool_digest'], state['rule_digest'], state['feasible_sets_digest']) != state['commitment']:
        raise CustodyError('seed does not open the commitment')
    sets, digest = _feasible(table, requirements, counts)
    if digest != state['feasible_sets_digest'] or rule_digest(requirements, counts) != state['rule_digest']:
        raise CustodyError('pool, rule or feasible test sets changed after commitment')
    groups = sets[int(_h(seed, 'draw'), 16) % len(sets)]
    families = sorted(f for g in groups for f in group_families[g])
    nonce = _h(seed, 'nonce')
    public = dict(state, state='drawn', test_set_commitment=test_set_commitment(families, nonce),
                  test_family_count=len(families))
    return public, {'seed': seed, 'nonce': nonce, 'test_groups': list(groups), 'test_families': families}


def test_set_commitment(test_families, nonce):
    return _h(nonce, json.dumps(sorted(test_families)))


def verify_test_set(state, test_families, nonce):
    return state.get('test_set_commitment') == test_set_commitment(test_families, nonce)


def accept(state, *, custodian, accepted_at, decision_ref):
    """Record the custodian's own acceptance; the caller supplies it, nothing is assumed."""
    _expect(state, 'drawn')
    if not all(isinstance(v, str) and v.strip() for v in (custodian, accepted_at, decision_ref)):
        raise CustodyError('acceptance requires custodian, accepted_at and decision_ref')
    if custodian != state['custodian']:
        raise CustodyError('only the declared custodian can accept custody')
    return dict(state, state='custody_accepted',
                acceptance={'custodian': custodian, 'accepted_at': accepted_at, 'decision_ref': decision_ref})
