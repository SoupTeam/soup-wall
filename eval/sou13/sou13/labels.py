"""Per-action tri-state labels and the D01 contract view.

Primary annotation (SOU-13/SOU-16 convention): five independent labels true/false/null,
known_mask, and a separately stored `unknown`. Contract view (SOU-10 D01, §3.1):
`actions` + `unknown`.

Unconditional invariants are only those that follow from the definitions:
  * known_mask[a] == int(label is not None)
  * contract actions == the set of true labels; contract unknown == record unknown
  * any null label  =>  unknown is true   (a null label is an indeterminate effect;
    SOU-10 §3.1 defines unknown as "unmodeled, unresolvable, or indeterminate effects exist")

The converse does NOT hold in general: §3.1 allows unknown=true for unmodeled effects
outside the five-action taxonomy even when all five labels are known. The reverse mapping
contract -> tri-state is therefore defined ONLY under the restrictive assumption SOU13-ASSUME-UNKNOWN-FROM-NULL
(unknown arises solely from the five labels) plus the SOU-13 annotation convention
`forbidden_actions` (SOU13-CONV-FORBIDDEN-ACTIONS, not a contract field), and raises AssumptionViolation otherwise.
"""

ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')


class AssumptionViolation(ValueError):
    pass


def known_mask(targets):
    return {a: int(targets[a] is not None) for a in ACTIONS}


def contract_view(targets, unknown):
    return {'actions': [a for a in ACTIONS if targets[a] is True], 'unknown': bool(unknown)}


def invariant_errors(targets, mask, unknown, view, forbidden=None):
    """Return a list of violated unconditional invariants (empty list = OK)."""
    errors = []
    if set(targets) != set(ACTIONS):
        return ['per_action_targets must have exactly the five actions']
    for a in ACTIONS:
        if targets[a] not in (True, False, None):
            errors.append(f'{a}: label must be true/false/null')
    if set(mask) != set(ACTIONS) or mask != known_mask(targets):
        errors.append('known_mask does not match labels')
    if type(unknown) is not bool:
        errors.append('unknown must be boolean')
    if any(targets[a] is None for a in ACTIONS) and unknown is not True:
        errors.append('a null label requires unknown=true')
    if not isinstance(view, dict) or set(view) != {'actions', 'unknown'}:
        errors.append('contract_view must contain exactly actions and unknown')
    else:
        if 'unknown' in view['actions']:
            errors.append('"unknown" must not appear in actions')
        if len(set(view['actions'])) != len(view['actions']) or not set(view['actions']) <= set(ACTIONS):
            errors.append('contract actions must be unique values of the five actions')
        if view != contract_view(targets, unknown):
            errors.append('contract_view is not derived from labels/unknown')
    if forbidden is not None:
        if any(targets.get(a) is not False for a in forbidden):
            errors.append('forbidden_actions must be known-false labels')
    return errors


def to_contract_with_forbidden(targets, unknown):
    """Tri-state -> (actions, unknown, forbidden_actions). forbidden is a SOU-13 convention (SOU13-CONV-FORBIDDEN-ACTIONS)."""
    view = contract_view(targets, unknown)
    forbidden = [a for a in ACTIONS if targets[a] is False] if unknown else []
    return view['actions'], view['unknown'], forbidden


def from_contract_under_sou13_assumptions(actions, unknown, forbidden):
    """Contract view -> tri-state. Valid ONLY under assumptions SOU13-ASSUME-UNKNOWN-FROM-NULL and SOU13-CONV-FORBIDDEN-ACTIONS."""
    actions, forbidden = set(actions), set(forbidden)
    if actions & forbidden:
        raise AssumptionViolation('an action cannot be both present and forbidden')
    if not unknown and forbidden:
        raise AssumptionViolation('forbidden_actions is only used when unknown=true (SOU13-CONV-FORBIDDEN-ACTIONS)')
    if unknown and len(actions | forbidden) == len(ACTIONS):
        raise AssumptionViolation('unknown=true with every label known (unmodeled non-taxonomy effects) is outside SOU13-ASSUME-UNKNOWN-FROM-NULL')
    out = {}
    for a in ACTIONS:
        if a in actions:
            out[a] = True
        elif not unknown or a in forbidden:
            out[a] = False
        else:
            out[a] = None
    return out
