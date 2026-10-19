"""Versioned, family-disjoint SOU-35 split manifest (restricted FULL manifest + PUBLIC view).

  build_draft     test families come ONLY from a drawn custody state (verified against its salted commitment);
                  the remaining whole leakage groups go to train/validation/calibration by a deterministic search
                  ordered by sha256(salt|group) (SOU-13 splits.hash_key). Requirements are recorded, never relaxed.
  manifest_errors digest, partition, leakage across splits, coverage, counts, fingerprints, custody binding; a DRAFT
                  must equal its deterministic rebuild; a FROZEN manifest must match its freeze record.
  freeze          requires custody_accepted and an explicit approval record (approved_by/approved_at/decision_ref).
  public_view     development families only; the test split appears as counts and commitments.

The FULL manifest names test families: it is custodian/owner material for the ignored sealed/ workspace only.
Amendment of a frozen manifest is not supported: any change requires a new manifest version."""
import copy

from . import adapters, custody, feasibility, records as record_validation, rulings

MANIFEST_VERSION = 'sou35-manifest-v2'  # v1 cannot be upgraded in-place
DEV_SPLITS = ('train', 'validation', 'calibration')


class ManifestError(ValueError):
    pass


def _sign(body):
    body = {k: v for k, v in body.items() if k != 'manifest_sha256'}
    return {**body, 'manifest_sha256': adapters.sha(body)}


def _groups(records):
    out = {}
    for r in records:
        out.setdefault(r['leakage_group_id'], set()).add(r['family_id'])
    return {g: sorted(f) for g, f in out.items()}


def _profile(requirements):
    return 'full' if requirements == feasibility.default_requirements() else 'custom'


def build_draft(decls, records, custody_state, test_families, nonce, counts, requirements, salt, *, rulings_register):
    ledger, _ = rulings.validate(rulings_register, decls, records)
    if ledger is None:
        raise ManifestError('semantic rulings register is missing, invalid or out of scope')
    if record_validation.dataset_errors(records, decls):
        raise ManifestError('candidate records failed validation')
    if custody_state.get('rulings_sha256') != rulings.digest(rulings_register):
        raise ManifestError('custody commitment is not bound to the semantic rulings register')
    if custody_state.get('state') not in ('drawn', 'custody_accepted'):
        raise ManifestError('test families must come from a drawn custody state')
    if not custody.verify_test_set(custody_state, test_families, nonce):
        raise ManifestError('test families do not open the custody test-set commitment')
    if custody.rule_digest(requirements, counts) != custody_state['rule_digest'] or \
            custody.pool_digest(decls) != custody_state['pool_digest']:
        raise ManifestError('pool or split rule differs from the custody declaration')
    groups = _groups(records)
    fam_group = {f: g for g, fs in groups.items() for f in fs}
    test_groups = {fam_group[f] for f in test_families}
    if sorted(f for g in test_groups for f in groups[g]) != sorted(test_families):
        raise ManifestError('test families must form whole leakage groups')
    table = feasibility.group_table(records, ledger)
    allowed = {g: (('test',) if g in test_groups else DEV_SPLITS) for g in groups}
    order = sorted(groups, key=lambda g: (adapters.splits_module().hash_key(salt, g), g))
    alloc = feasibility.find_allocation(table, requirements, counts, allowed, order)
    if alloc is None:
        raise ManifestError('IMPOSSIBLE: no allocation of the remaining groups meets the recorded requirements')
    fam_split = {f: alloc[fam_group[f]] for f in sorted(fam_group)}
    by_split = {s: [f for f, x in fam_split.items() if x == s] for s in feasibility.SPLITS}
    body = {
        'manifest_kind': 'sou35_family_split_manifest', 'manifest_version': MANIFEST_VERSION,
        'status': 'DRAFT', 'frozen': False, 'freeze_record': None,
        'salt': salt, 'counts': dict(counts),
        'requirements': {s: sorted(r) for s, r in requirements.items()}, 'requirements_profile': _profile(requirements),
        'pool_digest': custody_state['pool_digest'],
        'record_inventory_sha256': record_inventory_digest(records),
        'rulings_sha256': rulings.digest(rulings_register),
        'custody': {k: custody_state[k] for k in ('custodian', 'commitment', 'test_set_commitment', 'rule_digest', 'rulings_sha256')},
        'family_split': fam_split, 'family_group': {f: fam_group[f] for f in sorted(fam_group)},
        'family_fingerprints': {d['family_id']: adapters.fingerprint(d) for d in sorted(decls, key=lambda d: d['family_id'])},
        'split_summary': {s: {'families': len(by_split[s]),
                              'records': sum(r['family_id'] in set(by_split[s]) for r in records)}
                          for s in feasibility.SPLITS},
        'contract': adapters.contract(), 'labels_in_manifest': False,
    }
    return _sign(body)


def record_inventory_digest(records):
    """Pin every case, including original arguments, annotation and effect evidence."""
    return adapters.sha([{'id': r['id'], 'row_sha256': adapters.sha(r)}
                         for r in sorted(records, key=lambda r: r['id'])])


def _requirements(m):
    return {s: frozenset(r) for s, r in m['requirements'].items()}


def manifest_errors(m, decls, records, custody_state, test_families=None, nonce=None, *, rulings_register=None):
    """Only a custodian with the complete test proof and ruling register can validate a manifest."""
    e = []
    if not isinstance(m, dict):
        return ['manifest is not an object']
    ledger, _ = rulings.validate(rulings_register, decls, records)
    if ledger is None:
        e.append('missing, invalid or out-of-scope semantic rulings register')
    elif m.get('rulings_sha256') != rulings.digest(rulings_register) or \
            custody_state.get('rulings_sha256') != rulings.digest(rulings_register):
        e.append('semantic rulings digest differs from manifest/custody commitment')
    if test_families is None or nonce is None:
        e.append('custodian test-set proof is mandatory')
    if record_validation.dataset_errors(records, decls):
        e.append('candidate record validation failed')
    if m.get('record_inventory_sha256') != record_inventory_digest(records):
        e.append('record inventory/source/evidence differs from frozen manifest')
    if m.get('manifest_sha256') != adapters.sha({k: v for k, v in m.items() if k != 'manifest_sha256'}):
        e.append('manifest_sha256 does not match the manifest content (tampered?)')
    if m.get('manifest_kind') != 'sou35_family_split_manifest' or m.get('manifest_version') != MANIFEST_VERSION:
        e.append('unknown manifest kind or version')
    if (m.get('status') == 'FROZEN') != (m.get('frozen') is True) or m.get('status') not in ('DRAFT', 'FROZEN'):
        e.append('status/frozen inconsistent')
    if m.get('labels_in_manifest') is not False:
        e.append('manifest must not carry labels')
    by_id = {d['family_id']: d for d in decls}
    split = m.get('family_split', {})
    if set(split) != set(by_id):
        e.append('family_split must partition exactly the declared families')
        return e
    groups = _groups(records)
    for g, fams in groups.items():
        if len({split[f] for f in fams}) != 1:
            e.append(f'leakage group {g} is split across {sorted({split[f] for f in fams})}')
        if any(m['family_group'].get(f) != g for f in fams):
            e.append(f'family_group disagrees with the leakage graph for {g}')
    items = [dict(adapters.leakage_item(adapters.to_leakage_family(d)), split=split[f]) for f, d in sorted(by_id.items())]
    e += adapters.cross_split_errors(items)
    for f, d in by_id.items():
        if m['family_fingerprints'].get(f) != adapters.fingerprint(d):
            e.append(f'{f}: leakage-relevant attributes changed since the manifest was built')
    count = {s: sum(v == s for v in split.values()) for s in feasibility.SPLITS}
    if count != m['counts']:
        e.append(f'split family counts {count} differ from recorded counts {m["counts"]}')
    req = _requirements(m)
    for s in feasibility.SPLITS:
        # Fail closed: an invalid register supplies no coverage at all (never the raw, unfiltered features).
        feats = set().union(*((feasibility.record_features(r, ledger) if ledger else set())
                              for r in records if split[r['family_id']] == s)) \
            if any(split[r['family_id']] == s for r in records) else set()
        missing = req[s] - feats
        if missing:
            e.append(f'{s}: coverage requirement not met: {sorted(missing)}')
    if m.get('requirements_profile') != _profile(req):
        e.append('requirements_profile does not describe the recorded requirements')
    if custody.public_state_errors(custody_state):
        e.append('custody state malformed')
    elif {k: custody_state.get(k) for k in m['custody']} != m['custody'] or \
            custody_state['pool_digest'] != m['pool_digest']:
        e.append('manifest is not bound to this custody state')
    if test_families is not None and nonce is not None:
        if sorted(f for f, s in split.items() if s == 'test') != sorted(test_families) or \
                not custody.verify_test_set(custody_state, test_families, nonce):
            e.append('test split is not the committed custody draw')
    if m.get('status') == 'DRAFT':
        if m.get('freeze_record') is not None:
            e.append('a DRAFT manifest cannot carry a freeze record')
        if test_families is not None and nonce is not None and not e:
            rebuilt = build_draft(decls, records, custody_state, test_families, nonce, m['counts'], req, m['salt'], rulings_register=rulings_register)
            if rebuilt != m:
                e.append('DRAFT manifest is not the deterministic rebuild')
    else:
        fr = m.get('freeze_record') or {}
        if not all(isinstance(fr.get(k), str) and fr[k].strip() for k in ('approved_by', 'approved_at', 'decision_ref')):
            e.append('frozen manifest without a complete approval record')
        if fr.get('frozen_assignment') != split or fr.get('frozen_assignment_sha256') != adapters.sha(split):
            e.append('assignment changed after freeze')
        if custody_state.get('state') != 'custody_accepted':
            e.append('frozen manifest requires custody_accepted')
    return e


def freeze(m, decls, records, custody_state, test_families, nonce, *, rulings_register, approved_by, approved_at, decision_ref):
    if not all(isinstance(v, str) and v.strip() for v in (approved_by, approved_at, decision_ref)):
        raise ManifestError('freeze requires approved_by, approved_at and decision_ref')
    if rulings.is_ai_identity(approved_by):
        raise ManifestError('an AI-assisted annotator cannot approve a freeze')
    if m.get('status') != 'DRAFT':
        raise ManifestError('only a DRAFT manifest can be frozen')
    if custody_state.get('state') != 'custody_accepted':
        raise ManifestError('custody must be accepted by the named custodian before freezing')
    errors = manifest_errors(m, decls, records, custody_state, test_families, nonce, rulings_register=rulings_register)
    if errors:
        raise ManifestError(f'cannot freeze an invalid manifest: {errors}')
    out = copy.deepcopy(m)
    out['status'], out['frozen'] = 'FROZEN', True
    out['freeze_record'] = {'approved_by': approved_by, 'approved_at': approved_at, 'decision_ref': decision_ref,
                            'frozen_assignment': dict(m['family_split']),
                            'frozen_assignment_sha256': adapters.sha(m['family_split'])}
    return _sign(out)


def public_view(m, decls, records, custody_state, test_families, nonce, *, rulings_register):
    """No test family is named; refuse an unverified full manifest."""
    errors = manifest_errors(m, decls, records, custody_state, test_families, nonce, rulings_register=rulings_register)
    if errors:
        raise ManifestError('public view refused: unverified full manifest/custody proof')
    dev = {f: s for f, s in m['family_split'].items() if s != 'test'}
    fr = m.get('freeze_record')
    return _sign({
        'manifest_kind': 'sou35_family_split_manifest_PUBLIC_VIEW', 'manifest_version': m['manifest_version'],
        'status': m['status'], 'frozen': m['frozen'], 'full_manifest_sha256': m['manifest_sha256'],
        'freeze_record': None if fr is None else {k: fr[k] for k in ('approved_by', 'approved_at', 'decision_ref')},
        'counts': m['counts'], 'requirements': m['requirements'], 'requirements_profile': m['requirements_profile'],
        'family_split': dev, 'family_group': {f: m['family_group'][f] for f in dev},
        'family_fingerprints': {f: m['family_fingerprints'][f] for f in dev},
        'test': {'families': m['split_summary']['test']['families'], 'records': m['split_summary']['test']['records'],
                 'identities': 'withheld (sealed custody)'},
        'custody': {k: m['custody'][k] for k in ('commitment', 'test_set_commitment')},
        'labels_in_manifest': False})


def public_view_errors(view, forbidden=()):
    """Checks available without restricted data; `forbidden` = private strings (owner mode) that must not appear."""
    import json
    e = []
    if view.get('manifest_sha256') != adapters.sha({k: v for k, v in view.items() if k != 'manifest_sha256'}):
        e.append('public view sha256 mismatch (tampered?)')
    if 'test' in view.get('family_split', {}).values():
        e.append('public view assigns a named family to test')
    if view.get('labels_in_manifest') is not False or not view.get('custody', {}).get('test_set_commitment'):
        e.append('public view must carry custody commitments and no labels')
    text = json.dumps(view)
    if any(t in text for t in forbidden):
        e.append('public view contains restricted test material')
    return e
