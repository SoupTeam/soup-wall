"""Deterministic family-level split assignment and the DRAFT split manifest.

Unit of assignment = leakage group (connected component of the leakage graph over taxonomy families).
1. Exposure pin: groups containing CP1 cases (already shared with the team) or material derived from the
   v0.2 pilot (its held-out labels were seen) may only go to `train`.
2. Remaining groups are visited by behaviour class (scarcest class first, ties in BEHAVIOR_CLASSES order),
   then by sha256(salt|group_id).
   Each goes to the allowed split that (a) still lacks that behaviour class and has positive deficit, else
   (b) has the largest weight deficit against the target ratios; ties -> SPLITS order.
A DRAFT manifest is a pure function of (taxonomy, salt, ratios) and is regenerated on every build.

FROZEN manifests (explicit `freeze()` with an approval record) are AUTHORITATIVE: they are never
regenerated. Labels, review statuses, pending flags, open questions and case counts are not part of the
family fingerprint, so changing them can never move a family. Adding a family or changing a family's
leakage-relevant attributes requires an explicit append-only `amend()` that is checked for leakage and
never changes an existing assignment; removing a family requires a new manifest version.

Test families are custodian-only (restricted.py): exposure `restricted_test` pins them to test, and a
public family (exposure `none`) can never be assigned to test, because its semantics are public."""
import copy
import hashlib

from sou13.cases import CONTRACT
from sou13.hashing import sha

from . import VERSION
from .identity import normalized_description
from .leakage import components, cross_split_errors, family_item
from .taxonomy import BEHAVIOR_CLASSES, COVERAGE_STRATA, taxonomy_document

ALGORITHM = 'cp2-family-split-v3'
SPLITS = ('train', 'validation', 'calibration', 'test')
# Q-CP2-RATIOS: train is mostly CP1-pinned families; held-out splits need one family per coverage stratum.
DEFAULT_RATIOS = {'train': 0.34, 'validation': 0.22, 'calibration': 0.22, 'test': 0.22}
DEFAULT_SALT = 'sou13-cp2-phase2-2026-10-10'
ALLOWED_BY_EXPOSURE = {'none': ('train', 'validation', 'calibration'), 'cp1_shared': ('train',),
                       'v02_derived': ('train',), 'restricted_test': ('test',)}
STATUSES = ('DRAFT', 'FROZEN')


def family_fingerprint(fam):
    """Leakage-relevant identity of a family. Labels, statuses, pending flags, open questions and case
    counts are deliberately excluded: changing them must never reassign a family."""
    rejected = sorted(map(list, fam.get('rejected_identities', [])))
    # key present only when non-empty, so families without admission-test identities keep their fingerprint
    return sha({'identities': sorted(map(list, fam['identities'])), **({'rejected_identities': rejected} if rejected else {}),
                'names': sorted(fam['normalized_names']),
                'descriptions': sorted(filter(None, (normalized_description(d) for d in fam['descriptions']))),
                'template_signatures': sorted(t['signature'] for t in fam['templates']),
                'behavior_class': fam['behavior_class'], 'exposure': fam['exposure']})


class SplitError(ValueError):
    pass


def hash_key(salt, group_id):
    return hashlib.sha256(f'{salt}|{group_id}'.encode('utf-8')).hexdigest()


def leakage_groups(fams):
    """[(group_id, [family dicts])] from the leakage graph over families (no split known yet)."""
    by_key = {'family:' + f['family_id']: f for f in fams}
    items = []
    for f in fams:
        it = family_item(f, None, None)
        it['features'].discard(('leakage_group', None))  # groups are not declared yet
        items.append(it)
    out = []
    for comp in components(items):
        members = [by_key[k] for k in comp]
        out.append(('lg.' + members[0]['family_id'][len('fam.'):], members))
    return out


def assign(fams, salt=DEFAULT_SALT, ratios=None):
    ratios = dict(DEFAULT_RATIOS if ratios is None else ratios)
    if set(ratios) != set(SPLITS) or abs(sum(ratios.values()) - 1) > 1e-9 or min(ratios.values()) < 0:
        raise SplitError(f'ratios must cover {SPLITS} and sum to 1')
    groups = []
    for gid, members in leakage_groups(fams):
        allowed = set(SPLITS)
        for m in members:
            allowed &= set(ALLOWED_BY_EXPOSURE[m['exposure']])
        if not allowed:
            raise SplitError(f'{gid}: exposure constraints leave no admissible split')
        classes = sorted({m['behavior_class'] for m in members}, key=BEHAVIOR_CLASSES.index)
        strata = sorted({m['coverage_stratum'] for m in members}, key=COVERAGE_STRATA.index)
        groups.append({'leakage_group_id': gid, 'families': [m['family_id'] for m in members],
                       'behavior_classes': classes, 'coverage_strata': strata,
                       'coverage_eligible': all(m['coverage_eligible'] for m in members),
                       'exposure': sorted({m['exposure'] for m in members}),
                       'allowed_splits': [s for s in SPLITS if s in allowed],
                       'weight': sum(m['planned_cases'] for m in members), 'hash_key': hash_key(salt, gid)})
    total = sum(g['weight'] for g in groups)
    target = {s: ratios[s] * total for s in SPLITS}
    load = {s: 0 for s in SPLITS}
    present = {s: set() for s in SPLITS}

    def place(g, split, reason):
        g['split'], g['assignment_reason'] = split, reason
        load[split] += g['weight']
        if g['coverage_eligible']:
            present[split].update(g['coverage_strata'])

    for g in sorted(groups, key=lambda g: g['leakage_group_id']):
        if len(g['allowed_splits']) == 1:
            place(g, g['allowed_splits'][0], 'exposure_pin:' + '+'.join(g['exposure']))
    free = [g for g in groups if 'split' not in g]
    # eligible groups first; within them the scarcest coverage stratum first, so strata with few free groups
    # still reach every held-out split; ineligible (pending) groups are placed last by deficit only
    scarcity = {c: sum(g['coverage_strata'][0] == c for g in free if g['coverage_eligible']) for c in COVERAGE_STRATA}
    free.sort(key=lambda g: (not g['coverage_eligible'], scarcity[g['coverage_strata'][0]],
                             COVERAGE_STRATA.index(g['coverage_strata'][0]), g['hash_key']))
    for g in free:
        def score(s):
            deficit = target[s] - load[s]
            lacks = g['coverage_eligible'] and any(c not in present[s] for c in g['coverage_strata'])
            return (0 if (lacks and deficit > 0) else 1, -deficit, SPLITS.index(s))
        best = min(g['allowed_splits'], key=score)
        place(g, best, 'class_coverage_then_deficit' if score(best)[0] == 0 else 'deficit')
    return sorted(groups, key=lambda g: g['leakage_group_id']), {'target_weight': target, 'assigned_weight': load,
                                                                   'total_weight': total}


def build_manifest(fams, salt=DEFAULT_SALT, ratios=None):
    fams = sorted(fams, key=lambda f: f['family_id'])  # input order must not matter
    tax = taxonomy_document(fams)
    groups, totals = assign(fams, salt, ratios)
    fam_split = {f: g['split'] for g in groups for f in g['families']}
    fam_group = {f: g['leakage_group_id'] for g in groups for f in g['families']}
    templates = {t['template_id']: fam_split[f['family_id']] for f in fams for t in f['templates']}
    body = {
        'manifest_kind': 'sou13_cp2_family_split_manifest',
        'status': 'DRAFT', 'frozen': False, 'freeze_record': None, 'amendments': [],
        'freeze_policy': 'DRAFT: regenerated on every build. Only an explicit freeze() with an approval record makes '
                         'the persisted manifest authoritative; afterwards only append-only amend() may add families.',
        'family_fingerprints': {f['family_id']: family_fingerprint(f) for f in fams},
        'cp2_version': VERSION, 'algorithm': ALGORITHM, 'salt': salt,
        'ratios': dict(DEFAULT_RATIOS if ratios is None else ratios),
        'exposure_policy': {k: list(v) for k, v in ALLOWED_BY_EXPOSURE.items()},
        'taxonomy_version': tax['taxonomy_version'], 'taxonomy_sha256': tax['taxonomy_sha256'],
        'contract': {k: CONTRACT[k] for k in ('version', 'sha256', 'commit', 'blob')},
        'groups': groups, 'family_split': fam_split, 'family_group': fam_group,
        'alias_group_split': {'ag.' + f[len('fam.'):]: s for f, s in fam_split.items()},
        'template_split': templates,
        'weights': totals,
        'split_summary': {s: {'groups': sum(g['split'] == s for g in groups),
                              'families': sum(fam_split[f] == s for f in fam_split),
                              'planned_cases': totals['assigned_weight'][s],
                              'behavior_classes': sorted({c for g in groups if g['split'] == s
                                                          for c in g['behavior_classes']},
                                                         key=BEHAVIOR_CLASSES.index)} for s in SPLITS},
        'labels_in_manifest': False,
    }
    return {**body, 'manifest_sha256': sha(body)}


def _sign(m):
    body = {k: v for k, v in m.items() if k != 'manifest_sha256'}
    return {**body, 'manifest_sha256': sha(body)}


def is_frozen(manifest):
    return manifest.get('status') == 'FROZEN' and manifest.get('frozen') is True


def freeze(manifest, fams, *, approved_by, approved_at, decision_ref):
    """Explicitly freeze a validated DRAFT manifest. All approval fields are mandatory; nothing here is
    called by the build pipeline."""
    if not (approved_by and approved_at and decision_ref):
        raise SplitError('freeze requires approved_by, approved_at and decision_ref')
    if is_frozen(manifest):
        raise SplitError('manifest is already frozen')
    errors = manifest_errors(manifest, fams)
    if errors:
        raise SplitError(f'cannot freeze an invalid manifest: {errors}')
    m = copy.deepcopy(manifest)
    m['status'], m['frozen'] = 'FROZEN', True
    m['freeze_record'] = {'approved_by': approved_by, 'approved_at': approved_at, 'decision_ref': decision_ref,
                          'frozen_assignment': dict(sorted(m['family_split'].items())),
                          'frozen_assignment_sha256': sha(dict(sorted(m['family_split'].items()))),
                          'frozen_fingerprints': dict(sorted(m['family_fingerprints'].items()))}
    return _sign(m)


def _linked_split(fam, fams_by_id, assignment):
    """Splits of already-assigned families that share a leakage feature with `fam`."""
    mine = family_item(fam, None, None)['features'] - {('leakage_group', None)}
    out = set()
    for fid, split in assignment.items():
        other = fams_by_id.get(fid)
        if other is not None and other['family_id'] != fam['family_id']:
            if mine & (family_item(other, None, None)['features'] - {('leakage_group', None)}):
                out.add(split)
    return out


def assignment_leak_errors(fams, assignment, groups):
    items = [family_item(f, assignment[f['family_id']], groups.get(f['family_id'], 'lg.' + f['family_id'][4:]))
             for f in fams if f['family_id'] in assignment]
    for it in items:
        it['features'] = {x for x in it['features'] if x[0] != 'leakage_group'}
    return cross_split_errors(items)


def amend(manifest, fams, *, add=(), acknowledge_changed=(), approved_by, reason):
    """Append-only amendment of a FROZEN manifest. New families are assigned without moving any existing
    family (to the split of a linked family if they share a leakage feature, else by deficit among the
    splits their exposure allows). Changed families keep their split and are accepted only if the frozen
    assignment stays leakage-free. Never removes or moves a family."""
    if not is_frozen(manifest):
        raise SplitError('amend() applies to FROZEN manifests only; DRAFT manifests are regenerated')
    if not (approved_by and reason):
        raise SplitError('amend requires approved_by and reason')
    by_id = {f['family_id']: f for f in fams}
    m = copy.deepcopy(manifest)
    assignment = m['family_split']
    load = {s: 0 for s in SPLITS}
    for f, s in assignment.items():
        load[s] += by_id[f]['planned_cases'] if f in by_id else 0
    total = sum(load.values()) + sum(by_id[f]['planned_cases'] for f in add)
    record = {'approved_by': approved_by, 'reason': reason, 'added': {}, 'acknowledged_changes': {},
              'prior_manifest_sha256': manifest['manifest_sha256']}
    for fid in sorted(add):
        if fid in assignment:
            raise SplitError(f'{fid} is already assigned; amendments never move families')
        fam = by_id[fid]
        allowed = set(ALLOWED_BY_EXPOSURE[fam['exposure']])
        linked = _linked_split(fam, by_id, assignment)
        if len(linked) > 1 or (linked and not linked <= allowed):
            raise SplitError(f'{fid} links families in {sorted(linked)}; cannot be added without leakage')
        split = next(iter(linked)) if linked else min(
            sorted(allowed, key=SPLITS.index), key=lambda s: -(m['ratios'][s] * total - load[s]))
        assignment[fid] = split
        m['family_group'][fid] = 'lg.' + fid[len('fam.'):]
        m['family_fingerprints'][fid] = family_fingerprint(fam)
        load[split] += fam['planned_cases']
        record['added'][fid] = split
    for fid in sorted(acknowledge_changed):
        if fid not in assignment:
            raise SplitError(f'{fid} is not assigned')
        m['family_fingerprints'][fid] = family_fingerprint(by_id[fid])
        record['acknowledged_changes'][fid] = m['family_fingerprints'][fid]
    leaks = assignment_leak_errors([by_id[f] for f in assignment if f in by_id], assignment, m['family_group'])
    if leaks:
        raise SplitError(f'amendment would create cross-split leakage: {leaks[:3]}')
    m['amendments'].append(record)
    return _sign(m)


def frozen_errors(manifest, fams):
    """Compatibility of the current taxonomy with an authoritative FROZEN manifest (no regeneration)."""
    e = []
    fr = manifest.get('freeze_record') or {}
    if not (fr.get('approved_by') and fr.get('approved_at') and fr.get('decision_ref')):
        e.append('frozen manifest without a complete approval record')
    frozen_assignment = fr.get('frozen_assignment', {})
    if sha(dict(sorted(frozen_assignment.items()))) != fr.get('frozen_assignment_sha256'):
        e.append('frozen_assignment altered after freeze')
    split = manifest['family_split']
    for f, s in frozen_assignment.items():
        if split.get(f) != s:
            e.append(f'{f}: frozen assignment {s} changed to {split.get(f)}')
    added = {f: s for a in manifest.get('amendments', []) for f, s in a['added'].items()}
    for f, s in split.items():
        if f not in frozen_assignment and added.get(f) != s:
            e.append(f'{f}: assignment not covered by the freeze record or an amendment')
    by_id = {f['family_id']: f for f in fams}
    for f in sorted(set(split) - set(by_id)):
        e.append(f'{f}: family removed from the taxonomy; a frozen manifest requires a new version to retire it')
    for f in sorted(set(by_id) - set(split)):
        e.append(f'{f}: new family not in the frozen manifest; add it explicitly with amend()')
    for f in sorted(set(by_id) & set(split)):
        if family_fingerprint(by_id[f]) != manifest['family_fingerprints'].get(f):
            e.append(f'{f}: leakage-relevant attributes changed since freeze; requires amend(acknowledge_changed=...)')
        if split[f] not in ALLOWED_BY_EXPOSURE[by_id[f]['exposure']]:
            e.append(f'{f}: exposure {by_id[f]["exposure"]} forbids split {split[f]}')
    e += assignment_leak_errors([by_id[f] for f in split if f in by_id], split, manifest['family_group'])
    return e


def manifest_errors(manifest, fams):
    """Integrity of a stored manifest against the taxonomy (empty list = OK). DRAFT manifests must equal the
    deterministic rebuild; FROZEN manifests are authoritative and are checked for compatibility only."""
    e = []
    body = {k: v for k, v in manifest.items() if k != 'manifest_sha256'}
    if manifest.get('manifest_sha256') != sha(body):
        e.append('manifest_sha256 does not match manifest content (hand edit?)')
    if manifest.get('status') not in STATUSES or (manifest.get('status') == 'FROZEN') != (manifest.get('frozen') is True):
        e.append('status/frozen inconsistent')
    if manifest.get('labels_in_manifest') is not False:
        e.append('manifest must not carry labels')
    if is_frozen(manifest):
        return e + frozen_errors(manifest, fams)
    if manifest.get('freeze_record') is not None or manifest.get('amendments'):
        e.append('a DRAFT manifest cannot carry a freeze record or amendments')
    try:
        rebuilt = build_manifest(fams, manifest.get('salt', ''), manifest.get('ratios'))
    except SplitError as exc:
        return e + [f'cannot rebuild manifest: {exc}']
    if rebuilt != manifest:
        diff = sorted(k for k in set(rebuilt) | set(manifest) if rebuilt.get(k) != manifest.get(k))
        e.append(f'manifest is not the deterministic output of (taxonomy, salt, ratios); differing keys: {diff}')
    fam_ids = {f['family_id'] for f in fams}
    listed = [f for g in manifest.get('groups', []) for f in g['families']]
    if sorted(listed) != sorted(fam_ids) or len(listed) != len(set(listed)):
        e.append('groups must partition the taxonomy families exactly once')
    for g in manifest.get('groups', []):
        if g.get('split') not in g.get('allowed_splits', []):
            e.append(f"{g['leakage_group_id']}: split {g.get('split')} violates exposure policy {g.get('allowed_splits')}")
        for f in g['families']:
            if manifest['family_split'].get(f) != g['split'] or manifest['family_group'].get(f) != g['leakage_group_id']:
                e.append(f'{f}: family_split/family_group disagree with its group')
    by_id = {f['family_id']: f for f in fams}
    for f, s in manifest.get('family_split', {}).items():
        if f in by_id:
            allowed = ALLOWED_BY_EXPOSURE[by_id[f]['exposure']]
            if s not in allowed:
                e.append(f'{f}: exposure {by_id[f]["exposure"]} forbids split {s}')
    return e


# ---- public view (no test family is named) -----------------------------------------------------------------
def public_view(manifest, fams, commitments):
    """Manifest view safe for public handoff: train/validation/calibration families with their assignment and
    fingerprints; test only as counts and SHA-256 commitments to the restricted materials."""
    public_ids = {f['family_id'] for f in fams if f['exposure'] != 'restricted_test'}
    test_ids = [f for f, s in manifest['family_split'].items() if s == 'test']
    if public_ids & set(test_ids):
        raise SplitError('a public family is assigned to test')
    by_id = {f['family_id']: f for f in fams}
    fr = manifest.get('freeze_record')
    view = {
        'manifest_kind': 'sou13_cp2_split_manifest_PUBLIC_VIEW', 'status': manifest['status'],
        'frozen': manifest['frozen'], 'algorithm': manifest['algorithm'], 'ratios': manifest['ratios'],
        'exposure_policy': manifest['exposure_policy'], 'contract': manifest['contract'],
        'freeze_record': None if fr is None else {k: fr[k] for k in ('approved_by', 'approved_at', 'decision_ref')},
        'family_split': {f: s for f, s in sorted(manifest['family_split'].items()) if f in public_ids},
        'family_group': {f: g for f, g in sorted(manifest['family_group'].items()) if f in public_ids},
        'family_fingerprints': {f: p for f, p in sorted(manifest['family_fingerprints'].items()) if f in public_ids},
        'test': {'families': len(test_ids), 'cases': sum(by_id[f]['planned_cases'] for f in test_ids if f in by_id),
                 'identities': 'withheld (restricted custodian package)'},
        'commitments': commitments, 'labels_in_manifest': False}
    return _sign(view)


def public_view_errors(view, public_fams):
    """Checks available without restricted data (public mode)."""
    e = []
    body = {k: v for k, v in view.items() if k != 'manifest_sha256'}
    if view.get('manifest_sha256') != sha(body):
        e.append('public view sha256 mismatch (hand edit?)')
    for f in public_fams:
        fid = f['family_id']
        if fid not in view['family_split']:
            e.append(f'{fid}: public family missing from the manifest view')
        elif view['family_fingerprints'].get(fid) != family_fingerprint(f):
            e.append(f'{fid}: changed since the manifest was built (rebuild/amend in full mode)')
        elif view['family_split'][fid] == 'test':
            e.append(f'{fid}: public family assigned to test')
    for fid in sorted(set(view['family_split']) - {f['family_id'] for f in public_fams}):
        e.append(f'{fid}: listed in the view but absent from the public taxonomy')
    if view.get('labels_in_manifest') is not False or not view.get('commitments'):
        e.append('public view must carry commitments and no labels')
    return e
