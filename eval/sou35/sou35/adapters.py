"""Thin, tested adapters onto frozen SOU-13 code (import only; nothing under eval/sou13 is edited).

Coupling notes (see tests/test_adapters.py):
  * `labels_from_execution` lives in sou13cp2.generate, whose import pulls sou13cp2.taxonomy/catalog. Those probe
    the consumed sealed directory at import time, so every import here re-runs the custody guard first.
  * `leakage.family_item` expects a CP2 taxonomy family dict; `to_leakage_family` builds exactly those fields
    from a SOU-35 declaration. The ('leakage_group', None) placeholder is dropped, as splits.leakage_groups does.
  * `splits.assign` is NOT used: it indexes the frozen SOU-13 BEHAVIOR_CLASSES / COVERAGE_STRATA and cannot take
    the SOU-35 `multimode` class. SOU-35 allocation lives in feasibility.py.
"""
import hashlib

from . import SOU13_ROOT, guard

DECL = 'declarative_semantics_execution'
INPUT_VALIDATION = 'input_validation'
CONTRACT_PATH = SOU13_ROOT.parents[1] / 'contract' / 'updated_contract2.md'


def _cp2():
    guard.check(SOU13_ROOT)
    from sou13cp2 import generate, identity, leakage, semantics, splits, taxonomy
    return {'generate': generate, 'identity': identity, 'leakage': leakage, 'semantics': semantics,
            'splits': splits, 'taxonomy': taxonomy}


# ---- interpreter, labels, hashing ----------------------------------------------------------------------------
def execute(program, args, world_spec=None):
    return _cp2()['semantics'].execute(program, args, world_spec)


def program_errors(program):
    return _cp2()['semantics'].program_errors(program)


def labels_from_execution(rec, semantics_sha):
    """(targets, unknown, label_evidence) exactly as SOU-13 CP2 derives them; mechanical, not a review."""
    return _cp2()['generate'].labels_from_execution(rec, semantics_sha)


def sha(x):
    from sou13.hashing import sha as _sha
    return _sha(x)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def lf_sha(path):
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def interpreter_sha():
    return lf_sha(SOU13_ROOT / 'sou13cp2' / 'semantics.py')


def compute_sha():
    return lf_sha(SOU13_ROOT / 'sou13cp2' / 'compute.py')


def contract():
    from sou13.cases import CONTRACT
    return {k: CONTRACT[k] for k in ('version', 'sha256', 'commit', 'blob')}


def contract_errors():
    """The reused SOU-13 contract binding must still describe the contract file in this checkout."""
    actual = lf_sha(CONTRACT_PATH)
    return [] if actual == contract()['sha256'] else [f'contract file sha256 {actual} != bound {contract()["sha256"]}']


# ---- input checks (SOU-10 §1.2 object-argument profile) ------------------------------------------------------
def input_errors(inp):
    from sou13.build import input_errors as f
    return f(inp)


def check_arguments(inp):
    from sou13.build import check_arguments as f
    return f(inp)


def definition_hash(inp):
    from sou13.build import definition_hash as f
    return f(inp)


# ---- identity / templates ---------------------------------------------------------------------------------------
def effect_profile_from_trace(trace):
    return _cp2()['identity'].effect_profile_from_trace(trace)


def event_action():
    return dict(_cp2()['taxonomy'].EVENT_ACTION)


def opaque_token():
    return _cp2()['taxonomy'].OPAQUE


def template_signature(schema, arg_keys, effect_profile, evidence_kind=DECL):
    return _cp2()['identity'].template_signature(schema, arg_keys, effect_profile, evidence_kind, ())


def shape_signature(schema, effect_profile, evidence_kind=DECL):
    return _cp2()['identity'].shape_signature(schema, effect_profile, evidence_kind, ())


def program_skeleton(program):
    return _cp2()['identity'].program_skeleton(program)


def slug(family_id):
    return family_id.split('.', 2)[2]


def to_leakage_family(decl):
    """CP2-taxonomy-shaped view of a SOU-35 declaration, sufficient for leakage.family_item."""
    ident = _cp2()['identity']
    descs = [d for d in (decl['descriptions'].get('honest'), decl['descriptions'].get('misleading')) if d]
    s = slug(decl['family_id'])
    return {'family_id': decl['family_id'], 'alias_group_id': 'ag35.' + s,
            'identities': [list(i) for i in decl['identities']], 'rejected_identities': [],
            'normalized_names': sorted({ident.normalized_name(t) for _, t in decl['identities']}),
            'descriptions': descs, 'near_duplicates': [],
            'templates': [{'template_id': t['template_id'], 'signature': t['signature']}
                          for t in decl['_templates']]}


def fingerprint(decl):
    """SOU-13 splits.family_fingerprint over the CP2-shaped view (identities, names, descriptions, template
    signatures, class, exposure): labels and case counts are excluded, so relabelling never moves a family."""
    fam = dict(to_leakage_family(decl), behavior_class=decl['behavior_class'], exposure=decl['exposure'])
    return _cp2()['splits'].family_fingerprint(fam)


def cross_split_errors(items):
    return _cp2()['leakage'].cross_split_errors(items)


def sou13_exports():
    """SOU-13 label-separated export helpers (model_input, label_row, LABEL_BEARING_KEYS), after the guard."""
    _cp2()
    from sou13cp2 import exports
    return exports


def leakage_item(fam):
    item = _cp2()['leakage'].family_item(fam, None, None)
    item['features'].discard(('leakage_group', None))
    return item


def components(items):
    return _cp2()['leakage'].components(items)


def splits_module():
    return _cp2()['splits']


# ---- novelty against the PUBLIC SOU-13 taxonomy -----------------------------------------------------------------
def sou13_public_families():
    tax = _cp2()['taxonomy']
    from sou13cp2 import restricted
    if restricted.available():  # belt and braces: the guard already refuses sealed checkouts
        raise guard.CustodyError('SOU-13 restricted declarations are loadable; refusing novelty check')
    return tax.families()


def novelty_errors(decls, sou13_fams=None):
    """A SOU-35 family must share no identity/server/name/description/template feature with any SOU-13 public
    family, and every shared field-name-insensitive template shape needs an adjudication in the declaration's
    `shape_reviews`; shape AND program skeleton equal is always a near-duplicate (SOU-13 owner rule 2026-10-11)."""
    sou13_fams = sou13_public_families() if sou13_fams is None else sou13_fams
    errors = []
    items = [leakage_item(f) for f in sou13_fams] + [leakage_item(to_leakage_family(d)) for d in decls]
    for comp in components(items):
        ours = [k for k in comp if k.startswith('family:f35.')]
        theirs = [k for k in comp if k.startswith('family:fam.')]
        if ours and theirs:
            errors.append(f'NOVELTY {ours} share identity features with SOU-13 {theirs[:3]}')
    sou13_shapes = {}
    for f in sou13_fams:
        for t in f['templates']:
            sou13_shapes.setdefault(t['shape_signature'], []).append(f)
    for d in decls:
        skel = program_skeleton(d['program'])
        reviews = d.get('shape_reviews', {})
        for t in d['_templates']:
            for other in sou13_shapes.get(t['shape_signature'], []):
                if other.get('program_skeleton') == skel:
                    errors.append(f'NEAR-DUPLICATE {d["family_id"]} template {t["template_id"]} has the shape and '
                                  f'program skeleton of SOU-13 {other["family_id"]}')
                elif other['family_id'] not in reviews:
                    errors.append(f'UNADJUDICATED {d["family_id"]} template {t["template_id"]} shares a template '
                                  f'shape with SOU-13 {other["family_id"]}; add a shape_reviews entry')
    return sorted(set(errors))
