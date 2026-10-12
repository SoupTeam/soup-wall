"""Loader for custodian-only test-family semantics (cp2_sealed/restricted/test_families.json).

The public repository contains NO declaration, program, argument pool or description of a test family.
When the restricted file is absent (any public copy), every function here returns empty results and the
pipeline runs in PUBLIC mode: it sees only train/validation/calibration families and takes split
assignments from the public manifest view."""
import copy
import functools
import json

from . import ROOT

RESTRICTED_FILE = 'cp2_sealed/restricted/test_families.json'
EXPOSURE = 'restricted_test'


@functools.lru_cache(maxsize=None)
def _load(root):
    p = root / RESTRICTED_FILE
    if not p.exists():
        return ()
    data = json.loads(p.read_text(encoding='utf-8'))
    if data.get('restricted_kind') != 'sou13_cp2_test_family_semantics':
        raise ValueError(f'{RESTRICTED_FILE}: unexpected content')
    return tuple(data['families'])


def available(root=ROOT):
    return bool(_load(root))


def declarations(root=ROOT):
    return [copy.deepcopy(f['declaration']) for f in _load(root)]


def catalog_entries(root=ROOT):
    return {f['declaration']['family_id']: copy.deepcopy(f['catalog']) for f in _load(root)}


def family_ids(root=ROOT):
    return sorted(f['declaration']['family_id'] for f in _load(root))
