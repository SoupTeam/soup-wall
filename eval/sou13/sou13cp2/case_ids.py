"""Non-predictable, stable case ids for new CP2 records (audit finding F1).

The former id was 'S13C2-' + sha256(family_id|index)[:10]: anyone who knew or guessed a family id could recompute it,
so ids in public exports and evaluation inputs disclosed the family (and with it the behaviour class/label).

Now every id is 'S13C2-' + 32 hex chars (128 bits) from the OS CSPRNG, allocated ONCE and persisted:
  cp2/ids/case_ids.PUBLIC.json           ids of train/validation/calibration cases (their family is public anyway
                                         through the label exports)
  cp2_sealed/ids/case_ids.TEST.json      ids of test cases (custodian only)
Keys are 'family_id|case_index'. Builds never allocate silently: a missing id is an error; allocation is an
explicit step (scripts_cp2/allocate_case_ids.py) that only adds missing keys and never rewrites existing ones."""
import functools
import hashlib
import json
import re
import secrets

from . import ROOT, restricted

PUBLIC_MAP = 'cp2/ids/case_ids.PUBLIC.json'
TEST_MAP = 'cp2_sealed/ids/case_ids.TEST.json'
ID_RE = re.compile(r'^S13C2-[0-9A-F]{32}$')
MAP_KIND = 'sou13_cp2_case_id_map'


class CaseIdError(ValueError):
    pass


def legacy_case_id(family_id, i):
    """The former, PREDICTABLE scheme. Kept only for the regression attack (never used to assign ids)."""
    return 'S13C2-' + hashlib.sha256(f'{family_id}|{i}'.encode('utf-8')).hexdigest()[:10].upper()


def key(family_id, i):
    return f'{family_id}|{i}'


def _read(rel, root, retired=False):
    p = root / rel
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding='utf-8'))
    if data.get('map_kind') != MAP_KIND:
        raise CaseIdError(f'{rel}: unexpected content')
    return data.get('retired_ids', {}) if retired else data['ids']


@functools.lru_cache(maxsize=None)
def _maps(root):
    return _read(PUBLIC_MAP, root), (_read(TEST_MAP, root) if restricted.available(root) else {})


def clear_cache():
    _maps.cache_clear()


def case_id(family_id, i, root=ROOT):
    public, test = _maps(root)
    k = key(family_id, i)
    cid = (test if family_id in restricted.family_ids(root) else public).get(k)
    if cid is None:
        raise CaseIdError(f'no persisted case id for {k}; allocate explicitly with scripts_cp2/allocate_case_ids.py')
    return cid


def _write(rel, ids, root, note, retired=None):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {'map_kind': MAP_KIND, 'note': note, 'ids': dict(sorted(ids.items()))}
    if retired:  # key present only when non-empty, so maps without retirements keep their bytes
        body['retired_ids'] = dict(sorted(retired.items()))
    p.write_text(json.dumps(body, indent=1, sort_keys=True) + '\n', encoding='utf-8')


def _all_retired(root):
    return {**_read(PUBLIC_MAP, root, retired=True), **_read(TEST_MAP, root, retired=True)}


def retire(family_ids, rel, root=ROOT):
    """Move the ids of withdrawn families from `ids` to `retired_ids` of the same map (explicit, logged step).
    Retired ids are never deleted and never re-issued; the families must no longer exist. Returns the count moved."""
    if rel not in (PUBLIC_MAP, TEST_MAP):
        raise CaseIdError(f'unknown map {rel}')
    p = root / rel
    data = json.loads(p.read_text(encoding='utf-8'))
    ids, retired = dict(data['ids']), dict(data.get('retired_ids', {}))
    moved = {k: v for k, v in ids.items() if k.rsplit('|', 1)[0] in set(family_ids)}
    if set(retired) & set(moved):
        raise CaseIdError('a key is already retired')
    for k in moved:
        retired[k] = ids.pop(k)
    _write(rel, ids, root, data['note'], retired)
    clear_cache()
    return len(moved)


def allocate(needed_keys, root=ROOT):
    """Add CSPRNG ids for keys that have none. Existing ids are never changed. Returns the number added."""
    test_fams = set(restricted.family_ids(root))
    public, test = (dict(m) for m in (_read(PUBLIC_MAP, root), _read(TEST_MAP, root)))
    retired = {'pub': _read(PUBLIC_MAP, root, retired=True), 'test': _read(TEST_MAP, root, retired=True)}
    used = set(public.values()) | set(test.values()) | set(retired['pub'].values()) | set(retired['test'].values())
    added = 0
    for k in sorted(needed_keys):
        fid, i = k.rsplit('|', 1)
        target = test if fid in test_fams else public
        if k in target:
            continue
        while True:
            cid = 'S13C2-' + secrets.token_hex(16).upper()
            if cid not in used and cid != legacy_case_id(fid, int(i)):
                break
        target[k] = cid
        used.add(cid)
        added += 1
    _write(PUBLIC_MAP, public, root, 'Random 128-bit ids of public (train/validation/calibration) CP2 cases.',
           retired['pub'])
    if test_fams:
        _write(TEST_MAP, test, root, 'RESTRICTED: random 128-bit ids of test cases (custodian only).',
               retired['test'])
    clear_cache()
    return added


def map_errors(root=ROOT):
    """Structural checks of the persisted maps (empty list = OK)."""
    e = []
    public, test = _maps(root)
    test_fams = set(restricted.family_ids(root))
    for name, ids in (('public', public), ('test', test)):
        for k, cid in ids.items():
            fid, i = k.rsplit('|', 1)
            if not ID_RE.match(cid):
                e.append(f'{name} map: {k} has a malformed id')
            if cid == legacy_case_id(fid, int(i)):
                e.append(f'{name} map: {k} uses the predictable legacy id')
            if (fid in test_fams) != (name == 'test'):
                e.append(f'{name} map: {k} is in the wrong map (test ids must stay in the restricted map)')
    if len(set(public.values()) | set(test.values())) != len(public) + len(test):
        e.append('case ids are not unique')
    retired = _all_retired(root)
    if set(retired.values()) & (set(public.values()) | set(test.values())):
        e.append('a retired case id was re-issued')
    live_fams = {k.rsplit('|', 1)[0] for k in list(public) + list(test)}
    if live_fams & {k.rsplit('|', 1)[0] for k in retired}:
        e.append('a family has both live and retired case ids')
    return e
