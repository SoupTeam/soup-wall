"""Release privacy gate: no git-visible file may carry private candidate-pool material.

With the private workspace present (owner checkout), every family id/slug, identity, description, mechanism, long
argument string, case id and seed is extracted from it and searched for in every file git could publish under
eval/sou35 and docs/benchmarks/sou35. Without the workspace (public checkout) the test skips with a named reason."""
import json
import subprocess
import unittest

from _util import ROOT

PRIVATE = ROOT / 'private'
REPO = ROOT.parents[1]
PUBLIC_DIRS = ('eval/sou35', 'docs/benchmarks/sou35')
MIN_ARG_LEN = 12  # shorter argument strings ('api', 'viewer') are too generic to identify a family


def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)


def private_tokens():
    tokens = set()
    for p in sorted((PRIVATE / 'pool').glob('*.json')):
        d = json.loads(p.read_text(encoding='utf-8'))
        tokens |= {d['family_id'], d['family_id'].split('.', 2)[2], d['mechanism']}
        tokens |= {x for ident in d['identities'] for x in ident}
        tokens |= {v for v in d['descriptions'].values() if v}
        tokens |= {s for c in d['cases'] + d['technical_error_cases'] for s in _strings(c['raw_arguments'])
                   if len(s) >= MIN_ARG_LEN}
    ids = PRIVATE / 'ids' / 'id_map.json'
    if ids.exists():
        tokens |= set(json.loads(ids.read_text(encoding='utf-8')).values())
    seeds = PRIVATE / 'seeds.json'
    if seeds.exists():
        tokens |= {str(v) for v in json.loads(seeds.read_text(encoding='utf-8')).values()}
    return tokens


def publishable_files():
    out = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '--', *PUBLIC_DIRS],
                         cwd=REPO, capture_output=True, text=True, check=True).stdout.split('\n')
    return [REPO / f for f in out if f]


class ReleasePrivacy(unittest.TestCase):
    def test_private_workspace_is_never_publishable(self):
        for f in publishable_files():
            self.assertNotIn('private', f.relative_to(REPO).parts, f)
            self.assertNotIn('sealed', f.relative_to(REPO).parts, f)
            self.assertFalse(f.suffix in ('.jsonl', '.zip', '.csv', '.sig'), f)

    def test_no_private_token_in_publishable_files(self):
        if not (PRIVATE / 'pool').is_dir():
            self.skipTest('PRIVATE ARTIFACT MISSING: eval/sou35/private/pool (public checkout)')
        tokens = private_tokens()
        self.assertGreater(len(tokens), 0)
        leaks = []
        for f in publishable_files():
            text = f.read_text(encoding='utf-8', errors='replace')
            leaks += [(f.name, '<private token withheld>') for t in tokens if t in text]  # never echo the token
        self.assertEqual(leaks, [])


if __name__ == '__main__':
    unittest.main()
