"""check_pool: refuses non-ignored outputs, prints aggregates without identifiers, applies the conservative filter."""
import json
import re
import unittest

from _util import ROOT, toys

from sou35 import check_pool


class OutputGuard(unittest.TestCase):
    def test_refuses_tracked_or_outside_paths(self):
        for bad in (ROOT / 'tests' / 'out', ROOT / 'schema', ROOT.parent / 'sou13' / 'private'):
            with self.subTest(path=bad), self.assertRaises(check_pool.PrivacyError):
                check_pool.ensure_private_out(bad)

    def test_accepts_ignored_private_path(self):
        self.assertEqual(check_pool.ensure_private_out(ROOT / 'private'), (ROOT / 'private').resolve())


class Aggregate(unittest.TestCase):
    def test_no_identifiers_in_aggregate(self):
        decls, recs = toys()
        text = json.dumps(check_pool.aggregate(recs, decls, [(0, 1, 1, 1)]))
        self.assertNotIn('f35.', text)
        self.assertIsNone(re.search(r'S35-[0-9A-F]{32}', text))  # case ids (decision ids are Q-S35-*)
        for r in recs:
            self.assertNotIn(r['id'], text)
        for d in decls:
            for server, tool in d['identities']:
                self.assertNotIn(server, text)
                self.assertNotIn(tool, text)
        agg = json.loads(text)
        self.assertEqual(agg['records'], 15)
        self.assertEqual(agg['human_approved'], 0)

    def test_invalid_pattern_is_flagged_not_counted(self):
        decls, recs = toys()
        agg = check_pool.aggregate(recs, decls, [(1, 1, 1, 1)])
        self.assertIn('invalid', agg['scenarios']['as_designed']['patterns']['1/1/1/1'])

    def test_conservative_filter(self):
        _, recs = toys()
        designed = check_pool.scenario_table(recs, 'as_designed')
        conservative = check_pool.scenario_table(recs, 'conservative')
        feats = lambda t: set().union(*(f for _, f in t.values()))
        self.assertIn('unknown', feats(designed))      # only the unmodelled toy mode is unknown
        self.assertNotIn('unknown', feats(conservative))
        # read=false next to an ACL change depends on Q-S35-INTERNAL-ACCESS: not a usable negative conservatively
        unshare = [r for r in recs if r['template_id'].endswith('.unshare')]
        self.assertEqual(len(unshare), 1)
        (g, (_, f_designed)), = check_pool.scenario_table(unshare, 'as_designed').items()
        (_, (_, f_conservative)), = check_pool.scenario_table(unshare, 'conservative').items()
        self.assertIn('neg:read', f_designed)
        self.assertNotIn('neg:read', f_conservative)
        self.assertIn('neg:write', f_conservative)


if __name__ == '__main__':
    unittest.main()
