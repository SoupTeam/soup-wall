"""Synthetic toy-only test: ban leakage groups from *future* test sets, never draw v3."""
import json
import unittest

from sou35 import custody, rulings
from test_release_workflow import COUNTS, REQ, SEED, pool, rulings_for


class TestExcludedTestFamilies(unittest.TestCase):
    def _fixture(self):
        decls, recs, table, groups = pool()
        st = custody.declare(decls, 'toy-custodian', REQ, COUNTS)
        digest = rulings.digest(rulings_for(decls, recs))
        return st, table, groups, digest

    def test_restricted_groups_never_drawn_and_commitment_is_private(self):
        st, table, groups, digest = self._fixture()
        banned = (sorted(table)[0],)
        st, _ = custody.commit(st, table, REQ, COUNTS, SEED,
                               rulings_sha256=digest, test_exclusions=banned)
        self.assertEqual(custody.public_state_errors(st), [])
        self.assertNotIn(banned[0], json.dumps(st))
        self.assertEqual(len(st['test_exclusions_commitment']), 64)
        st, private = custody.draw(st, table, REQ, COUNTS, SEED, groups,
                                   test_exclusions=banned)
        self.assertFalse(set(private['test_groups']) & set(banned))
        self.assertEqual(custody.public_state_errors(st), [])

    def test_draw_refuses_removed_or_changed_bans(self):
        st, table, groups, digest = self._fixture()
        banned = (sorted(table)[0],)
        st, _ = custody.commit(st, table, REQ, COUNTS, SEED,
                               rulings_sha256=digest, test_exclusions=banned)
        with self.assertRaisesRegex(custody.CustodyError, 'policy changed'):
            custody.draw(st, table, REQ, COUNTS, SEED, groups, test_exclusions=())
        with self.assertRaisesRegex(custody.CustodyError, 'policy changed'):
            custody.draw(st, table, REQ, COUNTS, SEED, groups,
                         test_exclusions=(sorted(table)[1],))

    def test_direct_calls_require_explicit_exclusions(self):
        st, table, groups, digest = self._fixture()
        with self.assertRaises(TypeError):
            custody.commit(st, table, REQ, COUNTS, SEED, rulings_sha256=digest)
        committed, _ = custody.commit(st, table, REQ, COUNTS, SEED,
                                      rulings_sha256=digest, test_exclusions=())
        with self.assertRaises(TypeError):
            custody.draw(committed, table, REQ, COUNTS, SEED, groups)

    def test_all_test_groups_banned_is_impossible(self):
        st, table, _, digest = self._fixture()
        with self.assertRaisesRegex(custody.CustodyError, 'IMPOSSIBLE'):
            custody.commit(st, table, REQ, COUNTS, SEED,
                           rulings_sha256=digest, test_exclusions=tuple(sorted(table)))

    def test_unknown_group_and_duplicate_bans_rejected(self):
        st, table, _, digest = self._fixture()
        for banned in (('absent',), ('x', 'x'), 'not-a-list'):
            with self.assertRaises(custody.CustodyError):
                custody.commit(st, table, REQ, COUNTS, SEED,
                               rulings_sha256=digest, test_exclusions=banned)


if __name__ == '__main__':
    unittest.main()
