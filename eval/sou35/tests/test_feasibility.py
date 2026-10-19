"""Deterministic feasibility: necessary-condition report, exact counts, leakage groups, no silent relaxation."""
import unittest

from _util import toys

from sou35 import feasibility as F

R, W, S = 'pos:read', 'pos:write', 'pos:send_data'


def table(**groups):
    return {g: (n, frozenset(feats)) for g, (n, feats) in groups.items()}


def req(held_out):
    return F.default_requirements(held_out)


class NecessaryConditions(unittest.TestCase):
    def test_feature_in_too_few_groups_is_impossible(self):
        t = table(a=(1, {R}), b=(1, {R}), c=(1, {W}))
        errs = F.necessary_condition_errors(t, req({R}))
        self.assertEqual(len(errs), 1)
        self.assertIn('IMPOSSIBLE pos:read', errs[0])
        self.assertEqual(F.count_allocations(t, req({R})), 0)

    def test_requirements_are_not_relaxed(self):
        _, recs = toys()
        rep = F.report(recs, candidate_patterns=[{'train': 0, 'validation': 1, 'calibration': 1, 'test': 1}])
        self.assertTrue(rep['impossible'])
        self.assertEqual(rep['feasible_patterns'], [])
        self.assertEqual(rep['requirements']['test'], sorted(F.FULL_HELD_OUT))


class ExactCounts(unittest.TestCase):
    def test_hand_checked_count(self):
        # three single-family groups each carrying R; three held-out splits need R; train needs nothing.
        t = table(a=(1, {R}), b=(1, {R}), c=(1, {R}), d=(1, {W}))
        # held-out splits get a permutation of a,b,c (3! = 6); d may go anywhere (4) -> 24 without counts
        self.assertEqual(F.count_allocations(t, req({R})), 24)
        # with counts 1/1/1/1, d must be train -> 6
        self.assertEqual(F.count_allocations(t, req({R}), {'train': 1, 'validation': 1, 'calibration': 1, 'test': 1}), 6)
        # with 0/2/1/1, d joins validation or a 2-family split... only validation has 2 slots -> 6 (perms) * 1
        self.assertEqual(F.count_allocations(t, req({R}), {'train': 0, 'validation': 2, 'calibration': 1, 'test': 1}), 6)

    def test_leakage_linked_families_move_together(self):
        # group g carries two families; it can fill a 2-slot split only
        t = table(g=(2, {R}), x=(1, {R}), y=(1, {R}))
        self.assertEqual(F.count_allocations(t, req({R}), {'train': 0, 'validation': 1, 'calibration': 1, 'test': 2}), 2)
        self.assertEqual(F.count_allocations(t, req({R}), {'train': 0, 'validation': 2, 'calibration': 1, 'test': 1}), 2)
        self.assertEqual(F.count_allocations(t, req({R}), {'train': 1, 'validation': 1, 'calibration': 1, 'test': 1}), 0)

    def test_allowed_splits_respected(self):
        t = table(a=(1, {R}), b=(1, {R}), c=(1, {R}))
        allowed = {'a': ('test',)}
        self.assertEqual(F.count_allocations(t, req({R}), {'train': 0, 'validation': 1, 'calibration': 1, 'test': 1},
                                             allowed), 2)

    def test_dp_equals_brute_force(self):
        import itertools
        import random
        rng = random.Random(35)
        pool = ['pos:read', 'pos:write', 'neg:read', 'noop', 'unknown']
        for _ in range(25):
            t = {f'g{i}': (rng.choice((1, 1, 2)), frozenset(rng.sample(pool, rng.randint(0, 3)))) for i in range(7)}
            rq = F.default_requirements(set(rng.sample(pool, 2)))
            rq['train'] = frozenset(rng.sample(pool, rng.randint(0, 1)))
            n = sum(s for s, _ in t.values())
            for counts in [None, next(iter(F.patterns(n)))]:
                g = sorted(t)
                brute = 0
                for a in itertools.product(range(4), repeat=len(g)):
                    load, cov = [0] * 4, [set() for _ in range(4)]
                    for gi, k in zip(g, a):
                        load[k] += t[gi][0]
                        cov[k] |= t[gi][1]
                    if counts and load != [counts[s] for s in F.SPLITS]:
                        continue
                    brute += all(rq[s] <= cov[k] for k, s in enumerate(F.SPLITS))
                self.assertEqual(F.count_allocations(t, rq, counts), brute)

    def test_patterns_enumeration(self):
        pats = list(F.patterns(5))
        self.assertEqual(len(pats), 4)  # compositions of 5 into 4 positive parts = C(4,3)
        self.assertTrue(all(sum(p.values()) == 5 for p in pats))


class RecordFeatures(unittest.TestCase):
    def test_features_from_toy_records(self):
        _, recs = toys()
        feats = F.family_features(recs)
        self.assertEqual(feats['f35.write.toy_batch'] & {'noop', 'pos:write', 'technical_error'},
                         {'noop', 'pos:write', 'technical_error'})
        self.assertIn('unknown', feats['f35.multimode.toy_switch'])
        self.assertNotIn('pos:delete', set().union(*feats.values()))

    def test_toy_pool_reduced_requirement_is_explicit_and_counted(self):
        _, recs = toys()
        need = {'pos:write', 'technical_error'}
        rep = F.report(recs, requirements=F.default_requirements(need),
                       candidate_patterns=[{'train': 1, 'validation': 1, 'calibration': 1, 'test': 0}])
        self.assertIn('IMPOSSIBLE pos:write', ' '.join(rep['impossible']))  # 2 write families, 3 held-out splits


if __name__ == '__main__':
    unittest.main()
