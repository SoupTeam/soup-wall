import itertools
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.labels import (ACTIONS, AssumptionViolation, contract_view, from_contract_under_sou13_assumptions,  # noqa: E402
                          invariant_errors, known_mask, to_contract_with_forbidden)


def vec(values):
    return dict(zip(ACTIONS, values))


ALL_VECTORS = [vec(v) for v in itertools.product((True, False, None), repeat=5)]


class UnconditionalInvariants(unittest.TestCase):
    def ok(self, t, unknown):
        return invariant_errors(t, known_mask(t), unknown, contract_view(t, unknown))

    def test_243_vectors_covered(self):
        self.assertEqual(len(ALL_VECTORS), 243)

    def test_known_mask_derived(self):
        for t in ALL_VECTORS:
            self.assertEqual(known_mask(t), {a: int(t[a] is not None) for a in ACTIONS})

    def test_null_requires_unknown(self):
        for t in ALL_VECTORS:
            has_null = any(v is None for v in t.values())
            self.assertEqual(self.ok(t, True), [])
            self.assertEqual(self.ok(t, False) == [], not has_null)

    def test_unknown_true_without_null_not_rejected(self):
        # SOU13-ASSUME-UNKNOWN-FROM-NULL is NOT an unconditional invariant: all-known labels with unknown=true are allowed.
        t = vec((True, False, False, False, False))
        self.assertEqual(self.ok(t, True), [])

    def test_contract_view_is_true_set(self):
        t = vec((True, None, False, True, None))
        self.assertEqual(contract_view(t, True), {'actions': ['read', 'send_data'], 'unknown': True})

    def test_rejects_bad_mask_view_and_unknown_string(self):
        t = vec((True, False, False, False, False))
        self.assertTrue(invariant_errors(t, {**known_mask(t), 'read': 0}, False, contract_view(t, False)))
        self.assertTrue(invariant_errors(t, known_mask(t), False, {'actions': ['read', 'unknown'], 'unknown': False}))
        self.assertTrue(invariant_errors(t, known_mask(t), False, {'actions': ['write'], 'unknown': False}))
        self.assertTrue(invariant_errors(t, known_mask(t), 'no', contract_view(t, False)))
        self.assertTrue(invariant_errors(t, known_mask(t), False, contract_view(t, False), forbidden=['read']))


class RoundTripUnderSou13Assumptions(unittest.TestCase):
    """Round-trip is claimed ONLY under SOU13-ASSUME-UNKNOWN-FROM-NULL (unknown iff some null) and SOU13-CONV-FORBIDDEN-ACTIONS (forbidden_actions
    carries known negatives when unknown=true). It is not a universal lossless mapping."""

    def test_tri_contract_tri_identity_for_all_243(self):
        for t in ALL_VECTORS:
            unknown = any(v is None for v in t.values())  # SOU13-ASSUME-UNKNOWN-FROM-NULL
            actions, u, forbidden = to_contract_with_forbidden(t, unknown)
            self.assertEqual(from_contract_under_sou13_assumptions(actions, u, forbidden), t)

    def test_contract_tri_contract_identity(self):
        seen = 0
        for actions in itertools.chain.from_iterable(itertools.combinations(ACTIONS, k) for k in range(6)):
            rest = [a for a in ACTIONS if a not in actions]
            for unknown in (False, True):
                forbidden_options = [()] if not unknown else itertools.chain.from_iterable(
                    itertools.combinations(rest, k) for k in range(len(rest)))
                for forbidden in forbidden_options:
                    t = from_contract_under_sou13_assumptions(actions, unknown, forbidden)
                    self.assertEqual(to_contract_with_forbidden(t, unknown), (list(actions), unknown, list(forbidden)))
                    seen += 1
        self.assertEqual(seen, 243)

    def test_outside_assumptions_raises(self):
        with self.assertRaises(AssumptionViolation):
            from_contract_under_sou13_assumptions(['read'], True, ['write', 'delete', 'send_data', 'change_permissions'])
        with self.assertRaises(AssumptionViolation):
            from_contract_under_sou13_assumptions(['read'], False, ['write'])
        with self.assertRaises(AssumptionViolation):
            from_contract_under_sou13_assumptions(['read'], True, ['read'])

    def test_without_forbidden_convention_known_negatives_are_lost(self):
        # Documents the limitation: plain D01 view (actions, unknown) cannot carry known negatives.
        t = vec((True, None, None, False, None))
        self.assertEqual(contract_view(t, True), contract_view(vec((True, None, None, None, None)), True))


if __name__ == '__main__':
    unittest.main()
