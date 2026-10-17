"""SOU-35 scoring exclusion regression; artificial toy data ONLY, no private pool.

Uses real (artificial) v2 ledgers instead of patching admissibility, so the evidence-stratum gate is exercised."""
import copy
import unittest

from _util import toys
from test_release_workflow import rulings_for
from sou35 import export, feasibility, rulings

Q = 'Q-S35-UNMODELLED-MODE'


class PrimaryScoringExclusions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.decls, cls.rows = toys()
        full = [r for r in cls.rows
                if r['expected_outcome'] == 'classification'
                and Q in r['open_questions']
                and r['annotation']['unknown'] is True
                and all(v is None for v in r['annotation']['per_action_targets'].values())]
        assert full, 'artificial toy switch must include an unmodelled full-unknown case'
        cls.full = full[0]

    def ledger(self, rows, **kw):
        return rulings.load(rulings_for(self.decls, rows, **kw), self.decls, rows)

    def replace(self, row):
        return [row if r['id'] == row['id'] else r for r in self.rows]

    def test_full_unmodelled_unknown_cannot_be_scored_even_with_approvals(self):
        reg = self.ledger(self.rows)  # load() refuses an invalid register
        self.assertTrue(rulings.excluded_from_primary_scoring(self.full))
        self.assertTrue(rulings.is_admissible(self.full, reg))  # accepted interface basis in the toy ledger
        self.assertEqual(rulings.evidence_stratum(self.full, reg), rulings.DISPUTED)
        self.assertFalse(rulings.primary_scoring_admissible(self.full, reg))
        self.assertFalse(export.scored(self.full, reg))
        self.assertEqual(feasibility.record_features(self.full, reg), set())
        # Raw exploratory/non-approved feature counts may still include it.
        self.assertIn('unknown', feasibility.record_features(self.full))

    def test_partial_unknown_retains_established_action_when_reviewed(self):
        partial = copy.deepcopy(self.full)
        partial['annotation']['per_action_targets']['delete'] = True
        rows = self.replace(partial)
        reg = self.ledger(rows)
        self.assertFalse(rulings.excluded_from_primary_scoring(partial))
        self.assertEqual(rulings.evidence_stratum(partial, reg), rulings.PRIMARY)
        self.assertTrue(export.scored(partial, reg))
        self.assertTrue({'pos:delete', 'unknown'} <= feasibility.record_features(partial, reg))

    def test_regular_unknown_without_disputed_unmodelled_mode_is_not_blanket_excluded(self):
        other = copy.deepcopy(self.full)
        other['open_questions'].remove(Q)
        reg = self.ledger(self.replace(other))
        self.assertFalse(rulings.excluded_from_primary_scoring(other))
        self.assertTrue(export.scored(other, reg))

    def test_non_unmodelled_tag_and_incomplete_target_map_do_not_match_exact_rule(self):
        without_tag = copy.deepcopy(self.full)
        without_tag['scenario_tags'] = [x for x in without_tag['scenario_tags'] if x != 'unmodelled_mode']
        self.assertFalse(rulings.excluded_from_primary_scoring(without_tag))
        missing_field = copy.deepcopy(self.full)
        missing_field['annotation']['per_action_targets'].pop('delete')
        self.assertFalse(rulings.excluded_from_primary_scoring(missing_field))

    def test_human_approval_is_still_required_for_non_excluded_cases(self):
        normal = next(r for r in self.rows
                      if r['expected_outcome'] == 'classification'
                      and not rulings.excluded_from_primary_scoring(r)
                      and rulings.mechanical_ceiling(r) == 'interface_supported')
        for status in ('pending', 'rejected', 'disputed'):
            reg = self.ledger(self.rows, statuses={normal['id']: status})
            with self.subTest(status=status):
                self.assertFalse(export.scored(normal, reg))
                self.assertFalse(feasibility.record_features(normal, reg))
        raw = rulings_for(self.decls, self.rows)
        raw['reviewed_cases'] = [c for c in raw['reviewed_cases'] if c['id'] != normal['id']]
        missing = rulings.load(raw, self.decls, self.rows)
        self.assertEqual(rulings.evidence_stratum(normal, missing), rulings.UNREVIEWED)
        self.assertFalse(feasibility.record_features(normal, missing))

    def test_technical_error_remains_outside_primary_scoring(self):
        tech = next(r for r in self.rows if r['expected_outcome'] == 'technical_error')
        reg = self.ledger(self.rows)
        self.assertFalse(rulings.excluded_from_primary_scoring(tech))
        self.assertEqual(rulings.evidence_stratum(tech, reg), rulings.TECHNICAL)
        self.assertFalse(export.scored(tech, reg))
        self.assertEqual(feasibility.record_features(tech, reg), {'technical_error'})


if __name__ == '__main__':
    unittest.main()
