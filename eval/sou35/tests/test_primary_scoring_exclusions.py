"""SOU-35 scoring exclusion regression; artificial toy data ONLY, no private pool."""
import copy
import unittest
from unittest.mock import patch

from _util import toys
from sou35 import export, feasibility, rulings

Q = 'Q-S35-UNMODELLED-MODE'


class PrimaryScoringExclusions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.rows = toys()
        full = [r for r in cls.rows
                if r['expected_outcome'] == 'classification'
                and Q in r['open_questions']
                and r['annotation']['unknown'] is True
                and all(v is None for v in r['annotation']['per_action_targets'].values())]
        assert full, 'artificial toy switch must include an unmodelled full-unknown case'
        cls.full = full[0]

    def test_full_unmodelled_unknown_cannot_be_scored_even_with_approvals(self):
        self.assertTrue(rulings.excluded_from_primary_scoring(self.full))
        with patch.object(rulings, 'is_admissible', return_value=True):
            self.assertFalse(rulings.primary_scoring_admissible(self.full, object()))
            self.assertFalse(export.scored(self.full, object()))
            self.assertEqual(feasibility.record_features(self.full, object()), set())
        # Raw exploratory/non-approved feature counts may still include it.
        self.assertIn('unknown', feasibility.record_features(self.full))

    def test_partial_unknown_retains_established_action_when_reviewed(self):
        partial = copy.deepcopy(self.full)
        partial['annotation']['per_action_targets']['delete'] = True
        self.assertFalse(rulings.excluded_from_primary_scoring(partial))
        with patch.object(rulings, 'is_admissible', return_value=True):
            self.assertTrue(export.scored(partial, object()))
            self.assertEqual({'pos:delete', 'unknown'} <= feasibility.record_features(partial, object()), True)

    def test_regular_unknown_without_disputed_unmodelled_mode_is_not_blanket_excluded(self):
        other = copy.deepcopy(self.full)
        other['open_questions'].remove(Q)
        self.assertFalse(rulings.excluded_from_primary_scoring(other))
        with patch.object(rulings, 'is_admissible', return_value=True):
            self.assertTrue(export.scored(other, object()))

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
                      and not rulings.excluded_from_primary_scoring(r))
        with patch.object(rulings, 'is_admissible', return_value=False):
            self.assertFalse(export.scored(normal, object()))
            self.assertFalse(feasibility.record_features(normal, object()))

    def test_technical_error_remains_outside_primary_scoring(self):
        tech = next(r for r in self.rows if r['expected_outcome'] == 'technical_error')
        self.assertFalse(rulings.excluded_from_primary_scoring(tech))
        with patch.object(rulings, 'is_admissible', return_value=True):
            self.assertFalse(export.scored(tech, object()))
            self.assertIn('technical_error', feasibility.record_features(tech, object()))


if __name__ == '__main__':
    unittest.main()
