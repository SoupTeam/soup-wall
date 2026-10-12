"""Public mode and adversarial reconstruction (requires the restricted materials to score)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sou13cp2 import ROOT, restricted
from _testsupport import CP1_DATA, CP2_PUBLIC, SEALED_COMMITTED, requires, requires_owner_anchor
from sou13cp2.public_audit import ATTACKER, run


@requires(CP1_DATA, CP2_PUBLIC, SEALED_COMMITTED)
class AdversarialAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run(ROOT)

    @requires_owner_anchor()  # the public copy's validator must authenticate the frozen public view
    def test_public_copy_reveals_nothing(self):
        r = self.report
        self.assertEqual(r['public_copy_contains_restricted_paths'], [])
        self.assertFalse(r['attacker']['restricted_available_in_copy'])
        self.assertEqual(r['attacker']['restricted_families_visible'], 0)
        self.assertEqual(r['test_inputs_given_to_attacker'], 54)
        self.assertEqual(r['test_inputs_mapped_to_public_semantics'], 0)
        self.assertEqual(r['test_labels_reconstructed_exactly'], 0)
        self.assertEqual(r['strong_fingerprint_hits'], {})
        self.assertEqual(r['public_mode_validation']['result'], 'PASS', r['public_mode_validation'])
        self.assertEqual(r['public_mode_validation']['mode'], 'public')
        self.assertTrue(r['passed'])

    def test_positive_control_attacker_works_when_semantics_are_visible(self):
        """Same attack against the FULL repository must reconstruct every test label (the attack has power)."""
        sealed = [json.loads(x) for x in (ROOT / 'cp2_sealed' / 'candidates_test.jsonl').read_text(encoding='utf-8')
                  .splitlines()]
        with tempfile.TemporaryDirectory() as tmp:
            inputs = Path(tmp) / 'in.jsonl'
            inputs.write_text(''.join(json.dumps({'id': r['id'], 'input': r['input']}) + '\n' for r in sealed),
                              encoding='utf-8')
            script = Path(tmp) / 'attacker.py'
            script.write_text(ATTACKER, encoding='utf-8')
            out = subprocess.run([sys.executable, '-I', '-B', str(script), str(ROOT), str(inputs)],
                                 capture_output=True, text=True, encoding='utf-8', check=True)
        attack = json.loads(out.stdout.strip().splitlines()[-1])
        truth = {r['id']: (r['annotation']['per_action_targets'], r['annotation']['unknown']) for r in sealed}
        correct = sum(any((p[0], p[1]) == truth[i] for p in kinds.values())
                      for i, kinds in attack['predictions'].items())
        self.assertEqual(attack['inputs_matched_by']['identity'], 54)
        self.assertEqual(correct, 54)


if __name__ == '__main__':
    unittest.main()
