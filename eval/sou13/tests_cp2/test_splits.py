import copy
import unittest

from sou13.hashing import sha
from sou13cp2.splits import SPLITS, SplitError, assign, build_manifest, leakage_groups, manifest_errors
from sou13cp2 import restricted
from sou13cp2.taxonomy import PLANNED_FAMILIES, _finalise, families
from _testsupport import RESTRICTED_FAMILIES, requires


PIN = {'cp1_shared': 'train', 'restricted_test': 'test'}


def resign(m):
    body = {k: v for k, v in m.items() if k != 'manifest_sha256'}
    m['manifest_sha256'] = sha(body)
    return m


class DeterministicAssignment(unittest.TestCase):
    def setUp(self):
        self.fams = families()
        self.manifest = build_manifest(self.fams)

    def test_two_builds_identical(self):
        self.assertEqual(build_manifest(families()), self.manifest)

    def test_family_order_does_not_matter(self):
        for order in (list(reversed(self.fams)), sorted(self.fams, key=lambda f: sha(f['family_id']))):
            self.assertEqual(build_manifest(order)['family_split'], self.manifest['family_split'])
            self.assertEqual(build_manifest(order)['manifest_sha256'], self.manifest['manifest_sha256'])

    def test_clean_manifest_passes(self):
        self.assertEqual(manifest_errors(self.manifest, self.fams), [])

    @requires(RESTRICTED_FAMILIES)  # the 'test' split is populated only by the restricted families
    def test_every_split_used_and_every_family_once(self):
        self.assertEqual(set(self.manifest['family_split'].values()), set(SPLITS))
        self.assertEqual(sorted(self.manifest['family_split']), sorted(f['family_id'] for f in self.fams))

    def test_cp1_families_pinned_to_train(self):
        for f in self.fams:
            if f['exposure'] == 'cp1_shared':
                self.assertEqual(self.manifest['family_split'][f['family_id']], 'train', f['family_id'])

    def test_salt_change_is_still_valid_and_keeps_pins(self):
        other = build_manifest(self.fams, salt='another-salt')
        self.assertEqual(manifest_errors(other, self.fams), [])
        for f in self.fams:
            if f['exposure'] != 'none':
                self.assertEqual(other['family_split'][f['family_id']], PIN[f['exposure']])

    def test_adding_a_family_does_not_move_pinned_groups(self):
        extra = _finalise(copy.deepcopy(PLANNED_FAMILIES[0]) | {
            'family_id': 'fam.read.extra_probe', 'identities': [['synthetic-extra', 'probe_status']],
            'descriptions': ['Probe something new.'], 'templates': [dict(PLANNED_FAMILIES[0]['templates'][0],
                                                                         variant='only', effect_profile=['store_read'],
                                                                         schema={'type': 'object', 'properties': {'probe': {'type': 'number'}}, 'required': ['probe'], 'additionalProperties': False},
                                                                         arg_keys=['probe'])]})
        grown = build_manifest(self.fams + [extra])
        for f in self.fams:
            if f['exposure'] != 'none':
                self.assertEqual(grown['family_split'][f['family_id']], PIN[f['exposure']])

    @requires(RESTRICTED_FAMILIES)
    def test_every_eval_split_gets_every_stratum_from_eligible_families(self):
        by = {f['family_id']: f for f in self.fams}
        required = {'read', 'write', 'delete', 'send_data', 'change_permissions', 'mixed', 'no_effect',
                    'unknown_partial', 'unknown_full'}
        for s in ('validation', 'calibration', 'test'):
            strata = {by[f]['coverage_stratum'] for f, sp in self.manifest['family_split'].items()
                      if sp == s and by[f]['coverage_eligible']}
            self.assertEqual(strata, required, s)

    def test_pending_family_does_not_take_a_coverage_slot(self):
        g = next(g for g in self.manifest['groups'] if 'fam.mixed.record_archive' in g['families'])
        self.assertFalse(g['coverage_eligible'])
        self.assertEqual(g['assignment_reason'], 'deficit')

    def test_bad_ratios_rejected(self):
        with self.assertRaises(SplitError):
            assign(self.fams, ratios={'train': 0.9, 'validation': 0.2, 'calibration': 0, 'test': 0})


@unittest.skipIf(restricted.available(), 'public-copy invariants; the full taxonomy is covered above')
class PublicCopyAssignment(unittest.TestCase):
    """Structural invariants of the data-free public copy (36 non-test families).

    The split recomputed here is NOT the frozen assignment: a public copy takes split assignments from the
    frozen public manifest view, which is private. Only invariants that hold for any public copy are checked."""

    def setUp(self):
        self.fams = families()
        self.manifest = build_manifest(self.fams)

    def test_no_restricted_family_and_no_test_assignment(self):
        self.assertFalse(any(f['exposure'] == restricted.EXPOSURE for f in self.fams))
        self.assertEqual(sorted(self.manifest['family_split']), sorted(f['family_id'] for f in self.fams))
        self.assertEqual(set(self.manifest['family_split'].values()), {'train', 'validation', 'calibration'})

    def test_development_eval_splits_get_every_stratum(self):
        by = {f['family_id']: f for f in self.fams}
        required = {'read', 'write', 'delete', 'send_data', 'change_permissions', 'mixed', 'no_effect',
                    'unknown_partial', 'unknown_full'}
        for s in ('validation', 'calibration'):
            strata = {by[f]['coverage_stratum'] for f, sp in self.manifest['family_split'].items()
                      if sp == s and by[f]['coverage_eligible']}
            self.assertEqual(strata, required, s)


class ManifestTampering(unittest.TestCase):
    def setUp(self):
        self.fams = families()
        self.manifest = build_manifest(self.fams)

    def test_hand_moved_family_rejected_even_if_resigned(self):
        m = copy.deepcopy(self.manifest)
        planned = next(f for f, s in m['family_split'].items() if s == 'validation')
        m['family_split'][planned] = 'test'
        self.assertTrue(any('sha256' in e for e in manifest_errors(m, self.fams)))
        resign(m)
        errors = manifest_errors(m, self.fams)
        self.assertTrue(any('deterministic output' in e for e in errors), errors)
        self.assertTrue(any('disagree with its group' in e for e in errors), errors)

    def test_cp1_family_in_test_rejected(self):
        m = copy.deepcopy(self.manifest)
        g = next(g for g in m['groups'] if g['leakage_group_id'] == 'lg.read.http_get')
        g['split'] = 'test'
        m['family_split']['fam.read.http_get'] = 'test'
        errors = manifest_errors(resign(m), self.fams)
        self.assertTrue(any('violates exposure policy' in e for e in errors), errors)
        self.assertTrue(any('exposure cp1_shared forbids split test' in e for e in errors), errors)

    def test_hand_frozen_manifest_rejected(self):
        m = copy.deepcopy(self.manifest)
        m['frozen'], m['status'] = True, 'FROZEN'
        errors = manifest_errors(resign(m), self.fams)  # a hand-made FROZEN status has no approval record
        self.assertTrue(any('without a complete approval record' in e for e in errors), errors)

    def test_labels_in_manifest_rejected(self):
        m = copy.deepcopy(self.manifest)
        m['labels_in_manifest'] = True
        self.assertTrue(any('must not carry labels' in e for e in manifest_errors(resign(m), self.fams)))


class GroupsMergeLinkedFamilies(unittest.TestCase):
    def test_shared_description_forces_one_group_and_one_split(self):
        fams = copy.deepcopy(families())
        a = next(f for f in fams if f['family_id'] == 'fam.send_data.chat_post')
        b = next(f for f in fams if f['family_id'] == 'fam.read.wiki_page_get')
        a['descriptions'] = list(b['descriptions'])
        groups = dict(leakage_groups(fams))
        merged = [g for g, members in groups.items()
                  if {'fam.send_data.chat_post', 'fam.read.wiki_page_get'} <= {m['family_id'] for m in members}]
        self.assertEqual(len(merged), 1)
        m = build_manifest(fams)
        self.assertEqual(m['family_split']['fam.send_data.chat_post'], m['family_split']['fam.read.wiki_page_get'])

    def test_link_to_cp1_family_pulls_planned_family_into_train(self):
        fams = copy.deepcopy(families())
        planned = next(f for f in fams if f['family_id'] == 'fam.send_data.chat_post')
        planned['identities'].append(['synthetic-buildhooks', 'post_channel_message'])  # shares CP1 server
        m = build_manifest(fams)
        self.assertEqual(m['family_split']['fam.send_data.chat_post'], 'train')


if __name__ == '__main__':
    unittest.main()
