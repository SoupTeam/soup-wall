import copy
import unittest

from sou13.cases import CASES
from sou13cp2 import restricted
from sou13cp2.taxonomy import BEHAVIOR_CLASSES, CP1_TEMPLATES, families, taxonomy_errors
from _testsupport import RESTRICTED_FAMILIES, requires


class TaxonomyIsValid(unittest.TestCase):
    def setUp(self):
        self.fams = families()

    def test_clean_taxonomy_passes(self):
        self.assertEqual(taxonomy_errors(self.fams), [])

    def test_every_behavior_class_present(self):
        self.assertEqual({f['behavior_class'] for f in self.fams}, set(BEHAVIOR_CLASSES))

    def test_required_behaviours_have_known_positive_templates(self):
        established = {a for f in self.fams for t in f['templates'] for a in t['established_actions']}
        self.assertEqual(established, {'read', 'write', 'delete', 'send_data', 'change_permissions'})
        profiles = {t['unknown_profile'] for f in self.fams for t in f['templates']}
        self.assertEqual(profiles, {'none', 'partial', 'full'})

    def test_every_cp1_case_mapped_once(self):
        self.assertEqual(sorted(CP1_TEMPLATES), sorted(s['id'] for s in CASES))
        mapped = sorted(c for f in self.fams for c in f['cp1_cases'])
        self.assertEqual(mapped, sorted(CP1_TEMPLATES))

    def test_cp2_families_are_not_cp1_exposed(self):
        for f in self.fams:
            if f['status'] == 'cp2_candidate':
                self.assertEqual(f['cp1_cases'], [])
                self.assertIn(f['exposure'], ('none', 'restricted_test'))

    @requires(RESTRICTED_FAMILIES)  # the 200-300 pilot size includes the 54 sealed test cases
    def test_pilot_size_within_200_300(self):
        self.assertTrue(200 <= sum(f['planned_cases'] for f in self.fams) <= 300)

    @unittest.skipIf(restricted.available(), 'public-copy totals; the full pilot size is checked above')
    def test_public_copy_is_the_documented_development_subset(self):
        # 19 legacy CP1 cases + 179 CP2 development candidates (docs/benchmarks/sou13/README.md)
        self.assertEqual(len(self.fams), 36)
        self.assertEqual(sum(len(f['cp1_cases']) for f in self.fams), 19)
        self.assertEqual(sum(f['new_cases'] for f in self.fams), 179)
        self.assertEqual(sum(f['planned_cases'] for f in self.fams), 198)

    def test_not_expanded_families(self):
        by = {f['family_id']: f for f in self.fams}
        for fid in ('fam.shell.posix_sh', 'fam.unknown.offline_summary'):
            self.assertEqual(by[fid]['new_cases'], 0, fid)
        # DEV-09 family: exactly one admitted replacement case, no expansion beyond it
        self.assertEqual(by['fam.unknown.workspace_tidy']['new_cases'], 1)

    def test_misleading_descriptions_are_family_specific(self):
        seen = {}
        for f in self.fams:
            if f.get('misleading_description'):
                self.assertNotIn(f['misleading_description'], seen)
                seen[f['misleading_description']] = f['family_id']
                self.assertIn(f['misleading_description'], f['descriptions'])


class TaxonomyRejectsDuplicates(unittest.TestCase):
    """Deliberately broken taxonomies must be rejected."""

    def setUp(self):
        self.fams = copy.deepcopy(families())
        self.by = {f['family_id']: f for f in self.fams}

    def assertRejected(self, needle):
        errors = taxonomy_errors(self.fams)
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_identity_in_two_families(self):
        self.by['fam.read.wiki_page_get']['identities'].append(['synthetic-statuspage', 'fetch_url'])
        self.assertRejected('identity=')

    def test_alias_name_in_two_families(self):
        f = self.by['fam.read.wiki_page_get']
        f['identities'].append(['synthetic-other', 'fetch_url_v2'])
        f['normalized_names'].append('fetch url')
        self.assertRejected("name='fetch url'")

    def test_shared_server_in_two_families(self):
        self.by['fam.read.wiki_page_get']['identities'].append(['synthetic-docstore', 'get_page2'])
        self.assertRejected("server='synthetic-docstore'")

    def test_same_description_in_two_families(self):
        self.by['fam.send_data.chat_post']['descriptions'] = ['Post a text message to a webhook endpoint!']
        self.assertRejected('description=')

    def test_near_duplicate_template_across_families(self):
        clone = copy.deepcopy(self.by['fam.delete.document_delete']['templates'][0])
        clone['template_id'] = 'tpl.delete.queue_ack.clone'
        self.by['fam.delete.queue_ack']['templates'].append(clone)
        self.assertRejected('template_signature=')

    def test_near_duplicate_template_inside_family(self):
        f = self.by['fam.write.flag_set']
        clone = dict(f['templates'][0], template_id='tpl.write.flag_set.copy')
        f['templates'].append(clone)
        self.assertRejected('near-duplicate inside family')

    def test_class_contradiction(self):
        t = self.by['fam.read.object_stat']['templates'][0]
        t['established_actions'] = ['read', 'delete']
        self.assertRejected('contradicts class read')

    def test_cp1_family_must_be_exposed(self):
        self.by['fam.read.http_get']['exposure'] = 'none'
        self.assertRejected('exposure cp1_shared')


if __name__ == '__main__':
    unittest.main()
