"""Deliberate leakage: each mutant must be rejected by the validator; the clean set must pass."""
import unittest

from sou13cp2.leakage import components, leakage_errors, record_item, taxonomy_items
from sou13cp2.records import record_errors
from _util import base, by_id, family_in, mutant
from _testsupport import CP1_DATA, RESTRICTED_FAMILIES, requires


def errors_for(fams, manifest, records):
    items = taxonomy_items(fams, manifest) + [record_item(r) for r in records]
    fam_by_id = {f['family_id']: f for f in fams}
    rec = [e for r in records for e in record_errors(r, fam_by_id, manifest)]
    return leakage_errors(items), rec


@requires(CP1_DATA)
class CleanSetPasses(unittest.TestCase):
    def test_no_false_positive(self):
        fams, manifest, records = base()
        leak, rec = errors_for(fams, manifest, records)
        self.assertEqual(leak, [])
        self.assertEqual(rec, [])


# Several attacks move a record into a real 'test' family, defined only by the restricted taxonomy.
@requires(CP1_DATA, RESTRICTED_FAMILIES)
class DeliberateLeakage(unittest.TestCase):
    def setUp(self):
        self.fams, self.manifest, self.records = base()

    def assertLeak(self, extra, namespace):
        leak, _ = errors_for(self.fams, self.manifest, self.records + extra)
        self.assertTrue(any(e.startswith(f'LEAK {namespace}=') for e in leak),
                        f'expected a {namespace} leak, got {leak}')
        return leak

    def test_same_family_in_two_splits(self):
        r = mutant(by_id(self.records, 'S13V03-DEV-01'), 'MUT-FAMILY', split='test',
                   input_changes={'raw_arguments': {'url': 'https://status.example.test/v2/ready'}})
        leak = self.assertLeak([r], 'family')
        self.assertTrue(any(e.startswith('LEAK template_id=') for e in leak))
        _, rec = errors_for(self.fams, self.manifest, [r])
        self.assertTrue(any('differs from manifest split' in e for e in rec), rec)

    def test_alias_tool_name_in_other_split(self):
        # `fetch_url_v2` on a new server, declared as a planned family that lives in another split
        target = family_in(self.manifest, 'test', 'read.')
        r = mutant(by_id(self.records, 'S13V03-DEV-01'), 'MUT-ALIAS', family=target, manifest=self.manifest,
                   template_id='tpl.' + target[4:] + '.canonical',
                   input_changes={'server_id': 'synthetic-statuspage-eu', 'tool_name': 'fetch_url_v2',
                                  'tool_description': 'Mirror fetcher.'})
        self.assertLeak([r], 'name')

    def test_alias_identity_in_other_split(self):
        target = family_in(self.manifest, 'validation')
        r = mutant(by_id(self.records, 'S13V03-DEV-02'), 'MUT-IDENT', family=target, manifest=self.manifest,
                   input_changes={'tool_description': 'Renamed description only.'})
        self.assertLeak([r], 'identity')

    def test_near_duplicate_template_renamed_tool(self):
        # DEV-03 structure (same schema, same arguments, same delete trace) under a new tool, server, text
        target = family_in(self.manifest, 'validation', 'delete.')
        r = mutant(by_id(self.records, 'S13V03-DEV-03'), 'MUT-NEARDUP', family=target, manifest=self.manifest,
                   input_changes={'server_id': 'synthetic-pagestore', 'tool_name': 'erase_page',
                                  'tool_description': 'Erase a page permanently.'})
        self.assertLeak([r], 'template_signature')

    def test_shared_description(self):
        dev02 = by_id(self.records, 'S13V03-DEV-02')
        target = family_in(self.manifest, 'calibration', 'send_data.')
        r = mutant(by_id(self.records, 'S13V03-DEV-12'), 'MUT-DESC', family=target, manifest=self.manifest,
                   input_changes={'server_id': 'synthetic-x', 'tool_name': 'shout_text',
                                  'tool_description': dev02['input']['tool_description'].upper()})
        self.assertLeak([r], 'description')

    def test_exact_duplicate_input(self):
        target = family_in(self.manifest, 'test')
        r = mutant(by_id(self.records, 'S13V03-DEV-12'), 'MUT-DUP', family=target, manifest=self.manifest)
        self.assertLeak([r], 'input_sha256')

    def test_transitive_chain_is_caught(self):
        # A (train, DEV-05) --description--> B (validation) --name--> C (test): rejected via a crossing edge
        dev05 = by_id(self.records, 'S13V03-DEV-05')
        val, tst = family_in(self.manifest, 'validation'), family_in(self.manifest, 'test')
        b = mutant(dev05, 'MUT-CHAIN-B', family=val, manifest=self.manifest,
                   input_changes={'server_id': 'synthetic-b', 'tool_name': 'chain_probe'})
        c = mutant(by_id(self.records, 'S13V03-DEV-11'), 'MUT-CHAIN-C', family=tst, manifest=self.manifest,
                   input_changes={'server_id': 'synthetic-c', 'tool_name': 'probe_chain',
                                  'tool_description': 'Unrelated words here.'})
        leak = self.assertLeak([b, c], 'description')
        self.assertTrue(any(e.startswith("LEAK name='chain probe'") for e in leak), leak)
        comp = [g for g in components(taxonomy_items(self.fams, self.manifest) +
                                      [record_item(x) for x in self.records + [b, c]])
                if 'record:MUT-CHAIN-C' in g][0]
        self.assertIn('record:S13V03-DEV-05', comp)

    def test_silent_merge_within_one_split_is_reported(self):
        # Two train families linked by a new record's description: same split, but groups must be merged
        r = mutant(by_id(self.records, 'S13V03-DEV-12'), 'MUT-MERGE',
                   input_changes={'tool_description': by_id(self.records, 'S13V03-DEV-03')['input']['tool_description']})
        leak, _ = errors_for(self.fams, self.manifest, self.records + [r])
        self.assertTrue(any(e.startswith('MERGE') for e in leak), leak)

    def test_declared_group_cannot_span_splits(self):
        r = mutant(by_id(self.records, 'S13V03-DEV-12'), 'MUT-GROUP', split='calibration',
                   input_changes={'raw_arguments': {'text': 'another sentence'}})
        r['family_id'] = family_in(self.manifest, 'calibration')
        self.assertLeak([r], 'leakage_group')


if __name__ == '__main__':
    unittest.main()
