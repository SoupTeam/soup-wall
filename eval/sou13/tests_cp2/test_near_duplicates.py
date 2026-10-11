"""Field-renamed near-duplicate templates (pre-freeze near-duplicate audit, 2026-10-11).

template_signature contains argument names, so a re-described copy with renamed fields escaped the leakage graph
(fam.unknown.partner_rpc in validation vs fam.unknown.vendor_bridge in train). shape_signature ignores names; every
shared shape must be adjudicated, near_duplicate verdicts link families into one leakage component, and shape alone
never links (no blanket grouping of unrelated tools with the same effect)."""
import json
import unittest

from sou13cp2 import ROOT, restricted
from sou13cp2 import taxonomy as T
from _testsupport import CP2_PUBLIC_VIEW, FULL_MANIFEST, RESTRICTED_FAMILIES, requires, skip_unless_present
from sou13cp2.identity import program_skeleton, shape_signature
from sou13cp2.leakage import cross_split_errors, taxonomy_items
from sou13cp2.pipeline import FULL_MANIFEST_FILE, PUBLIC_ARTEFACTS, PUBLIC_VIEW_FILE
from sou13cp2.splits import assign, leakage_groups, manifest_errors


def fam(fid, ident, desc, props, profile, exposure='none', review=None):
    f = T._planned(fid, 'mechanism of ' + fid, 'synthetic test family', [ident], desc, T.S(props), profile)
    f['exposure'] = exposure
    if review:
        f['shape_review'] = review
    return T._finalise(f)


RPC = dict(props={'procedure': 'string', 'args': 'object'}, profile=[T.OPAQUE])
BRIDGE = dict(props={'operation': 'string', 'payload': 'object'}, profile=[T.OPAQUE])


def pair(review=None, exposure_b='none'):
    a = fam('fam.unknown.syn_rpc', ('synthetic-a', 'call_proc'), 'Call a procedure on the partner system.', **RPC)
    b = fam('fam.unknown.syn_bridge', ('synthetic-b', 'bridge_invoke'), 'Invoke an operation on the partner.',
            exposure=exposure_b, review=review, **BRIDGE)
    return T.attach_near_duplicates([a, b])


def groups(fams):
    return sorted(sorted(f['family_id'] for f in members) for _, members in leakage_groups(fams))


class ShapeSignature(unittest.TestCase):
    def test_renamed_fields_share_shape_but_not_template_signature(self):
        a, b = pair()
        self.assertNotEqual(a['templates'][0]['signature'], b['templates'][0]['signature'])
        self.assertEqual(a['templates'][0]['shape_signature'], b['templates'][0]['shape_signature'])

    def test_shape_keeps_types_effects_and_evidence(self):
        base = shape_signature(T.S({'x': 'string', 'y': 'object'}), [T.OPAQUE], T.DECL)
        self.assertEqual(base, shape_signature(T.S({'q': 'string', 'z': 'object'}), [T.OPAQUE], T.DECL))
        self.assertNotEqual(base, shape_signature(T.S({'x': 'string', 'y': 'string'}), [T.OPAQUE], T.DECL))
        self.assertNotEqual(base, shape_signature(T.S({'x': 'string', 'y': 'object'}), ['store_delete'], T.DECL))
        self.assertNotEqual(base, shape_signature(T.S({'x': 'string', 'y': 'object'}), [T.OPAQUE],
                                                  'controlled_execution'))
        self.assertNotEqual(base, shape_signature(T.S({'x': 'string', 'y': 'object'}, ['x']), [T.OPAQUE], T.DECL))


class Adjudication(unittest.TestCase):
    def test_unreviewed_renamed_copy_is_an_error_not_silently_split(self):
        errs = T.shape_review_errors(pair())
        self.assertEqual(len(errs), 1)
        self.assertIn('unreviewed field-renamed near-duplicate candidate', errs[0])

    def test_near_duplicate_verdict_links_into_one_component(self):
        fams = pair({'fam.unknown.syn_rpc': {'verdict': T.NEAR_DUPLICATE, 'rationale': 'same partner call, renamed'}})
        self.assertEqual(T.shape_review_errors(fams), [])
        self.assertEqual(groups(fams), [['fam.unknown.syn_bridge', 'fam.unknown.syn_rpc']])

    def test_near_duplicate_follows_the_cp1_exposure_pin_to_train(self):
        fams = pair({'fam.unknown.syn_rpc': {'verdict': T.NEAR_DUPLICATE, 'rationale': 'same partner call, renamed'}},
                    exposure_b='cp1_shared')
        g, _ = assign(fams)
        self.assertEqual([x['split'] for x in g], ['train'])

    def test_distinct_verdict_does_not_link(self):
        fams = pair({'fam.unknown.syn_rpc': {'verdict': T.DISTINCT, 'rationale': 'local macro vs external partner'}})
        self.assertEqual(T.shape_review_errors(fams), [])
        self.assertEqual(len(groups(fams)), 2)

    def test_review_needs_verdict_and_rationale(self):
        for bad in ({'verdict': 'maybe', 'rationale': 'x' * 30}, {'verdict': T.DISTINCT, 'rationale': 'short'}):
            self.assertTrue(T.shape_review_errors(pair({'fam.unknown.syn_rpc': bad})))

    def test_same_effect_different_shape_is_not_grouped_or_flagged(self):
        # unrelated tools of one class: same effect profile, different argument structure -> no candidate, no link
        a = fam('fam.delete.syn_one', ('synthetic-c', 'drop_one'), 'Delete one entry.', {'key': 'string'},
                ['store_delete'])
        b = fam('fam.delete.syn_two', ('synthetic-d', 'drop_pair'), 'Delete a pair entry.',
                {'a': 'string', 'b': 'string'}, ['store_delete'])
        fams = T.attach_near_duplicates([a, b])
        self.assertEqual(T.shape_candidates(fams), [])
        self.assertEqual(T.shape_review_errors(fams), [])
        self.assertEqual(len(groups(fams)), 2)


class ProgramSkeleton(unittest.TestCase):
    OPQ = [{'op': 'opaque', 'component': ['rpc:', '$procedure']}]

    def test_renamed_arguments_and_constants_keep_the_skeleton(self):
        self.assertEqual(program_skeleton(self.OPQ),
                         program_skeleton([{'op': 'opaque', 'component': ['macro:', '$name']}]))
        self.assertEqual(program_skeleton([{'op': 'delete', 'store': 'cache', 'key': '$key'}]),
                         program_skeleton([{'op': 'delete', 'store': 'docs', 'key': '$document_id'}]))
        self.assertEqual(
            program_skeleton([{'op': 'acl_set', 'resource': ['files/', '$f'], 'principal': 'anyone', 'role': '$v'}]),
            program_skeleton([{'op': 'acl_set', 'resource': ['objects/', '$o'], 'principal': 'mode', 'role': '$m'}]))

    def test_semantic_differences_change_the_skeleton(self):
        base = program_skeleton([{'op': 'delete', 'store': 's', 'key': '$k'}])
        for other in ([{'op': 'delete_prefix', 'store': 's', 'prefix': '$k'}],                      # other operation
                      [{'op': 'delete', 'store': 's', 'key': ['$a', '/', '$b']}],                    # composite key
                      [{'op': 'foreach', 'arg': 'ids', 'as': 'i', 'do': [{'op': 'delete', 'store': 's', 'key': '@i'}]}],
                      [{'op': 'delete', 'store': 's', 'key': 'fixed'}]):                            # constant key
            self.assertNotEqual(base, program_skeleton(other), other)
        self.assertNotEqual(program_skeleton([{'op': 'compute', 'fn': 'plan', 'inputs': ['$a']}]),
                            program_skeleton([{'op': 'compute', 'fn': 'word_count', 'inputs': ['$a']}]))
        self.assertNotEqual(program_skeleton([{'op': 'send', 'channel': 'sms', 'to': '$a', 'payload': '$b'}]),
                            program_skeleton([{'op': 'send', 'channel': 'chat', 'to': '$a', 'payload': '$b'}]))
        self.assertIsNone(program_skeleton(None))

    def _pair_with(self, verdict, skel_b):
        fams = pair({'fam.unknown.syn_rpc': {'verdict': verdict, 'rationale': 'different domain wording only here'}})
        fams[0]['program_skeleton'] = program_skeleton(self.OPQ)
        fams[1]['program_skeleton'] = skel_b
        return fams

    def test_distinct_rejected_when_shape_and_skeleton_match(self):
        errs = T.shape_review_errors(self._pair_with(T.DISTINCT, program_skeleton(self.OPQ)))
        self.assertEqual(len(errs), 1)
        self.assertIn('do not establish independence', errs[0])

    def test_near_duplicate_accepted_when_shape_and_skeleton_match(self):
        self.assertEqual(T.shape_review_errors(self._pair_with(T.NEAR_DUPLICATE, program_skeleton(self.OPQ))), [])

    def test_distinct_allowed_when_skeleton_differs(self):
        other = program_skeleton([{'op': 'switch', 'on': '$r', 'cases': {'x': self.OPQ}}])
        self.assertEqual(T.shape_review_errors(self._pair_with(T.DISTINCT, other)), [])


class RetiredCaseIds(unittest.TestCase):
    def test_retired_ids_are_kept_and_never_reissued(self):
        import tempfile
        from pathlib import Path
        from sou13cp2 import case_ids as C
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            C.allocate([C.key('fam.delete.syn_old', i) for i in range(3)], root)
            old = dict(C._read(C.PUBLIC_MAP, root))
            self.assertEqual(C.retire(['fam.delete.syn_old'], C.PUBLIC_MAP, root), 3)
            self.assertEqual(C._read(C.PUBLIC_MAP, root), {})
            self.assertEqual(C._read(C.PUBLIC_MAP, root, retired=True), old)
            C.allocate([C.key('fam.delete.syn_new', i) for i in range(3)], root)
            self.assertFalse(set(C._read(C.PUBLIC_MAP, root).values()) & set(old.values()))
            self.assertEqual(C.map_errors(root), [])
            # re-issuing a retired id is detected
            data = json.loads((root / C.PUBLIC_MAP).read_text(encoding='utf-8'))
            data['ids'][C.key('fam.delete.syn_new', 0)] = next(iter(old.values()))
            (root / C.PUBLIC_MAP).write_text(json.dumps(data), encoding='utf-8')
            C.clear_cache()
            self.assertIn('a retired case id was re-issued', C.map_errors(root))
            C.clear_cache()


@requires(CP2_PUBLIC_VIEW)
class RealTaxonomy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fams = T.families()
        cls.manifest = json.loads((ROOT / FULL_MANIFEST_FILE).read_text(encoding='utf-8')) \
            if restricted.available() else json.loads((ROOT / PUBLIC_VIEW_FILE).read_text(encoding='utf-8'))

    def test_every_shared_shape_is_adjudicated(self):
        self.assertEqual(T.shape_review_errors(self.fams), [])

    def test_partner_rpc_and_vendor_bridge_share_component_and_train(self):
        groups_ = {f['family_id']: g for g, members in leakage_groups(self.fams) for f in members}
        self.assertEqual(groups_['fam.unknown.partner_rpc'], groups_['fam.unknown.vendor_bridge'])
        self.assertEqual(self.manifest['family_split']['fam.unknown.partner_rpc'], 'train')
        self.assertEqual(self.manifest['family_split']['fam.unknown.vendor_bridge'], 'train')

    def test_only_adjudicated_near_duplicates_are_linked(self):
        # public view of the links; P-2 added by owner decision 2026-10-11 (SAME_TEMPLATE)
        linked = {f['family_id']: f['near_duplicates'] for f in self.fams if f['near_duplicates']}
        self.assertEqual(linked, {'fam.unknown.partner_rpc': ['fam.unknown.vendor_bridge'],
                                  'fam.unknown.vendor_bridge': ['fam.unknown.partner_rpc'],
                                  'fam.delete.cache_purge': ['fam.delete.document_delete'],
                                  'fam.delete.document_delete': ['fam.delete.cache_purge']})

    def test_p2_linked_and_kept_in_train(self):
        groups_ = {f['family_id']: g for g, members in leakage_groups(self.fams) for f in members}
        self.assertEqual(groups_['fam.delete.cache_purge'], groups_['fam.delete.document_delete'])
        for fid in ('fam.delete.cache_purge', 'fam.delete.document_delete'):
            self.assertEqual(self.manifest['family_split'][fid], 'train')

    def test_no_distinct_verdict_on_equal_shape_and_skeleton(self):
        by = {f['family_id']: f for f in self.fams}
        reviews = T.shape_reviews(self.fams)
        for a, b in T.shape_candidates(self.fams):
            if T.same_skeleton(by[a], by[b]):
                self.assertEqual(reviews[(a, b)]['verdict'], T.NEAR_DUPLICATE, (a, b))

    def test_cross_split_pairs_never_share_shape_and_skeleton(self):
        if not restricted.available():
            skip_unless_present(self, RESTRICTED_FAMILIES, FULL_MANIFEST)
        by = {f['family_id']: f for f in self.fams}
        split = self.manifest['family_split']
        for a, b in T.shape_candidates(self.fams):
            if split[a] != split[b]:
                self.assertFalse(T.same_skeleton(by[a], by[b]), 'cross-split same template')

    def test_public_code_and_docs_never_name_test_families(self):
        if not restricted.available():
            skip_unless_present(self, RESTRICTED_FAMILIES, FULL_MANIFEST)
        ids = restricted.family_ids()
        for p in list(ROOT.glob('sou13cp2/*.py')) + list(ROOT.glob('scripts_cp2/*.py')) + \
                list(ROOT.glob('tests_cp2/*.py')) + list(ROOT.glob('docs/*.md')):
            text = p.read_text(encoding='utf-8', errors='replace')
            for fid in ids:
                self.assertNotIn(fid, text, p.name)

    def test_no_cross_split_leak_including_near_duplicate_edges(self):
        if not restricted.available():
            skip_unless_present(self, RESTRICTED_FAMILIES, FULL_MANIFEST)
        self.assertEqual(manifest_errors(self.manifest, self.fams), [])
        self.assertEqual(cross_split_errors(taxonomy_items(self.fams, self.manifest)), [])

    def test_restricted_shape_reviews_not_in_public_artefacts(self):
        if not restricted.available():
            skip_unless_present(self, RESTRICTED_FAMILIES, FULL_MANIFEST)
        test_ids = restricted.family_ids()
        public = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for rel in PUBLIC_ARTEFACTS + (PUBLIC_VIEW_FILE,)
                           for p in ([ROOT / rel] if (ROOT / rel).is_file() else (ROOT / rel).rglob('*'))
                           if p.is_file())
        self.assertNotIn('shape_review', public)
        for fid in test_ids:
            self.assertNotIn(fid, public)


if __name__ == '__main__':
    unittest.main()
