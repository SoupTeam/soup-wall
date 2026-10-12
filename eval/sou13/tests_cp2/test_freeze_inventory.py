# SPDX-License-Identifier: Apache-2.0
"""Public, data-free guard for frozen source identity.

The digests below are copied from two owner-local records and identify SOURCE files only (no data):
  * CP1 freeze (data/freeze.json, `source_sha256_lf_normalised`): every file matched by sou13/build.py
    SOURCE_GLOBS, hashed by sou13.build.source_hashes (LF-normalised text, canonical JSON string hash).
  * CP2 dev review package (handoff/dev_review_package/MANIFEST.json, `files_sha256`): raw-byte SHA-256 of the
    shipped interpreter tools, schemas and requirements.
If either test fails, a frozen file changed or a file was added to a frozen glob: restore the original bytes.
Do not update these digests to make the test pass; a new freeze needs owner approval.
"""
import unittest

from sou13.build import ROOT as CP1_ROOT
from sou13.build import SOURCE_GLOBS, source_hashes
from sou13.hashing import file_sha
from sou13cp2 import ROOT

CP1_SOURCE_LF_NORMALISED = {
    'scripts/build_dev16.py': 'e883f656aed257e03c9538ab8b75748c684d89aee5673a4dc7cd20b1c97c6fef',
    'scripts/validate.py': 'ef69789b95125f928290817af470271341d5d1ae8fdf0043051c7618ff437b2d',
    'sou13/__init__.py': '2e0bbf58a5603a213d2e4e0f3f74ec53b5d07e6daa329051ddb53b95bebecad9',
    'sou13/build.py': 'e8ce5b2b7b151a97ce6a2b928253bd12d7918a7fd664597b696dc2790183cded',
    'sou13/cases.py': 'cf641bca4175216fe38c80792ea501a298e2122de4bfc78857350ab62a1e65dc',
    'sou13/fixtures.py': 'fa0a377c28351c481a7c9b4bfd289b00f120e378939578c3bd1c24cde3b8855b',
    'sou13/hashing.py': 'bdcf9b9ccc32ffe3fc93cad4e6d42cbf16f8cdad173512560e4cbbd7da3f0a86',
    'sou13/labels.py': '706f96ee01c15b08adfceae67361d42d6bfff525c5cd794c79a6a7056513b6f6',
    'sou13/sandbox.py': '2bc095d84f525caa9408f0e57334ae892febe0c5139eced56cada502ba6efd3f',
    'sou13/validate.py': '8509b53be86c3bf8469a4f7da286cea89f6a5a3e70771d905383feca1421c1d9',
}

# repository path -> (path inside the dev review package, raw-byte SHA-256)
CP2_DEV_PACKAGE_RAW = {
    'sou13cp2/compute.py': ('tools/compute.py', '80db8d5e13c46c5c585079522ecdf7e5d01e50a34292171427ed2c02c525228f'),
    'sou13/hashing.py': ('tools/hashing.py', 'ff6f269371dbf2f37330f9969f257d8f48acde1a08425f61d79977b6f546454a'),
    'sou13cp2/semantics.py': ('tools/semantics.py',
                              'f169215c57df044cd9e2a0a5bd3e5037fa909bad508331e022056a3850097758'),
    'schema/cp2_case.schema.json': ('schema/cp2_case.schema.json',
                                    'e6c55cdc7e08e0fb21cd7443b1f9ab7a7dd310383233111ae67f0a49ab57c5fb'),
    'schema/case.schema.cp1-fix1.json': ('schema/case.schema.cp1-fix1.json',
                                         '2cb56a412b06a4d0d4ab34188840cb4309a01b1ee42de56365fef08534f39d52'),
    'requirements-cp2.txt': ('requirements-cp2.txt',
                             'e753f83a5b97f2ef170bd0daee9d1f771db27195321976a10a074e5bf4099769'),
}


# Frozen with CRLF line endings; .gitattributes stores them verbatim (-text). Raw digests are those of the
# owner tree (verified byte-identical by scripts_cp2/verify_source_identity.py).
CRLF_VERBATIM = {
    'schema/case.schema.cp1-fix1.json': '2cb56a412b06a4d0d4ab34188840cb4309a01b1ee42de56365fef08534f39d52',
    'schema/case.schema.json': '71dbcfc801a7592e72fe4ce24da2e6ab5210d9a7b452192568452bbe3c67632a',
    'sou13/cases.py': 'c83759a9005d49a2d78794c2daeb8fb95bd0faa666c8c9a5f4cc8098a762e6a3',
}


class LineEndingsSurviveCheckout(unittest.TestCase):
    def test_crlf_frozen_files_are_byte_identical(self):
        for rel, digest in CRLF_VERBATIM.items():
            with self.subTest(rel=rel):
                data = (ROOT / rel).read_bytes()
                self.assertEqual(data.count(b'\n'), data.count(b'\r\n'), 'line endings were normalised')
                self.assertEqual(file_sha(ROOT / rel), digest)

    def test_other_pinned_files_are_lf(self):
        for rel in CP2_DEV_PACKAGE_RAW:
            if rel not in CRLF_VERBATIM:
                with self.subTest(rel=rel):
                    self.assertNotIn(b'\r', (ROOT / rel).read_bytes())


class Cp1FreezeSourceInventory(unittest.TestCase):
    def test_roots_agree(self):
        self.assertEqual(CP1_ROOT, ROOT)

    def test_globs_are_the_frozen_ones(self):
        self.assertEqual(SOURCE_GLOBS, ('sou13/*.py', 'scripts/*.py'))

    def test_source_inventory_and_digests_match_the_freeze(self):
        # Equality of the whole mapping also rejects any file added to sou13/ or scripts/.
        self.assertEqual(source_hashes(CP1_ROOT), CP1_SOURCE_LF_NORMALISED)


class Cp2DevPackageRawBytes(unittest.TestCase):
    def test_pinned_files_are_byte_identical(self):
        for rel, (package_rel, digest) in CP2_DEV_PACKAGE_RAW.items():
            with self.subTest(rel=rel, package=package_rel):
                self.assertEqual(file_sha(ROOT / rel), digest)

    def test_case_id_pattern_matches_the_allocator(self):
        # The superseded overlay schema allowed only 10 hex digits; the allocator issues 32 (128 bits).
        from sou13cp2.case_ids import ID_RE
        from sou13cp2.schemas import CP2_SCHEMA, validator
        pattern = validator(CP2_SCHEMA).schema['properties']['id']['pattern']
        self.assertIn('S13C2-[0-9A-F]{32}', pattern)
        self.assertEqual(ID_RE.pattern, r'^S13C2-[0-9A-F]{32}$')


if __name__ == '__main__':
    unittest.main()
