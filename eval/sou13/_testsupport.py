# SPDX-License-Identifier: Apache-2.0
"""Explicit private-artifact gating for the SOU-13 test suites (test-only; not imported by production code).

The public repository ships SOU-13 source, schemas and tests but none of the frozen CP1/CP2 datasets, review
working files or custodian-only material. A test that reads such an artifact is decorated with ``requires``,
naming the exact relative paths it needs. When any of them is absent it is skipped with a message listing the
missing paths, so every public skip is attributable to a named private dependency.

Skips never hide failures: a test whose artifacts are present always runs, and ``SOU13_REQUIRE_PRIVATE=1``
disables every skip here, so a private run with a missing artifact errors instead of passing quietly.
Only existence is checked; this module never reads artifact contents.
"""
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STRICT_ENV = 'SOU13_REQUIRE_PRIVATE'

# CP1 frozen dataset and review working files (owner-local; covered by data/freeze.json).
CP1_DATA = ('data/dev16.jsonl', 'data/dev_supplementary.jsonl')
CP1_FREEZE = ('data/freeze.json',)
CP1_REVIEW = ('review/DEV16_REVIEW_QUEUE.csv', 'review/DEV16_REVIEW_PACKAGE.md')
# Open-question registers read by the CP1 validator and the CP2 record checks (owner-local documents).
OPEN_QUESTIONS = ('docs/OPEN_QUESTIONS.md', 'docs/CP2_OPEN_QUESTIONS.md')
# CP2 development-side artifacts (unreleased dev exports and manifests; not test material).
CP2_PUBLIC_VIEW = ('cp2/manifests/split_manifest.PUBLIC_VIEW.json',)
CP2_PUBLIC = CP2_PUBLIC_VIEW + ('cp2/taxonomy/families.PUBLIC.json', 'cp2/ids/case_ids.PUBLIC.json',
                                'cp2/data/candidates.jsonl')
# Custodian-only material. Existence is probed; Claude Code and public CI never read it.
RESTRICTED_FAMILIES = ('cp2_sealed/restricted/test_families.json',)
FULL_MANIFEST = ('cp2_sealed/manifest/split_manifest.FULL.json',)
SEALED_CANDIDATES_ART = ('cp2_sealed/candidates_test.jsonl',)  # not pipeline.SEALED_CANDIDATES (a path)
# Everything sou13cp2.pipeline.commitments() hashes.
SEALED_COMMITTED = RESTRICTED_FAMILIES + FULL_MANIFEST + SEALED_CANDIDATES_ART + (
    'cp2_sealed/test_labels.jsonl', 'cp2_sealed/model_inputs_test.jsonl', 'cp2_sealed/ids/case_ids.TEST.json')


# Owner trust anchor for a FROZEN manifest (sou13cp2.anchor.ENV; the signature defaults to <anchor>.sig). It is
# supplied from outside the repository; pipeline.validate() refuses a frozen manifest without it (audit F2).
OWNER_ANCHOR_ENV = ('SOU13_CP2_ANCHOR', 'SOU13_CP2_ALLOWED_SIGNERS', 'SOU13_CP2_TRUSTED_KEY_FPR', 'SOU13_CP2_SIGNER')


def requires_owner_anchor():
    """Skip (unless strict) when the owner trust-anchor configuration is not set in the environment."""
    absent = [v for v in OWNER_ANCHOR_ENV if not os.environ.get(v)]
    if not absent or strict():
        return lambda obj: obj
    return unittest.skip('PRIVATE ARTIFACT MISSING: owner trust-anchor configuration ' + ', '.join(absent))


def strict():
    return os.environ.get(STRICT_ENV) == '1'


def missing(*groups):
    return [p for g in groups for p in g if not (ROOT / p).exists()]


def _reason(absent):
    return 'PRIVATE ARTIFACT MISSING: ' + ', '.join(absent)


def requires(*groups):
    """Class or method decorator: skip only when a named artifact is absent and strict mode is off."""
    absent = missing(*groups)
    if not absent or strict():
        return lambda obj: obj
    return unittest.skip(_reason(absent))


def skip_unless_present(case, *groups):
    """In-test equivalent of ``requires`` for checks that branch on artifact availability."""
    absent = missing(*groups)
    if absent and not strict():
        case.skipTest(_reason(absent))
