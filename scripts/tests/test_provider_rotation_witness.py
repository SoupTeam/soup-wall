"""The interrupted rotation witness must identify the current index destination."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if sys.platform.startswith("linux"):
    QUALIFIER = load("rotation_witness_qualifier", "qualify-installed-front-door.py")
    STORE = load("rotation_witness_store", "pilot_provider_profiles.py")


@unittest.skipUnless(sys.platform.startswith("linux"), "native Linux provider rotation")
class RotationCommitWitness(unittest.TestCase):
    def trace(self, source=".profile-temporary", destination=None, killed=True):
        destination = STORE.INDEX_FILE if destination is None else destination
        return ((f'123 renameat(4, "{source}", 4, "{destination}") = ?\n' +
                 ('123 +++ killed by SIGKILL +++\n' if killed else '')).encode())

    def test_current_store_index_commit_is_recognized(self):
        self.assertTrue(QUALIFIER.provider_index_commit_interrupted(self.trace(), STORE.INDEX_FILE))

    def test_superseded_or_similar_metadata_name_is_not_the_commit(self):
        for name in ("index.json", "xindex-v2", STORE.INDEX_FILE + "-other"):
            with self.subTest(name=name):
                self.assertFalse(QUALIFIER.provider_index_commit_interrupted(
                    self.trace(destination=name), STORE.INDEX_FILE))

    def test_index_in_source_position_does_not_prove_index_publication(self):
        self.assertFalse(QUALIFIER.provider_index_commit_interrupted(
            self.trace(source=STORE.INDEX_FILE, destination="unrelated"), STORE.INDEX_FILE))

    def test_index_commit_without_the_injected_kill_is_not_interruption(self):
        self.assertFalse(QUALIFIER.provider_index_commit_interrupted(
            self.trace(killed=False), STORE.INDEX_FILE))
