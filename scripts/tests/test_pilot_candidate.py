# SPDX-License-Identifier: Apache-2.0
"""Negative custody controls using inert owned bytes, never runtime evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts"))
import pilot_candidate as c
import candidate_fixture

class CandidateControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.commit="a"*40
        self.receipt=candidate_fixture.populate(self.root,self.commit)

    def test_complete_inert_inventory_preserves_no_protection_claim(self):
        result=c.validate_directory(self.root,self.commit)
        self.assertFalse(result["active_protection"])
        self.assertEqual(set(result["binaries"]),{"agentfw","git_launcher"})

    def test_each_missing_changed_or_wrong_mode_input_refuses(self):
        for name in (*c.FILES,"agentfw"):
            with self.subTest(name=name):
                path=self.root/name;raw=path.read_bytes();mode=path.stat().st_mode & 0o777
                path.unlink()
                with self.assertRaises((OSError,ValueError,KeyError)):c.validate_directory(self.root,self.commit)
                path.write_bytes(raw+b"changed");path.chmod(mode)
                with self.assertRaises((ValueError,KeyError)):c.validate_directory(self.root,self.commit)
                path.write_bytes(raw);path.chmod(0o600)
                with self.assertRaises(ValueError):c.validate_directory(self.root,self.commit)
                path.chmod(mode)

    def test_wrong_source_compiler_and_component_custody_refuse(self):
        for change in (lambda r:r.update(toolchain="1.94.1"), lambda r:r.update(lane="debug"),
                       lambda r:r["source"].update(commit="f"*40),
                       lambda r:r.update(component_manifest_sha256="f"*64),
                       lambda r:r["binaries"]["git_launcher"].update(sha256="f"*64)):
            receipt=copy.deepcopy(self.receipt);change(receipt)
            (self.root/c.RECEIPT).write_bytes(c.canonical(receipt))
            with self.assertRaises(ValueError):c.validate_directory(self.root,self.commit)
        (self.root/c.RECEIPT).write_bytes(c.canonical(self.receipt))
        with self.assertRaises(ValueError):c.validate_directory(self.root,"f"*40)

    def test_links_duplicate_fields_and_unbounded_metadata_refuse(self):
        path=self.root/c.SOURCE;raw=path.read_bytes();path.unlink()
        path.symlink_to(self.root/c.RECEIPT)
        with self.assertRaises(ValueError):c.validate_directory(self.root,self.commit)
        path.unlink();path.write_bytes(raw)
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b' '*65537):
            with self.assertRaises(ValueError):c.parse(raw)
