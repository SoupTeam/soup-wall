# SPDX-License-Identifier: Apache-2.0
"""A matching commit cannot make incompatible build declarations compatible."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_build_inventory as INV


class Inventory(unittest.TestCase):
    def test_selected_pair_and_incompatible_native_pilot_remain_distinct(self):
        report = INV.inventory()
        self.assertEqual({job["job"] for job in report["selected_candidates"]}, set(INV.CONSUMERS))
        native = next(job for job in report["jobs"] if job["workflow"] == "mcp-real-filesystem.yml"
                      and job["job"] == "native-ubuntu-2404")
        self.assertEqual(native["environment_toolchains"], ["1.94.1"])
        self.assertFalse(INV.compatible_declaration(native))
        self.assertNotIn(".github/workflows/ci-components.yml", report["workflow_files_sha256"])

    def test_ubuntu_compiler_flags_features_and_profiles_are_not_interchangeable(self):
        selected = INV.inventory()["selected_candidates"][0]
        for field, changed in (("runner", "ubuntu-22.04"), ("toolchain_actions", ["stable"]),
                               ("environment_toolchains", ["1.94.1"])):
            with self.subTest(field=field):
                bad = copy.deepcopy(selected)
                bad[field] = changed
                self.assertFalse(INV.compatible_declaration(bad))
        for declaration in ("RUSTFLAGS: -C opt-level=3", "RUSTC_WRAPPER: other",
                            "CARGO_PROFILE_DEV_OPT_LEVEL: 3"):
            bad = copy.deepcopy(selected)
            bad["build_environment_declarations"].append(declaration)
            self.assertFalse(INV.compatible_declaration(bad))
        for field, changed in (("all_features", True), ("no_default_features", True),
                               ("features", "another-feature"), ("target", "aarch64-unknown-linux-gnu"),
                               ("profile", "release")):
            with self.subTest(field=field):
                bad = copy.deepcopy(selected)
                bad["cargo"][0][field] = changed
                self.assertFalse(INV.compatible_declaration(bad))

    def test_multiline_commands_keep_the_actual_flags(self):
        body = "cargo build --locked " + chr(92) + "\n --offline -p agentfw --bin agentfw\ncargo test -p agentfw --lib filter -- --nocapture\n"
        commands = INV.cargo_commands(body)
        self.assertEqual(len(commands), 2)
        self.assertTrue(commands[0]["offline"])
        self.assertTrue(commands[0]["locked"])
        self.assertEqual(commands[0]["package"], "agentfw")
        self.assertIn("-- --nocapture", commands[1]["command"])


if __name__ == "__main__":
    unittest.main()
