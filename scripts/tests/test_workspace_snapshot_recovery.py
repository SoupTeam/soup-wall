# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SNAPSHOT = Path(__file__).resolve().parents[1] / "pilot_workspace_snapshot.py"


class SnapshotRecovery(unittest.TestCase):
    @unittest.skipIf(sys.platform == "linux", "Unsupported-platform check")
    def test_inventory_refuses_unsupported_platform(self):
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import sys; from pilot_workspace_snapshot import main; "
                "sys.exit(main(sys.argv[1:]))",
                "recovery-inventory", "--store", ".",
            ],
            cwd=SNAPSHOT.parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertEqual(
            "workspace_snapshot_recovery_platform_unsupported",
            json.loads(result.stdout)["reason"],
        )

    @unittest.skipUnless(sys.platform == "linux", "Linux snapshot store required")
    def test_inventory_leaves_legacy_stage_for_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory).resolve()
            stage = store / (".snapshot-" + "a" * 32)
            stage.mkdir(mode=0o700)
            marker = stage / "partial"
            marker.write_bytes(b"partial capture")
            result = subprocess.run(
                [
                    sys.executable, "-c",
                    "import sys; from pilot_workspace_snapshot import main; "
                    "sys.exit(main(sys.argv[1:]))",
                    "recovery-inventory", "--store", str(store),
                ],
                cwd=SNAPSHOT.parent,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr or result.stdout)
            rows = json.loads(result.stdout)["stages"]
            self.assertEqual([(stage.name, "unknown")], [
                (row["stage"], row["state"]) for row in rows
            ])
            self.assertEqual(b"partial capture", marker.read_bytes())
