#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import runpy
import sys

if __name__ == "__main__":
    ledger = Path(sys.argv.pop(1))
    with ledger.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"environment_keys": sorted(os.environ)}) + "\n")
    runpy.run_path(str(Path(__file__).with_name("mcp_admission_demo_server.py")), run_name="__main__")

