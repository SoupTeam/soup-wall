#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Discovery-only local fixture: record any forwarded call without executing it."""
import argparse
import json
from pathlib import Path
import sys

SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}},
          "required": ["path"], "additionalProperties": False}
TOOLS = [{"name": name, "description": "Read a local document.", "inputSchema": SCHEMA}
         for name in ("read_document", "read_note")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--recipient", required=True)
    args = parser.parse_args()
    # An existing empty ledger, paired with a startup/handshake witness, is
    # distinguishable from a missing server or missing evidence file.
    args.ledger.touch(exist_ok=False)
    args.ledger.with_suffix(".responses").touch(exist_ok=False)
    args.ledger.with_suffix(".started").write_text("started\n", encoding="utf-8")
    for raw in sys.stdin.buffer:
        with args.ledger.with_suffix(".input").open("ab") as stream:
            stream.write(raw)
        request = json.loads(raw)
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "soup-wall-resource-probe", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            with args.ledger.open("ab") as stream:
                stream.write(raw)
            result = {"content": [{"type": "text", "text": "UNEXPECTED-CHILD-EXECUTION"}]}
        else:
            continue
        line = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}) + "\n"
        with args.ledger.with_suffix(".responses").open("a", encoding="utf-8") as stream:
            stream.write(line)
        sys.stdout.write(line)
        sys.stdout.flush()


if __name__ == "__main__":
    main()
