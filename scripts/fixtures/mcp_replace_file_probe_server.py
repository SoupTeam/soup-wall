#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Discovery-only replacement witness. Any tools/call is a test violation."""
import argparse
import json
from pathlib import Path
import sys

IDENTITY_FIELDS = ("device", "inode", "size", "mtime_seconds", "mtime_nanoseconds",
                   "ctime_seconds", "ctime_nanoseconds", "uid", "gid", "mode")
SCHEMA = {"type": "object", "properties": {
    "path": {"type": "string", "minLength": 1, "maxLength": 4096},
    "content": {"type": "string", "maxLength": 4096},
    "old_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
    "old_identity": {"type": "object", "properties": {key: {"type": "integer"} for key in IDENTITY_FIELDS},
                     "required": list(IDENTITY_FIELDS), "additionalProperties": False}},
    "required": ["path", "content", "old_sha256", "old_identity"], "additionalProperties": False}
TOOLS = [{"name": "replace_result", "description": "Replace the exact output file with the supplied bounded text.", "inputSchema": SCHEMA},
         {"name": "read_document", "description": "Read the output document.", "inputSchema": {
             "type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}}]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    ledger = parser.parse_args().ledger
    ledger.touch(exist_ok=False)
    for raw in sys.stdin.buffer:
        request = json.loads(raw)
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "sou159-discovery-only", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            with ledger.open("ab") as output:
                output.write(raw)
            result = {"isError": True, "content": [{"type": "text", "text": "UNEXPECTED-CHILD-DISPATCH"}]}
        else:
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
