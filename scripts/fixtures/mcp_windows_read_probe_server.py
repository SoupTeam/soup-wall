#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned discovery fixture; every forwarded tools/call is a boundary failure."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

SCHEMA = {"type": "object", "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096}},
          "required": ["path"], "additionalProperties": False}
TOOLS = [{"name": "read_document", "description": "Read an assigned local document.", "inputSchema": SCHEMA}]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args()
    args.ledger.touch(exist_ok=False)
    args.ledger.with_suffix(".responses").touch(exist_ok=False)
    args.ledger.with_suffix(".started").write_text("started\n", encoding="utf-8")
    args.ledger.with_suffix(".pid").write_text(str(os.getpid()), encoding="ascii")
    try:
        for raw in sys.stdin.buffer:
            with args.ledger.with_suffix(".input").open("ab") as stream:
                stream.write(raw)
            request = json.loads(raw)
            method = request.get("method")
            if method == "initialize":
                result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "soup-wall-windows-read-probe", "version": "1"}}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                with args.ledger.open("ab") as stream:
                    stream.write(raw)
                result = {"isError": False, "content": [{"type": "text", "text": "UNEXPECTED-SERVER-READ"}]}
            else:
                continue
            line = (json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result},
                               ensure_ascii=False) + "\n").encode("utf-8")
            with args.ledger.with_suffix(".responses").open("ab") as stream:
                stream.write(line)
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
    finally:
        args.ledger.with_suffix(".closed").write_text("closed\n", encoding="utf-8")


if __name__ == "__main__":
    main()
