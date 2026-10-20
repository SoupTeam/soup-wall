#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Discovery-only macOS SOU-94 witness: record calls, never create or read their paths."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

CREATE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": 4096},
        "content": {"type": "string", "maxLength": 4096},
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}
READ_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": 4096},
    },
    "required": ["path"],
    "additionalProperties": False,
}
CUSTOM_CREATE_SCHEMA = {
    "type": "object",
    "properties": {
        "spec": {
            "type": "object",
            "properties": {
                "destination": {"type": "string", "minLength": 1, "maxLength": 4096},
                "payload": {"type": "string", "maxLength": 4096},
            },
            "required": ["destination", "payload"],
            "additionalProperties": False,
        }
    },
    "required": ["spec"],
    "additionalProperties": False,
}
CUSTOM_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {
            "type": "object",
            "properties": {
                "target_file": {"type": "string", "minLength": 1, "maxLength": 4096},
            },
            "required": ["target_file"],
            "additionalProperties": False,
        }
    },
    "required": ["query"],
    "additionalProperties": False,
}
TOOLS = [
    {
        "name": "create_file",
        "description": "Create one new UTF-8 file in the approved workspace on macOS APFS.",
        "inputSchema": CREATE_SCHEMA,
    },
    {
        "name": "read_document",
        "description": "Read an approved UTF-8 document on macOS APFS.",
        "inputSchema": READ_SCHEMA,
    },
    {
        "name": "custom_create_file",
        "description": "SOU-67 custom create file on macOS APFS.",
        "inputSchema": CUSTOM_CREATE_SCHEMA,
    },
    {
        "name": "custom_read_document",
        "description": "SOU-67 custom read document on macOS APFS.",
        "inputSchema": CUSTOM_READ_SCHEMA,
    },
]


def append(path: Path, raw: bytes):
    with path.open("ab") as handle:
        handle.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    args = parser.parse_args()
    args.ledger.touch(exist_ok=False)
    args.ledger.with_suffix(".input").touch(exist_ok=False)
    args.ledger.with_suffix(".responses").touch(exist_ok=False)
    args.ledger.with_suffix(".started").write_text("started\n", encoding="utf-8")
    for raw in sys.stdin.buffer:
        append(args.ledger.with_suffix(".input"), raw)
        try:
            request = json.loads(raw)
        except Exception:
            continue
        method = request.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "soup-wall-macos-file-probe", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            append(args.ledger, raw)
            result = {
                "isError": True,
                "content": [{"type": "text", "text": "UNEXPECTED-CHILD-EXECUTION"}],
            }
        else:
            continue
        line = (
            json.dumps(
                {"jsonrpc": "2.0", "id": request["id"], "result": result},
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode()
        append(args.ledger.with_suffix(".responses"), line)
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    args.ledger.with_suffix(".closed").write_text("closed\n", encoding="utf-8")


if __name__ == "__main__":
    main()
