# SPDX-License-Identifier: Apache-2.0
"""Owned Windows MCP fixture for native connection acceptance."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from mcp_windows_create_probe_server import TOOLS

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args()
    args.ledger.touch()
    args.ledger.with_suffix(".environment").write_text(json.dumps({
        "provider_key_present": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "sentinel_present": bool(os.environ.get("SOUP_CONNECTION_SENTINEL")),
    }), encoding="utf-8")
    for raw in sys.stdin.buffer:
        frame = json.loads(raw)
        method = frame.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "owned-windows-connection", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            with args.ledger.open("ab") as stream:
                stream.write(raw)
            values = frame["params"]["arguments"]
            if frame["params"]["name"] == "read_document":
                text = Path(values["path"]).read_text(encoding="utf-8")
            else:
                with Path(values["path"]).open("x", encoding="utf-8") as stream:
                    stream.write(values["content"])
                text = "created"
            result = {"content": [{"type": "text", "text": text}]}
        else:
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "result": result},
                         ensure_ascii=False), flush=True)

if __name__ == "__main__":
    main()
