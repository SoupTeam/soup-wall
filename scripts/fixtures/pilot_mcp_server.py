#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lightweight stdio MCP server fixture for SOU-99 Claude Code pilot launcher acceptance.

Supports both filesystem and git server roles with standard JSON-RPC 2.0 stdio framing.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def make_fs_tools():
    return [
        {
            "name": "read_text_file",
            "description": "Read the complete contents of a file from the file system as text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "list_directory",
            "description": "Get a detailed listing of all files and directories.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    ]


def make_git_tools():
    return [
        {
            "name": "git_status",
            "description": "Shows the working tree status",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo_path": {"type": "string"}
                },
                "required": ["repo_path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "git_reset",
            "description": "Unstages all staged changes or resets HEAD",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo_path": {"type": "string"}
                },
                "required": ["repo_path"],
                "additionalProperties": False,
            },
        },
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=["filesystem", "git"], required=True)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--tools", type=str, default=None, help="Comma-separated list of tools to expose")
    args, _ = parser.parse_known_args()

    all_tools = make_fs_tools() if args.role == "filesystem" else make_git_tools()
    if args.tools:
        allowed = {t.strip() for t in args.tools.split(",") if t.strip()}
        tools = [t for t in all_tools if t["name"] in allowed]
    else:
        tools = all_tools

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": f"soup-wall-{args.role}",
                        "version": "1.0.0",
                    },
                },
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "notifications/initialized":
            pass
        elif method == "ping":
            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {},
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "tools/list":
            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": tools},
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                if tool_name == "read_text_file":
                    p = Path(tool_args["path"])
                    content = p.read_text(encoding="utf-8")
                    result = {"content": [{"type": "text", "text": content}]}
                elif tool_name == "list_directory":
                    p = Path(tool_args.get("path", args.workspace))
                    entries = [e.name for e in p.iterdir()]
                    result = {"content": [{"type": "text", "text": json.dumps(entries)}]}
                elif tool_name == "git_status":
                    result = {"content": [{"type": "text", "text": "On branch main\nnothing to commit, working tree clean"}]}
                elif tool_name == "git_show":
                    result = {"content": [{"type": "text", "text": "commit 0123456789abcdef\nAuthor: pilot <pilot@example.com>"}]}
                elif tool_name == "git_diff":
                    result = {"content": [{"type": "text", "text": ""}]}
                elif tool_name == "git_reset":
                    result = {"content": [{"type": "text", "text": "Unstaged changes after reset"}]}
                else:
                    result = {"content": [{"type": "text", "text": f"unknown tool {tool_name}"}], "isError": True}
            except Exception as ex:
                result = {"content": [{"type": "text", "text": f"tool error: {ex}"}], "isError": True}

            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result,
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif msg_id is not None:
            res = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method {method} not found"},
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
