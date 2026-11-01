#!/usr/bin/env python3
"""Show the installed offline command catalog and safe shell completion."""
from __future__ import annotations
import argparse, json, sys

CATALOG = {"schema": "sw-agent-command-catalog/1", "version": "0.3.0", "commands": [
    {"name": "doctor", "kind": "read", "flags": ["--json", "--support-bundle"]},
    {"name": "doctor compare", "kind": "read", "flags": ["--json-out", "--markdown-out"]},
    {"name": "protection-status", "kind": "read", "flags": ["--json"]},
    {"name": "preflight", "kind": "read", "flags": ["--require-enforce", "--timeout-seconds"]},
    {"name": "lifecycle status", "kind": "read", "flags": []},
    {"name": "lifecycle start", "kind": "mutate", "confirmation": "required", "flags": []},
    {"name": "lifecycle stop", "kind": "mutate", "confirmation": "required", "flags": []},
    {"name": "mcp self-test", "kind": "read", "flags": ["--json"]},
]}

def catalog(raw: str | None) -> dict:
    value = CATALOG if raw is None else json.loads(raw)
    if value.get("schema") != CATALOG["schema"] or value.get("version") != CATALOG["version"]:
        raise ValueError("catalog version mismatch")
    commands = value.get("commands")
    if not isinstance(commands, list) or len(commands) > 64: raise ValueError("invalid catalog")
    for item in commands:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str): raise ValueError("invalid command")
        if any(ch in item["name"] for ch in "\r\n;|&$`<>"): raise ValueError("unsafe command name")
        if any(not isinstance(x, str) or x.startswith("/") or any(ch in x for ch in "\r\n;|&$`<>") for x in item.get("flags", [])): raise ValueError("unsafe flag")
    return value

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("list", "topic", "completion"))
    p.add_argument("value", nargs="?")
    p.add_argument("--shell", choices=("bash", "zsh", "fish"))
    p.add_argument("--catalog-json", help="test-only catalog JSON; never executed")
    args = p.parse_args(argv)
    try: data = catalog(args.catalog_json)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    items = data["commands"]
    if args.action == "list": print(json.dumps(data, indent=2)); return 0
    if args.action == "topic":
        if not args.value: print("error: topic is required", file=sys.stderr); return 2
        for item in items:
            if item["name"] == args.value: print(json.dumps(item, indent=2)); return 0
        print("error: unknown topic", file=sys.stderr); return 2
    if not args.shell: print("error: --shell is required", file=sys.stderr); return 2
    names = sorted({x for item in items for x in [item["name"].split()[0], *item["name"].split()[1:], *item.get("flags", [])]})
    if args.shell == "fish": print("\n".join(f"complete -c agentfw -f -a '{x}'" for x in names))
    else: print(" ".join(names))
    return 0
if __name__ == "__main__": sys.exit(main())
