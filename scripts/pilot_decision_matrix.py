#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Development-only classifier observations; never an execution authorization."""
import argparse
import importlib.util
import json
from pathlib import Path
import time

import pilot_policy as pilot


def observe():
    pilot.verify_assets()
    rows = []
    arguments = {
        "read_file": {"path": "/workspace/notes.txt"},
        "read_text_file": {"path": "/workspace/notes.txt"},
        "read_multiple_files": {"paths": ["/workspace/notes.txt"]},
        "list_directory": {"path": "/workspace"},
        "list_directory_with_sizes": {"path": "/workspace", "sortBy": "size"},
        "directory_tree": {"path": "/workspace"},
        "search_files": {"path": "/workspace", "pattern": "notes.txt"},
        "get_file_info": {"path": "/workspace/notes.txt"},
        "list_allowed_directories": {},
        "git_status": {"repo_path": "/workspace"},
        "git_log": {"repo_path": "/workspace", "max_count": 3},
        "git_diff": {"repo_path": "/workspace", "target": "HEAD", "context_lines": 3},
        "git_diff_staged": {"repo_path": "/workspace", "context_lines": 3},
        "git_diff_unstaged": {"repo_path": "/workspace", "context_lines": 3},
        "git_show": {"repo_path": "/workspace", "revision": "HEAD"},
    }
    for kind, (name, classifier) in pilot.KINDS.items():
        spec = importlib.util.spec_from_file_location("pilot_classifier", pilot.ROOT / classifier)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tools = pilot.read(pilot.ROOT / "profiles/mcp" / name / "upstream-tools-list.json")["result"]["tools"]
        inputs = [
            {"tool_name": tool["name"], "raw_arguments": arguments[tool["name"]],
             "server_id": name, "tool_description": tool.get("description", ""),
             "tool_schema": tool["inputSchema"], "pinned_schema": tool["inputSchema"]}
            for tool in tools if tool["name"] in arguments
        ]
        inputs.extend([
            {"tool_name": "opaque", "raw_arguments": {}},
            {"tool_name": "run_task", "tool_description": "Read-only helper",
             "raw_arguments": {"command": "rm -rf /workspace/owned-fixture"}},
            {"tool_name": "run_task", "raw_arguments": {"command": "cat /workspace/notes.txt; eval \"$CMD\""}},
        ])
        for event in inputs:
            started = time.perf_counter()
            result = module.classify(event)
            elapsed = (time.perf_counter() - started) * 1000
            rows.append({
                "kind": kind, "input": event, "classification": result,
                "classification_ms": round(elapsed, 3),
                "intended_read": event["tool_name"] in arguments,
                "read_coverage_gap": event["tool_name"] in arguments and
                    (result.get("unknown") is not False or result.get("actions") != ["read"]),
            })
    return {
        "format": "sw-pilot-development-observations/1",
        "not_execution_evidence": True, "sealed_data_used": False,
        "manifest_sha256": pilot.sha(pilot.ASSETS / "manifest.json"),
        "rows": rows,
        "coverage_gaps": sum(r["read_coverage_gap"] for r in rows),
        "intended_reads": sum(r["intended_read"] for r in rows),
        "latency_scope": "single in-process classify call; excludes subprocess startup, IPC, policy and execution",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = observe()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: data[key] for key in ("format", "coverage_gaps", "intended_reads")}))


if __name__ == "__main__":
    main()
