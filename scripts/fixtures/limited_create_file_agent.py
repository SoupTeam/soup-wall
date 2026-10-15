#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned Linux-only SOU-54 fixture: limit its Agent's file size before exec.

The parent supplies a stderr pipe and drains it outside this process's limit.
This is a fixture launch configuration, never an Agent production fault hook.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import sys

LIMIT_BYTES = 2048


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("agent_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("this owned file-size-limit fixture requires Linux")
    import resource
    command = args.agent_args[1:] if args.agent_args[:1] == ["--"] else args.agent_args
    if command[:2] != ["mcp", "--native-admission"] or not args.agentfw.is_file():
        parser.error("an existing Agent and native MCP command are required")
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT_BYTES, LIMIT_BYTES))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    print(json.dumps({"event": "sou54_os_file_size_limit", "rlimit_fsize": list(resource.getrlimit(resource.RLIMIT_FSIZE)),
                      "sigxfsz_ignored": signal.getsignal(signal.SIGXFSZ) == signal.SIG_IGN}, separators=(",", ":")),
          file=sys.stderr, flush=True)
    executable = str(args.agentfw.resolve())
    os.execv(executable, [executable, *command])


if __name__ == "__main__":
    main()
