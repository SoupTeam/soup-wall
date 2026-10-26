# SPDX-License-Identifier: Apache-2.0
"""Minimal stdio MCP client used only to run one original-server call for corpus generation."""
import json
import subprocess


def call(cmd, tool, args, env=None, cwd=None):
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=env, cwd=cwd)

    def send(message):
        process.stdin.write((json.dumps(message) + "\n").encode())
        process.stdin.flush()

    def receive(identifier):
        while True:
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("original server closed before answering")
            message = json.loads(line)
            if message.get("id") == identifier:
                return message

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "sou123", "version": "1"}}})
    receive(1)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    result = receive(2)["result"]
    process.stdin.close()
    process.wait(timeout=10)
    return result
