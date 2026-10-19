#!/usr/bin/env python3
"""Run the absent-config recovery test while an owned listener holds port 8787.

Run only in a disposable test environment. Never stops an existing listener.
"""
import socket
import subprocess


def main():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 8787))
        listener.listen(128)
        return subprocess.call([
            "cargo", "test", "--locked", "-p", "agentfw", "--lib",
            "mcp::profile_lifecycle::tests::recovery_removes_incomplete_candidate_scratch_without_publishing",
            "--", "--exact", "--nocapture", "--test-threads=1",
        ])


if __name__ == "__main__":
    raise SystemExit(main())
