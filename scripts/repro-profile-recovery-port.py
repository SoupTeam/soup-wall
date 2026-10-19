#!/usr/bin/env python3
"""Run the absent-config recovery test while an owned listener holds port 8787.

Run from the repository root, only in a disposable test environment. Never
stops an existing listener. This reproduces a failure mechanism, not historical
evidence that port 8787 was occupied during the original Windows VPS run.
"""
import socket
import subprocess
import sys


def main():
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", 8787))
        except OSError as error:
            print(f"Cannot own test port 8787; leaving existing services untouched: {error}",
                  file=sys.stderr)
            return 2
        listener.listen(128)
        return subprocess.call([
            "cargo", "test", "--locked", "-p", "agentfw", "--lib",
            "mcp::profile_lifecycle::tests::recovery_removes_incomplete_candidate_scratch_without_publishing",
            "--", "--exact", "--nocapture", "--test-threads=1",
        ])


if __name__ == "__main__":
    raise SystemExit(main())
