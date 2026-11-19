# SPDX-License-Identifier: Apache-2.0
"""Private candidate qualification: fresh daemon records, never collector markers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

RULE = "filesystem-profile-refuse-result-injection"
FRAME = f"Soup Wall withheld MCP result ({RULE})"
MAX_AUDIT = 4 * 1024 * 1024


def require(value, reason):
    if not value:
        raise ValueError(reason)


class AuditWindow:
    """Keep the already-open daemon sink and exclude every pre-existing event.

    The harness owns an isolated HOME/daemon and runs one client at a time. This
    is local test evidence, not authentication against another same-UID process.
    """

    def __init__(self, path):
        self.path = Path(path)
        require(not self.path.is_symlink(), "audit_symlink")
        self.stream = self.path.open("rb")
        info = os.fstat(self.stream.fileno())
        require(stat.S_ISREG(info.st_mode), "audit_not_regular")
        self.identity = (info.st_dev, info.st_ino)
        self.offset = info.st_size

    def close(self):
        self.stream.close()

    def records(self):
        named = self.path.lstat()
        require(stat.S_ISREG(named.st_mode)
                and (named.st_dev, named.st_ino) == self.identity, "audit_replaced")
        require(self.offset <= named.st_size <= self.offset + MAX_AUDIT, "audit_size_changed")
        self.stream.seek(self.offset)
        data = self.stream.read(MAX_AUDIT + 1)
        require(len(data) <= MAX_AUDIT and (not data or data.endswith(b"\n")), "audit_incomplete")
        records = [json.loads(line) for line in data.splitlines()]
        require(all(isinstance(row, dict) for row in records), "audit_record_invalid")
        return records


def policy_evidence(response, records, registry_sha256):
    require(response == {"jsonrpc": "2.0", "id": 3, "result": {
        "isError": True, "content": [{"type": "text", "text": FRAME}]}}, "policy_frame_mismatch")
    calls = [row for row in records if row.get("event") == "native_call"
             and row.get("tool") == "read_file"]
    results = [row for row in records if row.get("event") == "native_result"
               and row.get("tool") == "read_file"]
    require(len(calls) == len(results) == 1, "fresh_daemon_call_result_required")
    call, result = calls[0], results[0]
    for field in ("session", "call_id", "binding_sha256", "registry_sha256"):
        require(isinstance(call.get(field), str) and bool(call[field])
                and result.get(field) == call[field], "daemon_call_binding_mismatch")
    require(call["registry_sha256"] == registry_sha256, "daemon_registry_mismatch")
    require(call.get("verdict") == "allow" and call.get("released") is True
            and call.get("shadow") is False, "daemon_invocation_not_allowed")
    require(result.get("seq", -1) > call.get("seq", -1)
            and result.get("verdict") == "deny" and result.get("released") is False
            and result.get("shadow") is False and result.get("rule") == RULE
            and result.get("reason_codes") == [RULE]
            and result.get("delivery") == "mcp_host", "daemon_result_not_denied")
    require(isinstance(result.get("content_sha256"), str)
            and len(result["content_sha256"]) == 64, "daemon_content_identity_missing")
    return {"call_id": call["call_id"], "binding_sha256": call["binding_sha256"],
            "content_sha256": result["content_sha256"], "rule": RULE}
