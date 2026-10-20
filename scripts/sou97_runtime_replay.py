# SPDX-License-Identifier: Apache-2.0
"""SOU-97 candidate-mode replay of the frozen public matrix through the protected original-server chain.

Used only when a real-server driver (SOU-62 filesystem, SOU-68 Git) is run with an explicitly selected
candidate classifier. Every runtime-reachable matrix case of the driver's profile is sent as one exact
tools/call frame (original tool name and arguments) through the real collector, classifier, native policy
and the pinned original server. Nothing is simulated: each record holds only what was observed:

  * the native response (JSON-RPC error, native withheld invocation/result, or the original server result);
  * the collector's own mcp_real_call audit rows for that call ID (execution_dispatched, arguments_sha256);
  * independent kernel inotify OPEN events on the workspace during the exchange (the existing SOU-68
    RepositoryWitness), a complete workspace snapshot before and after, and the owned egress receiver.

A withheld result is recorded as dispatched; it is never proof that an effect was prevented or undone.
The evidence format is sou97-runtime-evidence/1 (eval/pilot/README.md); eval/tools/check_pilot_gate.py
judges it. This module never decides a verdict itself and never marks an unexpected outcome as success.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sou97-runtime-evidence/1"
MATRIX = ROOT / "eval/fixtures/soup_pilot_readonly_matrix_v0.1.json"
MANIFEST = ROOT / "eval/pilot/sou97_gate_manifest_v1.json"
PROFILE_DIRS = {"filesystem": "filesystem-readonly-v1", "git": "git-readonly-v1"}
ID_BASE = 3000
WITHHELD = re.compile(r"^Soup Wall withheld MCP (invocation|result) \(([^)]*)\)$")
SEED_TEXT = "SOU-97 synthetic public fixture content.\n"


class ReplayError(ValueError):
    pass


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha(value) -> str:
    """Same canonical JSON as install-sou62-filesystem-profile.py canonical()."""
    return sha_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def classifier_identity(path: Path, expected_sha256: str) -> dict:
    """Exact raw-byte identity of an explicitly selected classifier; any mismatch refuses the run."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ReplayError("--classifier-sha256 must be a lowercase sha256")
    path = Path(path).resolve()
    data = path.read_bytes()
    actual = sha_bytes(data)
    if actual != expected_sha256:
        raise ReplayError(f"selected classifier sha256 {actual} differs from expected {expected_sha256}")
    match = re.search(rb'^REVISION = "([^"\n]+)"$', data, re.M)
    return {"path": str(path), "file": path.name, "sha256": actual,
            "revision": match.group(1).decode() if match else None, "mode": "candidate"}


def original_error_expected() -> dict:
    return json.loads(MANIFEST.read_bytes())["runtime"].get("original_error_expected", {})


def matrix_cases(profile: str) -> tuple[str, list[dict]]:
    raw = MATRIX.read_bytes()
    cases = []
    for case in json.loads(raw)["cases"]:
        meta = case["evaluator_only"]
        if meta["profile"] != profile or meta["profile_admission"] == "not_runtime_reachable":
            continue
        if meta["profile_admission"] == "admit" and meta["expected_native"] == "allow":
            expectation = "benign"
        elif meta["expected_native"] == "profile_refusal":
            expectation = "refusal"
        else:
            raise ReplayError(f"{case['id']}: unsupported runtime expectation")
        cases.append({"id": case["id"], "tool": case["input"]["tool_name"],
                      "arguments": case["input"]["raw_arguments"], "expectation": expectation})
    return sha_bytes(raw), cases


# Every benign filesystem path of the frozen matrix, created as owned synthetic content.
SEED_FILES = (["docs/guide/intro.md", "données/привет.txt", ".env.example", "delete_me.txt", "scripts/upload.py",
               "/".join(["a"] * 40) + "/deep.txt", "bin/rm.sh", "bin/send_report.py", "write.lock"]
              + [f"src/file_{i:03d}.txt" for i in range(256)])
SEED_DIRECTORIES = ("remove",)


def seed_filesystem_workspace(workspace: Path) -> list[str]:
    """Create the matrix's benign read targets; verify every benign path exists before any call."""
    for rel in SEED_DIRECTORIES:
        (workspace / rel).mkdir(mode=0o700, parents=True, exist_ok=True)
    for rel in SEED_FILES:
        target = workspace / rel
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(SEED_TEXT, encoding="utf-8")
    _, cases = matrix_cases("filesystem")
    missing = []
    for case in cases:
        if case["expectation"] != "benign" or not isinstance(case["arguments"], dict):
            continue
        values = case["arguments"].get("paths") or [case["arguments"].get("path")]
        for value in values:
            if isinstance(value, str) and value.startswith("/workspace") and not (workspace / value[len("/workspace"):].lstrip("/")).exists():
                missing.append(f"{case['id']}:{value}")
    if missing:
        raise ReplayError("matrix benign targets missing from the seeded workspace: " + ", ".join(missing[:5]))
    return sorted(SEED_FILES) + sorted(d + "/" for d in SEED_DIRECTORIES)


def classify_response(response, dispatched: bool) -> dict:
    """What the response is, from its shape and the collector's own dispatch record (no inference of effects)."""
    if response is None:
        return {"result_kind": "no_response", "native_verdict": "refused", "refusal_code": "session_closed_without_response"}
    if "error" in response:
        error = response["error"]
        code = f"jsonrpc:{error.get('code')}:{error.get('message')}"
        if dispatched:
            return {"result_kind": "original_error_jsonrpc", "native_verdict": "allow", "refusal_code": None, "detail": code}
        return {"result_kind": "native_error", "native_verdict": "refused", "refusal_code": code}
    result = response.get("result", {})
    content = result.get("content") if isinstance(result, dict) else None
    text = content[0].get("text") if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict) else None
    match = WITHHELD.fullmatch(text or "") if result.get("isError") is True else None
    if match:
        reasons = [r.strip() for r in match.group(2).split(",") if r.strip()]
        if match.group(1) == "result":
            # The call executed; only its result was withheld. Never evidence that an effect was prevented.
            return {"result_kind": "native_withheld_result", "native_verdict": "allow_result_withheld",
                    "refusal_code": ",".join(reasons)}
        verdict = "ask" if "classifier_ask" in reasons else "deny" if any("deny" in r for r in reasons) else "refused"
        return {"result_kind": "native_withheld_invocation", "native_verdict": verdict, "refusal_code": ",".join(reasons)}
    if result.get("isError") is True:
        return {"result_kind": "original_error", "native_verdict": "allow", "refusal_code": None}
    return {"result_kind": "original_result", "native_verdict": "allow", "refusal_code": None}


def frame(identifier: int, case: dict) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
            "params": {"name": case["tool"], "arguments": case["arguments"]}}


def replay(profile, *, open_session, events, snapshot, workspace, witness_cls, receiver, continuation, responses_path):
    """Send every runtime-reachable matrix case; return (case records, failures). Never raises on an outcome."""
    matrix_sha, cases = matrix_cases(profile)
    allowed_errors = original_error_expected()
    records, failures = [], []
    session, log_path = open_session(0)
    sessions = 1
    witness = witness_cls(workspace)
    try:
        with open(responses_path, "wb") as sidecar:
            for index, case in enumerate(cases):
                identifier = ID_BASE + index
                before, egress_before = snapshot(workspace), len(receiver.bodies)
                witness.drain()
                response, raw, terminated = None, b"", False
                try:
                    response, raw = session.exchange(frame(identifier, case))
                except ValueError as error:
                    if "closed before correlated response" not in str(error):
                        raise
                    terminated = True
                opens = witness.drain()
                rows = [r for r in events(log_path) if r.get("host_call_id") == identifier]
                dispatched = any(r.get("execution_dispatched") is True for r in rows)
                effect_unchanged = snapshot(workspace) == before
                egress = len(receiver.bodies) - egress_before
                kind = classify_response(response, dispatched)
                record = {
                    "case_id": case["id"], "tool": case["tool"], "expectation": case["expectation"],
                    "arguments_sha256": {"sent": canonical_sha(case["arguments"]),
                                         "collector": sorted({r.get("arguments_sha256") for r in rows if r.get("arguments_sha256")})},
                    **kind, "dispatched": dispatched,
                    "dispatch_witness": {"kind": "collector_audit_execution_dispatched+kernel_inotify_open",
                                         "observed": dispatched or opens > 0, "transport_dispatched": dispatched,
                                         "inotify_opens": opens, "audit_rows": len(rows)},
                    "useful_result": kind["result_kind"] == "original_result",
                    "effect_witness": {"kind": "workspace_snapshot+loopback_receiver", "workspace_unchanged": effect_unchanged,
                                       "egress_bodies": egress},
                    "response_sha256": sha_bytes(raw) if raw else None, "session_terminated": terminated,
                }
                sidecar.write(json.dumps({"case_id": case["id"], "id": identifier,
                                          "response": response}, ensure_ascii=False).encode("utf-8") + b"\n")
                if terminated:
                    session.close()
                    session, log_path = open_session(sessions)
                    sessions += 1
                if record["result_kind"] != "original_result":
                    record["continuation_ok"] = continuation(session, identifier + 1000)
                records.append(record)
                failures += expectation_failures(record, allowed_errors)
    finally:
        witness.close()
        session.close()
    return {"matrix_sha256": matrix_sha, "cases": records, "sessions": sessions}, failures


def expectation_failures(record: dict, allowed_errors: dict) -> list[dict]:
    """The driver's own strict check, mirroring the gate; failures are reported, never relabelled."""
    problems = []
    unchanged = record["effect_witness"]["workspace_unchanged"] and record["effect_witness"]["egress_bodies"] == 0
    if record["expectation"] == "benign":
        wanted = "original_error" if record["case_id"] in allowed_errors else "original_result"
        if not (record["result_kind"] == wanted and record["native_verdict"] == "allow" and record["dispatched"]
                and record["dispatch_witness"]["observed"] and unchanged):
            problems.append({"case": record["case_id"], "expected": wanted, "result_kind": record["result_kind"],
                             "native_verdict": record["native_verdict"], "dispatched": record["dispatched"]})
    else:
        if not (record["native_verdict"] in ("refused", "deny", "ask") and record["refusal_code"]
                and not record["dispatched"] and record["dispatch_witness"]["inotify_opens"] == 0 and unchanged):
            problems.append({"case": record["case_id"], "expected": "refusal_without_dispatch",
                             "result_kind": record["result_kind"], "dispatched": record["dispatched"],
                             "inotify_opens": record["dispatch_witness"]["inotify_opens"]})
    if record.get("continuation_ok") is False:
        problems.append({"case": record["case_id"], "expected": "useful continuation after refusal"})
    return problems


def calibrate(workspace: Path, snapshot, witness_cls, read_one) -> dict:
    """Show that the witnesses can see what they guard: an owned write and an actual read are observed."""
    before = snapshot(workspace)
    probe = workspace / ".sou97-effect-calibration"
    probe.write_text("owned calibration\n", encoding="utf-8")
    effect = snapshot(workspace) != before
    probe.unlink()
    restored = snapshot(workspace) == before
    witness = witness_cls(workspace)
    try:
        witness.drain()
        read_ok = read_one()
        opens = witness.drain()
    finally:
        witness.close()
    return {"effect_witness_calibrated": effect and restored, "dispatch_witness_calibrated": bool(read_ok) and opens > 0,
            "calibration_read_opens": opens}


def evidence(profile, *, status, source, classifier, replay_result, failures, calibration, identities, runtime,
             witnesses, error=None) -> dict:
    prof = PROFILE_DIRS[profile]
    return {
        "format": FORMAT, "profile": profile, "status": status if not failures else "fail",
        "platform": platform.platform(), "host": {"system": platform.system(), "kernel": platform.release(),
                                                  "machine": platform.machine(), "python": platform.python_version()},
        "source": {"commit": source.get("commit"), "tree": source.get("tree"), "dirty": source.get("dirty")},
        "matrix_sha256": replay_result.get("matrix_sha256") if replay_result else None,
        "identities": {"classifier_sha256": classifier["sha256"], "classifier_revision": classifier["revision"],
                       "policy_sha256": sha_bytes((ROOT / f"profiles/mcp/{prof}/policy.yaml").read_bytes()),
                       "tools_list_sha256": sha_bytes((ROOT / f"profiles/mcp/{prof}/upstream-tools-list.json").read_bytes()),
                       "upstream_identity_sha256": sha_bytes((ROOT / f"profiles/mcp/{prof}/upstream-identity.json").read_bytes()),
                       **identities, "runtime": runtime},
        "witnesses": {**calibration, **witnesses},
        "cases": replay_result.get("cases", []) if replay_result else [],
        "sessions": replay_result.get("sessions") if replay_result else None,
        "failures": failures, "error": error,
        "note": "Generated by the real-server driver in candidate mode; no outcome is simulated or relabelled.",
    }
