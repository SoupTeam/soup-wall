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
# Tiny per-case content keeps every original benign result inside the profile's 16 KiB output bound.
SEED_TEXT = "SOU-97\n"
# Every fixed JSON-RPC error message of the native real-server path (crates/agentfw/src/mcp/admission/real_server.rs).
# A response carrying one of these is native, never an original-server error; a test keeps this list in sync.
NATIVE_ERROR_MESSAGES = frozenset((
    "MCP request cancelled or incomplete; dispatched execution may have occurred",
    "MCP request cancelled; dispatched execution may have occurred",
    "MCP manifest differs from the installed selected-server profile",
    "Unsupported MCP result withheld by the selected output profile",
    "MCP arguments violate the selected input profile",
    "MCP params must be an object",
    "MCP tool name is required",
    "Unsupported MCP call parameters",
    "Unsupported MCP discovery parameters",
    "MCP method is unsupported by the selected profile",
    "MCP tool is explicitly unsupported in the read-only profile",
    "MCP tool is not installed in this profile",
    "Server callbacks are unsupported by this operator profile",
    "MCP pending-call limit reached",
    "MCP physical pending-call limit reached",
    "MCP control request is busy or not initialized",
    "Operator-pinned MCP discovery is required",
    "MCP call timed out; dispatched execution may have occurred",
    "Replayed or spent MCP request ID refused",
    "Git local reference unavailable, unsupported, or its source changed",
    "Git local-reference view changed during execution",
    "Git local-reference view changed or target unsupported",
    "An original create operation is already active",
    "Original create staging failed; no file committed",
    "Original create timed out before publication; no file committed",
    "Original create workspace identity unavailable",
    "Original isolated MCP create failed; workspace unchanged",
    "Unsafe or existing original-create destination; no publication",
    "Native collector became uncertain before publication",
    # Fixed *_MESSAGE constants of the same file.
    "MCP result withheld: a result text exceeds the 262144-byte per-result budget; the original call may have executed",
    "MCP result withheld: the response frame exceeds the 1048576-byte envelope budget; the original call may have executed",
    "MCP path refused before execution: it is outside the selected workspace /workspace",
    "MCP path refused before execution: unsupported spelling (empty, '.', '..' or '//' segment, backslash, '~', "
    "control character, relative ':' or over 4096 bytes)",
    # DaemonSizeLimit::message (crates/agentfw/src/mcp/admission.rs), sent through the same error frame.
    "MCP result withheld: the native daemon record limit (native_record_over_cap) refused its size; "
    "the original call may have executed",
    "MCP result withheld: the native daemon content limit (native_content_over_cap) refused its size; "
    "the original call may have executed",
    "MCP result withheld: the native daemon body limit (native_body_over_cap) refused its size; "
    "the original call may have executed",
))
NOT_CLASSIFIED_PREFIX = "Soup Wall could not classify the MCP invocation ("
OUTPUT_PROFILE_WITHHELD = "Unsupported MCP result withheld by the selected output profile"


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


# Per-case seeding: only the benign case's own read targets exist while it runs, then they are removed.
# Seeding the whole matrix at once made original directory_tree results exceed the profile's 16 KiB
# output bound, which native validation correctly withheld (SOU-97 first Linux run, request id 38).
DIRECTORY_TOOLS = frozenset(("list_directory", "list_directory_with_sizes", "directory_tree", "search_files"))
DIRECTORY_TARGETS = frozenset(("docs", "docs/guide", "remove"))  # also named by get_file_info in the matrix


def case_targets(case: dict) -> list[tuple[str, str]]:
    """(relative path, 'file' | 'directory') that a benign filesystem case needs; refusals need nothing."""
    if case["expectation"] != "benign" or not isinstance(case["arguments"], dict):
        return []
    args = case["arguments"]
    values = args["paths"] if isinstance(args.get("paths"), list) else [args.get("path")]
    targets = []
    for value in values:
        if not isinstance(value, str) or not (value == "/workspace" or value.startswith("/workspace/")):
            continue
        rel = value[len("/workspace"):].lstrip("/")
        if not rel:
            continue
        kind = "directory" if case["tool"] in DIRECTORY_TOOLS or rel in DIRECTORY_TARGETS else "file"
        targets.append((rel, kind))
    return targets


def seed_case(workspace: Path, case: dict) -> list[Path]:
    """Create exactly the missing targets of one case; return what was created, in creation order."""
    created = []
    for rel, kind in case_targets(case):
        target = workspace / rel
        missing_parents = [parent for parent in reversed(target.relative_to(workspace).parents) if str(parent) != "."]
        for parent in missing_parents:
            path = workspace / parent
            if not path.exists():
                path.mkdir(mode=0o700)
                created.append(path)
        if target.exists():
            continue  # pre-existing driver fixtures (notes.txt, the FIFOs) are never replaced or removed
        if kind == "directory":
            target.mkdir(mode=0o700)
        else:
            target.write_text(SEED_TEXT, encoding="utf-8")
        created.append(target)
    for rel, _ in case_targets(case):
        if not (workspace / rel).exists():
            raise ReplayError(f"{case['id']}: seeded target {rel} is missing")
    return created


def unseed_case(created: list[Path]) -> None:
    """Remove exactly what seed_case created, deepest first; nothing else is touched."""
    for path in reversed(created):
        if path.is_dir() and not path.is_symlink():
            path.rmdir()  # fails loudly if anything unexpected appeared inside
        else:
            path.unlink()


def classify_response(response, dispatched: bool) -> dict:
    """What the response is, from its shape and the collector's own dispatch record (no inference of effects)."""
    if response is None:
        return {"result_kind": "no_response", "native_verdict": "refused", "refusal_code": "session_closed_without_response"}
    if "error" in response:
        error = response["error"]
        message = error.get("message") if isinstance(error, dict) else None
        code = f"jsonrpc:{error.get('code') if isinstance(error, dict) else None}:{message}"
        native = isinstance(message, str) and (message in NATIVE_ERROR_MESSAGES or message.startswith(NOT_CLASSIFIED_PREFIX))
        if dispatched and native:
            # Executed, then the native layer replaced the result (output profile, timeout, cancellation).
            # Never an original-server error and never a successful allow; never proof an effect was undone.
            kind = "native_withheld_result" if message == OUTPUT_PROFILE_WITHHELD else "native_error_after_dispatch"
            return {"result_kind": kind, "native_verdict": "allow_result_withheld", "refusal_code": code}
        if dispatched:
            return {"result_kind": "original_error_jsonrpc", "native_verdict": "allow", "refusal_code": None, "detail": code}
        return {"result_kind": "native_error", "native_verdict": "refused", "refusal_code": code,
                **({} if native else {"unrecognised_native_message": True})}
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


def replay(profile, *, open_session, events, snapshot, workspace, witness_cls, receiver, continuation, responses_path,
           prepare=None, restore=None):
    """Send every runtime-reachable matrix case; return (case records, failures). Never raises on an outcome.

    With prepare/restore (filesystem), each case runs in its own seeded workspace: targets are created first,
    a fresh file-open witness is installed afterwards so new directories are watched, and after the exchange
    exactly the created entries are removed and the workspace must equal its pre-replay snapshot.
    """
    matrix_sha, cases = matrix_cases(profile)
    allowed_errors = original_error_expected()
    records, failures = [], []
    session, log_path = open_session(0)
    sessions = 1
    base = snapshot(workspace)
    witness = None if prepare else witness_cls(workspace)
    try:
        with open(responses_path, "wb") as sidecar:
            for index, case in enumerate(cases):
                identifier = ID_BASE + index
                created = prepare(case) if prepare else []
                if prepare:
                    witness = witness_cls(workspace)  # installed after seeding: every seeded directory is watched
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
                if prepare:
                    witness.close()
                    witness = None
                    restore(created)
                    record["seeded"] = len(created)
                    record["workspace_restored"] = snapshot(workspace) == base
                records.append(record)
                failures += expectation_failures(record, allowed_errors)
    finally:
        if witness is not None:
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
    if record.get("workspace_restored") is False:
        problems.append({"case": record["case_id"], "expected": "workspace restored after per-case seeding"})
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
