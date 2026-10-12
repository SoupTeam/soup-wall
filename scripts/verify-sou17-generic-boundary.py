#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict SOU-17 generic classification admission checks against an exact clean source.

Synthetic replies pass through the production Python bridge, composed policy,
native daemon and existing safe-local executor. This checks runtime wiring, not
classification quality. An empty reply on a harmless read is a shape fixture,
not proof that the tool is a no-op. Complete acceptance remains false. No build,
external model, external destination or production-source change is performed.
Exit 0: bounded checks pass; 1: observed violation; 2: inconclusive evidence.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import queue
import re
import signal
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "sw-classification/candidate-1"
SEND_BODY = "SOU17 synthetic authorized mixed-action delivery"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HELPER_PATH = ROOT / "scripts/verify-sou17-pending-admission.py"
HELPER = load_module("sou17_generic_helpers", HELPER_PATH)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    base = {"status": "ok", "actions": ["read"], "unknown": False, "confidence": .95,
            "uncertainty": .05, "reason": "Synthetic generic boundary fixture"}
    def case(name, changes, verdict, *, tool="read_document", failure=None, stdout=None, missing=None):
        reply = dict(base, **changes)
        if missing:
            reply.pop(missing)
        return {"name": name, "tool": tool, "reply": reply, "expected_verdict": verdict,
                "expected_failure": failure,
                "stdout": stdout if stdout is not None else json.dumps(reply, separators=(",", ":"))}
    return [
        case("single-read-before", {}, "allow"),
        case("empty-known-low", {"actions": []}, "allow"),
        case("empty-known-high", {"actions": [], "uncertainty": .9}, "ask"),
        case("authorized-mixed-send", {"actions": ["read", "send_data"]}, "allow", tool="send_http"),
        case("unknown-empty-low", {"status": "unknown", "actions": [], "unknown": True}, "ask"),
        case("read-plus-unknown-low", {"unknown": True}, "ask"),
        case("delete-plus-unknown-low", {"actions": ["read", "delete"], "unknown": True}, "deny"),
        case("delete-plus-unknown-high", {"actions": ["read", "delete"], "unknown": True, "uncertainty": 1.}, "deny"),
        case("readonly-write-plus-unknown-high", {"actions": ["read", "write"], "unknown": True, "uncertainty": 1.}, "deny"),
        case("duplicate-actions", {"actions": ["read", "read"]}, None, failure="classifier_invalid"),
        case("duplicate-confidence-json", {}, None, failure="classifier_error",
             stdout='{"status":"ok","actions":["read"],"unknown":false,"confidence":0.95,"confidence":0.5,"uncertainty":0.05,"reason":"Synthetic generic boundary fixture"}'),
        case("missing-actions", {}, None, failure="classifier_error", missing="actions"),
        case("invalid-confidence", {"confidence": 1.1}, None, failure="classifier_invalid"),
        case("nonfinite-uncertainty-json", {}, None, failure="classifier_error",
             stdout='{"status":"ok","actions":["read"],"unknown":false,"confidence":0.95,"uncertainty":1e999,"reason":"Synthetic generic boundary fixture"}'),
        case("single-read-after", {}, "allow"),
    ]


def arguments(case, receiver_url):
    return {"url": receiver_url, "body": SEND_BODY} if case["tool"] == "send_http" else {"name": "inventory"}


def frame(case, receiver_url):
    index = [item["name"] for item in cases()].index(case["name"]) + 1
    return json.dumps({"jsonrpc": "2.0", "id": "generic-" + case["name"], "method": "tools/call",
        "params": {"name": case["tool"], "arguments": arguments(case, receiver_url),
            "_meta": {"claudecode/toolUseId": "toolu_generic_" + str(index), "progressToken": index}}}, separators=(",", ":"))


def dictionary(value):
    return value if isinstance(value, dict) else {}


def valid_semantics(value, reply):
    return isinstance(value, dict) and all(type(value.get(key)) is type(reply.get(key)) and value.get(key) == reply.get(key)
        for key in ("actions", "unknown", "confidence", "uncertainty")) \
        and value.get("reason_sha256") == sha(reply["reason"].encode())


def grade_case(case, row, stable, digest):
    def result(status, reason):
        return {"status": status, "reason": reason}
    if stable is not True or not HELPER.digest_valid(digest) or not isinstance(row, dict):
        return result("inconclusive", "unstable source/binary/classifier or missing case evidence")
    if row.get("case") != case["name"] or row.get("host_call_id") != "generic-" + case["name"]:
        return result("inconclusive", "case identity mismatch")
    receiver_url = row.get("receiver_url")
    if not isinstance(receiver_url, str) or re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/capture", receiver_url) is None:
        return result("inconclusive", "safe-local receiver identity missing")
    expected_frame = frame(case, receiver_url)
    if row.get("submitted_frame") != expected_frame or row.get("executor_ledger_final_reconciled") is not True:
        return result("inconclusive", "original frame or final post-shutdown ledger missing")
    expected_request = HELPER.strict_json(expected_frame)
    evidence = row.get("classifications")
    if not isinstance(evidence, list) or len(evidence) != 1 or not isinstance(evidence[0], dict):
        return result("inconclusive", "missing/duplicate production classification witness")
    evidence = evidence[0]
    expected_baseline = "network" if case["tool"] == "send_http" else "read_only"
    if any(evidence.get(key) != value for key, value in {
        "source": "rule-baseline/python", "classifier_sha256": digest, "contract_version": CONTRACT,
        "host_call_id": row["host_call_id"], "tool": case["tool"], "server_id": "demo",
        "trusted_baseline": expected_baseline, "registry_sha256": row.get("registry_sha256"),
        "args_sha256": sha(json.dumps(arguments(case, receiver_url), sort_keys=True, separators=(",", ":")).encode()),
    }.items()) or not HELPER.digest_valid(row.get("registry_sha256")):
        return result("inconclusive", "production source, revision or original input correlation mismatch")
    entries, errors = HELPER.ledger(row.get("executor_ledger_raw"))
    matching = [entry for entry in entries if entry[1].get("id") == row["host_call_id"]]
    if case["expected_verdict"] != "allow" and matching:
        return result("fail", "forbidden call entered executor, including a possible late effect")
    if errors or any(entry[1].get("id") != row["host_call_id"] for entry in entries):
        return result("inconclusive", "corrupt or unrelated executor ledger bytes")
    witness = row.get("classifier_input")
    expected_index = [item["name"] for item in cases()].index(case["name"])
    if not isinstance(witness, dict) or witness.get("index") != expected_index \
            or witness.get("classifier_sha256") != digest or witness.get("stdout_sha256") != sha((case["stdout"] + "\n").encode()) \
            or dictionary(witness.get("request")).get("tool_name") != case["tool"] \
            or dictionary(witness.get("request")).get("raw_arguments") != arguments(case, receiver_url) \
            or witness.get("emitted") is not True:
        return result("inconclusive", "selected classifier input/output fixture handshake missing")
    raw_response = row.get("client_response_raw")
    try:
        response = HELPER.strict_json(raw_response)
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or response.get("id") != row["host_call_id"]:
            raise ValueError("response identity mismatch")
    except (ValueError, TypeError):
        return result("inconclusive", "missing/malformed correlated client response; retained raw bytes")
    if row.get("gateway_exit_code") != 0 or type(row.get("gateway_exit_code")) is not int:
        return result("inconclusive", "gateway did not complete normally")
    receiver_bodies = row.get("receiver_bodies_at_response")
    if not isinstance(receiver_bodies, list) or row.get("server_responses_valid") is not True:
        return result("inconclusive", "independent delivery/server response evidence missing or corrupt")
    original = row.get("original_server_results")
    if not isinstance(original, list):
        return result("inconclusive", "original server result witness missing")
    native = row.get("native_decisions")
    if row.get("native_audit_valid") is not True or not isinstance(native, list) or not all(isinstance(item, dict) for item in native):
        return result("inconclusive", "native result/admission witness missing")
    if case["expected_failure"]:
        if evidence.get("policy") != "not_reached" or evidence.get("failure") != case["expected_failure"] \
                or evidence.get("authoritative_verdict") != case["expected_failure"] \
                or dictionary(response.get("error")).get("code") != -32603 \
                or case["expected_failure"] not in str(dictionary(response.get("error")).get("message", "")) \
                or "policy not reached" not in str(dictionary(response.get("error")).get("message", "")):
            return result("fail", "corrupt classifier reply did not get the required technical pre-policy refusal")
        if case["expected_failure"] == "classifier_invalid" and not valid_semantics(evidence.get("classification"), case["reply"]):
            return result("inconclusive", "invalid semantic reply itself was not attested")
        if entries or original or native or receiver_bodies:
            return result("fail", "technical failure reached execution, native admission or delivery")
        return result("pass", "technical_not_reached with independent zero execution/result/delivery")
    if not valid_semantics(evidence.get("classification"), case["reply"]):
        return result("inconclusive", "selected valid synthetic reply not attested")
    if evidence.get("policy") != "reached" or evidence.get("failure") is not None:
        return result("fail", "valid classifier reply did not reach authoritative production policy")
    if evidence.get("authoritative_verdict") != case["expected_verdict"]:
        return result("fail", "authoritative verdict does not match the agreed fixture expectation")
    if case["expected_verdict"] == "allow":
        expected_text = "Recipient accepted the body" if case["tool"] == "send_http" else "Inventory: 7 red widgets."
        if len(entries) != 1 or entries[0][0] != expected_frame + "\n" or entries[0][1] != expected_request \
                or original != [raw_response] or dictionary(response.get("result")).get("isError") is True \
                or dictionary(response.get("result")).get("content") != [{"type": "text", "text": expected_text}]:
            return result("fail", "Allow lacked one exact original execution and useful released original result")
        expected_bodies = [SEND_BODY] if case["tool"] == "send_http" else []
        if receiver_bodies != expected_bodies:
            return result("fail", "independent receiver did not witness exactly the permitted body delivery")
        if [item.get("event") for item in native] != ["native_call", "native_result"] \
                or any(item.get("verdict") != "allow" or item.get("released") is not True \
                    or item.get("shadow") is not False or item.get("tool") != case["tool"] \
                    or item.get("registry_sha256") != row["registry_sha256"] for item in native):
            return result("fail", "useful call/result native gates were not both enforcing Allow for this tool/registry")
        call, completion = native
        valid_id = lambda value: isinstance(value, str) and 0 < len(value) <= 128 and not any(ord(c) < 32 for c in value)
        if not valid_id(call.get("call_id")) or not valid_id(call.get("session")) \
                or completion.get("call_id") != call["call_id"] or completion.get("session") != call["session"] \
                or not HELPER.digest_valid(call.get("binding_sha256")) \
                or completion.get("binding_sha256") != call["binding_sha256"] \
                or call.get("content_sha256") is not None or completion.get("content_sha256") != sha(raw_response.encode()) \
                or completion.get("delivery") != "mcp_host":
            return result("fail", "native grant/session/binding or exact original result content identity mismatched")
    else:
        reason = "policy_denied" if case["expected_verdict"] == "deny" else "policy_unconfirmed_ask"
        if entries or original or native or receiver_bodies:
            return result("fail", "Deny/Ask reached execution, native capacity or original delivery")
        if dictionary(response.get("result")).get("isError") is not True or reason not in json.dumps(response):
            return result("fail", "expected ordinary correlated policy refusal missing")
    return result("pass", "ordinary authoritative policy with exact execution/result/delivery witnesses")


def grade_report(rows, stable, digest, final_receiver_bodies, final_native, classifications, gateway_exit,
                 *, transcript=None, error=None):
    grades = []
    table = cases()
    for row in rows:
        case = next((case for case in table if case["name"] == row.get("case")), None)
        grade = grade_case(case, row, stable, digest) if case else {"status": "inconclusive", "reason": "unknown case"}
        row["grade"] = grade
        grades.append(grade)
    if any(grade["status"] == "fail" for grade in grades):
        return "fail", 1
    names = [case["name"] for case in table]
    if stable is not True or [row.get("case") for row in rows] != names:
        return "inconclusive", 2
    if not isinstance(transcript, dict) or transcript.get("client_output_complete") is not True \
            or transcript.get("client_frames_valid") is not True or transcript.get("server_frames_valid") is not True:
        return "inconclusive", 2
    clients, servers = transcript.get("client_frames"), transcript.get("server_frames")
    if not isinstance(clients, list) or not isinstance(servers, list) or len(clients) < 2:
        return "inconclusive", 2
    try:
        client_values = [HELPER.strict_json(raw) for raw in clients]
        if not all(isinstance(value, dict) for value in client_values):
            raise ValueError("bad client frame")
        if [value.get("id") for value in client_values] != ["probe-init", "probe-list"] + ["generic-" + name for name in names]:
            return "fail", 1
        if not all(isinstance(value.get("result"), dict) for value in client_values[:2]):
            return "inconclusive", 2
    except (TypeError, ValueError):
        return "inconclusive", 2
    expected_clients = clients[:2] + [row.get("client_response_raw") for row in rows]
    expected_servers = clients[:2] + [raw for row in rows for raw in row.get("original_server_results", [])]
    if clients != expected_clients or servers != expected_servers:
        return "fail", 1
    if any(grade["status"] != "pass" for grade in grades):
        return "inconclusive", 2
    if gateway_exit != 0 or type(gateway_exit) is not int or not isinstance(classifications, list) \
            or len(classifications) != len(names) or not all(isinstance(item, dict) for item in classifications) \
            or [item.get("host_call_id") for item in classifications] != ["generic-" + name for name in names]:
        return "inconclusive", 2
    # Account for deliveries and native events occurring after the row-level response snapshots.
    if final_receiver_bodies != [SEND_BODY] or final_native != [item for row in rows for item in row["native_decisions"]]:
        return "fail", 1
    calls = [item for item in final_native if item.get("event") == "native_call"]
    if len({item["call_id"] for item in calls}) != len(calls) or len({item["session"] for item in calls}) != 1:
        return "fail", 1
    if error is not None:
        return "inconclusive", 2
    return "pass", 0


def classifier_source(private, receiver_url):
    table = [{"tool": case["tool"], "arguments": arguments(case, receiver_url), "stdout": case["stdout"]} for case in cases()]
    return f'''#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import hashlib,json,pathlib,sys
root=pathlib.Path({str(private)!r})
request=json.loads(sys.stdin.readline())
table=json.loads({json.dumps(table)!r})
counter=root/'counter'
index=int(counter.read_text()) if counter.exists() else 0
assert index<len(table)
selected=table[index]
assert request['tool_name']==selected['tool'] and request['raw_arguments']==selected['arguments']
counter.write_text(str(index+1))
with (root/'inputs.jsonl').open('a') as stream:
 stream.write(json.dumps({{'index':index,'request':request,'classifier_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
 'stdout_sha256':hashlib.sha256((selected['stdout']+'\\n').encode()).hexdigest()}})+'\\n')
sys.stdout.write(selected['stdout']+'\\n')
sys.stdout.flush()
with (root/'emitted.jsonl').open('a') as stream: stream.write(json.dumps({{'index':index,'emitted':True}})+'\\n')
'''


def parse_responses(raw):
    valid, records = True, []
    for line in raw.splitlines(keepends=True):
        try:
            value = HELPER.strict_json(line)
            if not line.endswith("\n") or not isinstance(value, dict) or value.get("jsonrpc") != "2.0" or "id" not in value:
                raise ValueError("bad original server response")
            records.append((line, value))
        except ValueError:
            valid = False
    return records, valid


def run_fixture(demo, binary, out):
    rows, frames, harness, error, gateway_exit = [], [], None, None, None
    artifacts, audit_errors = {}, []
    client_output_complete = False
    with tempfile.TemporaryDirectory(prefix="sou17-generic-") as tmp:
        root = Path(tmp).resolve()
        private = root / "classifier"
        private.mkdir()
        # agent_stack constructs its environment lazily; the classifier path is
        # fixed before the collector starts, after the actual local receiver URL exists.
        script = out / "synthetic-classifier.py"
        demo.classifier_environment = lambda: {"AGENTFW_CLASSIFIER": "rule-baseline",
            "AGENTFW_RULE_BASELINE": str(script), "AGENTFW_CLASSIFIER_PYTHON": sys.executable}
        with demo.agent_stack(binary, root / "workspace") as stack:
            source = classifier_source(private, stack.receiver.url)
            script.write_text(source, encoding="utf-8")
            digest = sha(source.encode())
            try:
                with stack.classifications.open("wb") as log:
                    harness = demo.Harness(stack.collector, stack.env, log)
                    frames.extend(HELPER.initialize(harness))
                    for case in cases():
                        submitted = frame(case, stack.receiver.url)
                        row = {"case": case["name"], "host_call_id": "generic-" + case["name"],
                            "submitted_frame": submitted, "receiver_url": stack.receiver.url,
                            "registry_sha256": stack.registry_sha256}
                        rows.append(row)
                        frames.append(submitted)
                        before = len(stack.receiver.bodies)
                        native_before = HELPER.read(stack.workspace / ".agentfw/audit.jsonl").decode("utf-8", "replace")
                        native_before = audited_records(native_before, audit_errors)
                        response = harness.send(submitted)
                        row["client_response_raw"] = (response or b"").decode("utf-8", "replace")
                        row["receiver_bodies_at_response"] = list(stack.receiver.bodies[before:])
                        native_after = audited_records(HELPER.read(stack.workspace / ".agentfw/audit.jsonl").decode("utf-8", "replace"), audit_errors)
                        if native_after[:len(native_before)] != native_before:
                            raise RuntimeError("native audit prefix changed")
                        row["native_decisions"] = native_after[len(native_before):]
                        if response is None:
                            raise RuntimeError("transport lost during generic matrix")
                    gateway_exit = HELPER.stop(harness)
            except Exception as exception:
                error = {"type": type(exception).__name__, "message": str(exception)}
            finally:
                if harness and harness.process.poll() is None:
                    HELPER.stop(harness)
                if harness:
                    client_output_complete = drain_output(harness)
                raw_ledger = HELPER.read(stack.ledger).decode("utf-8", "replace")
                HELPER.reconcile_final_ledger(rows, raw_ledger)
                classifications = HELPER.telemetry(HELPER.read(stack.classifications).decode("utf-8", "replace"))
                inputs, inputs_valid = json_records(HELPER.read(private / "inputs.jsonl").decode("utf-8", "replace"))
                emissions, emissions_valid = json_records(HELPER.read(private / "emitted.jsonl").decode("utf-8", "replace"))
                originals, server_valid = parse_responses(HELPER.read(stack.responses).decode("utf-8", "replace"))
                for row in rows:
                    index = [item["name"] for item in cases()].index(row["case"])
                    matching_inputs = [item for item in inputs if isinstance(item, dict) and item.get("index") == index]
                    matching_emissions = [item for item in emissions if isinstance(item, dict) and item.get("index") == index]
                    row["classifier_input"] = dict(matching_inputs[0], emitted=matching_emissions[0].get("emitted")) \
                        if inputs_valid and emissions_valid and len(matching_inputs) == len(matching_emissions) == 1 else None
                    row["classifications"] = [item for item in classifications if item.get("host_call_id") == row["host_call_id"]]
                    row["original_server_results"] = [raw for raw, item in originals if item.get("id") == row["host_call_id"]]
                    row["gateway_exit_code"] = gateway_exit
                    row["server_responses_valid"] = server_valid
                    row["native_audit_valid"] = not audit_errors
                    entries, errors = HELPER.ledger(row["executor_ledger_raw"])
                    row["execution_count"] = len(entries) if not errors else None
                    row["client_response_bytes"] = len(row.get("client_response_raw", "").encode())
                    row["released_original_result_bytes"] = row["client_response_bytes"] if row["original_server_results"] == [row.get("client_response_raw")] else 0
                native_final = audited_records(HELPER.read(stack.workspace / ".agentfw/audit.jsonl").decode("utf-8", "replace"), audit_errors)
                for row in rows:
                    row["native_audit_valid"] = not audit_errors
                client_raw = b"".join(harness.received).decode("utf-8", "replace") if harness else ""
                client_frames, client_valid = parse_responses(client_raw)
                transcript = {"client_output_complete": client_output_complete, "client_frames_valid": client_valid,
                    "server_frames_valid": server_valid, "client_frames": [raw for raw, _ in client_frames],
                    "server_frames": [raw for raw, _ in originals]}
                final_receiver = list(stack.receiver.bodies)
                final_entries, final_ledger_errors = HELPER.ledger(raw_ledger)
                final_execution_count = len(final_entries) if not final_ledger_errors else None
                artifacts = {"client-input.jsonl": ("\n".join(frames) + "\n").encode(),
                    "client-output.jsonl": b"".join(harness.received) if harness else b"",
                    "executor-ledger.jsonl": HELPER.read(stack.ledger), "server-responses.jsonl": HELPER.read(stack.responses),
                    "collector.log": HELPER.read(stack.classifications), "native-audit.jsonl": HELPER.read(stack.workspace / ".agentfw/audit.jsonl"),
                    "daemon.log": HELPER.read(stack.workspace / "daemon.log"), "registry.json": HELPER.read(stack.workspace / "registry.json"),
                    "policy.yaml": HELPER.read(stack.workspace / "policy.yaml"), "daemon-config.json": HELPER.read(stack.workspace / ".agentfw/config.yaml"),
                    "classifier-inputs.jsonl": HELPER.read(private / "inputs.jsonl"),
                    "classifier-emitted.jsonl": HELPER.read(private / "emitted.jsonl"),
                    "receiver-bodies.json": (json.dumps(final_receiver) + "\n").encode()}
                tokens = [HELPER.read(stack.workspace / ".agentfw" / name).strip() for name in ("token", "native-token")]
                if any(token and token in data for token in tokens for data in artifacts.values()):
                    raise RuntimeError("fixture credentials detected; refusing artifact retention")
                for name, data in artifacts.items():
                    (out / name).write_bytes(data)
    return {"rows": rows, "classifier_sha256": digest, "classifier_sha256_after": sha(script.read_bytes()),
        "gateway_exit_code": gateway_exit, "classifications": classifications, "native_decisions": native_final,
        "receiver_bodies": final_receiver, "error": error, "transcript": transcript, "native_audit_errors": audit_errors,
        "final_execution_count": final_execution_count,
        "final_ledger_errors": final_ledger_errors,
        "artifacts": {name: {"bytes": len(data), "sha256": sha(data)} for name, data in artifacts.items()}}


def json_records(raw):
    values, valid = [], True
    for line in raw.splitlines(keepends=True):
        try:
            value = HELPER.strict_json(line)
            if not line.endswith("\n") or not isinstance(value, dict):
                raise ValueError("bad JSON witness")
            values.append(value)
        except ValueError:
            valid = False
    return values, valid


def native_records(raw):
    values = []
    for line in raw.splitlines(keepends=True):
        if not line.endswith("\n"):
            raise ValueError("unterminated native audit record")
        value = HELPER.strict_json(line)
        if not isinstance(value, dict) or not isinstance(value.get("event"), str) or not value["event"].strip():
            raise ValueError("malformed native audit record/event")
        if value.get("event") in {"native_call", "native_result"}:
            values.append(value)
    return values


def audited_records(raw, diagnostics):
    try:
        return native_records(raw)
    except ValueError as error:
        diagnostics.append(str(error))
        return []


def drain_output(harness):
    """Retain every stdout frame, including late/unsolicited frames, through EOF."""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            raw = harness.lines.get(timeout=max(.001, deadline - time.monotonic()))
        except queue.Empty:
            return False
        if raw is None:
            return True
        harness.received.append(raw)
    return False


def run(args):
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    if not re.fullmatch(r"[a-f0-9]{40}", args.expected_commit) or not HELPER.digest_valid(args.expected_binary_sha256):
        raise ValueError("exact commit and binary SHA-256 pins required")
    before = HELPER.snapshot(repo)
    if before["commit"] != args.expected_commit or before["dirty"]:
        raise ValueError("candidate must have exact expected HEAD and clean tracked/untracked source")
    binary_before = sha(binary.read_bytes())
    if binary_before != args.expected_binary_sha256:
        raise ValueError("binary SHA-256 differs from the requested pin")
    helper_before = sha(HELPER_PATH.read_bytes())
    if helper_before != sha((repo / "scripts/verify-sou17-pending-admission.py").read_bytes()):
        raise ValueError("shared helper differs from the pinned candidate source")
    script_before = sha(Path(__file__).read_bytes())
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": "sou17-generic-boundary/1", "acceptance_passed": False,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(), "source": before,
        "binary_sha256_before": binary_before, "script_sha256_before": script_before, "helper_sha256_before": helper_before,
        "environment": {"os": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "expected_commit": args.expected_commit, "expected_binary_sha256": args.expected_binary_sha256,
        "expectations": cases(), "limitations": ["Synthetic replies through actual production bridge; classification quality not measured.",
            "Empty actions on a harmless read verifies accepted reply shape, not actual tool no-op behavior.",
            "Source/binary stability does not independently attest build linkage; retain matching pinned launcher evidence.",
            "Resource-profile executor remains unsupported; actual host and external models not tested."],
        "limits": {"active_deadline_seconds": 90, "cases": len(cases()), "external_model_calls": 0}}
    old_handler = signal.getsignal(signal.SIGALRM)
    def deadline(_signum, _frame):
        raise TimeoutError("bounded generic admission probe exceeded 90 seconds")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(90)
    observed = None
    try:
        demo = load_module("sou17_generic_demo", repo / "scripts/mcp-admission-demo.py")
        observed = run_fixture(demo, binary, out)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    after = HELPER.snapshot(repo)
    binary_after, script_after, helper_after = sha(binary.read_bytes()), sha(Path(__file__).read_bytes()), sha(HELPER_PATH.read_bytes())
    stable = before == after and binary_before == binary_after and script_before == script_after and helper_before == helper_after \
        and observed is not None and observed["classifier_sha256"] == observed["classifier_sha256_after"]
    status, code = grade_report(observed["rows"], stable, observed["classifier_sha256"], observed["receiver_bodies"],
        observed["native_decisions"], observed["classifications"], observed["gateway_exit_code"],
        transcript=observed["transcript"], error=observed["error"]) if observed else ("inconclusive", 2)
    report.update(status=status, stable=stable, source_after=after, binary_sha256_after=binary_after,
        script_sha256_after=script_after, helper_sha256_after=helper_after, observed=observed)
    rows = observed["rows"] if observed else []
    report["counts"] = {kind: sum(row["grade"]["status"] == kind for row in rows) for kind in ("pass", "fail", "inconclusive")}
    report["execution_count"] = observed["final_execution_count"] if observed else None
    report["released_original_result_bytes"] = sum(row.get("released_original_result_bytes") or 0 for row in rows)
    (out / "results.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    (out / "report.md").write_text("# SOU-17 strict generic boundary\n\n"
        + f"Status: **{status}**; complete acceptance: **false**. Candidate: `{before['commit']}`.\n\n"
        + "| Case | Grade | Observation |\n| --- | --- | --- |\n"
        + "".join(f"| {row['case']} | {row['grade']['status']} | {row['grade']['reason']} |\n" for row in rows)
        + "\nRaw original/unexpected responses and independent executor/receiver witnesses are retained.\n"
        + "Empty-action fixtures are reply-shape tests, not classifier-quality evidence.\n", encoding="utf-8")
    print(json.dumps({"status": status, "counts": report["counts"], "acceptance_passed": False,
        "execution_count": report["execution_count"], "released_original_result_bytes": report["released_original_result_bytes"], "results": str(out / "results.json")}))
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    if sys.platform not in {"linux", "darwin"}:
        parser.error("native Linux/macOS Python required for POSIX bounded diagnostics")
    try:
        return run(args)
    except Exception as error:
        print(f"Inconclusive: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
