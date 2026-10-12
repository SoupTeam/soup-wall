#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Safe local diagnostic of classifier actions versus a trusted registry baseline.

This intentionally changes an operator registry before daemon startup. ReadOnly
for the fixture's send_http is an incorrect semantic declaration, not registry
tampering by an untrusted tool. No production source, native pipeline or policy
implementation is substituted. Exit 0 confirms the declared diagnostic pattern;
exit 2 means inconclusive. Complete SOU-17 acceptance always remains false.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

COMMIT = "45b611a36834533b9d17d12d6b9a1357a3843457"
CALL_ID = "action-scope-call"
RULE = "action-scope-sensitive-send"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def reject(_value):
        raise ValueError("nonfinite JSON")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, parse_constant=reject, object_pairs_hook=pairs)


def records(raw):
    if raw and not raw.endswith(b"\n"):
        raise ValueError("unterminated witness")
    result = [strict_json(line) for line in raw.splitlines()]
    if any(not isinstance(row, dict) for row in result):
        raise ValueError("witness row is not an object")
    return result


def read(path):
    return path.read_bytes() if path.is_file() else b""


def snapshot(repo):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, timeout=10).decode().strip()
    return {"commit": git("rev-parse", "HEAD"),
            "dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
            "tree": git("rev-parse", "HEAD^{tree}")}


def policy(require_network):
    minimum = ", min_action_class: network" if require_network else ""
    return f"""agent_policies:
  - name: {RULE}
    when: {{ detector: secret, facet: tool_args{minimum} }}
    action: deny
egress_allowlist: [127.0.0.1]
default: allow
"""


def classifier_source(actions, args):
    reply = {"status": "ok", "actions": actions, "unknown": False, "confidence": 0.95,
             "uncertainty": 0.05, "reason": "Synthetic action-set versus trusted-baseline diagnostic"}
    return ("#!/usr/bin/env python3\n# SPDX-License-Identifier: Apache-2.0\n"
            "import json,sys\nrequest=json.loads(sys.stdin.readline())\n"
            "assert request['tool_name']=='send_http'\n"
            f"assert request['raw_arguments']==json.loads({json.dumps(args)!r})\n"
            f"print({json.dumps(reply, separators=(',', ':'))!r})\n")


def run_case(demo, binary, out, name, baseline, require_network, actions, args, expected_execute):
    directory = out / name
    directory.mkdir()
    source = classifier_source(actions, args).encode()
    classifier = directory / "classifier.py"
    classifier.write_bytes(source)
    original_registry = demo._scope_original_registry
    def registry(tools):
        value = strict_json(original_registry(tools))
        selected = next(tool for tool in value["tools"] if tool["name"] == "send_http")
        # Preserve the default Send fixture's declared URL selector and schema.
        selected["action_class"] = baseline
        assert selected["egress"] == [{"pointer": "/url", "kind": "url_host", "optional": False}]
        return demo.canonical(value)
    demo.registry = registry
    demo.POLICY = policy(require_network)
    demo.classifier_environment = lambda: {
        "AGENTFW_CLASSIFIER": "rule-baseline", "AGENTFW_RULE_BASELINE": str(classifier),
        "AGENTFW_CLASSIFIER_PYTHON": sys.executable}
    row = {"case": name, "operator_baseline": baseline, "rule_requires_network": require_network,
           "classifier_actions": actions, "classifier_sha256": sha(source),
           "actual_arguments": args, "arguments_sha256": sha(demo.canonical(args)),
           "expected_executor_count": int(expected_execute), "status": "inconclusive"}
    harness = None
    try:
        with tempfile.TemporaryDirectory(prefix="sou17-action-scope-") as temp:
            with demo.agent_stack(binary, Path(temp).resolve() / "workspace") as stack:
                receiver_before = len(stack.receiver.bodies)
                frames = [
                    '{"jsonrpc":"2.0","id":"scope-init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"claude-code","version":"scope-fixture"}}}',
                    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
                    '{"jsonrpc":"2.0","id":"scope-list","method":"tools/list"}',
                ]
                with stack.classifications.open("wb") as log:
                    harness = demo.Harness(stack.collector, stack.env, log)
                    initialized = harness.send(frames[0])
                    harness.send(frames[1], reply=False)
                    manifest = harness.send(frames[2])
                    if not initialized or strict_json(initialized).get("id") != "scope-init" \
                            or not manifest or strict_json(manifest).get("result", {}).get("tools") != stack.tools:
                        raise ValueError("initialization/discovery was not admitted")
                    frame = json.dumps({"jsonrpc": "2.0", "id": CALL_ID, "method": "tools/call",
                        "params": {"name": "send_http", "arguments": args,
                            "_meta": {"claudecode/toolUseId": "toolu_scope", "progressToken": 17}}}, separators=(",", ":"))
                    frames.append(frame)
                    delivered = harness.send(frame)
                    exit_code = harness.close()
                blobs = {"client-input.jsonl": ("\n".join(frames) + "\n").encode(),
                    "client-output.jsonl": b"".join(harness.received), "call-response.jsonl": delivered or b"",
                    "executor-ledger.jsonl": read(stack.ledger), "server-responses.jsonl": read(stack.responses),
                    "collector.log": read(stack.classifications), "daemon.log": read(stack.workspace / "daemon.log"),
                    "native-audit.jsonl": read(stack.workspace / ".agentfw/audit.jsonl"),
                    "registry.json": read(stack.workspace / "registry.json"), "policy.yaml": read(stack.workspace / "policy.yaml"),
                    "daemon-config.json": read(stack.workspace / ".agentfw/config.yaml")}
                credentials = [read(stack.workspace / ".agentfw" / token).strip() for token in ("token", "native-token")]
                if any(token and token in blob for token in credentials for blob in blobs.values()):
                    raise ValueError("fixture credential found; refusing evidence retention")
                executions = records(blobs["executor-ledger.jsonl"])
                original = [line for line in blobs["server-responses.jsonl"].splitlines(keepends=True)
                            if strict_json(line).get("id") == CALL_ID]
                classifications = [entry for entry in demo.classification_evidence(stack.classifications)
                                   if entry.get("host_call_id") == CALL_ID]
                native = [entry for entry in records(blobs["native-audit.jsonl"])
                          if entry.get("event") in ("native_call", "native_result")]
                receiver_bodies = stack.receiver.bodies[receiver_before:]
                response = strict_json(delivered) if delivered else None
                exact_result = bool(delivered and len(original) == 1 and delivered == original[0])
                row.update(executor_count=len(executions), executor_original_bytes=blobs["executor-ledger.jsonl"] == (frame + "\n").encode(),
                    receiver_count=len(receiver_bodies), receiver_bodies=receiver_bodies,
                    receiver_body_sha256=[sha(body.encode()) for body in receiver_bodies],
                    original_server_result_count=len(original), client_response=response,
                    original_result_bytes_released=len(delivered) if exact_result else 0, exact_original_result_released=exact_result,
                    classifications=classifications, native_decisions=native, gateway_exit_code=exit_code,
                    registry_sha256=sha(blobs["registry.json"]), policy_sha256=sha(blobs["policy.yaml"]),
                    config_sha256=sha(blobs["daemon-config.json"]), original_call_sha256=sha((frame + "\n").encode()))
                configured = strict_json(blobs["daemon-config.json"])
                registered = next(tool for tool in strict_json(blobs["registry.json"])["tools"] if tool["name"] == "send_http")
                semantic = classifications[0] if len(classifications) == 1 else {}
                prediction = semantic.get("classification", {})
                valid = configured.get("enforce") is True and configured.get("native", {}).get("registry_sha256") == row["registry_sha256"] \
                    and registered.get("action_class") == baseline and registered.get("egress") == [
                        {"pointer": "/url", "kind": "url_host", "optional": False}] \
                    and semantic.get("source") == "rule-baseline/python" and semantic.get("classifier_sha256") == sha(source) \
                    and semantic.get("args_sha256") == row["arguments_sha256"] and semantic.get("trusted_baseline") == baseline \
                    and semantic.get("policy") == "reached" and semantic.get("failure") is None \
                    and semantic.get("authoritative_verdict") == "allow" and prediction.get("actions") == actions \
                    and prediction.get("unknown") is False and prediction.get("confidence") == 0.95 \
                    and prediction.get("uncertainty") == 0.05 and isinstance(response, dict) \
                    and response.get("jsonrpc") == "2.0" and response.get("id") == CALL_ID and exit_code == 0
                if expected_execute:
                    boundary = executions == [strict_json(frame)] and row["executor_original_bytes"] \
                        and receiver_bodies == [args["body"]] and exact_result \
                        and response.get("result") == {"content": [{"type": "text", "text": "Recipient accepted the body"}]} \
                        and [event.get("verdict") for event in native] == ["allow", "allow"] \
                        and [event.get("event") for event in native] == ["native_call", "native_result"]
                else:
                    boundary = blobs["executor-ledger.jsonl"] == b"" and not original and not receiver_bodies \
                        and response.get("result", {}).get("isError") is True \
                        and RULE in json.dumps(response) and len(native) == 1 \
                        and native[0].get("event") == "native_call" and native[0].get("verdict") == "deny" \
                        and native[0].get("reason_codes") == [RULE]
                row["status"] = "diagnostic_expectation_observed" if valid and boundary else "inconclusive"
                row["artifacts"] = {name: {"bytes": len(blob), "sha256": sha(blob)} for name, blob in blobs.items()}
                for name, blob in blobs.items():
                    (directory / name).write_bytes(blob)
    except Exception as error:
        if harness and harness.process.poll() is None:
            demo.stop(harness.process)
        row.update(status="inconclusive", error_type=type(error).__name__, error=str(error))
    (directory / "results.json").write_text(json.dumps(row, indent=2, allow_nan=False) + "\n")
    print(json.dumps({key: row.get(key) for key in ("case", "status", "executor_count", "receiver_count", "original_result_bytes_released", "error")}))
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    before = snapshot(repo)
    if before["commit"] != COMMIT or before["dirty"] or not binary.is_file():
        parser.error("clean exact PR82 merged source and separately pinned binary required")
    binary_digest = sha(binary.read_bytes())
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("sou17_action_scope_demo", repo / "scripts/mcp-admission-demo.py")
    demo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = demo
    spec.loader.exec_module(demo)
    demo._scope_original_registry = demo.registry
    shared = demo.Receiver()
    class SharedReceiver:
        def __init__(self):
            self.url, self.bodies = shared.url, shared.bodies
        def close(self):
            pass  # Outer owner keeps one identical recipient across fresh daemons.
    demo.Receiver = SharedReceiver
    sensitive = {"url": shared.url, "body": "key=" + demo.SECRET}
    benign = {"url": shared.url, "body": "Synthetic benign fixture summary: 7 red widgets."}
    report = {"schema_version": "sou17-action-scope-diagnostic/0.1", "acceptance_passed": False,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(), "source_before": before,
        "binary": {"path": str(binary), "sha256": binary_digest}, "probe_script_sha256": sha(Path(__file__).read_bytes()),
        "scope": "Reviewed safe fixture server; operator registry baseline changed BEFORE startup; fixed owned loopback receiver; synthetic classifier seam.",
        "payload_provenance": "Published demonstration-only key from existing demo.SECRET; no credential/user data.",
        "source_files_sha256": {name: sha((repo / name).read_bytes()) for name in (
            "scripts/mcp-admission-demo.py", "scripts/fixtures/mcp_admission_demo_server.py", "crates/agentfw/src/mcp/admission.rs",
            "crates/agentfw/src/native.rs", "crates/agent/src/engine.rs", "crates/agent/src/policy.rs", "crates/agent/src/action.rs")},
        "cases": []}
    prior = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("90-second diagnostic deadline")))
    signal.alarm(90)
    try:
        for values in [
            ("network-mixed-sensitive", "network", True, ["read", "send_data"], sensitive, False),
            ("readonly-mixed-sensitive", "read_only", True, ["read", "send_data"], sensitive, True),
            ("readonly-mixed-unconditional-secret", "read_only", False, ["read", "send_data"], sensitive, False),
            ("readonly-singleton-sensitive", "read_only", True, ["read"], sensitive, True),
            ("network-mixed-benign", "network", True, ["read", "send_data"], benign, True),
        ]:
            report["cases"].append(run_case(demo, binary, out, *values))
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prior)
        shared.close()
    report["source_after"] = snapshot(repo)
    report["stable"] = before == report["source_after"] and sha(binary.read_bytes()) == binary_digest
    paired = report["cases"][:3]
    report["counterfactual_inputs_identical"] = len(paired) == 3 and all(
        row.get("arguments_sha256") == paired[0].get("arguments_sha256")
        and row.get("classifier_sha256") == paired[0].get("classifier_sha256")
        and row.get("original_call_sha256") == paired[0].get("original_call_sha256") for row in paired)
    observed = report["stable"] and report["counterfactual_inputs_identical"] and len(report["cases"]) == 5 \
        and all(row["status"] == "diagnostic_expectation_observed" for row in report["cases"]) and "error" not in report
    report["status"] = "scope_difference_observed" if observed else "inconclusive"
    report["interpretation"] = ("With a correctly declared Network baseline, the configured network-sensitive rule denied the sensitive fixture before execution. With the deliberately incorrect ReadOnly baseline and the same admitted egress, args and mixed classifier actions, the call executed and its synthetic bytes reached the owned receiver. An unconditional secret rule still denied it; an understated singleton classifier also executed under that incorrect baseline. This demonstrates dependence on trusted registry semantics, not registry tampering, arbitrary-server containment, or a bypass of correctly declared Network fixtures. Full per-classified-action configured-rule evaluation is not established.")
    (out / "results.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "acceptance_passed": False, "output": str(out)}))
    return 0 if observed else 2


if __name__ == "__main__":
    raise SystemExit(main())
