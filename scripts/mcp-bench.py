#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure real local MCP requests using the existing admission demo fixtures."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import platform
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def distribution(samples):
    if not samples or any(type(x) not in (int, float) or not math.isfinite(x) for x in samples):
        raise ValueError("finite, nonempty samples required")
    values = sorted(samples)
    return {"samples": len(values), "mean_ns": statistics.mean(values),
            "min_ns": values[0], "max_ns": values[-1],
            **{f"p{p}_ns": values[math.ceil(len(values) * p / 100) - 1] for p in (50, 95, 99)}}


def benign_metrics(rows):
    benign = [row for row in rows if row["benign"]]
    allowed = [row for row in benign if row["expected_outcome"] == "allow"]
    interrupted = [row for row in benign if not row["executed"]]
    false = [row for row in allowed if not row["executed"] or row["actual_outcome"] != "allow"]
    return {"benign_total": len(benign), "expected_allow_total": len(allowed),
            "unexpected_false_blocks": len(false), "benign_interruptions": len(interrupted),
            "benign_verdict_counts": dict(Counter(row["actual_outcome"] for row in benign)),
            "unexpected_false_block_rate_all_benign": len(false) / len(benign) if benign else None,
            "unexpected_false_block_rate_expected_allow": len(false) / len(allowed) if allowed else None,
            "benign_interruption_rate": len(interrupted) / len(benign) if benign else None,
            "false_block_ids": [row["scenario"] for row in false]}


def load_demo(repo):
    spec = importlib.util.spec_from_file_location("task3_existing_demo", repo / "scripts/mcp-admission-demo.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.REAL_BASELINE = True
    module.CLASSIFIER = "rule-baseline/python"
    return module


def initialize(harness):
    responses = []
    for frame in (
        '{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"task3-local-evaluation","version":"1"}}}',
        '{"jsonrpc":"2.0","id":"list","method":"tools/list"}',
    ):
        response = harness.send(frame)
        if not response or "result" not in json.loads(response):
            raise RuntimeError("MCP initialization/discovery failed")
        responses.append(response)
        if json.loads(frame)["method"] == "initialize":
            harness.send('{"jsonrpc":"2.0","method":"notifications/initialized"}', reply=False)
    return responses


@contextmanager
def client(demo, command, env, log):
    with log.open("wb") as errors:
        harness = demo.Harness(command, env, errors)
        try:
            harness.initialization_responses = initialize(harness)
            yield harness
        finally:
            code = harness.close()
            if harness.process.poll() is None:
                demo.stop(harness.process)
            if sys.exc_info()[0] is None and code != 0:
                raise RuntimeError(f"MCP process exit {code}")


def exchange(demo, harness, stack, request_id, tool, arguments, expected, ledger, responses, witnesses=None):
    before = len(demo.lines(ledger))
    receivers = len(stack.receiver.bodies)
    started = time.perf_counter_ns()
    frame, response = harness.call(request_id, tool, arguments)
    elapsed = time.perf_counter_ns() - started
    if response is None:
        raise RuntimeError("request timed out or transport closed")
    reply = json.loads(response)
    if reply.get("id") != request_id or reply.get("jsonrpc") != "2.0":
        raise RuntimeError("native response identity changed")
    result = reply.get("result", {})
    text = reply.get("error", {}).get("message", (result.get("content") or [{}])[0].get("text", ""))
    actual = demo.outcome_of(text, "error" in reply or result.get("isError"))
    calls = demo.lines(ledger)[before:]
    delivery = len(stack.receiver.bodies) - receivers
    if actual != expected or len(calls) != int(expected == "allow") or delivery != 0:
        raise RuntimeError(f"{tool}: expected {expected}; got {actual}, executions={len(calls)}, deliveries={delivery}")
    if expected == "allow":
        if calls != [(frame + "\n").encode()] or demo.lines(responses)[-1] != response:
            raise RuntimeError("original arguments/call/result bytes changed")
        if witnesses is not None:
            witnesses.append(((frame + "\n").encode(), response))
    return {"call_id": request_id, "tool": tool, "expected_verdict": expected,
            "actual_verdict": actual, "executor_count": len(calls), "receiver_delta": delivery,
            "request_ns": elapsed, "call_sha256": hashlib.sha256(frame.encode()).hexdigest(),
            "response_sha256": hashlib.sha256(response).hexdigest()}


def verify_complete_execution(ledger, responses, witnesses, initialization=()):
    for path, column, label in ((ledger, 0, "executor"), (responses, 1, "server result")):
        actual = path.read_bytes() if path.is_file() else b""
        expected = (b"".join(initialization) if column == 1 else b"") + b"".join(row[column] for row in witnesses)
        if actual != expected:
            raise RuntimeError(f"post-stop {label} witness mismatch: missing, extra or changed bytes")


def retain(demo, stack, directory, paths):
    artifacts = {}
    tokens = [(stack.workspace / ".agentfw" / name).read_bytes().strip()
              for name in ("token", "native-token") if (stack.workspace / ".agentfw" / name).is_file()]
    for name, path in paths.items():
        data = path.read_bytes() if path.is_file() else b""
        if any(token and token in data for token in tokens):
            raise RuntimeError("fixture credential found in evidence")
        destination = directory / name
        destination.write_bytes(data)
        artifacts[name] = {"bytes": len(data), "sha256": digest(destination)}
    return artifacts


@contextmanager
def witnessed_stack(demo, binary, temporary, directory):
    with demo.agent_stack(binary, Path(temporary) / "protected") as stack:
        try:
            yield stack
        except Exception:
            retain(demo, stack, directory, {
                "failed-executor.jsonl": stack.ledger, "failed-results.jsonl": stack.responses,
                "failed-classifier.log": stack.classifications,
                "failed-daemon.log": stack.workspace / "daemon.log",
                "failed-native-audit.jsonl": stack.workspace / ".agentfw/audit.jsonl",
            })
            raise


def benchmark_session(demo, binary, out, count, warmup, repeat):
    directory = out / f"latency-{repeat}"
    directory.mkdir()
    records = {name: [] for name in ("direct", "allow", "deny", "ask")}
    pairs = []
    witnesses = {name: [] for name in ("direct", "protected")}
    with tempfile.TemporaryDirectory(prefix="task3-latency-") as temporary:
        with witnessed_stack(demo, binary, temporary, directory) as stack:
            direct_ledger = Path(temporary) / "direct-ledger.jsonl"
            direct_command = [sys.executable, "-I", "-u", str(demo.FIXTURE), "--notes", str(stack.notes),
                              "--ledger", str(direct_ledger), "--recipient", stack.receiver.url]
            with client(demo, stack.collector, stack.env, stack.classifications) as protected:
                with client(demo, direct_command, stack.env, Path(temporary) / "direct.log") as direct:
                    for index in range(warmup + count):
                        request_id = 1000 + index
                        observed = {}
                        for name in (("direct", "allow") if index % 2 == 0 else ("allow", "direct")):
                            ledger = direct_ledger if name == "direct" else stack.ledger
                            response_file = ledger.with_suffix(".responses")
                            row = exchange(demo, direct if name == "direct" else protected, stack,
                                           request_id, "read_document", {"name": "inventory"}, "allow", ledger, response_file,
                                           witnesses["direct" if name == "direct" else "protected"])
                            if index >= warmup:
                                records[name].append(row)
                                observed[name] = row["request_ns"]
                        if observed:
                            pairs.append(observed["allow"] - observed["direct"])
                    for mode, tool, arguments in (
                        ("deny", "delete_note", {"name": "inventory"}),
                        ("ask", "send_http", {"url": stack.receiver.url, "body": "Contact alice@example.com"}),
                    ):
                        for index in range(warmup + count):
                            request_id = (2000 if mode == "deny" else 3000) + index
                            row = exchange(demo, protected, stack, request_id,
                                           tool, arguments, mode, stack.ledger, stack.responses)
                            if index >= warmup:
                                records[mode].append(row)
        hashes = retain(demo, stack, directory, {
            "protected-executor.jsonl": stack.ledger, "direct-executor.jsonl": direct_ledger,
            "protected-server-results.jsonl": stack.responses,
            "direct-server-results.jsonl": direct_ledger.with_suffix(".responses"),
            "classification.jsonl": stack.classifications,
            "native-audit.jsonl": stack.workspace / ".agentfw/audit.jsonl",
            "policy.yaml": stack.workspace / "policy.yaml", "registry.json": stack.workspace / "registry.json",
        })
        verify_complete_execution(stack.ledger, stack.responses, witnesses["protected"], protected.initialization_responses)
        verify_complete_execution(direct_ledger, direct_ledger.with_suffix(".responses"), witnesses["direct"], direct.initialization_responses)
        evidence = demo.classification_evidence(stack.classifications)
        expected_count = 3 * (count + warmup)
        if len(evidence) != expected_count or any(row.get("source") != "rule-baseline/python" for row in evidence):
            raise RuntimeError("missing/duplicate/incorrect real-classifier evidence")
        if stack.receiver.bodies or (stack.notes / "inventory.txt").read_text() != "Inventory: 7 red widgets.":
            raise RuntimeError("refused call produced a delayed side effect")
    stats = {name: distribution([row["request_ns"] for row in rows]) for name, rows in records.items()}
    added = stats["allow"]["mean_ns"] - stats["direct"]["mean_ns"]
    result = {"repeat": repeat, "samples_per_path": count, "warmup_per_path": warmup,
              "percentile_method": "nearest-rank ceil(N*p), p50/p95/p99; all raw samples retained",
              "scope": "client write through original stdio MCP transport to response read; real Python baseline, collector, daemon and local file server",
              "policy_timing": "not separately instrumented; no subtraction claimed as pure policy cost",
              "profile": "debug, no incremental compilation, build/startup/discovery/witness validation excluded",
              "summary": stats, "paired_added_ns": pairs, "paired_added_summary": distribution(pairs),
              "mean_overhead_ms": added / 1_000_000,
              "relative_mean_overhead_percent": added / stats["direct"]["mean_ns"] * 100,
              "post_stop_reconciled": True,
              "complete_execution_counts": {name: len(rows) for name, rows in witnesses.items()},
              "records": records, "artifacts": hashes, "status": "pass"}
    (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return {key: value for key, value in result.items() if key not in {"records", "paired_added_ns"}}


def session_batches(count, warmup):
    per_session = 20 - warmup
    if count < 1 or warmup < 1 or per_session < 1:
        raise ValueError("positive sample count and warmup between 1 and 19 required")
    return [min(per_session, count - index) for index in range(0, count, per_session)]


def benchmark(demo, binary, out, count, warmup, repeat):
    rows = {name: [] for name in ("direct", "allow", "deny", "ask")}
    pairs, batches = [], []
    sizes = session_batches(count, warmup)
    for size in sizes:
        label = f"{repeat}-batch-{len(batches) + 1}"
        batch = benchmark_session(demo, binary, out, size, warmup, label)
        batches.append(batch)
        raw = json.loads((out / f"latency-{label}" / "results.json").read_text())
        for name in rows:
            rows[name].extend(raw["records"][name])
        pairs.extend(raw["paired_added_ns"])
    stats = {name: distribution([row["request_ns"] for row in values]) for name, values in rows.items()}
    added = stats["allow"]["mean_ns"] - stats["direct"]["mean_ns"]
    return {"repeat": repeat, "samples_per_path": count, "sessions": len(batches),
            "warmup_per_path_per_session": warmup, "warmup_per_path_total": warmup * len(batches),
            "max_protected_calls_per_session": 3 * (warmup + max(sizes)),
            "summary": stats, "paired_added_summary": distribution(pairs),
            "mean_overhead_ms": added / 1_000_000,
            "relative_mean_overhead_percent": added / stats["direct"]["mean_ns"] * 100,
            "batches": batches, "status": "pass"}


def quality(demo, binary, out):
    directory = out / "runtime-scenarios"
    directory.mkdir()
    with tempfile.TemporaryDirectory(prefix="task3-runtime-") as temporary:
        with demo.agent_stack(binary, Path(temporary) / "workspace") as stack:
            result = demo.scripted(stack)
            for row in result["rows"]:
                row["benign"] = row["scenario"] in {
                    "read_allowed", "send_allowed", "unfamiliar_publish_report_allowed",
                    "email_send_needs_confirmation", "work_continues"}
            result["summary"] = demo.summarize(result["rows"])
            result["benign_metrics"] = benign_metrics(result["rows"])
            result["artifacts"] = retain(demo, stack, directory, {
                "executor-ledger.jsonl": stack.ledger, "server-results.jsonl": stack.responses,
                "classification.jsonl": stack.classifications,
                "native-audit.jsonl": stack.workspace / ".agentfw/audit.jsonl",
                "policy.yaml": stack.workspace / "policy.yaml", "registry.json": stack.workspace / "registry.json",
            })
            result["passed"] = all(row["passed"] for row in result["rows"]) and all(row["passed"] for row in result["checks"])
    (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    if not result["passed"]:
        raise RuntimeError("real baseline scenario mismatch; see runtime-scenarios/results.json")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=5, help="warmup per path in each bounded session")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.samples < 100 or not 1 <= args.warmup < 20 or args.repeats < 1:
        parser.error("at least 100 samples, 1-19 warmups per path per session and 1 repeat required")
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.out.resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo, text=True)
    if commit != args.expected_commit or dirty.strip():
        parser.error("exact commit and clean tracked runtime source required")
    out.mkdir(parents=True, exist_ok=False)
    inputs = {name: digest(repo / name) for name in (
        "rule_baseline/rule_baseline.py", "scripts/mcp-admission-demo.py",
        "scripts/fixtures/mcp_admission_demo_server.py", "contract/updated_contract2.md",
        "crates/agentfw/src/mcp/admission.rs", "crates/agentfw/src/native.rs", "Cargo.lock")}
    report = {"schema_version": "task3-shared-local-evaluation/1", "source_commit": commit,
              "tracked_dirty": False, "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "script_sha256": digest(__file__), "agentfw_sha256": digest(binary), "inputs_sha256": inputs,
              "environment": {"python": sys.version, "platform": platform.platform(), "machine": platform.machine()},
              "limitations": ["Synthetic local diagnostic fixtures; no population false-positive or model accuracy claim.",
                  "Scripted native MCP frames, not an installed Claude Code host or external provider.",
                  "Trusted fixture server; generic resource-profile execution remains unsupported.",
                  "Debug binaries and Docker/WSL scheduling; timing is not a release performance gate."],
              "status": "error", "latency": []}
    try:
        demo = load_demo(repo)
        report["runtime"] = quality(demo, binary, out)
        print("Real classifier runtime scenarios passed", flush=True)
        for repeat in range(1, args.repeats + 1):
            report["latency"].append(benchmark(demo, binary, out, args.samples, args.warmup, repeat))
            print(f"Latency repeat {repeat}: {args.samples} samples per path", flush=True)
        if digest(binary) != report["agentfw_sha256"] or any(digest(repo / name) != value for name, value in inputs.items()):
            raise RuntimeError("tested binary/source changed during evaluation")
        if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip() != commit:
            raise RuntimeError("HEAD changed during evaluation")
        if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo, text=True).strip():
            raise RuntimeError("tracked runtime source changed during evaluation")
        report["status"] = "pass"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        print(report["error"], file=sys.stderr)
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
