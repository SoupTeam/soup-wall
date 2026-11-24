#!/usr/bin/env python3
"""Run the public SOU-36 development selection under its two original producers."""
import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

REVISIONS = {"baseline": "6fe98d71fc2b806d996ec0ca493f20f4d9da2202",
             "candidate": "ad41af500710450e8f1697da57eafdf5571301fa"}
MODEL = "sou153-owned-read-only"
BUDGET = {"max_calls": 64, "max_total_request_bytes": 16 * 1024 * 1024, "max_output_tokens": 64,
          "max_reserved_usd": 0, "input_usd_per_million": 0, "output_usd_per_million": 0}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], timeout=30, text=True).strip()


class ScriptedProvider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        count = int(self.headers.get("Content-Length", "0"))
        if self.path != "/v1/chat/completions" or not 0 < count <= BUDGET["max_total_request_bytes"]:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(count))
        if request.get("model") != MODEL:
            self.send_error(400)
            return
        self.server.request_count += 1
        has_result = any(message["role"] == "tool" for message in request["messages"])
        message = {"role": "assistant", "content": "Scripted read-only development exercise complete."}
        finish = "stop"
        if not has_result:
            if not any(tool["function"]["name"] == "list_files" for tool in request.get("tools", [])):
                self.send_error(422)
                return
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_sou153_list_files", "type": "function",
                "function": {"name": "list_files", "arguments": "{}"},
            }]}
            finish = "tool_calls"
        raw = json.dumps({"id": "sou153-script", "object": "chat.completion", "created": 0, "model": MODEL,
                          "choices": [{"index": 0, "finish_reason": finish, "message": message}],
                          "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout_parent", type=Path)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    args = parser.parse_args()
    parent, upstream, output = (p.resolve() for p in (args.checkout_parent, args.upstream, args.output))
    output.mkdir(mode=0o700)
    host_script = Path(__file__).resolve()
    cargo = args.cargo.resolve(strict=True)
    rustc = args.rustc.resolve(strict=True)
    receipt = {"provider_source_sha256": file_sha(host_script), "rustc_sha256": file_sha(rustc),
               "cargo_sha256": file_sha(cargo), "python_sha256": file_sha(Path(sys.executable)),
               "rustc": subprocess.check_output([rustc, "-vV"], timeout=30, text=True).strip(),
               "build_command": ["cargo", "build", "--locked", "-p", "agentfw", "--bin", "agentfw"],
               "build_environment": {"CARGO_BUILD_JOBS": "1", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0"},
               "evidence": {}, "gaps": ["upstream case manifest absent", "producer semantic families absent",
                                       "producer unknown outcomes unavailable", "script independent of supplied prompts"]}
    sys.dont_write_bytecode = True
    with HTTPServer(("127.0.0.1", 0), ScriptedProvider) as provider:
        provider.request_count = 0
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{provider.server_port}/v1"
        try:
            prepare_and_run(parent, upstream, output, base_url, provider, receipt)
        finally:
            provider.shutdown()
            thread.join(timeout=5)
            write(output / "run-receipt.json", receipt)


def prepare_and_run(parent, upstream, output, base_url, provider, receipt):
    frozen = datetime.now(timezone.utc).isoformat()
    baseline = parent / "baseline"
    candidate = parent / "candidate"
    sys.path.insert(0, str(candidate / "scripts/benchmarks"))
    cli = load(candidate / "scripts/agentdojo-live.py", "candidate_producer")
    from agentdojo_workspace import registry_bytes
    upstream_identity = cli.adapter.load_upstream(upstream).verified
    receipt["upstream"] = upstream_identity
    shared_plan_path = baseline / "scripts/benchmarks/agentdojo-sou36-workspace.plan.json"
    shared_plan = shared_plan_path.read_bytes()
    if shared_plan != (candidate / shared_plan_path.relative_to(baseline)).read_bytes():
        raise ValueError("public workspace selection drift")
    template = cli.protocol.load_plan(shared_plan, cli.adapter.REVISION)
    if upstream_identity["source_inventory_sha256"] != template["upstream"]["source_inventory_sha256"]:
        raise ValueError("public suite source inventory changed")
    if cli.installed_lock_identity() != template["identities"]["runtime"]["dependency_lock_sha256"]:
        raise ValueError("producer dependency lock differs")
    suite, attack = cli.upstream_attack(template)
    if cli.derive_cases(suite, attack, template["selection"], template["sets"]) != template["sets"]:
        raise ValueError("public suite selection does not reproduce")
    registry = registry_bytes(suite.tools)
    (output / "candidate-registry.json").write_bytes(registry)
    files = {name: (upstream / name).read_bytes().decode("utf-8")
             for name in git(upstream, "ls-files", "src").splitlines()}
    injections = {}
    for row in template["sets"]["development"]["cases"]:
        if row["injection_task_id"] is not None:
            task = suite.get_user_task_by_id(row["user_task_id"])
            injection = suite.get_injection_task_by_id(row["injection_task_id"])
            injections[row["case_id"]] = attack.attack(task, injection)
    write(output / "inputs.json", {
        "schema": "soup-wall-paired-regression-inputs/1", "case_manifest": None, "files": files,
        "provenance": {"kind": "public-upstream", "description": "Pinned public AgentDojo src tree and original development injections"},
        "upstream": {key: template["upstream"][key] for key in ("revision", "suite", "benchmark_version")},
        "injections": injections,
    })

    commands = {}
    for label, revision in REVISIONS.items():
        repo = parent / label
        if git(repo, "rev-parse", "HEAD") != revision or git(repo, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError(label + " source changed")
        binary = parent / (label + "-agentfw")
        binary_sha = file_sha(binary)
        policy = repo / "crates/agent/policies/agent-default.yaml"
        registry_path = output / "candidate-registry.json"
        selected_registry = label == "candidate"
        plan = json.loads(shared_plan)
        plan["plan_id"] = "sou153-public-scripted-" + label
        plan["frozen_at_utc"] = frozen
        plan["identities"].update(
            candidate={"source_revision": revision, "agent_binary_sha256": binary_sha,
                       "adapter": "sw-native/1" if selected_registry else "existing-hook-native-name-fallback-v1",
                       "native_semantics_registry_sha256": sha(registry) if selected_registry else None},
            policy_sha256=file_sha(policy),
            model={"provider": "openai-compatible", "model_id": MODEL, "provider_url_sha256": sha(base_url.encode())})
        plan["identities"]["runtime"]["python"] = ".".join(str(n) for n in sys.version_info[:3])
        plan["access"] = {
            "model_access": {"status": "selected", "kind": "local-fixture", "reference": "SOU-153 owned loopback script"},
            "budget_approval": {"status": "approved", "approved_by": "SOU-153 owner-authorized local scripted run",
                                "reference": "zero-cost loopback only; no live access or fresh evaluation authorized"},
        }
        plan["notes"] = ["Public SOU-36 development set, original evaluators, deterministic read-only loopback script.",
                         "No remote provider, inference or fresh evaluation. No safety or utility efficacy claim."]
        plan["sets"]["development"]["budget"] = dict(BUDGET)
        plan_path = output / (label + "-plan.json")
        write(plan_path, plan)
        (repo / "target").mkdir(mode=0o700, exist_ok=True)
        producer = repo / "scripts/agentdojo-live.py"
        evidence_path = output / (label + "-run.json")
        words = [sys.executable, "-I", "-B", str(producer), "--mode", "live", "--plan", str(plan_path),
                 "--plan-set", "development", "--upstream-checkout", str(upstream), "--agent-binary", str(binary),
                 "--evidence", str(evidence_path), "--provider", "openai-compatible", "--model", MODEL,
                 "--base-url", base_url, "--credential-env", "SOU153_LOOPBACK_TOKEN", "--acknowledge-cost-estimate"]
        for key, value in BUDGET.items():
            words += ["--" + key.replace("_", "-"), str(value)]
        if selected_registry:
            words += ["--native-registry", str(registry_path)]
        receipt["evidence"][label] = {"commit": revision, "tree": git(repo, "rev-parse", "HEAD^{tree}"),
                                       "binary_sha256": binary_sha, "policy_sha256": plan["identities"]["policy_sha256"],
                                       "plan_sha256": file_sha(plan_path), "cli_sha256": file_sha(producer),
                                       "cargo_lock_sha256": file_sha(repo / "Cargo.lock"),
                                       "rust_toolchain_sha256": file_sha(repo / "rust-toolchain.toml")}
        commands[label] = (words, repo, evidence_path)

    for label, (words, repo, evidence_path) in commands.items():
        before = provider.request_count
        record = receipt["evidence"][label]
        with (output / (label + "-producer.log")).open("xb") as logs:
            try:
                process = subprocess.run(words, cwd=repo, env={"PATH": os.defpath, "SOU153_LOOPBACK_TOKEN": "local-owned-sou153"},
                                         stdin=subprocess.DEVNULL, stdout=logs, stderr=subprocess.STDOUT, timeout=240)
                record["exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
        record["observed_loopback_requests"] = provider.request_count - before
        if evidence_path.exists():
            record["run_sha256"] = file_sha(evidence_path)
        record["source_after_clean"] = (not git(repo, "status", "--porcelain", "--untracked-files=all") and
                                        git(repo, "rev-parse", "HEAD") == record["commit"])
        if not record["source_after_clean"]:
            raise ValueError(label + " source changed during measurement")


if __name__ == "__main__":
    main()
