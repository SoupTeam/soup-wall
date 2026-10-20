#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate or fixture-check the pinned runtime; live requires explicit operator inputs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys
import time
import tempfile
import types

sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).resolve().parent / "benchmarks/agentdojo_live.py"
MODULE_BYTES = MODULE_PATH.read_bytes()
CLI_BYTES = Path(__file__).read_bytes()
sys.path.insert(0, str(MODULE_PATH.parent))
# Compile the exact bytes recorded in evidence; do not execute a stale helper pyc.
adapter = types.ModuleType("agentdojo_live")
adapter.__file__ = str(MODULE_PATH)
sys.modules["agentdojo_live"] = adapter
exec(compile(MODULE_BYTES, str(MODULE_PATH), "exec", dont_inherit=True), adapter.__dict__)
NATIVE_PATH = MODULE_PATH.with_name("agentdojo_native.py")
NATIVE_BYTES = NATIVE_PATH.read_bytes()
native = types.ModuleType("agentdojo_native")
native.__file__ = str(NATIVE_PATH)
sys.modules["agentdojo_native"] = native
exec(compile(NATIVE_BYTES, str(NATIVE_PATH), "exec", dont_inherit=True), native.__dict__)
PROTOCOL_PATH = MODULE_PATH.with_name("agentdojo_protocol.py")
PROTOCOL_BYTES = PROTOCOL_PATH.read_bytes()
protocol = types.ModuleType("agentdojo_protocol")
protocol.__file__ = str(PROTOCOL_PATH)
sys.modules["agentdojo_protocol"] = protocol
exec(compile(PROTOCOL_BYTES, str(PROTOCOL_PATH), "exec", dont_inherit=True), protocol.__dict__)
DEPENDENCIES = ["openai", "pydantic", "docstring-parser", "typing-extensions", "PyYAML", "tenacity",
                "google-genai", "rich", "deepdiff", "anthropic", "cohere", "requests"]


class LiveGateClosed(adapter.AdapterError):
    """A frozen plan forbids live execution; no provider request is sent."""
    def __init__(self, blockers, credential_read=False):
        super().__init__("Live gate closed: " + "; ".join(blockers))
        self.blockers = list(blockers)
        self.credential_read = credential_read


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["manifest", "validate", "fixture", "native-fixture", "live",
                                           "freeze-plan", "plan-check", "report",
                                           "workspace-profile", "workspace-fixture"], default="manifest")
    parser.add_argument("--upstream-checkout", type=Path)
    parser.add_argument("--agent-binary", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--plan", type=Path, help="Explicit frozen native task/injection selection JSON")
    parser.add_argument("--plan-set", choices=list(protocol.SETS),
                        help="Plan schema 2 only: the frozen set to run")
    parser.add_argument("--plan-spec", type=Path, help="freeze-plan: plan fields without cases or source inventory")
    parser.add_argument("--results", type=Path, nargs="+", help="report: every published run report for the plan")
    parser.add_argument("--report-out", type=Path, help="report: fresh directory for report.json and report.md")
    parser.add_argument("--native-registry", type=Path,
                        help="Explicit operator-installed sw-native/1 semantics registry; fallback remains default")
    parser.add_argument("--provider", choices=["openai-compatible"])
    parser.add_argument("--model")
    parser.add_argument("--base-url")
    parser.add_argument("--credential-env", help="Only this explicitly selected variable is read; no default provider key")
    parser.add_argument("--max-calls", type=int)
    parser.add_argument("--max-total-request-bytes", type=int)
    parser.add_argument("--max-output-tokens", type=int)
    parser.add_argument("--max-reserved-usd", type=float)
    parser.add_argument("--input-usd-per-million", type=float)
    parser.add_argument("--output-usd-per-million", type=float)
    parser.add_argument("--acknowledge-cost-estimate", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    if args.mode == "manifest":
        print(json.dumps({"schema_version": 1, "upstream_revision": adapter.REVISION,
                          "adapter": native.CONTRACT if args.native_registry else "existing-hook-native-name-fallback-v1", "model_calls": 0,
                          "protocol": protocol.PROTOCOL, "plan_schema_versions": [1, protocol.PLAN_SCHEMA],
                          "policy": "unchanged shipped agent-default.yaml; judge disabled",
                          "post_result_behavior": "explicit native result/context admission" if args.native_registry else "observe only; no result gating",
                          "live_requires": ["pinned upstream checkout", "Agent binary", "frozen task plan",
                                            "explicit provider/model/base URL/credential variable", "call/byte/output/cost limits"]}, indent=2))
        return
    if args.mode == "report":
        if args.plan is None or not args.results or args.report_out is None:
            parser.error("Report requires --plan, --results and a fresh --report-out directory")
        sys.exit(write_report(args.plan, args.results, args.report_out))
    if args.upstream_checkout is None:
        parser.error("Select --upstream-checkout explicitly")
    if args.mode in {"workspace-profile", "workspace-fixture"}:
        if args.report_out is None or (args.mode == "workspace-fixture" and args.agent_binary is None):
            parser.error("Workspace requires fresh --report-out; fixture also requires --agent-binary")
        sanitize_environment()
        snapshots = {"cli": adapter.digest(CLI_BYTES), "agentdojo_live": adapter.digest(MODULE_BYTES),
                     "agentdojo_native": adapter.digest(NATIVE_BYTES), "agentdojo_protocol": adapter.digest(PROTOCOL_BYTES)}
        for name in ("agentdojo_workspace", "agentdojo_workspace_checks"):
            path = MODULE_PATH.with_name(name + ".py")
            raw = path.read_bytes()
            helper = types.ModuleType(name)
            helper.__file__ = str(path)
            sys.modules[name] = helper
            exec(compile(raw, str(path), "exec", dont_inherit=True), helper.__dict__)
            snapshots[name] = adapter.digest(raw)
        checks = sys.modules["agentdojo_workspace_checks"]
        if args.mode == "workspace-profile":
            checks.prepare(args.upstream_checkout, repo, args.report_out)
            print(json.dumps({"status":"proposal_only","model_calls":0,"live_approved":False}))
            return
        try:
            result = checks.run(args.upstream_checkout, args.agent_binary, repo, args.report_out)
            result["source_sha256"] = snapshots
        except Exception as error:
            if args.report_out.is_dir():
                (args.report_out / "failure.json").write_text(
                    json.dumps({"status":"incomplete","model_calls":0,"effectiveness_claim":False,
                                "error_type":type(error).__name__,"error":str(error),
                                "source_sha256":snapshots},indent=2),encoding="utf-8")
            raise
        (args.report_out / "report.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"status":result["status"],"checks":sum("check" in r for r in result["checks"]),
                          "model_calls":0,"effectiveness_claim":False}))
        return
    if args.mode == "validate":
        print(json.dumps(adapter.verify_checkout(args.upstream_checkout), indent=2))
        return
    if args.mode == "freeze-plan":
        if args.plan_spec is None or args.evidence is None:
            parser.error("Freeze requires --plan-spec and a fresh --evidence destination for the plan")
        sanitize_environment()
        plan = freeze_plan(args.upstream_checkout, args.plan_spec.read_bytes())
        raw = (json.dumps(plan, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            with args.evidence.open("xb") as output:
                output.write(raw)
        except OSError:
            raise adapter.AdapterError("Plan destination must be fresh and writable") from None
        print(json.dumps({"plan_sha256": adapter.digest(raw), "cases": {name: len(plan["sets"][name]["cases"])
                                                                        for name in protocol.SETS}}, indent=2))
        return
    if args.mode == "plan-check":
        if args.plan is None:
            parser.error("Plan check requires --plan")
        sanitize_environment()
        result = check_plan(args.upstream_checkout, args.plan.read_bytes(), repo)
        print(json.dumps(result, indent=2))
        if result["errors"]:
            raise adapter.AdapterError("Frozen plan does not reproduce from the pinned upstream source")
        return
    if args.agent_binary is None or not args.agent_binary.is_file():
        parser.error("Select --agent-binary explicitly")
    if args.mode in {"fixture", "native-fixture"}:
        fixture_output = None
        if args.mode == "native-fixture":
            if args.evidence is None:
                parser.error("Native fixture requires a fresh explicit --evidence destination")
            fixture_output = adapter.EvidenceOutput(args.evidence)
        sanitize_environment()
        snapshots = {"cli": adapter.digest(CLI_BYTES), "agentdojo_live": adapter.digest(MODULE_BYTES),
                     "agentdojo_native": adapter.digest(NATIVE_BYTES), "agentdojo_protocol": adapter.digest(PROTOCOL_BYTES)}
        helpers = ["test_agentdojo_live", "test_agentdojo_native" if args.mode == "native-fixture" else "test_agentdojo_protocol"]
        compiled_helpers = {}
        for name in helpers:
            path = MODULE_PATH.with_name(name + ".py")
            source = path.read_bytes()
            helper = types.ModuleType(name)
            helper.__file__ = str(path)
            sys.modules[name] = helper
            exec(compile(source, str(path), "exec", dont_inherit=True), helper.__dict__)
            compiled_helpers[name] = helper
            snapshots[name] = adapter.digest(source)
        run_fixture_checks = compiled_helpers["test_agentdojo_native" if args.mode == "native-fixture"
                                              else "test_agentdojo_live"].run_fixture_checks
        try:
            if args.mode == "native-fixture":
                result = run_fixture_checks(args.upstream_checkout, args.agent_binary, repo / "target", snapshots)
            else:
                result = run_fixture_checks(args.upstream_checkout, args.agent_binary, repo / "target")
            if fixture_output is not None:
                result["cli_source_sha256"] = adapter.digest(CLI_BYTES)
                fixture_output.publish(result)
        except Exception as error:
            if fixture_output is not None:
                fixture_output.publish({"status": "incomplete", "field_gate_complete": False,
                                        "error_type": type(error).__name__})
            raise
    else:
        required = [args.plan, args.provider, args.model, args.base_url, args.credential_env,
                    args.max_calls, args.max_total_request_bytes, args.max_output_tokens]
        rates = [args.max_reserved_usd, args.input_usd_per_million, args.output_usd_per_million]
        if not all(required) or any(value is None for value in rates) or not args.acknowledge_cost_estimate:
            parser.error("Live requires an explicit plan, provider/model/URL/credential variable and all budget options; acknowledge the cost estimate")
        if args.evidence is None or args.evidence.exists():
            parser.error("Live requires a fresh explicit --evidence destination")
        output = adapter.EvidenceOutput(args.evidence)
        try:
            result = run_live(args, repo)
        except LiveGateClosed as error:
            output.publish({"status": "blocked", "live_gate_complete": False, "live_gate_blockers": error.blockers,
                            "model_calls": 0})
            note = "no provider request was sent" if error.credential_read else "no credential was read"
            raise adapter.AdapterError(f"{error}; {note}") from None
        except Exception as error:
            output.publish({"status": "incomplete", "live_gate_complete": False, "error_type": type(error).__name__})
            raise adapter.AdapterError("Live setup failed; sanitized failure evidence was preserved") from None
        output.publish(result)
    if args.evidence and args.mode not in {"live", "native-fixture"}:
        args.evidence.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if result.get("status") == "incomplete":
        raise adapter.AdapterError("Live run incomplete; sanitized partial evidence was preserved")


def sanitize_environment():
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PROGRAMFILES", "SYSTEMDRIVE"}
    retained = {name: os.environ[name] for name in keep if name in os.environ}
    os.environ.clear()
    os.environ.update(retained)


def lock_identity():
    """Dependency lock digest (LF-normalized) and its exact pins."""
    raw = MODULE_PATH.with_name("agentdojo-live.requirements.txt").read_bytes().replace(b"\r\n", b"\n")
    pins = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "==" in line:
            name, version = line.split("==", 1)
            pins[normalize_distribution(name)] = version.strip()
    return adapter.digest(raw), pins


def normalize_distribution(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_lock_identity():
    """The lock digest only when every recorded dependency is installed at its pinned version."""
    lock_sha, pins = lock_identity()
    for name in DEPENDENCIES:
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            installed = None
        if pins.get(normalize_distribution(name)) != installed:
            return "installed-dependencies-differ-from-lock"
    return lock_sha


def derive_cases(suite, attack, selection, sets_spec):
    """Original upstream tasks and attack strings for the pre-registered selection rule."""
    chosen = protocol.select_cases(selection["salt"], suite.user_tasks, suite.injection_tasks,
                                   selection["development_user_tasks"])
    sets = {name: {"repetitions": sets_spec[name]["repetitions"], "budget": sets_spec[name]["budget"], "cases": []}
            for name in protocol.SETS}
    for user_task_id, choice in chosen.items():
        task = suite.get_user_task_by_id(user_task_id)
        injection_task_id = choice["injection_task_id"]
        injections = attack.attack(task, suite.get_injection_task_by_id(injection_task_id))
        sets[choice["set"]]["cases"] += [
            {"case_id": f"{user_task_id}/benign", "user_task_id": user_task_id, "injection_task_id": None,
             "injection_vectors": [], "injections_sha256": protocol.EMPTY_INJECTIONS_SHA256},
            {"case_id": f"{user_task_id}/{injection_task_id}", "user_task_id": user_task_id,
             "injection_task_id": injection_task_id, "injection_vectors": sorted(injections),
             "injections_sha256": protocol.injections_sha256(injections)}]
    return sets


def upstream_attack(plan):
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(plan["upstream"]["benchmark_version"], plan["upstream"]["suite"])
    # The derivation name satisfies the original constructor; model-independent attacks overwrite it.
    attack = load_attack(plan["attack"]["name"], suite, types.SimpleNamespace(name=plan["attack"]["derivation_pipeline_name"]))
    return suite, attack


def freeze_plan(checkout, spec_bytes):
    spec = protocol.strict_json(spec_bytes)
    fields = {"schema_version", "protocol", "plan_id", "plan_version", "upstream", "attack", "selection", "seeds",
              "sets", "identities", "access", "limits", "rerun_policy", "notes"}
    if not isinstance(spec, dict) or set(spec) != fields:
        raise adapter.AdapterError("Plan spec must contain every plan field except frozen_at_utc")
    upstream = adapter.load_upstream(checkout)
    plan = dict(spec)
    plan["upstream"] = dict(spec["upstream"], source_inventory_sha256=upstream.verified["source_inventory_sha256"])
    suite, attack = upstream_attack(plan)
    plan["sets"] = derive_cases(suite, attack, spec["selection"], spec["sets"])
    plan["frozen_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ordered = {key: plan[key] for key in ["schema_version", "protocol", "plan_id", "plan_version", "frozen_at_utc",
                                          "upstream", "attack", "selection", "seeds", "identities", "access",
                                          "limits", "rerun_policy", "notes", "sets"]}
    errors = protocol.validate_plan(ordered, adapter.REVISION)
    if errors:
        raise adapter.AdapterError("Frozen plan is invalid: " + "; ".join(errors))
    return ordered


def check_plan(checkout, plan_bytes, repo):
    """Re-derive a frozen plan's selection and injection hashes from the pinned upstream source."""
    plan = protocol.load_plan(plan_bytes, adapter.REVISION)
    upstream = adapter.load_upstream(checkout)
    errors = []
    if upstream.verified["source_inventory_sha256"] != plan["upstream"]["source_inventory_sha256"]:
        errors.append("upstream source inventory differs from the frozen plan")
    suite, attack = upstream_attack(plan)
    derived = derive_cases(suite, attack, plan["selection"], plan["sets"])
    for name in protocol.SETS:
        if derived[name]["cases"] != plan["sets"][name]["cases"]:
            errors.append(f"{name} cases do not reproduce from the selection rule and original attack")
    policy = adapter.digest((repo / "crates/agent/policies/agent-default.yaml").read_bytes())
    if plan["identities"]["policy_sha256"] != policy:
        errors.append("plan policy identity differs from the shipped policy bytes")
    if plan["identities"]["runtime"]["dependency_lock_sha256"] != lock_identity()[0]:
        errors.append("plan dependency lock identity differs from the repository lock")
    return {"plan_sha256": adapter.digest(plan_bytes), "plan_id": plan["plan_id"], "errors": errors,
            "reproduced": not errors, "upstream": upstream.verified,
            "cases": {name: len(plan["sets"][name]["cases"]) for name in protocol.SETS},
            "live_gate_blockers": {name: protocol.live_gate(plan, name) for name in protocol.SETS},
            "model_calls": 0}


def write_report(plan_path, result_paths, out_dir):
    out_dir = out_dir.absolute()
    if out_dir.exists() or not out_dir.parent.is_dir():
        raise adapter.AdapterError("Report destination must be a fresh directory under an existing parent")
    plan_bytes = plan_path.read_bytes()
    runs = [(path.name, path.read_bytes()) for path in result_paths]
    result = protocol.aggregate(plan_bytes, runs, adapter.REVISION)
    out_dir.mkdir()
    raw = (json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    (out_dir / "report.json").write_bytes(raw)
    (out_dir / "report.md").write_bytes(protocol.render_markdown(result).encode("utf-8"))
    print(json.dumps({"valid": result["valid"], "errors": result["errors"], "report_sha256": adapter.digest(raw)}, indent=2))
    return 0 if result["valid"] else 1


def run_live(args, repo):
    plan_bytes = args.plan.read_bytes()
    plan = json.loads(plan_bytes)
    frozen = isinstance(plan, dict) and plan.get("schema_version") == protocol.PLAN_SCHEMA
    policy_bytes = (repo / "crates/agent/policies/agent-default.yaml").read_bytes()
    policy_hash = adapter.digest(policy_bytes)
    binary_hash = adapter.file_hash(args.agent_binary)
    native_registry_path = getattr(args, "native_registry", None)
    native_registry = native.Registry(native_registry_path.read_bytes()) if native_registry_path else None
    plan_set = getattr(args, "plan_set", None)
    started_at = datetime.now(timezone.utc).isoformat()
    if frozen:
        plan = protocol.load_plan(plan_bytes, adapter.REVISION)
        if plan_set is None:
            raise LiveGateClosed(["select --plan-set for a schema 2 plan"])
        blockers = protocol.live_gate(plan, plan_set)
        if blockers:
            raise LiveGateClosed(blockers)
        observed = {"upstream_revision": adapter.REVISION,
                    "source_inventory_sha256": adapter.verify_checkout(args.upstream_checkout)["source_inventory_sha256"],
                    "agent_binary_sha256": binary_hash,
                    "adapter": native.CONTRACT if native_registry else "existing-hook-native-name-fallback-v1",
                    "native_semantics_registry_sha256": native_registry.sha256 if native_registry else None,
                    "policy_sha256": policy_hash, "provider": args.provider, "model": args.model,
                    "provider_url_sha256": adapter.digest(args.base_url.encode()),
                    "python": ".".join(str(part) for part in sys.version_info[:3]),
                    "dependency_lock_sha256": installed_lock_identity(),
                    "budget": {key: getattr(args, key) for key in protocol.BUDGET_KEYS}}
        blockers = protocol.check_live_identity(plan, plan_set, observed)
        if blockers:
            raise LiveGateClosed(blockers)
    else:
        if plan_set is not None:
            raise adapter.AdapterError("--plan-set requires a schema 2 frozen plan")
        if (set(plan) != {"schema_version", "upstream_revision", "benchmark_version", "suite", "cases"}
                or plan["schema_version"] != 1 or plan["upstream_revision"] != adapter.REVISION
                or not isinstance(plan["cases"], list) or not plan["cases"]):
            raise adapter.AdapterError("Invalid frozen experiment plan")
        for case in plan["cases"]:
            if (set(case) != {"user_task_id", "injection_task_id", "injections"}
                    or not isinstance(case["injections"], dict)
                    or not all(isinstance(key, str) and isinstance(value, str) for key, value in case["injections"].items())):
                raise adapter.AdapterError("Invalid experiment case")
    # No ambient credentials are consulted. Imports/daemon children see only runtime paths.
    key = os.environ.get(args.credential_env)
    if not key:
        raise adapter.AdapterError("The explicitly selected credential variable is empty")
    sanitize_environment()
    upstream = adapter.load_upstream(args.upstream_checkout)
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.task_suite.load_suites import get_suite
    provider = adapter.BudgetProvider(args.base_url, key, args.model, max_calls=args.max_calls,
                                      max_total_request_bytes=args.max_total_request_bytes,
                                      max_output_tokens=args.max_output_tokens, max_reserved_usd=args.max_reserved_usd,
                                      input_usd_per_million=args.input_usd_per_million,
                                      output_usd_per_million=args.output_usd_per_million)
    if frozen:
        suite, attack = upstream_attack(plan)
        suite_name, benchmark_version = plan["upstream"]["suite"], plan["upstream"]["benchmark_version"]
    else:
        suite = get_suite(plan["benchmark_version"], plan["suite"])
        suite_name, benchmark_version = plan["suite"], plan["benchmark_version"]
    if native_registry is not None:
        for function in suite.tools:
            native_registry.schema(function)
    registry = [{"name": function.name, "description": function.description,
                 "schema": function.parameters.model_json_schema(), "docstring": function.full_docstring,
                 "dependencies": {name: dependency.env_dependency if isinstance(dependency.env_dependency, str)
                                  else "callable-bound-by-source-inventory" for name, dependency in function.dependencies.items()}}
                for function in suite.tools]
    selected = []
    if frozen:
        entry = plan["sets"][plan_set]
        for case in entry["cases"]:
            task = suite.get_user_task_by_id(case["user_task_id"])
            injection = suite.get_injection_task_by_id(case["injection_task_id"]) if case["injection_task_id"] else None
            injections = attack.attack(task, injection) if injection else {}
            if (sorted(injections) != case["injection_vectors"]
                    or protocol.injections_sha256(injections) != case["injections_sha256"]):
                raise LiveGateClosed([f"original injections for {case['case_id']} differ from the frozen plan"],
                                     credential_read=True)
            suite.load_and_inject_default_environment(injections)
            selected += [(case, task, injection, injections, repetition)
                         for repetition in range(1, entry["repetitions"] + 1)]
    else:
        for case in plan["cases"]:
            task = suite.get_user_task_by_id(case["user_task_id"])
            injection = suite.get_injection_task_by_id(case["injection_task_id"]) if case["injection_task_id"] else None
            suite.load_and_inject_default_environment(case["injections"])
            selected.append((case, task, injection, case["injections"], None))
    dependency_versions = {name: importlib.metadata.version(name) for name in DEPENDENCIES}
    # Every daemon uses the same private snapshot, never the mutable repository policy path.
    adapter.safe_temporary_parent(repo / "target")
    snapshot_directory = tempfile.TemporaryDirectory(prefix="agentdojo-policy-", dir=repo / "target")
    policy = Path(snapshot_directory.name) / "policy.yaml"
    policy.write_bytes(policy_bytes)
    rows = []
    failure = None
    try:
        for case, task, injection, injections, repetition in selected:
            for defended in [False, True]:
                started = time.monotonic()
                before = (provider.calls, provider.request_bytes, provider.reserved_usd, provider.completion_tokens,
                          provider.responses_without_usage, provider.exhausted, provider.transport_failures)
                daemon = None
                try:
                    llm = OpenAILLM(provider, args.model)
                    llm.name = args.model
                    pipeline = AgentPipeline.from_config(PipelineConfig(llm=llm, model_id=args.model, defense=None,
                                                                        system_message_name=None, system_message=None))
                    if adapter.file_hash(args.agent_binary) != binary_hash or policy.read_bytes() != policy_bytes:
                        raise adapter.AdapterError("Frozen executable or policy snapshot changed")
                    daemon = adapter.DisposableAgent(args.agent_binary, policy, repo / "target",
                                                      native_registry=native_registry if defended else None)
                    with daemon:
                        if defended and native_registry is not None:
                            runtime = native.runtime_class(upstream, daemon.client)
                            native.guard_pipeline(pipeline, upstream, daemon.client)
                        else:
                            runtime = adapter.runtime_class(upstream, daemon.client) if defended else upstream.runtime.FunctionsRuntime
                        task_started = time.monotonic()
                        utility, injection_success = adapter.run_original_task(suite, pipeline, task, injection, injections, runtime)
                        task_elapsed_ms = round((time.monotonic() - task_started) * 1000)
                        if daemon.client.failed or getattr(daemon.client, "withheld", False):
                            raise adapter.AdapterError("Task has incomplete inspection evidence; evaluators are not reported")
                        row = {"user_task_id": case["user_task_id"], "injection_task_id": case["injection_task_id"],
                                 "defended": defended, "utility": utility,
                                 "injection_success": injection_success if injection else None,
                                 "elapsed_ms": round((time.monotonic() - started) * 1000),
                                 "pre_calls": sum(row["event"] == "PreToolUse" for row in daemon.client.receipts),
                                 "post_results_observed": sum(row["event"] == "PostToolUse" for row in daemon.client.receipts),
                                 "deny": sum(row["decision"] == "deny" for row in daemon.client.receipts),
                                 "approval_required": sum(row["decision"] == "ask" for row in daemon.client.receipts),
                                 "receipt_sha256": adapter.digest(adapter.encoded(daemon.client.receipts))}
                        if defended and native_registry is not None:
                            row.update(pre_calls=sum(item["event"] == "call" for item in daemon.client.receipts),
                                       post_results_observed=sum(item["event"] == "result" for item in daemon.client.receipts),
                                       contexts_admitted=sum(item["event"] == "context" and item["release"]
                                                             for item in daemon.client.receipts))
                    if frozen:
                        row = {"case_id": case["case_id"], "set": plan_set, "repetition": repetition, **row,
                               "task_elapsed_ms": task_elapsed_ms, "provider_attempts": provider.calls - before[0],
                               "request_bytes": provider.request_bytes - before[1],
                               "reserved_usd": round(provider.reserved_usd - before[2], 9),
                               "completion_tokens_reported": provider.completion_tokens - before[3]
                               if provider.responses_without_usage == before[4] else None}
                    rows.append(row)
                except Exception as error:
                    failure = {"user_task_id": case["user_task_id"], "injection_task_id": case["injection_task_id"],
                               "defended": defended, "error_type": type(error).__name__,
                               "evaluators_reported": False}
                    if defended and native_registry is not None and daemon is not None and hasattr(daemon, "client"):
                        failure.update(native_policy_withheld=getattr(daemon.client, "withheld", False),
                                       inspection_failed=daemon.client.failed,
                                       native_receipt_sha256=adapter.digest(adapter.encoded(daemon.client.receipts)))
                    if frozen:
                        client = getattr(daemon, "client", None) if daemon is not None else None
                        if provider.exhausted and not before[5]:
                            reason = "budget_exhausted"
                        elif isinstance(error, native.NativeWithheld) or getattr(client, "withheld", False):
                            reason = "policy_withheld"
                        elif client is not None and client.failed:
                            reason = "inspection_failed"
                        elif provider.transport_failures > before[6]:
                            reason = "provider_failure"
                        else:
                            reason = "runtime_error"
                        failure = {"case_id": case["case_id"], "set": plan_set, "repetition": repetition,
                                   **failure, "reason": reason}
                    break
            if failure:
                break
    finally:
        snapshot_root = Path(snapshot_directory.name).resolve()
        if snapshot_root.parent != (repo / "target").resolve() or not snapshot_root.name.startswith("agentdojo-policy-"):
            raise adapter.AdapterError("Refusing cleanup outside the generated policy snapshot directory")
        snapshot_directory.cleanup()
    report = {"schema_version": 1, "mode": "live-native" if native_registry else "live-fallback", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "incomplete" if failure else "completed", "incomplete_case": failure,
            "upstream": upstream.verified, "plan_sha256": adapter.digest(plan_bytes),
            "policy_sha256": policy_hash, "agent_binary_sha256": binary_hash,
            "adapter_source_sha256": adapter.digest(MODULE_BYTES), "cli_source_sha256": adapter.digest(CLI_BYTES),
            "native_registry_sha256": adapter.digest(adapter.encoded(registry)),
            "native_tool_names": [function.name for function in suite.tools],
            "python_version": ".".join(str(part) for part in sys.version_info[:3]),
            "dependency_versions": dependency_versions,
            "model": args.model, "provider": args.provider, "provider_url_sha256": adapter.digest(args.base_url.encode()),
            "selection": {"suite": suite_name, "benchmark_version": benchmark_version,
                          "case_count": len(plan["sets"][plan_set]["cases"]) if frozen else len(plan["cases"]),
                          "matched_modes": ["undefended", "enforced"]},
            "settings": {"formatter": "upstream_default_yaml", "ask_handling": "refuse_without_approval",
                         "judge_enabled": False, "concurrency": 1, "tools_loop_max_iterations": 15,
                         "upstream_task_attempts": 3, "upstream_llm_retries": 3, "http_timeout_seconds": 30,
                         "output_limit_parameter": "max_tokens"},
            "budget": {"max_calls": args.max_calls, "max_total_request_bytes": args.max_total_request_bytes,
                       "max_output_tokens": args.max_output_tokens, "max_reserved_usd": args.max_reserved_usd,
                       "input_usd_per_million": args.input_usd_per_million, "output_usd_per_million": args.output_usd_per_million,
                       "reservation": "UTF-8 request-byte input units plus requested output cap; failed attempts retained"},
            "provider_attempts": provider.calls, "request_bytes": provider.request_bytes,
            "reserved_estimated_usd": provider.reserved_usd, "cases": rows,
            "limitations": ["Unknown native names retain coding-tool action/trust fallback",
                            "PostToolUse records only; no result approval gate",
                            "Unattended Ask refuses execution, without a human approval channel",
                            "Input cost reservation uses UTF-8 request bytes, not a verified model tokenizer or invoice",
                            "No native-semantic adaptation or attack effectiveness claim from fixture checks"]}
    if frozen:
        report.update(schema_version=protocol.RUN_SCHEMA, protocol=protocol.PROTOCOL, plan_id=plan["plan_id"],
                      plan_set=plan_set, started_at_utc=started_at, dependency_lock_sha256=installed_lock_identity(),
                      protocol_source_sha256=adapter.digest(PROTOCOL_BYTES),
                      completion_tokens_reported=provider.completion_tokens if not provider.responses_without_usage else None)
        report["selection"].update(repetitions=plan["sets"][plan_set]["repetitions"], attack=plan["attack"]["name"])
    if native_registry is not None:
        report.update(native_contract=native.CONTRACT, native_semantics_registry_sha256=native_registry.sha256,
                      native_adapter_source_sha256=adapter.digest(NATIVE_BYTES),
                      limitations=["HTTP authenticates a trusted local collector; it cannot attest actual tool execution",
                                   "Operator-installed registry accuracy remains an explicit trust boundary",
                                   "No human native approval channel; Ask/Deny stop and suppress evaluators",
                                   "Calls failing before the validated native callable abort without prevention credit",
                                   "Nested calls may already have effects before an outer call or result is withheld",
                                   "Withheld results cannot undo completed tool effects",
                                   "Serial pipeline, one original ToolsExecutor, fixed server bounds and expiry",
                                   "Cost reservation uses request bytes, not verified tokens or a provider invoice",
                                   "Fixture evidence is not independent attack effectiveness or task utility"])
    return report


if __name__ == "__main__":
    try:
        main()
    except adapter.AdapterError as error:
        print(json.dumps({"status": "failed", "error": str(error), "live_gate_complete": False}), file=sys.stderr)
        sys.exit(2)
