#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controlled recording of one SOU-123 result-inspection run for SOU-191 (offline, bounded).

For the predeclared revision of ``--role`` this tool:

1. resolves the full commit and requires it on the first-parent history of the predeclared ref;
2. clones it into a new directory with ``core.autocrlf=false`` and checks that the tree is clean
   and that every build input and payload is byte-identical to its Git object;
3. refuses Cargo configuration files and build-affecting environment variables;
4. builds with the predeclared Cargo command into a new, empty target directory;
5. takes the example executable only from Cargo's own ``compiler-artifact`` message, inside that
   target directory, and checks the checkout again after the build;
6. hashes that artifact, executes exactly it on the checkout's frozen corpus and policy, and hashes
   it again afterwards;
7. retains the raw adapter output, exit status, timeout flag, bounded build and run logs, and the
   original ``sw-result-inspection-report/1`` built with the revision's own ``build_report``.

Every invocation becomes a new ``attempt-NNN`` directory; nothing is overwritten. This record is
an attestation by the machine that ran it, not a cryptographic proof (see
``result_inspection_compare.TRUST_BOUNDARY``).

    python scripts/benchmarks/result_inspection_record.py --role baseline \
      --predeclaration docs/benchmarks/evidence/sou191/predeclaration.json \
      --work-root SCRATCH_DIR --out docs/benchmarks/evidence/sou191/runs/baseline
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import result_inspection_compare as contract  # noqa: E402

REFUSED_VARIABLES = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTC_WRAPPER",
                     "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL",
                     "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS")
REFUSED_PREFIXES = ("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")
RECORDED_VARIABLES = ("CARGO_HOME", "RUSTUP_HOME", "PROCESSOR_ARCHITECTURE", "OS")
BUILD_TIMEOUT = 3 * 3600


class Refused(Exception):
    pass


def sha(raw: bytes) -> str:
    return contract._sha(raw)


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def refused_environment(env) -> list[str]:
    return sorted(name for name in env if name in REFUSED_VARIABLES or name.startswith(REFUSED_PREFIXES))


def cargo_configs(start: Path, env) -> list[str]:
    """Cargo reads .cargo/config[.toml] in every ancestor and in CARGO_HOME; none may exist."""
    found = []
    for directory in [start, *start.parents]:
        found += [str(p) for p in (directory / ".cargo" / "config", directory / ".cargo" / "config.toml") if p.is_file()]
    home = Path(env.get("CARGO_HOME") or Path.home() / ".cargo")
    found += [str(p) for p in (home / "config", home / "config.toml") if p.is_file()]
    return sorted(set(found))


def select_artifact(messages: bytes, target_dir: Path) -> Path:
    """The single example executable Cargo reports, required to lie inside the fresh target directory."""
    chosen = []
    for line in messages.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        target = message.get("target") if isinstance(message, dict) else None
        if message.get("reason") == "compiler-artifact" and isinstance(target, dict) and \
                target.get("name") == "result_inspection_corpus" and "example" in target.get("kind", []) and \
                message.get("executable"):
            chosen.append(message["executable"])
    if len(chosen) != 1:
        raise Refused(f"expected one result_inspection_corpus example artifact from Cargo, found {len(chosen)}")
    artifact = Path(chosen[0]).resolve()
    root = target_dir.resolve()
    if root not in artifact.parents or not artifact.is_file():
        raise Refused("Cargo's artifact is not a file inside the fresh target directory")
    return artifact


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def execute_verified(argv, artifact: Path, expected: str, timeout: int):
    """Run ``argv`` (whose program is ``artifact``) only if the artifact still has the built hash."""
    before = file_sha(artifact)
    if before != expected:
        raise Refused("artifact changed between build and execution")
    started = time.monotonic()
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout)
        code, out, err, timed_out = done.returncode, done.stdout, done.stderr, False
    except subprocess.TimeoutExpired as error:
        code, out, err, timed_out = None, error.stdout or b"", error.stderr or b"", True
    after = file_sha(artifact)
    return {"exit_code": code, "timed_out": timed_out, "duration_s": round(time.monotonic() - started, 3),
            "artifact_sha256_before": before, "artifact_sha256_after": after}, out, err


def sanitizer(*roots):
    """Replace local absolute paths in retained text; JSON-escaped and URL forms included."""
    forms = []
    for root, label in roots:
        text = str(Path(root).resolve())
        for form in {text, text.replace("\\", "/"), text.replace("\\", "\\\\"), "/" + text.replace("\\", "/")}:
            forms.append((form, label))
    forms.sort(key=lambda item: -len(item[0]))

    def apply(raw: bytes) -> bytes:
        text = raw.decode("utf-8", "replace")
        for form, label in forms:
            text = re.sub(re.escape(form), label.replace("\\", "\\\\"), text, flags=re.IGNORECASE)
        return text.encode("utf-8")
    return apply


def retain(run_dir: Path, name: str, raw: bytes, limit: int, clean=None) -> dict:
    kept = clean(raw) if clean else raw
    truncated = len(kept) > limit
    if truncated:
        kept = kept[:limit]
    (run_dir / name).write_bytes(kept)
    return {"file": name, "raw_sha256": sha(raw), "raw_bytes": len(raw), "retained_sha256": sha(kept),
            "retained_bytes": len(kept), "truncated": truncated, "sanitized": clean is not None and kept != raw}


def run_text(argv, cwd=None, env=None, timeout=120) -> str:
    done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    if done.returncode != 0:
        raise Refused(f"{argv[0]} {' '.join(argv[1:3])} failed: {done.stderr.decode('utf-8', 'replace')[:300]}")
    return done.stdout.decode("utf-8", "replace").strip()


def verify_checkout(git: contract.Git, checkout: Path, commit: str, payload_ids) -> dict:
    head = run_text(["git", "-C", str(checkout), "rev-parse", "HEAD"])
    status = run_text(["git", "-C", str(checkout), "-c", "core.autocrlf=false", "status", "--porcelain=v1",
                       "--untracked-files=all"])
    inputs, mismatched = {}, []
    for path in contract.BUILD_INPUTS:
        blob = git.blob_id(commit, path)
        local = git.hash_file(checkout / path)
        inputs[path] = {"blob": blob, "sha256": file_sha(checkout / path)}
        if local != blob:
            mismatched.append(path)
    for case_id in payload_ids:
        rel = f"eval/sou123/payloads/{case_id}.txt"
        if git.hash_file(checkout / rel) != git.blob_id(commit, rel):
            mismatched.append(rel)
    inputs["eval/sou123/payloads"] = {"tree": git.text("rev-parse", f"{commit}:eval/sou123/payloads")}
    return {"head": head, "clean": head == commit and not status, "status": status.splitlines()[:20],
            "inputs": inputs, "inputs_match_blobs": not mismatched, "mismatched": mismatched[:20]}


def next_attempt(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    existing = sorted(p.name for p in out.iterdir() if re.fullmatch(r"attempt-\d{3}", p.name))
    path = out / f"attempt-{len(existing) + 1:03d}"
    if path.exists():
        raise Refused(f"{path.name} already exists; attempts are never overwritten")
    path.mkdir()
    return path


def toolchain(channel, env, cwd):
    rustc = run_text(["rustc", f"+{channel}", "-vV"], cwd=cwd, env=env)
    cargo = run_text(["cargo", f"+{channel}", "-vV"], cwd=cwd, env=env)
    fields = dict(line.split(": ", 1) for line in rustc.splitlines() if ": " in line)
    return {"requested": channel, "rustc_vV": rustc, "cargo_vV": cargo, "rustc_release": fields.get("release"),
            "rustc_commit_hash": fields.get("commit-hash"), "host": fields.get("host")}


def record(args) -> int:
    pre, pre_sha = contract.load_predeclaration(args.predeclaration)
    commit = pre["revisions"][args.role]["commit"]
    repo = Path(args.repo).resolve()
    git = contract.Git(repo)
    run_dir = next_attempt(Path(args.out))
    work = Path(args.work_root).resolve() / f"{args.role}-{run_dir.name}"
    if work.exists():
        raise Refused(f"work directory {work} already exists")
    checkout, target = work / "src", work / "target"
    tool = Path(__file__).resolve()
    run = {"schema": contract.RUN_SCHEMA, "role": args.role, "attempt": int(run_dir.name[-3:]),
           "status": "refused_before_build", "predeclaration_sha256": pre_sha,
           "recorder": {"recorder_sha256": file_sha(tool),
                        "contract_sha256": file_sha(tool.parent / "result_inspection_compare.py"),
                        "started_utc": utc()},
           "revision": {"commit": commit}, "checkout": {}, "toolchain": {}, "environment": {}, "build": {},
           "execution": {}, "report": None, "problems": []}
    clean = sanitizer((work, "<work>"), (repo, "<repo>"), (Path.home(), "<home>"))

    def finish(code):
        run["recorder"]["finished_utc"] = utc()
        (run_dir / "run.json").write_bytes((json.dumps(run, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
        print(f"{args.role} {run_dir.name}: {run['status']}" + (f" ({run['problems'][0]})" if run["problems"] else ""))
        return code

    try:
        resolved = git.text("rev-parse", "--verify", f"{commit}^{{commit}}")
        accepted = pre["accepted_main_ref"]["commit"]
        if resolved != commit or commit not in git.first_parent(accepted):
            raise Refused(f"{commit} is not on the first-parent history of {accepted}")
        run["revision"].update(tree=git.text("rev-parse", f"{commit}^{{tree}}"), accepted_ref_commit=accepted,
                               first_parent=True)
        work.mkdir(parents=True)
        run_text(["git", "clone", "--quiet", "--no-checkout", "--shared", str(repo), str(checkout)], timeout=600)
        run_text(["git", "-C", str(checkout), "config", "core.autocrlf", "false"])
        run_text(["git", "-C", str(checkout), "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach",
                  commit], timeout=600)
        manifest = json.loads((checkout / "eval/sou123/manifest.json").read_bytes())
        ids = [case["case_id"] for case in manifest["cases"]]
        before = verify_checkout(git, checkout, commit, ids)
        env = dict(os.environ)
        refused, configs = refused_environment(env), cargo_configs(checkout, env)
        run["environment"] = {"refused_variables_present": refused,
                              "recorded": {k: clean(env[k].encode()).decode() for k in RECORDED_VARIABLES if k in env},
                              "cargo": clean((shutil.which("cargo") or "not found").encode()).decode()}
        run["checkout"] = {"method": "git clone --shared --no-checkout; core.autocrlf=false; checkout --detach",
                           "clean_before": before["clean"], "inputs_match_blobs_before": before["inputs_match_blobs"],
                           "status_before": before["status"], "mismatched_before": before["mismatched"],
                           "inputs": before["inputs"], "cargo_config_files": [clean(p.encode()).decode() for p in configs]}
        if not (before["clean"] and before["inputs_match_blobs"]):
            raise Refused("checkout is not clean or not byte-identical to the Git objects")
        if refused or configs:
            raise Refused(f"build-affecting environment {refused} or Cargo config files {len(configs)} present")
        run["toolchain"] = toolchain(pre["build"]["toolchain"], env, checkout)
        if run["toolchain"]["rustc_release"] != pre["build"]["toolchain"] or \
                run["toolchain"]["host"] != pre["build"]["target"]:
            raise Refused(f"toolchain {run['toolchain']['rustc_release']}/{run['toolchain']['host']} is not predeclared")
        env["CARGO_TARGET_DIR"] = str(target)
        argv = list(pre["build"]["argv"])
        started = time.monotonic()
        run["status"] = "build_failed"
        try:
            done = subprocess.run(argv, cwd=checkout, env=env, capture_output=True, timeout=BUILD_TIMEOUT)
            code, messages, stderr, timed_out = done.returncode, done.stdout, done.stderr, False
        except subprocess.TimeoutExpired as error:
            code, messages, stderr, timed_out = None, error.stdout or b"", error.stderr or b"", True
        run["build"] = {"argv": argv, "cwd": "<work>/src", "target_dir": "<work>/target", "target_dir_fresh": True,
                        "exit_code": code, "timed_out": timed_out, "duration_s": round(time.monotonic() - started, 1),
                        "messages": retain(run_dir, "build-messages.jsonl", messages, contract.LIMITS["max_log_bytes"], clean),
                        "stderr": retain(run_dir, "build-stderr.txt", stderr, contract.LIMITS["max_log_bytes"], clean),
                        "artifact": None}
        after = verify_checkout(git, checkout, commit, ids)
        run["checkout"].update(clean_after=after["clean"], inputs_match_blobs_after=after["inputs_match_blobs"],
                               status_after=after["status"], mismatched_after=after["mismatched"])
        if code != 0:
            raise Refused(f"build exit {code}{' (timeout)' if timed_out else ''}")
        if not (after["clean"] and after["inputs_match_blobs"]):
            raise Refused("the build changed the checkout")
        artifact = select_artifact(messages, target)
        built = file_sha(artifact)
        run["build"]["artifact"] = {"relative_path": artifact.relative_to(target.resolve()).as_posix(),
                                    "sha256": built, "bytes": artifact.stat().st_size}
        runner = contract.load_runner(git, commit)
        problems = runner.verify_payloads(manifest, checkout / "eval/sou123/payloads")
        if problems:
            raise Refused("payloads differ from the frozen manifest: " + "; ".join(problems[:3]))
        corpus = {k: checkout / v for k, v in (("manifest", "eval/sou123/manifest.json"),
                                               ("payloads", "eval/sou123/payloads"),
                                               ("policy", "profiles/pilot/linux-readonly-v1/policy.yaml"))}
        exec_argv = [str(artifact), "--manifest", str(corpus["manifest"]), "--payload-dir", str(corpus["payloads"]),
                     "--policy", str(corpus["policy"])]
        run["status"] = "integrity_failed"
        execution, stdout, stderr = execute_verified(exec_argv, artifact, built, pre["execution"]["timeout_s"])
        run["execution"] = {"argv": [clean(a.encode()).decode() for a in exec_argv],
                            "timeout_s": pre["execution"]["timeout_s"], **execution,
                            "stdout": retain(run_dir, "adapter-stdout.json", stdout, contract.LIMITS["max_stdout_bytes"]),
                            "stderr": retain(run_dir, "adapter-stderr.txt", stderr, contract.LIMITS["max_log_bytes"], clean)}
        if execution["artifact_sha256_after"] != built:
            raise Refused("artifact changed during execution")
        run["status"] = "executed"
        if execution["exit_code"] == 0 and not execution["timed_out"]:
            try:
                results = json.loads(stdout)["results"]
            except (ValueError, KeyError, TypeError):
                run["problems"].append("adapter exit 0 but its output is not a result document; no report built")
                return finish(1)
            identities = {"source": commit, "rustc": run["toolchain"]["rustc_release"] + " " + pre["build"]["profile"],
                          "policy_path": "profiles/pilot/linux-readonly-v1/policy.yaml",
                          "manifest_sha256": file_sha(corpus["manifest"]), "policy_sha256": file_sha(corpus["policy"]),
                          "adapter_sha256": built}
            report = runner.build_report(manifest, results, identities)
            raw = (json.dumps(report, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
            (run_dir / "report.json").write_bytes(raw)
            run["report"] = {"file": "report.json", "sha256": sha(raw)}
        else:
            run["problems"].append(f"adapter exit {execution['exit_code']}, timed_out={execution['timed_out']}; "
                                   "partial output retained, no report built")
        return finish(0)
    except (Refused, contract.Invalid, OSError, subprocess.SubprocessError) as error:
        run["problems"].append(clean(str(error).encode()).decode()[:500])
        return finish(2)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--role", required=True, choices=contract.ROLES)
    parser.add_argument("--predeclaration", required=True)
    parser.add_argument("--repo", default=".", help="Git repository holding the predeclared commits")
    parser.add_argument("--work-root", required=True, help="scratch directory for the clone and target directory")
    parser.add_argument("--out", required=True, help="role directory that receives a new attempt-NNN")
    return record(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
