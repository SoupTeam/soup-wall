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
      --amendment docs/benchmarks/evidence/sou191/predeclaration-amendment-001.json \
      --work-root SCRATCH_DIR --out docs/benchmarks/evidence/sou191/runs/baseline
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import result_inspection_compare as contract  # noqa: E402

REFUSED_VARIABLES = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTC_WRAPPER",
                     "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL",
                     "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS")
REFUSED_PREFIXES = ("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")
RECORDED_VARIABLES = ("CARGO_HOME", "RUSTUP_HOME", "PROCESSOR_ARCHITECTURE", "OS")
BUILD_TIMEOUT = 3 * 3600
PATH_DUMP = re.compile(r"(\bPATH = Some\()(.*)\)(?=\r?$)", re.MULTILINE)


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


# ---------------------------------------------------------------- bounded capture
#
# Policy (CAPTURE_POLICY): each stream is read incrementally by its own thread, so a child filling one pipe
# never blocks on the other. At most ``limit`` bytes are kept in memory; every observed byte is hashed. When a
# stream passes its limit, "terminate" kills the whole process tree and classifies the attempt
# (output_limit_exceeded); "discard" keeps reading and hashing to EOF but keeps no more bytes. A stream is
# "complete" only when it reached EOF without the process being killed; only then is its digest labelled as the
# complete output (raw_sha256).

CHUNK = 64 * 1024
GRACE_S = 10
CAPTURE_POLICY = {
    "build_stdout": "terminate (Cargo's JSON messages are needed whole to select the artifact)",
    "build_stderr": "discard beyond the limit; the build continues",
    "adapter_stdout": "terminate; the attempt is unobserved and its output is never parsed",
    "adapter_stderr": "discard beyond the limit; the run continues",
}


class Stream:
    """One pipe read to EOF on a thread: bounded prefix, digest and size of everything observed."""

    def __init__(self, pipe, limit: int, policy: str, on_limit):
        self.limit, self.policy, self.on_limit = limit, policy, on_limit
        self.kept, self.hasher, self.observed = bytearray(), hashlib.sha256(), 0
        self.limit_exceeded, self.eof = False, False
        self.thread = threading.Thread(target=self._read, args=(pipe,), daemon=True)
        self.thread.start()

    def _read(self, pipe):
        try:
            while True:
                chunk = pipe.read1(CHUNK) if hasattr(pipe, "read1") else pipe.read(CHUNK)
                if not chunk:
                    self.eof = True
                    return
                self.hasher.update(chunk)
                self.observed += len(chunk)
                room = self.limit - len(self.kept)
                if room > 0:
                    self.kept += chunk[:room]
                if self.observed > self.limit and not self.limit_exceeded:
                    self.limit_exceeded = True
                    if self.policy == "terminate":
                        self.on_limit()
        except (OSError, ValueError):
            return  # pipe closed after the process tree was killed; eof stays False
        finally:
            try:
                pipe.close()
            except OSError:
                pass


class ProcessTree:
    """The child and all its descendants, so that cleanup also reaches processes whose parent already exited.

    Windows: a Job Object with KILL_ON_JOB_CLOSE. The child is created suspended, assigned to the job and only
    then resumed, so every descendant is born inside the job. POSIX: a new session, killed as a process group."""

    def __init__(self, argv, cwd, env):
        self.job = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            self._k32 = k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
            k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
            k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
            k32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
            k32.QueryInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                      wintypes.DWORD, ctypes.c_void_p)
            k32.CloseHandle.argtypes = (wintypes.HANDLE,)

            class Limits(ctypes.Structure):  # JOBOBJECT_EXTENDED_LIMIT_INFORMATION (x64 layout via ctypes)
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD), ("IoCounters", ctypes.c_uint64 * 6),
                            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
            self.job = k32.CreateJobObjectW(None, None)
            info = Limits(LimitFlags=0x2000)  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self.job or not k32.SetInformationJobObject(self.job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError(ctypes.get_last_error(), "cannot create the Windows job object for the child")
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x4  # CREATE_SUSPENDED
            self.proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, creationflags=flags)
            ntdll = ctypes.WinDLL("ntdll")
            ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
            if not k32.AssignProcessToJobObject(self.job, int(self.proc._handle)):
                error = ctypes.get_last_error()
                self.proc.kill()
                raise OSError(error, "cannot assign the child to its job object")
            ntdll.NtResumeProcess(int(self.proc._handle))
        else:
            self.proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, start_new_session=True)

    def kill(self):
        if self.job:
            self._k32.TerminateJobObject(self.job, 1)
        else:
            try:
                os.killpg(self.proc.pid, 9)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            self.proc.kill()
        except OSError:
            pass

    def active(self):
        """Processes still alive in the job (Windows); None where it cannot be counted."""
        if not self.job:
            return None
        import ctypes
        info = (ctypes.c_uint32 * 12)()  # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION; ActiveProcesses is field 10
        if not self._k32.QueryInformationJobObject(self.job, 1, info, ctypes.sizeof(info), None):
            return None
        return int(info[10])

    def close(self):
        if self.job:
            self._k32.CloseHandle(self.job)  # KILL_ON_JOB_CLOSE: nothing in the job survives this
            self.job = None


def capture(argv, timeout: float, limits, cwd=None, env=None):
    """Run ``argv`` with bounded, concurrent stdout/stderr capture, a timeout and process-tree cleanup.

    ``limits`` maps "stdout"/"stderr" to (byte limit, "terminate" | "discard"). Returns the process facts and
    the two ``Stream`` objects. ``cleanup`` reports what was still alive after cleanup, never assumed."""
    started = time.monotonic()
    tree = ProcessTree(argv, cwd, env)
    proc = tree.proc
    stop = threading.Event()
    streams = {name: Stream(getattr(proc, name), limit, policy, stop.set)
               for name, (limit, policy) in limits.items()}
    reason = None
    while proc.poll() is None:
        if stop.is_set():
            reason = "output_limit"
        elif time.monotonic() - started > timeout:
            reason = "timeout"
        if reason:
            tree.kill()
            break
        stop.wait(0.05)
    code = proc.wait()
    if reason is None:
        # Descendants may outlive the direct child and keep a pipe open; wait only until the run's deadline.
        for stream in streams.values():
            stream.thread.join(max(0.0, timeout - (time.monotonic() - started)))
        if any(s.thread.is_alive() for s in streams.values()):
            reason = "descendant_held_output_open"
    remaining = tree.active()
    if reason or remaining:
        tree.kill()  # also any descendant left in the job after a normal exit
    for stream in streams.values():
        stream.thread.join(GRACE_S)
    settle = time.monotonic() + GRACE_S
    while tree.active() and time.monotonic() < settle:  # job termination is asynchronous
        time.sleep(0.05)
    exceeded = sorted(name for name, s in streams.items() if s.limit_exceeded and s.policy == "terminate")
    if exceeded and reason is None:
        reason = "output_limit"  # the limit was passed as the process exited: still not a complete output
    cleanup = {"method": "windows_job_object" if tree.job else "posix_process_group",
               "job_processes_at_exit": remaining, "job_processes_after_cleanup": tree.active(),
               "reader_threads_alive": sum(s.thread.is_alive() for s in streams.values())}
    tree.close()
    cleanup["complete"] = cleanup["reader_threads_alive"] == 0 and cleanup["job_processes_after_cleanup"] in (0, None)
    return {"exit_code": None if reason else code, "returncode_after_kill": code if reason else None,
            "timed_out": reason == "timeout", "output_limit_exceeded": exceeded[0] if exceeded else None,
            "killed": reason, "cleanup": cleanup, "duration_s": round(time.monotonic() - started, 3)}, streams


def execute_verified(argv, artifact: Path, expected: str, timeout: int, limits=None):
    """Run ``argv`` (whose program is ``artifact``) only if the artifact still has the built hash."""
    before = file_sha(artifact)
    if before != expected:
        raise Refused("artifact changed between build and execution")
    limits = limits or {"stdout": (contract.LIMITS["max_stdout_bytes"], "terminate"),
                        "stderr": (contract.LIMITS["max_log_bytes"], "discard")}
    facts, streams = capture(argv, timeout, limits)
    after = file_sha(artifact)
    return {**facts, "artifact_sha256_before": before, "artifact_sha256_after": after}, streams


def sanitizer(*roots):
    """Replace local absolute paths in retained text; JSON-escaped (also twice, as in cc-rs errors
    inside Cargo's JSON) and URL forms included."""
    forms = []
    for root, label in roots:
        text = str(Path(root).resolve())
        for form in {text, text.replace("\\", "/"), text.replace("\\", "\\\\"), text.replace("\\", "\\\\\\\\"),
                     "/" + text.replace("\\", "/")}:
            forms.append((form, label))
    forms.sort(key=lambda item: -len(item[0]))

    def apply(raw: bytes) -> bytes:
        text = raw.decode("utf-8", "replace")
        # cc-rs prints the build script's PATH on failure: installed-software layout, not run evidence.
        text = PATH_DUMP.sub(lambda m: f"{m.group(1)}<redacted: {m.group(2).count(';') + 1} entries>)", text)
        for form, label in forms:
            text = re.sub(re.escape(form), label.replace("\\", "\\\\"), text, flags=re.IGNORECASE)
        return text.encode("utf-8")
    return apply


def retain(run_dir: Path, name: str, stream: Stream, killed, clean=None) -> dict:
    """Write the bounded prefix (sanitized when ``clean``) and describe exactly what each digest covers.

    observed_*: every byte read from the pipe. raw_*: the complete stream, set only when ``complete`` (EOF
    reached and the process was not killed), else null. retained_*: the bytes written to ``name``."""
    prefix = bytes(stream.kept)
    truncated = stream.observed > len(prefix)
    if truncated and clean and b"\n" in prefix:
        prefix = prefix[:prefix.rindex(b"\n") + 1]  # never sanitize half a path at the cut
    kept = clean(prefix) if clean else prefix
    kept = kept[:stream.limit]
    (run_dir / name).write_bytes(kept)
    complete = stream.eof and killed is None
    observed = stream.hasher.hexdigest()
    return {"file": name, "complete": complete, "limit_bytes": stream.limit, "limit_policy": stream.policy,
            "limit_exceeded": stream.limit_exceeded, "observed_bytes": stream.observed, "observed_sha256": observed,
            "raw_sha256": observed if complete else None, "raw_bytes": stream.observed if complete else None,
            "retained_sha256": sha(kept), "retained_bytes": len(kept), "truncated": truncated,
            "sanitized": clean is not None and kept != prefix}


def run_text(argv, cwd=None, env=None, timeout=120) -> str:
    try:
        done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise Refused(f"{argv[0]} not found on PATH" + (" (the +toolchain form needs rustup's proxies)"
                                                        if argv[0] in ("rustc", "cargo") else "")) from None
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
    pre, chain = contract.load_declarations(args.predeclaration, args.amendment)
    pre_sha = chain[-1]["sha256"]  # the governing declaration: the predeclaration or its latest amendment
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
        run["status"] = "build_failed"
        facts, streams = capture(argv, BUILD_TIMEOUT, {"stdout": (contract.LIMITS["max_log_bytes"], "terminate"),
                                                       "stderr": (contract.LIMITS["max_log_bytes"], "discard")},
                                 cwd=checkout, env=env)
        code = facts["exit_code"]
        run["build"] = {"argv": argv, "cwd": "<work>/src", "target_dir": "<work>/target", "target_dir_fresh": True,
                        **facts, "capture_policy": {k: CAPTURE_POLICY[k] for k in ("build_stdout", "build_stderr")},
                        "messages": retain(run_dir, "build-messages.jsonl", streams["stdout"], facts["killed"], clean),
                        "stderr": retain(run_dir, "build-stderr.txt", streams["stderr"], facts["killed"], clean),
                        "artifact": None}
        after = verify_checkout(git, checkout, commit, ids)
        run["checkout"].update(clean_after=after["clean"], inputs_match_blobs_after=after["inputs_match_blobs"],
                               status_after=after["status"], mismatched_after=after["mismatched"])
        if code != 0 or not run["build"]["messages"]["complete"]:
            raise Refused(f"build exit {code}" + (f" (killed: {facts['killed']})" if facts["killed"] else ""))
        if not (after["clean"] and after["inputs_match_blobs"]):
            raise Refused("the build changed the checkout")
        artifact = select_artifact(bytes(streams["stdout"].kept), target)
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
        execution, streams = execute_verified(exec_argv, artifact, built, pre["execution"]["timeout_s"])
        run["execution"] = {"argv": [clean(a.encode()).decode() for a in exec_argv],
                            "timeout_s": pre["execution"]["timeout_s"], **execution,
                            "capture_policy": {k: CAPTURE_POLICY[k] for k in ("adapter_stdout", "adapter_stderr")},
                            "stdout": retain(run_dir, "adapter-stdout.json", streams["stdout"], execution["killed"]),
                            "stderr": retain(run_dir, "adapter-stderr.txt", streams["stderr"], execution["killed"],
                                             clean)}
        if execution["artifact_sha256_after"] != built:
            raise Refused("artifact changed during execution")
        run["status"] = "executed"
        stdout_entry = run["execution"]["stdout"]
        if execution["exit_code"] == 0 and stdout_entry["complete"] and not stdout_entry["truncated"]:
            try:
                results = contract.shared.parse(bytes(streams["stdout"].kept))["results"]
            except (contract.shared.Rejected, KeyError, TypeError):
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
            run["problems"].append(f"adapter exit {execution['exit_code']}, killed={execution['killed']}, "
                                   f"output_limit_exceeded={execution['output_limit_exceeded']}; "
                                   "partial output retained and never parsed, no report built")
        return finish(0)
    except (Refused, contract.Invalid, OSError, subprocess.SubprocessError) as error:
        run["problems"].append(clean(str(error).encode()).decode()[:500])
        return finish(2)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--role", required=True, choices=contract.ROLES)
    parser.add_argument("--predeclaration", required=True)
    parser.add_argument("--amendment", action="append", default=[],
                        help="additive predeclaration amendment, in sequence; repeat for each")
    parser.add_argument("--repo", default=".", help="Git repository holding the predeclared commits")
    parser.add_argument("--work-root", required=True, help="scratch directory for the clone and target directory")
    parser.add_argument("--out", required=True, help="role directory that receives a new attempt-NNN")
    return record(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
