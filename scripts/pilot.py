#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guided entry point for the Linux read-only filesystem/Git pilot.

    pilot.py preview --prefix DIR [inputs]      read-only plan, no effects
    pilot.py prepare --apply --prefix DIR [inputs]
    pilot.py run --prefix DIR [--prompt TEXT]
    pilot.py status --prefix DIR
    pilot.py help

This is a front door over the accepted scripts, not a second installer:
prepare-native-pilot-prerequisites.py, build-native-pilot-inputs.py,
prepare-installed-pilot.py and pilot-run.py keep their own verification,
transactions, receipts and failure semantics. Preview and status never build,
download, start a daemon, host or server, create a selection, edit a project
or Claude configuration, or contact a provider.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FORMAT = "sw-pilot-front-door/1"
STATE = "front-door.json"
RUNNER = SCRIPTS / "pilot-run.py"
MAX_STATE = 65536
PLAN_SECONDS = 180
CLAUDE_VERSION = "2.1.251 (Claude Code)"
CLAUDE_RELATIVE = "node_modules/@anthropic-ai/claude-code-linux-x64/claude"
EXECUTABLE_INPUTS = ("agentfw", "git_launcher", "sandbox_tests", "git", "bwrap", "node", "npm", "claude", "python")
FILE_INPUTS = ("node_archive", "python_archive", "git_archive", "bwrap_archive")
DIR_INPUTS = ("npm_cache", "wheelhouse", "filesystem_workspace", "git_workspace", "native_output", "agent_output",
              "pkg_config_libdir", "pkg_config_sysroot", "meson_pythonpath")
NEVER = ["start a daemon, Claude host or MCP server", "edit a project, Git repository or Claude configuration",
         "create or change an active selection", "download or build anything", "contact a model provider"]
HINTS = {
    "not_prepared": "No prepared selection under this prefix. Run `pilot.py preview`, then `pilot.py prepare --apply`.",
    "front_door_state_invalid": "The front-door record is unreadable or changed. Prepare again with --apply.",
    "stale_source": "The selection was prepared from another commit. Check out the reviewed commit or prepare again with --apply.",
    "dirty_source": "The checkout has uncommitted changes. Use a clean reviewed checkout.",
    "selection_not_current": "The recorded selection is no longer the selected generation. Prepare again with --apply.",
    "candidate_source_mismatch": "The selection was prepared from different source. Prepare again from this clean commit.",
    "preparation_marker_mismatch": "The selection is not the current generation. Prepare again with --apply.",
    "selected_artifact_changed": "A selected input changed after preparation. Prepare again with --apply --rebuild.",
    "selected_executable_changed": "A selected program changed after preparation. Prepare again with --apply --rebuild.",
    "selected_artifact_unavailable": "A selected input is missing. Prepare again with --apply --rebuild.",
    "selected_executable_unavailable": "A selected program is missing. Prepare again with --apply --rebuild.",
    "native_linux_x86_64_required": "Use native Ubuntu 24.04 x86_64.",
    "native_ubuntu_required_wsl_is_separate": "WSL is a separate environment and is not supported by this flow.",
    "ubuntu_24_04_required": "Use native Ubuntu 24.04 x86_64.",
    "non_root_operator_required": "Run as an ordinary user, not root.",
    "owned_daemon_not_ready": "The private enforcing daemon did not become ready. No host was started.",
    "authenticated_readiness_failed": "The private daemon could not be verified. No host was started.",
    "owned_daemon_lost": "The private daemon stopped during the run; the run failed closed.",
    "occupied_port_refused": "The requested port is in use. Omit --port to choose a free loopback port.",
    "pilot_cancelled": "The run was cancelled. Owned processes were stopped.",
    "pilot_cancelled_before_host": "The run was cancelled before the host started.",
    "pilot_timeout": "The run reached its deadline. Owned processes were stopped.",
    "restricted_launcher_failed": "The protected host exited with an error. Effects already performed are not rolled back.",
    "owned_process_cleanup_failed": "Cleanup was incomplete. Follow the storage recovery runbook before another run.",
    "existing_workspace_missing_or_moved": "A selected project root moved or is missing. Prepare again for the new root.",
    "selected_workspace_changed": "A selected project root changed identity. Prepare again for the new root.",
    "cancelled": "Cancelled by the operator. The step's own transaction left the previous selection unchanged.",
}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load("front_door_preparation", "prepare-installed-pilot.py")


class Failure(Exception):
    def __init__(self, code, stage=None, detail=None):
        super().__init__(code)
        self.code, self.stage, self.detail = code, stage, detail


def require(ok, code, stage=None):
    if not ok:
        raise Failure(code, stage)


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def platform_reason():
    try:
        PREP.supported_platform()
        return None
    except (ValueError, OSError) as error:
        return str(error) if re.fullmatch(r"[a-z0-9_]{1,80}", str(error)) else "unsupported_platform"


def source():
    value = PREP.PILOT.source()
    return {"commit": value["commit"], "tree": value["tree"], "dirty": value["dirty"]}


def layout(prefix, inputs=None):
    inputs = inputs or {}
    return {"native": inputs.get("native_output", prefix / "native"), "agent": inputs.get("agent_output", prefix / "agent"),
            "inputs": prefix / "inputs", "preparation": prefix / "preparation", "state": prefix / STATE}


def check_prefix(prefix, roots):
    require(prefix is not None and prefix.is_absolute(), "absolute_prefix_required")
    try:
        canonical = prefix.parent.resolve(strict=True) / prefix.name
    except OSError:
        raise Failure("prefix_parent_must_exist") from None
    require(canonical == prefix and ".." not in prefix.parts, "canonical_prefix_required")
    require(not prefix.is_relative_to(ROOT) and not ROOT.is_relative_to(prefix), "prefix_inside_checkout")
    require(prefix != Path.home().resolve() and not Path.home().resolve().is_relative_to(prefix),
            "home_directory_prefix_refused")
    for root in roots:
        require(not prefix.is_relative_to(root) and not root.is_relative_to(prefix), "prefix_overlaps_workspace")


def roots(args):
    values = [getattr(args, name) for name in ("filesystem_workspace", "git_workspace")]
    require((values[0] is None) == (values[1] is None), "both_workspaces_or_neither")
    return [Path(value) for value in values if value is not None]


def read_state(prefix):
    path = layout(prefix)["state"]
    if not path.exists():
        return None
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
            and info.st_size <= MAX_STATE, "front_door_state_invalid")
    try:
        value = PREP.PILOT.strict_json(path.read_bytes())
    except Exception:
        raise Failure("front_door_state_invalid") from None
    require(isinstance(value, dict) and value.get("format") == FORMAT and isinstance(value.get("selection"), str)
            and re.fullmatch(r"[0-9a-f]{40}", value.get("commit", "")), "front_door_state_invalid")
    return value


def write_state(prefix, value):
    path = layout(prefix)["state"]
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def recorded_inputs(args, state):
    """Explicit operator inputs. A later prepare may omit them to reuse the
    recorded explicit values; nothing is looked up on PATH."""
    inputs = {}
    for name in EXECUTABLE_INPUTS + FILE_INPUTS + DIR_INPUTS:
        value = getattr(args, name, None)
        if value is None and state is not None:
            value = state.get("inputs", {}).get(name)
        if value is not None:
            path = Path(value)
            require(path.is_absolute(), "absolute_input_path_required:" + name)
            inputs[name] = path
    if "python" not in inputs:
        # The interpreter the operator invoked, resolved once and recorded; not a PATH search.
        inputs["python"] = Path(sys.executable).resolve(strict=True)
    return inputs


def describe(path, kind="file"):
    if path is None:
        return None
    try:
        info = path.stat()
    except OSError:
        return {"path": str(path), "present": False}
    row = {"path": str(path), "present": True}
    if kind == "file" and stat.S_ISREG(info.st_mode):
        row["sha256"] = sha(path)
    return row


def child(words, *, timeout=None, cwd=None):
    """Run one accepted script; its last stdout line is its JSON result."""
    command = [sys.executable, "-B", *[str(word) for word in words]]
    try:
        # Never let a toolchain manager install anything as a side effect.
        env = dict(os.environ, RUSTUP_AUTO_INSTALL="0", PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(command, cwd=cwd or Path.home(), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, {"status": "failed", "reason": "step_timeout"}
    lines = [line for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    try:
        value = json.loads(lines[-1]) if lines else {}
    except ValueError:
        value = {}
    if not isinstance(value, dict):
        value = {}
    if result.returncode < 0:
        value = {"status": "failed", "reason": "cancelled" if -result.returncode == signal.SIGINT else
                 "signal_" + str(-result.returncode)}
    return result.returncode, value


def stage_words(args, inputs, paths, commit):
    native = ["scripts/prepare-native-pilot-prerequisites.py", "--output", paths["native"], "--expected-commit", commit]
    for name in ("git_archive", "bwrap_archive", "pkg_config_libdir", "pkg_config_sysroot", "meson_pythonpath"):
        if name in inputs:
            native += ["--" + name.replace("_", "-"), inputs[name]]
    if args.allow_download:
        native.append("--allow-download")
    agent = ["scripts/build-native-pilot-inputs.py", "--output", paths["agent"], "--expected-commit", commit]
    return native, agent


def prepare_words(args, inputs, paths, commit, produced):
    words = ["scripts/prepare-installed-pilot.py", "--output", paths["preparation"], "--expected-commit", commit]
    selected = dict(produced)
    for name in ("agentfw", "git_launcher", "sandbox_tests", "git", "bwrap", "claude", "python", "node", "npm"):
        if name in inputs:
            selected[name] = inputs[name]
    for name, value in selected.items():
        words += ["--" + name.replace("_", "-"), value]
    for name in ("node_archive", "python_archive", "npm_cache", "wheelhouse", "filesystem_workspace", "git_workspace"):
        if name in inputs:
            words += ["--" + name.replace("_", "-"), inputs[name]]
    words += ["--filesystem-classifier", ROOT / "rule_baseline/rule_baseline.py",
              "--git-classifier", ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py",
              "--policy", paths["inputs"] / "policy.yaml"]
    if args.allow_download:
        words.append("--allow-download")
    return words


def plan(args):
    """Read-only inventory composed from the accepted plans."""
    state = None
    report = {"format": FORMAT, "command": "preview", "executed": False, "never": NEVER}
    reason = platform_reason()
    report["platform"] = {"supported": reason is None, "reason": reason,
                          "required": "native Ubuntu 24.04 x86_64, non-root"}
    current = source()
    report["source"] = current
    if args.expected_commit:
        require(args.expected_commit == current["commit"], "stale_source")
    prefix = args.prefix
    workspace_roots = roots(args)
    check_prefix(prefix, workspace_roots)
    paths = layout(prefix)
    if prefix.exists():
        PREP.private_dir(prefix)
        state = read_state(prefix)
    # A repeated prepare may omit the recorded explicit options, including the
    # operator's earlier download permission; reuse never downloads anything.
    args.allow_download = bool(args.allow_download or (state or {}).get("allow_download"))
    inputs = recorded_inputs(args, state)
    paths = layout(prefix, inputs)
    native, agent = stage_words(args, inputs, paths, current["commit"])
    stages = []
    produced = {}
    if "git" in inputs and "bwrap" in inputs:
        stages.append({"stage": "native", "action": "use supplied executables",
                       "inputs": {name: describe(inputs[name]) for name in ("git", "bwrap")}})
    else:
        code, value = child(native, timeout=PLAN_SECONDS, cwd=ROOT)
        stages.append({"stage": "native", "action": "build pinned Git and bubblewrap into " + str(paths["native"]),
                       "plan_status": value.get("status"), "missing": value.get("missing", []),
                       "pins": value.get("pins")})
        produced.update(git=paths["native"] / "PENDING/git-src/git", bwrap=paths["native"] / "PENDING/bwrap-build/bwrap")
    if all(name in inputs for name in ("agentfw", "git_launcher", "sandbox_tests")):
        stages.append({"stage": "agent", "action": "use supplied Agent executables",
                       "inputs": {name: describe(inputs[name]) for name in ("agentfw", "git_launcher", "sandbox_tests")}})
    else:
        code, value = child(agent, timeout=PLAN_SECONDS, cwd=ROOT)
        stages.append({"stage": "agent", "action": "build Agent executables from this commit into " + str(paths["agent"]),
                       "plan_status": value.get("status"), "missing": value.get("missing", []),
                       "toolchain": value.get("toolchain") or value.get("compiler")})
        produced.update(agentfw=paths["agent"] / "PENDING/bin/agentfw")
    if "node_archive" in inputs or ("node" in inputs and "npm" in inputs):
        stages.append({"stage": "node", "action": "use supplied Node runtime",
                       "inputs": {name: describe(inputs[name]) for name in ("node_archive", "node", "npm") if name in inputs}})
    else:
        stages.append({"stage": "node", "action": "download pinned Node 22.22.0 archive into " + str(paths["inputs"]),
                       "url": PREP.NODE_URL, "sha256": PREP.NODE_ARCHIVE_SHA256,
                       "missing": [] if args.allow_download else ["--node-archive PINNED_TAR_XZ, --node and --npm, or --allow-download"]})
    automatic_node = not ("node_archive" in inputs or ("node" in inputs and "npm" in inputs))
    if "claude" in inputs:
        stages.append({"stage": "claude", "action": "use supplied Claude Code", "inputs": {"claude": describe(inputs["claude"])},
                       "required_version": CLAUDE_VERSION})
    else:
        stages.append({"stage": "claude", "action": "install the locked Claude Code package without scripts into " +
                       str(paths["inputs"] / "claude"), "required_version": CLAUDE_VERSION,
                       "lockfile_sha256": sha(ROOT / "profiles/mcp/filesystem-readonly-v1/claude-host/package-lock.json"),
                       "missing": [] if args.allow_download and ("node_archive" in inputs or automatic_node)
                       else ["--claude ABSOLUTE_PATH, or --allow-download with the pinned Node archive"]})
    stages.append({"stage": "policy", "action": "write the accepted pilot policy to " + str(paths["inputs"] / "policy.yaml"),
                   "sha256": hashlib.sha256(PREP.PILOT.PILOT_POLICY.encode("utf-8")).hexdigest()})
    words = prepare_words(args, inputs, paths, current["commit"], {})
    code, value = child(words, timeout=PLAN_SECONDS, cwd=ROOT)
    missing = [item for item in value.get("missing", []) if not any(
        item.startswith(prefix_) for prefix_ in ("--agentfw", "--git-launcher", "--sandbox-tests", "--git ", "--bwrap",
                                                 "--claude", "--node-archive", "provide existing absolute --policy"))]
    stages.append({"stage": "selection", "action": "prepare pinned original filesystem and Git servers and select a "
                   "generation under " + str(paths["preparation"]), "plan_status": value.get("status"),
                   "missing": missing, "workspaces": value.get("workspaces"), "profiles": value.get("profiles"),
                   "reason": value.get("reason")})
    report.update(prefix={"path": str(prefix), "exists": prefix.exists(), "layout": {k: str(v) for k, v in paths.items()}},
                  workspaces={"mode": "existing", "filesystem": str(workspace_roots[0]), "git": str(workspace_roots[1])}
                  if workspace_roots else {"mode": "generated-demo"},
                  inputs={name: describe(path) for name, path in inputs.items()
                          if name not in ("filesystem_workspace", "git_workspace")},
                  stages=stages, recorded_selection=state and state.get("selection"),
                  downloads_allowed_on_apply=bool(args.allow_download))
    report["missing"] = [item for row in stages for item in row.get("missing", []) if item]
    if reason:
        report["missing"].insert(0, "run on native Ubuntu 24.04 x86_64 as a non-root user")
    if current["dirty"]:
        report["missing"].insert(0, "use a clean reviewed checkout")
    report["planned_effects_on_apply"] = [
        f"create private 0700 directories under {prefix}",
        *(["download pinned public archives and locked packages"] if args.allow_download else []),
        *[row["action"] for row in stages],
        "record the selected generation in " + str(paths["state"]),
        "no daemon, host or server starts; protection starts only with `pilot.py run`"]
    report["next"] = ("pilot.py prepare --apply with the same options" if not report["missing"]
                      else "resolve the missing items, then preview again")
    return report


def prepare(args):
    report = plan(args)
    report.update(command="prepare", executed=True, steps=[])
    require(not report["missing"], "missing_inputs")
    prefix = args.prefix
    paths = layout(prefix)
    if not prefix.exists():
        prefix.mkdir(mode=0o700)
    PREP.private_dir(prefix)
    state = read_state(prefix)
    inputs = recorded_inputs(args, state)
    paths = layout(prefix, inputs)
    commit = report["source"]["commit"]
    native, agent = stage_words(args, inputs, paths, commit)
    produced = {}

    def step(name, words):
        code, value = child([*words[:1], "--prepare" if name == "native" else "--build", *words[1:]], cwd=ROOT)
        status = value.get("status")
        report["steps"].append({"stage": name, "status": status, "exit": code})
        if code != 0 or status in (None, "failed"):
            raise Failure(value.get("reason") or "step_failed", name, value.get("stage"))
        return value

    if not ("git" in inputs and "bwrap" in inputs):
        value = step("native", native + (["--rebuild"] if args.rebuild else []))
        produced.update(git=Path(value["git"]), bwrap=Path(value["bwrap"]))
    if not all(name in inputs for name in ("agentfw", "git_launcher", "sandbox_tests")):
        value = step("agent", agent + (["--rebuild"] if args.rebuild else []))
        produced.update(agentfw=Path(value["agentfw"]), git_launcher=Path(value["git_launcher"]),
                        sandbox_tests=Path(value["sandbox_tests"]))
    inputs_dir = paths["inputs"]
    if not inputs_dir.exists():
        inputs_dir.mkdir(mode=0o700)
    PREP.private_dir(inputs_dir)
    if not ("node_archive" in inputs or ("node" in inputs and "npm" in inputs)):
        archive = inputs_dir / "node-v22.22.0-linux-x64.tar.xz"
        if not archive.exists():
            download(PREP.NODE_URL, archive, PREP.NODE_ARCHIVE_SHA256)
        require(sha(archive) == PREP.NODE_ARCHIVE_SHA256, "node_archive_digest_mismatch", "node")
        inputs["node_archive"] = archive
        report["steps"].append({"stage": "node", "status": "verified", "sha256": PREP.NODE_ARCHIVE_SHA256})
    if "claude" not in inputs:
        inputs["claude"] = install_claude(inputs, inputs_dir)
        report["steps"].append({"stage": "claude", "status": "installed-locked"})
    # The front door never executes a supplied or installed host to probe it:
    # the accepted selection step pins and verifies the exact host image.
    policy = inputs_dir / "policy.yaml"
    expected = PREP.PILOT.PILOT_POLICY.encode("utf-8")
    if not policy.exists():
        PREP.PILOT.owned_bytes(policy, expected)
    require(policy.read_bytes() == expected, "selected_policy_changed", "policy")
    words = prepare_words(args, inputs, paths, commit, produced)
    words.insert(1, "--prepare")
    if args.rebuild:
        words.insert(2, "--rebuild")
    code, value = child(words, cwd=ROOT)
    report["steps"].append({"stage": "selection", "status": value.get("status"), "exit": code})
    require(code == 0 and value.get("status") in ("prepared-not-active", "reused"),
            value.get("reason") or "selection_failed", "selection")
    selection = Path(value["selection"])
    record = {"format": FORMAT, "commit": commit, "tree": report["source"]["tree"], "selection": str(selection),
              "selection_sha256": sha(selection), "status": value["status"],
              "allow_download": bool(args.allow_download),
              "inputs": {name: str(path) for name, path in inputs.items()}}
    write_state(prefix, record)
    report.update(status=value["status"], selection=str(selection),
                  next="pilot.py run --prefix " + str(prefix) + " (protection starts only then)")
    return report


def download(url, target, digest):
    """Explicitly allowed by --allow-download; pinned HTTPS URL and digest."""
    import urllib.request
    require(url.startswith("https://"), "unpinned_download_refused", "node")
    partial = target.with_name(target.name + ".partial")
    hasher = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=60) as response, partial.open("xb") as stream:
        require(response.geturl().startswith("https://"), "insecure_download_redirect", "node")
        while block := response.read(1 << 20):
            hasher.update(block)
            stream.write(block)
            require(stream.tell() <= 128 * 1024 * 1024, "download_size_limit", "node")
    if hasher.hexdigest() != digest:
        partial.unlink()
        raise Failure("node_archive_digest_mismatch", "node")
    os.replace(partial, target)


def install_claude(inputs, inputs_dir):
    """Locked package, no lifecycle scripts. npm runs only from the pinned
    Node archive this command verified and extracted itself."""
    target = inputs_dir / "claude"
    binary = target / CLAUDE_RELATIVE
    if binary.is_file():
        return binary
    archive = inputs.get("node_archive")
    require(archive is not None and sha(archive) == PREP.NODE_ARCHIVE_SHA256,
            "claude_install_requires_pinned_node_archive_or_supply_claude", "claude")
    node_dir = inputs_dir / "node"
    if not node_dir.exists():
        node_dir.mkdir(mode=0o700)
        PREP.extract_node(archive, node_dir)
    nodes = list(node_dir.glob("**/bin/node"))
    clis = list(node_dir.glob("**/lib/node_modules/npm/bin/npm-cli.js"))
    require(len(nodes) == 1 and len(clis) == 1, "node_archive_layout", "claude")
    target.mkdir(mode=0o700, exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        (target / name).write_bytes((ROOT / "profiles/mcp/filesystem-readonly-v1/claude-host" / name).read_bytes())
    env = {"PATH": str(nodes[0].parent) + ":/usr/bin:/bin", "HOME": str(inputs_dir), "LANG": "C.UTF-8",
           "npm_config_cache": str(inputs_dir / "npm-cache")}
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "npm_config_cafile"):
        if key in os.environ:
            env[key] = os.environ[key]
    result = subprocess.run([str(nodes[0]), str(clis[0]), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                             "--prefix", str(target)], stdin=subprocess.DEVNULL, capture_output=True, timeout=600, env=env)
    require(result.returncode == 0 and binary.is_file(), "claude_locked_install_failed", "claude")
    return binary


def verified_state(prefix):
    require(prefix is not None and prefix.is_absolute(), "absolute_prefix_required")
    if not prefix.exists():
        raise Failure("not_prepared")
    PREP.private_dir(prefix)
    state = read_state(prefix)
    if state is None:
        raise Failure("not_prepared")
    current = source()
    require(not current["dirty"], "dirty_source")
    require(state["commit"] == current["commit"], "stale_source")
    marker = layout(prefix)["preparation"] / "current.json"
    try:
        record = PREP.PILOT.strict_json(marker.read_bytes())
    except Exception:
        raise Failure("selection_not_current") from None
    selection = Path(state["selection"])
    require(record.get("generation") == selection.parent.name
            and record.get("selection_sha256") == state.get("selection_sha256"), "selection_not_current")
    return state


def run(args):
    """Delegate to the accepted entry point; exact status and signals are kept."""
    state = verified_state(args.prefix)
    words = [sys.executable, "-B", str(RUNNER), "--run", "--selection", state["selection"],
             "--expected-commit", state["commit"], "--timeout-seconds", str(args.timeout_seconds),
             "--ask-wait-seconds", str(args.ask_wait_seconds), "--port", str(args.port)]
    if args.state_root is not None:
        words += ["--state-root", str(args.state_root)]
    if args.prompt is not None:
        words += ["--prompt", args.prompt]
    # The terminal delivers Ctrl-C to the whole foreground group; the accepted
    # supervisor owns cancellation and cleanup, so this process only waits.
    # TERM and HUP sent to this process are forwarded unchanged.
    process = subprocess.Popen(words, cwd=Path.home(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    forwarded = []

    def forward(signum, _frame):
        forwarded.append(signum)
        try:
            process.send_signal(signum)
        except ProcessLookupError:
            pass

    previous = {signal.SIGINT: signal.signal(signal.SIGINT, signal.SIG_IGN),
                signal.SIGTERM: signal.signal(signal.SIGTERM, forward),
                signal.SIGHUP: signal.signal(signal.SIGHUP, forward)}
    try:
        output, _ = process.communicate()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    lines = [line for line in output.decode("utf-8", "replace").splitlines() if line.strip()]
    sys.stdout.write((lines[-1] if lines else "") + "\n")
    sys.stdout.flush()
    try:
        value = json.loads(lines[-1]) if lines else {}
    except ValueError:
        value = {}
    reason = value.get("reason") if isinstance(value, dict) else None
    if process.returncode == 0:
        print("pilot: run " + str(value.get("status")) + "; cleanup " + str(value.get("cleanup")), file=sys.stderr)
    elif reason:
        print("pilot: " + reason + ". " + HINTS.get(reason, "See the run report."), file=sys.stderr)
    if process.returncode < 0:
        # Same signal disposition as the supervisor itself.
        signal.signal(-process.returncode, signal.SIG_DFL)
        os.kill(os.getpid(), -process.returncode)
    return process.returncode


def expected_identity(state, selection):
    """What a run protecting THIS selection must show. Computed from the
    verified selection only, never from a run's own files."""
    generation = Path(state["selection"]).parent
    profiles = {kind: Path(selection["prepared_profiles"][kind]["profile"]["path"]) for kind in ("filesystem", "git")}
    tools = []
    for kind in ("filesystem", "git"):
        tools.extend(PREP.PILOT.strict_json((profiles[kind].parent / "registry.json").read_bytes())["tools"])
    registry = {"contract_version": "sw-native/1", "registry_id": "prepared-pilot-v1", "tools": tools}
    raw = (json.dumps(registry, sort_keys=True, indent=2) + "\n").encode()
    roots = PREP.workspace_paths(selection, generation, revalidate=False)
    files = selection["files"]
    return {"selection": state["selection"], "commit": state["commit"], "selection_sha256": state["selection_sha256"],
            "agentfw": files["agentfw"]["path"], "agentfw_sha256": files["agentfw"]["sha256"],
            "policy": files["policy"]["path"], "policy_sha256": files["policy"]["sha256"],
            "claude": files["claude"]["path"], "registry_sha256": hashlib.sha256(raw).hexdigest(),
            "workspace": str(roots["filesystem"]), "git_workspace": str(roots["git"]),
            "fs_profile": str(profiles["filesystem"]), "git_profile": str(profiles["git"])}


def argv(pid):
    raw = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
    require(Path(f"/proc/{int(pid)}").stat().st_uid == os.getuid(), "foreign_process")
    return [os.fsdecode(word) for word in raw.split(b"\0")[:-1]]


def option(words, name):
    return words[words.index(name) + 1] if name in words and words.index(name) + 1 < len(words) else None


def bound_to(record, expected):
    """True only if this live run was started for exactly this selection:
    its supervisor names the selection and commit, and its launcher uses the
    selected binary, policy, profiles and project roots."""
    supervisor = argv(record["supervisor_pid"])
    launcher = argv(record["launcher_pid"])
    daemon = argv(record["daemon_pid"])
    return (str(RUNNER) in supervisor and "--run" in supervisor
            and option(supervisor, "--selection") == expected["selection"]
            and option(supervisor, "--expected-commit") == expected["commit"]
            and launcher[:2] == [expected["agentfw"], "pilot-launch"]
            and option(launcher, "--home") == record["home"]
            and option(launcher, "--claude") == expected["claude"]
            and option(launcher, "--policy") == expected["policy"]
            and option(launcher, "--workspace") == expected["workspace"]
            and option(launcher, "--git-workspace") == expected["git_workspace"]
            and option(launcher, "--fs-profile") == expected["fs_profile"]
            and option(launcher, "--git-profile") == expected["git_profile"]
            and daemon[:2] == [expected["agentfw"], "serve"])


def selected_policy_digest(expected, cwd):
    """The selection's parsed `agent-policy-json/1` identity, computed offline
    by the selected binary with the accepted policy parser."""
    result = subprocess.run([expected["agentfw"], "protection-status", "--expect-policy-file", expected["policy"],
        "--selected-policy-digest"], cwd=cwd, env={"PATH": "/usr/bin:/bin", "HOME": str(cwd), "LANG": "C.UTF-8"},
        stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
    if result.returncode != 0 or len(result.stdout) > 4096:
        return None
    value = PREP.PILOT.strict_json(result.stdout)
    digest = value.get("sha256")
    if value.get("digest_format") != "agent-policy-json/1" or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        return None
    return digest


def authenticated(record, expected):
    """The existing nonce-checked status query, answered by the run's own
    daemon process, for this selection's exact binary and registry and its
    loaded policy: the active `agent-policy-json/1` digest must equal the
    selected policy's parsed digest. The query also binds the daemon's
    current configuration, which must name this selection's policy file."""
    home = Path(record["home"])
    if sha(expected["policy"]) != expected["policy_sha256"]:
        return None
    policy_digest = selected_policy_digest(expected, home.parent)
    if policy_digest is None:
        return None
    query = subprocess.run([expected["agentfw"], "protection-status", "--home", str(home), "--query-only",
        "--require-enforce", "--expect-binary-sha256", expected["agentfw_sha256"],
        "--expect-registry-sha256", expected["registry_sha256"], "--expect-policy-sha256", policy_digest],
        cwd=home.parent, env={"PATH": "/usr/bin:/bin", "HOME": str(home.parent), "LANG": "C.UTF-8"},
        stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
    if query.returncode != 0 or len(query.stdout) > 65536:
        return None
    snapshot = PREP.PILOT.strict_json(query.stdout)["snapshot"]
    config = PREP.PILOT.strict_json(PREP.bounded_file(home / "config.yaml", MAX_STATE).read_bytes())
    if (snapshot["runtime"]["pid"] != record["daemon_pid"] or config.get("enforce") is not True
            or snapshot["policy"].get("digest_format") != "agent-policy-json/1"
            or snapshot["policy"]["sha256"] != policy_digest
            or config.get("policy") != expected["policy"]
            or config.get("native", {}).get("registry_sha256") != expected["registry_sha256"]):
        return None
    return {"daemon_pid": snapshot["runtime"]["pid"], "instance": snapshot["runtime"]["instance"],
            "policy_digest": policy_digest}


def live_runs(state_roots, expected):
    """Classify owned run records. Only a run bound to the requested selection
    and confirmed by an authenticated answer counts as observed-live; other
    owned runs are reported as unrelated and never prove this selection."""
    rows = []
    for root in state_roots:
        try:
            candidates = sorted(root.glob("soup-wall-run-*/run.json"))
        except OSError:
            continue
        for record_path in candidates[:32]:
            row = {"run_directory": str(record_path.parent)}
            try:
                info = record_path.lstat()
                if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode):
                    continue
                record = PREP.PILOT.strict_json(record_path.read_bytes())
                home = Path(record["home"])
                require(record.get("format") == "sw-prepared-pilot-run/1" and home.parent == record_path.parent,
                        "run_record_invalid")
                for key in ("supervisor_pid", "launcher_pid", "daemon_pid"):
                    require(type(record[key]) is int and record[key] > 1, "run_record_invalid")
                alive = all(Path(f"/proc/{record[key]}").exists()
                            for key in ("supervisor_pid", "launcher_pid", "daemon_pid"))
                runs = sorted(path.parent.name for path in (home / "pilot-runs").glob("*/run.json"))
                row.update(home=str(home), run_ids=runs)
                if not alive:
                    row.update(protection="unavailable", selection_match=None,
                               reason="owned processes are not running; private state may need recovery")
                elif expected is None:
                    row.update(protection="unknown", selection_match=None, reason="no verified selection to compare")
                elif not bound_to(record, expected):
                    row.update(protection="unrelated", selection_match=False,
                               reason="a different selection, workspace or policy; not evidence for this prefix")
                else:
                    live = authenticated(record, expected)
                    row["selection_match"] = True
                    if live:
                        row.update(protection="observed-live", enforce=True, **live)
                    else:
                        row.update(protection="unavailable",
                                   reason="this selection's daemon did not answer an authenticated status query")
            except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, Failure):
                row.update(protection="unknown", selection_match=None, reason="run record unreadable or not owned")
            rows.append(row)
    return rows


def overall(runs, selection_state):
    """Only runs bound to this selection decide its protection."""
    mine = [row for row in runs if row.get("selection_match") is True]
    unclear = [row for row in runs if row.get("selection_match") is None]
    if any(row["protection"] == "observed-live" for row in mine):
        return "observed-live"
    if mine:
        return "unavailable"
    if any(row["protection"] == "unknown" for row in unclear):
        return "unknown"
    return {"configured": "configured-not-running", "stale": "unavailable"}.get(selection_state, "not-configured")


def status(args):
    report = {"format": FORMAT, "command": "status", "executed": False}
    reason = platform_reason()
    report["platform"] = {"supported": reason is None, "reason": reason}
    expected = None
    try:
        state = verified_state(args.prefix)
        code, value = child(["scripts/pilot-run.py", "--selection", state["selection"],
                             "--expected-commit", state["commit"]], timeout=PLAN_SECONDS, cwd=ROOT)
        if code == 0 and value.get("status") == "plan":
            report["selection"] = {"state": "configured", "path": state["selection"], "commit": state["commit"],
                                   "workspaces": value.get("workspaces")}
            selection = PREP.PILOT.strict_json(Path(state["selection"]).read_bytes())
            expected = expected_identity(state, selection)
        else:
            report["selection"] = {"state": "stale", "reason": value.get("reason") or "selection_invalid",
                                   "hint": HINTS.get(value.get("reason"), "Prepare again with --apply.")}
    except Failure as failure:
        report["selection"] = {"state": "missing" if failure.code == "not_prepared" else "stale",
                               "reason": failure.code, "hint": HINTS.get(failure.code, "Prepare again with --apply.")}
    roots = [args.state_root] if args.state_root else [Path(tempfile.gettempdir()).resolve()]
    runs = live_runs(roots, expected)
    report["runs"] = [row for row in runs if row.get("protection") != "unrelated"]
    report["unrelated_owned_runs"] = sum(1 for row in runs if row.get("protection") == "unrelated")
    report["protection"] = overall(runs, report["selection"]["state"])
    report["meaning"] = {"observed-live": "a run of this exact selection answered an authenticated status query now",
                         "configured-not-running": "a verified selection exists; nothing is protected until `run`",
                         "unavailable": "a run or selection exists but cannot protect now (see selection and runs)",
                         "unknown": "state could not be read safely", "not-configured": "nothing prepared"}[report["protection"]]
    return report


def human(report):
    lines = []
    if report.get("command") in ("preview", "prepare"):
        platform = report["platform"]
        lines.append("Platform: " + ("supported" if platform["supported"] else "NOT supported (" + str(platform["reason"]) + ")"))
        lines.append("Source: " + report["source"]["commit"] + (" (dirty)" if report["source"]["dirty"] else " (clean)"))
        lines.append("Prefix: " + report["prefix"]["path"] + (" (exists)" if report["prefix"]["exists"] else " (will be created)"))
        workspaces = report["workspaces"]
        lines.append("Roots: " + ("generated demo workspaces" if workspaces["mode"] == "generated-demo" else
                     "filesystem " + workspaces["filesystem"] + ", Git " + workspaces["git"]))
        for row in report["stages"]:
            lines.append(f"  [{row['stage']}] {row['action']}")
            for item in row.get("missing", []):
                lines.append("      missing: " + item)
        for row in report.get("steps", []):
            lines.append(f"  done [{row['stage']}] {row['status']}")
        if report.get("selection"):
            lines.append("Selection: " + report["selection"] + " (" + report["status"] + "; not active until run)")
        else:
            lines.append("Preview never: " + "; ".join(NEVER))
        lines.append("Next: " + report["next"])
    elif report.get("command") == "status":
        lines.append("Protection: " + report["protection"] + " (" + report["meaning"] + ")")
        lines.append("Selection: " + report["selection"]["state"] + (": " + report["selection"].get("hint", "")
                     if report["selection"]["state"] != "configured" else ""))
        for row in report["runs"]:
            lines.append("  run " + row["run_directory"] + ": " + str(row.get("protection")))
            for run_id in row.get("run_ids", []):
                lines.append(f"    stop: agentfw pilot-approval --home {row['home']} --run {run_id} stop")
    return "\n".join(lines)


def parser():
    top = argparse.ArgumentParser(prog="pilot.py", description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = top.add_subparsers(dest="command")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--prefix", type=Path, required=True, help="absolute private directory for all pilot state")
    shared.add_argument("--json", action="store_true", help="print the JSON report only")
    inputs = argparse.ArgumentParser(add_help=False)
    inputs.add_argument("--expected-commit", help="assert the clean checkout commit")
    inputs.add_argument("--allow-download", action="store_true", help="prepare may download pinned public inputs")
    for name in EXECUTABLE_INPUTS + FILE_INPUTS + DIR_INPUTS:
        inputs.add_argument("--" + name.replace("_", "-"), type=Path)
    for name in ("preview", "prepare"):
        command = commands.add_parser(name, parents=[shared, inputs])
        if name == "prepare":
            command.add_argument("--apply", action="store_true", help="perform the planned preparation")
            command.add_argument("--rebuild", action="store_true", help="prepare a new generation; keep the old one")
    command = commands.add_parser("run", parents=[shared])
    command.add_argument("--prompt")
    command.add_argument("--timeout-seconds", type=int, default=180)
    command.add_argument("--ask-wait-seconds", type=int, default=0)
    command.add_argument("--state-root", type=Path)
    command.add_argument("--port", type=int, default=0)
    command = commands.add_parser("status", parents=[shared])
    command.add_argument("--state-root", type=Path)
    commands.add_parser("help")
    return top


def main(argv=None):
    top = parser()
    args = top.parse_args(argv)
    if args.command in (None, "help"):
        top.print_help()
        return 0
    if args.command == "run":
        try:
            return run(args)
        except Failure as failure:
            print(json.dumps({"format": FORMAT, "command": "run", "status": "failed", "executed": False,
                              "reason": failure.code}, sort_keys=True))
            print("pilot: " + failure.code + ". " + HINTS.get(failure.code, ""), file=sys.stderr)
            return 1
    try:
        if args.command == "preview" or (args.command == "prepare" and not args.apply):
            report = plan(args)
            if args.command == "prepare":
                report["next"] = "add --apply to perform this plan" if not report["missing"] else report["next"]
        elif args.command == "prepare":
            report = prepare(args)
        else:
            report = status(args)
        code = 0
    except KeyboardInterrupt:
        report = {"format": FORMAT, "command": args.command, "status": "failed", "reason": "cancelled",
                  "hint": HINTS["cancelled"]}
        code = 130
    except Failure as failure:
        report = {"format": FORMAT, "command": args.command, "status": "failed", "reason": failure.code[:240],
                  "stage": failure.stage, "hint": HINTS.get(failure.code, "See the stage's own report.")}
        code = 2
    except Exception as error:  # Finite reason only; never a raw message or traceback.
        code_text = str(error) if not isinstance(error, subprocess.SubprocessError) else "source_or_tool_inspection_failed"
        report = {"format": FORMAT, "command": args.command, "status": "failed",
                  "reason": code_text if re.fullmatch(r"[a-z0-9_:]{1,120}", code_text) else "input_or_runtime_failure"}
        code = 2
    print(json.dumps(report, sort_keys=True))
    if not args.json:
        summary = human(report) if report.get("status") != "failed" else (
            "pilot: " + str(report.get("reason")) + (" (stage " + str(report["stage"]) + ")" if report.get("stage") else "")
            + ". " + str(report.get("hint", "")))
        if summary:
            print(summary, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
