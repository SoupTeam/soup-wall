#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Plan, select and recover prepared pilot generations without rebuilding them.

Run from a clean, reviewed checkout. Each supplied source root is checked against
its generation's own source receipt before its accepted validator is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load("transition_preparation", "prepare-installed-pilot.py")
LOCK = load("transition_lock", "pilot-selection-lock.py")
LIMIT = 65536
ID = re.compile(r"[0-9a-f]{32}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MARKER_FORMAT = "sw-pilot-preparation/1"
JOURNAL_FORMAT = "sw-pilot-transition/1"
JOURNAL = "transition-journal.json"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and info.st_size <= LIMIT, "owned_bounded_record_required")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(LIMIT + 1)
        latest = path.lstat()
        require(len(raw) <= LIMIT and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                == (latest.st_dev, latest.st_ino, latest.st_size, latest.st_mtime_ns),
                "record_changed_during_read")
        return info, raw
    finally:
        os.close(fd)


def strict_record(path):
    info, raw = regular(path)
    return info, raw, PREP.PILOT.strict_json(raw)


def output_root(path):
    require(path.is_absolute() and path.resolve(strict=True) == path,
            "canonical_output_required")
    PREP.private_dir(path)
    PREP.private_dir(path / "generations")
    require(not path.is_relative_to(ROOT), "output_inside_checkout")
    return path


def marker(output):
    info, raw, value = strict_record(output / "current.json")
    require(type(value) is dict and set(value) == {"format", "generation", "selection_sha256", "status"}
            and value["format"] == MARKER_FORMAT and value["status"] == "prepared-not-active"
            and type(value["generation"]) is str and ID.fullmatch(value["generation"])
            and type(value["selection_sha256"]) is str and HEX.fullmatch(value["selection_sha256"]),
            "invalid_current_marker")
    return info, raw, value


def source_identity(root):
    require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir()
            and root.stat().st_uid == os.getuid(), "canonical_owned_source_required")
    git_env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root),
               "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null"}
    def git(*words, text=True):
        return subprocess.check_output(["git", *words], cwd=root, timeout=30, text=text,
                                       env=git_env)
    require(Path(git("rev-parse", "--show-toplevel").strip()) == root, "source_root_mismatch")
    commit = git("rev-parse", "HEAD").strip()
    tree = git("rev-parse", "HEAD^{tree}").strip()
    dirty = bool(git("status", "--porcelain").strip())
    files = git("ls-files", "-z", text=False).split(b"\0")
    # Match the accepted preparation source digest, including the tracked bytes.
    hashes = {os.fsdecode(name): sha(root / os.fsdecode(name)) for name in files if name}
    return {"commit": commit, "tree": tree, "dirty": dirty, "files_sha256": digest(hashes)}


def source_compatible(root, source):
    require(source_identity(root) == source and source["dirty"] is False,
            "generation_source_mismatch")
    # Older pilot-run entry points have no lifetime lock. A /proc snapshot or
    # run.json cannot close their admission-to-launch race; refuse them.
    run = root / "scripts/pilot-run.py"
    lock = root / "scripts/pilot-selection-lock.py"
    preparation = root / "scripts/prepare-installed-pilot.py"
    require(all(path.exists() and stat.S_ISREG(path.lstat().st_mode)
                and path.stat().st_size <= 1024 * 1024
                for path in (run, lock, preparation))
            and b'SELECTION_LOCK.hold(' in run.read_bytes()
            and b'SELECTION_LOCK.hold(output, exclusive=True)' in preparation.read_bytes()
            and b'CONTRACT = "sw-pilot-selection-lock/1"' in lock.read_bytes(),
            "source_run_lifetime_lock_unavailable")


def generation(output, identifier, source_root):
    require(type(identifier) is str and ID.fullmatch(identifier), "generation_id_required")
    directory = output / "generations" / identifier
    PREP.private_dir(directory)
    path = directory / "selection.json"
    _, raw, selection = strict_record(path)
    require(type(selection) is dict and type(selection.get("source")) is dict,
            "invalid_generation_selection")
    source_compatible(source_root, selection["source"])
    classifier = Path(selection["files"]["git_classifier"]["path"])
    accepted_classifier = source_root / "rule_baseline/git_readonly_v1/rule_baseline.py"
    require(classifier.is_file() and accepted_classifier.is_file()
            and classifier.stat().st_size <= 1024 * 1024
            and accepted_classifier.stat().st_size <= 1024 * 1024
            and classifier.read_bytes() == accepted_classifier.read_bytes(),
            "accepted_two_server_classifier_required")
    # Execute only the exact clean source's accepted validator. Its own assets,
    # classifiers and profile installers are used, even when A and B differ.
    program = '''import importlib.util,json,sys\nfrom pathlib import Path\nroot=Path(sys.argv[1]); gen=Path(sys.argv[2]); commit=sys.argv[3]\nspec=importlib.util.spec_from_file_location("owned_prep",root/"scripts/prepare-installed-pilot.py")\nm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\npath,profiles=m.verify_generation(gen,commit)\nprint(json.dumps({"selection_sha256":m.FS.sha(path),"profiles":profiles},sort_keys=True))'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c", program,
                             str(source_root), str(directory), selection["source"]["commit"]],
                            cwd=source_root, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=120, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                              "HOME": str(source_root), "GIT_OPTIONAL_LOCKS": "0",
                                              "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
    require(result.returncode == 0 and len(result.stdout) <= LIMIT,
            "accepted_generation_validation_failed")
    verified = PREP.PILOT.strict_json(result.stdout)
    require(verified["selection_sha256"] == hashlib.sha256(raw).hexdigest(),
            "generation_changed_during_validation")
    summary = {"generation": identifier, "selection_sha256": verified["selection_sha256"],
               "source": selection["source"],
               "agent_sha256": selection["files"]["agentfw"]["sha256"],
               "agent_path": str(Path(selection["files"]["agentfw"]["path"]).resolve(strict=True)),
               "claude_path": str(Path(selection["files"]["claude"]["path"]).resolve(strict=True)),
               "server_profiles": verified["profiles"],
               "policy_sha256": selection["files"]["policy"]["sha256"],
               "filesystem_classifier_sha256": selection["files"]["filesystem_classifier"]["sha256"],
               "git_classifier_sha256": selection["files"]["git_classifier"]["sha256"]}
    require(len(canonical(summary)) <= LIMIT, "generation_summary_limit")
    return summary


def require_inactive(*summaries):
    """Find orphaned accepted pilot processes after locking out new launches.

    A surviving daemon/host has no supervisor lock after abrupt owner loss.
    The accepted process/executable identities are observable in /proc on the
    supported native target; missing access is uncertainty, never permission.
    """
    selected = {entry[key] for entry in summaries for key in ("agent_path", "claude_path")}
    require(Path("/proc").is_dir(), "pilot_process_observation_unavailable")
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or int(process.name) == os.getpid():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            with (process / "cmdline").open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "pilot_process_observation_unavailable")
            if not raw:
                continue  # A finished zombie has no live command or authority.
            arguments = [os.fsdecode(part) for part in raw.split(b"\0") if part]
            require(not any(arg in selected for arg in arguments)
                    and not any(Path(arg).name == "pilot-run.py" for arg in arguments),
                    "active_or_uncertain_pilot_run")
            try:
                executable = os.readlink(process / "exe")
            except (PermissionError, FileNotFoundError):
                # Same-owner system daemons can forbid exe inspection. The
                # accepted pilot uses exact absolute argv[0], checked above.
                # A process may also exit between cmdline and exe inspection.
                continue
            require(executable not in selected, "active_or_uncertain_pilot_run")
        except FileNotFoundError:
            if process.exists():
                raise ValueError("pilot_process_observation_unavailable") from None
            continue
        except (PermissionError, OSError):
            raise ValueError("pilot_process_observation_unavailable") from None


def journal(output):
    path = output / JOURNAL
    if not path.exists() and not path.is_symlink():
        return {"format": JOURNAL_FORMAT, "pending": None, "history": []}
    _, _, value = strict_record(path)
    require(type(value) is dict and set(value) == {"format", "pending", "history"}
            and value["format"] == JOURNAL_FORMAT and type(value["history"]) is list
            and len(value["history"]) <= 16 and len(canonical(value)) <= LIMIT,
            "invalid_transition_journal")
    return value


def publish_json(output, name, value):
    raw = canonical(value) + b"\n"
    require(len(raw) <= LIMIT, "transaction_record_limit")
    temporary = output / (".transition-" + uuid.uuid4().hex)
    try:
        with temporary.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output / name)
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def plan(output, target, previous_source, target_source):
    require(journal(output)["pending"] is None, "recover_pending_transition_first")
    require(not output.is_relative_to(previous_source) and not output.is_relative_to(target_source)
            and not previous_source.is_relative_to(output) and not target_source.is_relative_to(output),
            "source_output_overlap")
    info, raw, current = marker(output)
    before = generation(output, current["generation"], previous_source)
    require(before["selection_sha256"] == current["selection_sha256"],
            "current_selection_digest_mismatch")
    require(target != current["generation"], "target_is_current")
    after = generation(output, target, target_source)
    # Both selections must describe the same preparation directory, though
    # their exact source and binary identities may legitimately differ.
    record = {"format": JOURNAL_FORMAT, "current_marker_sha256": hashlib.sha256(raw).hexdigest(),
              "previous": before, "target": after, "previous_source_root": str(previous_source),
              "target_source_root": str(target_source), "effect": "prepared-selection-only"}
    require(len(canonical(record)) <= LIMIT, "transition_plan_limit")
    return info, raw, current, {**record, "plan_sha256": digest(record)}


def recover(output):
    with LOCK.hold(output, exclusive=True):
        state = journal(output)
        try:
            _, raw, current = marker(output)
        except (OSError, ValueError, KeyError, TypeError):
            # An unrecognizable pointer is never repaired by replaying intent.
            # Its actual selected generation is unknown until operator review.
            return {"status": "conflicting_operator_edit", "actual_generation": None,
                    "current_marker_sha256": None,
                    "pending_plan_sha256": state["pending"]["plan_sha256"] if state["pending"] else None}
        pending = state["pending"]
        if pending is None:
            return {"status": "settled", "actual_generation": current["generation"],
                    "current_marker_sha256": hashlib.sha256(raw).hexdigest()}
        actual = hashlib.sha256(raw).hexdigest()
        if actual == pending["before_sha256"]:
            outcome = "interrupted_before_publication"
        elif actual == pending["after_sha256"]:
            outcome = "published_before_journal_completion"
        else:
            return {"status": "conflicting_operator_edit", "actual_generation": current["generation"],
                    "current_marker_sha256": actual, "pending_plan_sha256": pending["plan_sha256"]}
        state["history"] = (state["history"] + [{**pending, "outcome": outcome}])[-16:]
        state["pending"] = None
        publish_json(output, JOURNAL, state)
        return {"status": outcome, "actual_generation": current["generation"],
                "current_marker_sha256": actual, "pending_plan_sha256": pending["plan_sha256"]}


def apply(output, target, previous_source, target_source, confirmation):
    with LOCK.hold(output, exclusive=True):
        state = journal(output)
        require(state["pending"] is None, "recover_pending_transition_first")
        info, raw, current, review = plan(output, target, previous_source, target_source)
        require(confirmation == review["plan_sha256"], "plan_confirmation_changed")
        require_inactive(review["previous"], review["target"])
        new_marker = {"format": MARKER_FORMAT, "generation": target,
                      "selection_sha256": review["target"]["selection_sha256"],
                      "status": "prepared-not-active"}
        pending = {"plan_sha256": review["plan_sha256"], "previous": current["generation"],
                   "target": target, "before_sha256": hashlib.sha256(raw).hexdigest(),
                   "after_sha256": hashlib.sha256(canonical(new_marker) + b"\n").hexdigest()}
        # The journal intent is durable before the only selection publication.
        state["pending"] = pending
        publish_json(output, JOURNAL, state)
        require(generation(output, current["generation"], previous_source) == review["previous"]
                and generation(output, target, target_source) == review["target"],
                "generation_changed_before_publication")
        require_inactive(review["previous"], review["target"])
        # Catch even non-cooperating edits observed before publication. All
        # supported writers must additionally participate in the same lock.
        latest, latest_raw, _ = marker(output)
        require((latest.st_dev, latest.st_ino, latest.st_mtime_ns, latest.st_size, latest_raw)
                == (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size, raw),
                "concurrent_marker_edit")
        publish_json(output, "current.json", new_marker)
        state["history"] = (state["history"] + [{**pending, "outcome": "published"}])[-16:]
        state["pending"] = None
        publish_json(output, JOURNAL, state)
        return {"status": "selected", "previous": current["generation"], "target": target,
                "plan_sha256": review["plan_sha256"], "active_protection": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target")
    parser.add_argument("--previous-source", type=Path, default=ROOT)
    parser.add_argument("--target-source", type=Path, default=ROOT)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    try:
        PREP.supported_platform()
        output = output_root(args.output)
        require(sum((args.apply, args.status, args.recover)) <= 1, "choose_one_action")
        if args.status or args.recover:
            require(args.target is None and args.confirm is None, "status_accepts_no_target")
            if args.recover:
                result = recover(output)
            else:
                _, raw, current = marker(output)
                state = journal(output)
                result = {"status": "pending" if state["pending"] else "settled",
                          "actual_generation": current["generation"],
                          "current_marker_sha256": hashlib.sha256(raw).hexdigest(),
                          "pending_plan_sha256": state["pending"]["plan_sha256"] if state["pending"] else None}
            result.update(selection_verified=False, active_protection=False)
        else:
            require(args.target is not None, "target_required")
            if args.apply:
                require(type(args.confirm) is str and HEX.fullmatch(args.confirm),
                        "exact_plan_confirmation_required")
                result = apply(output, args.target, args.previous_source, args.target_source, args.confirm)
            else:
                require(args.confirm is None, "confirmation_only_with_apply")
                _, _, _, result = plan(output, args.target, args.previous_source, args.target_source)
                result = {"status": "plan", "executed": False, **result}
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] != "conflicting_operator_edit" else 2
    except Exception as error:
        # A reason code only: no raw paths, private validator output or credentials.
        code = str(error)
        public = {"canonical_output_required", "private_directory_required",
                  "private_owned_0700_directory_required", "output_inside_checkout",
                  "owned_bounded_record_required", "invalid_current_marker", "source_root_mismatch",
                  "record_changed_during_read", "generation_changed_before_publication",
                  "pilot_process_observation_unavailable", "active_or_uncertain_pilot_run",
                  "canonical_owned_source_required", "generation_source_mismatch",
                  "source_run_lifetime_lock_unavailable", "generation_id_required",
                  "invalid_generation_selection", "accepted_generation_validation_failed",
                  "generation_changed_during_validation", "generation_summary_limit",
                  "accepted_two_server_classifier_required",
                  "invalid_transition_journal", "transaction_record_limit", "transition_plan_limit",
                  "current_selection_digest_mismatch", "target_is_current", "recover_pending_transition_first",
                  "plan_confirmation_changed", "concurrent_marker_edit",
                  "selected_generation_in_use_or_transitioning", "owned_selection_lock_required",
                  "target_required", "exact_plan_confirmation_required", "choose_one_action",
                  "status_accepts_no_target", "confirmation_only_with_apply"}
        public.add("source_output_overlap")
        print(json.dumps({"status": "failed", "reason": code if code in public else "transition_input_or_validation_failed"},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
