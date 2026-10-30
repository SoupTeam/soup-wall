#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit preview -> verified private archive -> apply for completed audit-only runs.

No automatic purge, prepared-asset removal, stop-receipt cleanup or process actions.
Interrupted apply retains the verified archive and reports partial/unknown state.
"""
import argparse
import ctypes
from contextlib import ExitStack, contextmanager
import io
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import tempfile
import time
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pilot_run_state as S

FORMAT = "sw-prepared-pilot-cleanup-plan/1"
ARCHIVE = "sw-prepared-pilot-private-archive/1"
OUTCOME = "sw-prepared-pilot-cleanup/1"
MAX_PLAN = 128 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_RUNS = 8
PLAN_SECONDS = 900


def preview(path, ids, minimum_age_seconds=0):
    S.require(type(minimum_age_seconds) is int and 0 <= minimum_age_seconds <= 365 * 86400,
              "invalid_retention_limit")
    S.require(ids and len(ids) <= MAX_RUNS and len(set(ids)) == len(ids), "explicit_unique_runs_required")
    plan = {"format": FORMAT, "created_at_ms": int(time.time() * 1000), "state_parent": str(path),
            "minimum_age_seconds": minimum_age_seconds, "runs": [], "excluded": []}
    with S.Directory(path, state_parent=True) as parent:
        plan["parent_identity"] = parent.object
        for selected_id in sorted(ids):
            name = "soup-wall-run-" + selected_id
            S.run_id(name)
            try:
                with parent.child(name) as run, S.audit_writer_lock(run):
                    selected, inventory, _ = S.completed_inventory(run)
                    finished_stat = inventory["files"]["audit-finished.json"]["identity"]
                    S.require(finished_stat[6] <= (time.time() - minimum_age_seconds) * 1e9,
                              "retention_age_not_met")
                    plan["runs"].append({"run_id": selected_id, "receipt": selected, "inventory": inventory})
            except S.Refusal as error:
                plan["excluded"].append({"run_id": selected_id, "reason": str(error)})
            except (OSError, ValueError, KeyError, TypeError):
                plan["excluded"].append({"run_id": selected_id, "reason": "state_unavailable"})
        parent.check()
    plan["plan_sha256"] = S.sha(S.encoded(plan))
    S.require(len(S.encoded(plan)) <= MAX_PLAN, "plan_size_limit")
    return plan


def load_plan(path, confirmation, fresh=True):
    with S.Directory(path.parent) as directory:
        plan = directory.json(path.name, MAX_PLAN)
    S.require(type(plan) is dict and set(plan) == {"format", "created_at_ms", "state_parent", "parent_identity",
              "minimum_age_seconds", "runs", "excluded", "plan_sha256"} and plan["format"] == FORMAT,
              "invalid_plan")
    body = {k: v for k, v in plan.items() if k != "plan_sha256"}
    S.require(type(confirmation) is str and S.SHA.fullmatch(confirmation)
              and confirmation == plan["plan_sha256"] == S.sha(S.encoded(body)), "plan_confirmation_mismatch")
    S.require(type(plan["created_at_ms"]) is int, "invalid_plan")
    if fresh:
        S.require(0 <= int(time.time() * 1000) - plan["created_at_ms"] <= PLAN_SECONDS * 1000, "plan_expired")
    S.require(type(plan["runs"]) is list and 1 <= len(plan["runs"]) <= MAX_RUNS, "no_eligible_runs")
    ids = [row["run_id"] for row in plan["runs"]]
    S.require(len(set(ids)) == len(ids), "invalid_plan")
    for selected_id in ids:
        S.run_id("soup-wall-run-" + selected_id)
    return plan


def current(parent, row):
    with parent.child("soup-wall-run-" + row["run_id"]) as run:
        selected, inventory, bodies = S.completed_inventory(run)
        S.require(selected == row["receipt"] and inventory == row["inventory"], "plan_changed")
        return bodies


def checked_parent(plan):
    parent = S.Directory(Path(plan["state_parent"]), state_parent=True)
    try:
        S.require(parent.object == plan["parent_identity"], "parent_changed")
        return parent
    except BaseException:
        parent.close()
        raise


def archive_bytes(plan, row, bodies, export, loss):
    name = row["run_id"]
    metadata = {"format": ARCHIVE, "plan_sha256": plan["plan_sha256"], "run_id": name,
                "receipt": row["receipt"], "inventory": row["inventory"],
                "loss": loss, "export_sha256": S.sha(export),
                "evidence_source": "local_owner_editable_audit", "execution_proven": False}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for filename, body in sorted({"archive.json": S.encoded(metadata), "retained-export.private.jsonl": export,
                                     **{"source/" + k: v for k, v in bodies.items()}}.items()):
            info = zipfile.ZipInfo(filename)
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            archive.writestr(info, body)
    body = output.getvalue()
    S.require(len(body) <= MAX_ARCHIVE, "archive_size_limit")
    return body


def verify_archive(body, plan, row):
    S.require(len(body) <= MAX_ARCHIVE, "archive_size_limit")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            expected = {"archive.json", "retained-export.private.jsonl"} | {"source/" + k for k in row["inventory"]["files"]}
            infos = archive.infolist()
            S.require(len(infos) == len(expected) and {info.filename for info in infos} == expected
                      and all(info.compress_type == zipfile.ZIP_STORED and info.file_size <= MAX_ARCHIVE for info in infos)
                      and sum(info.file_size for info in infos) <= MAX_ARCHIVE, "archive_members_invalid")
            meta = S.strict(archive.read("archive.json"))
            S.require(type(meta) is dict and set(meta) == {"format", "plan_sha256", "run_id", "receipt", "inventory",
                      "loss", "export_sha256", "evidence_source", "execution_proven"}
                      and meta["format"] == ARCHIVE and meta["plan_sha256"] == plan["plan_sha256"]
                      and meta["run_id"] == row["run_id"] and meta["receipt"] == row["receipt"]
                      and meta["inventory"] == row["inventory"] and meta["execution_proven"] is False
                      and meta["evidence_source"] == "local_owner_editable_audit", "archive_identity_mismatch")
            for name, expected_row in row["inventory"]["files"].items():
                source = archive.read("source/" + name)
                S.require(len(source) == expected_row["bytes"] and S.sha(source) == expected_row["sha256"],
                          "archive_member_hash_mismatch")
            exported = archive.read("retained-export.private.jsonl")
            S.require(S.sha(exported) == meta["export_sha256"], "archive_export_hash_mismatch")
            header = S.strict(exported.split(b"\n", 1)[0])
            S.require(meta["loss"] == {key: header[key] for key in ("notices", "gaps")}, "archive_loss_mismatch")
            return meta
    except (zipfile.BadZipFile, KeyError, RuntimeError, EOFError):
        raise S.Refusal("archive_invalid") from None


def publish(directory, filename, body):
    """Fsync exact private bytes, publish exclusively, then fsync the directory."""
    temporary = ".archive-" + secrets.token_hex(16) + ".pending"
    fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory.fd)
    try:
        S.require(os.fstat(fd).st_mode & 0o777 == 0o600, "archive_permissions_unverified")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(fd)
        directory.check()
        S.require(directory.read(temporary, MAX_ARCHIVE)[0] == body, "archive_write_unverified")
        # link is an atomic no-replace publication on the same filesystem.
        os.link(temporary, filename, src_dir_fd=directory.fd, dst_dir_fd=directory.fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory.fd)
        os.fsync(directory.fd)
        S.require(directory.read(filename, MAX_ARCHIVE)[0] == body, "archive_publication_unverified")
    finally:
        os.close(fd)
        # On failure a pending file may remain as private, incomplete evidence.


def archive_name(plan, row):
    return "run-" + row["run_id"] + "-" + plan["plan_sha256"] + ".zip"


def _build_archives_locked(plan, destination):
    result = []
    with checked_parent(plan) as parent, S.Directory(destination) as output:
        for row in plan["runs"]:
            name = "soup-wall-run-" + row["run_id"]
            S.require(not destination.is_relative_to(Path(plan["state_parent"]) / name), "archive_inside_source")
            bodies = current(parent, row)
            filename = archive_name(plan, row)
            # Accepted retention export owns loss/truncation semantics. It writes
            # solely to an explicitly requested private archive staging directory.
            with tempfile.TemporaryDirectory(prefix=".audit-export-", dir=destination) as temporary:
                stage = Path(temporary)
                export_path = stage / "retained.private.jsonl"
                retained = S.AUDIT.REPORT.export_retained(parent.path / name / "audit", export_path)
                S.require(not set(retained["notices"]) - {"intentional_retention", "partial_tail"}, "audit_export_incomplete_or_corrupt")
                with S.Directory(stage) as staging:
                    exported = staging.read(export_path.name, MAX_ARCHIVE)[0]
            S.require(current(parent, row) == bodies, "plan_changed")
            body = archive_bytes(plan, row, bodies, exported, {key: retained[key] for key in ("notices", "gaps")})
            verify_archive(body, plan, row)
            try:
                existing = output.read(filename, MAX_ARCHIVE)[0]
            except FileNotFoundError:
                publish(output, filename, body)
                existing = output.read(filename, MAX_ARCHIVE)[0]
            # Repeated archive is allowed only for exactly verified bytes.
            S.require(existing == body, "archive_already_exists_or_changed")
            verify_archive(existing, plan, row)
            os.fsync(output.fd)
            result.append({"run_id": row["run_id"], "outcome": "archived_source_retained",
                           "archive": filename, "archive_sha256": S.sha(existing)})
    return result


def build_archives(plan, destination):
    with checked_parent(plan) as parent, ExitStack() as held:
        for row in plan["runs"]:
            run = held.enter_context(parent.child("soup-wall-run-" + row["run_id"]))
            held.enter_context(S.audit_writer_lock(run))
        return _build_archives_locked(plan, destination)


def rename_exclusive(source_fd, source, destination_fd, destination):
    """Linux renameat2(NO_REPLACE); do not emulate it with a racy exists check."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    S.require(rename is not None, "exclusive_rename_unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1) != 0:
        raise OSError(ctypes.get_errno(), "exclusive rename refused")


def validate_remaining(run, audit, files, audit_present=True):
    run.check()
    expected_root = {key for key in files if "/" not in key}
    if audit_present:
        expected_root.add("audit")
    S.require(set(run.names(16)) == expected_root, "removal_state_changed")
    if audit_present:
        S.require(set(audit.names(8)) == {key.split("/", 1)[1] for key in files if key.startswith("audit/")},
                  "removal_state_changed")
    for key, expected in files.items():
        directory, name = (audit, key.split("/", 1)[1]) if "/" in key else (run, key)
        body, info = directory.read(name)
        S.require(info == expected["identity"] and len(body) == expected["bytes"]
                  and S.sha(body) == expected["sha256"], "removal_state_changed")


def remove_member(directory, name, quarantine, expected, archive_guard, maximum=S.MAX_RECORD):
    """Detach a single member exclusively and verify it before unlinking.

Replacement in the source namespace is preserved as a staged member; it must
never be mistaken for the selected inode after the last inventory check.
"""
    staging_name = "member-" + secrets.token_hex(16)
    archive_guard()
    source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
    try:
        # Keep the original inode alive across detachment. A source replacement
        # cannot reuse a freed inode between the inventory and staging checks.
        S.require(S.identity(os.fstat(source_fd)) == expected["identity"], "removal_state_changed")
        rename_exclusive(directory.fd, name, quarantine.fd, staging_name)
        os.fsync(directory.fd)
        os.fsync(quarantine.fd)
        body, held = quarantine.read(staging_name, maximum)
        # A rename changes ctime; all other selected attributes and bytes match.
        S.require(held == S.identity(os.fstat(source_fd)) and held[:7] == expected["identity"][:7]
                  and len(body) == expected["bytes"] and S.sha(body) == expected["sha256"], "staged_member_changed")
        S.require(quarantine.read(staging_name, maximum)[1] == held, "staged_member_changed")
        archive_guard()
        os.unlink(staging_name, dir_fd=quarantine.fd)
        os.fsync(quarantine.fd)
    finally:
        os.close(source_fd)


@contextmanager
def durable_archive(output, plan, row):
    """Pin and sync the current verified archive, not a prior publication inode."""
    filename = archive_name(plan, row)
    with durable_file(output, filename, MAX_ARCHIVE, lambda body: verify_archive(body, plan, row)) as selected:
        yield selected


@contextmanager
def durable_file(output, filename, maximum, verify):
    """Shared pinned publication guard; the caller owns its archive schema."""
    body, selected = output.read(filename, maximum)
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=output.fd)
    try:
        S.require(S.identity(os.fstat(fd)) == selected, "archive_changed_during_apply")
        verify(body)

        def check():
            current, identity = output.read(filename, maximum)
            S.require(identity == selected == S.identity(os.fstat(fd)) and current == body,
                      "archive_changed_during_apply")

        def guard():
            check()
            os.fsync(fd)
            os.fsync(output.fd)
            check()

        guard()
        yield body, guard
    finally:
        os.close(fd)


def apply_one(parent, output, plan, row):
    with durable_archive(output, plan, row) as (body, verify_durable_archive):
        return _apply_one(parent, output, plan, row, body, verify_durable_archive)


def _apply_one(parent, output, plan, row, body, verify_durable_archive):
    def archive_guard():
        verify_durable_archive()
        if moved:
            parent.check()
            try:
                os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise S.Refusal("run_name_reappeared")
    current(parent, row)
    name = "soup-wall-run-" + row["run_id"]
    quarantine_name = ".soup-wall-cleanup-" + secrets.token_hex(16)
    result = {"run_id": row["run_id"], "outcome": "retained", "archive_sha256": S.sha(body)}
    moved = False
    removed = False
    try:
        # Detach only the exact selected run, without replacing another path.
        # Any interruption leaves a private, identifiable quarantine and archive.
        os.mkdir(quarantine_name, mode=0o700, dir_fd=parent.fd)
        with parent.child(quarantine_name) as quarantine, parent.child(name) as run:
            S.require(run.object == row["inventory"]["run"], "plan_changed")
            current(parent, row)
            publish(quarantine, "cleanup.json", S.encoded({"format": "sw-prepared-pilot-cleanup-journal/1",
                "plan_sha256": plan["plan_sha256"], "row": row}))
            archive_guard()
            rename_exclusive(parent.fd, name, quarantine.fd, "run")
            moved = True
            result.update(outcome="partial", quarantine=quarantine_name)
            os.fsync(parent.fd)
            os.fsync(quarantine.fd)
            # Preserve the logical original path used by retention selection;
            # named descriptor checks now address the detached selected object.
            run.parent, run.name = quarantine, "run"
            selected, inventory, _ = S.completed_inventory(run)
            S.require(inventory["run_generation"][:7] == row["inventory"]["run_generation"][:7], "plan_changed")
            inventory["run_generation"] = row["inventory"]["run_generation"]
            S.require(selected == row["receipt"] and inventory == row["inventory"], "plan_changed")
            files = dict(inventory["files"])
            with run.child("audit") as audit:
                for key in sorted(key for key in files if key.startswith("audit/")):
                    validate_remaining(run, audit, files)
                    remove_member(audit, key.split("/", 1)[1], quarantine, files[key], archive_guard)
                    del files[key]
                    os.fsync(audit.fd)
                validate_remaining(run, audit, files)
                archive_guard()
                os.rmdir("audit", dir_fd=run.fd)
            for key in ("audit-finished.json", "audit-run.json"):
                validate_remaining(run, None, files, audit_present=False)
                remove_member(run, key, quarantine, files[key], archive_guard)
                del files[key]
                os.fsync(run.fd)
            validate_remaining(run, None, files, audit_present=False)
            archive_guard()
            os.rmdir("run", dir_fd=quarantine.fd)
            removed = True
            os.fsync(quarantine.fd)
            S.require(set(quarantine.names(16)) == {"cleanup.json"}, "quarantine_changed")
            archive_guard()
            os.unlink("cleanup.json", dir_fd=quarantine.fd)
            os.fsync(quarantine.fd)
        os.rmdir(quarantine_name, dir_fd=parent.fd)
        os.fsync(parent.fd)
        archive_guard()
        result.pop("quarantine", None)
        result["outcome"] = "archived_and_removed"
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["reason"] = str(error) if isinstance(error, S.Refusal) else "removal_unavailable"
        result["outcome"] = "unknown" if removed else "partial" if moved else "retained"
        if removed:
            result["source_state"] = "removal_durability_unverified"
        if not moved:
            result["quarantine"] = quarantine_name
            try:
                os.rmdir(quarantine_name, dir_fd=parent.fd)
                os.fsync(parent.fd)
            except OSError:
                pass
    return result


def _apply_locked(plan, destination):
    results = []
    with checked_parent(plan) as parent, S.Directory(destination) as output:
        # Validate all archives and selections before beginning the first run.
        for row in plan["runs"]:
            verify_archive(output.read(archive_name(plan, row), MAX_ARCHIVE)[0], plan, row)
            current(parent, row)
        for row in plan["runs"]:
            try:
                result = apply_one(parent, output, plan, row)
            except (OSError, ValueError, KeyError, TypeError) as error:
                result = {"run_id": row["run_id"], "outcome": "retained",
                          "reason": str(error) if isinstance(error, S.Refusal) else "apply_preflight_unavailable"}
            results.append(result)
            if result["outcome"] != "archived_and_removed":
                results.extend({"run_id": rest["run_id"], "outcome": "not_attempted", "reason": "prior_run_incomplete"}
                               for rest in plan["runs"][len(results):])
                break
    return results


def apply(plan, destination):
    with checked_parent(plan) as parent, ExitStack() as held:
        for row in plan["runs"]:
            run = held.enter_context(parent.child("soup-wall-run-" + row["run_id"]))
            held.enter_context(S.audit_writer_lock(run))
        return _apply_locked(plan, destination)


def inspect_quarantine(plan, destination, name):
    """Read-only recovery: never infer completion from absence or resume deletion."""
    import re
    S.require(re.fullmatch(r"\.soup-wall-cleanup-[0-9a-f]{32}", name), "invalid_quarantine")
    with checked_parent(plan) as parent, S.Directory(destination) as output, parent.child(name) as quarantine:
        journal = quarantine.json("cleanup.json", MAX_PLAN)
        S.require(type(journal) is dict and set(journal) == {"format", "plan_sha256", "row"}
                  and journal["format"] == "sw-prepared-pilot-cleanup-journal/1"
                  and journal["plan_sha256"] == plan["plan_sha256"]
                  and journal["row"] in plan["runs"], "quarantine_journal_invalid")
        row = journal["row"]
        verify_archive(output.read(archive_name(plan, row), MAX_ARCHIVE)[0], plan, row)
        result = {"run_id": row["run_id"], "quarantine": name, "archive_verified": True,
                  "outcome": "unknown", "reason": "completion_not_committed", "remaining_files": 0,
                  "unverified_members": 0, "recovery": "retain_for_manual_review"}
        names = quarantine.names(32)
        root_name = "soup-wall-run-" + row["run_id"]
        try:
            current(parent, row)
            if set(names) == {"cleanup.json"}:
                result.update(outcome="retained", reason="source_intact_before_detachment")
                return result
        except (OSError, ValueError, KeyError, TypeError):
            pass
        expected = row["inventory"]["files"]
        known = set()
        def member(directory, filename, selected_key=None):
            body, held = directory.read(filename)
            matches = [key for key, value in expected.items() if held[:7] == value["identity"][:7]
                       and len(body) == value["bytes"] and S.sha(body) == value["sha256"]]
            if len(matches) != 1 or matches[0] in known or selected_key is not None and matches[0] != selected_key:
                result["unverified_members"] += 1
            else:
                known.add(matches[0])
            result["remaining_files"] += 1
        for entry in names:
            if entry == "cleanup.json":
                continue
            if entry == "run":
                with quarantine.child(entry) as run:
                    S.require(run.object == row["inventory"]["run"], "quarantine_run_replaced")
                    for root_member in run.names(16):
                        if root_member == "audit":
                            with run.child("audit") as audit:
                                S.require(audit.object == row["inventory"]["audit"], "quarantine_audit_replaced")
                                for audit_member in audit.names(8):
                                    member(audit, audit_member, "audit/" + audit_member)
                        else:
                            member(run, root_member, root_member)
            elif re.fullmatch(r"member-[0-9a-f]{32}", entry):
                member(quarantine, entry)
            else:
                result["unverified_members"] += 1
        if "run" in names or result["remaining_files"]:
            result.update(outcome="partial" if not result["unverified_members"] else "unknown",
                          reason="verified_archive_and_remaining_state" if not result["unverified_members"] else "unexpected_remaining_state")
        quarantine.check()
        return result


def archive_batch(plan, destination):
    rows = []
    for row in plan["runs"]:
        try:
            rows.extend(build_archives(dict(plan, runs=[row]), destination))
        except (OSError, ValueError, KeyError, TypeError) as error:
            rows.append({"run_id": row["run_id"], "outcome": "retained", "archive_state": "unknown",
                         "reason": str(error) if isinstance(error, S.Refusal) else "archive_unavailable"})
            rows.extend({"run_id": rest["run_id"], "outcome": "not_attempted", "reason": "prior_run_incomplete"}
                        for rest in plan["runs"][len(rows):])
            break
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("preview")
    p.add_argument("--state-parent", type=Path, required=True)
    p.add_argument("--run-id", action="append", required=True)
    p.add_argument("--minimum-age-seconds", type=int, default=0)
    for action in ("archive", "apply", "inspect"):
        p = sub.add_parser(action)
        p.add_argument("--plan", type=Path, required=True)
        p.add_argument("--confirm", required=True)
        p.add_argument("--archive-directory", type=Path, required=True)
        if action == "inspect":
            p.add_argument("--quarantine", required=True)
    args = parser.parse_args(argv)
    def interrupted(_signum, _frame):
        raise InterruptedError("operator_interrupted")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        if args.action == "preview":
            result = preview(args.state_parent, args.run_id, args.minimum_age_seconds)
            code = 0 if not result["excluded"] else 2
        else:
            S.platform()
            plan = load_plan(args.plan, args.confirm, fresh=args.action != "inspect")
            rows = (archive_batch(plan, args.archive_directory) if args.action == "archive" else
                    [inspect_quarantine(plan, args.archive_directory, args.quarantine)] if args.action == "inspect" else
                    apply(plan, args.archive_directory))
            expected = "archived_source_retained" if args.action == "archive" else "archived_and_removed"
            complete = len(rows) == len(plan["runs"]) and all(row["outcome"] == expected for row in rows)
            result = {"format": OUTCOME, "action": args.action, "runs": rows, "excluded": plan["excluded"],
                      "complete": complete}
            code = 0 if complete or args.action == "inspect" else 2
    except S.Refusal as error:
        result, code = {"format": OUTCOME, "action": args.action, "complete": False, "reason": str(error)}, 1
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        result, code = {"format": OUTCOME, "action": args.action, "complete": False, "reason": "operation_unavailable"}, 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
