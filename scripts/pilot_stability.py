# SPDX-License-Identifier: Apache-2.0
"""Frozen SOU-127 workload, independent Linux metadata observer and grader.

The optional privileged observer reads metadata only for the pinned driver and
its descendants. It needs privilege to count FDs of non-dumpable sandbox owners;
an unreadable observation is a failure, never an empty successful measurement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import sys
import time

FORMAT = "sw-pilot-stability/1"
BOUNDS = {"processes": 96, "fds": 2048, "threads": 256,
          "rss_bytes": 1536 * 1024 * 1024, "observer_bytes": 64 * 1024 * 1024,
          "trace_bytes": 32 * 1024 * 1024, "recovery_seconds": 15,
          "idle_fd_growth": 32, "idle_thread_growth": 16,
          "idle_rss_growth": 128 * 1024 * 1024}
DEFAULT_PROVENANCE = {"per_session_bytes": 8388608, "total_bytes": 67108864,
    "max_sessions": 512, "max_input_bytes": 262144, "max_source_bytes": 1024,
    "max_literal_bytes": 4096, "max_session_id_bytes": 256}
FAULTS = {2: "parallel-cancellation", 4: "collector-death", 6: "server-death",
          8: "daemon-outage", 10: "provenance-pressure"}


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def plan(mode="soak"):
    require(mode in ("smoke", "soak"), "unknown_run_mode")
    return {"format": FORMAT, "mode": mode, "duration_seconds": 3600 if mode == "soak" else 90,
        "rounds": 12 if mode == "soak" else 6, "interval_seconds": 300 if mode == "soak" else 15,
        "hosts_per_round": 2, "workflows_per_host": 10 if mode == "soak" else 1,
        "parallel_tools_per_workflow": 2,
        "faults": {str(k): v for k, v in (FAULTS.items() if mode == "soak" else enumerate(FAULTS.values()))},
        "resource_bounds": dict(BOUNDS), "native_provenance_limits": dict(DEFAULT_PROVENANCE),
        "native_sessions_max": 64, "active_filesystem_slots": 8,
        "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_measured",
        "pressure_scope": "accepted SOU-72 owned generic control; original pilot keeps shipped defaults"}


def identity(pid, proc=Path("/proc")):
    try:
        raw = (proc / str(pid) / "stat").read_text()
    except FileNotFoundError:
        return None
    fields = raw[raw.rfind(")") + 2:].split()
    require(len(fields) >= 22, "proc_stat_incomplete")
    return int(fields[19])


def process_row(pid, proc=Path("/proc")):
    start = identity(pid, proc)
    if start is None:
        return None
    try:
        base = proc / str(pid)
        status = {}
        for line in (base / "status").read_text().splitlines():
            key, _, value = line.partition(":")
            status[key] = value.strip()
        tasks = list((base / "task").iterdir())
        children = set()
        for task in tasks:
            try:
                children.update(int(p) for p in (task / "children").read_text().split())
            except FileNotFoundError:
                continue  # A thread exit, not an unsupported interface.
        fds = len(list((base / "fd").iterdir()))
        state = status["State"].split()[0]
        # A zombie has no resident memory; missing VmRSS on a live process is
        # unsupported observation, not zero RSS.
        rss = 0 if state in ("Z", "X") else int(status["VmRSS"].split()[0]) * 1024
        row = {"pid": pid, "start_ticks": start, "fds": fds,
               "threads": int(status["Threads"]), "rss_bytes": rss,
               "children": sorted(children), "state": state}
    except (FileNotFoundError, ProcessLookupError):
        require(identity(pid, proc) != start, "live_process_observation_missing")
        return None
    require(identity(pid, proc) in (None, start), "process_identity_changed_during_sample")
    return row


def snapshot(root, expected_start, known=None, proc=Path("/proc")):
    require(identity(root, proc) == expected_start, "observer_root_identity_lost")
    known = known if known is not None else {}
    pending, visited, rows = [root], set(), []
    # Follow previously observed descendants even after reparenting.
    pending.extend(pid for pid, start in list(known.items()) if identity(pid, proc) == start)
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        row = process_row(pid, proc)
        if row is None:
            continue
        known[pid] = row["start_ticks"]
        require(len(known) <= 16384, "owned_identity_storage_bound")
        pending.extend(row.pop("children"))
        rows.append(row)
        require(len(rows) <= BOUNDS["processes"], "owned_process_bound_exceeded")
    require(rows and any(row["pid"] == root for row in rows), "empty_observer_sample")
    totals = {name: sum(row[name] for row in rows) for name in ("fds", "threads", "rss_bytes")}
    totals["processes"] = len(rows)
    require(all(totals[key] <= BOUNDS[key] for key in totals), "owned_resource_bound_exceeded")
    return {"monotonic": time.monotonic(), "totals": totals, "processes": rows}


def native_sample(instance):
    provenance = instance["provenance"]
    require(provenance["accounting_revision"] == "sw-provenance-storage/1"
            and provenance["limits"] == DEFAULT_PROVENANCE, "shipped_provenance_limits_changed")
    usage = provenance["usage"]
    for field, limit in (("sessions", 512), ("retained_bytes", 67108864),
                         ("max_session_retained_bytes", 8388608)):
        require(type(usage[field]) is int and 0 <= usage[field] <= limit, "native_capacity_bound_exceeded")
    collectors = instance["pilot_collectors"]
    require(len(collectors) <= 64, "native_session_bound_exceeded")
    return {"instance_sha256": digest(instance["instance_id"]), "usage": usage,
            "limits": provenance["limits"], "accounting_revision": provenance["accounting_revision"],
            "collectors": len(collectors), "active_collectors": sum(r["active"] for r in collectors)}


def grade(report):
    workload = report["workload"]
    require(workload == plan("soak") and report["workload_sha256"] == digest(workload), "frozen_soak_plan_required")
    require(report["elapsed_seconds"] >= 3600 and report["elapsed_seconds"] <= 3900, "full_hour_not_observed")
    require(report["source_before"] == report["source_after"] and not report["source_before"]["dirty"], "source_changed")
    require(report["selected_unchanged"] is True and report["skipped"] == 0, "exact_inputs_required")
    rounds = report["iterations"]
    require(len(rounds) == 12 and [r["index"] for r in rounds] == list(range(12)), "incomplete_iterations")
    require(all(r["status"] == "pass" and r["completed_workflows"] == 20
                and r["false_interruptions"] == 0 and r["elapsed_seconds"] <= 180 for r in rounds), "workflow_incomplete")
    require(sum(r["completed_workflows"] for r in rounds) == 240, "workload_denominator_changed")
    require(all(abs(r["started_seconds"] - i * 300) <= 15 for i, r in enumerate(rounds)), "sustained_schedule_not_observed")
    for key in ("sandbox", "calibration", "protection_before", "protection_after", "final_follow_up", "cleanup", "observer_calibration"):
        require(report[key]["passed"] is True, "required_witness_missing:" + key)
    require(set(report["faults"]) == set(FAULTS.values()), "fault_iteration_missing")
    require(all(row["passed"] is True for row in report["faults"].values()), "fault_recovery_failed")
    observer = report["observer"]
    require(observer["samples"] >= 3500 and observer["max_gap_seconds"] <= 5
            and not observer["errors"] and observer["stopped"] is True, "observer_incomplete")
    require(all(0 < observer["peaks"][name] <= BOUNDS[name] for name in ("processes", "fds", "threads", "rss_bytes")), "resource_peak_invalid")
    require(len(report["native_samples"]) >= 650, "native_sampling_incomplete")
    available = [row for row in report["native_samples"] if not row.get("unavailable")]
    require(len(available) >= 650 and len(report["native_samples"]) - len(available) <= 4,
            "native_observation_unavailable")
    times = [row["seconds"] for row in report["native_samples"]]
    require(times == sorted(times) and times[0] <= 5 and times[-1] >= 3590
            and max(b - a for a, b in zip(times, times[1:])) <= 15, "native_sampling_gap")
    for row in available:
        require(row["limits"] == DEFAULT_PROVENANCE and row["accounting_revision"] == "sw-provenance-storage/1",
                "native_observed_limits_changed")
        require(0 <= row["active_collectors"] <= row["collectors"] <= 64, "native_collector_bound")
        usage = row["usage"]
        require(0 <= usage["sessions"] <= 512 and 0 <= usage["retained_bytes"] <= 67108864
                and 0 <= usage["max_session_retained_bytes"] <= 8388608, "native_observed_capacity_exceeded")
    idle = [row["idle"] for row in rounds[2:8]]  # Compare before intentional daemon replacement.
    require(all(row["processes"] == idle[0]["processes"] for row in idle), "idle_process_growth")
    for field, limit in (("fds", BOUNDS["idle_fd_growth"]), ("threads", BOUNDS["idle_thread_growth"]),
                         ("rss_bytes", BOUNDS["idle_rss_growth"])):
        require(max(row[field] for row in idle) - min(row[field] for row in idle) <= limit, "idle_resource_growth:" + field)
    return {"completed_workflows": 240, "false_interruptions": 0, "skipped": 0}


def observe(root, expected_start):
    known, started = {}, time.monotonic()
    try:
        while time.monotonic() - started <= 4500:
            if select.select([sys.stdin], [], [], 0)[0]:
                break  # STOP or EOF from the owned driver.
            print(json.dumps(snapshot(root, expected_start, known), separators=(",", ":")), flush=True)
            time.sleep(1)
        else:
            raise ValueError("observer_deadline")
    except Exception as error:
        print(json.dumps({"error": type(error).__name__}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", action="store_true", required=True)
    parser.add_argument("--root", type=int, required=True)
    parser.add_argument("--start", type=int, required=True)
    options = parser.parse_args()
    require(options.root > 1 and options.start > 0, "pinned_owned_driver_required")
    raise SystemExit(observe(options.root, options.start))
