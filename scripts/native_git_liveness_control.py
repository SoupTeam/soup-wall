# SPDX-License-Identifier: Apache-2.0
"""Qualification-only native lease expiry; never extends or revives authority."""
import hashlib
import json
import os
import signal
import time
from pathlib import Path

HEALTHY_LEASE_SECONDS = 10
SHORT_LEASE_SECONDS = 2


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def audit_rows(path):
    data = path.read_bytes()
    need(len(data) <= 2 * 1024 * 1024, "qualification audit exceeds bound")
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def enrolled_epoch(rows, session_id, seconds):
    matches = [row for row in rows if row.get("event") == "native_liveness_enrolled"
               and row.get("session_id") == session_id]
    need(len(matches) == 1 and matches[0].get("lease_seconds") == seconds,
         "actual granted lease/session not matched")
    epoch = matches[0].get("session")
    need(isinstance(epoch, str) and epoch, "enrolled epoch missing")
    return epoch


def expired(rows, session_id, epoch):
    return any(row.get("event") == "native_session_expired"
               and row.get("session_id") == session_id and row.get("session") == epoch
               for row in rows)


def qualify_short_lease(*, make_client, make_call, audit, log_path, witness_factory,
                        expected_sha256, report):
    need(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
         "pidfd liveness-control prerequisite unavailable")
    row = {"passed": False, "requested_seconds": SHORT_LEASE_SECONDS}
    report["short_lease_expiry"] = row
    pin, witness, suspended = None, None, False
    with log_path.open("wb") as log:
        client = make_client(log, SHORT_LEASE_SECONDS)
        witness = witness_factory(client.process.pid)
        try:
            client.initialize()
            session_id = client.liveness_session_id
            epoch = enrolled_epoch(audit_rows(audit), session_id, SHORT_LEASE_SECONDS)
            start = witness.identity(client.process.pid)
            need(start is not None and client.process.poll() is None, "owned collector already stopped")
            pin = os.pidfd_open(client.process.pid, 0)
            os.set_inheritable(pin, False)
            need(witness.identity(client.process.pid) == start, "collector identity changed before pin")
            signal.pidfd_send_signal(pin, signal.SIGSTOP)
            suspended = True
            deadline = time.monotonic() + 0.5
            stopped = False
            while time.monotonic() < deadline:
                text = Path(f"/proc/{client.process.pid}/stat").read_text()
                state = text[text.rfind(")") + 2:].split()[0]
                need(witness.identity(client.process.pid) == start, "pinned collector identity changed")
                if state in ("T", "t"):
                    stopped = True
                    break
                time.sleep(0.005)
            need(stopped, "collector stop barrier not observed")
            deadline = time.monotonic() + SHORT_LEASE_SECONDS + 4
            while not expired(audit_rows(audit), session_id, epoch):
                need(time.monotonic() < deadline, "exact native lease expiry not audited")
                time.sleep(0.05)
            # The namespace owner has its own 1500ms guard. Its exit is never
            # substituted for the matched native expiry above.
            client.send(make_call(90))
            signal.pidfd_send_signal(pin, signal.SIGCONT)
            os.close(pin)
            pin = None
            client.process.wait(timeout=8)
            rows = audit_rows(audit)
            need(not any(item.get("event") == "native_git_execution_reserved"
                         and item.get("session") == epoch for item in rows),
                 "expired session reserved execution")
            need(not any(item.get("event") == "native_result" and item.get("session") == epoch
                         for item in rows), "expired session produced an original result")
            need(not any(json.loads(raw).get("id") == 90 and "result" in json.loads(raw)
                         for raw in client.received), "expired original result reached host")
            terminal = [line for line in log_path.read_text().splitlines() if line.startswith("Error:")]
            need(client.process.returncode != 0 and terminal
                 and terminal[-1] == "Error: native_liveness_uncertain",
                 "expired session did not terminate on liveness uncertainty")
            row.update(granted_seconds=SHORT_LEASE_SECONDS, native_expiry_audited=True,
                       epoch_sha256=hashlib.sha256(epoch.encode()).hexdigest(),
                       stopped_collector={"pid": client.process.pid, "start_time_ticks": start},
                       execution_reservations=0, original_results=0, terminal="native_liveness_uncertain")
        finally:
            if pin is not None:
                try:
                    if suspended:
                        signal.pidfd_send_signal(pin, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(pin)
            try:
                client.close()
            finally:
                row["cleanup"] = witness.finish()
    need(row["cleanup"]["all_stopped"] and any(
        item.get("original_git_server") and not item["parent_process"]
        for item in row["cleanup"]["observed"]), "expired collector cleanup observation incomplete")
    with log_path.with_name(log_path.stem + "-fresh.log").open("wb") as log:
        fresh = make_client(log, HEALTHY_LEASE_SECONDS)
        fresh_witness = witness_factory(fresh.process.pid)
        try:
            fresh.initialize()
            fresh_epoch = enrolled_epoch(audit_rows(audit), fresh.liveness_session_id, HEALTHY_LEASE_SECONDS)
            need(fresh.liveness_session_id != session_id and fresh_epoch != epoch, "expired session was reused")
            _, raw = fresh.exchange(make_call(10))
            need(hashlib.sha256(raw).hexdigest() == expected_sha256, "fresh session original bytes differ")
        finally:
            try:
                fresh.close()
            finally:
                row["fresh_cleanup"] = fresh_witness.finish()
    need(fresh.process.returncode == 0 and row["fresh_cleanup"]["all_stopped"],
         "fresh healthy collector cleanup unverified")
    row.update(fresh_requested_and_granted_seconds=HEALTHY_LEASE_SECONDS,
               fresh_original_bytes_equal=True, expired_session_revived=False, passed=True)
