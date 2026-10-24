# SPDX-License-Identifier: Apache-2.0
"""SOU-124 latency bookkeeping. Never changes timeouts or admission policy."""
import math


TRACE_SYSCALLS = "execve,openat,write,writev,clone,clone3,exit,exit_group"


def trace_request():
    return {"mode": "seccomp-bpf", "fallback_possible": True, "syscalls": TRACE_SYSCALLS}


def summarize(cases, planned_per_profile):
    if type(planned_per_profile) is not int or not 20 <= planned_per_profile <= 100:
        raise ValueError("latency_sample_plan_invalid")
    report = {}
    for profile in ("filesystem", "git"):
        rows = [r for r in cases if r.get("profile") == profile and r.get("case") == "approve"]
        indices = [r.get("sample_index") for r in rows]
        if (len(rows) > planned_per_profile or len(set(indices)) != len(indices)
                or any(type(i) is not int or not 0 <= i < planned_per_profile for i in indices)):
            raise ValueError("latency_duplicate_or_invalid_sample")
        successful, failed = [], 0
        for row in rows:
            elapsed = row.get("decision_to_result_ms")
            if (row.get("passed") is True and row.get("approved") is True
                    and row.get("released") is True and type(row.get("dispatched")) is int
                    and row.get("dispatched") == 1
                    and type(row.get("kernel_effects")) is int and row.get("kernel_effects") == 1 and type(elapsed) in (int, float)
                    and math.isfinite(elapsed) and elapsed >= 0):
                successful.append(elapsed)
            else:
                failed += 1
        successful.sort()
        def percentile(fraction):
            return successful[math.ceil(len(successful) * fraction) - 1] if successful else None
        p95 = percentile(.95)
        incomplete = planned_per_profile - len(rows)
        report[profile] = {
            "planned": planned_per_profile, "successful": len(successful),
            "failed": failed, "incomplete": incomplete,
            "p50_ms": percentile(.5), "p95_ms": p95,
            "metric": "operator_attempt_to_correlated_original_result_monotonic",
            "target_ms": 3000,
            "target_met": failed == incomplete == 0 and p95 is not None and p95 <= 3000,
        }
    report["status"] = ("target_met" if all(report[p]["target_met"] for p in ("filesystem", "git"))
                        else "performance_blocker")
    return report


class ObservationError(ValueError):
    """A finite parser diagnosis and record digest; never raw trace contents."""
    def __init__(self, kind, line):
        import hashlib
        super().__init__("reuse_diagnostic_write_unobserved")
        self.kind = kind
        self.record_sha256 = hashlib.sha256(line.encode()).hexdigest()


def collector_stderr_rows(lines, collector_pid, *, completed_call=False):
    """Decode only a selected collector's bounded, kernel-observed stderr."""
    import ast
    import json
    import re
    buffer = b""
    observations = []
    reuse_profile = None
    approved_key = None
    progress = set()
    active = {collector_pid}
    def quoted_bytes(raw, line):
        try:
            return ast.literal_eval("b" + raw)
        except (ValueError, SyntaxError, UnicodeError):
            raise ObservationError('literal_payload', line) from None
    for line in lines:
        owner = re.match(r'^(\d+)\s+', line)
        if not owner or int(owner[1]) not in active:
            continue
        clone = re.match(r'^\d+\s+clone(?:3)?\(.*?flags=([^,}]+).*\)\s*=\s*(\d+)$', line)
        if clone and 'CLONE_THREAD' in clone[1].split('|'):
            active.add(int(clone[2]))
        if re.match(r'^\d+\s+exit_group\(', line):
            active.clear()
        elif re.match(r'^\d+\s+(?:exit\(|\+\+\+ (?:exited with|killed by))', line):
            active.discard(int(owner[1]))
        if not re.match(r'^\d+\s+(?:write|writev)\(2,', line):
            continue
        # Only bytes reported transferred can form an observation. Linux can
        # expose a pre-transfer signal restart (ERESTART*) to strace, then issue
        # the write again. Empty/failed attempts contribute no bytes, even if
        # strace prints an undecodable buffer address instead of a string.
        # A restart alone can never satisfy the required completed proof event.
        if re.search(r'\)\s*=\s*(?:0|-1 (?:EINTR|EAGAIN|EWOULDBLOCK)(?: \([^\n]*\))?'
                     r'|\? ERESTART(?:SYS|NOINTR|NOHAND|_RESTARTBLOCK)(?: \([^\n]*\))?)$', line):
            continue
        scalar = re.fullmatch(r'\d+\s+write\(2,\s*("(?:[^"\\]|\\.)*"),\s*(\d+)\)\s*=\s*(\d+|-1 [^\n]+)', line)
        vector = re.fullmatch(r'\d+\s+writev\(2,\s*\[(.*)\],\s*(\d+)\)\s*=\s*(\d+|-1 [^\n]+)', line)
        if scalar:
            raw = quoted_bytes(scalar[1], line)
            count = int(scalar[2])
            result = scalar[3]
        elif vector:
            item = r'\{iov_base=("(?:[^"\\]|\\.)*"|NULL|0x[0-9a-fA-F]+),\s*iov_len=(\d+)\}'
            pieces = re.findall(item, vector[1])
            if (not pieces or len(pieces) != vector[1].count("iov_base=")
                    or len(pieces) != int(vector[2])):
                raise ObservationError("vector_payload", line)
            if re.sub(item, '', vector[1]).strip(' ,\t'):
                raise ObservationError("vector_syntax", line)
            decoded = []
            for raw, size in pieces:
                size = int(size)
                if size == 0:
                    decoded.append((b'', 0))
                elif raw.startswith('"'):
                    decoded.append((quoted_bytes(raw, line), size))
                else:
                    raise ObservationError("vector_payload", line)
            if any(len(raw) != size for raw, size in decoded):
                raise ValueError("reuse_diagnostic_write_truncated")
            raw = b"".join(raw for raw, _ in decoded)
            count, result = len(raw), vector[3]
        else:
            raise ObservationError("write_syntax", line)
        written = 0 if result.startswith("-1 ") else int(result)
        if len(raw) < written or written > count:
            raise ValueError("reuse_diagnostic_write_truncated")
        buffer += raw[:written]
        if len(buffer) > 262144:
            raise ValueError("reuse_diagnostic_limit")
        while b"\n" in buffer:
            payload, buffer = buffer.split(b"\n", 1)
            try:
                row = json.loads(payload)
            except (ValueError, UnicodeError):
                continue
            if isinstance(row, dict):
                observations.append(row)
                if not completed_call:
                    continue
                if row.get('event') == 'mcp_verified_inputs_resume':
                    reuse_profile = row.get('profile')
                if (row.get('event') != 'mcp_real_approval_timing'
                        or row.get('clock') != 'collector_monotonic'
                        or row.get('authority') is not False or row.get('success') is not True
                        or type(row.get('host_call_id')) not in (str, int)
                        or row.get('profile') not in (
                            'sw-mcp/filesystem-readonly/1', 'sw-mcp/git-readonly/1')):
                    continue
                key = (row['profile'], type(row['host_call_id']), row['host_call_id'])
                stage = row.get('stage')
                if (approved_key is None and stage == 'profile_and_assets'
                        and reuse_profile == row['profile']):
                    approved_key = key
                if key != approved_key:
                    continue
                if stage == 'original_dispatch':
                    progress.add(stage)
                elif stage == 'original_response' and 'original_dispatch' in progress:
                    progress.add(stage)
                elif stage == 'result_inspection' and 'original_response' in progress:
                    # This exact invocation's verification/dispatch/response/
                    # release window is complete. Shutdown writes, or a later
                    # invocation's diagnostics, cannot change its history.
                    # Outer wire/kernel/cleanup witnesses still use all lines.
                    return observations
    if completed_call:
        raise ValueError('approved_reuse_scope_incomplete')
    return observations


def reuse_observation(lines, collector_pid, *, require_completed_call=False):
    """Counts are an exact selected collector event, not a timing inference."""
    observations = []
    timings = []
    for row in collector_stderr_rows(lines, collector_pid, completed_call=require_completed_call):
        event, stage = row.get("event"), row.get("stage")
        if event == "mcp_asset_verification_timing" and stage in (
                "selected_profile", "runtime_and_libraries", "package_tree"):
            keys = ("elapsed_ms",)
        elif event == "mcp_real_approval_timing" and stage in (
                "profile_and_assets", "policy_boundary", "classifier", "daemon_redemption",
                "original_dispatch", "original_response", "result_inspection"):
            keys = ("stage_ms", "post_observed_ms")
        else:
            keys = ()
        if (keys and len(timings) < 32
                and all(type(row.get(k)) in (int, float) and math.isfinite(row[k])
                        and row[k] >= 0 for k in keys)):
            # Fixed fields only; these observations never replace the outer
            # end-to-end clock or participate in approval/target decisions.
            timings.append(dict(event=event, stage=stage, **{k: row[k] for k in keys}))
        if row.get("event") != "mcp_verified_inputs_resume":
            continue
        keys = ("immutable_files", "leased_files", "rehashed_files")
        if any(type(row.get(key)) is not int or row[key] < 0 for key in keys):
            raise ValueError("reuse_counts_invalid")
        observations.append({key: row[key] for key in keys})
    if len(observations) != 1:
        raise ValueError("one_selected_reuse_observation_required")
    result = dict(observations[0], observer="collector mcp_verified_inputs_resume",
                  diagnostic_timings=timings)
    if require_completed_call:
        result['scope'] = 'completed_original_approval'
    return result
