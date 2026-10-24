"""Validate the opt-in pilot operator contract at the subprocess boundary."""
import re

FORMAT = "sw-pilot-operator-result/1"
FIELDS = {"format", "operation", "outcome", "reason", "identity", "data"}
SUCCESS = {"list": "listed", "inspect": "inspection_presented", "approve": "decision_submitted",
           "reject": "rejection_submitted", "stop": "stop_confirmed"}
SUCCESS_REASON = {"list": "pending_snapshot", "inspect": "exact_pending_arguments",
                  "approve": "approval_submitted", "reject": "rejection_submitted", "stop": "owned_stop_receipt"}
REASONS = {name: 3 for name in (
    "unsupported_platform", "invalid_input", "unsafe_run_record", "run_expired", "run_stopping",
    "selection_changed", "daemon_refused", "daemon_identity_changed", "pending_unavailable",
    "pending_expired", "binding_changed", "inspection_required", "decision_conflict")}
REASONS.update({"run_unavailable": 4, "daemon_unavailable": 4, "stop_ownership_unverified": 5,
                "stop_unconfirmed": 5, "unknown": 5, "output_unavailable": 6, "output_limit": 6})


def validate(record, operation, exit_code):
    def require(condition):
        if not condition:
            raise ValueError("invalid_operator_result")

    require(type(record) is dict and set(record) == FIELDS)
    require(record["format"] == FORMAT and record["operation"] == operation and operation in SUCCESS)
    require(type(record["reason"]) is str and re.fullmatch(r"[a-z_]{1,64}", record["reason"]))
    identity, data = record["identity"], record["data"]
    if identity is not None:
        require(type(identity) is dict and set(identity) in (
            {"run_id", "run_sha256", "instance_id", "registry_sha256"},
            {"run_id", "run_sha256", "instance_id", "registry_sha256", "pending_id", "binding_sha256"}))
        require(type(identity["run_id"]) is str and re.fullmatch(r"[a-fA-F0-9]{32}", identity["run_id"]))
        for key in ("run_sha256", "registry_sha256", "binding_sha256"):
            if key in identity:
                require(type(identity[key]) is str and re.fullmatch(r"[a-f0-9]{64}", identity[key]))
        for key in ("instance_id", "pending_id"):
            if key in identity:
                require(type(identity[key]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity[key]))
    if exit_code == 0:
        require(record["outcome"] == SUCCESS[operation] and identity is not None)
        require(record["reason"] == SUCCESS_REASON[operation])
        if operation == "list":
            require(type(data) is list and len(data) <= 16)
            for row in data:
                require(type(row) is dict and set(row) == {
                    "server", "tool", "pending_id", "binding_sha256", "expires_at_ms", "state"})
        else:
            require(type(data) is dict)
        if operation == "approve":
            require(data.get("dispatched") == "not_observed" and data.get("released") == "not_observed")
        elif operation == "reject":
            require(data.get("released") is False)
        elif operation == "stop":
            require(data.get("status") in ("stopped", "already_stopped")
                    and data.get("running_effects_rolled_back") is False)
    else:
        require(exit_code in (3, 4, 5, 6))
        if operation == "inspect" and record["outcome"] == "inspection_presented":
            require(record["reason"] == "exact_pending_arguments")
        else:
            require(REASONS.get(record["reason"]) == exit_code)
            require(data is None and record["outcome"] in ("refused", "unavailable", "unknown", "stop_requested"))
            require(record["outcome"] != "stop_requested" or operation == "stop")
            expected = "unavailable" if exit_code == 4 else "unknown" if exit_code in (5, 6) else "refused"
            require(record["outcome"] in (expected, "stop_requested"))
    return record
