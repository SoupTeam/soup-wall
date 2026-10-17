# SPDX-License-Identifier: Apache-2.0
"""Persistent worker framing for a packaged rule classifier (sw-classifier-worker/1).

The classifier module itself is executed unchanged by the bootstrap that verified its
bytes. This file only frames requests: one JSON line in, one JSON line out, each
reply bound to the request id and to the SHA-256 of the exact semantic input bytes.
No request is retained after its reply is written.

request : {"v","id","input_sha256","input_json"}   (input_json = exact semantic input bytes)
ready   : {"v","ready":true,"classifier_sha256"}
reply   : {"v","id","input_sha256","result_json"}  (result_json = what single-shot prints)
"""
import hashlib
import json
import sys

PROTOCOL = "sw-classifier-worker/1"
MAX_INPUT_BYTES = 1024 * 1024
MAX_FRAME_BYTES = 2 * MAX_INPUT_BYTES + 4096


def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen[key] = value
    return seen


def _emit(frame):
    sys.stdout.write(json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run(namespace, classifier_sha256):
    """Serve frames until EOF. Any protocol violation ends the process (exit 3)."""
    classify = namespace["classify"]
    error = namespace["_error"]
    stream = sys.stdin.buffer
    _emit({"v": PROTOCOL, "ready": True, "classifier_sha256": classifier_sha256})
    while True:
        line = stream.readline(MAX_FRAME_BYTES + 2)
        if not line:
            return 0
        if len(line) > MAX_FRAME_BYTES + 1 or not line.endswith(b"\n"):
            return 3
        try:
            frame = json.loads(line[:-1].decode("utf-8"), object_pairs_hook=_no_duplicates)
        except (ValueError, UnicodeError, RecursionError):
            return 3
        if (
            not isinstance(frame, dict)
            or set(frame) != {"v", "id", "input_sha256", "input_json"}
            or frame["v"] != PROTOCOL
            or type(frame["id"]) is not int
            or not isinstance(frame["input_sha256"], str)
            or not isinstance(frame["input_json"], str)
        ):
            return 3
        payload = frame["input_json"].encode("utf-8")
        if hashlib.sha256(payload).hexdigest() != frame["input_sha256"]:
            return 3
        # Same semantics as the single-shot main(): size limit, then parse, then classify.
        if len(payload) > MAX_INPUT_BYTES:
            result = error("invalid_input: input line exceeds the size limit")
        else:
            try:
                result = classify(json.loads(payload.decode("utf-8")))
            except (ValueError, UnicodeError, RecursionError):
                result = error("invalid_input: not valid UTF-8 JSON")
        _emit(
            {
                "v": PROTOCOL,
                "id": frame["id"],
                "input_sha256": frame["input_sha256"],
                "result_json": json.dumps(result, ensure_ascii=False),
            }
        )
