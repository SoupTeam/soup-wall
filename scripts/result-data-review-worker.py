#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Embedded, offline CPU result reviewer. Never grants permissions.

Run as: python -I -u -c EMBEDDED_SOURCE ABSOLUTE_ASSET_DIRECTORY
The owner supervises startup (120s) and each complete request (1400ms), killing
and reaping this process on timeout. This worker adds no longer timeout/retry.
Errors are Unknown; stderr contains only stable codes. Uncorrelatable malformed
frames use reserved reply id=0 / zero digest, which can never match a valid id.
view_count is N+1 only for a complete review, otherwise zero. Partial results
are discarded, never represented as complete evidence.
"""
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys

VERSION = "soup-result-data/1"
REPO = "Horizon-Labs/prompt-injection-guard-base"
REVISION = "70b65c51c03f7d9b5d1f18726defee45f3936610"
MODEL_SHA256 = "5ae9f527897b1ffcb2b13440875769d0c28a25fb976b8b42465f0ad5b462b61b"
RUNTIME = {"onnxruntime": "1.23.2", "tokenizers": "0.22.1", "numpy": "2.3.4"}
# Exact reviewed scripts/horizon-model-lock.json, embedded for python -c / -I.
ASSETS = {
    "README.md": (24766, "c49195493b18f925843461029780c8eb8b61aa41e5529e5fc9048baa43f5d084"),
    "config.json": (2032, "34fbf08b5c26d800bb55d6f1de0d3a39c35eb8b5d4208c681361a20f93923f54"),
    "tokenizer.json": (34387555, "47834a7dbbb0c4324fe9569fe47955241594a9ee539c9e478755d6fbc51e5f46"),
    "tokenizer_config.json": (46440, "1d2f82c1341a79748e00efe82e67690f99d00b3c2a894f2b23128fd9d3519da3"),
    "special_tokens_map.json": (636, "baec30ea10906f16adb8c18af7a34023002c1746542612b8b41c9f09e1351351"),
    "onnx/model.onnx": (1230730152, MODEL_SHA256),
}
MAX_LINE = 2 * 1024 * 1024
MAX_REPLY = 64 * 1024
MAX_CHANNEL_BYTES = 1024 * 1024
MAX_CHANNELS = 64
CONTEXT = 8192
ZERO_DIGEST = "0" * 64
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
CODES = frozenset({
    "arguments", "asset_directory", "asset_file", "asset_integrity", "model_format",
    "runtime_version", "runtime_setup", "request_line", "request_json", "request_schema",
    "input_digest", "input_json", "input_schema", "input_limit", "unsupported_context",
    "review_error", "reply_error", "internal_error",
})


class Failure(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else "internal_error"
        super().__init__(self.code)


def error_code(stream, code):
    try:
        stream.write((code if code in CODES else "internal_error") + "\n")
        stream.flush()
    except OSError:
        pass  # A closed owner pipe must not cause a secondary traceback.


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def no_constant(_):
    raise ValueError("nonfinite JSON")


def strict_json(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=no_constant)


class AssetReader:
    """Open every directory component and regular file relative to nofollow FDs."""
    def __init__(self, directory):
        self.fd = None
        if (not isinstance(directory, str) or not directory.startswith("/")
                or "\0" in directory or ".." in directory.split("/")
                or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
                or os.open not in os.supports_dir_fd):
            raise Failure("asset_directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current = None
        try:
            current = os.open("/", flags)
            for part in directory.split("/"):
                if part in ("", "."):
                    continue
                next_fd = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = next_fd
            self.fd = current
        except Exception:
            if current is not None:
                os.close(current)
            raise Failure("asset_directory") from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read(self, relative, expected_size, expected_sha):
        parts = relative.split("/")
        if not parts or any(p in ("", ".", "..") for p in parts):
            raise Failure("asset_file")
        directory = os.dup(self.fd)
        file_fd = None
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=directory)
                os.close(directory)
                directory = next_fd
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                              dir_fd=directory)
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                raise Failure("asset_integrity")
            with os.fdopen(file_fd, "rb", closefd=False) as source:
                data = source.read(expected_size + 1)
            after = os.fstat(file_fd)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            if (len(data) != expected_size or identity(before) != identity(after)
                    or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha)):
                raise Failure("asset_integrity")
            return data
        except Failure:
            raise
        except Exception:
            raise Failure("asset_file") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(directory)


class ModelWireCheck:
    """Bounded protobuf inspection, without importing/executing an ONNX graph.

    The full immutable model hash is mandatory first. This also explicitly
    rejects external tensor data, custom domains/functions, sparse/training
    graphs and unsupported wire formats. Length-delimited weights are views,
    never copied or interpreted as code/filesystem paths.
    """
    def __init__(self):
        self.remaining = 200000

    @staticmethod
    def varint(data, pos):
        value = 0
        for shift in range(0, 70, 7):
            if pos >= len(data):
                raise Failure("model_format")
            byte = data[pos]
            pos += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                if value > (1 << 64) - 1:
                    raise Failure("model_format")
                return value, pos
        raise Failure("model_format")

    def fields(self, data):
        pos = 0
        while pos < len(data):
            self.remaining -= 1
            if self.remaining < 0:
                raise Failure("model_format")
            tag, pos = self.varint(data, pos)
            field, wire = tag >> 3, tag & 7
            if field == 0:
                raise Failure("model_format")
            if wire == 0:
                value, pos = self.varint(data, pos)
            elif wire in (1, 2, 5):
                if wire == 2:
                    size, pos = self.varint(data, pos)
                else:
                    size = 8 if wire == 1 else 4
                if size > len(data) - pos:
                    raise Failure("model_format")
                value = data[pos:pos + size]
                pos += size
            else:
                raise Failure("model_format")
            yield field, wire, value

    def tensor(self, data):
        for field, wire, value in self.fields(data):
            if field == 13 or (field == 14 and (wire != 0 or value != 0)):
                raise Failure("model_format")

    def attribute(self, data, depth):
        for field, wire, value in self.fields(data):
            if field in (5, 10):
                if wire != 2:
                    raise Failure("model_format")
                self.tensor(value)
            elif field in (6, 11):
                if wire != 2:
                    raise Failure("model_format")
                self.graph(value, depth + 1)
            elif field in (22, 23):
                raise Failure("model_format")

    def graph(self, data, depth=0):
        if depth > 64:
            raise Failure("model_format")
        for field, wire, value in self.fields(data):
            if field == 1:
                if wire != 2:
                    raise Failure("model_format")
                for nf, nw, nv in self.fields(value):
                    if nf == 7 and (nw != 2 or nv not in (b"", b"ai.onnx")):
                        raise Failure("model_format")
                    if nf == 5:
                        if nw != 2:
                            raise Failure("model_format")
                        self.attribute(nv, depth)
            elif field == 5:
                if wire != 2:
                    raise Failure("model_format")
                self.tensor(value)
            elif field == 15:
                raise Failure("model_format")

    def check(self, data):
        graphs = 0
        for field, wire, value in self.fields(memoryview(data)):
            if field == 7:
                if wire != 2:
                    raise Failure("model_format")
                graphs += 1
                self.graph(value)
            elif field == 8:
                if wire != 2:
                    raise Failure("model_format")
                for of, ow, ov in self.fields(value):
                    if of == 1 and (ow != 2 or ov not in (b"", b"ai.onnx")):
                        raise Failure("model_format")
            elif field in (20, 25):
                raise Failure("model_format")
        if graphs != 1:
            raise Failure("model_format")


def envelope(channels):
    return "".join(
        f'[untrusted channel c{i}; utf8_bytes={len(text.encode("utf-8"))}]\n'
        + text + f"\n[end channel c{i}]\n"
        for i, text in enumerate(channels)
    )


def classify(score):
    if score <= 0.05:
        return "data"
    if score >= 0.5:
        return "instruction"
    return "unknown"


class Reviewer:
    def __init__(self, tokenizer, session, numpy):
        self.tokenizer = tokenizer
        self.session = session
        self.np = numpy
        tokenizer.no_truncation()
        tokenizer.no_padding()
        # Caller text is data. Literal <bos>/<eos>/<mask> strings must not
        # become model control IDs; the post-processor still adds its own
        # trusted boundary IDs. This changes no original input bytes.
        tokenizer.encode_special_tokens = True
        inputs = session.get_inputs()
        if (session.get_providers() != ["CPUExecutionProvider"] or len(inputs) != 2
                or {item.name for item in inputs} != {"input_ids", "attention_mask"}
                or any(item.type != "tensor(int64)" for item in inputs)):
            raise Failure("runtime_setup")

    def review(self, channels):
        # Preflight every whole view before any inference. Unsupported global
        # context is Unknown; raw-channel scores never replace the envelope.
        encoded = [self.tokenizer.encode(text, add_special_tokens=True)
                   for text in (envelope(channels), *channels)]
        if any(len(item.ids) > CONTEXT for item in encoded):
            raise Failure("unsupported_context")
        maximum = 0.0
        completed = 0
        try:
            for item in encoded:
                if not item.ids or len(item.ids) != len(item.attention_mask):
                    raise Failure("review_error")
                feed = {"input_ids": self.np.asarray([item.ids], dtype=self.np.int64),
                        "attention_mask": self.np.asarray([item.attention_mask], dtype=self.np.int64)}
                outputs = self.session.run(None, feed)
                if len(outputs) != 1:
                    raise Failure("review_error")
                values = self.np.asarray(outputs[0])
                if values.shape != (1, 2) or values.dtype != self.np.float32:
                    raise Failure("review_error")
                logits = [float(value) for value in values[0]]
                if any(not math.isfinite(value) for value in logits):
                    raise Failure("review_error")
                exp = [math.exp(value - max(logits)) for value in logits]
                score = exp[1] / sum(exp)
                if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                    raise Failure("review_error")
                maximum = max(maximum, score)
                completed += 1
        except Exception:
            # No partial view, partial max, runtime exception text or payload is
            # exposed as complete evidence. The owner treats this as Unknown.
            raise Failure("review_error") from None
        return classify(maximum), completed, maximum


def build_reviewer(directory):
    try:
        import numpy
        import onnxruntime as ort
        import tokenizers
    except Exception:
        raise Failure("runtime_setup") from None
    versions = {"onnxruntime": ort.__version__, "tokenizers": tokenizers.__version__, "numpy": numpy.__version__}
    if versions != RUNTIME:
        raise Failure("runtime_version")
    reader = AssetReader(directory)
    verified = {}
    try:
        for name, (size, sha) in ASSETS.items():
            verified[name] = reader.read(name, size, sha)
    finally:
        reader.close()
    model = verified.pop("onnx/model.onnx")
    tokenizer_bytes = verified.pop("tokenizer.json")
    ModelWireCheck().check(model)
    try:
        tokenizer = tokenizers.Tokenizer.from_str(tokenizer_bytes.decode("utf-8", "strict"))
        options = ort.SessionOptions()
        options.intra_op_num_threads = 6
        options.inter_op_num_threads = 1
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        options.log_severity_level = 4
        # Verified immutable bytes: no model-path reopen / path TOCTOU, external
        # initializer files, custom-op registration, provider fallback or network.
        session = ort.InferenceSession(model, sess_options=options, providers=["CPUExecutionProvider"])
        reviewer = Reviewer(tokenizer, session, numpy)
        reviewer.review(["Warm-up: ordinary sample text."])
    except Failure:
        raise
    except Exception:
        raise Failure("runtime_setup") from None
    return reviewer, versions


def parse_request(line):
    try:
        value = strict_json(line.decode("utf-8", "strict"))
    except Exception:
        raise Failure("request_json") from None
    if not isinstance(value, dict):
        raise Failure("request_schema")
    return value


def correlation(request):
    request_id = request.get("id")
    digest = request.get("input_sha256")
    if type(request_id) is not int or not 1 <= request_id <= (1 << 64) - 1:
        request_id = 0
    if not isinstance(digest, str) or HEX_DIGEST.fullmatch(digest) is None:
        digest = ZERO_DIGEST
    return request_id, digest


def channels_for(request):
    if (set(request) != {"v", "id", "input_sha256", "input_json"}
            or request.get("v") != VERSION or type(request.get("id")) is not int
            or not 1 <= request["id"] <= (1 << 64) - 1
            or not isinstance(request.get("input_sha256"), str)
            or HEX_DIGEST.fullmatch(request["input_sha256"]) is None
            or not isinstance(request.get("input_json"), str)):
        raise Failure("request_schema")
    try:
        raw = request["input_json"].encode("utf-8", "strict")
    except UnicodeError:
        raise Failure("input_json") from None
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), request["input_sha256"]):
        raise Failure("input_digest")
    try:
        value = strict_json(raw.decode("utf-8"))
    except Exception:
        raise Failure("input_json") from None
    if not isinstance(value, dict) or set(value) != {"channels"} or not isinstance(value["channels"], list):
        raise Failure("input_schema")
    channels = value["channels"]
    if not 1 <= len(channels) <= MAX_CHANNELS or any(not isinstance(text, str) for text in channels):
        raise Failure("input_schema")
    try:
        if sum(len(text.encode("utf-8", "strict")) for text in channels) > MAX_CHANNEL_BYTES:
            raise Failure("input_limit")
    except UnicodeError:
        raise Failure("input_json") from None
    return channels


def review_request(line, reviewer):
    request_id, digest = 0, ZERO_DIGEST
    result = {"v": VERSION, "type": "review", "id": request_id, "input_sha256": digest,
              "model_sha256": MODEL_SHA256, "assessment": "unknown", "coverage_complete": False,
              "view_count": 0, "max_score": None}
    try:
        request = parse_request(line)
        request_id, digest = correlation(request)
        result["id"], result["input_sha256"] = request_id, digest
        channels = channels_for(request)
        assessment, count, score = reviewer.review(channels)
        if (type(score) is not float or type(count) is not int
                or assessment != classify(score) or count != len(channels) + 1
                or not math.isfinite(score) or not 0.0 <= score <= 1.0):
            raise Failure("review_error")
        result.update(assessment=assessment, coverage_complete=True, view_count=count, max_score=score)
        return result, None
    except Failure as error:
        return result, error.code
    except Exception:
        return result, "review_error"


def emit(output, value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"
    if len(raw) > MAX_REPLY:
        raise Failure("reply_error")
    output.write(raw)
    output.flush()


def serve(source, output, errors, reviewer):
    while True:
        line = source.readline(MAX_LINE + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE or not line.endswith(b"\n"):
            # Never drain an unbounded hostile frame or reinterpret its tail as
            # another request. No valid correlation can be recovered safely.
            reply, _ = review_request(b"{}", reviewer)
            emit(output, reply)
            error_code(errors, "request_line")
            return 1
        reply, code = review_request(line, reviewer)
        emit(output, reply)
        if code:
            error_code(errors, code)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        error_code(sys.stderr, "arguments")
        return 2
    try:
        reviewer, versions = build_reviewer(argv[0])
        emit(sys.stdout.buffer, {"v": VERSION, "type": "ready", "model_sha256": MODEL_SHA256, "runtime": versions})
        return serve(sys.stdin.buffer, sys.stdout.buffer, sys.stderr, reviewer)
    except Failure as error:
        error_code(sys.stderr, error.code)
        return 1
    except Exception:
        error_code(sys.stderr, "internal_error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
