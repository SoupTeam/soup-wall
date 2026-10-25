# SPDX-License-Identifier: Apache-2.0
"""No weights/downloads/inference: protocol, ownership and fake-runtime tests."""
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

WORKER = Path(__file__).parents[1] / "result-data-review-worker.py"
spec = importlib.util.spec_from_file_location("result_data_worker", WORKER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Array:
    def __init__(self, data, dtype="float32"):
        self.data = data
        self.dtype = dtype
        self.shape = (len(data), len(data[0])) if data and isinstance(data[0], list) else (len(data),)

    def __getitem__(self, index):
        return self.data[index]


class Numpy:
    __version__ = "2.3.4"
    int64 = "int64"
    float32 = "float32"

    @staticmethod
    def asarray(value, dtype=None):
        return value if isinstance(value, Array) else Array(value, dtype or "float32")


class Tokenizer:
    def __init__(self):
        self.texts = []
        self.no_cut = False
        self.no_pad = False
        self.oversized = None

    def no_truncation(self):
        self.no_cut = True

    def no_padding(self):
        self.no_pad = True

    def encode(self, text, add_special_tokens):
        assert add_special_tokens
        self.texts.append(text)
        ids = [2, *text.encode("utf-8"), 1]
        if text == self.oversized:
            ids = [2] * 8193
        return SimpleNamespace(ids=ids, attention_mask=[1] * len(ids))


class Session:
    def __init__(self, scores=None):
        self.scores = iter(scores or [.01] * 100)
        self.calls = []
        self.providers = ["CPUExecutionProvider"]

    def get_providers(self):
        return self.providers

    def get_inputs(self):
        return [SimpleNamespace(name=n, type="tensor(int64)") for n in ("input_ids", "attention_mask")]

    def run(self, names, feed):
        self.calls.append(feed)
        value = next(self.scores)
        if isinstance(value, Exception):
            raise value
        if isinstance(value, list):
            return [value]
        return [[[math.log1p(-value), math.log(value)]]]


def engine(scores=None):
    tok, sess = Tokenizer(), Session(scores)
    return m.Reviewer(tok, sess, Numpy), tok, sess


def request(channels=None, input_json=None, request_id=1):
    if input_json is None:
        input_json = json.dumps({"channels": ["ordinary"] if channels is None else channels}, ensure_ascii=False)
    return {"v": m.VERSION, "id": request_id, "input_sha256": hashlib.sha256(input_json.encode()).hexdigest(),
            "input_json": input_json}


def line(value):
    return json.dumps(value, ensure_ascii=True).encode() + b"\n"


class Protocol(unittest.TestCase):
    def unknown(self, value, code=None):
        reviewer, tok, session = engine()
        result, actual = m.review_request(line(value), reviewer)
        self.assertEqual(result["assessment"], "unknown")
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["view_count"], 0)
        self.assertIsNone(result["max_score"])
        self.assertFalse(tok.texts)
        self.assertFalse(session.calls)
        if code:
            self.assertEqual(actual, code)
        return result

    def test_exact_utf8_json_digest_and_all_original_views(self):
        channels = ["Я😀\r\n---\n", "", "Я😀\r\n---\n", "\x00tail\r"]
        raw = '{ "channels" : ' + json.dumps(channels, ensure_ascii=False) + ' }\r\n'
        reviewer, tok, session = engine([.01, .02, .03, .8, .04])
        original = request(input_json=raw, request_id=(1 << 64) - 1)
        result, code = m.review_request(line(original), reviewer)
        self.assertIsNone(code)
        self.assertEqual(result["id"], (1 << 64) - 1)
        self.assertEqual(result["input_sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(tok.texts, [m.envelope(channels), *channels])
        self.assertTrue(tok.no_cut and tok.no_pad)
        self.assertEqual(len(session.calls), 5)
        self.assertEqual(result["assessment"], "instruction")
        self.assertTrue(result["coverage_complete"])
        self.assertEqual(result["view_count"], 5)
        self.assertAlmostEqual(result["max_score"], .8)
        self.assertEqual(set(result), {"v", "type", "id", "input_sha256", "model_sha256", "assessment",
                                      "coverage_complete", "view_count", "max_score"})
        # No canonicalization of whitespace, CRLF or JSON's literal UTF-8.
        original["input_sha256"] = hashlib.sha256(json.dumps({"channels": channels}).encode()).hexdigest()
        self.unknown(original, "input_digest")

    def test_unknown_keys_labels_tasks_and_strict_ids(self):
        for key in ("label", "task", "extra"):
            value = request(); value[key] = "PRIVATE_MARKER"
            self.unknown(value, "request_schema")
        for value in (True, False, 0, -1, 1.0, "1", None, 1 << 64):
            with self.subTest(request_id=value):
                result = self.unknown(request(request_id=value), "request_schema")
                self.assertEqual(result["id"], 0)
        for payload in ({"channels": ["x"], "label": "benign"}, {"channels": []}, {"channels": [1]},
                        {"channels": "text"}, {"channels": ["x"] * 65}, ["x"]):
            self.unknown(request(input_json=json.dumps(payload)), "input_schema")

    def test_duplicate_keys_nonfinite_utf8_surrogates_and_limits(self):
        self.unknown(request(input_json='{"channels":["x"],"channels":["y"]}'), "input_json")
        self.unknown(request(input_json='{"channels":[NaN]}'), "input_json")
        self.unknown(request(input_json='{"channels":["\\ud800"]}'), "input_json")
        self.unknown(request(channels=["x" * (1024 * 1024 + 1)]), "input_limit")
        reviewer, _, _ = engine()
        for raw in (b'\xff\n', b'{"id":1,"id":2}\n', b'NaN\n', b'[]\n'):
            result, code = m.review_request(raw, reviewer)
            self.assertEqual(result["assessment"], "unknown")
            self.assertIn(code, ("request_json", "request_schema"))

    def test_all_views_required_and_errors_cannot_report_partial_data(self):
        reviewer, tok, session = engine()
        tok.oversized = "oversize"
        result, code = m.review_request(line(request(channels=["oversize"])), reviewer)
        self.assertEqual(code, "unsupported_context")
        self.assertFalse(result["coverage_complete"])
        self.assertFalse(session.calls)
        # The second view fails after a successful benign first view.
        reviewer, _, _ = engine([.001, RuntimeError("PRIVATE_MARKER raw logits")])
        result, code = m.review_request(line(request()), reviewer)
        self.assertEqual(code, "review_error")
        self.assertFalse(result["coverage_complete"])
        self.assertIsNone(result["max_score"])
        for output in ([[float("nan"), 0]], [[0, float("inf")]], [[0, 1, 2]]):
            reviewer, _, _ = engine([output])
            result, code = m.review_request(line(request()), reviewer)
            self.assertEqual(code, "review_error")
            self.assertIsNone(result["max_score"])

    def test_finite_unknown_is_not_null_and_thresholds_unchanged(self):
        self.assertEqual([m.classify(x) for x in (0.05, .050001, .499999, .5)],
                         ["data", "unknown", "unknown", "instruction"])
        reviewer, _, _ = engine([.2, .3])
        result, code = m.review_request(line(request()), reviewer)
        self.assertIsNone(code)
        self.assertTrue(result["coverage_complete"])
        self.assertEqual(result["assessment"], "unknown")
        self.assertAlmostEqual(result["max_score"], .3)

    def test_maximum_channels_empty_duplicates_and_utf8_byte_boundary(self):
        reviewer, tok, session = engine()
        result, code = m.review_request(line(request(channels=[""] * 64)), reviewer)
        self.assertIsNone(code)
        self.assertEqual(result["view_count"], 65)
        self.assertEqual(tok.texts[1:], [""] * 64)
        self.assertEqual(len(session.calls), 65)
        exact = "é" * (m.MAX_CHANNEL_BYTES // 2)
        self.assertEqual(m.channels_for(request(channels=[exact])), [exact])
        with self.assertRaises(m.Failure): m.channels_for(request(channels=[exact + "é"]))

    def test_stream_bounds_errors_never_echo_raw_text(self):
        reviewer, _, _ = engine([RuntimeError("PRIVATE_MARKER")])
        output, errors = io.BytesIO(), io.StringIO()
        status = m.serve(io.BytesIO(line(request(channels=["PRIVATE_MARKER"]))), output, errors, reviewer)
        self.assertEqual(status, 0)
        self.assertEqual(errors.getvalue(), "review_error\n")
        self.assertNotIn(b"PRIVATE_MARKER", output.getvalue())
        self.assertLess(len(output.getvalue()), m.MAX_REPLY)
        for raw in (b"x" * (m.MAX_LINE + 1) + b"\n" + line(request()), b'{}'):
            output, errors = io.BytesIO(), io.StringIO()
            self.assertEqual(m.serve(io.BytesIO(raw), output, errors, reviewer), 1)
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertEqual(errors.getvalue(), "request_line\n")


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd, "POSIX nofollow assets")
class AssetSafety(unittest.TestCase):
    def read(self, directory, name="asset", data=b"abc"):
        reader = m.AssetReader(str(directory))
        try:
            return reader.read(name, len(data), hashlib.sha256(data).hexdigest())
        finally:
            reader.close()

    def test_regular_verified_bytes_and_changed_content(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "asset").write_bytes(b"abc")
            self.assertEqual(self.read(root), b"abc")
            (root / "asset").write_bytes(b"bad")
            with self.assertRaises(m.Failure): self.read(root)
            (root / "asset").write_bytes(b"ab")
            with self.assertRaises(m.Failure): self.read(root)

    def test_symlink_directory_file_subdirectory_and_fifo_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); real = root / "real"; real.mkdir()
            (real / "asset").write_bytes(b"abc")
            (root / "linked").symlink_to(real, target_is_directory=True)
            with self.assertRaises(m.Failure): m.AssetReader(str(root / "linked"))
            (root / "asset").symlink_to(real / "asset")
            with self.assertRaises(m.Failure): self.read(root)
            with self.assertRaises(m.Failure): self.read(root, "linked/asset")
            os.mkfifo(root / "fifo")
            with self.assertRaises(m.Failure): self.read(root, "fifo")
            with self.assertRaises(m.Failure): self.read(root, "../real/asset")


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128); value >>= 7
    return bytes(out + bytes([value]))


def field(number, value):
    return varint(number * 8 + 2) + varint(len(value)) + value


class GraphSafety(unittest.TestCase):
    def test_no_external_data_custom_ops_functions_or_nested_escape(self):
        m.ModelWireCheck().check(field(7, b""))
        external = field(5, field(13, b""))
        external_location = field(5, varint(14 * 8) + varint(1))
        custom = field(1, field(7, b"untrusted.custom"))
        nested = field(1, field(5, field(6, custom)))
        for graph in (external, external_location, custom, nested, field(15, b"")):
            with self.assertRaises(m.Failure): m.ModelWireCheck().check(field(7, graph))
        with self.assertRaises(m.Failure): m.ModelWireCheck().check(field(7, b"") + field(25, b""))
        with self.assertRaises(m.Failure): m.ModelWireCheck().check(b"\x3a\xff")

    def test_pins_equal_original_reviewed_lock(self):
        lock = json.loads((WORKER.parent / "horizon-model-lock.json").read_bytes())
        self.assertEqual((m.REPO, m.REVISION, m.RUNTIME), (lock["repo"], lock["revision"], lock["runtime"]))
        self.assertEqual(m.ASSETS, {name: (info["bytes"], info["sha256"]) for name, info in lock["files"].items()})


class Loader(unittest.TestCase):
    def test_verified_bytes_cpu_only_versions_and_synthetic_warmup(self):
        tok, sess = Tokenizer(), Session()
        model = field(7, b"")
        values = {name: b"{}" for name in m.ASSETS}; values["onnx/model.onnx"] = model
        reader = mock.Mock()
        reader.read.side_effect = lambda name, *_: values[name]
        factory = mock.Mock(return_value=sess)
        tokenizer_factory = mock.Mock(return_value=tok)
        ort = SimpleNamespace(__version__="1.23.2", SessionOptions=SimpleNamespace,
            ExecutionMode=SimpleNamespace(ORT_SEQUENTIAL="sequential"),
            GraphOptimizationLevel=SimpleNamespace(ORT_ENABLE_ALL="all"), InferenceSession=factory)
        tokenizers = SimpleNamespace(__version__="0.22.1", Tokenizer=SimpleNamespace(from_str=tokenizer_factory))
        with mock.patch.dict(sys.modules, {"numpy": Numpy, "onnxruntime": ort, "tokenizers": tokenizers}), \
                mock.patch.object(m, "AssetReader", return_value=reader):
            reviewer, versions = m.build_reviewer("/assets")
            self.assertEqual(versions, m.RUNTIME)
            self.assertIs(reviewer.session, sess)
            self.assertIs(factory.call_args.args[0], model)
            self.assertEqual(factory.call_args.kwargs["providers"], ["CPUExecutionProvider"])
            self.assertEqual(factory.call_args.kwargs["sess_options"].intra_op_num_threads, 6)
            self.assertEqual(tokenizer_factory.call_args.args, ("{}",))
            self.assertEqual(tok.texts, [m.envelope(["Warm-up: ordinary sample text."]), "Warm-up: ordinary sample text."])
            self.assertEqual(reader.read.call_count, 6)
            reader.close.assert_called_once()
            factory.reset_mock()
            ort.__version__ = "other"
            with self.assertRaises(m.Failure): m.build_reviewer("/assets")
            factory.assert_not_called()

    def test_gpu_provider_cannot_silently_fallback(self):
        session = Session(); session.providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        with self.assertRaises(m.Failure): m.Reviewer(Tokenizer(), session, Numpy)

    def test_isolated_embedded_entrypoint_has_no_repo_file_dependency(self):
        # Only replace startup with a deterministic fake. Execute the real
        # protocol/main source via the intended -I -u -c entrypoint, env cleared.
        source = WORKER.read_text().split('if __name__ == "__main__":')[0]
        source += '''
class FakeReviewer:
    def review(self, channels):
        return "data", len(channels)+1, 0.01
build_reviewer = lambda directory: (FakeReviewer(), dict(RUNTIME))
raise SystemExit(main())
'''
        value = request(channels=["Я\r\n", "", "Я\r\n"])
        completed = subprocess.run([sys.executable, "-I", "-u", "-c", source, "/unused"],
            input=line(value), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        ready, reply = [json.loads(s) for s in completed.stdout.splitlines()]
        self.assertEqual(ready, {"v": m.VERSION, "type": "ready", "model_sha256": m.MODEL_SHA256, "runtime": m.RUNTIME})
        self.assertEqual(reply["input_sha256"], value["input_sha256"])
        self.assertEqual((reply["assessment"], reply["view_count"], reply["coverage_complete"]), ("data", 4, True))


if __name__ == "__main__":
    unittest.main()
