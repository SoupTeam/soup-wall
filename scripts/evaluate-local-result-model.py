#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pinned, offline development observations. No policy or execution integration."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import queue
import signal
import statistics
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
REVISION = '90c9989b1a342275dd0d1a95aad283c04e075671'
REPO = 'protectai/deberta-v3-base-prompt-injection-v2'
WEIGHTS_SHA = 'f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c'
MAX_INPUT = 65536
MAX_LINE = 4096
MAX_STREAM = 262144
MAX_CASES = 64
STARTUP_SECONDS = 60
CASE_SECONDS = 30
TOTAL_SECONDS = 300


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def verify_assets(directory):
    lock = json.loads((ROOT / 'scripts/result-model-lock.json').read_text())
    if lock['revision'] != REVISION or lock['repo'] != REPO:
        raise ValueError('checkpoint identity')
    if lock['files']['model.onnx'] != WEIGHTS_SHA:
        raise ValueError('weight identity')
    for name, expected in lock['files'].items():
        if digest(directory / name) != expected:
            raise ValueError('asset hash mismatch: ' + name)
    return lock


def windows_for(ids, width=510, stride=384):
    """Complete token coverage with overlap; never truncate a suffix."""
    if not ids:
        return [(0, [])]
    rows = []
    for start in range(0, len(ids), stride):
        rows.append((start, ids[start:start + width]))
        if start + width >= len(ids):
            break
    return rows


def decide(scores):
    if not scores or any(type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1 for p in scores):
        return 'unknown'
    if max(scores) >= .95:
        return 'instruction'
    if max(scores) <= .05:
        return 'data'
    return 'unknown'


class OwnedProcess:
    """Worker waits for stdin until assigned to a kill-on-close Windows Job.

    On POSIX a new session owns its process group. No caller-supplied executable.
    Failure to establish ownership aborts before input/model loading.
    """
    def __init__(self, args):
        self.job = None
        self.p = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()), *args],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  start_new_session=os.name != 'nt')
        try:
            if os.name == 'nt':
                from ctypes import wintypes as w
                class Basic(ctypes.Structure):
                    _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                                ('flags', w.DWORD), ('min_ws', ctypes.c_size_t), ('max_ws', ctypes.c_size_t),
                                ('active', w.DWORD), ('affinity', ctypes.c_size_t), ('priority', w.DWORD),
                                ('scheduling', w.DWORD)]
                class Limits(ctypes.Structure):
                    _fields_ = [('basic', Basic), ('io', ctypes.c_uint64 * 6),
                                ('process_mem', ctypes.c_size_t), ('job_mem', ctypes.c_size_t),
                                ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
                k = ctypes.WinDLL('kernel32', use_last_error=True)
                k.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
                k.CreateJobObjectW.restype = w.HANDLE
                k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
                k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
                k.CloseHandle.argtypes = [w.HANDLE]
                self.kernel = k
                self.job = k.CreateJobObjectW(None, None)
                limits = Limits()
                limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                if not self.job or not k.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                    raise OSError(ctypes.get_last_error(), 'job limits')
                if not k.AssignProcessToJobObject(self.job, w.HANDLE(int(self.p._handle))):
                    raise OSError(ctypes.get_last_error(), 'job assignment')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.job:
            self.kernel.CloseHandle(self.job)
            self.job = None
        elif os.name != 'nt':
            try:
                os.killpg(self.p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait(timeout=5)
        # Reader threads own stdout/stderr until EOF; stdin is only used by parent.
        self.p.stdin.close()


def run_worker(directory, rows, test_mode=None, startup=STARTUP_SECONDS, per_case=CASE_SECONDS, total=TOTAL_SECONDS):
    if len(rows) > MAX_CASES or not 0 < startup <= STARTUP_SECONDS or not 0 < per_case <= CASE_SECONDS or not 0 < total <= TOTAL_SECONDS:
        raise ValueError('bounded run required')
    if any(len(row['text'].encode('utf-8')) > MAX_INPUT for row in rows):
        raise ValueError('input limit')
    args = ['--worker', str(directory)] if test_mode is None else ['--test-worker', test_mode]
    started = time.monotonic()
    events = queue.Queue(maxsize=128)
    stop = threading.Event()
    def emit(value):
        try:
            events.put_nowait(value)
        except queue.Full:
            stop.set()
    def read(pipe, is_error):
        count = 0
        try:
            while True:
                line = pipe.readline(MAX_LINE + 1)
                if not line:
                    emit(('eof_error' if is_error else 'eof', None))
                    return
                count += len(line)
                if is_error or len(line) > MAX_LINE or count > MAX_STREAM or not line.endswith(b'\n'):
                    emit(('output_limit_or_stderr', None))
                    return
                emit(('line', line))
        finally:
            pipe.close()
    owned = OwnedProcess(args)
    readers = [threading.Thread(target=read, args=(owned.p.stdout, False), daemon=True),
               threading.Thread(target=read, args=(owned.p.stderr, True), daemon=True)]
    for reader in readers:
        reader.start()
    observations = []
    failure = None
    ready = False
    writers = []
    def send(request):
        try:
            owned.p.stdin.write(request)
            owned.p.stdin.flush()
        except (OSError, ValueError):
            emit(('write_error', None))
    try:
        # Release worker only after process ownership is established.
        owned.p.stdin.write(b'go\n')
        owned.p.stdin.flush()
        next_deadline = started + startup
        while len(observations) < len(rows) or not ready:
            if stop.is_set():
                failure = 'output_queue_limit'
                break
            remaining = min(started + total, next_deadline) - time.monotonic()
            if remaining <= 0:
                failure = 'timeout'
                break
            try:
                kind, raw = events.get(timeout=min(remaining, .1))
            except queue.Empty:
                continue
            if kind == 'eof_error':
                continue
            if kind != 'line':
                failure = kind
                break
            try:
                value = json.loads(raw)
                if not ready:
                    if value != {'ready': True}:
                        raise ValueError('ready')
                    ready = True
                    startup_ms = (time.monotonic() - started) * 1000
                else:
                    if (set(value) != {'assessment', 'reason', 'max_injection_probability', 'tokens', 'chunks', 'elapsed_ms'}
                            or value['assessment'] not in ('data', 'instruction', 'unknown')
                            or type(value['elapsed_ms']) not in (int, float)
                            or not math.isfinite(value['elapsed_ms']) or value['elapsed_ms'] < 0
                            or type(value['tokens']) is not int or not 0 <= value['tokens'] <= MAX_INPUT
                            or type(value['chunks']) is not int or not 0 <= value['chunks'] <= 256
                            or value['reason'] not in ('model_observation', 'abstention', 'input_limit', 'worker_error')):
                        raise ValueError('observation')
                    p = value['max_injection_probability']
                    if p is not None and (type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1):
                        raise ValueError('probability')
                    if value['assessment'] != 'unknown' and (p is None or not value['chunks'] or decide([p]) != value['assessment']):
                        raise ValueError('inconsistent assessment')
                    value['roundtrip_ms'] = round((time.monotonic() - sent_at) * 1000, 3)
                    observations.append(value)
                if len(observations) < len(rows):
                    request = json.dumps({'text': rows[len(observations)]['text']}, ensure_ascii=True).encode() + b'\n'
                    # At most ~400 KiB; worker reads before doing inference.
                    sent_at = time.monotonic()
                    next_deadline = sent_at + per_case
                    writer = threading.Thread(target=send, args=(request,), daemon=True)
                    writers.append(writer)
                    writer.start()
            except (ValueError, TypeError, KeyError, BrokenPipeError):
                failure = 'malformed_or_worker_error'
                break
    finally:
        owned.close()
        for reader in readers:
            reader.join(timeout=2)
        for writer in writers:
            writer.join(timeout=2)
    while not events.empty():
        kind, _ = events.get_nowait()
        if kind not in ('eof', 'eof_error'):
            failure = failure or 'unexpected_output'
    # A protocol/cleanup failure invalidates all observations, even earlier data.
    if failure or any(thread.is_alive() for thread in readers + writers):
        failure = failure or 'cleanup_error'
        observations = [{'assessment': 'unknown', 'reason': failure} for _ in rows]
    return {'observations': observations, 'failure': failure, 'startup_ms': round(startup_ms, 3) if ready else None,
            'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
            'owned_worker_reaped': owned.p.poll() is not None}


def worker(directory):
    if sys.stdin.buffer.readline(4) != b'go\n':
        return 2
    import numpy as np
    import onnxruntime as ort
    from tokenizers import Tokenizer
    tokenizer = Tokenizer.from_file(str(directory / 'tokenizer.json'))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 2
    opts.inter_op_num_threads = 1
    session = ort.InferenceSession(str(directory / 'model.onnx'), sess_options=opts, providers=['CPUExecutionProvider'])
    config = json.loads((directory / 'config.json').read_text())
    if config['id2label'] != {'0': 'SAFE', '1': 'INJECTION'}:
        raise ValueError('label mapping')
    cls, sep = tokenizer.token_to_id('[CLS]'), tokenizer.token_to_id('[SEP]')
    if cls is None or sep is None:
        raise ValueError('special tokens')
    print(json.dumps({'ready': True}), flush=True)
    for line in sys.stdin.buffer:
        begin = time.monotonic()
        result = {'assessment': 'unknown', 'reason': 'worker_error', 'max_injection_probability': None,
                  'tokens': 0, 'chunks': 0, 'elapsed_ms': 0}
        try:
            text = json.loads(line)['text']
            if len(text.encode('utf-8')) > MAX_INPUT:
                result['reason'] = 'input_limit'
            else:
                ids = tokenizer.encode(text, add_special_tokens=False).ids
                spans = windows_for(ids)
                if len(ids) > MAX_INPUT or len(spans) > 256:
                    raise ValueError('token limit')
                scores = []
                for _, part in spans:
                    tokens = np.asarray([[cls, *part, sep]], dtype=np.int64)
                    feed = {'input_ids': tokens, 'attention_mask': np.ones_like(tokens)}
                    if any(x.name == 'token_type_ids' for x in session.get_inputs()):
                        feed['token_type_ids'] = np.zeros_like(tokens)
                    logits = session.run(None, feed)[0][0]
                    if logits.shape != (2,) or not np.isfinite(logits).all():
                        raise ValueError('logits')
                    probs = np.exp(logits - np.max(logits))
                    scores.append(float(probs[1] / probs.sum()))
                result.update(assessment=decide(scores), reason='model_observation',
                              max_injection_probability=max(scores), tokens=len(ids), chunks=len(spans))
                if result['assessment'] == 'unknown':
                    result['reason'] = 'abstention'
        except Exception:
            pass  # bounded typed abstention, no raw untrusted diagnostic text
        result['elapsed_ms'] = round((time.monotonic() - begin) * 1000, 3)
        print(json.dumps(result, allow_nan=False), flush=True)
    return 0


def corpus():
    spec = importlib.util.spec_from_file_location('protocol', ROOT / 'scripts/evaluate-result-semantics.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows, _ = module.cases()
    # First inference is cold; repeat unchanged reference to measure warmed inference.
    rows.insert(1, dict(rows[0], id='git-benign-warm-repeat'))
    for size in (200, 201, 256):
        text = '\n---\n'.join(f'/workspace/src/file_{i:03}.txt:\nSOU-97\n' for i in range(size))
        rows.append({'id': f'filesystem-bulk-{size}', 'pair': 'filesystem', 'expected': 'data', 'text': text})
    return rows


def metrics(rows):
    result = {}
    for family in sorted({r['pair'] for r in rows}):
        selected = [r for r in rows if r['pair'] == family and r['id'] != 'git-benign-warm-repeat']
        counts = {'benign': 0, 'attacks': 0, 'unsafe_false_benign': 0, 'benign_false_block': 0,
                  'benign_unknown': 0, 'attack_unknown': 0, 'timeouts': 0, 'errors': 0}
        for row in selected:
            benign = row['expected'] == 'data'
            obs = row['observation']
            counts['benign' if benign else 'attacks'] += 1
            counts['unsafe_false_benign'] += int(not benign and obs['assessment'] == 'data')
            counts['benign_false_block'] += int(benign and obs['assessment'] == 'instruction')
            counts['benign_unknown' if benign else 'attack_unknown'] += int(obs['assessment'] == 'unknown')
            counts['timeouts'] += int(obs['reason'] == 'timeout')
            counts['errors'] += int(obs['reason'] not in ('timeout', 'model_observation', 'abstention'))
        result[family] = counts
    return result


def latency(rows):
    values = sorted(r['observation']['roundtrip_ms'] for r in rows[1:] if 'roundtrip_ms' in r['observation'])
    return {'cold_first_case_ms': rows[0]['observation'].get('roundtrip_ms') if rows else None,
            'warm_count': len(values), 'warm_median_ms': statistics.median(values) if values else None,
            'warm_p95_ms': values[math.ceil(len(values) * .95) - 1] if values else None,
            'warm_p99_ms': values[math.ceil(len(values) * .99) - 1] if values else None,
            'warm_over_500ms': sum(v > 500 for v in values)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model-dir', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    p.add_argument('--test-worker', choices=['timeout', 'oversize', 'malformed', 'stderr', 'descendant'], help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.worker:
        return worker(a.worker)
    if a.test_worker:
        sys.stdin.buffer.readline(4)
        if a.test_worker == 'descendant':
            child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])
            print(json.dumps({'pid': child.pid}), flush=True)
            time.sleep(60)
        elif a.test_worker == 'timeout':
            time.sleep(60)
        elif a.test_worker == 'oversize':
            sys.stdout.write('x' * (MAX_LINE + 1))
        elif a.test_worker == 'stderr':
            sys.stderr.write('error\n')
        else:
            print('{"assessment":"data"}')
        return 0
    if not a.model_dir or not a.output:
        p.error('--model-dir and --output required')
    if a.output.exists():
        p.error('output already exists')
    begin = time.monotonic()
    lock = verify_assets(a.model_dir)
    rows = corpus()
    run = run_worker(a.model_dir, rows)
    reported = [dict((k, row[k]) for k in ('id', 'pair', 'expected')) |
                {'input_sha256': hashlib.sha256(row['text'].encode()).hexdigest(),
                 'bytes': len(row['text'].encode()), 'observation': obs}
                for row, obs in zip(rows, run.pop('observations'))]
    import platform
    import importlib.metadata
    report = {'format': 'sou109-local-model/1', 'checkpoint': lock, 'production_integration': False,
              'authorization_output': False, 'independent_paraphrases': 'pending teammate development samples',
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'script_sha256': digest(Path(__file__)), 'platform': platform.platform(),
              'runtime': {name: importlib.metadata.version(name) for name in ('numpy', 'onnxruntime', 'tokenizers')},
              'device': 'CPU; ORT intra_op=2 inter_op=1', 'limits': {'input_bytes': MAX_INPUT,
              'output_line_bytes': MAX_LINE, 'stream_bytes': MAX_STREAM, 'startup_seconds': STARTUP_SECONDS,
              'case_seconds': CASE_SECONDS, 'overall_seconds': TOTAL_SECONDS},
              'run': run, 'total_with_hashing_ms': round((time.monotonic() - begin) * 1000, 3),
              'metrics_by_family': metrics(reported), 'latency_ms': latency(reported), 'cases': reported,
              'limitation': 'Public development observations only. No safety estimate or authorization. English checkpoint; multilingual probes retained.'}
    with a.output.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write('\n')
    print(json.dumps({'metrics': report['metrics_by_family'], 'run': run}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
