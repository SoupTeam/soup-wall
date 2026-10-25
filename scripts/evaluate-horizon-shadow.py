#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One pinned local encoder screen. No production authority, no truncated inputs."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import queue
import statistics
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owned', Path(__file__).with_name('evaluate-local-result-model.py'))
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)
REQUEST_SHA = '80827223a50d1e605de60536b0713c134671f9e4ea92fc55d1360c3717babc56'
REFERENCE_SHA = '7ed6c65b99f440d2597dd53aa70b1d5f6788b4d89ad88dc7c85e10c66a03e2a1'
CONTEXT = 8192
BUDGET = 10


def envelope(channels):
    text, spans = '', []
    for i, channel in enumerate(channels):
        text += f'[untrusted channel c{i}; utf8_bytes={len(channel.encode("utf-8"))}]\n'
        start = len(text)
        text += channel
        spans.append({'channel': i, 'start_char': start, 'end_char': len(text),
                      'source_start_byte': 0, 'source_end_byte': len(channel.encode('utf-8'))})
        text += f'\n[end channel c{i}]\n'
    return text, spans


def assessment(logits):
    if len(logits) != 2 or any(not math.isfinite(x) for x in logits):
        raise ValueError('invalid binary logits')
    values = [math.exp(x - max(logits)) for x in logits]
    score = values[1] / sum(values)
    return ('instruction' if score >= .5 else 'data'), score


def infer(session, tokenizer, channels):
    import numpy as np
    begun = time.monotonic()
    text, spans = envelope(channels)
    encoded = tokenizer.encode(text, add_special_tokens=True)
    count = len(encoded.ids)
    base = {'tokens': count, 'input_envelope_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
            'source_spans': spans, 'windowed': False, 'global_context_unproven': count > CONTEXT}
    if count > CONTEXT:
        return dict(base, assessment='unknown', reason='unsupported_full_context', coverage_complete=False,
                    score=None, logits=None, elapsed_ms=(time.monotonic()-begun)*1000)
    feed = {'input_ids': np.asarray([encoded.ids], dtype=np.int64),
            'attention_mask': np.asarray([encoded.attention_mask], dtype=np.int64)}
    names = {x.name for x in session.get_inputs()}
    if not names.issubset(feed): raise ValueError('unsupported model inputs')
    outputs = session.run(None, {k:v for k,v in feed.items() if k in names})
    logits = np.asarray(outputs[0])
    if logits.shape != (1, 2): raise ValueError('unexpected logits shape')
    raw = logits[0].astype(float).tolist()
    label, score = assessment(raw)
    return dict(base, assessment=label, reason='full_classifier_pass', coverage_complete=True,
                token_range=[0,count], offsets=[list(x) for x in encoded.offsets],
                score=score, logits=raw, elapsed_ms=(time.monotonic()-begun)*1000)


def worker(assets):
    if sys.stdin.buffer.readline() != b'go\n': return
    import numpy
    import onnxruntime as ort
    import tokenizers
    lock = json.loads((ROOT/'scripts/horizon-model-lock.json').read_text(encoding='utf-8'))
    if lock['runtime'] != {'onnxruntime':ort.__version__, 'tokenizers':tokenizers.__version__, 'numpy':numpy.__version__}:
        raise ValueError('runtime version mismatch')
    tokenizer = tokenizers.Tokenizer.from_file(str(assets/'tokenizer.json'))
    tokenizer.no_truncation(); tokenizer.no_padding()
    options = ort.SessionOptions(); options.intra_op_num_threads=6; options.inter_op_num_threads=1
    options.execution_mode=ort.ExecutionMode.ORT_SEQUENTIAL
    options.log_severity_level=3
    session=ort.InferenceSession(str(assets/'onnx/model.onnx'), options, providers=['CPUExecutionProvider'])
    # Fixed synthetic warm-up, never a benchmark case; included in startup time.
    infer(session, tokenizer, ['Warm-up: ordinary sample text.'])
    print(json.dumps({'ready':True,'providers':session.get_providers()}),flush=True)
    for line in sys.stdin.buffer:
        try:
            request=json.loads(line)
            result=infer(session,tokenizer,request['channels'])
        except Exception as error:
            result={'assessment':'unknown','reason':'worker_error','error':type(error).__name__+': '+str(error),
                    'score':None,'coverage_complete':False}
        print(json.dumps(result,ensure_ascii=True,allow_nan=False),flush=True)


def rss(process):
    if os.name != 'nt': return None
    from ctypes import wintypes as w
    class Counters(ctypes.Structure):
        _fields_=[('cb',w.DWORD),('faults',w.DWORD)]+[(n,ctypes.c_size_t) for n in
          ('peak_rss','rss','peak_pool','pool','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
    value=Counters(); value.cb=ctypes.sizeof(value)
    call=ctypes.WinDLL('psapi').GetProcessMemoryInfo
    call.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD]
    if call(w.HANDLE(int(process._handle)),ctypes.byref(value),value.cb):
        return {'rss_bytes':value.rss,'process_peak_rss_bytes':value.peak_rss}
    return None


class Worker:
    def __init__(self,assets,test=False):
        self.events=queue.Queue(maxsize=4)
        self.owned=owned.OwnedProcess(['--hang-worker'] if test else ['--worker',str(assets)],worker_script=__file__)
        self.stderr=[]
        def reader():
            try:
                while True:
                    line=self.owned.p.stdout.readline(1000001)
                    if not line: break
                    if len(line)>1000000: self.events.put(('error','output_limit'));return
                    self.events.put(('line',line))
            finally:
                self.owned.p.stdout.close()
        def errors():
            self.stderr.append(self.owned.p.stderr.read(8192));self.owned.p.stderr.close()
        self.readers=[threading.Thread(target=reader,daemon=True),threading.Thread(target=errors,daemon=True)]
        for t in self.readers:t.start()
        self.owned.p.stdin.write(b'go\n');self.owned.p.stdin.flush()
    def receive(self,seconds):
        start=time.monotonic();peak=0;last=None
        while time.monotonic()-start<seconds:
            last=rss(self.owned.p)
            if last:peak=max(peak,last['process_peak_rss_bytes'])
            try:kind,raw=self.events.get(timeout=min(.02,max(.001,seconds-(time.monotonic()-start))))
            except queue.Empty:
                if self.owned.p.poll() is not None:raise RuntimeError('worker exited')
                continue
            if kind!='line':raise ValueError(raw)
            return json.loads(raw),{'process_peak_rss_bytes':peak,'last_sample':last}
        raise TimeoutError('hard per-input deadline')
    def close(self):
        self.owned.close()
        for t in self.readers:t.join(timeout=2)
        if any(t.is_alive() for t in self.readers):raise RuntimeError('reader cleanup failed')


def persist(path,value):
    with path.open('a',encoding='utf-8') as f:
        f.write(json.dumps(value,ensure_ascii=True,allow_nan=False)+'\n');f.flush();os.fsync(f.fileno())


def main(args):
    lock=json.loads((ROOT/'scripts/horizon-model-lock.json').read_text(encoding='utf-8'))
    if lock['revision']!='70b65c51c03f7d9b5d1f18726defee45f3936610':raise ValueError('revision mismatch')
    for name,info in lock['files'].items():
        if owned.digest(args.assets/name)!=info['sha256']:raise ValueError('asset hash mismatch: '+name)
    for name,sha in [('requests.jsonl',REQUEST_SHA),('references.jsonl',REFERENCE_SHA)]:
        if owned.digest(args.prepared/name)!=sha:raise ValueError('input hash mismatch')
    rows=[json.loads(x) for x in (args.prepared/'requests.jsonl').read_text(encoding='utf-8').splitlines()]
    if len(rows)!=58 or len({r['request_id'] for r in rows})!=58:raise ValueError('case identity')
    args.output.mkdir(exist_ok=False,parents=True)
    identity={'assets':lock,'request_sha256':REQUEST_SHA,'reference_sha256':REFERENCE_SHA,
              'threshold':.5,'context':CONTEXT,'per_input_seconds':BUDGET,'threads':6,'windowing':False,
              'envelope':'ordered raw channels with cN and utf8 length header and end marker; no task or expected labels',
              'source_script_sha256':owned.digest(Path(__file__)), 'ownership_script_sha256':owned.digest(Path(owned.__file__)),
              'production_authority':False,'restart_policy':'after killed timeout, next case only; never retry an input',
              'startup_budget_seconds':120,'warmup':'Warm-up: ordinary sample text.'}
    (args.output/'identity.json').write_text(json.dumps(identity,indent=2)+'\n',encoding='utf-8')
    current=None;observations=[];begun=time.monotonic()
    try:
        for row in rows:
            if current is None:
                started=time.monotonic();current=Worker(args.assets)
                try:
                    ready,memory=current.receive(120)
                    if ready!={'ready':True,'providers':['CPUExecutionProvider']}:raise ValueError('invalid readiness')
                except BaseException:
                    current.close();current=None;raise
                persist(args.output/'startups.jsonl',{'elapsed_ms':(time.monotonic()-started)*1000,'memory':memory})
            request=json.dumps({'channels':row['input']['untrusted_text_channels']},ensure_ascii=True).encode()+b'\n'
            persist(args.output/'journal.jsonl',{'request_id':row['request_id'],'state':'started'})
            started=time.monotonic();write_errors=[]
            def send():
                try:current.owned.p.stdin.write(request);current.owned.p.stdin.flush()
                except Exception as error:write_errors.append(type(error).__name__)
            writer=threading.Thread(target=send,daemon=True);writer.start()
            try:
                result,memory=current.receive(max(.001,BUDGET-(time.monotonic()-started)))
                if write_errors:raise RuntimeError('write error')
                if time.monotonic()-started>BUDGET:raise TimeoutError('deadline elapsed')
                result['memory']=memory
            except (TimeoutError,RuntimeError,ValueError) as error:
                memory=rss(current.owned.p)
                current.close();current=None
                result={'assessment':'unknown','reason':'timeout' if isinstance(error,TimeoutError) else 'worker_failure',
                        'error':str(error),'coverage_complete':False,'score':None,'memory_at_failure':memory}
            writer.join(timeout=2)
            if writer.is_alive():raise RuntimeError('writer cleanup failed')
            result.update(request_id=row['request_id'],input_sha256=row['input_sha256'],roundtrip_ms=(time.monotonic()-started)*1000)
            persist(args.output/'observations.jsonl',result);observations.append(result)
            persist(args.output/'journal.jsonl',{'request_id':row['request_id'],'state':'completed'})
            print(row['request_id'],result['assessment'],result['reason'],round(result['roundtrip_ms']),flush=True)
    finally:
        if current:current.close()
        (args.output/'summary.json').write_text(json.dumps({'complete':len(observations)==58,'observations':len(observations),
            'elapsed_seconds':time.monotonic()-begun,'production_authority':False},indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--worker':worker(Path(sys.argv[2]))
    elif len(sys.argv)>1 and sys.argv[1]=='--hang-worker':
        sys.stdin.buffer.readline();time.sleep(600)
    else:
        parser=argparse.ArgumentParser(description=__doc__)
        for name in ('assets','prepared','output'):parser.add_argument('--'+name,type=Path,required=True)
        main(parser.parse_args())
