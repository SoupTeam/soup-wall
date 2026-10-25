#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild inert base safetensors from pinned ONNX and previously verified map.

No graph execution, external tensor reads, random parameters or model inference.
Container identity is explicitly derived, not asserted equal to native HF bytes.
"""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import resource
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REF = 'fa5b91e738644936ec8e378cd8e6aa1d81f527d6'
ORIGINAL_NATIVE = 'd0c0f899f118481855cfe34ba718cf5e44613d266270721c380d54741626d405'


def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def blob(path):
    return subprocess.check_output(['git','-C',str(ROOT),'show',REF+':'+path])


def main(args):
    import numpy as np
    import onnx
    from onnx import numpy_helper
    from safetensors import safe_open
    from safetensors.numpy import save_file
    begun = time.monotonic()
    old_lock_raw = blob('scripts/horizon-model-lock.json')
    old_lock = json.loads(old_lock_raw)
    mapping_raw = blob('docs/operations/evidence/sou109-sdpa-targeted.json')
    mapping = json.loads(mapping_raw)['weights']
    assert mapping['native_count'] == mapping['onnx_initializer_count'] == len(mapping['matched']) == 138
    assert not mapping['unmatched_native'] and not mapping['unmatched_onnx']
    assert all(len(m['native']) == 1 for m in mapping['matched'])
    source = args.assets/'onnx/model.onnx'
    assert digest(source) == old_lock['files']['onnx/model.onnx']['sha256']
    args.output.mkdir(parents=True,exist_ok=False)
    lock = {k:old_lock[k] for k in ('repo','revision','license')}
    lock['files'] = {}
    for name,entry in old_lock['files'].items():
        if name == 'onnx/model.onnx':continue
        raw = (args.assets/name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry['sha256']
        (args.output/name).write_bytes(raw)
        lock['files'][name] = entry
    graph = onnx.load_model(str(source),load_external_data=False)
    initializers = {t.name:t for t in graph.graph.initializer}
    assert len(initializers) == 138 and set(initializers) == {m['onnx'] for m in mapping['matched']}
    arrays, records = {}, []
    for match in mapping['matched']:
        tensor = initializers[match['onnx']]
        assert not tensor.external_data and tensor.data_location != onnx.TensorProto.EXTERNAL
        original = numpy_helper.to_array(tensor)
        assert list(original.shape) == match['shape'] and original.dtype == np.float32
        name,transform = match['native'][0]
        assert name not in arrays and transform in ('direct','transpose')
        if transform == 'transpose':assert original.ndim == 2
        native = np.ascontiguousarray(original.T if transform == 'transpose' else original)
        restored = np.ascontiguousarray(native.T if transform == 'transpose' else native)
        source_sha = hashlib.sha256(memoryview(original).cast('B')).hexdigest()
        assert hashlib.sha256(memoryview(restored).cast('B')).hexdigest() == source_sha
        arrays[name] = native
        records.append({'native':name,'onnx':tensor.name,'transform':transform,'dtype':str(native.dtype),
            'shape':list(native.shape),'onnx_shape':list(original.shape),'onnx_array_sha256':source_sha,
            'native_array_sha256':hashlib.sha256(memoryview(native).cast('B')).hexdigest()})
    assert len(arrays) == 138
    destination = args.output/'model.safetensors'
    save_file(arrays,str(destination),metadata={'format':'pt'})
    with safe_open(str(destination),framework='numpy') as saved:
        assert set(saved.keys()) == set(arrays)
        for record in records:
            value = saved.get_tensor(record['native'])
            assert list(value.shape) == record['shape'] and value.dtype == np.float32
            assert hashlib.sha256(memoryview(value).cast('B')).hexdigest() == record['native_array_sha256']
    derived_sha = digest(destination)
    lock['files']['model.safetensors'] = {'sha256':derived_sha,'bytes':destination.stat().st_size}
    lock['derived_artifact'] = {'original_native_container_sha256':ORIGINAL_NATIVE,
        'container_hash_matches_original':derived_sha == ORIGINAL_NATIVE,
        'source_onnx_sha256':old_lock['files']['onnx/model.onnx']['sha256'],
        'mapping_report_commit':REF,'mapping_report_sha256':hashlib.sha256(mapping_raw).hexdigest(),
        'prior_verified_mapping_sha256':hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest(),
        'derivation_script_sha256':digest(Path(__file__)),'tensor_count':138,
        'tensor_parameter_count':sum(a.size for a in arrays.values()),'no_external_data':True,
        'all_tensor_bytes_roundtrip_verified':True,'inference_performed':False}
    report = {'identity':lock['derived_artifact'],'tensors':records,'elapsed_ms':(time.monotonic()-begun)*1000,
        'actual_process_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        'runtime':{k:importlib.metadata.version(k) for k in ('onnx','numpy','safetensors','protobuf')}}
    (args.output/'model-lock.json').write_text(json.dumps(lock,indent=2)+'\n')
    (args.output/'derivation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(lock['derived_artifact'],indent=2),flush=True)
    print('DERIVED',derived_sha,destination.stat().st_size,flush=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args())
