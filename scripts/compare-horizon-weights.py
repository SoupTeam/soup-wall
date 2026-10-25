# SPDX-License-Identifier: Apache-2.0
import argparse,hashlib,json
from pathlib import Path
import numpy as np
import onnx
from onnx import numpy_helper
from safetensors.numpy import load_file
parser=argparse.ArgumentParser()
parser.add_argument('--assets',type=Path,required=True)
args=parser.parse_args()
p=args.assets
native=load_file(p/'model.safetensors')
index={}
for name,a in native.items():
    for transform,b in [('direct',a),('transpose',a.T)] if a.ndim==2 else [('direct',a)]:
        key=(b.shape,hashlib.sha256(b.tobytes()).hexdigest())
        index.setdefault(key,[]).append([name,transform])
model=onnx.load(p/'onnx/model.onnx')
matched=[];unmatched=[];covered=set()
for t in model.graph.initializer:
    a=numpy_helper.to_array(t);key=(a.shape,hashlib.sha256(a.tobytes()).hexdigest())
    hits=index.get(key,[])
    if hits:
        matched.append({'onnx':t.name,'native':hits,'shape':a.shape})
        covered.update(x[0] for x in hits)
    else:unmatched.append({'name':t.name,'shape':a.shape,'dtype':str(a.dtype)})
out={'matched':matched,'unmatched_onnx':unmatched,'unmatched_native':[n for n in native if n not in covered],
     'native_count':len(native),'onnx_initializer_count':len(model.graph.initializer)}
(p.parent/'sou109-sdpa-weight-comparison.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items() if k!='matched'}))
