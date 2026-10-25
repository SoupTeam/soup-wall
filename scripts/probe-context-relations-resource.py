#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fixed maximum-size integrity check, never a semantic benchmark."""
import importlib.util
import json
from pathlib import Path
import time

spec=importlib.util.spec_from_file_location('relation_checker',Path(__file__).with_name('result-context-relations.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
begun=time.monotonic()
channels=['x'*(8*1024*1024)]
proposal={'source_sha256':r.source_hash(channels),'scopes':[
    {'channel':0,'start':i*128,'end':(i+1)*128,'role':'other'} for i in range(65536)],'relations':[]}
result=r.check(channels,proposal)
assert result['coverage_complete'] and result['enforcement']=='unresolved'
try:
    r.source_hash([channels[0]+'x'])
except ValueError:
    rejected=True
else:
    rejected=False
assert rejected
print(json.dumps({'source_bytes':8*1024*1024,'scope_count':65536,
    'elapsed_ms':(time.monotonic()-begun)*1000,'integrity_result':result,
    'oversize_rejected':rejected,'semantic_efficacy_claim':False}))
