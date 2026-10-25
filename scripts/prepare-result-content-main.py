# SPDX-License-Identifier: Apache-2.0
import io, pathlib, subprocess, tarfile, hashlib, json
root=pathlib.Path(__file__).resolve().parents[1]
import argparse
parser=argparse.ArgumentParser(description='Prepare an isolated pinned-main diagnostic build; no production changes.')
parser.add_argument('--output', type=pathlib.Path, required=True)
out=parser.parse_args().output
out.mkdir(exist_ok=False)
ref='1c55ead230c8b5757035df32ded63e60ea881fae'
archive=subprocess.check_output(['git','-c','core.autocrlf=false','-C',str(root),'archive',ref])
with tarfile.open(fileobj=io.BytesIO(archive)) as tf: tf.extractall(out,filter='data')
paths=subprocess.check_output(['git','-C',str(root),'ls-tree','-r','--name-only',ref]).decode().splitlines()
identity={}
for path in paths:
    if path.endswith('.rs') or pathlib.Path(path).name in ('Cargo.toml','Cargo.lock'):
        raw=subprocess.check_output(['git','-C',str(root),'show',ref+':'+path])
        (out/path).write_bytes(raw)
        identity[path]=hashlib.sha256(raw).hexdigest()
source=subprocess.check_output(['git','-C',str(root),'show','HEAD:crates/agent/examples/result_evidence.rs']).decode()
source=source.replace('let cross = InjectionDetector::cross_block_signatures(&texts);','let cross: Vec<soup_wall_core::Finding> = Vec::new();')
source=source.replace('firewall.preview_native_mcp_result_with_evidence(&ev, &cross)','firewall.preview_native_result(&ev)')
a=source.index('    // BEGIN LEDGER:');b=source.index('    // END LEDGER',a)
source=source[:a]+source[b+len('    // END LEDGER'):]
source=source.replace('let mut result = json!', 'let result = json!')
(out/'crates/agent/examples/result_content_main.rs').write_text(source)
identity['diagnostic_example_sha256']=hashlib.sha256(source.encode()).hexdigest()
(out/'build-identity.json').write_text(json.dumps({'accepted_main':ref,'tracked_build_sources':identity,'diagnostic_transform':'no cross evidence (not present on main); preview_native_result; no ledger'},indent=2)+'\n')
print(out)
