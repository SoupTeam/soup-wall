#!/usr/bin/env python3
"""One reproducible model-free native component dev replay, never live-host qualification."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];EVIDENCE=ROOT/'docs/operations/evidence/sou109-structural-attribution'
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--cargo',default=shutil.which('cargo') or 'cargo');args=p.parse_args()
 manifest=json.loads((EVIDENCE/'dev-manifest.json').read_bytes());source=EVIDENCE/'dev-input.json'
 assert sha(source.read_bytes())==manifest['input_sha256']
 for path,digest in manifest['fixed_files'].items():assert sha((ROOT/path).read_bytes().replace(b'\r\n',b'\n'))==digest,path
 out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 env=os.environ|{'SOU109_STRUCTURAL_DEV_INPUT':str(source),'SOU109_STRUCTURAL_DEV_OUTPUT':str(out/'native-results.json')}
 command=[args.cargo,'test','-p','agentfw','--lib','--no-default-features','native::tests::result_evidence_tests::public_dev_replay','--','--ignored','--exact','--nocapture']
 run=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=300)
 (out/'test.log').write_text(run.stdout+run.stderr);assert run.returncode==0,run.stdout+run.stderr
 report=json.loads((out/'native-results.json').read_bytes());rows=report['cases'];assert len(rows)==manifest['case_count']
 evaluated=[r for r in rows if r['status']=='evaluated'];attacks=[r for r in evaluated if r['expected']=='instruction'];benign=[r for r in evaluated if r['expected']=='data'];unsupported=[r for r in rows if r['status']=='unsupported']
 summary={'evaluated_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'input_sha256':manifest['input_sha256'],'total':len(rows),'evaluated':len(evaluated),'attacks_evaluated':len(attacks),'attacks_missed':sum(r['release'] for r in attacks),'benign_total':manifest['expected_benign'],'benign_supported_evaluated':len(benign),'benign_released':sum(r['release'] for r in benign),'remaining_false_refusals':[r['id'] for r in benign if not r['release']],'unsupported_not_success':[r['id'] for r in unsupported],'model_calls':0,'live_runtime_qualification':False,'SOU109_complete':False}
 assert summary['attacks_missed']==0
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
