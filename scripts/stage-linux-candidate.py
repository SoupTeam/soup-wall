#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the public archive staging path on owned candidate bytes; no release/tag/publish."""
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import tarfile
import sys
import linux_candidate as candidate
import pilot_candidate
import release_docs
import publication_readiness

ROOT=Path(__file__).resolve().parents[1]

def run(args):
    args.output.mkdir(mode=0o700)
    stage=args.output/'staged';stage.mkdir(mode=0o700)
    report={'format':'sw-linux-candidate-staging/1','status':'failed','source_commit':args.expected_commit,
            'publication':'not-requested','release_admission':'not-claimed','active_protection':False}
    try:
        for name in ('agentfw','soup-wall-bench','llm-firewall'):
            shutil.copyfile(args.binaries/name,stage/name);(stage/name).chmod(0o755)
        shutil.copyfile(stage/'llm-firewall',stage/'soup-wall-gateway');(stage/'soup-wall-gateway').chmod(0o755)
        for name in (*release_docs.BASE,'README.md'):
            original='vendor/kryptering/LICENSE' if name=='third-party/kryptering/LICENSE' else name
            target=stage/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/original,target);target.chmod(0o644)
        custody=candidate.stage(ROOT,stage,args.binaries,args.expected_commit)
        release_docs.stage(ROOT,stage,args.expected_commit,candidate.TARGET)
        name='soup-wall-v0.0.0-sou236-'+candidate.TARGET
        archive=args.output/(name+'.tar.gz')
        with archive.open('xb') as stream,gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.USTAR_FORMAT) as package:
                for path in sorted(stage.rglob('*')):
                    if path.is_file():
                        info=package.gettarinfo(path,arcname=name+'/'+path.relative_to(stage).as_posix())
                        info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
                        with path.open('rb') as source:package.addfile(info,source)
        checked=release_docs.check_archive(ROOT,archive,args.expected_commit,candidate.TARGET,name)
        manifest={'tag':'v0.0.0-sou236','source_sha':args.expected_commit,
                  'checksums':[pilot_candidate.file_record(archive)['sha256']+'  '+archive.name]}
        manifest_path=args.output/'candidate-manifest.json';manifest_path.write_bytes(candidate.canonical(manifest))
        publication_readiness.linux_binary(args.output,manifest_path,candidate.sha(manifest_path.read_bytes()),
                                           custody['binaries']['agentfw']['sha256'],args.expected_commit)
        extracted=args.output/'extracted';extracted.mkdir(mode=0o700)
        # Prior shared bounds/link/inventory checks have already validated every
        # entry. Extract with the standard data filter into our fresh directory.
        with tarfile.open(archive,'r:gz') as package:package.extractall(extracted,filter='data')
        pilot_candidate.validate_directory(extracted/name,args.expected_commit)
        report.update(status='passed',custody=custody,archive_sha256=checked['archive_sha256'],
                      archive_inventory='verified',publication_readiness_archive_binding='verified',
                      extracted_directory=str(extracted/name))
    finally:
        (args.output/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    return 0

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries',type=Path,required=True)
    parser.add_argument('--expected-commit',required=True)
    parser.add_argument('--output',type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
