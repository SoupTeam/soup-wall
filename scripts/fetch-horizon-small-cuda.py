# SPDX-License-Identifier: Apache-2.0
"""Download only reviewed inert model assets at one immutable HF revision."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import urllib.request

REPO = 'Horizon-Labs/prompt-injection-guard-small'
REVISION = '0e3774536debbcd71dbb8534ef71451b583853b8'
FILES = ['README.md', 'config.json', 'tokenizer.json', 'tokenizer_config.json',
         'special_tokens_map.json', 'model.safetensors']


def finish_ranges(path, url, total):
    start = path.stat().st_size
    assert 0 < start < total
    step = 16*1024*1024
    ranges = [(i,min(i+step,total)-1) for i in range(start,total,step)]
    def download(pair):
        a,b = pair
        part = path.with_name(path.name+f'.range-{a}-{b}')
        req = urllib.request.Request(url,headers={'Range':f'bytes={a}-{b}'})
        with urllib.request.urlopen(req,timeout=120) as src, part.open('wb') as dst:
            assert src.status == 206 and src.headers['Content-Range'] == f'bytes {a}-{b}/{total}'
            while chunk := src.read(1024*1024):
                dst.write(chunk)
        assert part.stat().st_size == b-a+1
        print('verified HTTP range',a,b,flush=True)
        return part
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        parts = list(pool.map(download,ranges))
    with path.open('ab') as dst:
        for part in parts:
            with part.open('rb') as src:
                while chunk := src.read(1024*1024):dst.write(chunk)


def fetch(output, resume=False):
    output.mkdir(parents=True, exist_ok=resume)
    url = f'https://huggingface.co/api/models/{REPO}/revision/{REVISION}?blobs=true'
    metadata = json.load(urllib.request.urlopen(url, timeout=60))
    assert metadata['sha'] == REVISION and metadata['cardData']['license'] == 'apache-2.0'
    (output/'hf-metadata.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf-8')
    index = {r['rfilename']: r for r in metadata['siblings']}
    lock = {'repo': REPO, 'revision': REVISION, 'license': 'apache-2.0', 'files': {}}
    for name in FILES:
        path = output/name
        url = f'https://huggingface.co/{REPO}/resolve/{REVISION}/{name}'
        if resume and path.exists():
            if path.stat().st_size != index[name]['size']:
                assert name == 'model.safetensors', 'only incomplete weights may resume'
                finish_ranges(path,url,index[name]['size'])
        else:
            with urllib.request.urlopen(url, timeout=120) as src, path.open('wb') as dst:
                while chunk := src.read(1024*1024):
                    dst.write(chunk)
        raw = path.read_bytes()
        entry = index[name]
        assert len(raw) == entry['size'], name
        if 'lfs' in entry:
            assert hashlib.sha256(raw).hexdigest() == entry['lfs']['sha256'], name
        else:
            assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == entry['blobId'], name
        lock['files'][name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        print(name, len(raw), lock['files'][name]['sha256'], flush=True)
    (output/'model-lock.json').write_text(json.dumps(lock, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--resume', action='store_true')
    args=parser.parse_args()
    fetch(args.output,args.resume)
