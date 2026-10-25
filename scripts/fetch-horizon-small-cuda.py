# SPDX-License-Identifier: Apache-2.0
"""Download only reviewed inert model assets at one immutable HF revision."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

REPO = 'Horizon-Labs/prompt-injection-guard-small'
REVISION = '0e3774536debbcd71dbb8534ef71451b583853b8'
FILES = ['README.md', 'config.json', 'tokenizer.json', 'tokenizer_config.json',
         'special_tokens_map.json', 'model.safetensors']


def fetch(output):
    output.mkdir(parents=True, exist_ok=False)
    url = f'https://huggingface.co/api/models/{REPO}/revision/{REVISION}?blobs=true'
    metadata = json.load(urllib.request.urlopen(url, timeout=60))
    assert metadata['sha'] == REVISION and metadata['cardData']['license'] == 'apache-2.0'
    (output/'hf-metadata.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf-8')
    index = {r['rfilename']: r for r in metadata['siblings']}
    lock = {'repo': REPO, 'revision': REVISION, 'license': 'apache-2.0', 'files': {}}
    for name in FILES:
        path = output/name
        with urllib.request.urlopen(f'https://huggingface.co/{REPO}/resolve/{REVISION}/{name}', timeout=120) as src, path.open('wb') as dst:
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
    fetch(parser.parse_args().output)
