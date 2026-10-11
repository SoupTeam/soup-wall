"""Test-only SSH key helpers (keys are generated in temporary directories and never stored in the repository)."""
import shutil
import subprocess
from pathlib import Path

from sou13cp2.anchor import NAMESPACE, key_fingerprints

SSH_KEYGEN = shutil.which('ssh-keygen')


def make_key(directory, name):
    key = Path(directory) / name
    subprocess.run([SSH_KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(key)], check=True)
    return key


def allowed_signers(directory, signer, key, filename='allowed_signers'):
    p = Path(directory) / filename
    pub = Path(str(key) + '.pub').read_text(encoding='utf-8').split()
    p.write_text(f'{signer} namespaces="{NAMESPACE}" {pub[0]} {pub[1]}\n', encoding='utf-8')
    return p


def fingerprint(signers_file):
    return key_fingerprints(signers_file)[0]


def sign(key, message_file, namespace=NAMESPACE):
    sig = Path(str(message_file) + '.sig')
    if sig.exists():
        sig.unlink()
    subprocess.run([SSH_KEYGEN, '-q', '-Y', 'sign', '-f', str(key), '-n', namespace, str(message_file)], check=True,
                   capture_output=True)
    return sig
