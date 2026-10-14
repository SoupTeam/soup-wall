# SPDX-License-Identifier: Apache-2.0
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

MATERIAL_LIMIT = 65536


class RotationError(RuntimeError):
    pass


def private_bytes(path, limit=MATERIAL_LIMIT):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise RotationError("material must be a private regular file owned by the operator")
        data = handle.read(limit + 1)
    if not data or len(data) > limit:
        raise RotationError("material is empty or exceeds 64 KiB")
    return data


def atomic_write(path, data):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=".tls-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def command(args, label):
    try:
        result = subprocess.run([str(part) for part in args], capture_output=True, timeout=15)
    except subprocess.TimeoutExpired as error:
        raise RotationError(f"{label} timed out") from error
    if result.returncode:
        raise RotationError(f"{label} failed (exit {result.returncode})")
    return result.stdout


def fingerprint(cert):
    der = command(["openssl", "x509", "-in", cert, "-outform", "DER"], "certificate parsing")
    return hashlib.sha256(der).hexdigest()


def validate_material(cert, key, ca):
    for path in (cert, key, ca):
        private_bytes(path)
    command(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", "localhost",
             "-CAfile", ca, cert], "certificate trust, hostname and validity check")
    cert_public = command(["openssl", "x509", "-in", cert, "-pubkey", "-noout"], "certificate public key")
    key_public = command(["openssl", "pkey", "-in", key, "-pubout"], "private key parsing")
    if cert_public != key_public:
        raise RotationError("certificate and private key do not match")
    return fingerprint(cert)


class Edge:
    def __init__(self, root, ca, template):
        self.root = Path(root)
        self.ca = Path(ca)
        self.template = Path(template)
        self.config = self.root / "Caddyfile"
        self.journal = self.root / "pending.json"
        self.good = self.root / "last-good.json"
        self.root.mkdir(mode=0o700, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RotationError("edge directory must be private and owned by the operator")

    @contextmanager
    def locked(self):
        descriptor = os.open(self.root / "rotation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError as error:
            raise RotationError("another rotation is in progress") from error
        finally:
            os.close(descriptor)

    def stage(self, cert, key):
        directory = Path(tempfile.mkdtemp(prefix="version-", dir=self.root))
        try:
            for source, name in ((cert, "cert.pem"), (key, "key.pem")):
                atomic_write(directory / name, private_bytes(source))
            expected = validate_material(directory / "cert.pem", directory / "key.pem", self.ca)
            config = self.template.read_text().replace("{$TLS_CERTIFICATE}", str(directory / "cert.pem"))
            config = config.replace("{$TLS_PRIVATE_KEY}", str(directory / "key.pem"))
            atomic_write(directory / "Caddyfile", config.encode())
            command(["caddy", "validate", "--config", directory / "Caddyfile", "--adapter", "caddyfile"],
                    "Caddy candidate validation")
            return {"config": config, "fingerprint_sha256": expected}
        except BaseException:
            shutil.rmtree(directory)
            raise

    def initialize(self, cert, key):
        with self.locked():
            if self.config.exists() or self.good.exists() or self.journal.exists():
                raise RotationError("edge is already initialized")
            candidate = self.stage(cert, key)
            atomic_write(self.config, candidate["config"].encode())
            atomic_write(self.good, json.dumps(candidate).encode())
            return candidate

    def reload(self):
        command(["caddy", "reload", "--force", "--config", self.config, "--adapter", "caddyfile"],
                "Caddy reload")

    def witness(self, expected):
        client = Path(__file__).with_name("tls_client.py")
        result = command([sys.executable, client, "--ca", self.ca], "independent HTTPS confirmation")
        row = json.loads(result)
        if not row["verified"] or row["http_status"] != 200 or row["fingerprint_sha256"] != expected:
            raise RotationError("served certificate or HTTPS health response differs from the candidate")
        return row

    def restore(self, previous):
        atomic_write(self.good, json.dumps(previous).encode())
        atomic_write(self.config, previous["config"].encode())
        self.reload()
        witness = self.witness(previous["fingerprint_sha256"])
        self.journal.unlink()
        return witness

    def rotate(self, cert, key):
        with self.locked():
            if self.journal.exists():
                raise RotationError("pending rotation requires recovery")
            previous = json.loads(private_bytes(self.good))
            if private_bytes(self.config).decode() != previous["config"]:
                raise RotationError("active configuration differs from the committed configuration")
            candidate = self.stage(cert, key)
            atomic_write(self.journal, json.dumps({"previous": previous, "candidate": candidate}).encode())
            try:
                atomic_write(self.config, candidate["config"].encode())
                self.reload()
                witness = self.witness(candidate["fingerprint_sha256"])
                atomic_write(self.good, json.dumps(candidate).encode())
                self.journal.unlink()
                return witness
            except Exception as error:
                try:
                    self.restore(previous)
                except Exception as recovery:
                    raise RotationError(f"rotation failed; recovery required: {recovery}") from error
                raise RotationError("rotation failed; previous certificate restored and verified") from error

    def recover(self):
        with self.locked():
            if self.journal.exists():
                previous = json.loads(private_bytes(self.journal))["previous"]
                return self.restore(previous)
            previous = json.loads(private_bytes(self.good))
            atomic_write(self.config, previous["config"].encode())
            self.reload()
            return self.witness(previous["fingerprint_sha256"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["initialize", "rotate", "recover"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args()
    try:
        edge = Edge(args.root, args.ca, args.template)
        if args.action in {"rotate", "initialize"}:
            if not args.cert or not args.key:
                parser.error("--cert and --key are required")
            result = getattr(edge, args.action)(args.cert, args.key)
        else:
            result = edge.recover()
        print(json.dumps({"status": "passed", "result": result}, sort_keys=True))
        return 0
    except (RotationError, OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "diagnostic": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
