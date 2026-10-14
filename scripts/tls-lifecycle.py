# SPDX-License-Identifier: Apache-2.0
import argparse
from datetime import datetime, timezone
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
CADDY_IMAGE = "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
PYTHON_IMAGE = "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
RUST_IMAGE = "rust:1.99-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def execute(args, timeout=30, **kwargs):
    return subprocess.run([str(arg) for arg in args], capture_output=True, timeout=timeout, **kwargs)


def require_command(args):
    result = execute(args)
    if result.returncode:
        raise RuntimeError(f"{args[0]} returned {result.returncode}")
    return result.stdout


def write_private(path, data):
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)


def generate_ca(directory, name):
    ca = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    require_command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", key, "-out", ca, "-subj", f"/CN={name}", "-days", "30",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    ca.chmod(0o600)
    key.chmod(0o600)
    return ca, key


def generate_cert(directory, name, ca, ca_key, hostname="localhost", expired=False):
    key, csr, cert = [directory / f"{name}.{suffix}" for suffix in ("key", "csr", "pem")]
    require_command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", key, "-out", csr, "-subj", f"/CN={name}"])
    key.chmod(0o600)
    extensions = directory / f"{name}.ext"
    text = (f"subjectAltName=DNS:{hostname}\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    write_private(extensions, text)
    if expired:
        index = directory / "index.txt"
        serial = directory / "serial"
        conf = directory / "ca.conf"
        write_private(index, "")
        write_private(serial, "01\n")
        write_private(conf, f"[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={index}\n"
                      f"serial={serial}\nnew_certs_dir={directory}\ncertificate={ca}\n"
                      f"private_key={ca_key}\ndefault_md=sha256\npolicy=names\n"
                      "[names]\ncommonName=supplied\n[leaf]\n" + text)
        require_command(["openssl", "ca", "-batch", "-config", conf, "-in", csr,
                         "-out", cert, "-notext", "-extensions", "leaf",
                         "-startdate", "200101000000Z", "-enddate", "200201000000Z"])
    else:
        require_command(["openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                         "-set_serial", str(secrets.randbits(120)), "-days", "30", "-sha256",
                         "-extfile", extensions, "-out", cert])
    cert.chmod(0o600)
    return cert, key


def source_manifest():
    listing = require_command(["git", "-C", ROOT, "ls-files", "-z"]).decode().split("\0")
    inputs = {}
    for name in listing:
        if name in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"} or (
                name.startswith(("crates/", "vendor/")) and "/tests/" not in name):
            path = ROOT / name
            if path.is_file():
                inputs[name] = digest(path.read_bytes())
    verification = {name: digest((ROOT / name).read_bytes()) for name in (
        "deploy/Dockerfile.tls", "deploy/Caddyfile.rotation", ".dockerignore",
        "scripts/tls-lifecycle.py", "scripts/fixtures/tls_edge.py",
        "scripts/fixtures/tls_client.py", "scripts/self-hosted-local-acceptance.py",
        "scripts/tests/test_tls_lifecycle.py")}
    return {"commit": require_command(["git", "-C", ROOT, "rev-parse", "HEAD"]).decode().strip(),
            "gateway_inputs": inputs, "gateway_source_sha256": digest(canonical(inputs)),
            "verification_inputs": verification,
            "verification_sha256": digest(canonical(verification)),
            "working_tree_modified": bool(require_command(["git", "-C", ROOT, "status", "--porcelain"]).strip())}


def run_host(args):
    output = args.out.resolve()
    if output.exists():
        raise RuntimeError("evidence destination must be new")
    output.mkdir(parents=True, mode=0o700)
    container_uid = os.getuid() if os.name == "posix" and os.getuid() else 65532
    container_gid = os.getgid() if os.name == "posix" and os.getuid() else 65532
    if os.name == "posix" and os.getuid() == 0:
        os.chown(output, container_uid, container_gid)
    manifest = source_manifest()
    (output / "source.json").write_text(json.dumps(manifest, indent=2) + "\n")
    name = "sou38-tls-" + secrets.token_hex(6)
    tag = "soup-wall-tls:" + manifest["gateway_source_sha256"][:12]
    build = ["docker", "build", "--build-arg", "SOURCE_SHA256=" + manifest["gateway_source_sha256"],
             "-f", ROOT / "deploy/Dockerfile.tls", "-t", tag, ROOT]
    print("Building the current Gateway and pinned Caddy runtime...", flush=True)
    with (output / "build.log").open("wb") as log:
        built = subprocess.run([str(arg) for arg in build], stdout=log, stderr=log, timeout=1800)
    if built.returncode:
        raise RuntimeError("TLS runtime build failed; see build.log")
    image = json.loads(require_command(["docker", "image", "inspect", tag]))[0]
    if image["Config"]["Labels"].get("soup-wall.tls.source-sha256") != manifest["gateway_source_sha256"]:
        raise RuntimeError("image source label does not match the source manifest")
    runtime = {"image_id": image["Id"], "architecture": image["Architecture"],
               "os": image["Os"], "caddy_image": CADDY_IMAGE, "python_image": PYTHON_IMAGE,
               "rust_image": RUST_IMAGE,
               "docker": require_command(["docker", "version", "--format", "{{.Server.Version}}"]).decode().strip()}
    (output / "image.json").write_text(json.dumps(runtime, indent=2) + "\n")
    command = ["docker", "run", "--name", name, "--user", f"{container_uid}:{container_gid}", "--read-only",
               "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,mode=1777",
               "--mount", f"type=bind,source={ROOT},target=/source,readonly",
               "--mount", f"type=bind,source={output},target=/evidence", tag]
    cleanup = {"container_name": name, "container_removed": False}
    try:
        process = subprocess.run([str(arg) for arg in command], timeout=300)
        code = process.returncode
    finally:
        removed = execute(["docker", "rm", "-f", name])
        cleanup["container_removed"] = removed.returncode == 0
        after = source_manifest()
        cleanup["source_unchanged"] = (after["gateway_inputs"] == manifest["gateway_inputs"]
                                       and after["verification_inputs"] == manifest["verification_inputs"])
        (output / "cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
    if not cleanup["container_removed"] or not cleanup["source_unchanged"]:
        raise RuntimeError("cleanup or source stability check failed")
    print(f"Evidence: {output}", flush=True)
    return code


def run_inside():
    sys.path.insert(0, str(ROOT / "scripts/fixtures"))
    from tls_edge import Edge, RotationError, fingerprint, atomic_write
    output = Path("/evidence")
    report = {"schema_version": "sou38-tls/1", "task": "SOU-38", "started_at_utc": timestamp(),
              "status": "failed", "checks": [], "witnesses": [], "rotation_errors": [],
              "source": json.loads((output / "source.json").read_text()),
              "runtime": json.loads((output / "image.json").read_text()),
              "limits": ["Controlled Linux/Docker localhost TLS with an operator-generated CA",
                         "No public ACME, customer domain or native Windows/macOS acceptance"]}
    runtime = report["runtime"]
    runtime.update(python=platform.python_version(), kernel=platform.release(), uid=os.getuid(),
                   openssl=require_command(["openssl", "version"]).decode().strip(),
                   caddy=require_command(["caddy", "version"]).decode().strip(),
                   gateway_binary_sha256=digest(Path("/usr/local/bin/soup-wall-gateway").read_bytes()),
                   caddy_binary_sha256=digest(Path("/usr/local/bin/caddy").read_bytes()))

    def check(name, condition, **details):
        row = {"name": name, "status": "passed" if condition else "failed", **details}
        report["checks"].append(row)
        print(f"{row['status'].upper()}: {name}", flush=True)
        if not condition:
            raise RuntimeError(f"check failed: {name}")

    processes = []
    logs = []
    provider = None
    private_root = None
    try:
        check("unprivileged_runtime", os.getuid() != 0)
        tests = execute([sys.executable, "-m", "unittest", "discover", "-s",
                         ROOT / "scripts/tests", "-p", "test_tls_lifecycle.py", "-v"], timeout=60)
        (output / "tests.log").write_bytes(tests.stdout + tests.stderr)
        check("focused_tests", tests.returncode == 0 and b"skipped" not in tests.stderr)
        with tempfile.TemporaryDirectory(prefix="sou38-") as temporary:
            private_root = Path(temporary)
            private_root.chmod(0o700)
            certificates = private_root / "certificates"
            certificates.mkdir(mode=0o700)
            ca, ca_key = generate_ca(certificates, "rotation-ca")
            rogue_ca, rogue_key = generate_ca(certificates, "untrusted-ca")
            initial = generate_cert(certificates, "initial", ca, ca_key)
            rotated = generate_cert(certificates, "rotated", ca, ca_key)
            expired = generate_cert(certificates, "expired", ca, ca_key, expired=True)
            wrong_host = generate_cert(certificates, "wrong-host", ca, ca_key, hostname="wrong.invalid")
            wrong_ca = generate_cert(certificates, "wrong-ca", rogue_ca, rogue_key)
            token_file = private_root / "token"
            token = secrets.token_urlsafe(32)
            write_private(token_file, token)
            body = private_root / "body.json"
            write_private(body, json.dumps({"model": "fixture-model", "messages": [{"role": "user", "content": "hello"}]}))
            spec = importlib.util.spec_from_file_location("local_acceptance", ROOT / "scripts/self-hosted-local-acceptance.py")
            local = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(local)
            local.Provider.calls = 0
            provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), local.Provider)
            threading.Thread(target=provider.serve_forever, daemon=True).start()
            write_private(private_root / "policy.yaml", "default: allow\n")
            write_private(private_root / "firewall.yaml", 'bind: "127.0.0.1:8080"\n'
                          'proxy_auth:\n  enabled: true\n  token_env: SOU38_PROXY_TOKEN\n'
                          f'upstream:\n  openai_base: "http://127.0.0.1:{provider.server_port}"\n'
                          'max_body_bytes: 4194304\npolicy_file: policy.yaml\nfail_mode: fail_closed\n')
            report["configuration"] = {"gateway_sha256": digest((private_root / "firewall.yaml").read_bytes()),
                                       "policy_sha256": digest((private_root / "policy.yaml").read_bytes()),
                                       "edge_template_sha256": digest((ROOT / "deploy/Caddyfile.rotation").read_bytes()),
                                       "gateway_bind": "127.0.0.1:8080", "edge_bind": "0.0.0.0:8443",
                                       "caddy_admin_bind": "127.0.0.1:2019", "published_host_ports": [],
                                       "body_bound_bytes": 4194304}
            environment = {"PATH": os.environ["PATH"], "HOME": str(private_root), "RUST_LOG": "warn",
                           "SOU38_PROXY_TOKEN": token, "PYTHONDONTWRITEBYTECODE": "1"}
            gateway_log = (output / "gateway.log").open("wb")
            logs.append(gateway_log)
            gateway = subprocess.Popen(["soup-wall-gateway"], cwd=private_root,
                                       env=environment, stdout=gateway_log, stderr=gateway_log)
            processes.append(gateway)
            edge = Edge(private_root / "edge", ca, ROOT / "deploy/Caddyfile.rotation")
            first = edge.initialize(*initial)["fingerprint_sha256"]
            (output / "Caddyfile.initial").write_bytes(edge.config.read_bytes())
            for source, name in ((private_root / "firewall.yaml", "gateway-config.yaml"),
                                 (private_root / "policy.yaml", "policy.yaml"), (ca, "ca.pem"),
                                 (initial[0], "initial.pem"), (rotated[0], "rotated.pem"),
                                 (expired[0], "expired.pem")):
                (output / name).write_bytes(source.read_bytes())
            caddy_log = (output / "caddy.log").open("wb")
            logs.append(caddy_log)

            def start_caddy():
                process = subprocess.Popen(["caddy", "run", "--config", edge.config, "--adapter", "caddyfile"],
                                           env=environment, stdout=caddy_log, stderr=caddy_log)
                processes.append(process)
                return process

            caddy = start_caddy()

            def witness(name, **options):
                command = [sys.executable, ROOT / "scripts/fixtures/tls_client.py", "--ca", options.pop("ca", ca)]
                for key, value in options.items():
                    command += ["--" + key.replace("_", "-"), value]
                result = execute(command)
                row = json.loads(result.stdout)
                row.update(name=name, client_exit_code=result.returncode, observed_at_utc=timestamp())
                report["witnesses"].append(row)
                return row

            def wait_https(expected):
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    try:
                        edge.witness(expected)
                        return
                    except RotationError:
                        if gateway.poll() is not None or caddy.poll() is not None:
                            raise RuntimeError("Gateway or Caddy exited during startup")
                        time.sleep(0.2)
                raise RuntimeError("HTTPS edge did not become ready")

            def useful(name, expected):
                before = local.Provider.calls
                row = witness(name, path="/v1/chat/completions", method="POST", body_file=body, token_file=token_file)
                check(name, row["verified"] and row["http_status"] == 200 and row.get("useful_response")
                      and row["fingerprint_sha256"] == expected and local.Provider.calls == before + 1,
                      provider_calls_before=before, provider_calls_after=local.Provider.calls)

            wait_https(first)
            row = witness("initial_handshake")
            check("initial_handshake", row["verified"] and row["fingerprint_sha256"] == first and row["http_status"] == 200)
            useful("initial_authenticated_request", first)
            before = local.Provider.calls
            row = witness("unauthenticated_request", path="/v1/chat/completions", method="POST", body_file=body)
            check("unauthenticated_request", row["http_status"] == 401 and local.Provider.calls == before)
            for path in ("/metrics", "/metrics/anything", "/admin", "/admin/v1/tenants"):
                row = witness("edge_boundary" + path, path=path)
                check("edge_boundary" + path, row["http_status"] == 404)
            row = witness("readiness", path="/readyz")
            check("readiness", row["http_status"] == 200)
            oversized = private_root / "oversized.json"
            write_private(oversized, b" " * (4194304 + 1))
            row = witness("body_bound", path="/v1/chat/completions", method="POST", body_file=oversized, token_file=token_file)
            check("body_bound", row["http_status"] == 413 and local.Provider.calls == before)
            result = edge.rotate(*rotated)
            second = fingerprint(rotated[0])
            (output / "Caddyfile.rotated").write_bytes(edge.config.read_bytes())
            report["witnesses"].append({"name": "rotation_confirmation", **result})
            check("rotation", second != first and result["fingerprint_sha256"] == second)
            useful("rotated_authenticated_request", second)

            malformed = certificates / "malformed.pem"
            write_private(malformed, "not a certificate\n")
            too_large = certificates / "oversized.pem"
            write_private(too_large, b"x" * 65537)
            symlink = certificates / "linked.pem"
            symlink.symlink_to(rotated[0])
            for name, pair in (("malformed_material", (malformed, rotated[1])),
                               ("mismatched_key", (rotated[0], initial[1])),
                               ("expired_material", expired), ("wrong_hostname_material", wrong_host),
                               ("untrusted_ca_material", wrong_ca), ("oversized_material", (too_large, rotated[1])),
                               ("symlink_material", (symlink, rotated[1]))):
                old_config = edge.config.read_bytes()
                error = None
                try:
                    edge.rotate(*pair)
                except (RotationError, OSError) as problem:
                    error = str(problem)
                report["rotation_errors"].append({"case": name, "diagnostic": error})
                check(name, error is not None and edge.config.read_bytes() == old_config and not edge.journal.exists())
                useful(name + "_preserves_gateway", second)

            for name, options, expected_code in (("wrong_hostname_client", {"verify_hostname": "wrong.invalid"}, 62),
                                                 ("untrusted_ca_client", {"ca": rogue_ca}, None)):
                before = local.Provider.calls
                row = witness(name, **options)
                check(name, not row["verified"] and row["http_status"] is None
                      and row.get("error") == "certificate_verification_failed"
                      and (expected_code is None or row["verify_code"] == expected_code)
                      and local.Provider.calls == before)
            useful("client_failures_preserve_gateway", second)

            bad_config = edge.root / "bad.Caddyfile"
            write_private(bad_config, (ROOT / "deploy/Caddyfile.rotation").read_text()
                          .replace("{$TLS_CERTIFICATE}", str(rotated[0]))
                          .replace("{$TLS_PRIVATE_KEY}", str(initial[1])))
            failure = execute(["caddy", "reload", "--config", bad_config, "--adapter", "caddyfile"])
            (output / "rejected-reload.log").write_bytes(failure.stderr)
            check("caddy_rejects_mismatched_reload", failure.returncode != 0)
            useful("caddy_reload_failure_preserves_gateway", second)

            expired_config = edge.root / "expired.Caddyfile"
            write_private(expired_config, (ROOT / "deploy/Caddyfile.rotation").read_text()
                          .replace("{$TLS_CERTIFICATE}", str(expired[0]))
                          .replace("{$TLS_PRIVATE_KEY}", str(expired[1])))
            require_command(["caddy", "reload", "--config", expired_config, "--adapter", "caddyfile"])
            row = witness("expired_server_client")
            check("expired_server_client", not row["verified"] and row.get("verify_code") == 10 and row["http_status"] is None)
            edge.recover()
            useful("expired_server_recovery", second)

            for phase in ("before_reload", "after_reload"):
                method = "reload" if phase == "before_reload" else "witness"
                code = ("import os,signal,sys; from pathlib import Path; "
                        "sys.path.insert(0,sys.argv[1]); from tls_edge import Edge; "
                        f"Edge.{method}=lambda *a: os.kill(os.getpid(),signal.SIGSTOP); "
                        "Edge(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4])).rotate(Path(sys.argv[5]),Path(sys.argv[6]))")
                child = subprocess.Popen([sys.executable, "-c", code, str(ROOT / "scripts/fixtures"),
                                          str(edge.root), str(ca), str(edge.template), str(initial[0]), str(initial[1])],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(child)
                deadline = time.monotonic() + 20
                stopped = False
                while time.monotonic() < deadline and child.poll() is None:
                    status = Path(f"/proc/{child.pid}/status").read_text()
                    if "State:\tT" in status:
                        stopped = True
                        break
                    time.sleep(0.05)
                check("interruption_" + phase + "_reached", stopped and edge.journal.exists())
                row = witness("interruption_" + phase + "_served")
                expected = second if phase == "before_reload" else first
                check("interruption_" + phase + "_observed", row.get("fingerprint_sha256") == expected and row["http_status"] == 200)
                child.kill()
                child.wait(timeout=5)
                result = edge.recover()
                report["witnesses"].append({"name": "recovery_" + phase, **result})
                check("recovery_" + phase, not edge.journal.exists() and result["fingerprint_sha256"] == second)
                useful("recovery_" + phase + "_authenticated_request", second)

            caddy.terminate()
            caddy.wait(timeout=10)
            error = None
            try:
                edge.rotate(*initial)
            except RotationError as problem:
                error = str(problem)
            report["rotation_errors"].append({"case": "reload_unavailable", "diagnostic": error})
            check("reload_unavailable", error is not None and edge.journal.exists())
            caddy = start_caddy()
            wait_https(second)
            edge.recover()
            useful("reload_unavailable_recovery", second)
            check("journal_cleared_after_recovery", not edge.journal.exists())
            private_files = list(edge.root.glob("version-*/key.pem"))
            check("private_material_permissions", bool(private_files) and all(path.stat().st_mode & 0o077 == 0 for path in private_files)
                  and edge.root.stat().st_mode & 0o077 == 0)
            report["provider_calls"] = local.Provider.calls
            report["configuration"]["committed_edge_sha256"] = digest(edge.config.read_bytes())
            report["certificates"] = {"initial": first, "rotated": second, "ca_sha256": digest(ca.read_bytes())}
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
            provider.shutdown()
            provider.server_close()
            provider = None
            check("owned_processes_stopped", all(process.poll() is not None for process in processes))
            for log in logs:
                log.flush()
            evidence = [path.read_bytes() for path in output.iterdir() if path.is_file()]
            evidence.append(canonical(report))
            check("evidence_excludes_private_material", all(
                token.encode() not in data and b"PRIVATE KEY-----" not in data for data in evidence))
        check("private_workspace_removed", not private_root.exists())
        report["status"] = "passed"
    except Exception as error:
        report["diagnostic"] = str(error)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        for log in logs:
            log.close()
        if provider:
            provider.shutdown()
            provider.server_close()
        report["cleanup"] = {"all_owned_processes_stopped": all(process.poll() is not None for process in processes),
                             "private_workspace_removed": private_root is not None and not private_root.exists()}
        report["finished_at_utc"] = timestamp()
        report["artifacts"] = {path.name: {"sha256": digest(path.read_bytes()), "bytes": path.stat().st_size}
                               for path in output.iterdir() if path.is_file()}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"TLS lifecycle: {report['status'].upper()} ({len(report['checks'])} checks)", flush=True)
    if report.get("diagnostic"):
        print(report["diagnostic"], flush=True)
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description="Run a disposable Linux/Docker TLS rotation and recovery drill.")
    parser.add_argument("--out", type=Path, default=ROOT / "target/tls-evidence" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        return run_inside() if args.inside else run_host(args)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
