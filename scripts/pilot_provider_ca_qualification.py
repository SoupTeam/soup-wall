#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned HTTPS and genuine installed-host witness for selected provider CA bytes.

All keys, private PEM files, raw request bodies and execution traces remain in
the private qualification directory. The returned report has only digests,
counts and finite outcomes; these scripted endpoints are not a live provider.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import threading
import time


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def unsafe_source_refused(code, outcome, delivered, stderr, secrets):
    """Early profile refusal has no host_started field; daemon startup must still be absent."""
    return (code != 0 and outcome.get("status") == "failed" and
            outcome.get("executed") is False and
            outcome.get("host_started") is not True and delivered == 0 and
            all(secret not in stderr for secret in secrets))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def openssl(*words, cwd):
    result = subprocess.run(["/usr/bin/openssl", *map(str, words)], cwd=cwd,
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    need(result.returncode == 0, "provider_ca_fixture_generation_failed")


def material(root, name, *, issuer=None, hostname="127.0.0.1"):
    directory = root / name
    directory.mkdir(mode=0o700)
    key, certificate = directory / "private.key", directory / "certificate.pem"
    if issuer is None:
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=Owned SOU-195 " + name, "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", key, "-out", certificate, cwd=directory)
    else:
        csr = directory / "request.csr"
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                "/CN=" + hostname, "-keyout", key, "-out", csr, cwd=directory)
        extensions = directory / "extensions.cnf"
        extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\n"
                              "subjectAltName=" + ("IP:" if hostname == "127.0.0.1" else "DNS:")
                              + hostname + "\n")
        openssl("x509", "-req", "-in", csr, "-CA", issuer[1], "-CAkey", issuer[0],
                "-CAcreateserial", "-out", certificate, "-days", "2",
                "-extfile", extensions, cwd=directory)
    key.chmod(0o600)
    certificate.chmod(0o600)
    return key, certificate


class HTTPSModel:
    """Keep the existing scripted Messages handler, replace only transport."""

    def __init__(self, scripted_model, certificate, key):
        model = scripted_model([])
        original = model.server.RequestHandlerClass
        model.close()  # No caller has received the unused HTTP URL.
        self.auth = []
        self.expected_credential = None
        self.on_authenticated = None
        observer = self

        class Handler(original):
            def do_POST(self):
                identity = (self.headers.get("x-api-key"), self.headers.get("authorization"))
                observer.auth.append(identity)
                if identity != (observer.expected_credential, None):
                    self.send_error(401)
                    return
                if observer.on_authenticated is not None:
                    observer.on_authenticated()
                return super().do_POST()

        class Server(http.server.ThreadingHTTPServer):
            def get_request(self):
                raw, address = self.socket.accept()
                try:
                    connection = self.context.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError):
                    self.refused_handshakes += 1
                    raw.close()
                    raise
                self.successful_handshakes += 1
                return connection, address

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certificate), str(key))
        server = Server(("127.0.0.1", 0), Handler)
        server.context = context
        server.successful_handshakes = server.refused_handshakes = 0
        model.server = server
        model.url = "https://127.0.0.1:" + str(server.server_address[1])
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.model = model

    def close(self):
        self.model.close()


def qualify(args, door, home, env, report, *, provider_call, exec_witness,
            guided, provider, base):
    """Run only after the existing installed component and selection are verified."""
    tls = args.output / "provider-ca-private"
    tls.mkdir(mode=0o700)
    old_ca = material(tls, "old-ca")
    new_ca = material(tls, "new-ca")
    unrelated_ca = material(tls, "unrelated-ca")
    old_leaf = material(tls, "old-leaf", issuer=old_ca)
    new_leaf = material(tls, "new-leaf", issuer=new_ca)
    untrusted_leaf = material(tls, "untrusted-leaf", issuer=unrelated_ca)
    wrong_host_leaf = material(tls, "wrong-host-leaf", issuer=new_ca, hostname="wrong.invalid")
    source = tls / "selected-ca.pem"
    old_bytes, new_bytes = old_ca[1].read_bytes(), new_ca[1].read_bytes()
    source.write_bytes(old_bytes)
    source.chmod(0o600)
    old_key = "sou195-old-" + os.urandom(16).hex()
    new_key = "sou195-new-" + os.urandom(16).hex()
    secret_values = (old_key, new_key)
    profile_env = {key: value for key, value in env.items() if key not in provider.KEYS}
    models = [HTTPSModel(base.DEMO.ScriptedModel, *pair[::-1]) for pair in
              (old_leaf, new_leaf, untrusted_leaf, wrong_host_leaf)]
    for model, key in zip(models, (old_key, new_key, new_key, new_key)):
        model.expected_credential = key
    old, new, untrusted, wrong_host = (item.model for item in models)
    old_observer, new_observer, untrusted_observer, wrong_host_observer = models
    calls = []
    traces = {name: args.output / ("provider-ca-" + name + ".trace.private")
              for name in ("old", "new", "restored")}

    def command(words, secret_fd=None):
        code, value = provider_call(args, home, profile_env, secret_values,
                                    words, secret_fd)
        calls.append({"action": words[0], "status": value.get("status"),
                      "reason": value.get("reason"), "exit": code})
        return code, value

    def create(name, model, credential):
        with provider.carrier({"ANTHROPIC_API_KEY": credential}) as fd:
            code, value = command(["create", "--name", name,
                "--model", "claude-sonnet-4-20250514", "--base-url", model.url,
                "--ssl-cert-file", str(source), "--secret-fd", str(fd), "--apply"], fd)
        need(code == 0 and value.get("status") == "saved", "provider_ca_profile_create_failed")
        code, value = command(["select", "--name", name, "--apply"])
        need(code == 0 and value.get("status") == "selected", "provider_ca_profile_select_failed")

    def checks(row, results, outcome, label, expected_ca, observer, credential):
        need(row["exit"] == 0 and row["status"] == "completed" and
             row["process_cleanup"]["all_stopped"] and
             results["toolu_front_" + label + "_0"]["is_error"] is False,
             "provider_ca_real_host_flow_failed")
        need(observer.model.server.successful_handshakes >= 2 and len(observer.model.requests) >= 2 and
             observer.auth and all(key == credential and token is None
                                   for key, token in observer.auth),
             "provider_ca_verified_tls_or_credential_missing")
        run_id = outcome.get("audit", {}).get("run_id")
        need(type(run_id) is str and 6 <= len(run_id) <= 64 and
             all(letter.isascii() and (letter.isalnum() or letter in "_-") for letter in run_id),
             "provider_ca_run_identity_missing")
        row["provider_ca"] = {"ca_sha256": expected_ca, "run_id": run_id,
                              "tls_handshakes": observer.model.server.successful_handshakes,
                              "authenticated_requests": len(observer.auth), "real_host": True,
                              "raw_material_exported": False}
        row["passed"] = True

    proposals = [("mcp__filesystem__read_text_file", {"path": "/workspace/README.md"})]
    old_ready, release_old = threading.Event(), threading.Event()
    old_result = {}
    observed_overlap = []

    try:
        create("owned-ca-old", old, old_key)

        def old_setup(model):
            need(model is old, "provider_ca_old_model_changed")
            step = model.next
            observed = False

            def hold_first_request(body):
                nonlocal observed
                names = {tool.get("name") for tool in body.get("tools", [])}
                if not observed and {"mcp__filesystem__read_text_file",
                                     "mcp__git__git_show"} <= names:
                    observed = True
                    old_ready.set()  # TLS handshake and authenticated request already arrived.
                    need(release_old.wait(120), "provider_ca_old_run_hold_timeout")
                return step(body)

            model.next = hold_first_request
            return {"ANTHROPIC_API_KEY": old_key, "ANTHROPIC_BASE_URL": old.url,
                    "SSL_CERT_FILE": str(source)}

        def run_old():
            try:
                old_result["value"] = guided.run_case(args, door, report, "ca-old", proposals,
                    provider_setup=old_setup, provider_trace=traces["old"],
                    model=old, close_model=False)
            except BaseException as error:
                old_result["error"] = error

        worker = threading.Thread(target=run_old, daemon=True)
        worker.start()
        try:
            need(old_ready.wait(120), "provider_ca_first_tls_request_missing")
            need(old_observer.auth and old_observer.auth[0] == (old_key, None),
                 "provider_ca_old_authentication_missing")
            old_handshakes_at_replace = old.server.successful_handshakes
            old_requests_at_replace = len(old_observer.auth)
            # Replace the operator's source while the first genuine host remains
            # active. Its next request must still authenticate against old TLS.
            replacement = tls / "replacement.pem"
            replacement.write_bytes(new_bytes)
            replacement.chmod(0o600)
            os.replace(replacement, source)
            need(source.read_bytes() == new_bytes, "provider_ca_source_not_replaced")
            create("owned-ca-new", new, new_key)

            def start_new_during_old():
                new_observer.on_authenticated = None
                observed_overlap.append(worker.is_alive() and old_ready.is_set())
                release_old.set()

            new_observer.on_authenticated = start_new_during_old
            fresh, fresh_results, fresh_outcome = guided.run_case(args, door, report,
                "ca-new", proposals, provider_setup=lambda model: {
                    "ANTHROPIC_API_KEY": new_key, "ANTHROPIC_BASE_URL": new.url,
                    "SSL_CERT_FILE": str(source)}, provider_trace=traces["new"],
                model=new, close_model=False)
            checks(fresh, fresh_results, fresh_outcome, "ca-new", sha(new_bytes), new_observer, new_key)
            fresh["provider_witness"] = exec_witness(
                traces["new"], args.claude, new_key, new.url, str(source))
            need(fresh_outcome.get("provider", {}).get("ca_sha256") == sha(new_bytes),
                 "provider_ca_new_run_receipt_mismatch")
        finally:
            release_old.set()
            worker.join(180)
        need(not worker.is_alive() and "error" not in old_result and "value" in old_result,
             "provider_ca_old_run_incomplete")
        need(observed_overlap and all(observed_overlap), "provider_ca_concurrent_runs_not_observed")
        previous, previous_results, previous_outcome = old_result["value"]
        checks(previous, previous_results, previous_outcome, "ca-old", sha(old_bytes), old_observer, old_key)
        previous["provider_witness"] = exec_witness(
            traces["old"], args.claude, old_key, old.url, str(source))
        need(previous_outcome.get("provider", {}).get("ca_sha256") == sha(old_bytes)
             and old.server.successful_handshakes > old_handshakes_at_replace
             and len(old_observer.auth) > old_requests_at_replace
             and source.read_bytes() == new_bytes,
             "provider_ca_old_run_not_pinned_after_source_replacement")
        previous["provider_ca"]["post_replacement_tls_handshakes"] = (
            old.server.successful_handshakes - old_handshakes_at_replace)
        previous["provider_ca"]["post_replacement_authenticated_requests"] = (
            len(old_observer.auth) - old_requests_at_replace)
        need(not any(key == new_key for key, _ in old_observer.auth) and
             not any(key == old_key for key, _ in new_observer.auth),
             "provider_ca_concurrent_identity_mixed")

        # A source replacement before launch is read afresh. It must not
        # silently reuse the old trust choice or deliver the old credential.
        code, selected = command(["select", "--name", "owned-ca-old", "--apply"])
        need(code == 0 and selected.get("status") == "selected",
             "provider_ca_old_profile_reselect_failed")
        before = len(old_observer.auth)
        prior_requests = len(old.requests)
        changed, changed_results, changed_outcome = guided.run_case(
            args, door, report, "ca-prelaunch-substitution", proposals,
            provider_setup=lambda _: {"ANTHROPIC_API_KEY": old_key,
                "ANTHROPIC_BASE_URL": old.url, "SSL_CERT_FILE": str(source)},
            model=old, close_model=False)
        need(changed["exit"] != 0 and changed["status"] == "failed" and
             changed["process_cleanup"]["all_stopped"] and
             changed_outcome.get("provider", {}).get("ca_sha256") == sha(new_bytes) and
             not any(key.startswith("toolu_front_ca-prelaunch-substitution_")
                     for key in changed_results) and len(old_observer.auth) == before and
             len(old.requests) == prior_requests,
             "provider_ca_prelaunch_substitution_not_bound")
        changed["provider_ca"] = {"selected_ca_sha256": sha(new_bytes),
                                  "credential_requests": 0, "raw_material_exported": False}
        changed["passed"] = True

        for label, witness in (("untrusted-certificate", untrusted_observer),
                               ("wrong-hostname", wrong_host_observer)):
            model = witness.model
            create("owned-ca-" + label, model, new_key)
            before_auth = len(witness.auth)
            before_requests = len(model.requests)
            row, results, _ = guided.run_case(args, door, report, "ca-" + label, proposals,
                provider_setup=lambda _: {"ANTHROPIC_API_KEY": new_key,
                    "ANTHROPIC_BASE_URL": model.url, "SSL_CERT_FILE": str(source)},
                model=model, close_model=False)
            delivered = len(witness.auth) - before_auth
            requests = len(model.requests) - before_requests
            row["provider_ca"] = {"tls_handshakes": model.server.successful_handshakes,
                                  "credential_requests": delivered,
                                  "model_requests": requests,
                                  "raw_material_exported": False}
            need(row["exit"] != 0 and row["status"] == "failed" and
                 row["process_cleanup"]["all_stopped"] and
                 not any(key.startswith("toolu_front_ca-" + label + "_") for key in results) and
                 delivered == 0 and requests == 0,
                 "provider_ca_bad_tls_credential_delivered")
            row["provider_ca"]["tls_refused"] = True
            row["passed"] = True

        # Unsafe selected CA sources refuse before the credential-bearing host
        # starts, and a later verified launch remains possible after restoration.
        for label in ("symlink", "hardlink", "fifo", "oversize", "malformed", "wrong-mode"):
            source.unlink()
            if label == "symlink":
                source.symlink_to(new_ca[1])
            elif label == "hardlink":
                os.link(new_ca[1], source)
            elif label == "fifo":
                os.mkfifo(source, 0o600)
            elif label == "oversize":
                with source.open("xb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(new_bytes + b"X" * (2 * 1024 * 1024))
            else:
                source.write_bytes(b"not a certificate\n" if label == "malformed" else new_bytes)
                source.chmod(0o666 if label == "wrong-mode" else 0o600)
            try:
                before = sum(len(item.auth) for item in models)
                code, outcome, stderr = door.call("run", "--state-root", str(args.state_root),
                    "--timeout-seconds", "30", "--prompt", "Owned CA boundary probe.",
                    inputs=False, env=profile_env, timeout=90)
                delivered = sum(len(item.auth) for item in models) - before
                safe = unsafe_source_refused(code, outcome, delivered, stderr, secret_values)
                report["cases"].append({"case": "provider-ca-" + label, "passed": safe,
                                        "executed": outcome.get("executed"),
                                        "host_started": outcome.get("host_started"),
                                        "credential_requests": delivered,
                                        "reason": outcome.get("reason")})
                need(safe, "provider_ca_unsafe_source_not_refused")
            finally:
                source.unlink()
                source.write_bytes(new_bytes)
                source.chmod(0o600)

        create("owned-ca-restored", new, new_key)
        restored, restored_results, restored_outcome = guided.run_case(
            args, door, report, "ca-restored", proposals,
            provider_setup=lambda _: {"ANTHROPIC_API_KEY": new_key,
                "ANTHROPIC_BASE_URL": new.url, "SSL_CERT_FILE": str(source)},
            provider_trace=traces["restored"], model=new, close_model=False)
        checks(restored, restored_results, restored_outcome, "ca-restored",
               sha(new_bytes), new_observer, new_key)
        restored["provider_witness"] = exec_witness(
            traces["restored"], args.claude, new_key, new.url, str(source))

        retained = 0
        for path in args.state_root.rglob("*"):
            info = path.lstat()
            need(not stat.S_ISLNK(info.st_mode), "provider_ca_retained_link_unexpected")
            if not stat.S_ISREG(info.st_mode):
                continue
            retained += 1
            need(retained <= 256 and info.st_size <= 16 * 1024 * 1024,
                 "provider_ca_retained_witness_limit")
            data = path.read_bytes()
            need(old_bytes not in data and new_bytes not in data,
                 "provider_ca_snapshot_retained_in_run_state")
        report["provider_ca"] = {"old_ca_sha256": sha(old_bytes),
                                 "new_ca_sha256": sha(new_bytes),
                                 "old_and_new_runs_isolated": True,
                                 "tls_verified_by_actual_requests": True,
                                 "private_key_or_ca_bytes_exported": False,
                                 "retained_run_files_checked": retained,
                                 "paid_api_calls": 0,
                                 "calls": calls}
        public = json.dumps(report, sort_keys=True)
        need(all(secret not in public for secret in secret_values)
             and str(source) not in public
             and old_bytes.decode("ascii") not in public
             and new_bytes.decode("ascii") not in public,
             "provider_ca_public_report_contains_private_input")
    finally:
        for item in models:
            item.close()
        for trace in traces.values():
            trace.unlink(missing_ok=True)
        # Certificate/key material is test-only and cannot survive the case.
        shutil.rmtree(tls)
