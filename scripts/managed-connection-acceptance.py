#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-231: installed Linux connection transactions against real disposable Consoles.
All credentials, config, raw process output and traces stay in a private tempdir.
Retained evidence contains only outcomes and exact source/binary hashes.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

D = module("sou231_rotation", "managed-credential-rotation-demo.py")
E = module("sou231_enrollment", "console-enrollment-acceptance.py")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def private(path, data):
    # Use the accepted credential-file publication primitive: O_EXCL, mode 0600
    # before any bytes, fsync and atomic replace. Never write then chmod.
    D.replace_secret(path, data.decode("utf-8") if isinstance(data, bytes) else data)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("sqlite", "postgres"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and shutil.which("strace"), "Linux and strace required"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    args.output = args.output.resolve()
    assert not args.output.is_relative_to(ROOT), "evidence destination must be outside source"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    checks, outputs, hidden = {}, [], []
    report = {"format": "sw-managed-connection-acceptance/1", "backend": args.backend,
              "status": "failed", "checks": checks,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "source_sha256": {}, "scope": "one installed Linux Agent, disposable Console and independently provisioned fixture trust; no production credentials"}
    for name in subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines():
        if name.startswith("crates/agentfw/") or name in ("crates/proxy/src/managed_agent_api.rs","Cargo.lock", "scripts/managed-connection-acceptance.py", "scripts/managed-credential-rotation-demo.py", "scripts/console-enrollment-acceptance.py", "scripts/console-rollout-acceptance.py", "scripts/managed-policy-demo.py", ".github/workflows/managed-credential-rotation.yml"):
            path = ROOT / name
            if path.is_file(): report["source_sha256"][name] = sha(path.read_bytes())

    def check(name, condition):
        checks[name] = bool(condition)
        assert condition, name
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="sou231-") as directory, ExitStack() as stack:
            temp = Path(directory).resolve()
            temp.chmod(0o700)
            hidden.append(str(temp))
            previous_umask = os.umask(0o077)
            stack.callback(os.umask, previous_umask)
            home = temp / "home"
            profile = home / ".agentfw"
            profile.mkdir(parents=True, mode=0o700)
            home.chmod(0o700)
            console_dir = temp / "console"
            console_dir.mkdir(mode=0o700)
            install = temp / "installed"
            install.mkdir(mode=0o700)
            binary = install / "agentfw"
            shutil.copyfile(ROOT / "target/debug/agentfw", binary)
            binary.chmod(0o700)
            console_binary = (ROOT / "target/debug/llm-firewall").resolve()
            report["agent_binary_sha256"] = sha(binary.read_bytes())
            report["console_binary_sha256"] = sha(console_binary.read_bytes())
            check("binary_and_working_directory_outside_checkout", not binary.is_relative_to(ROOT) and not temp.is_relative_to(ROOT))
            owner, seed = secrets.token_urlsafe(32), secrets.token_hex(32)
            hidden += [owner, seed]
            env = {k:v for k,v in os.environ.items() if not k.startswith(("SOUP_MANAGED_AGENT_", "SOUP_AGENT_POLICY_", "LLM_FW_", "OPENAI_", "PG"))}
            console_env = dict(env, LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="operator-231", SOUP_AGENT_POLICY_SEED_HEX=seed)
            store = '  backend: sqlite\n  database_path: "console.sqlite"\n'
            if args.backend == "postgres":
                pg = Path("/usr/lib/postgresql/16/bin")
                assert (pg / "initdb").is_file(), "PostgreSQL 16 fixture required"
                url, ca, password, _ = E.postgres(stack, temp, pg)
                hidden += [url, password]
                console_env.update(LLM_FW_POSTGRES_URL=url, LLM_FW_POSTGRES_CA_CERT_FILE=str(ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
                report["database_transport"] = "PostgreSQL 16, owned CA, verified TLS"
            else:
                report["database_transport"] = "SQLite, owned private local file"
            cp, ap = D.port(), D.port()
            console = f"http://127.0.0.1:{cp}"
            agent = f"http://127.0.0.1:{ap}"
            private(console_dir / "firewall.yaml", f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store)
            if args.backend == "postgres":
                migration = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=console_env, capture_output=True, timeout=180)
                check("postgres_tls_migration", migration.returncode == 0)
            def start_console():
                p = D.run_process(stack, [str(console_binary)], console_dir, console_env, temp / f"console-{len(outputs)}.log")
                D.await_result("Console ready", lambda: True if D.call("GET", console + "/healthz")[0] == 200 else None)
                return p
            console_process = start_console()
            admin = {"x-llm-firewall-admin-token": "Bearer " + owner}
            tenant = D.expect(201, "POST", console + "/admin/v1/tenants", {"name":"installed-231"}, admin)["id"]
            base = console + f"/admin/v1/tenants/{tenant}/agents/installed-231"
            enrollment = D.expect(201, "POST", console + f"/admin/v1/tenants/{tenant}/agents", {"agent_id":"installed-231"}, admin)
            credential = profile / "credential"
            secret = enrollment["token"]
            hidden.append(secret)
            private(credential, secret)
            public = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            hidden.append(public)
            keyring = profile / "issuers.json"
            private(keyring, json.dumps({"schema_version":1,"issuers":[{"key_id":"operator-231","public_key_hex":public,"revoked":False}]}))
            check("issuer_trust_selected_independently_of_console_discovery", public not in " ".join(sys.argv))
            for revision, decision in (("deny-231","deny"),("allow-231","allow")):
                D.expect(201, "POST", base + "/revisions", {"revision":revision,"policy_yaml":f"default: {decision}\n"}, admin)
                D.expect(204, "POST", base + f"/revisions/{revision}/approve", {}, admin)
            first = D.expect(201, "POST", base + "/revisions/deny-231/deploy", {"rollback":False}, admin)
            origin, edge_ca, edge_counts, _ = E.EDGE.tls_edge(stack, temp, cp)
            edge_ca.chmod(0o600)
            private(profile / "config.yaml", f"bind: 127.0.0.1\nport: {ap}\nenforce: true\n")
            agent_env = dict(env, HOME=str(home))
            selector = profile / "managed-console.json"
            settings = ["--console",origin,"--tenant",tenant,"--agent","installed-231","--credential-file",str(credential),"--issuer-keyring",str(keyring),"--ca-file",str(edge_ca)]
            def run(words, success=True, environment=None):
                command = [str(binary), *words]
                check("no_credential_or_key_material_in_argv", not any(secret in " ".join(command) for secret in hidden if len(secret)>40))
                r = subprocess.run(command, cwd=temp, env=environment or agent_env, capture_output=True, timeout=60)
                outputs.append(r.stdout + r.stderr)
                report["last_cli"]={"command":words[:2],"exit_code":r.returncode}
                if success: assert r.returncode == 0, "installed CLI failed; private output suppressed"
                else: assert r.returncode != 0, "unsafe transition unexpectedly succeeded"
                return json.loads(r.stdout) if r.stdout.startswith(b"{") else None
            def managed(action, options=(), success=True):
                return run(["managed-console",action,*options], success)
            def preview(options=None):
                return managed("preview", settings if options is None else options)["confirmation"]
            def select(options=None):
                options = settings if options is None else options
                return managed("apply",[*options,"--confirm",preview(options)])
            run(["lifecycle","install","231.0.0",str(binary),"--sha256",report["agent_binary_sha256"]])
            stack.callback(lambda: subprocess.run([str(binary),"lifecycle","stop"],cwd=temp,env=agent_env,capture_output=True,timeout=45))
            source_before = {str(p.relative_to(profile)):sha(p.read_bytes()) for p in profile.rglob("*") if p.is_file()}
            c = preview()
            check("preview_is_read_only", source_before == {str(p.relative_to(profile)):sha(p.read_bytes()) for p in profile.rglob("*") if p.is_file()})
            # Incorrect authority or transport must preserve the previous selection.
            wrong = profile / "wrong-issuers.json"
            private(wrong, json.dumps({"schema_version":1,"issuers":[{"key_id":"operator-231","public_key_hex":"01"*32,"revoked":False}]}))
            wrong_ca = profile / "wrong-ca.pem"
            wrong_ca_key = profile / "wrong-ca.key"
            subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(wrong_ca_key),"-out",str(wrong_ca),"-days","2","-subj","/CN=Unrelated CA"],check=True,capture_output=True)
            for label, flag, value in (("audience","--agent","another-agent"),("issuer","--issuer-keyring",str(wrong)),("ca","--ca-file",str(wrong_ca))):
                bad = settings.copy()
                bad[bad.index(flag)+1] = value
                consent = preview(bad)
                managed("apply",[*bad,"--confirm",consent],False)
                check("wrong_"+label+"_preserves_previous_connection", not selector.exists())
            other = D.expect(201, "POST", console + f"/admin/v1/tenants/{tenant}/agents", {"agent_id":"empty-inbox-other"}, admin)
            hidden.append(other["token"])
            import urllib.request
            metadata_request=urllib.request.Request(console+"/agent/v1/policy",headers={"Authorization":"Bearer "+other["token"],"x-soup-agent-tenant":tenant,"x-soup-agent-id":"installed-231"})
            with urllib.request.urlopen(metadata_request,timeout=5) as metadata_response:
                check("authenticated_scope_ignores_forged_request_metadata",metadata_response.status==204 and metadata_response.headers.get("x-soup-agent-tenant")==tenant and metadata_response.headers.get("x-soup-agent-id")=="empty-inbox-other")
            foreign = profile / "foreign-credential"
            private(foreign, other["token"])
            wrong_scope = settings.copy()
            wrong_scope[wrong_scope.index("--credential-file")+1] = str(foreign)
            managed("apply",[*wrong_scope,"--confirm",preview(wrong_scope)],False)
            check("empty_inbox_foreign_credential_cannot_bind_wrong_audience",not selector.exists())
            forwarded = edge_counts["forwarded"]
            D.replace_secret(credential, secret)
            managed("apply",[*settings,"--confirm",c],False)
            check("stale_input_rejected_before_network_or_state_change", not selector.exists() and forwarded==edge_counts["forwarded"])
            # Two valid settings race for the same initial selector; exactly one owns it.
            alternate = profile / "alternate-credential"
            private(alternate, secret)
            alternate_settings = settings.copy()
            alternate_settings[alternate_settings.index("--credential-file")+1] = str(alternate)
            c1, c2 = preview(), preview(alternate_settings)
            def concurrent(options, consent):
                r = subprocess.run([str(binary),"managed-console","apply",*options,"--confirm",consent],cwd=temp,env=agent_env,capture_output=True,timeout=60)
                outputs.append(r.stdout+r.stderr)
                return r.returncode
            with ThreadPoolExecutor(2) as pool:
                results = [pool.submit(concurrent,*pair) for pair in ((settings,c1),(alternate_settings,c2))]
                results = [r.result() for r in results]
            check("concurrent_different_apply_has_single_winner", results.count(0)==1)
            selected = managed("inspect")["settings"]
            credential = Path(selected["credential_file"])
            settings[settings.index("--credential-file")+1] = str(credential)
            old = selector.read_bytes()
            # Change only a reference to the same valid credential. Kill the process at
            # the actual rename syscall, after durable staging and before publication.
            next_credential = profile / "next-credential"
            private(next_credential, secret)
            interrupted = settings.copy()
            interrupted[interrupted.index("--credential-file")+1] = str(next_credential)
            consent = preview(interrupted)
            trace = subprocess.run(["strace","--quiet","-e","trace=renameat","-e","inject=renameat:error=EINTR:signal=SIGKILL:when=1","-o",str(temp / "interrupt.trace"),str(binary),"managed-console","apply",*interrupted,"--confirm",consent],cwd=temp,env=agent_env,capture_output=True,timeout=60)
            outputs.append(trace.stdout+trace.stderr)
            trace_text=(temp / "interrupt.trace").read_text() if (temp / "interrupt.trace").exists() else ""
            report["interruption"]={"exit_code":trace.returncode,"rename_observed":"renameat(" in trace_text,"selected_filename_observed":"managed-console.json" in trace_text,"injection_annotation_observed":"INJECTED" in trace_text,"sigkill_observed":"SIGKILL" in trace_text,"previous_selector_preserved":selector.read_bytes()==old,"ptrace_denied":b"Operation not permitted" in trace.stderr}
            check("real_sigkill_before_commit_preserves_previous_selector", trace.returncode!=0 and selector.read_bytes()==old and all(marker in trace_text for marker in ("renameat(","managed-console.json","SIGKILL")))
            managed("apply",[*interrupted,"--confirm",consent])
            after = selector.read_bytes()
            check("interrupted_apply_resumes_and_exact_retry_is_idempotent", managed("apply",[*interrupted,"--confirm",consent])["status"]=="already_committed" and after==selector.read_bytes())
            settings, credential = interrupted, next_credential
            before_start=managed("verify")
            check("fresh_candidate_verification_is_not_application",before_start["verification"]["state"]=="verified_candidate" and not before_start["verification"]["applied"] and before_start["recorded_application"] is None)
            run(["lifecycle","start"])
            def active(sequence):
                return D.await_result("actual policy application", lambda: (lambda h:h if (h.get("managed_policy") or {}).get("deployment_sequence")==sequence else None)(D.call("GET",agent+"/health")[1]))
            def applied(sequence):
                return D.await_result("recorded application", lambda: (lambda entries:entries[0] if entries and entries[0]["deployment_sequence"]==sequence and entries[0]["status"]=="applied" else None)(D.call("GET",base+"/deployments",headers=admin)[1]))
            active(1)
            applied(1)
            hook_token = (profile / "token").read_text().strip()
            hidden.append(hook_token)
            def verdict(label):
                response = D.call("POST",agent+"/hook",{"session_id":"sou231-"+label,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo harmless"}},{"Authorization":"Bearer "+hook_token})[1]
                return "allow" if response=={} else response["hookSpecificOutput"]["permissionDecision"]
            check("installed_agent_applied_exact_signed_deny", verdict("initial")=="deny" and active(1)["managed_policy"]["policy_sha256"]==first["policy_sha256"])
            observed = managed("inspect")
            check("configured_and_authenticated_running_identities_distinguished", observed["runtime_authenticated"] and observed["running_matches_configured"] and observed["recorded_application"]["managed_sequence"]==1 and observed["transport"]["state"]=="online")
            verified = managed("verify")
            check("verification_never_claims_application", verified["verification"]["state"]=="authenticated_bound_no_policy" and verified["verification"]["audience_verified"] and verified["verification"]["applied"] is False)
            process = run(["lifecycle","status"])["process"]
            cmdline = Path(f'/proc/{process["pid"]}/cmdline').read_bytes()
            check("running_process_argv_contains_no_secrets", all(v.encode() not in cmdline for v in hidden if v!=str(temp)))
            rotation = "sw_agent_"+secrets.token_urlsafe(32)
            hidden.append(rotation)
            D.expect(200,"POST",base+"/credential-rotations",{"expected_generation":1,"operation_id":secrets.token_hex(16),"replacement_token":rotation},admin)
            D.await_result("credential failure",lambda:True if (D.call("GET",agent+"/health")[1].get("managed_transport") or {}).get("state")=="auth_unavailable" else None)
            check("missing_current_credential_preserves_enforced_policy",verdict("credential-gap")=="deny")
            D.replace_secret(credential,rotation)
            D.await_result("credential reload",lambda:True if (D.call("GET",agent+"/health")[1].get("managed_transport") or {}).get("state")=="online" else None)
            check("credential_rotation_reload_without_restart",run(["lifecycle","status"])["process"]["pid"]==process["pid"])
            run(["lifecycle","restart"])
            check("restart_restores_signed_policy_and_sync",active(1)["managed_policy"]["policy_sha256"]==first["policy_sha256"] and verdict("restart")=="deny")
            D.stop(console_process)
            D.await_result("Console outage",lambda:True if (D.call("GET",agent+"/health")[1].get("managed_transport") or {}).get("state")=="offline" else None)
            check("console_outage_retains_active_policy",verdict("offline")=="deny")
            run(["lifecycle","restart"])
            check("offline_restart_retains_policy",verdict("offline-restart")=="deny")
            console_process = start_console()
            D.await_result("Console recovery",lambda:True if (D.call("GET",agent+"/health")[1].get("managed_transport") or {}).get("state")=="online" else None)
            disconnect = managed("disconnect-preview")["confirmation"]
            old = selector.read_bytes()
            managed("disconnect",["--confirm",disconnect],False)
            check("disconnect_refuses_active_instance_without_mutation",selector.read_bytes()==old and verdict("guarded")=="deny")
            run(["lifecycle","stop"])
            managed("disconnect",["--confirm",disconnect],False)
            check("disconnect_requires_fresh_lifecycle_bound_consent",selector.read_bytes()==old)
            private(profile / "user.keep",b"user data remains")
            retained = {p.name:sha(p.read_bytes()) for p in profile.iterdir() if p.is_file() and p.name not in ("managed-console.json",) and not p.name.startswith(".managed-console-stage-")}
            disconnect = managed("disconnect-preview")["confirmation"]
            managed("disconnect",["--confirm",disconnect])
            check("disconnect_retains_policy_cache_anti_replay_credentials_config_and_user_files",all(sha((profile/name).read_bytes())==digest for name,digest in retained.items()))
            run(["lifecycle","start"])
            before = edge_counts["forwarded"]
            second = D.expect(201,"POST",base+"/revisions/allow-231/deploy",{"rollback":False},admin)
            time.sleep(5)
            check("disconnected_restart_never_syncs_or_weakens_policy",edge_counts["forwarded"]==before and active(1)["managed_transport"]["state"]=="disconnected" and verdict("disconnected")=="deny")
            run(["lifecycle","stop"])
            saved = selector.read_bytes()
            mixed = dict(agent_env,SOUP_MANAGED_AGENT_CONSOLE=origin)
            run(["serve"],False,mixed)
            check("mixed_configuration_fails_closed",selector.read_bytes()==saved)
            private(selector,b"{}")
            run(["serve"],False)
            check("invalid_explicit_profile_never_falls_back",selector.read_bytes()==b"{}")
            private(selector,saved)
            # Re-enable requires fresh consent; preserved sequence prevents silently
            # reverting to the local default between disconnect and reconnect.
            select()
            run(["lifecycle","start"])
            applied(second["deployment_sequence"])
            check("explicit_reconnect_applies_next_sequence",active(2)["managed_policy"]["policy_sha256"]==second["policy_sha256"] and verdict("reconnected")=="allow")
            run(["lifecycle","stop"])
            legacy_home = temp / "legacy-home"
            legacy_profile = legacy_home / ".agentfw"
            legacy_profile.mkdir(parents=True,mode=0o700)
            lp = D.port()
            private(legacy_profile / "config.yaml",f"port: {lp}\nenforce: true\n")
            # A fresh environment-only home has no cached policy. Give it its own
            # pending deployment instead of expecting redelivery of an applied inbox.
            legacy_id="legacy-231"
            legacy_base=console+f"/admin/v1/tenants/{tenant}/agents/{legacy_id}"
            legacy_enrollment=D.expect(201,"POST",console+f"/admin/v1/tenants/{tenant}/agents",{"agent_id":legacy_id},admin)
            hidden.append(legacy_enrollment["token"])
            legacy_credential=legacy_profile/"credential"
            private(legacy_credential,legacy_enrollment["token"])
            D.expect(201,"POST",legacy_base+"/revisions",{"revision":"legacy-deny","policy_yaml":"default: deny\n"},admin)
            D.expect(204,"POST",legacy_base+"/revisions/legacy-deny/approve",{},admin)
            legacy_deployment=D.expect(201,"POST",legacy_base+"/revisions/legacy-deny/deploy",{"rollback":False},admin)
            legacy_env = dict(env,HOME=str(legacy_home),SOUP_MANAGED_AGENT_CONSOLE=origin,SOUP_MANAGED_AGENT_TOKEN_FILE=str(legacy_credential),SOUP_MANAGED_AGENT_TENANT=tenant,SOUP_MANAGED_AGENT_ID=legacy_id,SOUP_MANAGED_AGENT_KEY_ID="operator-231",SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=public,SOUP_MANAGED_AGENT_TLS_CA_FILE=str(edge_ca))
            legacy_process = D.run_process(stack,[str(binary),"serve"],temp,legacy_env,temp / "legacy.log")
            D.await_result("legacy environment startup",lambda:True if (D.call("GET",f"http://127.0.0.1:{lp}/health")[1].get("managed_policy") or {}).get("deployment_sequence")==legacy_deployment["deployment_sequence"] else None)
            legacy_inspection = run(["managed-console","inspect"], environment=legacy_env)
            check("legacy_running_state_does_not_claim_profile_identity_match",legacy_inspection["runtime_authenticated"] and legacy_inspection["configured"] is None and not legacy_inspection["running_matches_configured"] and not legacy_inspection["pending_restart"])
            D.stop(legacy_process)
            check("environment_only_startup_preserved",not (legacy_profile / "managed-console.json").exists())
            log_bytes=[]
            for logfile in temp.rglob("*.log"):
                with logfile.open("rb") as stream:
                    value=stream.read(8*1024*1024+1)
                assert len(value)<=8*1024*1024,"owned log cap exceeded"
                log_bytes.append(value)
            raw = b"\n".join(outputs + log_bytes)
            assert len(raw)<=64*1024*1024,"owned diagnostic cap exceeded"
            check("ordinary_cli_outputs_and_logs_redact_tokens_and_key_material",all(v.encode() not in raw for v in hidden if v!=str(temp)))
            report["status"] = "passed"
            report["recorded_sequences"] = [first["deployment_sequence"],second["deployment_sequence"]]
            report["console_to_agent_transport"] = "HTTPS, independently selected owned CA, no proxy or redirects"
    except Exception as error:
        report["failure_type"] = type(error).__name__
        # Arbitrary subprocess or HTTP failures may contain private paths/config;
        # record a fixed class, never raw exception/response text.
        print("FAILED:", type(error).__name__, "(private details suppressed)", flush=True)
        sys.exit(1)
    finally:
        text = json.dumps(report,indent=2,sort_keys=True)+"\n"
        assert not any(v in text for v in hidden if len(v)>40), "evidence secret scan failed"
        args.output.write_text(text)

if __name__ == "__main__":
    main()
