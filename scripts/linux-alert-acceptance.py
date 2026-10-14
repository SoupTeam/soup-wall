#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in current-source Linux/Docker dependency alerts and durable protected receipts."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[1]
ALERTS = {
    "postgres": ("LLMFirewallControlPlaneUnavailable", "control-plane", 120),
    "redis": ("LLMFirewallRedisLimitsUnavailable", "admission-limits", 60),
    "gateway": ("LLMFirewallGatewayTargetDown", "gateway", 120),
}
JOB, INSTANCE = "soup-wall-gateway", "gateway:8080"
RECEIVER, EXTERNAL_URL = "soup-wall-protected", "http://alertmanager:9093"
TEXT = "Useful monitored Gateway fixture response"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


class DrillError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def request(url, *, body=None, headers=None, method=None, ca=None):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or parsed.hostname != "127.0.0.1"
            or parsed.port is None or parsed.username is not None or parsed.password is not None):
        raise DrillError("only owned numeric loopback HTTP endpoints are supported")
    context = ssl.create_default_context(cafile=str(ca)) if ca else ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=context))
    raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    message = urllib.request.Request(url, raw, {"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        response = opener.open(message, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(262145)
        if len(raw) > 262144:
            raise DrillError("HTTP response exceeded bound")
        return response.status, raw


def decoded(value):
    status, content = value
    try:
        return status, json.loads(content)
    except (ValueError, UnicodeError):
        raise DrillError("invalid JSON response") from None


def metric(text, name, label=None):
    values = [float(line.split()[-1]) for line in text.splitlines()
              if re.match(re.escape(name) + r"(?:\{|\s)", line) and (label is None or label in line)]
    return sum(values) if values else None


def pinned_images():
    manifest = json.loads((REPO / "deploy/monitoring-images.json").read_text())
    if set(manifest.get("images", {})) != {"prometheus", "alertmanager", "postgres", "redis", "python", "rust"}:
        raise DrillError("incomplete image inventory")
    if any(not re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", entry.get("image", ""))
           for entry in manifest["images"].values()):
        raise DrillError("images must be pinned by digest")
    return manifest


def source_identity():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "clean": not git("status", "--porcelain"), "cargo_lock_sha256": digest((REPO / "Cargo.lock").read_bytes())}


def plan():
    return {"schema_version": 1, "status": "plan", "executed": False,
            "scope": "SOU-41 controlled Linux notification/recovery slice", "source": source_identity(),
            "images": pinned_images(), "rule_for_seconds": {k: v[2] for k, v in ALERTS.items()},
            "rule_evaluation_interval_seconds": 30, "notification_group_wait_seconds": 30,
            "notification_group_interval_seconds": 15,
            "notification_group_interval_scope": "controlled drill override; production example remains 5m",
            "network_scope": "dedicated standard bridge with numeric loopback publications; no network-level egress-denial claim",
            "paid_models_or_external_incident_channels": False,
            "production_routing_or_staffed_response_accepted": False}


class Output:
    def __init__(self, path):
        self.path = path.absolute()
        if not self.path.parent.is_dir() or self.path.is_symlink():
            raise DrillError("evidence needs an existing unlinked parent")
        with self.path.open("x") as output:
            output.write('{"status":"reserved"}\n')
            output.flush()
            os.fsync(output.fileno())
        self.identity = self.path.stat().st_ino

    def save(self, report):
        if self.path.stat().st_ino != self.identity:
            raise DrillError("reserved evidence was replaced")
        descriptor, temporary = tempfile.mkstemp(prefix="sou41-evidence-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(report, output, indent=2, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            self.identity = self.path.stat().st_ino
        finally:
            Path(temporary).unlink(missing_ok=True)


def protected_file(path, content, mode=0o600):
    path.write_text(content)
    path.chmod(mode)


def make_policy():
    return {"receiver": RECEIVER, "external_url": EXTERNAL_URL, "optional_labels": {},
            "sources": [{"job": JOB, "instance": INSTANCE, "alerts": [
                {"alertname": value[0], "severity": "critical", "component": value[1]} for value in ALERTS.values()]}]}


def replay_payload(row):
    return {"version": "4", "receiver": RECEIVER, "status": row["status"], "groupLabels": row["labels"],
            "commonLabels": row["labels"], "commonAnnotations": {}, "externalURL": EXTERNAL_URL,
            "groupKey": "controlled-replay", "truncatedAlerts": 0,
            "alerts": [{"status": row["status"], "labels": row["labels"], "annotations": {},
                        "startsAt": row["starts_at"], "endsAt": row["ends_at"],
                        "generatorURL": "http://prometheus:9090/graph", "fingerprint": "0123456789abcdef"}]}


def checked_receipts(response):
    code, data = response
    if code != 200 or not isinstance(data, dict) or data.get("has_more") is not False:
        raise DrillError("receipt evidence unavailable or truncated")
    rows = data.get("records")
    if (not isinstance(rows, list) or type(data.get("total_unique_events")) is not int
            or data["total_unique_events"] != len(rows) or data.get("returned_records") != len(rows)):
        raise DrillError("incomplete receipt inventory")
    declared = {value[0]: value[1] for value in ALERTS.values()}
    seen_ids, cycles = set(), {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("labels"), dict):
            raise DrillError("invalid receipt")
        labels, status = row["labels"], row.get("status")
        name = labels.get("alertname")
        expected = {"alertname": name, "job": JOB, "instance": INSTANCE,
                    "severity": "critical", "component": declared.get(name)}
        if name not in declared or labels != expected or status not in {"firing", "resolved"}:
            raise DrillError("unapproved receipt source")
        if (any(not isinstance(row.get(field), str) or not re.fullmatch(r"[a-f0-9]{64}", row[field])
                for field in ["event_id", "cycle_id"])
                or not isinstance(row.get("starts_at"), str) or not row["starts_at"]
                or not isinstance(row.get("ends_at"), str) or not row["ends_at"]):
            raise DrillError("invalid receipt identity")
        cycle = cycles.setdefault(name, {})
        if row["event_id"] in seen_ids or status in cycle:
            raise DrillError("duplicate declared receipt")
        seen_ids.add(row["event_id"])
        cycle[status] = row
    for cycle in cycles.values():
        if "firing" in cycle and "resolved" in cycle:
            firing, resolved = cycle["firing"], cycle["resolved"]
            if (firing["cycle_id"] != resolved["cycle_id"] or firing["starts_at"] != resolved["starts_at"]
                    or firing["labels"] != resolved["labels"]):
                raise DrillError("uncorrelated receipt cycle")
    return data


class Runtime:
    def __init__(self, report, output):
        self.report, self.output = report, output
        self.project, self.owner = "sou41" + secrets.token_hex(8), secrets.token_hex(16)
        base = REPO / "target"
        base.mkdir(exist_ok=True)
        if base.is_symlink() or base.resolve() != base:
            raise DrillError("runtime target must not traverse links")
        self.directory = Path(tempfile.mkdtemp(prefix="linux-alert-", dir=base))
        self.directory.chmod(0o700)
        self.started, self.compose_file, self.sequence = False, None, 0
        self.token, self.admin, self.tenant_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32), None
        self.urls = {}
        report["ownership"] = {"project": self.project, "run_id": self.owner}

    def command(self, args, *, timeout=180):
        if not self.report["executed"]:
            self.report["executed"] = True
            self.output.save(self.report)
        self.sequence += 1
        path = self.directory / f"command-{self.sequence}.log"
        with path.open("wb") as log:
            result = subprocess.run(args, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise DrillError("owned runtime command failed")
        return path.read_text(errors="replace")

    def compose(self, *args, timeout=180):
        return self.command(["docker", "compose", "--project-name", self.project, "--file", str(self.compose_file), *args], timeout=timeout)

    def check(self, name, condition, **witness):
        self.report["checks"].append({"check": name, "outcome": "pass" if condition else "fail", "observed_at_utc": now(), **witness})
        self.output.save(self.report)
        print(json.dumps({"check": name, "outcome": "pass" if condition else "fail"}), flush=True)
        if not condition:
            raise DrillError("acceptance witness failed")

    def wait(self, name, predicate, timeout=390):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                result = predicate()
                if result:
                    self.check(name, True, elapsed_seconds=round(time.monotonic() - start, 3))
                    return result
            except (OSError, urllib.error.URLError, DrillError, http.client.HTTPException):
                pass
            time.sleep(2)
        self.check(name, False, elapsed_seconds=round(time.monotonic() - start, 3))

    def setup(self, skip_build=False):
        images = {k: v["image"] for k, v in self.report["images"]["images"].items()}
        self.command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
        self.command(["docker", "compose", "version"], timeout=30)
        existing = self.command(["docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={self.project}"])
        self.check("fresh_project", not existing.strip())
        snapshot = self.directory / "source"
        snapshot.mkdir()
        archive = self.directory / "source.tar"
        with archive.open("wb") as target:
            subprocess.run(["git", "archive", self.report["source"]["commit"]], cwd=REPO, stdout=target, check=True)
        with tarfile.open(archive) as bundle:
            bundle.extractall(snapshot, filter="data")
        self.image = "soup-wall-monitoring:" + self.report["source"]["commit"][:16]
        if not skip_build:
            print(json.dumps({"check": "current_gateway_linux_build", "outcome": "running"}), flush=True)
            self.command(["docker", "build", "--file", str(snapshot / "deploy/Dockerfile.monitoring"),
                          "--build-arg", "RUST_IMAGE=" + images["rust"], "--build-arg", "PYTHON_IMAGE=" + images["python"],
                          "--label", "soup-wall.source=" + self.report["source"]["commit"], "--tag", self.image, str(snapshot)], timeout=1800)
        identity = self.command(["docker", "image", "inspect", self.image, "--format", '{{.Id}} {{index .Config.Labels "soup-wall.source"}}']).split()
        self.check("immutable_source_image", len(identity) == 2 and re.fullmatch(r"sha256:[a-f0-9]{64}", identity[0]) is not None and identity[1] == self.report["source"]["commit"], image_id=identity[0] if identity else "missing")
        self.image = identity[0]
        self.report["gateway_image_id"] = self.image
        self.report["gateway_binary_sha256"] = self.command(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python3", self.image,
               "-c", "import hashlib;print(hashlib.sha256(open('/usr/local/bin/soup-wall-gateway','rb').read()).hexdigest())"]).strip()
        for name in ["receiver-data", "prometheus-data", "alertmanager-data", "provider-data", "redis-data"]:
            (self.directory / name).mkdir(mode=0o700)
        protected_file(self.directory / "token", self.token + "\n")
        protected_file(self.directory / "policy.json", json.dumps(make_policy(), indent=2))
        self.prepare_tls()
        rules = self.directory / "rules"
        rules.mkdir(mode=0o755)
        for name in ["prometheus-alerts.yaml", "prometheus-alerts.test.yaml"]:
            protected_file(rules / name, (snapshot / "deploy" / name).read_text(), 0o444)
        prometheus = """global:
  scrape_interval: 15s
  scrape_timeout: 5s
  evaluation_interval: 30s
rule_files: [/config/prometheus-alerts.yaml]
alerting:
  alertmanagers:
    - static_configs: [{targets: ['alertmanager:9093']}]
scrape_configs:
  - job_name: soup-wall-gateway
    metrics_path: /metrics
    follow_redirects: false
    proxy_from_environment: false
    static_configs: [{targets: ['gateway:8080']}]
"""
        names = "|".join(value[0] for value in ALERTS.values())
        alertmanager = f"""route:
  receiver: unrelated-drop
  group_by: [alertname, job, instance]
  group_wait: 30s
  group_interval: 15s
  repeat_interval: 4h
  routes:
    - receiver: soup-wall-protected
      matchers: ['job=\"soup-wall-gateway\"', 'instance=\"gateway:8080\"', 'alertname=~\"{names}\"']
receivers:
  - name: unrelated-drop
  - name: soup-wall-protected
    webhook_configs:
      - url: https://receiver:8443/alerts
        send_resolved: true
        http_config:
          follow_redirects: false
          proxy_from_environment: false
          authorization:
            credentials_file: /config/token
          tls_config:
            ca_file: /config/ca.pem
"""
        pg_password, redis_password = secrets.token_hex(32), secrets.token_hex(32)
        protected_file(self.directory / "redis.conf", "bind 0.0.0.0\nprotected-mode yes\nappendonly yes\ndir /data\nrequirepass " + redis_password + "\n")
        firewall = """bind: 0.0.0.0:8080
proxy_auth: {enabled: false}
tenant_store:
  enabled: true
  backend: postgres
  postgres_url_env: LLM_FW_POSTGRES_URL
  admin_token_env: LLM_FW_ADMIN_TOKEN
  postgres_command_timeout_ms: 1000
  postgres_pool_max_size: 8
  postgres_pool_wait_timeout_ms: 1000
  audit_queue_capacity: 100
redis_limits:
  enabled: true
  url_env: LLM_FW_REDIS_URL
  command_timeout_ms: 250
  fail_mode: fail_closed
upstream: {openai_base: 'http://upstream:8081', anthropic_base: 'http://upstream:8081'}
fail_mode: fail_closed
policy_file: policies/default.yaml
"""
        for name, content in [("prometheus.yaml", prometheus), ("alertmanager.yaml", alertmanager), ("firewall.yaml", firewall)]:
            protected_file(self.directory / name, content, 0o444)
        self.report["configuration_sha256"] = {name: digest((self.directory / name).read_bytes()) for name in ["policy.json", "prometheus.yaml", "alertmanager.yaml", "firewall.yaml"]}
        self.report["rule_configuration_sha256"] = {p.name: digest(p.read_bytes()) for p in rules.iterdir()}
        user, labels = f"{os.getuid()}:{os.getgid()}", {"soup-wall.monitoring-run": self.owner}
        def common(image):
            return {"image": image, "labels": labels, "user": user, "read_only": True, "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true"], "tmpfs": ["/tmp:rw,noexec,nosuid,size=128m"], "init": True}
        def mount(name, target, readonly=True):
            return {"type": "bind", "source": str(self.directory / name), "target": target, "read_only": readonly}
        def port(number):
            return [{"target": number, "published": "0", "host_ip": "127.0.0.1"}]
        services = {
            "postgres": {"image": images["postgres"], "labels": labels, "environment": {"POSTGRES_USER": "firewall", "POSTGRES_DB": "firewall", "POSTGRES_PASSWORD": pg_password}, "volumes": ["postgres-data:/var/lib/postgresql/data"]},
            "redis": {**common(images["redis"]), "command": ["redis-server", "/config/redis.conf"], "volumes": [mount("redis.conf", "/config/redis.conf"), mount("redis-data", "/data", False)]},
            "receiver": {**common(self.image), "entrypoint": ["python3", "/app/scripts/alert-receiver.py"],
                         "command": ["--listen", "0.0.0.0", "--port", "8443", "--data-dir", "/data", "--token-file", "/config/token", "--policy-file", "/config/policy.json", "--retention-days", "30", "--max-events", "1000", "--tls-cert", "/config/server.pem", "--tls-key", "/config/server.key"],
                         "ports": port(8443), "volumes": [mount("receiver-data", "/data", False), mount("token", "/config/token"), mount("policy.json", "/config/policy.json"), mount("server.pem", "/config/server.pem"), mount("server.key", "/config/server.key")]},
            "upstream": {**common(self.image), "entrypoint": ["python3", "/app/scripts/monitoring_fixture.py"], "command": ["--receipts", "/data/requests.jsonl"], "volumes": [mount("provider-data", "/data", False)]},
            "gateway": {**common(self.image), "environment": {"LLM_FW_ADMIN_TOKEN": self.admin, "LLM_FW_POSTGRES_URL": f"postgresql://firewall:{pg_password}@postgres:5432/firewall?sslmode=disable", "LLM_FW_REDIS_URL": f"redis://:{redis_password}@redis:6379/0", "RUST_LOG": "warn"}, "ports": port(8080), "volumes": [mount("firewall.yaml", "/app/firewall.yaml")]},
            "prometheus": {**common(images["prometheus"]), "command": ["--config.file=/config/prometheus.yaml", "--storage.tsdb.path=/data", "--storage.tsdb.retention.time=1d"], "ports": port(9090), "volumes": [mount("prometheus.yaml", "/config/prometheus.yaml"), mount("rules/prometheus-alerts.yaml", "/config/prometheus-alerts.yaml"), mount("prometheus-data", "/data", False)]},
            "alertmanager": {**common(images["alertmanager"]), "command": ["--config.file=/config/alertmanager.yaml", "--storage.path=/data", "--cluster.listen-address=", "--web.external-url=" + EXTERNAL_URL], "ports": port(9093), "volumes": [mount("alertmanager.yaml", "/config/alertmanager.yaml"), mount("token", "/config/token"), mount("ca.pem", "/config/ca.pem"), mount("alertmanager-data", "/data", False)]},
        }
        self.compose_file = self.directory / "compose.json"
        protected_file(self.compose_file, json.dumps({"services": services, "volumes": {"postgres-data": {}}, "networks": {"default": {}}}, indent=2))
        for args in [["check", "rules", "/rules/prometheus-alerts.yaml"], ["test", "rules", "/rules/prometheus-alerts.test.yaml"]]:
            self.command(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,nosuid,noexec,size=128m", "--mount", f"type=bind,src={rules},dst=/rules,readonly", "--entrypoint", "/bin/promtool", images["prometheus"], *args])
        self.check("pinned_rules_and_regressions", True)
        self.started = True
        self.compose("up", "--detach", "postgres", "redis", "receiver", "upstream")
        self.wait("postgres_ready", lambda: self.compose("exec", "--no-TTY", "postgres", "pg_isready", "-U", "firewall", "-d", "firewall").strip(), 60)
        self.compose("run", "--rm", "--no-deps", "gateway", "migrate")
        self.compose("up", "--detach", "gateway", "prometheus", "alertmanager")
        for service, target in [("gateway", 8080), ("receiver", 8443), ("prometheus", 9090), ("alertmanager", 9093)]:
            self.urls[service] = self.published_endpoint(service, target)
        self.wait("gateway_ready", lambda: self.gateway("/readyz")[0] == 200, 90)
        self.wait("receiver_ready", lambda: self.receipts()[0] == 200, 60)
        self.wait("prometheus_ready", lambda: request(self.urls["prometheus"] + "/-/ready")[0] == 200, 60)
        self.wait("alertmanager_ready", lambda: request(self.urls["alertmanager"] + "/-/ready")[0] == 200, 60)
        self.report["runtime_versions"] = {service: self.compose("exec", "--no-TTY", service, *args).strip() for service, args in [
            ("prometheus", ["/bin/prometheus", "--version"]), ("alertmanager", ["/bin/alertmanager", "--version"]), ("postgres", ["postgres", "--version"]), ("redis", ["redis-server", "--version"]), ("receiver", ["python3", "--version"])]}
        self.check("owned_pinned_services_ready", True)

    def prepare_tls(self):
        self.ca = self.directory / "ca.pem"
        protected_file(self.directory / "ca.cnf", """[req]
distinguished_name = ca_name
prompt = no
x509_extensions = ca_extensions
[ca_name]
CN = Soup Wall isolated monitoring CA
[ca_extensions]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
""")
        self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                      "-keyout", str(self.directory / "ca.key"), "-out", str(self.ca), "-days", "2",
                      "-config", str(self.directory / "ca.cnf")])
        self.command(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
                      "-keyout", str(self.directory / "server.key"), "-out", str(self.directory / "server.csr"),
                      "-subj", "/CN=receiver"])
        protected_file(self.directory / "server.ext", """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = DNS:receiver,DNS:localhost,IP:127.0.0.1
""")
        self.command(["openssl", "x509", "-req", "-sha256", "-in", str(self.directory / "server.csr"),
                      "-CA", str(self.ca), "-CAkey", str(self.directory / "ca.key"), "-CAcreateserial",
                      "-out", str(self.directory / "server.pem"), "-days", "2",
                      "-extfile", str(self.directory / "server.ext")])
        for path in self.directory.glob("*.key"):
            path.chmod(0o600)
        for path in [self.ca, self.directory / "server.pem"]:
            path.chmod(0o444)
        self.command(["openssl", "verify", "-x509_strict", "-purpose", "sslserver", "-verify_ip", "127.0.0.1",
                      "-CAfile", str(self.ca), str(self.directory / "server.pem")])
        self.report["receiver_ca_sha256"] = digest(self.ca.read_bytes())
        self.check("receiver_certificate_chain_strict", True,
                   leaf_certificate_sha256=digest((self.directory / "server.pem").read_bytes()))

    def published_endpoint(self, service, target):
        identifiers = self.compose("ps", "--quiet", service).split()
        if len(identifiers) != 1 or re.fullmatch(r"[a-f0-9]{12,64}", identifiers[0]) is None:
            raise DrillError("owned service container is unavailable or ambiguous")
        template = ('{"owner":{{json (index .Config.Labels "soup-wall.monitoring-run")}},'
                    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                    '"ports":{{json .NetworkSettings.Ports}}}')
        try:
            data = json.loads(self.command(["docker", "inspect", "--format", template, identifiers[0]]))
        except ValueError:
            raise DrillError("invalid owned port-binding witness") from None
        if (not isinstance(data, dict) or data.get("owner") != self.owner
                or data.get("project") != self.project or data.get("service") != service):
            raise DrillError("published endpoint ownership mismatch")
        ports = data.get("ports")
        bindings = ports.get(str(target) + "/tcp") if isinstance(ports, dict) else None
        if not isinstance(bindings, list) or len(bindings) != 1 or not isinstance(bindings[0], dict):
            raise DrillError("published endpoint is unavailable or ambiguous")
        binding = bindings[0]
        value = binding.get("HostPort")
        if (binding.get("HostIp") != "127.0.0.1" or not isinstance(value, str)
                or re.fullmatch(r"[0-9]+", value) is None or not 1 <= int(value) <= 65535):
            raise DrillError("published endpoint is not an assigned numeric loopback port")
        self.check(service + "_owned_loopback_endpoint", True, host_ip="127.0.0.1",
                   container_port=target, assigned_host_port=int(value))
        return ("https" if service == "receiver" else "http") + "://127.0.0.1:" + value

    def gateway(self, path, **args):
        return request(self.urls["gateway"] + path, **args)

    def receipts(self):
        return decoded(request(self.urls["receiver"] + "/receipts?limit=1000", headers={"Authorization": "Bearer " + self.token}, ca=self.ca))

    def query(self, query):
        status, data = decoded(request(self.urls["prometheus"] + "/api/v1/query?" + urllib.parse.urlencode({"query": query})))
        if status != 200 or data.get("status") != "success":
            raise DrillError("Prometheus query failed")
        return data["data"]["result"]

    def failures(self):
        status, data = request(self.urls["alertmanager"] + "/metrics")
        if status != 200:
            raise DrillError("Alertmanager metrics unavailable")
        value = metric(data.decode(), "alertmanager_notifications_failed_total", 'integration="webhook"')
        if value is None or not math.isfinite(value) or value < 0:
            raise DrillError("Alertmanager retry counter unavailable or invalid")
        return value

    def observed_alert(self, key, state):
        return self.query(f'ALERTS{{alertname="{ALERTS[key][0]}",job="{JOB}",instance="{INSTANCE}",alertstate="{state}"}}')

    def receipt(self, key, status):
        data = checked_receipts(self.receipts())
        return next((row for row in data["records"] if row["labels"]["alertname"] == ALERTS[key][0] and row["status"] == status), None)

    def provider_count(self):
        path = self.directory / "provider-data/requests.jsonl"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def completed_audit_ids(self):
        code, rows = decoded(self.gateway(f"/admin/v1/tenants/{self.tenant}/audit?limit=100",
                                         headers={"x-llm-firewall-admin-token": self.admin}))
        if code != 200 or not isinstance(rows, list) or len(rows) >= 100:
            raise DrillError("durable audit witness unavailable or bounded history exhausted")
        if any(not isinstance(row, dict) or type(row.get("id")) is not int for row in rows):
            raise DrillError("invalid durable audit witness")
        return {row["id"] for row in rows if row.get("path") == "/v1/chat/completions"
                and row.get("status_code") == 200 and row.get("outcome") == "completed"}

    def useful(self, stage):
        before = self.provider_count()
        audit_before = self.completed_audit_ids()
        code, data = decoded(self.gateway("/v1/chat/completions", body={"model": "fixture-safe", "messages": [{"role": "user", "content": "Hello"}], "stream": False}, headers={"x-llm-firewall-token": "Bearer " + self.tenant_token, "Authorization": "Bearer fixture-only"}))
        self.check("useful_" + stage, code == 200 and data.get("choices", [{}])[0].get("message", {}).get("content") == TEXT and self.provider_count() == before + 1,
                   http_status=code, provider_entries_delta=self.provider_count() - before, useful_response_sha256=digest(TEXT.encode()))
        def persisted():
            after = self.completed_audit_ids()
            return {"new_completed_audit_rows": 1} if audit_before <= after and len(after - audit_before) == 1 else None
        witness = self.wait("audit_persisted_" + stage, persisted, 30)
        self.check("durable_audit_witness_" + stage, True, **witness)

    def health_witness(self, key, healthy):
        code, data = decoded(self.gateway("/readyz"))
        metrics_status, metrics = self.gateway("/metrics")
        values = {name: metric(metrics.decode(), name) for name in ["llm_firewall_control_plane_ready", "llm_firewall_redis_limits_ready"]}
        rows = self.query(f'up{{job="{JOB}",instance="{INSTANCE}"}}')
        selected_name = "llm_firewall_control_plane_ready" if key == "postgres" else "llm_firewall_redis_limits_ready"
        other_name = "llm_firewall_redis_limits_ready" if key == "postgres" else "llm_firewall_control_plane_ready"
        selected_state, other_state = ("control_plane", "redis") if key == "postgres" else ("redis", "control_plane")
        matched = (code == (200 if healthy else 503) and metrics_status == 200
                   and values[selected_name] == (1 if healthy else 0) and values[other_name] == 1
                   and data.get(selected_state) == ("ready" if healthy else "unavailable")
                   and data.get(other_state) == "ready" and len(rows) == 1 and rows[0]["value"][1] == "1")
        return {"readyz_status": code, "metrics_status": metrics_status, "control_plane": data.get("control_plane"),
                "redis": data.get("redis"), "metrics": values,
                "prometheus_up": rows[0]["value"][1] if rows else "missing", "matched": matched}

    def seed_tenant(self):
        headers = {"x-llm-firewall-admin-token": self.admin}
        code, data = decoded(self.gateway("/admin/v1/tenants", body={"name": "SOU-41 controlled fixture"}, headers=headers))
        if code not in {200, 201}:
            raise DrillError("tenant fixture creation failed")
        self.tenant = data["tenant"]["id"] if "tenant" in data else data["id"]
        code, issued = decoded(self.gateway(f"/admin/v1/tenants/{self.tenant}/tokens", body={"label": "monitoring-fixture"}, headers=headers))
        if code not in {200, 201}:
            raise DrillError("tenant fixture token failed")
        self.tenant_token = issued["token"]
        code, _ = self.gateway(f"/admin/v1/tenants/{self.tenant}/limits", body={"rate_limit": {"requests_per_window": 100, "window_seconds": 60}}, headers=headers, method="PUT")
        self.check("authenticated_useful_tenant_configured", code == 200)

    def rejection_probes(self):
        before = checked_receipts(self.receipts())
        labels = {"job": JOB, "instance": INSTANCE, "alertname": ALERTS["gateway"][0], "severity": "critical", "component": "gateway"}
        body = replay_payload({"status": "firing", "labels": labels, "starts_at": now(), "ends_at": "0001-01-01T00:00:00Z"})
        url, auth = self.urls["receiver"] + "/alerts", {"Authorization": "Bearer " + self.token}
        for case, headers in [("missing", {}), ("wrong", {"Authorization": "Bearer wrong-token"})]:
            code, _ = request(url, body=body, headers=headers, ca=self.ca)
            self.check("authentication_" + case + "_refused", code == 401, http_status=code)
        code, _ = request(url, body={"version": "4"}, headers=auth, ca=self.ca)
        self.check("malformed_message_refused", code == 400, http_status=code)
        body["alerts"][0]["labels"]["instance"] = "unrelated:8080"
        code, _ = request(url, body=body, headers=auth, ca=self.ca)
        self.check("unrelated_target_refused", code == 400, http_status=code)
        after = checked_receipts(self.receipts())
        self.check("refusals_leave_no_durable_receipts", before["total_unique_events"] == after["total_unique_events"] == 0)

    def dependency_cycle(self, key, receiver_fault=False):
        if receiver_fault:
            self.compose("stop", "--timeout", "2", "receiver")
        self.compose("stop", "--timeout", "2", key)
        def state(healthy):
            witness = self.health_witness(key, healthy)
            return witness if witness["matched"] else None
        witness = self.wait(key + "_actual_readiness_loss", lambda: state(False), 45)
        self.check(key + "_scrape_remains_live", witness["prometheus_up"] == "1", **{k: v for k, v in witness.items() if k != "matched"})
        before = self.provider_count()
        code, _ = self.gateway("/v1/chat/completions", body={"model": "fixture-safe", "messages": [{"role": "user", "content": "Hello"}]}, headers={"x-llm-firewall-token": "Bearer " + self.tenant_token, "Authorization": "Bearer fixture-only"})
        self.check(key + "_unavailable_request_refused", code == 503 and self.provider_count() == before, http_status=code, provider_entries_delta=self.provider_count() - before)
        self.wait(key + "_real_rule_firing", lambda: self.observed_alert(key, "firing"), 300)
        if receiver_fault:
            def retried():
                failures = self.failures()
                return {"observed_failed_notifications": failures} if failures >= 2 else None
            retry_witness = self.wait("real_alertmanager_retry_while_receiver_down", retried, 90)
            self.check("receiver_outage_delivery_failure_witness", True, **retry_witness)
            self.compose("start", "receiver")
        firing = self.wait(key + "_authenticated_durable_firing", lambda: self.receipt(key, "firing"), 180)
        if receiver_fault:
            self.compose("restart", "--timeout", "2", "receiver")
            retained = self.wait("receiver_restart_retains_firing", lambda: self.receipt(key, "firing"), 45)
            self.check("receiver_restart_preserves_identity", retained["event_id"] == firing["event_id"] and retained["cycle_id"] == firing["cycle_id"])
            previous = checked_receipts(self.receipts())
            code, result = decoded(request(self.urls["receiver"] + "/alerts", body=replay_payload(firing), headers={"Authorization": "Bearer " + self.token}, ca=self.ca))
            current = checked_receipts(self.receipts())
            self.check("authenticated_replay_after_restart_is_duplicate", code == 200 and result.get("duplicates") == 1 and previous["total_unique_events"] == current["total_unique_events"], http_status=code)
        self.compose("start", key)
        recovered = self.wait(key + "_actual_readiness_recovered", lambda: state(True), 90)
        resolved = self.wait(key + "_authenticated_durable_resolved", lambda: self.receipt(key, "resolved"), 150)
        self.check(key + "_correlated_cycle", firing["cycle_id"] == resolved["cycle_id"] and firing["starts_at"] == resolved["starts_at"] and firing["labels"] == resolved["labels"], cycle_id=firing["cycle_id"], starts_at=firing["starts_at"], recovered_readiness=recovered)
        self.useful("after_" + key)

    def gateway_cycle(self):
        self.compose("stop", "--timeout", "2", "gateway")
        def stopped():
            rows = self.query(f'up{{job="{JOB}",instance="{INSTANCE}"}}')
            return rows if rows and rows[0]["value"][1] == "0" else None
        self.wait("gateway_scrape_loss", stopped, 45)
        self.check("gateway_outage_has_no_invented_readiness_zero", not self.query(f'llm_firewall_control_plane_ready{{job="{JOB}",instance="{INSTANCE}"}}'))
        self.wait("gateway_real_rule_firing", lambda: self.observed_alert("gateway", "firing"), 300)
        firing = self.wait("gateway_authenticated_durable_firing", lambda: self.receipt("gateway", "firing"), 120)
        self.compose("start", "gateway")
        self.wait("gateway_ready_after_restart", lambda: self.gateway("/readyz")[0] == 200, 90)
        resolved = self.wait("gateway_authenticated_durable_resolved", lambda: self.receipt("gateway", "resolved"), 150)
        self.check("gateway_correlated_cycle", firing["cycle_id"] == resolved["cycle_id"] and firing["starts_at"] == resolved["starts_at"] and firing["labels"] == resolved["labels"], cycle_id=firing["cycle_id"], starts_at=firing["starts_at"])
        self.useful("after_gateway_restart")

    def cleanup(self):
        if not self.started:
            return True
        for identifier in self.compose("ps", "--all", "--quiet").split():
            label = self.command(["docker", "inspect", "--format", '{{index .Config.Labels "soup-wall.monitoring-run"}}', identifier])
            if label.strip() != self.owner:
                raise DrillError("cleanup ownership mismatch")
        self.compose("down", "--volumes", "--timeout", "3")
        left = self.command(["docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={self.project}"])
        return not left.strip()


def execute(args):
    os.umask(0o077)
    output = Output(args.out)
    report = {"schema_version": 1, "status": "running", "executed": False, "started_at_utc": now(), "checks": []}
    runtime = None
    try:
        report.update(plan(), status="running", executed=False)
        output.save(report)
        if not report["source"]["clean"] or (args.expected_commit and args.expected_commit != report["source"]["commit"]):
            raise DrillError("expected clean exact source required")
        runtime = Runtime(report, output)
        runtime.setup(args.no_build)
        runtime.seed_tenant()
        runtime.rejection_probes()
        runtime.useful("before_outages")
        runtime.dependency_cycle("postgres", receiver_fault=True)
        runtime.dependency_cycle("redis")
        runtime.gateway_cycle()
        receipts = checked_receipts(runtime.receipts())
        expected = {(value[0], status) for value in ALERTS.values() for status in ["firing", "resolved"]}
        observed = {(row["labels"]["alertname"], row["status"]) for row in receipts["records"]}
        runtime.check("complete_declared_cycles_only", observed == expected and receipts["total_unique_events"] == 6 and not receipts.get("has_more"))
        report["receiver_receipts"] = receipts
        report["source_after"] = source_identity()
        runtime.check("source_unchanged", report["source_after"] == report["source"])
        report["status"] = "pass"
    except (Exception, KeyboardInterrupt) as error:
        report["status"], report["error_type"] = "incomplete", type(error).__name__
        if runtime:
            try:
                report["partial_receiver_receipts"] = runtime.receipts()[1]
            except Exception:
                report["partial_receiver_receipts_available"] = False
    finally:
        report["cleanup"] = {"owned_services_stopped": False, "private_profile_retained": bool(runtime)}
        if runtime:
            try:
                report["cleanup"]["owned_services_stopped"] = runtime.cleanup()
            except Exception as error:
                report["cleanup"]["error_type"], report["status"] = type(error).__name__, "incomplete"
            if report["status"] == "pass" and report["cleanup"]["owned_services_stopped"]:
                try:
                    shutil.rmtree(runtime.directory)
                    report["cleanup"]["private_profile_retained"] = False
                except OSError:
                    report["status"] = "incomplete"
            elif report["status"] == "pass":
                report["status"] = "incomplete"
        report["finished_at_utc"] = now()
        output.save(report)
    print(json.dumps({"status": report["status"], "evidence": str(args.out), "checks": len(report["checks"])}), flush=True)
    return 0 if report["status"] == "pass" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--no-build", action="store_true", help="reuse only an image labelled with this exact source revision")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(plan(), indent=2))
        return 0
    if args.out is None:
        parser.error("--execute requires a fresh --out")
    try:
        return execute(args)
    except Exception as error:
        print(json.dumps({"status": "incomplete", "error_type": type(error).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
