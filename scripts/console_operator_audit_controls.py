# SPDX-License-Identifier: Apache-2.0
"""Privacy-safe operator audit witnesses against the real Console fixture."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import secrets
import sqlite3
import subprocess
from urllib.parse import urlencode, urlsplit


def database(backend, console_dir, postgres_url, ca, binaries, env):
    """Return a fixture-only SQL runner. Database credentials are never in argv."""
    if backend == "sqlite":
        def sql(query):
            with sqlite3.connect(console_dir / "console.sqlite", timeout=10) as db:
                db.executescript(query)
        return sql
    url = urlsplit(postgres_url)
    pg_env = dict(env, PGHOST=url.hostname, PGPORT=str(url.port), PGDATABASE=url.path[1:],
                  PGUSER=url.username, PGPASSWORD=url.password, PGSSLMODE="verify-full", PGSSLROOTCERT=str(ca))
    def sql(query):
        result = subprocess.run([str(binaries / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1"],
                                input=query.encode(), env=pg_env, capture_output=True, timeout=30)
        assert result.returncode == 0, "PostgreSQL fixture SQL failed"
    return sql


def audit_controls(api, sql, backend, viewer, check, private):
    def expected(code, method, path, payload=None, **kwargs):
        status, body = api(method, path, payload, **kwargs)
        assert status == code, f"Unexpected status {status} for {method} {path.split('?')[0]}"
        return body

    tenant = expected(201, "POST", "/admin/v1/tenants", {"name": "Audit Alpha"})["id"]
    other = expected(201, "POST", "/admin/v1/tenants", {"name": "Audit Beta"})["id"]
    actor = expected(201, "POST", "/admin/v1/admins", {"name": "Audit fixture owner", "role": "owner"})
    owner = actor["token"]
    private.append(owner)
    actor_id = actor["admin"]["id"]
    viewer_id = expected(200, "GET", "/admin/v1/whoami", token=viewer)["admin_id"]
    base = f"/admin/v1/tenants/{tenant}"
    audit = base + "/operator-audit"
    peer = f"/admin/v1/tenants/{other}"
    agent = "."
    scope = "?" + urlencode({"agent_id": agent})
    revision_scope = "?" + urlencode({"agent_id": agent, "revision": "audit-r1"})
    private_yaml = "owned-policy-payload-" + secrets.token_hex(12)
    token = expected(201, "POST", base + "/agents", {"agent_id": agent}, token=owner)["token"]
    private.extend([token, private_yaml])
    expected(400, "POST", base + "/agents", {"agent_id": agent}, token=owner)
    expected(403, "POST", base + "/agents/revoke" + scope, {}, token=viewer)
    expected(401, "POST", base + "/agents/revoke" + scope, {}, token=token)
    lookup = expected(200, "GET", base + "/agents/enrollment" + scope, token=viewer)
    check("dot-agent-addressable-and-private-inventory", lookup["agent_id"] == agent
          and lookup["credential_generation"] == 1 and token not in json.dumps(lookup))
    created = expected(201, "POST", base + "/agents/policy-revisions" + scope,
                       {"revision": "audit-r1", "policy_yaml": "default: deny\n# " + private_yaml}, token=owner)
    expected(204, "POST", base + "/agents/policy-revision/approve" + revision_scope, {}, token=owner)
    endpoint = base + "/agents/policy-revision/deploy" + revision_scope
    key = "audit-controlled-" + secrets.token_hex(12)
    private.append(key)

    # A trigger suppresses the audit insert without a database error. The store
    # must check affected rows, roll back the issuance and leave its key reusable.
    if backend == "sqlite":
        suppress = ("CREATE TRIGGER audit_fixture_suppress BEFORE INSERT ON operator_audit_events "
                    "WHEN NEW.outcome='committed' BEGIN SELECT RAISE(IGNORE); END;")
        reset = "DROP TRIGGER audit_fixture_suppress;"
    else:
        suppress = ("CREATE FUNCTION audit_fixture_suppress() RETURNS trigger LANGUAGE plpgsql AS "
                    "$$ BEGIN IF NEW.outcome='committed' THEN RETURN NULL; END IF; RETURN NEW; END; $$; "
                    "CREATE TRIGGER audit_fixture_suppress BEFORE INSERT ON operator_audit_events "
                    "FOR EACH ROW EXECUTE FUNCTION audit_fixture_suppress();")
        reset = ("DROP TRIGGER audit_fixture_suppress ON operator_audit_events;"
                 "DROP FUNCTION audit_fixture_suppress();")
    sql(suppress)
    try:
        failed, _ = api("POST", endpoint, {"expected_sequence": 0}, token=owner, idempotency=key)
        still_empty = expected(200, "GET", base + "/agents/policy-deployments" + scope, token=owner)
        refused_enrollment, _ = api("POST", base + "/agents", {"agent_id": "audit-suppressed"}, token=owner)
        absent, _ = api("GET", base + "/agents/enrollment?agent_id=audit-suppressed", token=owner)
        check("audit-write-suppressed-rolls-back-issuance-key-and-enrollment",
              failed >= 400 and still_empty == [] and refused_enrollment >= 400 and absent == 404)
    finally:
        sql(reset)

    def deploy():
        return api("POST", endpoint, {"expected_sequence": 0}, token=owner, idempotency=key)
    with ThreadPoolExecutor(max_workers=2) as workers:
        a, b = [work.result() for work in (workers.submit(deploy), workers.submit(deploy))]
    check("concurrent-idempotent-deployment-issues-once",
          a[0] == b[0] == 201 and all(row["deployment_sequence"] == 1 for _, row in (a, b))
          and sorted([a[1]["idempotency"]["replayed"], b[1]["idempotency"]["replayed"]]) == [False, True])

    gateway = base + "/policy-versions"
    versions = []
    for model in ("audit-model-a", "audit-model-b"):
        version = expected(201, "POST", gateway, {"document": {"schema_version": 1,
                           "model_policy": {"allowed_models": [model]}}}, token=owner)
        versions.append(version["id"])
        expected(200, "POST", f"{gateway}/{version['id']}/approve", token=owner)
        expected(200, "POST", f"{gateway}/{version['id']}/activate", token=owner)
    sql(suppress)
    try:
        refused, _ = api("POST", f"{gateway}/{versions[0]}/rollback", token=owner)
        active = expected(200, "GET", base + "/model-policy", token=owner)
        check("audit-write-suppressed-preserves-active-gateway-policy",
              refused >= 400 and active["allowed_models"] == ["audit-model-b"])
    finally:
        sql(reset)
    expected(200, "POST", f"{gateway}/{versions[0]}/rollback", token=owner)

    group = base + "/groups/audit-group"
    cohort_token = expected(201, "POST", base + "/agents", {"agent_id": "cohort-1"}, token=owner)["token"]
    private.append(cohort_token)
    cohort = base + "/agents/cohort-1/revisions"
    expected(201, "POST", cohort, {"revision": "baseline", "policy_yaml": "default: allow\n"}, token=owner)
    expected(204, "POST", cohort + "/baseline/approve", {}, token=owner)
    baseline = expected(201, "POST", cohort + "/baseline/deploy", {}, token=owner)
    expected(200, "GET", "/agent/v1/policy", bearer=cohort_token)
    expected(204, "POST", "/agent/v1/policy/ack",
             {"deployment_sequence": baseline["deployment_sequence"], "revision": baseline["revision"],
              "policy_sha256": baseline["policy_sha256"], "status": "applied"}, bearer=cohort_token)
    expected(201, "POST", base + "/groups", {"group_id": "audit-group", "name": "Audit group"}, token=owner)
    expected(201, "POST", group + "/members", {"agent_id": "cohort-1", "is_pilot": True}, token=owner)
    expected(201, "POST", group + "/revisions", {"revision": "cohort-r1", "policy_yaml": "default: deny\n"}, token=owner)
    expected(204, "POST", group + "/revisions/cohort-r1/approve", {}, token=owner)
    preview = expected(200, "POST", group + "/rollout/preview", {"revision": "cohort-r1"}, token=owner)
    confirmation = preview["confirmation"]["id"]
    private.append(confirmation)
    body = {"revision": "cohort-r1", "confirmation_id": confirmation}
    started = expected(201, "POST", group + "/rollout", body, token=owner)
    replay = expected(201, "POST", group + "/rollout", body, token=owner)
    check("guarded-rollout-replay-keeps-original-fact", started["rollout_id"] == replay["rollout_id"]
          and replay["confirmation"]["replayed"])
    expected(200, "POST", group + "/rollout/pause", {}, token=owner)
    expected(200, "POST", group + "/rollout/pause", {}, token=owner)
    expected(200, "POST", group + "/rollout/rollback", {}, token=owner)

    def rotate():
        replacement = "sw_agent_" + secrets.token_urlsafe(32)
        rotation = {"expected_generation": 1, "operation_id": secrets.token_hex(16),
                    "replacement_token": replacement}
        code, receipt = api("POST", base + "/agents/credential-rotations" + scope, rotation, token=owner)
        return code, receipt, rotation
    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = [work.result() for work in (workers.submit(rotate), workers.submit(rotate))]
    winner = next(r for r in (first, second) if r[0] == 200)
    check("concurrent-rotation-records-one-winner", sorted([first[0], second[0]]) == [200, 409])
    private.extend(r[2]["replacement_token"] for r in (first, second))
    identical = expected(200, "POST", base + "/agents/credential-rotations" + scope, winner[2], token=owner)
    check("identical-rotation-replays-without-audit-duplicate", identical["already_applied"] and identical["generation"] == 2)
    expected(401, "GET", "/agent/v1/whoami", bearer=token)
    expected(200, "GET", "/agent/v1/whoami", bearer=winner[2]["replacement_token"])
    expected(204, "POST", base + "/agents/revoke" + scope, token=owner)
    expected(401, "GET", "/agent/v1/whoami", bearer=winner[2]["replacement_token"])

    # The independent attempts quota cannot evict committed records. Seed an
    # owned refusal history and make a genuine denial cross the retention cap.
    assert re.fullmatch("[a-zA-Z0-9_-]+", other)
    values = ",".join(f"('{other}',1,'unavailable','agent.enroll','tenant','{other}','denied')" for _ in range(500))
    token_shaped_id = "llmfw_admin_" + secrets.token_urlsafe(32)
    private.extend([token_shaped_id, expected(201, "POST", peer + "/agents", {"agent_id": token_shaped_id}, token=owner)["token"]])
    sql("INSERT INTO operator_audit_events(tenant_id,received_at_unix,actor_kind,operation,target_kind,target_id,outcome) VALUES " + values + ";")
    expected(403, "POST", peer + "/agents", {"agent_id": "forbidden"}, token=viewer)

    def read_page(path, cursor=None, limit=5):
        query = {"limit": limit}
        if cursor:
            query["before"] = cursor
        return expected(200, "GET", path + "?" + urlencode(query), token=viewer)

    first_page = read_page(audit)
    expected(400, "GET", peer + "/operator-audit?" + urlencode({"before": first_page["next_before"]}), token=viewer)
    expected(400, "GET", audit + "?limit=101", token=viewer)
    expected(401, "GET", audit, token=token)
    events, cursor = list(first_page["events"]), first_page["next_before"]
    for _ in range(20):
        if cursor is None:
            break
        page = read_page(audit, cursor)
        events.extend(page["events"])
        cursor = page["next_before"]
    event_ids = [int(row["event_id"]) for row in events]
    check("tenant-bound-keyset-pages-stable-and-bounded", cursor is None and event_ids == sorted(set(event_ids), reverse=True)
          and all(row["tenant_id"] == tenant for row in events))
    facts = [row for row in events if row["outcome"] == "committed"]
    refusal = [row for row in events if row["outcome"] == "denied"]
    check("verified-actor-or-explicitly-unavailable-and-denied-distinct",
          all(row["actor_kind"] == "admin" and row["actor_id"] == actor_id for row in facts)
          and any(row["actor_id"] == viewer_id and row["operation"] == "agent.revoke" for row in refusal)
          and any(row["actor_kind"] == "unavailable" and row["actor_id"] is None for row in refusal)
          and any(row["outcome"] == "failed" for row in events))
    deployed = [row for row in facts if row["operation"] == "agent_policy.deploy" and row["target_id"] == agent]
    check("exact-stable-target-revision-digest-and-one-deployment-fact",
          len(deployed) == 1 and deployed[0]["target_id"] == agent and deployed[0]["source_ref"] == "audit-r1"
          and deployed[0]["source_sha256"] == created["policy_sha256"] and deployed[0]["source_sequence"] == "1")
    operations = [row["operation"] for row in facts]
    check("agent-policy-and-rollout-facts-are-single-commits",
          all(operations.count(op) == count for op, count in {
              "agent.enroll": 2, "agent.rotate": 1, "agent.revoke": 1, "policy.create": 2,
              "policy.approve": 2, "policy.activate": 2, "policy.rollback": 1,
              "rollout.start": 1, "rollout.pause": 1, "rollout.rollback": 1,
          }.items()))
    peer_events, cursor = [], None
    for _ in range(6):
        page = read_page(peer + "/operator-audit", cursor, limit=100)
        peer_events.extend(page["events"])
        cursor = page["next_before"]
        if cursor is None:
            break
    check("attempt-retention-does-not-evict-peer-commits",
          cursor is None and len(peer_events) == 501
          and all(row["tenant_id"] == other for row in peer_events)
          and sum(row["outcome"] == "committed" for row in peer_events) == 1)
    check("audit-contains-no-private-payload-or-credential",
          any(row["target_id"] == "sha256:" + hashlib.sha256(token_shaped_id.encode()).hexdigest()
              for row in peer_events)
          and not any(secret in json.dumps(events + peer_events) for secret in private))
    return {"tenant": tenant, "path": audit, "events": events}
