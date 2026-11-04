# Individual Agent signed policy operations (SOU-227)

Select a tenant in Console, then an enrolled Agent in **Individual Agent signed
policy**. This panel controls signed AgentPolicySet policies. Owner is required
for every mutation; Viewer and Operator can inspect recorded evidence. Existing
group preview and heartbeat interfaces are unchanged.

1. Create an immutable revision from exact AgentPolicySet YAML and a new revision
   ID. Creation does not approve or issue the policy.
2. Select the revision. Review its exact server YAML and SHA-256. The browser
   independently verifies that digest before enabling approval or deployment.
3. Explicitly approve the reviewed revision. Refresh/read back before issuance.
4. Confirm deployment for the selected tenant/Agent, revision/digest and signer.
   A random Idempotency-Key is allocated only after that confirmation.
5. Refresh to inspect issued, delivered, applied or rejected records. A revoked
   enrollment is displayed separately and disables new mutation.
6. To roll back, select and review an approved historical revision different
   from the latest deployment, then explicitly confirm historical rollback. The
   engine signs a **new higher-sequence** deployment; it never replays an old
   signed envelope to restore policy.

The server checks the Console's observed `expected_sequence` in the issuance
transaction. Changed inventory or ownership by a persisted active group rollout
(including a paused plan or a frozen worker removed from live membership) returns
409 with no deployment/key allocation. Refresh, review the new state and confirm
again. This optional guard requires Idempotency-Key. Existing keyless and
unguarded SOU-219 API behavior and persisted digests are preserved byte-for-byte.

If a deployment response is lost, its outcome is explicitly unresolved. Use
**Retry exact deployment intent**: the same URL, key, action, signer selection and
observed sequence are presented to the durable server record. An existing key is
reconciled before new-issuance preconditions, so an applied ACK or a later group
rollout cannot cause extra issuance. A changed intent requires fresh review and
confirmation. Retries never silently renew sequence, envelope or expiry. A key
is scoped to tenant, Agent and authenticated admin and never grants authority.
The intent map holds at most 16 Agent scopes in page memory; unresolved entries
are not evicted. Closing/reloading the tab loses this local map: inspect server
history before explicitly confirming a new operation. No automatic issuance
occurs on refresh, readback, page load or selection change.

401/403, revoked Agents, mismatched identities/YAML/digests, unavailable evidence
and stale asynchronous replies cannot enable a new mutation. GETs are cancelled
on selection changes; confirmed POSTs retain their captured scope and do not
write responses into another selection. Create/approve recheck current Owner
and Agent eligibility within the backend transaction as well as existing HTTP
middleware. Credentials remain in the existing dashboard memory boundary;
policies and raw errors are not added to logs. Draft YAML is cleared on tenant
or Agent switches. The panel uses text nodes for all server content.

Applied acknowledgement is historical evidence for an exact sequence/revision/
digest, not proof of current runtime protection. Consult fleet freshness and
local Agent health separately. Sequence values outside JavaScript's exact
integer range leave the panel unresolved. Deployment readback shows the existing
latest 50 records. Revision discovery is keyset-paged with 1–100 summaries
(default 50), followed by one bounded exact YAML read:

- `GET /admin/v1/tenants/:tenant/agents/:agent/revisions?limit=50&after=ID`
- `GET /admin/v1/tenants/:tenant/agents/:agent/revisions/:revision`

These authorized GETs allocate no issuance/key and introduce no new schema,
migration or recovery inventory entry.

## Runnable acceptance

```sh
cargo test --locked -p llm-firewall --test managed_deployment_idempotency
SOUP_DEPLOY_TEST_POSTGRES_URL="$OWNED_DISPOSABLE_DATABASE_URL" cargo test --locked -p llm-firewall --test managed_deployment_idempotency postgres_deployment_idempotency_over_http -- --ignored
python3 -B -m unittest scripts/tests/test_console_single_policy_browser.py -v
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/console-single-policy-acceptance.py --no-build --backend sqlite --output /tmp/single-policy-evidence
python3 -B scripts/console-single-policy-acceptance.py --no-build --backend postgres --output /tmp/single-policy-evidence
```

Use the existing pinned Playwright driver and Chromium. The PostgreSQL witness
uses the existing disposable local TLS fixture, never a production database.
The browser drives creation, review, approval, delivery, lost-response retry and
rollback while a real Agent independently applies/acknowledges the signed bundles.
`agent-fleet.yml` and its generated component retain sanitized reports including
failed attempts, source/configuration and binary identities. Profiled PostgreSQL
HTTP controls also run in `managed-group-rollout.yml`. A browser runtime skip is
not acceptance evidence.
