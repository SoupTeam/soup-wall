# Staged Managed Agent Group Policy Rollout (SOU-47)

> **Implementation & Verification Completed.** This document details the managed Agent group staged policy rollout mechanism (canary/pilot group first, followed by standard workers, with automated verification and failure rollback).

---

## 1. Architecture & Policy Separation

Managed Agent groups allow operators to organize enrolled agents into logical fleets (e.g. `prod-fleet`, `staging-cluster`) and roll out immutable, approved `AgentPolicySet` revisions in controlled stages.

### Group Membership Roles
- **Pilot Agents (`is_pilot: true`)**: The canary group. Receives candidate policy deployments first.
- **Standard Agents (`is_pilot: false`)**: The general fleet. Fully protected and insulated from candidate revisions until all pilot agents have verified and successfully applied the candidate policy.

### Rollout Lifecycle State Machine

```
              ┌───────────────┐
              │     idle      │
              └───────┬───────┘
                      │ POST /rollout
                      ▼
              ┌───────────────┐
       ┌─────►│     pilot     │────── pilot rejection ──────┐
       │      └───────┬───────┘                             │
       │              │ all pilots ack 'applied'            ▼
manual │              ▼                              ┌───────────────┐
advance│      ┌───────────────┐                      │  rolled_back  │
       └──────│   standard    │── standard rejection ┤ (safe baseline│
              └───────┬───────┘                      │  restored)    │
                      │ all standards ack 'applied'  └───────────────┘
                      ▼
              ┌───────────────┐
              │   completed   │
              └───────────────┘
```

1. **Phase: `pilot`**
   - Candidate policy revision is signed and deployed **only** to agents marked `is_pilot: true`.
   - Standard workers remain on their active baseline policy and receive `204 No Content` when polling `/agent/v1/policy`.
2. **Phase: `standard`**
   - Automatically triggered when all pilot members report `applied` via `/agent/v1/policy/ack`.
   - Candidate policy revision is signed and deployed to all standard workers.
3. **Phase: `completed`**
   - Automatically entered when all standard workers report `applied`.
4. **Phase: `rolled_back` (Automated Failure Recovery)**
   - Triggered immediately if **any** pilot or standard agent reports `rejected` (e.g., validation failure, regex error, unpinned issuer key).
   - The rollout state machine halts forward progression immediately.
   - For all agents that received candidate deployments, Console automatically issues **new monotonically numbered signed deployments** of each agent's previous known-good revision with `action: "rollback"`.
   - Workers that never received candidate deployments remain untouched on their safe baseline throughout.

---

## 2. Admin HTTP API Surface

Admin endpoints require control-plane authorization (`x-llm-firewall-admin-token: Bearer <token>`):

### Managed Groups
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/admin/v1/tenants/:t/groups` | Create managed group (`{"group_id":"...", "name":"..."}`) |
| `GET` | `/admin/v1/tenants/:t/groups` | List managed groups for tenant |
| `GET` | `/admin/v1/tenants/:t/groups/:g` | Get group details |
| `DELETE` | `/admin/v1/tenants/:t/groups/:g` | Delete managed group (cascades memberships) |

### Group Members
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/admin/v1/tenants/:t/groups/:g/members` | Add agent to group (`{"agent_id":"...", "is_pilot":bool}`) |
| `GET` | `/admin/v1/tenants/:t/groups/:g/members` | List members of group |
| `DELETE` | `/admin/v1/tenants/:t/groups/:g/members/:agent_id` | Remove agent from group |

### Group Revisions
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/admin/v1/tenants/:t/groups/:g/revisions` | Author group revision (`{"revision":"...", "policy_yaml":"..."}`) |
| `GET` | `/admin/v1/tenants/:t/groups/:g/revisions` | List group revisions |
| `POST` | `/admin/v1/tenants/:t/groups/:g/revisions/:r/approve` | Approve revision for rollout deployment |

### Staged Rollout Execution
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/admin/v1/tenants/:t/groups/:g/rollout` | Start staged rollout (`{"revision":"...", "issuer_key_id": optional}`). Returns 409 if rollout active. |
| `GET` | `/admin/v1/tenants/:t/groups/:g/rollout` | Get current/latest rollout status and agent phases |
| `POST` | `/admin/v1/tenants/:t/groups/:g/rollout/advance` | Manually advance rollout phase |
| `POST` | `/admin/v1/tenants/:t/groups/:g/rollout/rollback` | Manually trigger automated rollback of active rollout |

---

## 3. Automated Verification & Demonstration

The complete multi-process demonstration script runs against live `llm-firewall` and real `agentfw serve` daemons:

```bash
python3 scripts/managed-group-rollout-demo.py
```

The script executes two realistic scenarios:
1. **Scenario 1: Canary Staged Rollout**:
   - Launches Console and 3 real `agentfw serve` daemons (1 pilot, 2 standard workers).
   - Starts staged rollout of `v1-allow`.
   - Verifies pilot applies sequence 1 first while workers remain untouched.
   - Verifies rollout advances to `standard` upon pilot ack.
   - Verifies standard workers apply sequence 1 and rollout reaches `completed`.
2. **Scenario 2: Automatic Rollback on Pilot Rejection**:
   - Starts staged rollout of `v2-untrusted` signed with an unpinned key.
   - Pilot agent rejects candidate verification due to zero-trust key pinning.
   - Console intercepts rejection, marks rollout `rolled_back`, and deploys monotonic rollback sequence 3 of safe baseline `v1-allow` to the pilot.
   - Standard workers remain on safe baseline sequence 1 and never receive `v2-untrusted`.

Captured demonstration evidence is stored at:
`docs/operations/evidence/managed-policy-group-rollout-2026-10-15.json`
