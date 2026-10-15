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
              ┌───────────────┐  POST /rollout/pause  ┌───────────────┐
       ┌─────►│     pilot     │──────────────────────►│    paused     │
       │      └───────┬───────┘◄──────────────────────└───────────────┘
       │              │ all pilots ack 'applied' POST /rollout/resume
manual │              ▼
advance│      ┌───────────────┐  POST /rollout/pause  ┌───────────────┐
       └──────│   standard    │──────────────────────►│    paused     │
              └───────┬───────┘◄──────────────────────└───────────────┘
                      │          POST /rollout/resume
                      │ rejection or timeout (>300s)
                      ▼
              ┌───────────────┐
              │ rolling_back  │ (rollback deployments issued to last applied baseline)
              └───────┬───────┘
                      │ all affected agents report 'applied' for rollback deployment
                      ▼
              ┌───────────────┐
              │  rolled_back  │ (confirmed safe baseline restoration)
              └───────────────┘
                      ▲
                      │ (if all standards report 'applied')
              ┌───────┴───────┐
              │   completed   │
              └───────────────┘
```

1. **Exact-Candidate Canary Gate & Collision Rejection**
   - Pre-existing revisions with identical revision names but differing policy SHA-256 digests fail-closed immediately with a revision collision error.
   - Deployments must match the exact candidate SHA-256 digest to satisfy canary promotion.
2. **Phase: `pilot`**
   - Candidate policy revision is signed and deployed **only** to agents marked `is_pilot: true`.
   - Standard workers remain on their active baseline policy and receive `204 No Content` when polling `/agent/v1/policy`.
3. **Phase: `paused`**
   - Operators can pause rollout at any time via `/rollout/pause` and resume via `/rollout/resume`.
   - While paused, rollouts do not automatically promote to subsequent phases.
4. **Phase: `standard`**
   - Automatically triggered when all pilot members report `applied` via `/agent/v1/policy/ack` matching candidate digest.
   - Candidate policy revision is signed and deployed to all standard workers.
5. **Phase: `completed`**
   - Automatically entered when all standard workers report `applied`.
6. **Phase: `rolling_back` -> `rolled_back` (Confirmed Rollback State Machine)**
   - Triggered immediately if **any** pilot or standard agent reports `rejected` or times out (>300s awaiting acknowledgement).
   - Rollout enters `rolling_back` (pending rollback), issuing rollback deployments pointing to the **previously acknowledged applied deployment baseline** (not unapplied drafts).
   - Rollout transitions to `rolled_back` **only** once agents have fetched and reported `applied` for the rollback deployment.
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
| `POST` | `/admin/v1/tenants/:t/groups/:g/rollout/pause` | Pause active group rollout |
| `POST` | `/admin/v1/tenants/:t/groups/:g/rollout/resume` | Resume paused group rollout |

---

## 3. Automated Verification & Demonstration

The complete multi-process demonstration script runs against live `llm-firewall` and real `agentfw serve` daemons:

```bash
python3 scripts/managed-group-rollout-demo.py
```

The script executes three realistic scenarios:
1. **Scenario 1: Canary Staged Rollout**:
   - Launches Console and 3 real `agentfw serve` daemons (1 pilot, 2 standard workers).
   - Starts staged rollout of `v1-allow`.
   - Verifies pilot applies sequence 1 first while workers remain untouched.
   - Verifies rollout advances to `standard` upon pilot ack.
   - Verifies standard workers apply sequence 1 and rollout reaches `completed`.
2. **Scenario 2: Automatic Confirmed Rollback on Pilot Rejection**:
   - Starts staged rollout of `v2-untrusted` signed with an unpinned key.
   - Pilot agent rejects candidate verification due to zero-trust key pinning.
   - Console intercepts rejection, enters `rolling_back`, and deploys monotonic rollback sequence 3 of safe baseline `v1-allow` to the pilot.
   - Pilot applies rollback and reports `applied`, transitioning rollout to confirmed `rolled_back`.
   - Standard workers remain on safe baseline sequence 1 and never receive `v2-untrusted`.
3. **Scenario 3: Pause & Resume Controls**:
   - Starts candidate rollout.
   - Pauses rollout via `/rollout/pause` (`phase = 'paused'`).
   - Resumes rollout via `/rollout/resume` (`phase = 'pilot'`).

Captured demonstration evidence is stored at:
`docs/operations/evidence/managed-policy-group-rollout-2026-10-15.json`
