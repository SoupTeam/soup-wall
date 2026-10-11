# Proposed owner-level semantic review and propagation protocol

**This is a draft for approval. It cannot by itself confer `confirmed` or gold status.**

1. **Pin the inputs.** Record the immutable dataset artifact digest, the normalized case IDs, the split, the
   registry program, the trace and evidence hashes, the unknown masks and the SOU-10 contract revision. Do
   not edit the frozen source.
2. **Owner review per variant.** The owner reviews each **unique executed semantic variant**, including
   conditional branches and opaque components. For each variant, record:
   - a human decision;
   - a reason tied to the operation and the typed trace;
   - the specific per-case evidence personally inspected.

   Human observation and rule propagation are separate provenance channels.
3. **Deterministic per-case check.** A script checks each candidate independently against the approved rule
   signature, the **executed branch**, the actual arguments, the typed access log, the audit status, the mask,
   the source's proposed labels and the evidence digests. A mismatch fails closed to `needs_review`. Re-run the
   check after any versioned change.
4. **Limits on propagation.**
   - Never propagate through opaque or misleading metadata, variable control flow or partial evidence, unless
     the approved variant explicitly encodes and justifies it.
   - Keep proven positive labels, and keep `null` for indeterminate effects.
   - Never silently coerce `null` to `false`, and never treat outbox audit writes as a generic write.
5. **Flag contract interpretations for adjudication.** These are Q-ADMISSION, Q-CP2-DECL-EVIDENCE, Q-FUTURE,
   Q-DEV09, Q-CP2-ACK and Q-DEV06-STEPS. They also include whether internal ACL `acl_read` access and
   `delete_prefix` `keys` access count as an independent `read` effect.
6. **Independent validation.** A named, **authorized** independent reviewer validates the protocol's scope, a
   reproducible sample and every disputed item. Developer technical feedback does not automatically count as
   independent gold sign-off.
7. **Record decisions only in a versioned gold addendum**
   ([`schema/gold_addendum.schema.json`](../../../eval/sou13/schema/gold_addendum.schema.json), checked by
   `eval/sou13/scripts_cp2/validate_gold_addendum.py`). Each entry names:
   - the case ID;
   - the frozen label-row digest and the input, argument and definition digests;
   - the status transition;
   - the decision IDs;
   - the adjudication channel.

   Approvals record the approver, the role, the date and a statement. Addenda are append-only and
   hash-chained, and they never modify the frozen snapshot.
8. **Promote only eligible cases.** Promote only the eligible subset, and only after all applicable approvals.
   The interface accepts `confirmed` only with `independent_human` adjudication that references an
   `independent_reviewer` approval. Pending cases stay pending. Masked-target denominators stay unchanged.

Acceptance metrics must keep these four groups separate:
- evidence inspected by the owner;
- reviewed by the owner as a family batch;
- propagated from owner rules and machine-verified;
- gold adjudicated by an independent human.

Report action-known mask coverage separately from the unknown flag. This procedure is a proposal for
approval. It is not evidence that approval has happened.
