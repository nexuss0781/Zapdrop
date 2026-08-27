# Zapdrop Phase 17 Control-Plane Slice

**Status:** Feature-gated topology planning and opaque encrypted-piece relay storage slice complete; wire-level tree/mesh integration remains open.

This slice adds the explicit `swarm-tree-mesh` Cargo feature, which depends on the experimental `swarm-v2` feature. The default build and the ordinary `swarm-v2` build do not enable tree/mesh planning. The new `plan_topology` function evaluates a tree or mesh job only when an authorized and consented relay satisfies the candidate capacity constraints and a matching `RelayGrant` is supplied.

A successful relay plan is bound to the exact job ID and snapshot root and carries only the grant’s authorized relay, child set, object allow-list, byte budget, and expiry. Direct and queued jobs always produce an explicit direct fallback, even if a relay candidate is present. A missing grant, no eligible candidate, or a grant byte budget smaller than the planned transfer also produces a direct fallback. Invalid or candidate-mismatched grants fail closed rather than producing a relay plan.

The slice also adds `RelayPieceEnvelope` and `RelayPieceStore`. A relay stores and returns the already-encrypted v2 piece envelope; it never receives the job decryption key and does not decrypt or re-encrypt payload bytes. Insertion validates the exact job, authorized child, allowed object, grant expiry, piece header, ciphertext length, and ciphertext SHA-256. Storage is bounded to 1,024 pieces and 64 MiB per in-memory store, with idempotent retransmission of an identical piece and rejection of conflicting duplicates.

## Verification

| Check | Result |
|---|---|
| Default v1 build | Existing default behavior remains unchanged. |
| Explicit feature gate | `swarm-tree-mesh` is separate from default and depends on `swarm-v2`. |
| Direct fallback | Direct and queued jobs never produce a relay plan. |
| Relay scope | A valid plan preserves job, snapshot, relay, child, object, byte, and expiry scope from the validated grant. |
| Fail-closed behavior | Invalid grants and relay-candidate mismatches are rejected; missing capability or insufficient budget falls back to direct transfer. |
| Relay storage | Opaque encrypted-piece storage validates scope, digest, quota, authorized child, unauthorized object, tampering, and idempotent duplicate behavior. |
| Automated tests | Five mesh tests pass in the feature-gated lane, including topology-planner and relay-storage coverage. |

## Honest boundary

Wire-level tree or mesh branch assignment, relay connection orchestration, parent failover, revocation propagation, multi-process source-upload measurement, and end-to-end relay routing are not implemented in this slice. The relay store is a tested bounded primitive, not a live network service. The existing v2 direct path remains the only production transfer path. This is not physical-LAN, Windows-runtime, production-security, or release qualification. The next Phase 17 slice must integrate the validated plan and opaque envelope into a bounded authenticated control exchange without enabling arbitrary relay requests or forwarding unrelated objects.
