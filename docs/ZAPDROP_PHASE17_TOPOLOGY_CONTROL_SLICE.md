# Zapdrop Phase 17 Control-Plane Slice

**Status:** Feature-gated topology planning, opaque encrypted-piece relay storage, and authenticated branch-assignment/connection control slice complete; live relay socket dispatch remains open.

This slice adds the explicit `swarm-tree-mesh` Cargo feature, which depends on the experimental `swarm-v2` feature. The default build and the ordinary `swarm-v2` build do not enable tree/mesh planning. The new `plan_topology` function evaluates a tree or mesh job only when an authorized and consented relay satisfies the candidate capacity constraints and a matching `RelayGrant` is supplied.

A successful relay plan is bound to the exact job ID and snapshot root and carries only the grant’s authorized relay, child set, object allow-list, byte budget, and expiry. Direct and queued jobs always produce an explicit direct fallback, even if a relay candidate is present. A missing grant, no eligible candidate, or a grant byte budget smaller than the planned transfer also produces a direct fallback. Invalid or candidate-mismatched grants fail closed rather than producing a relay plan.

The slice also adds `RelayPieceEnvelope` and `RelayPieceStore`. A relay stores and returns the already-encrypted v2 piece envelope; it never receives the job decryption key and does not decrypt or re-encrypt payload bytes. Insertion validates the exact job, authorized child, allowed object, grant expiry, piece header, ciphertext length, and ciphertext SHA-256. Storage is bounded to 1,024 pieces and 64 MiB per in-memory store, with idempotent retransmission of an identical piece and rejection of conflicting duplicates.

Branch assignments and relay connection requests/responses are now explicit, typed, and encrypted with dedicated associated data on the ordered v2 secure channel. Each assignment binds the job, snapshot, signed sender as parent, authorized relay and child, object allow-list, byte budget, expiry, and nonce. The `RelayConnectionOrchestrator` admits at most eight child assignments, rejects duplicate branches, and advances a child only from `Assigned` to `Connected` after a matching response. The response nonce and all job/snapshot/relay/child fields are checked before the state transition.

## Verification

| Check | Result |
|---|---|
| Default v1 build | Existing default behavior remains unchanged. |
| Explicit feature gate | `swarm-tree-mesh` is separate from default and depends on `swarm-v2`. |
| Direct fallback | Direct and queued jobs never produce a relay plan. |
| Relay scope | A valid plan preserves job, snapshot, relay, child, object, byte, and expiry scope from the validated grant. |
| Fail-closed behavior | Invalid grants and relay-candidate mismatches are rejected; missing capability or insufficient budget falls back to direct transfer. |
| Relay storage | Opaque encrypted-piece storage validates scope, digest, quota, authorized child, unauthorized object, tampering, and idempotent duplicate behavior. |
| Wire assignment | Dedicated-AAD encrypted branch assignment and relay connection request/response messages round-trip over ordered secure channels. |
| Connection orchestration | Assignment and response state transitions are bounded, duplicate-safe, nonce-bound, and fail closed on child or scope tampering. |
| Automated tests | Eight mesh tests pass in the feature-gated lane, including topology-planner, relay-storage, wire-message, and orchestration coverage. |

## Honest boundary

Live relay socket/session dispatch, parent failover, revocation propagation, multi-process source-upload measurement, and end-to-end multi-process relay routing are not implemented in this slice. The encrypted wire helpers and orchestrator are tested control-plane primitives; the relay store is not yet a live network service. The existing v2 direct path remains the only production transfer path. This is not physical-LAN, Windows-runtime, production-security, or release qualification. The next Phase 17 slice must connect the authenticated control messages to a bounded relay listener/session without enabling arbitrary relay requests or forwarding unrelated objects.
