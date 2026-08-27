# Zapdrop Phase 17 Tree/Mesh Integration

**Status:** Complete as a feature-gated experimental direct-only tree/mesh integration. Topology planning, opaque encrypted-piece relay storage, authenticated branch control, live listener/session dispatch, parent-to-child routing, revocation enforcement, direct fallback, and loopback qualification are complete.

This slice adds the explicit `swarm-tree-mesh` Cargo feature, which depends on the experimental `swarm-v2` feature. The default build and the ordinary `swarm-v2` build do not enable tree/mesh planning. The new `plan_topology` function evaluates a tree or mesh job only when an authorized and consented relay satisfies the candidate capacity constraints and a matching `RelayGrant` is supplied.

A successful relay plan is bound to the exact job ID and snapshot root and carries only the grant’s authorized relay, child set, object allow-list, byte budget, and expiry. Direct and queued jobs always produce an explicit direct fallback, even if a relay candidate is present. A missing grant, no eligible candidate, or a grant byte budget smaller than the planned transfer also produces a direct fallback. Invalid or candidate-mismatched grants fail closed rather than producing a relay plan.

The slice also adds `RelayPieceEnvelope` and `RelayPieceStore`. A relay stores and returns the already-encrypted v2 piece envelope; it never receives the job decryption key and does not decrypt or re-encrypt payload bytes. Insertion validates the exact job, authorized child, allowed object, grant expiry, piece header, ciphertext length, and ciphertext SHA-256. Storage is bounded to 1,024 pieces and 64 MiB per in-memory store, with idempotent retransmission of an identical piece and rejection of conflicting duplicates.

Branch assignments and relay connection requests/responses are now explicit, typed, and encrypted with dedicated associated data on the ordered v2 secure channel. Each assignment binds the job, snapshot, signed sender as parent, authorized relay and child, object allow-list, byte budget, expiry, and nonce. The `RelayConnectionOrchestrator` admits at most eight child assignments, rejects duplicate branches, and advances a child only from `Assigned` to `Connected` after a matching response. The response nonce and all job/snapshot/relay/child fields are checked before the state transition.

`RelayListener` provides the live feature-gated TCP session boundary. It accepts at most eight concurrent sessions, performs the existing signed ephemeral v2 handshake against an exact trusted peer record, receives a bounded encrypted session-start frame, verifies the job sender key/fingerprint and relay grant, and sends an authenticated connection response. Parent sessions ingest only scoped encrypted relay-data frames into a bounded store; child sessions can request only the exact assigned object/piece and receive the stored ciphertext without the relay possessing a content decryption key. The worker stops cleanly when the listener is dropped; rejected trust, identity, scope, revocation, or framing conditions do not create relay state.

The parent-to-relay-to-child path is qualified over loopback with two authenticated sessions. The parent uploads one opaque encrypted piece, the child requests it by object/piece/index, and the child receives an identical ciphertext envelope. A parent revocation is acknowledged over the authenticated channel and subsequent child requests receive no payload. Each completed session reports bounded piece count, ciphertext bytes, and elapsed duration for measurement evidence. A relay failure converts the selected topology plan into an explicit direct fallback through `fallback_after_relay_failure`.

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
| Live listener | A real loopback TCP session completes trusted v2 handshake, session-start authorization, authenticated response, and opaque piece ingestion. |
| Parent-to-child routing | A trusted parent uploads an encrypted piece and a separately authenticated trusted child retrieves the identical ciphertext through the relay. |
| Revocation | A parent revocation is validated, acknowledged, and enforced before subsequent child retrieval; revoked children receive no payload. |
| Direct fallback | A relay plan can be converted to an explicit direct fallback after connection failure; planner tests also cover direct-only jobs and missing grants. |
| Measurements | Completed parent and child sessions report pieces, ciphertext bytes, and bounded elapsed duration. |
| Listener bounds | Socket frames are length-prefixed and bounded; active sessions are capped at eight and session-start control payloads at 1 MiB. |
| Automated tests | Nine mesh tests pass in the feature-gated lane, including topology planning, relay storage, encrypted wire, parent/child routing, revocation, orchestration, and live-listener coverage. |

## Honest boundary

Phase 17 is complete within its explicit experimental boundary. The implementation is a bounded direct-only tree/mesh control and routing path behind `swarm-tree-mesh`; it is not enabled in default v1 or ordinary v2 builds. The loopback evidence is not physical-LAN, Windows-runtime, packet-capture, independent-security-review, production-certification, or release qualification. Parent failover is represented by explicit direct fallback, but no automatic alternate-relay migration is claimed. Phase 18 is the next separate phase for repair evaluation. Phase 20 remains the only release phase.
