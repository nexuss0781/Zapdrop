# Zapdrop Phase 9 Status

**Status:** Least-privilege tree/mesh control-plane foundation implemented; forwarding integration remains gated.

Phase 9 adds signed relay-grant data structures that bind a relay to one job, one snapshot root, an authorized child set, an explicit `ForwardPiece` operation, an allowed object set, a byte budget, and an expiry no later than the parent job. Direct and queued jobs reject relay grants. The control plane also rejects duplicate or unauthorized children and disallows a relay from granting itself as a child.

Topology candidates are scored only when the peer is authorized by the job, has explicitly consented to relay, has adequate capacity, and reports finite bounded measurements. A branch-revocation object provides job-scoped peer revocation semantics for future transport integration.

The current slice intentionally does not enable peer forwarding, relay storage, or tree/mesh routing on the wire. Those operations require encrypted capability delivery, per-piece grant enforcement, parent failover, revocation propagation, privacy review, and physical multi-PC qualification. Until those gates are complete, v2 remains direct-only and feature-gated.
