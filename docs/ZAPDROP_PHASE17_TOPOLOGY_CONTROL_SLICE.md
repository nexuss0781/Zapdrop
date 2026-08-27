# Zapdrop Phase 17 Control-Plane Slice

**Status:** First Phase 17 slice complete; encrypted tree/mesh forwarding remains unimplemented and disabled.

This slice adds the explicit `swarm-tree-mesh` Cargo feature, which depends on the experimental `swarm-v2` feature. The default build and the ordinary `swarm-v2` build do not enable tree/mesh planning. The new `plan_topology` function evaluates a tree or mesh job only when an authorized and consented relay satisfies the candidate capacity constraints and a matching `RelayGrant` is supplied.

A successful relay plan is bound to the exact job ID and snapshot root and carries only the grant’s authorized relay, child set, object allow-list, byte budget, and expiry. Direct and queued jobs always produce an explicit direct fallback, even if a relay candidate is present. A missing grant, no eligible candidate, or a grant byte budget smaller than the planned transfer also produces a direct fallback. Invalid or candidate-mismatched grants fail closed rather than producing a relay plan.

## Verification

| Check | Result |
|---|---|
| Default v1 build | Existing default behavior remains unchanged. |
| Explicit feature gate | `swarm-tree-mesh` is separate from default and depends on `swarm-v2`. |
| Direct fallback | Direct and queued jobs never produce a relay plan. |
| Relay scope | A valid plan preserves job, snapshot, relay, child, object, byte, and expiry scope from the validated grant. |
| Fail-closed behavior | Invalid grants and relay-candidate mismatches are rejected; missing capability or insufficient budget falls back to direct transfer. |
| Automated tests | Four mesh tests pass in the feature-gated lane, including the two new topology-planner tests. |

## Honest boundary

No tree or mesh data-plane frame, relay storage, encrypted piece forwarding, branch assignment on the wire, parent failover, revocation propagation, or source-upload measurement is implemented in this slice. The existing v2 direct path remains the only transfer path. This is not physical-LAN, Windows-runtime, production-security, or release qualification. The next Phase 17 slice must integrate the validated plan into a bounded control exchange without enabling arbitrary relay requests or forwarding unrelated objects.
