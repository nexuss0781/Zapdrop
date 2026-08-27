# Zapdrop Phase 15 Cross-Snapshot Object Integration

**Status:** Local cross-snapshot reuse and object-catalog integration implemented and qualified; network object retrieval remains open.

The snapshot engine now exposes a bounded `reuse_plan` that compares both subtree generation and content-derived subtree object ID. This prevents a changed file from being reused merely because its containing directory timestamp did not change. The engine also exposes a typed `SnapshotObjectCatalog` covering directory objects, file objects, and piece-index pages, with kind-and-ID lookup for future authenticated object retrieval.

The implementation is deliberately local and does not change the default v1 transfer wire path or enable arbitrary v2 object forwarding.

## Verification

| Check | Result |
|---|---|
| Independent snapshot builds | Passed |
| Unchanged subtree reuse | Passed |
| Changed subtree exclusion | Passed even when directory timestamp is unchanged |
| Directory object lookup | Passed |
| File object lookup | Passed |
| Piece-index object lookup | Passed |
| Default build | Passed |
| `swarm-v2` build | Passed |
| Full qualification | Passed with 59 gated desktop tests, 2 companion tests, and frontend build |

## Honest boundary

This phase provides the local reuse decision and typed object catalog. It does not yet transport directory or piece-index objects over the network, perform authenticated object retrieval, or integrate subtree reuse into the v2 transfer session. Those are the next isolated integration steps. The tree/mesh data plane, repair path, companion, and release work remain deferred.
