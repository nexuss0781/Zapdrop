# Zapdrop Phase 7 Status

**Status:** Implemented foundation; integration and qualification continue.

Phase 7 adds a reusable local snapshot engine without changing the default v1 transfer behavior. The engine indexes regular files and directories through a bounded streaming walk, normalizes Unicode path components to NFC, rejects symbolic links and traversal components, sorts directory entries canonically, hashes file content in bounded buffers, and produces content-addressed directory, file, and piece-index objects.

Piece descriptors are grouped into bounded JSON index pages with chained page identifiers. A file object records its size, SHA-256 digest, chunk profile, piece count, and first index page. The v2 direct sender now uses this snapshot-derived file metadata to construct its encrypted manifest, so source indexing and the v2 job snapshot are no longer based on filesystem enumeration order alone.

Phase 7 also introduces a crash-safe transfer journal. Journal files are stored below a deterministic job-scoped `.zapdrop-journals` directory, updated atomically through a temporary file and rename, and bounded by a maximum number of verified ranges. The v2 receiver records each authenticated piece range, exposes sparse missing ranges to the sender, performs destination free-space preflight, and marks an item complete only after full-file digest verification and final publication. Legacy unjournaled partial files are discarded rather than trusted.

Metadata objects can be emitted as bounded chained pages, and exact directory modification generations can be used through `SubtreeReuseIndex` to reuse unchanged subtree references. The v2 sender performs a source-generation/content digest check before creating the encrypted job, preventing a changed source from silently being paired with an old snapshot.

The implementation includes tests for canonical snapshots, Unicode normalization, traversal rejection, bounded piece and metadata pages, exact subtree-generation matching, source mutation detection, disk-space preflight, sparse missing-range recovery, and atomic journal round trips. Remaining Phase 7 qualification work is a network control exchange for metadata pages and subtree reuse across independent jobs, disk-full fault injection, durable sparse writes across process termination, and 4 GiB-plus physical-file testing. Those capabilities are deliberately not claimed as fully qualified by this status document.

## Network metadata contract slice

The metadata-page type exposes bounded validation for protocol kind, version, 64-character digest identifiers, allowed object kinds, and chained page links. The experimental v2 direct path now sends one authenticated, job-bound metadata page before the receiver offer; the receiver validates its content against the signed manifest before presenting approval. Serialization round-trip and mismatch tests reject malformed or unrelated metadata. The snapshot qualification runner exercises the validation checks in both default and `swarm-v2` builds.

This is the first bounded network metadata exchange, not a complete paged-tree protocol. Multiple page transport, subtree reuse across independent network snapshots, interruption after process termination, and 4 GiB-plus physical-file acceptance remain open follow-up work.

The v1 path remains the default and is not switched to the Phase 7 engine. v2 remains feature-gated and opt-in pending the Phase 6 security and physical-LAN gates.
