# Zapdrop Phase 7 Status

**Status:** Implemented foundation; integration and qualification continue.

Phase 7 adds a reusable local snapshot engine without changing the default v1 transfer behavior. The engine indexes regular files and directories through a bounded streaming walk, normalizes Unicode path components to NFC, rejects symbolic links and traversal components, sorts directory entries canonically, hashes file content in bounded buffers, and produces content-addressed directory, file, and piece-index objects.

Piece descriptors are grouped into bounded JSON index pages with chained page identifiers. A file object records its size, SHA-256 digest, chunk profile, piece count, and first index page. The v2 direct sender now uses this snapshot-derived file metadata to construct its encrypted manifest, so source indexing and the v2 job snapshot are no longer based on filesystem enumeration order alone.

Phase 7 also introduces a crash-safe transfer journal. Journal files are stored below a deterministic job-scoped `.zapdrop-journals` directory, updated atomically through a temporary file and rename, and bounded by a maximum number of verified ranges. The v2 receiver records each authenticated piece range and marks an item complete only after full-file digest verification and final publication.

The implementation includes tests for canonical snapshots, Unicode normalization, traversal rejection, bounded piece pages, and atomic journal round trips. The remaining Phase 7 qualification work is a streamed network index-page exchange for millions of entries, sparse-range recovery, disk-space preflight, explicit source mutation generation changes, and 4 GiB-plus physical-file testing. Those capabilities are deliberately not claimed as complete by this status document.

The v1 path remains the default and is not switched to the Phase 7 engine. v2 remains feature-gated and opt-in pending the Phase 6 security and physical-LAN gates.
