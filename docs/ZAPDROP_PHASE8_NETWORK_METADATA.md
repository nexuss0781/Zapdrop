# Zapdrop Phase 8 Network Metadata Exchange

**Status:** Bounded authenticated metadata-page chain implemented and tested; active-transfer interruption acceptance remains open.

The experimental `swarm-v2` direct path now sends a bounded chain of `V2DirectMetadataPage` frames after the secure handshake and before the receiver offer. Each page is encrypted under the established channel with dedicated associated data, carries the transfer job ID, contains file object IDs and sizes derived from the sender’s manifest, and links to the next page by content-derived page ID. The receiver reads pages until a terminal link, validates each page ID and chain link, and checks the complete object set against the signed manifest before presenting the approval offer.

This preserves the authorization boundary: discovery does not authorize a peer, the secure handshake still requires an exact trusted identity, and content-key provisioning still occurs only after receiver approval. The default v1 path is unchanged.

## Verification

| Check | Result |
|---|---|
| v2 metadata frame ordering | Passed: the complete metadata chain is sent before the offer and read before offer validation |
| Authenticated associated data | Passed through the existing secure-channel frame tests and v2 direct roundtrip |
| Job binding | Passed: receiver rejects a metadata envelope for another job |
| Manifest binding | Passed: receiver rejects metadata whose object IDs or sizes differ from the signed manifest |
| Metadata-page validation | Passed for malformed page IDs, object IDs, object kinds, links, chain length, chain order, and manifest mismatch |
| v2 direct file transfer | Passed: existing encrypted loopback transfer completes with the new frame |
| Full automated qualification | Passed after the change |

## Honest boundary

This is a bounded multi-page exchange, not an unbounded paged-tree protocol. The chain is capped at 2,048 pages and each encrypted metadata payload is bounded to a 16 KiB packing target. Local cross-snapshot reuse is qualified separately, while authenticated network directory and piece-index retrieval, active-transfer interruption behavior, and 4 GiB-plus physical-file acceptance remain open. The `swarm-v2` path remains feature-gated and experimental; no TLS 1.3 or production-certified security claim is made.

Active-transfer interruption and local cross-snapshot reuse acceptance are now covered separately. The next isolated phase is authenticated network directory and piece-index object retrieval. It must be implemented and verified separately from tree/mesh, repair, companion, and release work.
