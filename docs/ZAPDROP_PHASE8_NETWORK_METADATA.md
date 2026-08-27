# Zapdrop Phase 8 Network Metadata Exchange

**Status:** Bounded authenticated metadata-page chain and directory/piece-index object retrieval implemented and tested; active-transfer interruption acceptance remains open.

The experimental `swarm-v2` direct path now sends a bounded chain of `V2DirectMetadataPage` frames after the secure handshake and before the receiver offer. Each page is encrypted under the established channel with dedicated associated data, carries the transfer job ID, contains directory, file, and piece-index references, and links to the next page by content-derived page ID. File object IDs and serialized lengths are included in the signed manifest commitment, preventing a file reference from being confused with its content SHA-256. The receiver reads pages until a terminal link, validates each page and chain link against the signed manifest, and presents approval only after that check.

This preserves the authorization boundary: discovery does not authorize a peer, the secure handshake still requires an exact trusted identity, and content-key provisioning still occurs only after receiver approval. The default v1 path is unchanged.

## Verification

| Check | Result |
|---|---|
| v2 metadata frame ordering | Passed: the complete metadata chain is sent before the offer and read before offer validation |
| Authenticated associated data | Passed through the existing secure-channel frame tests and v2 direct roundtrip |
| Job binding | Passed: receiver rejects a metadata envelope for another job |
| Manifest binding | Passed: receiver rejects metadata whose object IDs or sizes differ from the signed manifest |
| Metadata-page validation | Passed for malformed page IDs, object IDs, object kinds, links, chain length, chain order, and manifest mismatch |
| v2 direct file transfer | Passed: encrypted loopback transfer completes with the new metadata chain |
| Authenticated object retrieval | Passed: approved receiver requests only non-file references; sender authorizes against its snapshot catalog; receiver validates job, reference set, lengths, base64, type, and content-derived IDs |
| Directory-source loopback | Passed: directory source with nested files and a piece-index page retrieves objects before encrypted payload transfer |
| Full automated qualification | Passed after the change |

## Honest boundary

This is a bounded multi-page exchange, not an unbounded paged-tree protocol. The chain is capped at 2,048 pages, each encrypted metadata payload is bounded to a 16 KiB packing target, and object retrieval is capped at 64 typed objects per response below the global frame limit. The sender authorizes requested objects against the freshly built snapshot catalog, and the receiver does not request objects before approval and job-key provisioning. Active-transfer interruption behavior and 4 GiB-plus physical-file acceptance remain open. The `swarm-v2` path remains feature-gated and experimental; no TLS 1.3 or production-certified security claim is made.

Active-transfer interruption and local cross-snapshot reuse acceptance are covered separately. Authenticated network directory and piece-index retrieval is now complete for this bounded direct-only slice. The next isolated phase is tree/mesh topology integration, and it must remain separate from repair, companion, and release work.
