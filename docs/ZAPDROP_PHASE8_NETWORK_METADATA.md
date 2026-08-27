# Zapdrop Phase 8 Network Metadata Exchange

**Status:** One authenticated metadata-page exchange implemented and tested; full multi-page interruption acceptance remains open.

The experimental `swarm-v2` direct path now sends one `V2DirectMetadataPage` after the secure handshake and before the receiver offer. The page is encrypted under the established channel with dedicated associated data, carries the transfer job ID, and contains file object IDs and sizes derived from the sender’s manifest. The receiver validates the metadata page before presenting the approval offer, then separately validates the signed manifest and requires the metadata objects to match the manifest exactly.

This preserves the authorization boundary: discovery does not authorize a peer, the secure handshake still requires an exact trusted identity, and content-key provisioning still occurs only after receiver approval. The default v1 path is unchanged.

## Verification

| Check | Result |
|---|---|
| v2 metadata frame ordering | Passed: metadata is sent before the offer and read before offer validation |
| Authenticated associated data | Passed through the existing secure-channel frame tests and v2 direct roundtrip |
| Job binding | Passed: receiver rejects a metadata envelope for another job |
| Manifest binding | Passed: receiver rejects metadata whose object IDs or sizes differ from the signed manifest |
| Metadata-page validation | Passed for malformed page IDs, object IDs, object kinds, and links |
| v2 direct file transfer | Passed: existing encrypted loopback transfer completes with the new frame |
| Full automated qualification | Passed after the change |

## Honest boundary

This is a bounded one-page exchange, not the complete paged metadata protocol. Multiple-page transport, page streaming for very large trees, subtree reuse across independent network snapshots, durable recovery after process termination, and 4 GiB-plus physical-file acceptance remain open. The `swarm-v2` path remains feature-gated and experimental; no TLS 1.3 or production-certified security claim is made.

The next isolated phase is interruption and resume integration acceptance. It must be implemented and verified separately from tree/mesh, repair, companion, and release work.
