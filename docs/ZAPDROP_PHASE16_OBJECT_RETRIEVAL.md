# Zapdrop Phase 16 Status: Authenticated Network Object Retrieval

**Status:** Complete for the bounded experimental `swarm-v2` direct path.

Phase 16 integrates typed snapshot metadata-object retrieval into the authenticated v2 direct session. The sender builds one canonical snapshot and derives both the encrypted metadata chain and file manifest from it. The manifest now carries optional v2-only file-object ID and serialized-length commitments; v1 serialization remains unchanged because these fields are omitted when absent. The signed snapshot root therefore binds file metadata references to the exact file objects that the sender indexed, rather than confusing file-object IDs with file-content SHA-256 values.

After receiver approval and encrypted per-job key provisioning, the receiver requests the non-file references advertised in the authenticated metadata chain. The request is encrypted with dedicated associated data and is sent before the ready frame and before any content pieces. The sender validates each requested reference against its freshly built `SnapshotObjectCatalog`, rejects file-object requests and unlisted or length-mismatched objects, serializes only directory and piece-index objects, and returns an authenticated response. The receiver checks the response job, exact requested reference set, duplicate exclusion, declared byte lengths, base64 decoding, object kind, structure, and content-derived object IDs before payload transfer begins.

## Bounded protocol contract

| Area | Contract |
|---|---|
| Authorization | Discovery remains non-authorizing; the secure channel, exact trusted peer identity, receiver approval, and job-key provisioning are required before object retrieval. |
| Metadata commitment | v2 `ManifestItem` includes signed optional `objectId` and `objectByteLen` values; legacy v1 manifests omit them. |
| Object kinds | Only `directory` and `piece-index` objects are retrievable in this phase. Raw file objects are rejected. |
| Request bound | At most 64 distinct typed object references are requested in one bounded exchange. |
| Response bound | The serialized response is kept below the global 8 MiB v2 frame limit with a 64 KiB safety margin. |
| Content validation | Directory and piece-index payloads must parse as their expected type and reproduce the advertised digest after canonicalizing the pending ID field. |
| Data-plane scope | No tree or mesh forwarding is enabled; file payloads still use the existing encrypted piece plane. |

## Verification evidence

The focused v2 transfer tests pass for valid directory and piece-index responses, rejected file requests, unlisted and byte-length-mismatched requests, duplicate requests and responses, wrong-job responses, malformed base64, content tampering, and content-derived ID mismatches. A v2 loopback test transfers a nested directory containing a multi-piece file and a small file; the authenticated object exchange completes before both destination files are published.

The snapshot qualification runner passes in both default and `swarm-v2` builds. The latest focused gated v2 transfer suite reports **17 passing tests**, including the directory-source loopback and object authorization/tamper test. Default v1 behavior remains covered separately and unchanged. Rust formatting, default and feature-gated compilation, shell syntax validation, and the repository qualification gate are required before the phase is committed.

## Honest boundary

This phase qualifies a bounded local loopback and code-level authorization contract. It does not claim TLS 1.3, production-certified security, independent review, fuzzing, complete rekey behavior, physical-LAN evidence, Windows runtime qualification, receiver process restart during an active payload write, 4 GiB-plus physical-file acceptance, tree/mesh forwarding, repair coding, companion compatibility, or release readiness. `swarm-v2` remains feature-gated and experimental; v1 remains the default.
