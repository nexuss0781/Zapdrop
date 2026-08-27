# Zapdrop Swarm Protocol v2

**Status:** Initial design specification with Phase 6 secure-channel foundation
**Protocol family:** Zapdrop local transfer
**Version:** `2`
**Transport status:** Wire models plus authenticated application-channel foundation; production listener migration and packet-capture qualification remain pending

## 1. Purpose and scope

Swarm Protocol v2 changes Zapdrop’s transfer abstraction from an isolated sender-to-receiver copy into an authorized **swarm job**. A swarm job describes one immutable content snapshot, one sender identity, one explicit recipient set, one distribution policy, and one expiry window. The protocol supports direct fan-out first and leaves tree, mesh, and repair-coded distribution as negotiated extensions.

The protocol is designed for private local-area networks. It does not require internet access, cloud storage, a central rendezvous service, SMB shares, mapped drives, domain credentials, or public DHT participation. Local discovery is only an untrusted hint. A device must be paired and trusted before it may receive a job capability or any file metadata.

This document defines the versioned application objects and state machine. The Phase 6 foundation now includes an authenticated application channel profile: Ed25519-signed ephemeral X25519 handshakes, HKDF-SHA256 directional keys, ChaCha20-Poly1305 frame protection, per-job key envelopes, and snapshot-bound authenticated associated data. The active v1 transfer path still uses its existing protocol; v2 production migration remains gated on integration and physical-LAN qualification.

## 2. Security model

Zapdrop distinguishes three states:

| State | Meaning | Permission |
|---|---|---|
| `visible` | The peer was discovered through mDNS/DNS-SD or entered manually | No file or job access |
| `trusted` | Both devices completed authenticated pairing and the public-key binding is persisted | May be considered for a job |
| `authorized` | The trusted identity is included in a signed, unexpired swarm capability | May access only the permitted job objects |

The sender signs the job descriptor and recipient capabilities with its persistent device identity. Each swarm job also receives a fresh symmetric content key. The secure session authenticates the device identity and protects control and piece traffic. A relay, if enabled in a later phase, receives only capability-scoped ciphertext pieces and never receives general filesystem authority.

The protocol MUST reject an unknown peer, a trusted peer not authorized for the current job, a changed public key, an expired capability, a replayed nonce, a mismatched snapshot root, a duplicate object identifier, an invalid path, and a piece whose authenticated digest does not match the snapshot object. There is no plaintext fallback.

## 3. Canonical encoding rules

The initial signed handshake and secure proof use one UTF-8 JSON object per newline-delimited frame. After the secure channel is established, encrypted v2 records use a four-byte big-endian length prefix followed by one UTF-8 JSON object. The post-handshake record length is bounded to 8 MiB in the direct profile, and the 4 MiB encrypted piece payload is base64url-encoded inside that bounded record. Byte strings are base64url without padding unless a field explicitly states another encoding. Hashes and identifiers use lowercase hexadecimal only when the field definition says `hex`.

Object identifiers are case-sensitive and MUST be compared after validation. Directory children MUST be sorted by their canonical UTF-8 relative names. Relative paths use `/` as the protocol separator regardless of host operating system. A path MUST be relative, MUST NOT contain `.` or `..` components, MUST NOT target a reserved partial directory, and MUST be validated again at the receiver’s native filesystem boundary.

The initial handshake line is bounded to 64 KiB. Post-handshake v2 records have a maximum encoded size of 8 MiB in the direct profile. Receivers MUST enforce the length before allocating the payload and MUST cap the number of objects, recipients, children, connections, pending offers, and outstanding requests before allocating additional state. The current implementation caps active listener connections and pending transfer offers at 64 and 32 respectively.

## 4. Core objects

### 4.1 `SwarmJob`

`SwarmJob` is the signed parent descriptor for one distribution operation.

| Field | Type | Rule |
|---|---|---|
| `kind` | string | `zapdrop_swarm_job` |
| `version` | integer | `2` |
| `jobId` | string | UUID or equivalent opaque ID, 1–128 bytes |
| `senderId` | string | Persistent Zapdrop device ID |
| `senderPublicKey` | string | Base64url-encoded Ed25519 public key |
| `senderFingerprint` | string | Persisted public-key fingerprint |
| `snapshotRoot` | string | Root content identifier |
| `recipientIds` | array of strings | Unique trusted device IDs, 1–256 entries |
| `distributionMode` | enum | `direct`, `queued`, `tree`, or `mesh` |
| `chunkProfile` | object | Versioned object/piece sizing parameters |
| `contentKeyId` | string | Non-secret identifier for the job content key |
| `createdAt` | integer | Unix seconds |
| `expiresAt` | integer | Greater than `createdAt`, bounded by implementation policy |
| `signature` | string | Signature over the canonical unsigned descriptor |

`recipientIds` is the authorization set, not a discovery list. The sender MUST NOT add a recipient after the job has begun without issuing a new signed job revision and obtaining the recipient’s explicit approval.

### 4.2 `SnapshotRoot`

`SnapshotRoot` commits to the complete content graph. It is immutable for the lifetime of a job.

| Field | Type | Rule |
|---|---|---|
| `kind` | string | `zapdrop_snapshot_root` |
| `version` | integer | `2` |
| `rootId` | string | Content identifier of this root |
| `nodeCount` | unsigned integer | Bounded by receiver policy |
| `totalBytes` | unsigned integer | 64-bit byte count |
| `totalFiles` | unsigned integer | Bounded by receiver policy |
| `chunkProfileId` | string | Must match `SwarmJob.chunkProfile` |
| `createdAt` | integer | Unix seconds |
| `signature` | string | Sender signature over the unsigned root descriptor |

A root references directory nodes and file objects. A receiver may request bounded metadata pages lazily instead of accepting one monolithic manifest. Page identifiers are content-addressed, and a sender may advertise an unchanged subtree reference when its exact modification generation and object identifier match a previously accepted cache entry.

### 4.3 `DirectoryNode`

A directory node contains a canonical sorted list of child descriptors. Its identifier is a cryptographic hash over the canonical node payload and child identifiers. Directory nodes are immutable; a changed child creates a different ancestor root.

Each child descriptor contains a relative name, object type, byte size when applicable, metadata needed for the destination policy, and the child object identifier. The receiver MUST reject duplicate names, invalid names, path escapes, unsupported types, and inconsistent aggregate sizes.

### 4.4 `FileObject`

A file object describes a regular file without requiring the entire file to be loaded into memory.

| Field | Type | Rule |
|---|---|---|
| `objectId` | string | Content identifier |
| `relativePath` | string | Canonical relative path |
| `size` | unsigned integer | 64-bit byte count |
| `sha256` | string | 32-byte digest encoded as lowercase hex |
| `pieces` | array or page reference | Bounded list/page of piece identifiers |
| `pieceCount` | unsigned integer | Consistent with the piece index |
| `mode` | string | `regular` in the initial desktop profile |

The initial profile uses fixed-size source pieces. Variable or content-defined chunking may be introduced through a new `chunkProfileId`; a receiver MUST NOT infer chunking from local defaults.

### 4.5 `PieceDescriptor`

A piece descriptor identifies the plaintext content before encryption.

| Field | Type | Rule |
|---|---|---|
| `pieceId` | string | Hash-derived identifier |
| `objectId` | string | Parent file object |
| `index` | unsigned integer | Zero-based piece index |
| `offset` | unsigned integer | 64-bit plaintext offset |
| `length` | unsigned integer | Plaintext length |
| `sha256` | string | Digest of the plaintext piece |

### 4.6 `EncryptedPiece`

`EncryptedPiece` is the authenticated payload envelope. It is sent as a bounded binary frame preceded by a validated control header.

| Field | Type | Rule |
|---|---|---|
| `kind` | string | `zapdrop_encrypted_piece` |
| `version` | integer | `2` |
| `jobId` | string | Must match the authorized job |
| `pieceId` | string | Must match the requested piece descriptor |
| `objectId` | string | Must match the file object |
| `index` | unsigned integer | Must match the piece descriptor |
| `offset` | unsigned integer | Must match the piece descriptor |
| `plaintextLength` | unsigned integer | 64-bit, bounded by chunk profile |
| `ciphertextLength` | unsigned integer | Bounded before allocation |
| `nonce` | bytes | AEAD nonce, algorithm-specific fixed length |
| `ciphertextSha256` | string | Digest of the transmitted ciphertext bytes |
| `tag` | bytes | AEAD authentication tag when not combined with ciphertext |

The associated authenticated data MUST bind at least `jobId`, `snapshotRoot`, `pieceId`, `objectId`, `index`, `offset`, and `plaintextLength`. A receiver MUST verify the ciphertext digest and AEAD tag before writing plaintext bytes to staging storage.

## 5. Secure-channel profile

The initial v2 secure-channel profile uses the following sequence. Each endpoint creates a fresh X25519 ephemeral keypair and an Ed25519-signed `SecureHandshake`. The signature covers the session ID, device ID, Ed25519 public key, public-key fingerprint, ephemeral public key, handshake nonce, supported secure profile list, protocol version, and timestamp. The receiver verifies the signature with the already trusted Ed25519 public key and compares the device ID, decoded public key, and fingerprint against the trusted-peer record. A mismatch fails the session before any job metadata is accepted. The current profile identifier is `x25519-hkdf-sha256-chacha20poly1305`.

Both endpoints compute the X25519 shared secret and a deterministic transcript hash over the two unsigned handshakes in device-ID order. The handshake fails if the peer does not advertise the supported secure profile. HKDF-SHA256 derives separate initiator-to-responder and responder-to-initiator 256-bit keys. Each direction uses a monotonically increasing 64-bit sequence number with a deterministic 96-bit nonce. A receiver accepts only the next expected sequence number, so replayed and out-of-order frames fail closed. The channel refuses to seal more than `2^32` frames or `2^40` plaintext bytes under one channel key; a future re-handshake must occur before those limits. ChaCha20-Poly1305 authenticates the frame ciphertext and binds the sequence number and caller-supplied control AAD.

A fresh 256-bit job key is generated per swarm job. The sender provisions it to each authorized recipient by encrypting it under the established directional channel key. The job-key envelope binds the job ID, snapshot root, key ID, and exact recipient ID as authenticated associated data. The content key itself is never serialized as plaintext. Encrypted piece headers bind the job, snapshot root, piece, object, index, offset, and plaintext length as authenticated associated data; ciphertext length and ciphertext SHA-256 are checked before decryption and staging writes.

This application channel is an implementation foundation and is not a TLS 1.3 deployment. The `swarm-v2` feature integrates a secure hello/proof exchange into the real TCP listener, an opt-in sender probe through `ZAPDROP_SWARM_V2_PROBE`, and a feature-gated encrypted direct-file exchange through `ZAPDROP_SWARM_V2_DIRECT`. Discovery metadata is not authoritative for trust: outbound selection requires an exact persisted peer ID, public key, and fingerprint tuple, and key changes require explicit revocation and re-pairing. The direct exchange sends the signed job and manifest before approval but provisions the per-job content key only after the receiver accepts the job. The receiver validates bounded identifiers and paths, recomputes the snapshot root from the canonical manifest, and rejects completed job IDs. After key provisioning, the receiver sends an encrypted ready frame containing validated piece-aligned offsets and optional sparse missing ranges for each item; the sender seeks to each requested range and resumes from the corresponding piece index. Existing partial bytes are retained only when a job-scoped journal agrees with the on-disk length; legacy unjournaled partials are discarded. The receiver preflights destination free space, records authenticated ranges atomically, and the final full-file SHA-256 check remains authoritative. Phase 7 snapshot indexing uses deterministic NFC paths, bounded chained metadata pages, content-addressed file and directory objects, exact source-generation/content checks before job creation, and a journal-derived sparse recovery model. Post-handshake records are length-prefixed and bounded before allocation. The active v1 transfer path remains the default and unchanged. Explicit re-handshake/rekey orchestration, robust failure alerts, packet capture, and physical-LAN qualification remain required before v2 is enabled by default.

## 6. Capability and control objects

### 6.1 `RecipientCapability`

A capability authorizes one trusted device for a narrow operation.

| Field | Type | Rule |
|---|---|---|
| `kind` | string | `zapdrop_recipient_capability` |
| `version` | integer | `2` |
| `jobId` | string | Parent job |
| `recipientId` | string | Exact trusted peer ID |
| `snapshotRoot` | string | Exact content root |
| `allowedObjectIds` | array or range reference | Only objects this recipient may access |
| `operations` | array | `readPiece`, `forwardPiece` only as negotiated |
| `expiresAt` | integer | Must not exceed job expiry |
| `nonce` | string | Fresh capability nonce |
| `signature` | string | Sender signature |

`forwardPiece` is not present in direct mode. It is granted only to a selected relay peer in tree or mesh mode and MUST include an authorized child set, maximum bytes, and forwarding expiry in the extension fields.

### 6.2 `SwarmFrame`

The initial v2 control frame kinds are:

| Kind | Direction | Purpose |
|---|---|---|
| `zapdrop_swarm_hello` | sender → receiver | Negotiates protocol version and authenticates the device session |
| `zapdrop_swarm_hello_ok` | receiver → sender | Confirms trusted identity and supported profiles |
| `zapdrop_swarm_job` | sender → receiver | Sends the signed job descriptor |
| `zapdrop_swarm_offer` | receiver → local UI | Holds the job for local acceptance before data access |
| `zapdrop_swarm_accept` | receiver → sender | Returns capability acknowledgement and selected destination policy |
| `zapdrop_swarm_reject` | receiver → sender | Refuses the job without writing data |
| `zapdrop_swarm_direct_ready` | receiver → sender | Returns encrypted, piece-aligned offsets and sparse missing ranges after approval and key provisioning |
| `zapdrop_snapshot_root` | sender → receiver | Commits the content graph |
| `zapdrop_index_request` | receiver → sender | Requests a bounded root/directory/file index page |
| `zapdrop_index_page` | sender → receiver | Returns a bounded metadata page |
| `zapdrop_piece_request` | receiver → sender/relay | Requests one or more authorized pieces |
| `zapdrop_piece_header` | sender/relay → receiver | Announces an encrypted piece binary payload |
| `zapdrop_piece_ack` | receiver → sender/relay | Confirms a verified piece or reports a retryable error |
| `zapdrop_swarm_cancel` | either direction | Cancels and revokes the job branch |
| `zapdrop_swarm_complete` | receiver → sender | Provides completion proof for the authorized snapshot |
| `zapdrop_swarm_error` | either direction | Returns a bounded structured error code |

Unknown mandatory frame kinds MUST fail the session. Unknown extension fields MAY be ignored only when the enclosing object remains valid and the extension is not security-critical.

## 7. State machine

```text
DISCOVERED
    |
    | existing pairing and trusted-key binding
    v
TRUSTED
    |
    | signed swarm hello + job descriptor
    v
OFFERED ---- reject/expire ----> CLOSED
    |
    | local accept + destination policy
    v
AUTHORIZED
    |
    | snapshot/index validation
    v
TRANSFERRING
    |        \
    |         \ cancel/revoke
    |          v
    |        CANCELLED
    |
    | all objects verified and atomically published
    v
COMPLETED
```

No receiver writes a final destination while in `OFFERED`. Staging allocation is permitted only after authorization and destination validation. In the direct profile, the receiver sends `zapdrop_swarm_direct_ready` only after approval and successful job-key unwrapping; its offsets are bounded by the manifest and aligned to the negotiated piece profile. A receiver rejects path-bearing identifiers, duplicate IDs or paths, mismatched canonical snapshot roots, wrong content-key IDs, oversized records, duplicate job IDs, or a symlinked staging chain before writing plaintext. A receiver may also reject a job because of user policy, disk space, conflicts, expired capability, unsupported profile, or security failure. Error codes must be stable enough for the UI and history layer to distinguish retryable network failures from permanent content or authorization failures.

## 8. Chunk profile v2 initial values

The initial profile is deliberately conservative and measurable. It is not a promise that these values are optimal for every filesystem or LAN.

| Parameter | Initial value | Constraint |
|---|---:|---|
| `pieceSize` | 4 MiB | Negotiated and bounded between 256 KiB and 16 MiB |
| `maxInFlightPieces` | 8 | Per session; global scheduler limit remains separate |
| `maxIndexPageBytes` | 1 MiB | Prevents monolithic metadata allocation |
| `maxRecipients` | 256 | Job authorization limit |
| `maxActiveDirectPeers` | 8 | Existing application resource ceiling |
| `hash` | SHA-256 | Must cover plaintext piece and final object |
| `aead` | `ChaCha20-Poly1305` for the application-channel foundation | No unauthenticated encryption mode |

## 9. Compatibility and migration

The current Phase 5 transfer protocol remains version `1` and must continue to operate while v2 is developed behind a feature boundary. A v1 peer must not be silently upgraded into a v2 swarm session. The hello negotiation must identify supported protocol versions and secure-channel profiles before a job descriptor is accepted.

A v2 implementation may use the existing signed device identity and trusted-peer persistence. It must not reinterpret a v1 transfer ID as a v2 job ID without an explicit migration adapter. History records should preserve the protocol version, distribution mode, snapshot root, and child-recipient outcomes.

## 10. Phase 6 implementation slices

The first implementation slice adds Rust serialization models, bounded validation, canonical identifier helpers, and unit tests. It does not change the active v1 transfer engine.

The secure-channel foundation adds signed ephemeral handshakes, directional key derivation, profile negotiation, bounded rekey limits, fresh job-key provisioning, snapshot-bound authenticated data, replay protection, and AEAD tests. The `swarm-v2` feature now runs a real TCP listener probe, encrypted proof exchange, and one direct file-transfer path using encrypted job, decision, key-provision, ready, piece, and completion frames. Pending v2 offers use the existing UI approval surface, and receive-side v2 transfers record history and emit progress events. The default v1 path remains active until sender-side v2 progress, explicit re-handshake/rekey orchestration, packet-capture evidence, and physical-LAN qualification are complete.

Tree/mesh forwarding, RaptorQ repair, privacy relays, and adaptive congestion-control selection are later protocol extensions. They must not be enabled by default until direct v2 transfer, large-file resume, revocation, and physical-LAN tests are complete.

## 11. Acceptance criteria

The initial protocol foundation is complete when all model types round-trip through JSON, invalid versions and kinds fail, duplicate recipients and malformed identifiers fail, capabilities cannot exceed job expiry, piece lengths and offsets are bounded, canonical snapshot objects reject duplicate children and unsafe paths, and v1 tests remain green. The secure-channel foundation additionally requires valid signed handshakes, trusted identity matching, directional key agreement, replay rejection, AAD tamper rejection, job-key envelope binding, and encrypted-piece snapshot binding; these tests are now implemented in `src-tauri/src/secure.rs`.

The secure-channel milestone is complete when a packet capture contains no readable payload, the receiver rejects a changed sender key, replayed capabilities fail, rejected or expired jobs write no file, a valid encrypted piece can be verified independently, the v2 loopback direct-file test succeeds with explicit approval, resume offsets are negotiated inside the encrypted channel, and rejection/integrity regression tests prove no unauthorized or corrupted content is committed.
