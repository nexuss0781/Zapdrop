# Zapdrop Phase 3 Status

**Status:** Implemented; final verification and repository push pending  
**Project:** standalone `nexuss0781/Zapdrop` private repository  
**Phase:** authenticated pairing, fingerprint confirmation, and trusted-peer persistence

## Delivered

Zapdrop now has an authenticated pairing layer on top of the Phase 2 local discovery service. Discovery remains an unauthenticated hint; it never grants trust by itself. A discovered or manually entered peer must complete the signed pairing protocol before the UI will treat it as eligible for a future transfer.

The protocol uses bounded JSON-line frames over the reserved local TCP listener. Pairing requests include a protocol version, unique request ID, device ID, display name, platform, Ed25519 public key, SHA-256 fingerprint, random nonce, timestamp, and signature. The canonical payload deliberately excludes the signature field and is reconstructed on both sides before verification. Requests are rejected when their protocol version is unsupported, their timestamp is outside the five-minute clock-skew window, their public-key fingerprint is inconsistent, their public key is malformed, or their signature is invalid.

Incoming requests are held as pending requests until the user explicitly accepts or rejects them. The receiving device sends a signed response containing the request ID, decision, device identity, public key, fingerprint, and optional rejection reason. The initiator verifies the response signature, request ID, and the response identity against the public key and fingerprint advertised during discovery. Short connect, read, and write timeouts prevent a pairing attempt from blocking the application indefinitely.

Accepted identities are persisted to `trusted-peers.json` using the existing atomic JSON write path. A trusted record contains the peer ID, display name, public key, fingerprint, endpoint, first-seen timestamp, and last-seen timestamp. Re-pairing updates the endpoint and last-seen timestamp. Users can revoke trust, which removes the binding and returns the peer to an untrusted state. Resetting the local device identity continues to invalidate the old local identity and requires existing relationships to be paired again.

## Native command surface

| Command | Purpose |
|---|---|
| `list_pending_pairings` | Returns incoming requests waiting for user action. |
| `list_trusted_peers` | Loads trusted-peer bindings from disk. |
| `pair_with_peer` | Starts a signed outbound pairing request and persists an accepted response. |
| `accept_pairing` | Sends a signed acceptance response and persists the incoming peer. |
| `reject_pairing` | Sends a signed rejection response and clears the pending request. |
| `revoke_trusted_peer` | Removes a persisted trust binding. |
| `list_peers` | Projects discovery records with current trust state. |
| `get_app_info` | Reports the pairing port and trusted-peer count. |

The frontend subscribes to `pairing-request`, `pairing-complete`, `peer-trust-updated`, and `peer-trust-removed`. It displays the peer fingerprint before acceptance, provides explicit Pair, Accept, Reject, and Revoke actions, and prevents the share preparation flow from proceeding when any selected peer is untrusted.

## Security controls

| Control | Implementation |
|---|---|
| Identity authenticity | Ed25519 signatures over canonical protocol payloads |
| Fingerprint confirmation | SHA-256 public-key fingerprint compared to discovery and handshake data |
| Replay resistance | Per-request random nonce, unique request ID, and timestamp validation |
| Frame bounds | Maximum 64 KiB JSON-line pairing frame |
| Network scope | Pairing uses the local endpoint and Phase 2 private/local discovery rules |
| Trust boundary | Discovery and manual endpoints remain untrusted until explicit acceptance |
| Persistence | Atomic writes to `trusted-peers.json` |
| Revocation | Explicit command removes the peer binding |
| Resource safety | Short connect/read/write timeouts and bounded pending-request flow |
| Transfer isolation | No file-transfer command is exposed in Phase 3 |

## Verification

The Phase 3 test suite covers signed-request verification, response-payload canonicalization, public-key fingerprint formatting, trusted-peer reload/update/revocation, Phase 2 settings and identity persistence, and private endpoint validation. The acceptance test still requires two PCs or VMs on the same private network to confirm actual mDNS discovery, TCP reachability, and the user-visible accept/reject flow across two running desktop instances.

## Phase 4 contract

Phase 4 can begin with the following stable interfaces:

1. `PeerRecord.trusted` is the current UI projection of persisted trust.
2. `TrustedPeer` contains the public key and fingerprint required to authorize a transfer connection.
3. The pairing listener owns the reserved local port and must re-check the trust store at connection time.
4. `list_pending_pairings`, `accept_pairing`, and `reject_pairing` establish the user-consent pattern for future transfer requests.
5. File transfer must use a new framed protocol or authenticated HTTP layer and must reject peers absent from `trusted-peers.json`.

The next phase should implement safe receive-directory resolution, transfer manifests, conflict policies, progress events, cancellation, and resumable chunks without bypassing the Phase 3 trust boundary.
