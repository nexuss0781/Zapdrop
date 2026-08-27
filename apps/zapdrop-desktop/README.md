# Zapdrop Desktop

Zapdrop is the local-only desktop client for sharing files between trusted PCs on the same network. This package is intentionally isolated from the Nexuss web application, so its discovery and future transfer workflow can operate without the web server or an internet connection.

## Phase 3 status

Phase 3 is complete. The native runtime now supports authenticated pairing over the reserved local TCP listener. Pairing requests are JSON-line frames containing a protocol version, request ID, device identity, public key, fingerprint, nonce, timestamp, and Ed25519 signature. The receiver verifies the public-key fingerprint, signature, protocol version, and timestamp before presenting the request to the user.

The initiator verifies the response request ID, response signature, response public key, and the fingerprint/public key advertised during discovery. A peer is trusted only after an explicit accept action on the receiving device or an accepted outbound pairing response. The trust decision is persisted atomically in `trusted-peers.json`, and the UI marks trusted peers separately from discovered-but-untrusted peers. File sharing remains blocked for untrusted peers.

Incoming requests remain pending until the user accepts or rejects them. The request view exposes the peer name, platform, endpoint, public key, and fingerprint so the user can compare the fingerprint through a second channel before accepting. Trust can be revoked later, which removes the persisted binding and changes the peer back to an untrusted state.

## Native commands

| Command | Purpose |
|---|---|
| `get_app_info` | Returns app version, identity, pairing port, key-storage mode, and trusted-peer count. |
| `get_settings` | Loads persisted settings. |
| `update_settings` | Atomically persists settings and restarts discovery/pairing when required. |
| `reset_identity` | Replaces the device key pair and restarts local services. |
| `list_peers` | Returns discovered and manual peers with current trust state. |
| `get_network_diagnostics` | Returns discovery, listener, and fallback diagnostics. |
| `scan_network` | Returns the current peer snapshot and emits `scan-complete`. |
| `add_manual_endpoint` | Validates and adds a private/local `ip:port` endpoint. |
| `list_pending_pairings` | Returns incoming requests awaiting user action. |
| `list_trusted_peers` | Returns persisted trusted-peer bindings. |
| `pair_with_peer` | Initiates a signed pairing request and persists the peer only after an accepted response. |
| `accept_pairing` | Signs an accepted response and persists the incoming peer trust record. |
| `reject_pairing` | Signs a rejected response and removes the pending request. |
| `revoke_trusted_peer` | Removes a trusted-peer binding. |

## Runtime data

Zapdrop stores settings and identity metadata in the platform data directory selected by the `directories` crate. The settings file is `settings.json`, the public identity record is `identity.json`, the Unix fallback secret is `identity.key`, and trusted bindings are stored in `trusted-peers.json`. JSON writes use a temporary file followed by rename to reduce the chance of a partially written file.

## Protocol security boundaries

Discovery is an unauthenticated hint and is never treated as trust. Manual endpoints are also untrusted until the signed handshake succeeds. Pairing is limited to the local endpoint advertised or entered by the user, uses short socket timeouts, rejects oversized frames, rejects stale timestamps, and verifies that the fingerprint matches the supplied public key. No file-transfer command is exposed by Phase 3.

## Development

From the repository root:

```bash
pnpm install:app
pnpm dev
```

Frontend build and type check:

```bash
pnpm build
```

Rust formatting, compile check, and Phase 3 unit tests:

```bash
cargo fmt --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml -- --check
pnpm check
cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --lib
```

Native Tauri build without installer bundling:

```bash
pnpm desktop:build
```

The Tauri Windows development prerequisites include Rust, Microsoft C++ Build Tools, and WebView2. Linux development additionally requires the WebKitGTK and GTK development libraries described by the Tauri documentation.

## Phase 4 status

Phase 4 is complete. The transfer engine uses a bounded framed TCP protocol on the existing authenticated local listener. The sender transmits a signed transfer hello, waits for the receiver’s hello acknowledgement, sends a validated manifest, receives resumable offsets, and streams checksummed chunks. The receiver re-checks the sender’s exact peer ID, public key, and fingerprint against `trusted-peers.json` at connection time before accepting the manifest.

Transfer sources may be regular files or recursively enumerated directories. Symbolic links, absolute paths, parent traversal, duplicate manifest IDs/paths, reserved `.zapdrop-partial` paths, unsupported item types, and manifest size mismatches are rejected. Partial chunks are written under a private transfer state directory and renamed into the configured receive directory only after the final SHA-256 digest matches the manifest. Relative paths are resolved beneath the canonical receive root.

The receiver supports `rename`, `overwrite`, and `skip` conflict policies. Partial item IDs are deterministic by relative path so a retry with the same transfer ID can resume an interrupted item. Sender sessions run independently for each recipient and are bounded to eight simultaneous recipients. Progress, completion, failure, and cancellation events are emitted per recipient. Cancellation is shared across the transfer’s workers and cleaned after the final worker exits.

The dashboard now accepts an explicit local source path, starts transfers only for selected trusted peers, displays per-recipient progress bars and current paths, and exposes cancellation. Native file browsing remains a later UI enhancement; the transfer engine itself already supports files and folders.

## Transfer commands

| Command | Purpose |
|---|---|
| `start_transfer` | Validates sources and trusted recipients, then starts independent parallel sessions. |
| `cancel_transfer` | Requests cancellation for all active recipient workers sharing a transfer ID. |

## Next phase

Phase 5 is ready to begin. It should add native filesystem browsing and file/folder selection, transfer history persistence, richer receive notifications, installer-level firewall guidance, two-machine acceptance automation, and performance tuning for large directories and high-throughput local networks. The trust check and safe destination resolver must remain in the receive path.
