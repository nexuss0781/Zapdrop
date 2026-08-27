# Zapdrop Phase 2 Status

**Status:** Complete and ready for Phase 3  
**Project:** standalone `nexuss0781/Zapdrop` private repository  
**Branch:** `main`

## Delivered

Phase 2 adds persistent settings, stable device identity, local network discovery, peer state events, diagnostics, and a manual endpoint fallback to the standalone Zapdrop desktop project.

The settings store uses a platform data directory and atomically writes `settings.json`. It persists the device name, receive directory, selected interface, settings version, and whether advertising/browsing should start automatically. Names are normalized and bounded before persistence.

The identity module creates a random Ed25519 signing key, persists the public identity metadata in `identity.json`, computes a SHA-256 fingerprint for human confirmation, and protects the private key with an OS keyring on Windows and macOS where available. On Unix-like targets without an available desktop keyring, the implementation falls back to `identity.key` with restrictive `0600` permissions. Resetting identity removes the old records and creates a new key pair.

The discovery module advertises and browses `_zapdrop._tcp.local.` using mDNS/DNS-SD. The advertised TXT metadata includes protocol version, device ID, device name, platform, identity fingerprint, and capability hints. The service reserves a local TCP listener for the next phase and emits `peer-updated` and `peer-removed` events when resolved peers appear or disappear. Resolved addresses are restricted to private/local network addresses, and the service ignores its own identity.

The manual fallback accepts private IPv4, IPv6, and link-local `ip:port` endpoints. Public endpoints are rejected. Manual peers remain visible even if mDNS cannot start, and they are marked as untrusted until the authenticated pairing phase.

The React dashboard now loads native settings, identity metadata, diagnostics, and peer snapshots; subscribes to discovery events; refreshes the current discovery snapshot; opens a settings modal; saves settings; resets identity; adds manual endpoints; and makes the Phase 3 trust boundary visible to the user.

## Verification

| Check | Result |
|---|---|
| Frontend type check and production build | Passed with `pnpm --dir apps/zapdrop-desktop build` |
| Rust formatting check | Passed with `cargo fmt --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml -- --check` |
| Rust compile check | Passed with `cargo check --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml` |
| Phase 2 unit tests | Passed: 5 tests, 0 failures |
| Native Tauri build without installer bundle | Passed; release binary generated at `apps/zapdrop-desktop/src-tauri/target/release/zapdrop` |
| Browser preview | Passed; dashboard, diagnostics strip, settings modal, and manual endpoint form rendered |
| Browser fallback behavior | Passed; preview clearly reports that native discovery requires the Tauri runtime |

The sandbox is headless, so a real two-machine multicast discovery test and Windows firewall prompt were not run here. The mDNS registration and browse loop compile and are covered by the discovery helper tests; real-network validation remains an acceptance test for the next environment with two PCs or VMs on the same private network.

## Ready-for-Phase-3 contract

Phase 3 can begin against these stable interfaces:

1. `DeviceIdentity` supplies `device_id`, public key, and fingerprint.
2. `PeerRecord` supplies the discovered endpoint, identity fingerprint, source, status, and trust flag.
3. `DiscoveryService` reserves the local TCP listener and publishes the service endpoint.
4. `AppSettings` supplies the device name, receive directory, selected interface, and startup preference.
5. The UI already distinguishes discovered peers from manual peers and does not claim that discovery equals trust.

Phase 3 should implement authenticated pairing over the reserved local listener, persist trust decisions, display fingerprint confirmation, and reject all file transfer requests until the peer is explicitly trusted.
