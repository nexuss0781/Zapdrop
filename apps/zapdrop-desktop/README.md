# Zapdrop Desktop

Zapdrop is the local-only desktop client for sharing files between trusted PCs on the same network. This package is intentionally isolated from the Nexuss web application, so its discovery and future transfer workflow can operate without the web server or an internet connection.

## Phase 2 status

Phase 2 is complete. The native runtime now creates and persists application settings, creates a stable Ed25519 device identity, computes a public-key fingerprint, stores private key material in the OS keyring on Windows and macOS where supported, and uses a restrictive `0600` file fallback on Unix-like systems when a keyring is unavailable.

The runtime advertises the device as `_zapdrop._tcp.local.` using mDNS/DNS-SD and continuously browses for other Zapdrop services. TXT metadata carries the protocol version, device ID, display name, platform, identity fingerprint, and capability hints. Resolved peers are emitted to the UI through `peer-updated` and `peer-removed` events. The service uses a local/private interface and keeps a local TCP listener reserved for the transfer phases.

The Phase 2 UI can refresh discovery, show mDNS diagnostics, edit the device name and receive directory, toggle advertisement on startup, reset the device identity, and add a validated private `ip:port` manual endpoint when multicast discovery is unavailable. Pairing and actual file transfer are intentionally deferred to later phases.

## Native commands

| Command | Purpose |
|---|---|
| `get_app_info` | Returns the app version, device identity, key-storage mode, and data directory. |
| `get_settings` | Loads the persisted settings snapshot. |
| `update_settings` | Atomically persists a settings patch and restarts discovery when required. |
| `reset_identity` | Replaces the device key pair and restarts mDNS advertisement. |
| `list_peers` | Returns the current mDNS and manual peer registry. |
| `get_network_diagnostics` | Returns interface, port, service type, and fallback status. |
| `scan_network` | Returns the current continuously browsed peer snapshot and emits `scan-complete`. |
| `add_manual_endpoint` | Validates and adds a private/local `ip:port` peer endpoint. |

## Runtime data

Zapdrop stores settings and identity metadata in the platform data directory selected by the `directories` crate. The settings file is `settings.json`, the public identity record is `identity.json`, and the Unix fallback secret is `identity.key`. JSON writes use a temporary file followed by rename to reduce the chance of a partially written settings file.

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

Rust compile check and Phase 2 unit tests:

```bash
pnpm check
cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --lib
```

Native Tauri build without installer bundling:

```bash
pnpm desktop:build
```

The Tauri Windows development prerequisites include Rust, Microsoft C++ Build Tools, and WebView2. Linux development additionally requires the WebKitGTK and GTK development libraries described by the Tauri documentation.

## Next phase

Phase 3 is ready to begin. It should implement the authenticated pairing handshake over the reserved local TCP listener, peer trust persistence, identity fingerprint confirmation, and explicit accept/reject flows. File transfer should remain disabled until that trust boundary is complete.
