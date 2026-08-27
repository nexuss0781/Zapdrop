# Zapdrop

Zapdrop is a desktop application for sharing files directly between trusted PCs on the same local network. It does not depend on the Nexuss-Agent web application or a public internet connection for its core workflow.

## Repository structure

```text
apps/zapdrop-desktop/   Tauri 2 + React + Rust desktop app
docs/                   Architecture and implementation research
```

## Current status

Phase 1 is complete: the Tauri desktop shell, React dashboard, Rust bridge, capabilities, icon assets, and project scripts are present.

Phase 2 is complete: persistent settings, stable device identity, protected private-key storage, mDNS/DNS-SD discovery, peer state events, diagnostics, and manual endpoint fallback are implemented. Phase 3 is complete: authenticated pairing, fingerprint confirmation, and trusted-peer persistence are implemented. Phase 4 is complete: trusted-peer-only transfer sessions, safe path validation, checksummed chunks, conflict policies, resumable partial files, progress events, cancellation, and bounded parallel recipients are implemented. Phase 5 is complete: native file/folder selection, safe Rust source inspection, bounded local transfer history, incoming-transfer offers with explicit accept/reject, receive destinations, and conflict-policy controls are implemented. Phase 6 v2 direct-transfer hardening includes versioned swarm protocol models, signed ephemeral handshakes, X25519 key agreement, HKDF-SHA256 directional keys, ChaCha20-Poly1305 frame protection, exact persisted peer-key binding independent of discovery metadata, job-key envelopes with content-key-ID binding, snapshot-bound AAD and canonical manifest-root validation, replay protection, secure-profile negotiation, bounded length-prefixed encrypted records, capped active connections and pending offers, symlink-resistant hashed staging paths, encrypted job/decision/key/ready/piece/completion frames, UI-backed receiver approval, piece-aligned resume negotiation, receive progress/history, and an opt-in real-TCP encrypted direct-file path. Phase 7 adds canonical content-addressed snapshot and bounded piece-index foundations with crash-safe journals. Phase 8 adds parent/child multi-recipient accounting and partial-success history. Phase 9 adds least-privilege relay grants, topology selection, and branch-revocation controls without enabling forwarding. Phase 10 adds bounded fountain-style repair and conservative adaptive decisions. Phase 11 adds a separately buildable WebView-free companion contract. Phase 12 adds an automated qualification harness and a documented physical-LAN release matrix. The active v1 file-transfer path remains the default; v2, relay forwarding, repair symbols, and legacy companion transport remain gated pending rekey orchestration, packet-capture review, physical-LAN qualification, and independent security sign-off. See `docs/ZAPDROP_SWARM_PROTOCOL_V2.md`, `docs/ZAPDROP_PHASE7_STATUS.md` through `docs/ZAPDROP_PHASE12_STATUS.md`, and `docs/ZAPDROP_FINAL_PHASES_ROADMAP.md`.

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

Rust compile check:

```bash
pnpm check
```

Native Tauri build without installer bundling:

```bash
pnpm desktop:build
```

The application is local-only by design. Discovery uses mDNS/DNS-SD when available and preserves a manual local endpoint fallback for networks that block multicast. File sharing is blocked until a peer has completed authenticated pairing and is present in `trusted-peers.json`. Transfer sessions run directly between trusted peers and do not use cloud storage. Incoming transfers are held for local review by default, and Phase 5 does not claim TLS payload encryption; see the Phase 5 status document before using Zapdrop on a hostile local network.
