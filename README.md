# Zapdrop

Zapdrop is a desktop application for sharing files directly between trusted PCs on the same local network. It does not depend on the Nexuss-Agent web application or a public internet connection for its core workflow.

## Repository structure

```text
apps/zapdrop-desktop/   Tauri 2 + React + Rust desktop app
docs/                   Architecture and implementation research
```

## Current status

Phase 1 is complete: the Tauri desktop shell, React dashboard, Rust bridge, capabilities, icon assets, and project scripts are present.

Phase 2 is complete: persistent settings, stable device identity, protected private-key storage, mDNS/DNS-SD discovery, peer state events, diagnostics, and manual endpoint fallback are implemented. Phase 3 is complete: authenticated pairing, fingerprint confirmation, and trusted-peer persistence are implemented. Phase 4 is complete: trusted-peer-only transfer sessions, safe path validation, checksummed chunks, conflict policies, resumable partial files, progress events, cancellation, and bounded parallel recipients are implemented. Phase 5 is complete: native file/folder selection, safe Rust source inspection, bounded local transfer history, incoming-transfer offers with explicit accept/reject, receive destinations, and conflict-policy controls are implemented. See `docs/ZAPDROP_PHASE5_STATUS.md` for the verification record and known limitations.

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
