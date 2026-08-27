# Zapdrop

Zapdrop is a desktop application for sharing files directly between trusted PCs on the same local network. It does not depend on the Nexuss-Agent web application or a public internet connection for its core workflow.

## Repository structure

```text
apps/zapdrop-desktop/   Tauri 2 + React + Rust desktop app
docs/                   Architecture and implementation research
```

## Current status

Phase 1 is complete: the Tauri desktop shell, React dashboard, Rust bridge, capabilities, icon assets, and project scripts are present.

Phase 2 is complete: persistent settings, stable device identity, protected private-key storage, mDNS/DNS-SD discovery, peer state events, diagnostics, and manual endpoint fallback are implemented. See `docs/ZAPDROP_PHASE2_STATUS.md` for the verification record and Phase 3 contract.

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

The application is local-only by design. Phase 2 discovery uses mDNS/DNS-SD when available and preserves a manual local endpoint fallback for networks that block multicast.
