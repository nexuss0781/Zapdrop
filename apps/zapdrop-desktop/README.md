# Zapdrop Desktop

Zapdrop is the local-only desktop client for sharing files between trusted PCs on the same network. This package is intentionally isolated from the existing Nexuss web application so that the desktop client can eventually operate without the web server or an internet connection.

## Phase 1 scope

Phase 1 provides the Tauri 2 desktop shell, React/TypeScript frontend, Rust backend, a minimal Tauri capability policy, and a typed native bridge command. The dashboard is a visual scaffold for the upcoming discovery, pairing, filesystem, and transfer phases. It does not yet perform network discovery or send files.

The dashboard can be previewed in a normal browser with the Vite server. In that mode, the native command bridge uses a safe fallback so the UI remains inspectable. Running through Tauri invokes the Rust `get_app_info` command and displays the native runtime information.

## Development

From the repository root:

```bash
pnpm --dir apps/zapdrop-desktop install
pnpm --dir apps/zapdrop-desktop dev
```

To run the desktop shell with the native bridge:

```bash
pnpm --dir apps/zapdrop-desktop tauri dev
```

To build the frontend and type-check it:

```bash
pnpm --dir apps/zapdrop-desktop build
```

To check the Rust backend:

```bash
cargo check --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml
```

The Tauri Windows development prerequisites include Rust, Microsoft C++ Build Tools, and WebView2. Linux development additionally requires the WebKitGTK and GTK development libraries described by the Tauri documentation.

## Next phase

Phase 2 will add persistent settings and device identity. Phase 3 will add local network interface selection, mDNS/DNS-SD registration and browsing, peer expiration, and the manual endpoint fallback.
