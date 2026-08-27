# Zapdrop Implementation Plan

**Project:** Zapdrop  
**Purpose:** Offline, local-network file sharing between nearby PCs  
**Prepared by:** Manus AI  
**Status:** Architecture and MVP planning

## 1. Product definition

Zapdrop is a cross-platform desktop application inspired by Xender. Multiple PCs install the application, discover one another on the same Wi-Fi network or hotspot, pair with explicit user approval, browse local files and folders, and transfer selected items to one or more nearby PCs simultaneously. The core product promise is that file sharing works **without an internet connection**; the local network is the only required transport.

The first release should focus on reliable PC-to-PC transfer rather than attempting to reproduce every feature of Xender. The MVP should support Windows first, with the architecture kept portable to macOS and Linux. A later release can add mobile clients, clipboard sharing, remote browsing, and more advanced transfer acceleration.

| Area | MVP decision | Later expansion |
|---|---|---|
| Devices | Nearby PCs running Zapdrop | Phones, tablets, and browser clients |
| Network | Same Wi-Fi LAN or Wi-Fi hotspot | Ethernet, IPv6-only networks, relay-assisted mode |
| Discovery | Automatic local discovery with manual IP fallback | QR-based invitation and remembered devices |
| Security | Explicit pairing, device identity, encrypted connection | Organization policies and managed trust groups |
| Files | Multi-select files and folders | Drag-and-drop, clipboard, quick-share menu |
| Recipients | One or multiple PCs, transferred in parallel | Group aliases and saved recipient groups |
| Transfer | Progress, pause, cancel, retry, overwrite policy | Resumable interrupted jobs and deduplicated peer fan-out |
| Internet | Not required and not used for payload transfer | Optional update checking or telemetry, disabled by default |

## 2. User experience and flows

### 2.1 First launch

On first launch, Zapdrop asks the user for a device name and creates a persistent local device identity. The device name is visible to peers, but the application should not expose the user’s operating-system username, home-directory path, or other unnecessary personal information during discovery. The home screen then starts the local discovery service and shows the current network status.

The user should see a clear status such as **Ready on “Home Wi-Fi”**, **Waiting for local network permission**, or **No peers found**. The interface must explain that an internet connection is not needed and that some guest Wi-Fi networks block device-to-device communication.

### 2.2 Discover and pair

When the user clicks **Scan**, Zapdrop browses for nearby Zapdrop services and displays each discovered PC as a device card containing the device name, operating system, approximate address or connection status, and trust state. Discovery should also run in the background while the application is open so that the scan button is an explicit refresh action rather than the only discovery mechanism.

Selecting an unpaired device starts a pairing request. Both devices display the other device name and a short verification code or equivalent confirmation phrase. The pairing succeeds only after the receiving user accepts and the verification values match. Once paired, the devices remain available as trusted peers until the user revokes trust.

### 2.3 Select and send

The main workspace should contain a local file explorer with breadcrumb navigation, a list/grid toggle, file and folder icons, size and modified-time columns, multi-selection, and a right-click context menu. The primary actions are **Share**, **Share to**, and **Open containing folder**. The user can select files, folders, or a mixture of both and then select one or more trusted recipients.

Before the transfer starts, Zapdrop shows a confirmation sheet with the item count, total size, recipients, destination behavior, and conflict policy. The default destination should be a dedicated `Zapdrop` folder inside the receiver’s chosen download directory rather than silently writing to arbitrary locations.

### 2.4 Receive

An incoming transfer request must be visible before any file is written. The receiver can accept, reject, accept once, or remember an approved sender. The request must show the sender, item names, total size, and destination folder. For safety, the receiver can set a default action for trusted senders, but the initial release should default to confirmation for every transfer.

During transfer, both sender and receiver see per-job progress. The sender sees a recipient-specific state because one peer may complete while another is paused or offline. The receiver sees disk space checks, file conflict choices, and the final saved location. Completed jobs appear in a local history view with sender, recipients, item count, size, time, and outcome.

### 2.5 Failure and recovery

The application must distinguish between a peer disappearing, a user rejecting a request, a file changing during transfer, insufficient disk space, permission failure, an existing-file conflict, and an integrity-check failure. Each error should have a plain-language explanation and an actionable recovery such as **Retry**, **Choose another folder**, **Skip**, or **Cancel all**.

## 3. Recommended technical architecture

The selected repository, `nexuss0781/Nexuss-Agents`, is currently a Vite/React/TypeScript application with a Node/Express server, tRPC, Drizzle, and database/storage-oriented dependencies. Its current build scripts target a web client and Node server rather than a native desktop binary. The safest approach is therefore to add Zapdrop as a separate desktop application within the repository instead of trying to turn the existing server into the file-transfer engine.

The recommended stack is **Tauri 2 + React/TypeScript + Rust/Tokio**. Tauri separates a WebView-based frontend from a Rust backend using message passing, which lets the existing team reuse React UI skills while keeping filesystem, socket, discovery, and cryptographic operations in a native backend [1]. Tokio provides the asynchronous runtime and networking foundation, while Rustls provides TLS client/server support and encrypted connections [2] [3].

| Layer | Recommendation | Responsibility |
|---|---|---|
| Desktop shell | Tauri 2 | Window lifecycle, packaging, native commands, permissions, tray integration |
| UI | React + TypeScript + existing design conventions where reusable | Explorer, device cards, pairing dialogs, transfer queue, history |
| Native backend | Rust | Filesystem access, network listeners, discovery, pairing, transfer scheduling |
| Async runtime | Tokio | Concurrent listeners, peer connections, bounded transfer workers |
| Discovery | mDNS/DNS-SD with a manual IP fallback | Advertise and browse Zapdrop peers on the local link |
| Control protocol | Versioned length-delimited messages | Pairing, offers, acceptance, progress, cancellation, errors |
| Payload transport | Authenticated TLS over TCP for MVP | Stream file bytes with backpressure and integrity checks |
| Local persistence | SQLite or a small versioned local database | Device identity, trusted peer keys, settings, transfer history |
| Shared contracts | Versioned protocol schemas and generated types where practical | Keep frontend/backend and future clients compatible |

### 3.1 Repository layout

Create a dedicated desktop boundary so that the current web product remains buildable while Zapdrop is developed:

```text
Nexuss-Agents/
├── apps/
│   └── zapdrop-desktop/
│       ├── src/                 # React/TypeScript UI
│       ├── src-tauri/           # Rust desktop backend
│       ├── package.json
│       └── README.md
├── packages/
│   └── zapdrop-protocol/        # Versioned schemas and shared constants
├── docs/
│   └── ZAPDROP_IMPLEMENTATION_PLAN.md
└── existing web application...
```

If the repository does not yet use an `apps` workspace, the initial implementation can live under `desktop/zapdrop` while the workspace structure is introduced in a small, isolated change. The desktop project should not depend on the existing Node server for discovery, pairing, transfers, or file access. It must run locally when the internet and the existing web backend are unavailable.

## 4. Local discovery design

Zapdrop should advertise a service such as `_zapdrop._tcp.local` using multicast DNS and DNS-Based Service Discovery. DNS-SD defines browsing service instances and resolving them through PTR, SRV, and TXT records [4]. Each running instance advertises its listening port and a small set of non-sensitive metadata.

A proposed advertisement is:

```text
Service type: _zapdrop._tcp.local
Instance: <human-readable-device-name> <short-device-id>._zapdrop._tcp.local
SRV: host and ephemeral TCP port
TXT:
  v=1
  id=<stable-device-id>
  name=<display-name>
  platform=windows|macos|linux
  caps=folders,multi-recipient,resume
```

The stable device ID must not be the raw hardware serial number or MAC address. Generate a random identifier during first launch and persist it locally. If the network supplies multiple interfaces, advertise and listen only on private/local interfaces selected by the operating system or by the user. Avoid exposing a publicly routable interface by default.

Discovery is not authentication. A malicious or unrelated device can advertise the same service name, so every discovered peer remains **untrusted** until pairing completes. A manual fallback should allow the user to enter a local IP address and port, with the same authentication and pairing checks applied.

The implementation must handle these network conditions explicitly:

| Condition | Expected behavior |
|---|---|
| Normal home Wi-Fi | Automatic discovery and direct connection |
| Wi-Fi hotspot | Automatic discovery if the hotspot permits client-to-client traffic |
| Guest Wi-Fi or AP isolation | Explain that the network blocks peer traffic and offer manual testing or another network |
| Windows firewall prompt | Request the minimum private-network inbound permission and explain why it is needed |
| VPN or virtual adapters | Prefer the active private LAN interface and allow the user to disable an interface |
| Multicast blocked | Keep the manual IP/QR invitation fallback available |
| Peer changes IP | Re-resolve service records instead of permanently trusting an address |

## 5. Pairing and security model

### 5.1 Device identity

At first launch, generate a device key pair and a self-signed local certificate or equivalent public-key identity. Store the private key using the operating system’s protected storage where available. The persisted identity should survive restarts but must be resettable from Settings with an explicit warning that all trusted peers will need to pair again.

### 5.2 Pairing

Use a two-step model:

1. Discovery identifies a candidate peer but grants no access.
2. An authenticated pairing exchange is approved by the user on both devices and binds the peer’s stable device ID to its public key.

The pairing dialog should show a short verification code derived from both public keys and a fresh nonce. The user confirms that the code displayed on both screens matches. After approval, store the peer public key and device metadata locally. Subsequent connections should reject a changed public key and require deliberate re-pairing rather than silently accepting it.

### 5.3 Connection security

Use TLS 1.3 where supported through Rustls, with certificate or public-key pinning to the paired peer. Rustls documents encrypted client/server connections and does not expose a main-API switch for disabling certificate verification [3]. The application layer should still verify the paired device identity because a normal public certificate authority is not the trust model for local peers.

The control protocol should include a protocol version, device ID, connection nonce, monotonically increasing message ID, and request/job ID. Reject malformed messages, unexpected state transitions, oversized metadata, duplicate IDs, and requests that exceed configured limits. Never trust a peer-provided path as an operating-system path.

### 5.4 Filesystem safety

The receiver must normalize every incoming relative path and ensure that its final destination remains inside the selected destination root. Reject absolute paths, parent traversal such as `../`, device names, invalid path components, and symlink escapes. Write files to a temporary job-specific directory and atomically rename them only after the full-file integrity check passes.

The receiver must never overwrite by default. The initial conflict choices should be **Keep both**, **Replace**, **Skip**, and **Ask for each**. A sender can transmit metadata and hashes, but the receiver remains responsible for local policy and available disk space.

## 6. Transfer protocol

### 6.1 Job lifecycle

A transfer is a job with one sender, one recipient connection, one manifest, and one or more entries. When the user selects multiple recipients, Zapdrop creates a recipient-specific transfer session for each peer. This makes progress, cancellation, retry, and failure independent while still allowing all sessions to run concurrently.

```text
DISCOVERED
  -> PAIRING_REQUIRED
  -> TRUSTED
  -> OFFER_SENT
  -> ACCEPTED or REJECTED
  -> PREPARING
  -> TRANSFERRING
  -> VERIFYING
  -> COMPLETED

TRANSFERRING may also transition to PAUSED, FAILED, or CANCELED.
```

### 6.2 Manifest and chunks

The sender first sends a manifest containing the job ID, protocol version, item count, relative paths, file sizes, modification timestamps, and optional content hashes. The receiver validates the manifest, selects a destination, checks available space, applies conflict policy, and accepts or rejects the job.

For each file, stream a sequence of length-delimited chunks. The receiver writes to a partial file and reports acknowledged offsets. Calculate a cryptographic digest for each completed file and compare it with the sender’s digest when supplied. A whole-job digest is useful for audit logging but should not require buffering the entire job in memory.

Recommended initial defaults are 1–8 MiB chunks, one stream per file per recipient, and a bounded number of active recipient connections. The exact values should be measured on low-end disks, fast wired LAN, Wi-Fi, and hotspot scenarios rather than treated as fixed performance guarantees.

### 6.3 Parallel multi-recipient sending

When one selection is shared to several recipients, the sender should open independent sessions and schedule them through a bounded task pool. This is true parallel transfer without allowing an accidental large recipient count to exhaust file handles, memory, or bandwidth.

Use a per-recipient queue with states for queued, active, paused, retrying, completed, failed, and canceled. The sender reads from disk in a backpressured way rather than loading all files into memory. If several recipients request the same file, a later optimization can read a bounded block once and fan it out to multiple writers; this should not complicate the reliable MVP.

### 6.4 Resume and retry

The MVP should support retrying a failed file or job from the beginning. The protocol should nevertheless include file offsets and stable file identifiers so resumable transfer can be added without breaking compatibility. Before resuming, compare the source metadata or content hash with the original manifest and restart if the source changed.

## 7. User-interface modules

| Module | Core UI | Backend contract |
|---|---|---|
| Home/dashboard | Network status, Scan, trusted peers, recent jobs | Discovery events and peer state |
| Device list | Discovered, trusted, offline, blocked states | Browse/resolve/pair/revoke commands |
| File explorer | Folders, files, breadcrumbs, multi-select, context menu | Permission-scoped filesystem listing and metadata |
| Share dialog | Selected items, recipient multi-select, conflict policy | Create transfer jobs and validate manifest |
| Incoming request | Sender, contents, size, destination, accept/reject | Approve or reject offer |
| Transfer center | Per-recipient progress, speed, ETA, pause/cancel/retry | Job lifecycle and progress events |
| History | Search/filter completed and failed jobs | Local transfer database |
| Settings | Device name, download root, trusted peers, network interfaces | Persisted settings and identity management |
| Tray menu | Open, scan, pause all, quit | Background lifecycle and notifications |

All long-running work should emit typed events to the UI. The frontend should never poll the filesystem or socket layer in a tight loop. Events should be coalesced so that progress updates do not cause unnecessary React re-renders, especially for many simultaneous recipients.

## 8. Implementation milestones

### Milestone 0: Architecture spike

Create the Tauri desktop shell and verify that a packaged application can launch on Windows. Add a Rust command that returns the local device ID and a React screen that displays it. Build a small local-only test harness that can launch two instances on one machine with separate data directories.

**Exit criteria:** Two local instances start; the UI can call Rust; device identity persists; the current web application still passes its existing checks.

### Milestone 1: Device identity and discovery

Implement identity generation, local settings, mDNS/DNS-SD advertisement, service browsing, peer list updates, deduplication, expiration, and manual IP entry. Add a network diagnostics panel that shows the selected interface, listening port, and whether the service is visible.

**Exit criteria:** Two PCs on the same private LAN discover one another without an internet connection; a manually entered peer can be resolved; blocked multicast produces a clear fallback message.

### Milestone 2: Pairing and secure session

Implement the pairing request, dual approval, verification code, public-key pinning, trust revocation, TLS connection setup, protocol version negotiation, and connection timeouts. Add tests for wrong-code rejection, changed-key rejection, replayed requests, malformed messages, and unpaired access attempts.

**Exit criteria:** A discovered but unpaired PC cannot browse or transfer; paired PCs reconnect securely; revoking trust invalidates later connections.

### Milestone 3: Local file explorer

Implement permission-scoped listing, breadcrumbs, sorting, search within the selected root, file/folder selection, context menu, and the destination-folder setting. Keep path operations in Rust and return normalized metadata to the UI.

**Exit criteria:** The user can select mixed files and folders, see an accurate total size, and choose a safe destination without exposing paths outside the approved scope.

### Milestone 4: One-to-one transfer

Implement manifest creation, incoming approval, disk-space validation, conflict handling, temporary files, streaming chunks, file hashes, atomic finalization, progress events, cancellation, and retry.

**Exit criteria:** A 0-byte file, small file, large file, nested folder, Unicode filename, duplicate filename, and permission failure behave correctly. Receiver output matches sender content hashes.

### Milestone 5: Multi-recipient parallel transfer

Add recipient-specific jobs, bounded concurrency, independent progress, one-recipient failure isolation, cancel-one and cancel-all actions, and aggregate history. Measure throughput and memory use with two, five, and ten recipients where available.

**Exit criteria:** Sending one selection to several paired PCs proceeds concurrently; a disconnected recipient does not corrupt or cancel successful transfers to other recipients.

### Milestone 6: Packaging and hardening

Add Windows installer packaging, application icons, firewall guidance, crash logging that excludes file contents and private paths where possible, signed release artifacts, upgrade behavior, and a supportable diagnostics export. Then validate macOS and Linux portability before declaring the architecture stable.

**Exit criteria:** A clean machine can install, launch, approve required private-network access, pair, transfer, uninstall, and reinstall without stale trust or data corruption.

## 9. Testing strategy

Testing must cover both protocol correctness and the behavior of real local networks. Unit tests should validate path normalization, manifest rules, conflict resolution, chunk accounting, digest verification, state transitions, and bounded scheduling. Integration tests should run two local backend instances against isolated temporary directories and exercise pairing, transfer, cancellation, retry, and resume-compatible offsets.

The release gate should include a physical-device matrix rather than relying only on loopback. At minimum, test two Windows PCs on a home router, two PCs connected through a hotspot, a network with client isolation, a machine with an active VPN, a large nested folder, filenames in multiple scripts, a disk-full simulation, sleep/wake during transfer, and an abrupt process termination.

| Test category | Required checks |
|---|---|
| Discovery | Service appears, expires, reappears, and handles duplicate names |
| Trust | Pairing confirmation, wrong code, changed key, revoke, replay protection |
| Protocol | Version mismatch, invalid message lengths, out-of-order messages, timeout |
| Filesystem | Traversal, symlink escape, overwrite policy, Unicode, long names, permissions |
| Integrity | Empty files, hashes, truncated chunks, corrupted payload, atomic finalization |
| Concurrency | Multiple recipients, one failure, cancel one, cancel all, resource limits |
| Network | Wi-Fi, hotspot, Ethernet, blocked multicast, address change, disconnect/reconnect |
| Packaging | Fresh install, firewall, offline launch, update, uninstall, clean reinstall |

## 10. Important product decisions to confirm

The implementation can start with the following defaults, but these decisions should be confirmed before Milestone 1 is coded:

| Decision | Recommended default |
|---|---|
| Target operating systems | Windows first; macOS and Linux follow |
| Desktop framework | Tauri 2 |
| Transfer transport | TLS 1.3 over TCP for MVP |
| Discovery | mDNS/DNS-SD plus manual IP fallback |
| Default receiver behavior | Confirm every incoming transfer |
| Default destination | A dedicated Zapdrop folder under the user-selected downloads root |
| Conflict behavior | Keep both unless the receiver explicitly chooses another option |
| Trust persistence | Persistent pinned peer identity with explicit revoke |
| Internet dependency | None for discovery, pairing, or payload transfer |
| Repository strategy | Separate `apps/zapdrop-desktop` boundary; preserve current web app |

## 11. Non-goals for the first release

The MVP should not include cloud storage, internet relays, accounts, server-side file indexing, unrestricted remote filesystem browsing, silent background acceptance from unknown devices, or automatic overwrite of existing files. It should also avoid implementing a custom cryptographic primitive or depending on a central service to make two local PCs communicate.

The most important quality target is not a marketing speed number. It is predictable behavior: the correct device is selected, the receiver explicitly controls where files go, corrupted or partial output is not presented as complete, and a problem on one recipient does not damage transfers to other recipients.

## 12. Immediate next steps

1. Confirm that the existing `Nexuss-Agents` repository is the intended home for Zapdrop and bind/select that repository folder before implementation begins.
2. Create a dedicated `apps/zapdrop-desktop` Tauri scaffold without changing the existing web application’s runtime behavior.
3. Implement the two-instance local harness before building the polished explorer UI.
4. Prove discovery and pairing on two real PCs connected to the same hotspot, because multicast and firewall behavior are the highest-risk assumptions.
5. Add the protocol and filesystem safety tests before implementing multi-recipient parallelism.
6. Ship one-to-one transfer first, then add independent parallel recipient sessions.

## References

[1]: https://v2.tauri.app/concept/architecture/ "Tauri Architecture"

[2]: https://tokio.rs/ "Tokio — An asynchronous Rust runtime"

[3]: https://docs.rs/rustls/latest/rustls/ "Rustls documentation"

[4]: https://www.rfc-editor.org/rfc/rfc6763 "RFC 6763: DNS-Based Service Discovery"

[5]: https://github.com/nexuss0781/Nexuss-Agents "nexuss0781/Nexuss-Agents repository"
