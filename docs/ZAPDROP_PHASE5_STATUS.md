# Zapdrop Phase 5 Status

**Status:** Implemented and pushed; concurrent transfer CI verified
**Project:** standalone `nexuss0781/Zapdrop` private repository
**Phase:** native file explorer integration, transfer history, and advanced receive management

## Delivered

Zapdrop now provides native source selection through the Tauri dialog plugin. Users can select multiple files or one folder from the operating-system picker. Selected paths are sent to a Rust `inspect_sources` command, which canonicalizes existing paths, rejects symbolic links and non-regular sources, and returns safe display metadata. The WebView does not receive a generic filesystem read/write capability. A diagnostics-only path field remains available for testing and troubleshooting, but it is routed through the same safe inspection command.

The explorer area now presents selected-source chips, file/folder type, metadata, removal controls, and separate **Choose files** and **Choose folder** actions. The existing trusted-recipient workflow remains unchanged: sharing is blocked until every selected recipient is an explicitly trusted peer, and one independent worker is created per recipient up to the Phase 4 limit of eight parallel recipients.

Transfer history is persisted locally in `transfer-history.json` through an atomic JSON replacement. The store retains at most 500 entries, updates a stable `{transfer-id}:{peer-id}` record across lifecycle transitions, and records direction, peer, source names, item count, total and completed bytes, status, conflict policy, timestamps, and failure text. The frontend exposes a local history view with filters for direction and status, byte and timestamp formatting, and a clear-history action.

Incoming transfers now use a two-stage authenticated offer flow. The receiver first validates the signed transfer hello and exact trusted-peer binding, acknowledges the session, validates the manifest, and emits an `incoming-transfer-offer`. It does not send resumable offsets and does not write transfer bytes until the user accepts the offer. The offer displays the sender, item summary, total size, existing destination conflicts, destination field, and conflict policy selector. The receiver can accept with `rename`, `overwrite`, or `skip`, optionally choose a destination, or reject the offer. Pending offers expire after two minutes and are removed during subsequent offer-list operations. A persisted **Always ask before receiving files** setting is enabled by default; disabling it permits automatic acceptance only for already trusted peers and still applies the configured default conflict policy.

## Native command surface

| Command | Purpose |
|---|---|
| `list_directory` | Canonicalizes and lists a local directory for future explorer expansion. Symlinks are identified and not treated as regular sources. |
| `inspect_sources` | Validates selected file/folder paths and returns safe metadata. |
| `list_pending_transfers` | Returns authenticated incoming offers awaiting a decision. |
| `accept_transfer` | Applies a receiver-selected policy and destination, sends resumable offsets, and starts the receive worker. |
| `reject_transfer` | Rejects and removes a pending incoming offer without writing files. |
| `list_transfer_history` | Loads the local bounded transfer ledger. |
| `clear_transfer_history` | Atomically clears the local transfer ledger. |
| `start_transfer` | Starts trusted-recipient parallel transfer workers. |
| `cancel_transfer` | Requests cancellation for all workers belonging to a transfer ID. |

## Receive protocol

```text
Sender                         Receiver
  |                               |
  |-- signed transfer hello ----->|
  |<-- hello accepted -------------|
  |-- manifest ------------------->|
  |<-- incoming-transfer-offer ---|  (local app event; no bytes written)
  |                               |
  |       user accepts            |
  |<-- resumable offsets ----------|
  |-- chunk header + bytes ------->|
  |-- chunk header + bytes ------->|
  |<-- completed / failed ---------|
```

The receive decision is local and is never granted to an unknown or merely discovered peer. The receiver still enforces canonical destination resolution, relative-path validation, reserved partial-state isolation, per-chunk checksums, complete-file checksums, conflict policies, and cancellation. Destination symlinks are rejected before replacement.

## Persisted settings

The settings schema is now version 2 and remains backward-compatible with Phase 4 settings files. Existing records receive these defaults when loaded:

| Setting | Default | Meaning |
|---|---:|---|
| `alwaysAskBeforeReceive` | `true` | Hold every trusted incoming offer for explicit local review. |
| `defaultConflictPolicy` | `rename` | Policy used for automatic acceptance when the user disables always-ask. |

The receive directory remains user-configurable. Native folder selection is limited to source selection in this phase; changing the receive directory remains a deliberate settings action.

## Verification

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed after formatting the new modules and tests |
| Rust unit tests | Passed: 15/15 |
| Explorer inspection and symlink rejection tests | Passed |
| History persistence/update/clear test | Passed |
| React/TypeScript production build | Passed |
| Tauri native release build without installer bundling | Passed (`CARGO_BUILD_JOBS=2`; release binary generated) |
| `git diff --check` | Passed |
| Browser preview | Passed; native picker actions, receive review section, and history view rendered coherently |
| Concurrent A-to-B/B-to-A transfer test | Passed on GitHub Actions run [33086473036](https://github.com/nexuss0781/Zapdrop/actions/runs/33086473036); both files and receive histories verified |
| Two-PC LAN acceptance test | Not run in the headless sandbox |

## Known limitations and next phase

The transport remains authenticated through signed identity material and trusted-peer binding, but Phase 5 does **not** claim TLS or payload encryption. A later security-hardening phase should add encrypted transport or document an equivalent protection model before production use on hostile local networks. Desktop OS notifications are represented by in-app events and the receive review panel; a notification plugin is not required for the Phase 5 acceptance path. The concurrent CI test uses two isolated protocol peers over the same runner’s loopback interface; it does not replace a real two-PC LAN, Wi-Fi hotspot, multicast, throughput, interruption/resume, or firewall acceptance test.

The next phase should prioritize two-machine acceptance tests, encrypted transport hardening, a fuller native directory browser, and optional platform notification integration.
