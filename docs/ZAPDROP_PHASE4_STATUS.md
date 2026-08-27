# Zapdrop Phase 4 Status

**Status:** Implemented; final verification and repository push pending  
**Project:** standalone `nexuss0781/Zapdrop` private repository  
**Phase:** transfer engine, safe destination resolution, and parallel streaming

## Delivered

Zapdrop now has a trusted-peer-only transfer engine on the existing local TCP listener. The sender opens one independent session per selected recipient, sends a signed transfer hello, waits for a receiver acknowledgement, sends a manifest, receives resumable offsets, and streams file chunks. The receiver dispatches transfer sessions only after the sender identity is verified and matches an exact trusted-peer record.

The transfer manifest supports regular files and recursively enumerated directories. Each item carries a deterministic item ID derived from its relative path, relative path, type, byte size, and SHA-256 digest. Deterministic IDs allow a retry with the same transfer ID to reuse partial item state. Every streamed chunk carries its transfer ID, item ID, relative path, offset, length, and SHA-256 digest. The receiver verifies the digest before writing the bytes and verifies the complete-file digest before moving the partial file into the receive directory.

The destination resolver canonicalizes the configured receive root, accepts only relative manifest paths, rejects absolute paths, parent traversal, symbolic-link sources, duplicate item IDs or paths, unsupported item types, size overflow, manifest total-size mismatches, and the reserved `.zapdrop-partial` state path. Partial files are isolated below `.zapdrop-partial/<transfer-id>`. The final destination is created only below the canonical receive root.

The receiver implements `rename`, `overwrite`, and `skip` conflict policies. The default sender policy is `rename`, which selects a numbered conflict-free filename. `skip` completes the item without replacing an existing destination. `overwrite` replaces the destination after the complete digest succeeds.

The sender validates all selected recipients against the runtime trust projection before starting. A transfer is limited to eight parallel recipients. Each worker has independent network and file state, while cancellation is shared by transfer ID and cleaned once the final worker exits. Progress events are emitted per recipient for start, transfer, completion, failure, and cancellation. The UI accepts an explicit local source path, starts transfers only for trusted recipients, renders per-recipient progress bars, and exposes cancellation.

## Native command surface

| Command | Purpose |
|---|---|
| `start_transfer` | Validates sources and trusted recipients, then starts independent parallel sessions. |
| `cancel_transfer` | Requests cancellation for all workers belonging to a transfer ID. |

## Protocol sequence

```text
Sender                         Receiver
  |                               |
  |-- signed transfer hello ----->|
  |<-- hello accepted -------------|
  |-- manifest ------------------->|
  |<-- resumable offsets ----------|
  |-- chunk header + bytes ------->|
  |-- chunk header + bytes ------->|
  |<-- completed ------------------|
```

The hello acknowledgement is intentionally sent before the manifest so the receiver can inspect the first frame without losing a subsequently buffered frame. The receiver keeps one persistent buffered reader for the manifest and all binary chunk payloads, preserving stream boundaries when TCP reads ahead.

## Verification

| Check | Result |
|---|---|
| Rust formatting | Passed |
| Rust compile check | Passed |
| Rust unit tests | Passed: 10/10 |
| Path traversal tests | Passed |
| Conflict rename/skip/invalid-policy tests | Passed |
| Existing settings, identity, trust, pairing, and discovery tests | Passed |
| React/TypeScript production build | Passed |
| Native Tauri release build without installer bundling | Passed |
| Git diff check | Passed before documentation update |

The sandbox cannot run a full two-PC transfer acceptance test because it is headless and has no second desktop instance on a shared private network. Acceptance testing should exercise one file, a nested directory, a duplicate destination, an interrupted transfer resumed with the same transfer ID, cancellation, untrusted-peer rejection, and two simultaneous trusted recipients.

## Phase 5 contract

Phase 5 can begin with the following stable interfaces:

1. `TransferSource` accepts a native file or directory path and an optional relative root name.
2. `TransferRequest` accepts recipient IDs, source paths, an optional transfer ID, and a conflict policy.
3. `TransferProgress` is emitted per recipient and includes bytes, item counts, current path, status, and error text.
4. `start_transfer` and `cancel_transfer` are available to the frontend.
5. The receiver’s trust check and safe destination resolver must remain mandatory for every connection, including retries and manual endpoints.

The next phase should replace the explicit source-path field with native file/folder selection, persist transfer history, add received-file notifications, and perform two-machine throughput and resume acceptance testing.
