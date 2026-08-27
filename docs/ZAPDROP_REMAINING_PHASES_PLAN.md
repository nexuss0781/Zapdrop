# Zapdrop Remaining Phases Plan

**Plan revision:** 2026-08-27

**Purpose:** Finish Zapdrop as a trusted, offline local-network file and folder sharing application through small, verifiable increments. This plan replaces the previous broad roadmap execution style with a strict one-phase-at-a-time process.

## Execution rule

Only one phase is active at a time. A phase is not complete until its implementation, tests, documentation, and repository checks pass. Each completed phase receives its own coherent commit and push. The next phase does not start until the previous phase has been reported as complete. A foundation, design, or test scaffold is never described as a production-complete feature.

Physical-PC, packet-capture, Windows-runtime, independent-security-review, and other hardware-dependent gates are recorded explicitly when they cannot be executed in the current environment. They are not silently converted into passing automated tests.

## Audited baseline

The current branch is clean at commit `40f53ca feat: complete Phase 8 bounded swarm scheduler`, pushed to `nexuss0781/Zapdrop`. The repository remains isolated from `Nexuss-Agents`.

| Area | Current truth | Classification |
|---|---|---|
| Core desktop app | Tauri 2, React/Vite frontend, Rust backend, local discovery, manual endpoint fallback, pairing/trust, receive approval, safe paths, history, and direct transfer are implemented. | Implemented baseline |
| Default transport | v1 direct transfer remains the default product path. | Implemented and retained as default |
| Secure v2 transport | Authenticated encrypted direct path is feature-gated and has substantial tests, but its independent security, rekey, fuzzing, packet-capture, and physical-LAN gates remain open. | Experimental foundation |
| Phase 7 | Snapshot, canonical paths, content-addressed metadata, journal recovery, sparse ranges, source-generation checks, and free-space preflight foundations are implemented and tested. | Foundation integrated; stress and physical acceptance remain open |
| Phase 8 | FIFO bounded admission, waiting queue, shared per-parent bandwidth pacing, transient-only retries, parent aggregate progress, parent cancellation, per-recipient cancellation, and UI controls are implemented and automated qualification passes. | Automated implementation slice complete; LAN acceptance remains open |
| Phase 9 | Least-privilege relay grants, topology selection, and revocation control-plane structures exist. No forwarding data plane is enabled. | Control-plane foundation only |
| Phase 10 | Bounded GF(256) repair primitives and conservative adaptive decisions exist. Repair is not enabled on the wire. | Algorithm foundation only |
| Phase 11 | Standalone companion capability/version/path contract exists. Shared encrypted transfer runtime is not implemented. | Contract foundation only |
| Phase 12 | Automated qualification script exists. Physical-LAN and release gates remain open. | Harness foundation only |

## Ordered execution phases

### Phase 1 — Baseline audit and plan lock

**State:** Complete in this revision.

**Deliverables:** Audit the repository and harness; record the truthful implementation boundary; check in this plan; push the plan before implementing the next feature.

**Exit evidence:** Clean branch, recent commit recorded, qualification harness inspected, and this document pushed.

### Phase 2 — Local multi-recipient acceptance harness

**Next active phase.** Add deterministic local tests that exercise an actual one-to-many transfer job with at least three recipients, bounded active admission, queued recipients, one failed child, one cancelled child, and parent outcome reconciliation. Where a full socket setup is impractical, use a narrowly scoped test seam rather than claiming a network test that was not run.

**Exit evidence:** Tests prove recipient isolation, queue admission, parent aggregate outcomes, and no active-count leaks. Default and `swarm-v2` suites pass, and the harness is included in `scripts/qualification.sh`.

### Phase 3 — Phase 8 qualification package

Add a repeatable operator script and evidence template for two, four, and eight real trusted PCs; mixed files and folders; hotspot/router modes; heterogeneous recipient speeds; cancellation; retry; receiver rejection; and failure injection. The script must distinguish automated results from required human observations.

**Exit evidence:** Qualification package is committed and documented. Real hardware results are only marked complete after they are actually supplied or executed.

### Phase 4 — v2 channel lifetime boundaries

**State:** Complete as a bounded lifetime-enforcement slice; re-handshake/rekey orchestration remains open.

Use one explicit accounting predicate for v2 send and receive channels. Refuse frames before sequence or byte-counter advancement when the `2^32` frame ceiling or `2^40` plaintext ceiling would be exceeded. Keep v1 default and preserve exact trust binding and receive approval. Do not market the result as TLS 1.3 or certified security.

**Exit evidence:** Exact-boundary, over-budget, send-side, and receive-side fail-closed tests pass in default and `swarm-v2` builds. See `docs/ZAPDROP_PHASE4_SECURITY_HARDENING.md`.

### Phase 5 — Direct-transfer security closure slice

Implement explicit v2 re-handshake/rekey orchestration as a separate phase, followed by independent review. Keep rekey traffic authenticated, job-scoped, bounded, and fail-closed; do not enable v2 by default.

### Phase 6 — Protocol robustness and dependency gate

Add malformed-input/fuzz targets or bounded property tests for discovery, pairing, manifests, secure frames, snapshot metadata, and journals; run dependency auditing; and record packet-capture expectations for the v1 and experimental v2 paths.

**Exit evidence:** Reproducible robustness commands and their results are checked in, with unresolved findings listed rather than hidden.

### Phase 7 — Controlled Phase 7 snapshot qualification

**State:** Complete in this revision; physical and process-termination gates remain open.

Stress snapshot indexing, subtree reuse, sparse resume, source mutation, disk-full behavior, Unicode paths, and large files using controlled local fixtures. Separate memory/CPU measurements from functional pass/fail claims.

**Exit evidence:** A 512-file deterministic fixture, bounded serialized metadata pages, unchanged-subtree reuse, and atomic sparse journal persistence pass in default and `swarm-v2` builds. See `docs/ZAPDROP_PHASE6_SNAPSHOT_QUALIFICATION.md`.

### Phase 8 — One-page authenticated network metadata exchange

**State:** Complete in this revision; multi-page transport and interruption acceptance remain open.

The experimental v2 direct path sends one encrypted, job-bound snapshot metadata page before the receiver offer. The receiver validates the page against the signed manifest before presenting approval. The default v1 path remains unchanged.

**Exit evidence:** Existing v2 direct roundtrip passes with the new frame ordering, metadata mismatch tests pass, and the full qualification harness passes. See `docs/ZAPDROP_PHASE8_NETWORK_METADATA.md`.

### Phase 9 — Persisted sparse-resume loopback acceptance

**State:** Complete in this revision; process-termination and physical-PC gates remain open.

The experimental v2 direct path starts a fresh authenticated session against a pre-seeded partial file and journal, retains verified ranges, requests missing ranges through the encrypted ready frame, verifies the final digest, and records journal completion.

**Exit evidence:** The real v2 loopback resume test passes, the snapshot qualification runner includes it, and the full qualification harness passes. See `docs/ZAPDROP_PHASE9_RESUME_ACCEPTANCE.md`.

### Phase 10 — Fail-closed stale-state recovery

**State:** Complete in this revision; operating-system termination and physical-file gates remain open.

Centralize partial-file and journal reconciliation so a non-final length mismatch, missing journal, oversized partial, or piece-misaligned partial resets stale state before missing-range negotiation. Preserve only the explicit complete-length exception.

**Exit evidence:** Deterministic mismatch-boundary tests and the real v2 persisted sparse-resume loopback pass in the full qualification harness. See `docs/ZAPDROP_PHASE10_STALE_STATE_RECOVERY.md`.

### Phase 11 — Crash-artifact journal recovery acceptance

**State:** Complete in this revision; actual process termination and physical-PC gates remain open.

Verify that stale temporary files cannot replace the last committed journal and that truncated or wrong-kind journal records fail closed. Keep the receiver’s partial-file and journal mismatch reset behavior covered by deterministic tests.

**Exit evidence:** Crash-artifact and malformed-journal tests pass in default and `swarm-v2` builds, the sparse-resume loopback remains green, and the full qualification harness passes. See `docs/ZAPDROP_PHASE10_STALE_STATE_RECOVERY.md`.

### Phase 12 — Journal-worker process-termination acceptance

**State:** Complete in this revision; active receiver termination during payload writes remains open.

The qualification suite self-spawns and terminates a journal worker after a committed journal and an in-flight truncated temporary artifact exist, then verifies the committed record survives.

**Exit evidence:** Default and `swarm-v2` process-termination tests pass, and the full qualification harness includes them. See `docs/ZAPDROP_PHASE12_PROCESS_TERMINATION.md`.

### Phase 13 — Bounded multi-page metadata-chain transport

**State:** Complete in this revision; active-transfer interruption and broader snapshot integration remain open.

The experimental v2 direct path transports a bounded encrypted chain of metadata pages before approval, validates content-derived page IDs and links, and matches the complete object set against the signed manifest.

**Exit evidence:** A deterministic 600-item chain test, existing direct transfer, sparse resume, and the full qualification harness pass. See `docs/ZAPDROP_PHASE13_METADATA_CHAIN.md`.

### Phase 14 — Active-transfer cancellation acceptance

**State:** Complete in this revision; receiver restart during active payload writes and broader snapshot integration remain open.

The experimental v2 sender now has a real throttled loopback cancellation test. A recipient canceled while payload transmission is active exits without completing or publishing the destination file. Untracked large objects also split into valid piece-sized missing ranges.

**Exit evidence:** Active cancellation, large missing-range splitting, metadata-chain, sparse-resume, and full qualification tests pass. See `docs/ZAPDROP_PHASE14_ACTIVE_INTERRUPTION.md`.

### Phase 15 — Cross-snapshot object integration acceptance

Qualify receiver restart during an active payload write, subtree reuse across independent network snapshots, directory and piece-index object retrieval, explicit source-mutation revisions, and the 4 GiB-plus physical-file requirement as a separately recorded hardware gate.

### Phase 16 — Phase 9 direct-only topology integration

Only after the direct path and authorization gates are stable, implement the least-privilege tree/mesh data plane behind an explicit feature flag. Enforce signed job scope, relay consent, object allow-lists, byte budgets, expiry, revocation, and direct fallback. Do not enable arbitrary forwarding.

**Exit evidence:** Multi-process tests demonstrate that unauthorized relays cannot receive or forward unrelated content, and direct fallback remains functional.

### Phase 17 — Phase 10 repair integration

Evaluate repair coding against measured loss conditions, then integrate only a bounded encrypted repair path if it improves completion time or source amplification without unacceptable CPU/memory cost. Keep systematic direct transfer as the reference path.

**Exit evidence:** Loss-injection benchmark, resource measurements, protocol tests, and an explicit decision to enable or defer repair.

### Phase 18 — Phase 11 companion runtime boundary

Implement the companion’s authenticated pairing, receive approval, send/receive operations, snapshot/piece/journal compatibility, and version negotiation only for platforms that can be built and tested honestly. If legacy Windows runtime support cannot be qualified, publish a clear supported-platform boundary instead of claiming compatibility.

**Exit evidence:** Modern desktop and companion exchange content in a reproducible test, or the unsupported-platform boundary is documented and enforced.

### Phase 19 — Final Windows release and physical qualification

Run the full automated gate, build Windows artifacts, perform the physical-LAN matrix, record privacy and firewall behavior, publish compatibility and known limitations, and package only artifacts whose signing and runtime status are explicit.

**Exit evidence:** Release checklist, test logs, Windows artifact metadata, manual-LAN evidence, rollback notes, and unresolved gates are all available.

## Immediate next move

Phase 14 is complete in this revision. The next implementation action is **Phase 15 only**: qualify cross-snapshot object integration. No tree/mesh, repair, companion, or release work will be started in the same phase. Phase 15 must be tested, documented, committed, and pushed before the next phase begins.
