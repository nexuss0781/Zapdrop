# Zapdrop Next-Agent Handoff

**Project:** Zapdrop  
**Repository:** [`nexuss0781/Zapdrop`](https://github.com/nexuss0781/Zapdrop)  
**Working directory:** `/home/ubuntu/Zapdrop`  
**Branch:** `main`  
**Current checkpoint:** `92409c9 feat: complete gated tree mesh routing`  
**Handoff status:** Phases 1–17 complete; Phase 18 is the next active phase.  
**Release policy:** Do not create or publish release artifacts before Phase 20.

## 1. Mission and non-negotiable boundaries

Zapdrop is a standalone Tauri 2, React, and Rust desktop application for trusted, offline local-network file and folder sharing among Windows-oriented PCs. The product model is familiar to Xender: devices discover one another on a Wi-Fi LAN or hotspot, trusted peers can be selected, files or folders can be chosen through the desktop explorer, and one sender can transfer to multiple recipients in parallel without internet access.

Discovery is never authorization. Every receiving operation must remain bound to an explicitly trusted peer, an exact public key and fingerprint, receiver consent, safe destination resolution, and authenticated job/snapshot/object scope. Unknown peers must not receive file authority. Do not weaken these properties to make tests or demos pass.

The default v1 path must remain unchanged. `swarm-v2` is experimental and must be enabled explicitly. `swarm-tree-mesh` is a second explicit feature that depends on `swarm-v2`; it is not enabled in default v1 or ordinary v2 builds. Do not describe v2 or tree/mesh as TLS 1.3, production-certified, independently reviewed, physically qualified, or Windows-runtime qualified. Those claims require evidence that does not yet exist.

The strict execution rule remains: implement exactly one manageable phase or slice, test it, document it, commit it, push it, and report it before beginning the next phase. Work only in `/home/ubuntu/Zapdrop` and the `nexuss0781/Zapdrop` repository. Never modify `Nexuss-Agents`.

## 2. Current repository state

The latest pushed commit is `92409c9`. The expected post-handoff workflow is to verify the branch and working tree before making changes:

```bash
cd /home/ubuntu/Zapdrop
. "$HOME/.cargo/env"
git status --short
git log -5 --oneline --decorate
git remote -v
```

The handoff documentation itself must be committed and pushed as a separate documentation checkpoint. After that commit, `git status --short` should be empty and `origin/main` should point at the new handoff commit.

## 3. What is complete through Phase 17

Phases 1–16 established persistent settings and identity, local discovery, authenticated pairing and trusted-peer persistence, safe direct transfer, transfer history and receive management, bounded multi-recipient scheduling, the experimental v2 secure channel, job-key provisioning, authenticated metadata chains, sparse resume and crash-safe journals, cancellation, snapshot object catalogs, local cross-snapshot reuse, and authenticated network directory/piece-index object retrieval.

Phase 17 is complete within an explicit experimental direct-only tree/mesh boundary. Its implementation is in `apps/zapdrop-desktop/src-tauri/src/mesh.rs` and is guarded by `swarm-tree-mesh` in `apps/zapdrop-desktop/src-tauri/Cargo.toml`.

| Completed capability | Contract that must be preserved |
|---|---|
| Topology planning | A relay is selected only for a Tree or Mesh job with an authorized and consented candidate, valid matching `RelayGrant`, object allow-list, byte budget, and expiry. |
| Direct fallback | Direct-only jobs, missing grants, unavailable candidates, insufficient grant budget, and relay failure produce explicit direct fallback. Invalid or mismatched grants fail closed. |
| Opaque relay storage | `RelayPieceStore` stores already-encrypted v2 piece envelopes only. It does not receive a job content-decryption key and does not decrypt or re-encrypt payloads. |
| Branch control | Assignments and connection requests/responses use typed messages with dedicated AEAD associated data and bind job, snapshot, sender parent, relay, child, objects, bytes, expiry, and nonce. |
| Live listener | `RelayListener` uses bounded TCP framing, the existing signed ephemeral v2 handshake, exact trusted-peer identity matching, an eight-session cap, and bounded session control frames. |
| Parent-child routing | A trusted parent uploads an opaque encrypted piece and a separately authenticated trusted child retrieves the identical ciphertext through the relay. Requests remain child-, object-, piece-, and grant-scoped. |
| Revocation | A parent revocation is authenticated and acknowledged before the revoked child can be denied subsequent payload retrieval. |
| Measurement | Completed relay sessions report piece count, ciphertext bytes, and elapsed duration. These are bounded routing measurements, not a physical throughput qualification. |
| Feature isolation | Default v1 and ordinary `swarm-v2` behavior remain unchanged. Tree/mesh code is not enabled without the explicit feature. |

The authoritative status records are `docs/ZAPDROP_PHASE17_TOPOLOGY_CONTROL_SLICE.md` and `docs/ZAPDROP_REMAINING_PHASES_PLAN.md`. Read both before editing protocol code.

## 4. Verification baseline

Run the repository gate before and after each remaining phase. The gate intentionally reports manual boundaries rather than pretending to qualify them:

```bash
cd /home/ubuntu/Zapdrop
. "$HOME/.cargo/env"
./scripts/qualification.sh
```

The known successful baseline at the Phase 17 checkpoint is **60 desktop Rust tests, 2 companion tests, frontend TypeScript/Vite build, formatting, shell checks, snapshot qualification, security qualification, and the feature-gated mesh suite**. The qualification output explicitly leaves physical-LAN, packet-capture, Windows runtime, and independent-security gates manual.

Useful focused commands are:

```bash
cargo fmt --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml -- --check
cargo check --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml
cargo check --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --features swarm-v2
cargo check --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --features swarm-tree-mesh
cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --features swarm-tree-mesh --lib mesh::tests -- --nocapture
bash -n scripts/qualification.sh scripts/snapshot_qualification.sh scripts/security_qualification.sh
git diff --check
```

Before committing, inspect `git diff --stat`, `git diff --name-only`, and credential hygiene. Do not commit build output, private keys, tokens, `.env` files, or artifacts outside the intended Zapdrop repository.

## 5. Remaining Phase 18 — repair integration evaluation

Phase 18 is the next active phase. It must be handled independently and must not include companion work or release packaging.

The goal is to evaluate whether bounded encrypted repair coding improves completion under measured loss without unacceptable CPU, memory, latency, or source-amplification cost. Systematic direct transfer remains the reference path. Do not enable repair merely because types compile.

### Required Phase 18 work

First audit the existing repair module and current v2 piece plane. Establish the repair symbol/profile model, exact job and snapshot bindings, maximum repair symbols, maximum memory, and cancellation/expiry behavior. Any repair frame must use authenticated associated data that binds the job, snapshot, object, piece group, symbol index, and sender/recipient scope. Repair data must never bypass receiver consent, safe destination staging, journal validation, or existing content/object commitments.

Implement only a bounded experimental repair path behind an explicit feature flag if the evaluation justifies it. It must fail closed on wrong job, object, group, symbol index, length, duplicate/conflicting symbol, expiry, malformed frame, or excessive resource request. Keep the direct systematic path available and make fallback explicit when repair is unavailable, rejected, canceled, or slower than the reference path.

Add deterministic tests for reconstruction from valid repair symbols, insufficient-symbol failure, malformed and duplicate symbols, wrong-scope rejection, byte/memory limits, cancellation, expiry, and direct fallback. Add a controlled loss-injection benchmark or reproducible test fixture comparing direct and repair paths. Record CPU, memory, source bytes, completion time, and success/failure results with the test parameters; do not call this a network or physical throughput qualification unless real evidence exists.

Update `docs/ZAPDROP_REMAINING_PHASES_PLAN.md` with the decision to enable, defer, or reject repair and create a Phase 18 status document. Run the full qualification gate. Commit and push only the complete Phase 18 slice, then report the exact evidence and unresolved boundaries. Do not start Phase 19 until this is done.

### Phase 18 exit gate

Phase 18 is complete only when a bounded loss-injection benchmark, resource measurements, authenticated protocol tests, direct fallback tests, full qualification output, documentation, one coherent commit, and a clean pushed `origin/main` checkpoint are available. If repair does not improve the measured result, document the decision to defer it rather than forcing integration.

## 6. Remaining Phase 19 — companion runtime boundary

Phase 19 starts only after Phase 18 is completely closed. It must not include final release packaging.

The goal is to define and implement the companion runtime boundary honestly. The companion must support authenticated pairing, trusted-peer verification, receive approval, send/receive operations, snapshot and piece compatibility, journal/sparse-resume compatibility where supported, and explicit version negotiation. It must not silently accept insecure peers or claim support for platforms that cannot be built and tested.

Start by inspecting `apps/zapdrop-companion`, its Cargo manifest, protocol compatibility, and current tests. Use the modern desktop runtime as the reference implementation. Reuse exact identity, fingerprint, job, snapshot, object, and safe-path contracts rather than creating a parallel authorization model. Add deterministic compatibility tests for modern desktop-to-companion exchange, protocol-version rejection, wrong-key rejection, receive consent, safe destination behavior, large/sparse transfer compatibility where supported, cancellation, and journal recovery.

If legacy Windows runtime support cannot be built or executed honestly in the available environment, document and enforce a supported-platform boundary. Do not fabricate an executable or claim Windows compatibility from a Linux build. The companion phase must end with either a reproducible modern desktop/companion exchange or a clear unsupported-platform boundary enforced by the application and documentation.

### Phase 19 exit gate

Phase 19 is complete only when the companion behavior or unsupported-platform boundary is covered by reproducible tests, documentation, full qualification, a coherent commit, and a clean pushed checkpoint. Windows release packaging remains deferred to Phase 20.

## 7. Remaining Phase 20 — final Windows release and physical qualification

Phase 20 is the only release phase. Do not create a release, publish an `.exe`, or claim production readiness before Phase 20 begins and its gates are met.

The goal is to run the full automated gate, build Windows artifacts through a documented and reproducible workflow, perform the physical-LAN matrix, record privacy and firewall behavior, publish supported-platform and known-limitation statements, and package only artifacts whose signing and runtime status are explicit.

### Required Phase 20 work

Run the full qualification gate from a clean checkout and preserve its logs. Inspect and update GitHub Actions workflows as needed, but never claim a successful Windows build from a job that did not actually produce and verify the artifact. Build the Tauri Windows installer or executable using the repository’s documented toolchain. Record artifact filename, SHA-256, target architecture, build mode, commit, toolchain, signing status, and whether the artifact was executed.

Run the physical-LAN matrix on the supported Windows machines and Wi-Fi/hotspot configurations that are actually available. Record discovery, manual peer fallback, pairing, fingerprint confirmation, multi-recipient transfer, folder transfer, large-file transfer, cancellation, resume, firewall/privacy prompts, offline behavior, and failure recovery. Packet capture, independent security review, audit remediation, rekey completeness, and other unresolved security gates must remain explicitly listed if they are not performed.

Create release notes that distinguish tested behavior from planned behavior. Do not market experimental v2/tree/mesh as production-certified or TLS 1.3. Do not publish artifacts with unknown signing status. If a physical or Windows gate cannot be completed, publish a clearly labeled prerelease or unsupported boundary rather than inventing evidence.

### Phase 20 exit gate

Phase 20 is complete only when the release checklist, full test logs, Windows artifact metadata and verification, physical-LAN evidence, privacy/firewall notes, rollback notes, supported-platform statement, known limitations, and unresolved security gates are all available. Only then may a release artifact be presented or published.

## 8. Commands and working discipline for the next agent

Use the following sequence for every remaining phase:

```bash
cd /home/ubuntu/Zapdrop
. "$HOME/.cargo/env"
git status --short
# Read the relevant status and roadmap documents.
# Implement one bounded phase slice.
cargo fmt --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml
./scripts/qualification.sh
git diff --check
git status --short
git add <only-intended-files>
git commit -m "<scoped phase message>"
git push origin main
git status --short
git log -1 --oneline --decorate
```

Every user-facing report must state the active phase, concrete implementation outcome, exact test evidence, commit and push status, and the exact remaining boundary. Do not skip the documentation, commit, or push step. Do not advance the roadmap until the current phase exit evidence is real.

## 9. Immediate next action

The next agent must begin **Phase 18 repair integration evaluation**. It must not begin companion work or release work. The release remains a Phase 20 responsibility, after Phases 18 and 19 have each been separately completed and pushed.
