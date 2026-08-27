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

### Phase 4 — Direct-transfer security closure slice

Address one security closure item at a time, beginning with explicit v2 session rekey/lifetime behavior and tests. Keep v1 default and preserve exact trust binding and receive approval. Do not market the result as TLS 1.3 or certified security.

**Exit evidence:** A narrowly scoped security change has tests, threat-model notes, and independent-review status recorded.

### Phase 5 — Protocol robustness and dependency gate

Add malformed-input/fuzz targets or bounded property tests for discovery, pairing, manifests, secure frames, snapshot metadata, and journals; run dependency auditing; and record packet-capture expectations for the v1 and experimental v2 paths.

**Exit evidence:** Reproducible robustness commands and their results are checked in, with unresolved findings listed rather than hidden.

### Phase 6 — Phase 7 large-dataset acceptance

Stress snapshot indexing, subtree reuse, sparse resume, source mutation, disk-full behavior, Unicode paths, and large files using controlled local fixtures. Separate memory/CPU measurements from functional pass/fail claims.

**Exit evidence:** Automated large-dataset report and remaining 4 GiB-plus physical-file requirements are documented.

### Phase 7 — Phase 9 direct-only topology integration

Only after the direct path and authorization gates are stable, implement the least-privilege tree/mesh data plane behind an explicit feature flag. Enforce signed job scope, relay consent, object allow-lists, byte budgets, expiry, revocation, and direct fallback. Do not enable arbitrary forwarding.

**Exit evidence:** Multi-process tests demonstrate that unauthorized relays cannot receive or forward unrelated content, and direct fallback remains functional.

### Phase 8 — Phase 10 repair integration

Evaluate repair coding against measured loss conditions, then integrate only a bounded encrypted repair path if it improves completion time or source amplification without unacceptable CPU/memory cost. Keep systematic direct transfer as the reference path.

**Exit evidence:** Loss-injection benchmark, resource measurements, protocol tests, and an explicit decision to enable or defer repair.

### Phase 9 — Phase 11 companion runtime boundary

Implement the companion’s authenticated pairing, receive approval, send/receive operations, snapshot/piece/journal compatibility, and version negotiation only for platforms that can be built and tested honestly. If legacy Windows runtime support cannot be qualified, publish a clear supported-platform boundary instead of claiming compatibility.

**Exit evidence:** Modern desktop and companion exchange content in a reproducible test, or the unsupported-platform boundary is documented and enforced.

### Phase 10 — Final Windows release and physical qualification

Run the full automated gate, build Windows artifacts, perform the physical-LAN matrix, record privacy and firewall behavior, publish compatibility and known limitations, and package only artifacts whose signing and runtime status are explicit.

**Exit evidence:** Release checklist, test logs, Windows artifact metadata, manual-LAN evidence, rollback notes, and unresolved gates are all available.

## Immediate next move

The next implementation action is **Phase 2 only**: build the local multi-recipient acceptance harness. No Phase 9, Phase 10, Phase 11, or final-release work will be started in the same phase. After Phase 2 passes, the change will be committed and pushed before Phase 3 begins.
