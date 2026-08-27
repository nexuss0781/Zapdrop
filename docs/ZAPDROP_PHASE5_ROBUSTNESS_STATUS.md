# Zapdrop Phase 5 Robustness and Dependency Audit

**Status:** Deterministic robustness gate and dependency-audit evidence implemented; advisory remediation remains open.

This phase adds a repeatable `scripts/security_qualification.sh` gate. It runs focused regression tests for traversal rejection, conflict handling, retry classification, the three-recipient scheduler harness, oversized v2 frame rejection, unsafe v2 metadata and snapshot mismatch, pre-approval key-envelope rejection, and v2 channel lifetime exhaustion. The main `scripts/qualification.sh` harness now invokes this security gate before the complete default and `swarm-v2` desktop suites.

The gate also runs `cargo-audit` in machine-readable mode against both Rust crates and fails if known vulnerabilities are found. The current audit recorded zero known vulnerabilities in the desktop and companion lockfiles. The desktop lockfile contains 489 dependency entries and the companion lockfile contains 12.

## Audit evidence captured on 2026-08-27

| Crate | Known vulnerabilities | Informational advisory findings | Release interpretation |
|---|---:|---:|---|
| `apps/zapdrop-desktop/src-tauri` | 0 | 16 unmaintained and 1 unsound transitive advisory | Not a clean release-security signoff. The GTK3/Unicode transitive findings remain for review, including `glib` 0.18.5 unsoundness advisory `RUSTSEC-2024-0429`. |
| `apps/zapdrop-companion` | 0 | 0 | No advisory findings reported by the current database. |

The raw machine-readable outputs are generated under the ignored `target/security-audit/` directory during each run. The gate intentionally does not hide informational or unsound warnings; they remain evidence requiring dependency review and platform-specific impact analysis.

## Honest boundary

This phase does not add a fuzzing corpus or claim independent security review. It provides deterministic malformed-input and boundary regression coverage plus a reproducible dependency-audit command. The v1 transfer path remains the default. The experimental `swarm-v2` path remains opt-in and is not TLS 1.3 or production-certified transport security.

The next separate phase is explicit v2 re-handshake/rekey orchestration. It must not be combined with this robustness and audit phase.

## Verification

The focused security runner passed in the default and `swarm-v2` configurations. The full automated qualification passed with 46 tests in the gated desktop suite, 2 companion tests, and a successful frontend production build. Hardware-dependent physical-LAN, packet-capture, fuzzing, and independent-review gates remain open.
