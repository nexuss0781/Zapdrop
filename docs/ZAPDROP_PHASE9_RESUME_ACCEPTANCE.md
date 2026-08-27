# Zapdrop Phase 9 Interruption and Resume Acceptance

**Status:** Persisted sparse-resume loopback acceptance implemented; process-termination and physical-file gates remain open.

The experimental `swarm-v2` direct path now has a real loopback acceptance test for a large logical file. The test creates a file spanning two complete 4 MiB pieces plus a tail, pre-seeds the receiver’s job-scoped partial file and journal with the first verified piece, starts a fresh authenticated direct session, and verifies that the receiver retains the verified range, requests the missing ranges, completes the file digest, and records the journal item as complete.

This test exercises the existing network ready-frame sparse-range negotiation rather than merely testing journal methods in isolation. Receiver approval remains mandatory before key provisioning, and the metadata page still arrives before the offer. The v1 path is unchanged and remains the default.

## Verification

| Check | Result |
|---|---|
| Fresh v2 direct session with persisted state | Passed on loopback |
| Verified prefix retention | Passed: first 4 MiB piece was retained |
| Missing-range negotiation | Passed through the encrypted ready frame |
| Final content integrity | Passed against the complete source file |
| Journal completion persistence | Passed after final publication |
| Default and gated builds | Existing snapshot and direct tests pass; resume test is gated by `swarm-v2` |
| Main qualification harness | Includes the resume test through `scripts/snapshot_qualification.sh` |

## Honest boundary

The test uses a controlled local loopback and pre-seeded persisted state. It does not simulate an operating-system crash during a write, prove durable recovery after process termination, qualify multi-page metadata for very large trees, or replace the 4 GiB-plus physical-PC test. Those remain separate acceptance gates. The experimental v2 path remains opt-in and is not TLS 1.3 or production-certified transport security.
