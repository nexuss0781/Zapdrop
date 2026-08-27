# Zapdrop Phase 14 Active-Transfer Interruption Acceptance

**Status:** Active recipient cancellation implemented and qualified; receiver-process restart during active payload writes remains open.

The experimental `swarm-v2` direct path now has a real throttled loopback test that starts a multi-piece transfer, cancels one recipient while payload transmission is active, and verifies that the sender exits without completing the destination file. The test accepts the expected interruption or connection-shutdown error produced when the canceled stream closes and confirms that a complete destination file is not published.

During this acceptance work, an edge case was corrected in sparse-range generation: an object absent from the journal now receives piece-sized missing ranges instead of one oversized range. This keeps large fresh transfers valid under the v2 range validator.

The default v1 path is unchanged. Parent-level and per-recipient cancellation controls remain distinct, and receiver approval is still required before v2 key provisioning.

## Verification

| Check | Result |
|---|---|
| Active v2 recipient cancellation | Passed on loopback |
| Cancellation during throttled payload handling | Passed |
| No completed destination publication | Passed |
| Large untracked object range splitting | Passed for two full pieces plus a tail |
| Persisted sparse-resume regression | Passed |
| Multi-page metadata-chain regression | Passed |
| Full qualification | Passed with 58 gated desktop tests, 2 companion tests, and frontend build |

## Honest boundary

This phase does not terminate the real receiver process during an active payload write. It also does not implement subtree reuse across independent network snapshots, directory/piece-index retrieval, source-mutation revision exchange, or 4 GiB-plus physical-PC acceptance. Those remain separate work. `swarm-v2` remains feature-gated and experimental.
