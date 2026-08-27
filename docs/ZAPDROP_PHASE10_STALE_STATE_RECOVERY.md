# Zapdrop Phase 10 Stale-State Recovery Boundary

**Status:** Fail-closed partial-file and journal reconciliation implemented; operating-system termination acceptance remains open.

The experimental v2 receiver now centralizes partial-file and journal reconciliation. If a partial file exists without a matching contiguous journal offset, if the journal offset disagrees with a non-final partial file length, if the partial file exceeds the manifest size, or if its length is not piece-aligned, the receiver removes the partial file and resets the stale journal item before computing missing ranges. A complete-length partial file is preserved as the explicit final-file exception so a completed journal can be reconciled safely.

This prevents stale metadata from causing the sender to skip bytes after a later session. The behavior is covered by deterministic boundary tests and the real v2 sparse-resume loopback test remains in the qualification runner.

## Verification

| Check | Result |
|---|---|
| Partial file without journal | Passed: reset to offset zero |
| Non-final partial/journal length mismatch | Passed: reset to offset zero and remove stale journal item |
| Piece misalignment | Passed: reset to offset zero |
| Oversized partial file | Passed: reset to offset zero |
| Complete-length partial exception | Passed: preserved for final reconciliation |
| Fresh v2 sparse-resume loopback | Passed: missing ranges transferred and final digest verified |
| Full qualification | Passed: 51 gated desktop tests, 2 companion tests, frontend build |

## Honest boundary

The automated test does not kill a receiver process during an actual write. A real operating-system termination test, durability measurement, multi-page metadata transport, and 4 GiB-plus physical-file acceptance remain separate manual or future integration gates. The default v1 path is unchanged, and `swarm-v2` remains feature-gated and experimental.
