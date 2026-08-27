# Zapdrop Phase 12 Process-Termination Journal Acceptance

**Status:** Actual journal-worker termination acceptance implemented; active receiver termination during payload writes and physical-file qualification remain open.

The snapshot test suite now self-spawns the journal worker test binary. The child creates and atomically commits a valid journal, writes a truncated `.tmp` artifact to represent an in-flight replacement, signals readiness, and remains alive. The parent terminates the child process, then verifies that the last committed journal still loads and that the incomplete temporary artifact remains isolated. The same test passes in default and `swarm-v2` builds.

This validates the atomic-save crash boundary with an actual process termination rather than only a pure function test. The receiver’s partial-file/journal mismatch reset and the fresh v2 sparse-resume loopback remain covered separately.

## Verification

| Check | Result |
|---|---|
| Self-spawned journal worker | Passed |
| Process termination after stale `.tmp` creation | Passed |
| Last committed journal survives | Passed |
| Truncated temporary artifact remains isolated | Passed |
| Default build | Passed |
| `swarm-v2` build | Passed |
| Main qualification harness | Includes the test |

## Honest boundary

The test does not terminate the real receiver in the middle of an active payload write. It also does not qualify multi-page metadata transport, subtree reuse across independent network snapshots, source mutation revisions, or 4 GiB-plus physical-file transfer. Those remain separate acceptance work. The v1 path remains the default, and `swarm-v2` remains feature-gated and experimental.
