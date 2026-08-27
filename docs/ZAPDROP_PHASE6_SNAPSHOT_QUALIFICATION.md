# Zapdrop Phase 6 Snapshot Qualification

**Status:** Controlled large-fixture and sparse-resume qualification implemented; 4 GiB-plus physical and process-termination acceptance remains open.

This phase adds `scripts/snapshot_qualification.sh` and two deterministic tests. The fixture test creates 512 files of 4096 bytes each across 16 directories, builds the snapshot twice, verifies 512 files and 2 MiB of content, checks that content-addressed root and file identifiers are stable, ensures metadata pages remain within the configured 64 KiB serialized bound, and confirms an unchanged subtree is reusable through its recorded generation.

The sparse-resume test records three non-contiguous 1 MiB verified ranges in a 12 MiB logical file, saves the job journal atomically, reloads it, and verifies contiguous progress, verified-byte totals, and missing-piece boundaries. The metadata page packer now accounts for serialized page envelopes, page IDs, chain links, and object separators when enforcing its configured limit.

## Verification

| Check | Result |
|---|---|
| Controlled snapshot fixture | Passed: 512 files, 16 directories, 2 MiB total |
| Deterministic content identifiers | Passed across two independent builds of the unchanged fixture |
| Serialized metadata page bound | Passed with 64 KiB configured pages |
| Subtree reuse generation check | Passed for unchanged `fixture/dir-00` |
| Atomic sparse journal persistence | Passed with three non-contiguous 1 MiB ranges in a 12 MiB logical file |
| Default Rust build | Focused tests passed |
| `swarm-v2` Rust build | Focused tests passed |
| Main qualification harness | Includes the snapshot runner and passed |

## Honest boundary

These tests are controlled local fixtures. They do not prove memory behavior for millions of entries, 4 GiB-plus physical-file transfer, durable recovery after process termination, network paged-metadata exchange, or multi-PC performance. Those remain explicit acceptance work. The v1 path remains the default, and the experimental v2 path remains gated.
