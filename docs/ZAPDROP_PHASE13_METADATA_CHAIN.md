# Zapdrop Phase 13 Bounded Metadata-Chain Transport

**Status:** Implemented and qualified; active-transfer interruption remains open.

The experimental `swarm-v2` direct path now transports a bounded chain of encrypted snapshot metadata pages before the receiver approval offer. Each page contains file object references derived from the sender manifest, is bound to the transfer job ID, carries a content-derived page ID, and links to the next page. The receiver reads until a terminal page, validates page IDs and links, enforces the 2,048-page chain cap, and compares the complete object set with the signed manifest before presenting approval.

The packing target is 16 KiB per metadata payload, while the existing encrypted frame cap remains authoritative. This supports large manifests without switching the default v1 path or weakening the trusted-peer and receiver-consent boundary.

## Verification

| Check | Result |
|---|---|
| Multi-page construction | Passed with a deterministic 600-item manifest |
| Page packing bound | Passed against the 16 KiB target plus envelope allowance |
| Page-ID content binding | Passed; tampered content or IDs are rejected |
| Chain link and terminal-page validation | Passed |
| Manifest object-set binding | Passed |
| Existing v2 direct transfer | Passed |
| Persisted sparse-resume loopback | Passed |
| Full qualification | Passed with 56 gated desktop tests, 2 companion tests, and frontend build |

## Honest boundary

This is a bounded metadata-chain transport, not a complete content-addressed tree exchange. Directory and piece-index object retrieval, subtree reuse across independent network snapshots, active-transfer interruption handling, and 4 GiB-plus physical-PC acceptance remain open. `swarm-v2` remains feature-gated and experimental; v1 remains the default.
