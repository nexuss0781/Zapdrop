# Zapdrop Phase 10 Status

**Status:** Bounded repair-coding and adaptive-decision foundation implemented; wire integration and benchmark acceptance remain open.

Phase 10 adds a dependency-free GF(256) linear repair layer. It supports systematic symbols, deterministic repair-symbol generation, bounded blocks of at most 64 source symbols and 1 MiB symbols, Gaussian-elimination reconstruction, and safe rejection of incompatible or linearly dependent symbol sets. Repair symbols carry the block identifier and coefficient vector so reconstruction cannot mix unrelated jobs.

A conservative adaptive controller maps measured loss, round-trip time, and CPU budget to a chunk size, in-flight limit, and repair-symbol count. Invalid measurements are handled conservatively. The controller is intentionally a decision primitive rather than an automatic transport override.

This is **not** an implementation or certification of RaptorQ. It is a bounded linear fountain-style foundation suitable for later comparison with a vetted RaptorQ library. Repair symbols are not yet sent on the v2 wire, and no performance claim is made until loss-injection and physical-LAN benchmarks exist. The reliable direct path remains the reference path.
