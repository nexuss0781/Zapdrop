# Zapdrop Phase 4 Security Hardening

**Status:** Explicit v2 channel lifetime limits implemented and tested; re-handshake/rekey orchestration remains open.

This phase closes one narrow fail-closed boundary in the experimental `swarm-v2` channel. Send and receive accounting now uses one explicit plaintext-budget predicate that rejects a frame when the next plaintext would exceed the configured `2^40`-byte channel budget, including the previously ambiguous case where a single plaintext is larger than the full budget. The existing `2^32` frame sequence ceiling remains enforced before nonce use.

The channel returns `SequenceExhausted` before advancing sequence or byte counters. Tests cover the exact byte boundary, an over-budget plaintext length, send-side sequence exhaustion, send-side byte exhaustion, and authenticated receive-side byte exhaustion. The v1 direct transfer path is unchanged and remains the default.

This is not a rekey implementation. The v2 protocol still requires explicit re-handshake or rekey orchestration before a channel reaches its lifetime ceiling, plus independent security review, malformed-input fuzzing, packet capture, and physical-LAN qualification. Until those gates are complete, `swarm-v2` remains opt-in and must not be described as TLS 1.3 or production-certified transport security.

## Verification

The focused test `secure::tests::channel_lifetime_limits_fail_closed_at_exact_boundaries` passes in both default and `swarm-v2` builds. The complete v2 library suite also passes after this change.
