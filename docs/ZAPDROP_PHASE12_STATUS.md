# Zapdrop Phase 12 Status

**Status:** Automated qualification harness implemented; physical release gate remains open.

The repository now includes `scripts/qualification.sh`. It refuses to run when the experimental v2 direct-transfer environment switch is enabled, runs formatting and default/feature-gated Rust library suites, builds and tests the standalone companion, builds the frontend, checks whitespace, and rejects obvious credential artifacts in the working tree.

The harness is intentionally not a substitute for the release gate. A final release requires at least two physical PCs on wired Ethernet, Wi-Fi infrastructure mode, and a phone-hotspot network; discovery and manual endpoint fallback; trusted and untrusted peer behavior; multi-recipient transfers; simultaneous bidirectional transfers; cancellation and resume; conflict policies; symlink and permission edge cases; firewall and multicast behavior; packet captures demonstrating the expected absence of readable v2 payloads; and Windows runtime smoke tests for the shipped installer and executable.

Privacy posture remains direct-only by default. The Phase 9 relay control plane does not enable forwarding, and no relay or telemetry service is required for local operation. Any future relay mode must have an explicit user-visible consent setting, job-scoped capabilities, revocation behavior, and a reviewed data-retention policy.

Until the physical matrix, packet capture, dependency audit, fuzzing, and independent sign-off are complete, the release status is **engineering preview**, not production-certified secure transport.
