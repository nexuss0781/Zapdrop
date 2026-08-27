# Zapdrop Final Production Phases Roadmap

**Document status:** Design approved for implementation planning  
**Current implementation:** Phases 1–5 complete  
**Product goal:** Secure, direct, offline file sharing between trusted PCs on the same local area network, with predictable high-throughput transfers, concurrent multi-PC distribution, large-file recovery, and a realistic path beyond legacy Windows file sharing.

## 1. Product target

Zapdrop should be positioned as an **application-level local transfer network**, not as a replacement for SMB shared folders. SMB exposes a remote filesystem model that is useful for mounted shares but brings administrative permissions, share configuration, credential management, and legacy protocol behavior into the user experience. Zapdrop should instead provide a deliberate send workflow: discover nearby peers, verify identity, select local content, choose recipients, approve incoming offers, transfer directly, and commit verified files locally.

The core workflow must remain independent of a public internet connection, cloud account, relay service, domain controller, or centralized server. mDNS/DNS-SD is appropriate for zero-configuration local discovery because it is designed for DNS-like operations on a local link without conventional unicast DNS infrastructure and is intended to work with little administration [1]. Discovery must remain optional, however, because guest Wi-Fi networks, firewalls, VPNs, and hotspot implementations may block multicast. Manual private endpoint entry and an invitation-code path must remain first-class fallbacks.

The current Phase 5 implementation already demonstrates the important product boundaries: pairing is explicit, trusted peers are required, incoming transfers are reviewed before writes, paths are validated in Rust, history is local, and the bidirectional CI test transfers one file in each direction concurrently. The next phases must turn that correctness foundation into a production-grade transport and performance system.

## 2. Compatibility envelope

The current Tauri desktop client should have a narrow, supportable compatibility contract rather than an unverified promise for every historical Windows release. Tauri’s current documentation describes WebView2 as supported on Windows 7 and newer, while Microsoft’s current Edge support matrix lists supported Edge platforms beginning with Windows 10 SAC 1709 and selected LTSC editions [2] [3]. Tauri also requires Microsoft C++ Build Tools and WebView2 for Windows development, and states that WebView2 is already present on Windows 10 version 1803 onward [4].

Therefore, the recommended product contract is Windows 10 version 1803 or later for the maintained graphical client, with Windows 11 as the primary target. Windows 7 and 8.1 should not be called fully supported until a pinned WebView2/runtime combination, installer path, security update policy, and real hardware test matrix are proven. If those systems are strategically required, support should be delivered through a separately tested headless or minimal native companion that uses the same signed transfer protocol and does not depend on the modern WebView UI.

| Platform class | Product treatment | Required evidence |
|---|---|---|
| Windows 11 x64 | Primary supported GUI target | Clean install, offline install, private Wi-Fi, hotspot, wired LAN, firewall, sleep/wake, large-file tests |
| Windows 10 1803+ x64 | Supported GUI target, subject to current WebView2/runtime availability | Versioned installer and WebView2 checks across supported editions |
| Windows 10 LTSC editions | Supported only for explicitly tested editions | Clean-machine matrix and WebView2 installation policy |
| Windows 7/8.1 | Compatibility evaluation or legacy companion target; not automatic GUI support | Pinned runtime, signed installer, IPv4/TLS test, no unsupported UI claims |
| Windows XP/Vista and unsupported CPUs | Not supported | Clear installer and documentation rejection message |
| macOS/Linux | Later portable-client targets | Native packaging, discovery, firewall, and filesystem-specific test matrix |

## 3. Final implementation phases

### Phase 6 — Encrypted authenticated transport

**Objective.** Replace the current authenticated-but-plaintext TCP payload with a confidential transport while preserving the trusted-device identity model.

The first implementation should use TLS 1.3 over the existing TCP connection. TLS 1.3 is designed to prevent eavesdropping, tampering, and message forgery [5]. Device identity keys should remain the trust anchor: the session certificate or public-key binding must be verified against the persisted trusted-peer record, not against a public certificate authority. The signed application hello should remain inside the protected session for protocol identity, transfer authorization, and replay checks.

The phase must define certificate creation and rotation, peer-key changes, session resumption policy, protocol-version negotiation, downgrade rejection, handshake timeouts, and a clear no-plaintext-fallback rule. Debug logs must never expose private keys, session secrets, or complete file contents. QUIC should remain an optional later transport rather than a prerequisite: QUIC supplies secure multiplexed streams, flow control, loss recovery, congestion control, and path migration over UDP [6], but it also introduces UDP firewall and deployment behavior that should not delay a secure TCP baseline.

**Exit gate:** Packet capture confirms that file payloads are encrypted; an untrusted or key-changed peer cannot complete the session; replayed hellos fail; a TLS or identity failure leaves no file presented as complete; and the existing one-to-one and multi-recipient tests pass unchanged at the application layer.

### Phase 7 — LAN connectivity, firewall, and network resilience

**Objective.** Make discovery and connectivity predictable across Wi-Fi, Ethernet, hotspots, multiple interfaces, IPv4, IPv6, and multicast-blocked networks.

The runtime should model interfaces explicitly and advertise only on eligible private interfaces selected by policy. Each peer record should retain the identity binding separately from changing addresses. Discovery should debounce duplicate events, expire stale records, handle address changes, and display why a candidate is unavailable. The manual fallback should validate private/link-local endpoints, test connectivity with a signed probe, and never imply that disabling the firewall is an acceptable fix.

The Windows installer should register the narrowest inbound firewall rule possible for Zapdrop on private networks, with a diagnostics page that tests listener reachability and reports whether the active network is public, private, hotspot, or VPN-backed. The product should not rely on SMB ports, Windows shared folders, mapped drives, administrator shares, or domain credentials.

**Exit gate:** Two real PCs discover and connect over wired LAN, private Wi-Fi, and a phone hotspot; multicast-blocked networks work through manual fallback; IPv4 works even when IPv6 is unavailable; an address change does not break trust; and no VPN or public interface is advertised unintentionally.

### Phase 8 — Transfer engine v2 and throughput tuning

**Objective.** Increase throughput without sacrificing integrity, fairness, bounded resource use, or cancellation behavior.

The transfer engine should be measured against a network baseline such as `iperf3` or an equivalent controlled throughput reference. The implementation should use bounded asynchronous I/O, reusable buffers, explicit backpressure, configurable chunk sizes, and separate control from payload scheduling. Chunk sizes should adapt within a safe range based on measured bandwidth-delay behavior rather than using an unbounded memory queue. Hashing should be streamed and parallelized only when measurements show that CPU hashing is the bottleneck.

The tuning process must measure single-file, multi-file, mixed-size, encrypted, and concurrent-recipient workloads. Results should record effective throughput, CPU, memory, disk write rate, time to first byte, total completion time, retransmitted or retried bytes, and fairness across recipients. The target is not a universal megabytes-per-second promise; the acceptance target is a stable percentage of the measured single-stream LAN baseline on the same machine and network.

| Workload | Required measurement | Initial acceptance target |
|---|---|---|
| One 4–16 GB file, wired LAN | Effective payload throughput and final hash | At least 80% of the controlled single-stream LAN baseline after warm-up |
| One 4–16 GB file, Wi-Fi | Throughput, retries, sleep/wake behavior | No corruption; performance baseline recorded for each test AP/hotspot |
| 10,000 small files | Metadata overhead and time to first payload | Bounded manifest memory and no UI freeze; target refined from baseline |
| Two and four recipients | Aggregate throughput and per-recipient fairness | One slow peer cannot indefinitely starve the others |
| Eight recipients | Resource ceiling and partial success | Bounded sockets, buffers, handles, and disk queue; independent outcomes |
| TLS-enabled transfers | Encryption overhead | Measured regression documented and accepted before release |

**Exit gate:** The performance test suite is repeatable, the encrypted path meets the agreed baseline, memory does not grow with file size, cancellation remains responsive, and a slow or disconnected recipient cannot corrupt or stall successful recipients.

### Phase 9 — Multi-PC distribution and peer-assisted sharing

**Objective.** Make large fan-out transfers efficient and understandable when one source sends to many PCs.

The default mode should remain **direct bounded fan-out**: the source opens independent sessions to selected trusted recipients, each with its own progress, retry, cancellation, and history. This is the safest model and matches the current Phase 4/5 design. The scheduler should support per-recipient priorities, a global bandwidth cap, a maximum active-recipient count, and a queue for additional recipients.

A second opt-in mode can reduce source upload amplification for large groups through **peer-assisted distribution**. In this mode the source sends verified chunks to a small set of trusted seed peers, and additional recipients fetch chunks from those peers over separately authorized sessions. Every chunk must remain content-addressed and hash-verified, and each forwarding authorization must be scoped to the original transfer, item, recipient set, expiry, and sender identity. No peer should become an implicit relay for unrelated devices, and the source must be able to revoke or stop the distribution.

| Distribution mode | Use case | Security and reliability rule |
|---|---|---|
| Direct fan-out | Two to eight recipients; default | Independent sessions and independent outcomes |
| Queued fan-out | More recipients than the active limit | Explicit queue, aggregate progress, no hidden auto-sharing |
| Peer-assisted | Large files and many trusted recipients | Opt-in, signed chunk authorization, verified chunks, revocable transfer scope |
| Offline bundle/export | No simultaneous connectivity | Encrypted, integrity-checked package with explicit import approval |

**Exit gate:** Two, four, and eight trusted recipients can receive the same selection concurrently; one failure does not affect successful recipients; aggregate and per-peer history are correct; peer-assisted mode is disabled by default until security and fairness tests pass.

### Phase 10 — Large-file resumability and storage reliability

**Objective.** Make transfers reliable for files larger than 4 GB and for interrupted sessions, without loading whole files into memory or exposing partial output.

The wire protocol and persistence schema must use unsigned 64-bit byte offsets and lengths everywhere. A transfer journal should record the transfer ID, source fingerprint, item ID, destination, completed chunk ranges, digest state, selected policy, and last verified checkpoint. Resume must be allowed only when the source identity and manifest still match; otherwise Zapdrop must restart or require explicit user confirmation. The receiver should use staging files under the existing protected partial directory, flush according to a documented durability policy, verify the final digest, and atomically publish the destination.

Storage management should include preflight free-space estimates, sparse-file or sequential-write policy by filesystem, stale-partial cleanup, disk-full recovery, permission and read-only handling, path-length and Unicode tests, reparse-point/symlink rejection, and safe behavior when a destination changes during transfer. History must distinguish completed, interrupted, resumed, cancelled, failed, skipped, and partially successful states.

**Exit gate:** A 4 GB-plus file and a multi-hundred-gigabyte test fixture can resume after process termination or network loss; a changed source cannot silently resume into a corrupt destination; disk-full and permission failures are recoverable; and no staging file is shown as a completed user file.

### Phase 11 — Legacy Windows companion and cross-platform packaging

**Objective.** Extend the useful life of the transfer protocol without pretending that every historical Windows GUI can provide the same experience.

The protocol should be versioned independently from the React/Tauri UI. A minimal native companion can provide a signed listener, pairing/import, receive approval through a console or simple native dialog, and send/receive operations over IPv4 TCP. It should share the identity, trust, manifest, checksum, and resume contracts with the main client. The companion must not silently expose a general filesystem share and must have an explicit receive root and approval policy.

For supported modern Windows, the release package should include an installer, a portable build where practical, WebView2 detection or offline installation policy, firewall guidance, code signing, upgrade migration, and uninstall behavior. For Windows 7/8.1, a separate compatibility build must use a pinned dependency set and be tested on clean machines; if the security or runtime support cannot be maintained, the release must clearly classify those versions as unsupported rather than silently shipping a broken GUI.

**Exit gate:** The modern installer works offline on the supported Windows matrix; the portable build reports missing runtime dependencies clearly; the companion can exchange files with the modern client using the same secure protocol; upgrades preserve trust/history according to policy; and no package depends on SMB configuration.

### Phase 12 — Physical-LAN qualification, security review, and stable release

**Objective.** Validate the product on real networks and publish a measured, supportable release.

The qualification lab should include at least two physical Windows PCs, one phone hotspot, one home Wi-Fi router, one wired switch, one multicast-blocked or guest network, one VPN-enabled machine, and a machine with restrictive firewall policy. The test plan should include first pairing, revocation, key change, one-to-one transfer, simultaneous bidirectional transfer, two/four/eight-recipient fan-out, large-file resume, sleep/wake, cancellation, conflict policies, disk-full handling, source mutation, malformed manifests, and untrusted-peer attempts.

The security review should cover the TLS implementation, trust-store migration, parser fuzzing, manifest limits, resource exhaustion, path handling, reparse points, logging, dependency audit, installer integrity, update signing, and rollback. A release candidate should publish its protocol version, supported operating systems, known limitations, measured performance, checksum/signature information, and a reproducible test report.

**Exit gate:** The physical-LAN matrix passes; the security review has no unresolved critical or high findings; release artifacts are signed or clearly marked unsigned for internal builds; performance results are published; and the product can be installed, used offline, upgraded, rolled back, and uninstalled without losing data unexpectedly.

## 4. Recommended implementation order

The next implementation milestone should be **Phase 6: encrypted authenticated transport**. It is the highest-priority gap because the current Zapdrop transport authenticates peers and verifies content but does not provide payload confidentiality. Phase 7 should follow immediately so transport changes are validated on real LAN topologies before performance work begins.

After that, implement Phase 8 throughput tuning and Phase 9 multi-PC scheduling as separate milestones. This preserves a measurable one-to-one baseline before adding peer-assisted distribution. Phase 10 should then harden large-file recovery, followed by Phase 11 compatibility packaging and Phase 12 physical qualification.

| Priority | Phase | Reason |
|---:|---|---|
| 1 | Phase 6 — Encrypted transport | Closes the current plaintext-payload security gap |
| 2 | Phase 7 — LAN resilience | Proves operation beyond the loopback and CI environment |
| 3 | Phase 8 — Throughput | Establishes measurable, encrypted performance |
| 4 | Phase 9 — Multi-PC distribution | Scales the validated engine to concurrent recipients |
| 5 | Phase 10 — Large-file recovery | Makes the product dependable for real archives and media |
| 6 | Phase 11 — Legacy companion and packaging | Extends reach without weakening the modern product contract |
| 7 | Phase 12 — Qualification and release | Converts engineering capability into a supported product |

## 5. Definition of the final goal

Zapdrop reaches its final product goal when a user can place two or more PCs on the same private LAN or hotspot, open the app without internet access, discover or manually connect to peers, verify trust, send one or more files or folders to several recipients, and receive files in the opposite direction at the same time. Each transfer must be encrypted, integrity-checked, resumable, independently cancellable, visible in history, and safe against path traversal, symlink/reparse-point escape, untrusted peers, disk failure, and partial output exposure.

The product succeeds by being **simpler and safer than shared folders for deliberate file movement**, not by reproducing every SMB feature. It should provide direct local movement, clear consent, multi-PC concurrency, reliable large-file handling, and a compatibility story that is honest about the difference between a supported modern GUI and a separately maintained legacy companion.

## References

[1]: https://datatracker.ietf.org/doc/html/rfc6762 "RFC 6762 - Multicast DNS"
[2]: https://v2.tauri.app/reference/webview-versions/ "Tauri Webview Versions"
[3]: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-supported-operating-systems "Microsoft Edge Supported Operating Systems"
[4]: https://v2.tauri.app/start/prerequisites/ "Tauri Prerequisites"
[5]: https://datatracker.ietf.org/doc/html/rfc8446 "RFC 8446 - The Transport Layer Security Protocol Version 1.3"
[6]: https://datatracker.ietf.org/doc/html/rfc9000 "RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport"
