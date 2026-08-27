# Zapdrop Grand Final Proposal: A Private Local Swarm for File Movement

**Document status:** Re-proposed after design review
**Current implementation:** Phases 1–5 complete; encrypted payload transport and physical two-PC qualification remain outstanding
**Product goal:** Move files and folders between trusted PCs over a private local network without internet, cloud storage, SMB shares, or a central service, while scaling from one-to-one transfer to secure one-to-many distribution.

## Executive proposal

Zapdrop should evolve from a conventional peer-to-peer file sender into a **private local content-distribution fabric**. The fundamental unit should no longer be “one TCP connection from one sender to one receiver.” It should be a signed **swarm job**: one immutable content snapshot, one authorized recipient set, one policy, and a scheduler that chooses direct, queued, or peer-assisted delivery for the local network.

This changes the theory in four ways. First, membership is identity-first: a device is not in a swarm merely because it is visible on the LAN. It must be paired, trusted, authorized for the specific job, and able to prove possession of the expected content capability. Second, data is content-first: files and folders are represented by a verifiable snapshot and content-addressed pieces, not by a single fragile static path list. Third, distribution is group-first: the source coordinates a recipient set and may form a bounded tree or mesh instead of opening an unconstrained one-to-one session to every PC. Fourth, completion is proof-first: a destination is published only after the receiver verifies the complete content and the signed snapshot relationship.

The user’s proposals are valuable, but they should be introduced as **measured layers**, not as simultaneous replacements for the current reliable transfer path. TLS or Noise should protect the first secure transport. Merkle-style manifests should solve very large folder metadata. Direct fan-out should establish the one-to-many baseline. Tree-mesh distribution and RaptorQ repair should follow only after those foundations are correct. BBR should be benchmarked and selected by transport capability, not assumed to be universally faster. Onion routing should be optional because hiding IP addresses is a different threat model from encrypting payloads and adds relay, latency, abuse, and debugging complexity.

## 1. Threat model and corrected security theory

Zapdrop must treat a local network as potentially hostile. An attacker may observe traffic, inject frames, impersonate a discovered device, replay an old offer, alter a piece, exhaust connections, exploit path handling, or attempt to become an unauthorized relay. Encryption protects payload confidentiality, but it does not automatically hide IP addresses, traffic timing, device availability, or the fact that a transfer exists.

### 1.1 Swarm membership is not discovery

mDNS/DNS-SD remains a useful zero-configuration discovery mechanism because it is designed for DNS-like operations on a local link without conventional unicast DNS infrastructure [1]. Discovery must remain an untrusted observation only. A discovered peer receives no file metadata, piece, filesystem authority, or relay role until it completes the existing pairing and trust process and receives a job-specific authorization.

The new security model should define three separate states: **visible**, **trusted**, and **authorized**. Visible means a peer announced a service or was entered manually. Trusted means both users approved a stable public-key binding. Authorized means that trusted identity was explicitly included in a particular swarm job, destination policy, and expiration window. This prevents the common mistake of treating LAN presence as permission.

### 1.2 Encrypted transport and encrypted pieces

The first secure implementation should place TLS 1.3 over the existing TCP framing, with the trusted device public key pinned into the certificate or handshake verification. TLS 1.3 is designed to prevent eavesdropping, tampering, and message forgery [2]. A Noise-style handshake can be evaluated later for a smaller protocol core or non-WebView companion, but Zapdrop should not maintain two independent security implementations before one is proven.

Every swarm job should have a fresh job key and signed capability. The manifest, piece identifiers, recipient set, expiration, and allowed operations should be bound to that job. Pieces should be encrypted in transit by the session and may additionally be encrypted at rest in the staging cache. For peer-assisted distribution, forwarding peers should be able to serve authenticated ciphertext pieces without receiving filesystem authority or unrelated job keys. Each recipient receives the decryption capability only after authorization and policy approval. Rejection, expiration, cancellation, or revocation must invalidate the job capability.

This is a more precise goal than “zero-knowledge swarm.” Cryptographic authentication and encrypted pieces can minimize trust and information disclosure, but they do not by themselves provide a zero-knowledge proof system or conceal network metadata. The product should use exact security claims: **authenticated peers, authorized jobs, encrypted payloads, integrity-verified pieces, and least-privilege relay capabilities**.

### 1.3 Onion or garlic routing is an optional privacy mode

A local privacy relay can hide the direct source-to-recipient relationship from ordinary peers, but it should not be the default LAN route. Multi-hop onion routing adds relay selection, path construction, latency, bandwidth amplification, failure handling, abuse controls, and a more complicated threat model. The Tor project documents onion-routing security as a separate topic with explicit residual attacks and limitations [10].

Zapdrop should therefore expose three modes: **direct**, the default and fastest mode; **trusted relay**, an opt-in mode where selected trusted PCs forward encrypted pieces; and **privacy relay**, a later experimental mode for users who explicitly accept slower transfers and weaker operational visibility. The local network will still be able to observe endpoints and traffic patterns unless additional protections are implemented, so the UI must never promise complete anonymity.

## 2. The swarm data model

The protocol should introduce a versioned job model that can coexist with the current Phase 5 transfer records. The source creates a snapshot, derives a root content identifier, signs a job descriptor, and authorizes a recipient set. Receivers fetch or receive pieces, verify them against the snapshot, and publish only verified files.

| Object | Contents | Security role |
|---|---|---|
| `SwarmJob` | Job ID, snapshot root, sender identity, recipient set, policy, expiry, topology mode | Binds the whole operation to an authorized group |
| `SnapshotRoot` | Root hash of the folder/file graph, version, source metadata, creation time | Commits to the exact content view |
| `DirectoryNode` | Sorted child names, types, metadata, child identifiers | Makes folder structure incrementally verifiable |
| `FileObject` | File size, chunking profile, chunk identifiers, optional file digest | Describes a file without loading it into memory |
| `Piece` | Content ID, job ID, sequence or symbol ID, length, ciphertext, authentication tag | Enables independent verification and relay |
| `Capability` | Recipient, allowed object set, expiry, operation, signature | Prevents an authorized peer from becoming an unrestricted relay |
| `TransferJournal` | Verified piece ranges, source fingerprint, destination, retry state | Enables safe resume and crash recovery |

The snapshot must be immutable for a job. If a source file changes after indexing, the sender must either create a new snapshot or explicitly restart the affected object. A receiver must never silently combine pieces from different snapshot roots.

## 3. One-to-many architecture

### 3.1 Direct fan-out remains the correctness baseline

For a small recipient set, the source should open independent encrypted sessions with bounded concurrency. Each child session has its own authorization, rate, retry, cancellation, history, and completion proof. The parent job aggregates progress but never hides a failed recipient inside a successful aggregate. This preserves the current trusted-peer model and makes two, four, and eight-recipient behavior measurable.

The scheduler should expose a global bandwidth budget, per-recipient minimum service, active-session limit, queue priority, and slow-peer policy. A recipient that is offline or slow must not prevent other recipients from completing. A group cancellation must revoke the job capability and stop all child sessions, while cancel-one should affect only that recipient unless the user chooses to cancel the job.

### 3.2 Tree-mesh distribution is the scale-out mode

When source upload becomes the bottleneck, Zapdrop should choose a bounded distribution topology. The source seeds verified pieces to a small number of high-capacity trusted peers. Those peers forward authorized ciphertext pieces to their assigned children. The structure should be a dynamic tree with controlled mesh repair: a receiver may have one preferred parent and a limited number of alternate peers for missing pieces.

Topology selection should use measured properties, not device labels alone. Candidate inputs include observed throughput, round-trip time, loss or retry rate, available disk space, CPU cost, user relay consent, and whether the device is metered or battery constrained. The source remains the policy authority and can revoke a branch. A peer must not forward to a device outside the authorized recipient set.

| Mode | Default status | Best use | Main risk |
|---|---|---|---|
| Direct bounded fan-out | Default | Up to a few recipients and heterogeneous networks | Source upload amplification |
| Queued fan-out | Supported | More recipients than active-session budget | Longer completion time |
| Tree distribution | Opt-in after qualification | Many recipients on a fast local network | Branch failure and relay abuse |
| Mesh repair | Opt-in inside tree jobs | Recovering missing pieces without returning to source | Duplicate traffic and authorization complexity |
| Privacy relay | Experimental | Users prioritizing relationship hiding over speed | Latency, relay cost, and incomplete anonymity |

### 3.3 Fountain and repair coding

RaptorQ is a suitable candidate for the repair layer because RFC 6330 specifies it for reliable object delivery and describes a systematic fountain code that can generate encoding symbols on demand and recover a source block from almost any sufficient set [4]. It should not replace the reliable baseline for every transfer. For a clean wired LAN, acknowledged source pieces plus selective retransmission will usually be easier to debug and may be more efficient than encoding every byte.

The recommended design is **systematic blocks with optional repair symbols**. Send original pieces first. Generate repair symbols only when loss, branch churn, or multi-recipient demand makes them cheaper than repeated retransmission. Use a bounded source block size, cap repair overhead, and verify reconstruction against the file object and snapshot root. RaptorQ belongs primarily in tree/mesh mode, high-loss hotspots, and branch repair—not in the first secure one-to-one path.

## 4. Massive files and folders

### 4.1 Merkle-DAG-inspired snapshots

The folder index should evolve from a single eager manifest into a Merkle-style snapshot graph. IPFS documentation describes Merkle-DAG nodes as content-addressed, immutable, self-verifying structures whose identifiers commit to node payloads and descendants [5]. Zapdrop should adapt this idea locally without joining the public IPFS network or requiring a DHT.

Directory nodes should hash a canonical, sorted list of child descriptors. File objects should reference chunk identifiers and size metadata. Unchanged subtrees can be reused between snapshots, allowing incremental re-send and rapid comparison. The source should stream index pages and permit the receiver to request only the directory or file objects needed for the chosen destination policy. Millions of entries must not require a single in-memory JSON document.

### 4.2 Chunking and storage rules

Start with a measured fixed chunk profile, such as 4 MiB for ordinary files, and evaluate adaptive profiles in a bounded range such as 1–16 MiB. Network pieces should not be blindly aligned to filesystem cluster size: filesystem allocation units, network MTU, encryption records, and application buffering solve different problems. Alignment may be an optimization in a specific storage backend, but it must be demonstrated by benchmarks rather than assumed.

The staging store should be content-addressed within a job or device scope, use 64-bit offsets, maintain a verified-piece bitmap or range set, and support sequential or sparse writes according to filesystem capability. The final file should be atomically published only after the object digest and snapshot relationship are verified. Stale journals and partial directories require bounded cleanup, and cancellation must never expose a partial file as complete.

### 4.3 Large-file resume contract

A resume is valid only if the source snapshot root, file object identifier, chunking profile, destination policy, and authorized job still match. The journal must detect source mutation, disk-full conditions, permission changes, sleep/wake interruptions, and destination conflicts. A 4 GB-plus test file is the minimum qualification case; production qualification should include multi-hundred-gigabyte fixtures and large sparse or highly fragmented folder trees.

## 5. Throughput and congestion control

Zapdrop should measure throughput against a controlled LAN baseline rather than advertise a universal speed number. Metrics should include effective payload throughput, time to first byte, aggregate and per-recipient throughput, CPU, memory, disk write rate, retransmitted bytes, repair overhead, queueing delay, and fairness.

BBR is a valid experiment because its design models delivery rate, round-trip time, and loss and controls pacing and in-flight volume [6]. However, an application cannot simply “modify TCP to BBR” in a portable way. BBR selection depends on the operating system, kernel, socket API, or userspace transport. Zapdrop should first benchmark the platform default, then evaluate BBR where the chosen transport exposes it, and record results on wired, Wi-Fi, hotspot, and lossy networks. QUIC is a later option because it supplies secure multiplexed streams, flow control, loss recovery, congestion control, and path migration over UDP [3], but UDP deployment and firewall behavior must be proven before it becomes a required transport.

| Benchmark family | Required comparison | Release decision |
|---|---|---|
| Single 4–16 GB file | Plain baseline versus encrypted transport | Encryption regression is measured and accepted |
| Two-way simultaneous transfer | A→B and B→A fairness | Neither direction starves the other |
| Two, four, and eight recipients | Direct fan-out aggregate rate | Resource limits and partial success remain correct |
| Tree/mesh job | Source upload reduction versus duplicate traffic | Improvement is measured, not assumed |
| RaptorQ repair | Retransmission bytes versus CPU and repair overhead | Enabled only where net benefit is demonstrated |
| BBR/default congestion control | Throughput, latency, fairness, loss | Selected per supported transport/platform, not by slogan |

## 6. Revised final implementation phases

### Phase 6 — Swarm protocol v2 and encrypted piece plane

**Objective:** Define the group-job protocol and close the current plaintext-payload gap.

Implement `SwarmJob`, snapshot roots, signed recipient capabilities, protocol-version negotiation, TLS 1.3 with pinned device identity, fresh job keys, encrypted piece framing, replay protection, key rotation, and no plaintext fallback. Preserve the current pairing and safe-path boundaries. Add parser limits, capability expiry, cancellation revocation, and redacted diagnostics.

**Acceptance gate:** Packet capture shows no readable file payload; a visible-but-untrusted peer cannot obtain a manifest or piece; a revoked recipient cannot continue; and wrong-key, replay, malformed-frame, and key-change tests fail safely.

### Phase 7 — Content-addressed snapshot and large-dataset engine

**Objective:** Replace eager monolithic manifests with streaming, incremental, verifiable folder snapshots.

**Implementation status:** The first foundation slice is implemented. It provides bounded file hashing, canonical NFC Unicode path normalization, traversal and symlink rejection, deterministic directory ordering, content-addressed directory/file/piece-index objects, bounded chained piece-index pages, and crash-safe job-scoped transfer journals. The feature-gated v2 direct sender now derives its file manifest from the snapshot engine, and the v2 receiver persists authenticated ranges and completion state in the journal.

The remaining Phase 7 work is a network paged-metadata exchange for very large trees, subtree reuse across snapshots, millions-of-entry stress qualification, disk-space preflight, sparse-range recovery, explicit source mutation revisions, and 4 GiB-plus physical-file testing. See `docs/ZAPDROP_PHASE7_STATUS.md` for the exact boundary of the implemented slice.

**Acceptance gate:** A large folder can be indexed and transferred without memory scaling with total dataset size; unchanged subtrees are reused; a 4 GB-plus file resumes after termination; and altered source content cannot silently merge into an old job.

### Phase 8 — One-to-many scheduler and direct swarm mode

**Objective:** Make group transfer the primary product abstraction.

Implement parent jobs and recipient child sessions, global bandwidth and resource budgets, per-recipient fairness, queued recipients, per-peer retry/cancel, aggregate progress, partial-success semantics, and group history. The default direct mode should support at least two, four, and eight trusted recipients and simultaneous transfers in both directions.

**Acceptance gate:** One source can complete a mixed file/folder job to multiple recipients; one failure does not affect successful peers; slow peers do not starve the group; and all child outcomes reconcile correctly into the parent history.

### Phase 9 — Tree-mesh and peer-assisted distribution

**Objective:** Reduce source upload amplification for large groups while preserving least privilege.

Implement capability-scoped forwarding, topology measurement, branch assignment, parent failover, alternate-peer repair, relay consent, global job revocation, and per-branch observability. Start with encrypted original pieces forwarded as ciphertext. Do not allow arbitrary relay requests or recipients outside the signed job set.

**Acceptance gate:** A tree job measurably reduces source upload for a defined multi-PC topology; a failed parent is repaired without corrupting the snapshot; a relay cannot access unrelated files; and direct fan-out remains available as a fallback.

### Phase 10 — Fountain repair and adaptive throughput

**Objective:** Add repair coding and congestion-control adaptation only where measurements justify them.

Implement systematic source blocks, bounded RaptorQ repair-symbol generation, receiver reconstruction, repair-overhead accounting, adaptive chunk profiles, backpressure, and transport-specific congestion-control experiments. Benchmark default TCP behavior, BBR where available, and a future QUIC prototype independently. Keep the reliable direct path as the reference implementation.

**Acceptance gate:** Repair coding lowers completion time or source amplification on selected loss/mesh workloads without unacceptable CPU or memory cost; ordinary clean-LAN transfers do not regress; and the chosen congestion strategy is documented per platform.

### Phase 11 — Legacy Windows companion and cross-platform protocol

**Objective:** Extend the protocol beyond the modern Tauri GUI without inheriting SMB’s shared-filesystem assumptions.

Maintain the Windows 10 1803+ and Windows 11 Tauri GUI as the primary supported client. Tauri documents WebView2 and native build prerequisites for Windows [7] [9], while Microsoft’s current Edge support matrix identifies Windows 10 SAC 1709 and later selected editions and Windows 11 as supported Edge platforms [8]. For Windows 7/8.1, build a separately tested minimal native companion only if real users require it. The companion should provide the signed listener, pairing, receive approval, and send/receive commands without depending on the modern WebView. It must share the same protocol version, snapshot, piece, capability, and journal contracts.

Add Linux x64/ARM64 and macOS Intel/Apple Silicon targets after the protocol is stable. Do not map drives, expose SMB shares, require domain credentials, or silently grant a remote filesystem browser. The differentiator is deliberate, authorized content movement rather than a new shared-folder administration surface.

**Acceptance gate:** A modern Windows client exchanges content with the companion using encrypted, version-negotiated protocol; installation and runtime prerequisites are reported clearly; upgrades preserve trust and history according to migration policy; and unsupported operating systems receive an honest compatibility message.

### Phase 12 — Physical-LAN qualification, privacy modes, and stable release

**Objective:** Prove the grand design on real networks and publish a supportable product.

Use at least two physical PCs, a wired LAN, a home Wi-Fi router, a phone hotspot, a guest or multicast-blocked network, a restrictive firewall, a VPN-enabled machine, and a low-end or older Windows system. Exercise discovery fallback, trust revocation, encrypted one-to-one transfer, simultaneous bidirectional transfer, two/four/eight-recipient fan-out, tree/mesh mode, repair coding, large-file resume, source mutation, disk-full, cancellation, sleep/wake, and malicious or malformed peers.

The release must include signed or explicitly classified unsigned artifacts, installer and portable options where supported, firewall guidance limited to private networks, WebView2/runtime behavior, protocol version, compatibility matrix, performance report, known limitations, rollback instructions, and a security review. Privacy relay should remain experimental until its threat model, relay abuse controls, and metadata claims are independently reviewed.

**Acceptance gate:** The physical-LAN matrix passes; critical and high security findings are closed; measured encrypted throughput and resource ceilings are published; large-file resume is reliable; and a clean supported machine can install, operate offline, transfer, upgrade, roll back, and uninstall predictably.

## 7. What Zapdrop deliberately does not become

| Temptation | Decision | Reason |
|---|---|---|
| Anonymous LAN swarm | Reject | Discovery is not authorization; it would weaken the trust boundary |
| SMB replacement or drive mapper | Reject | It recreates shared-filesystem permissions and legacy administration problems |
| Mandatory onion routing | Reject | It adds latency and relay complexity without solving the primary payload-security need |
| Mandatory RaptorQ for all files | Reject | It adds CPU and implementation complexity where retransmission is sufficient |
| Hard-coded BBR promise | Reject | Congestion-control availability and results depend on transport and platform |
| One giant JSON manifest | Reject | It does not scale to millions of entries or incremental updates |
| Unrestricted peer relay | Reject | Forwarding must be scoped to a signed job, recipient set, and expiry |
| Silent overwrite or auto-accept | Reject | User consent, conflict policy, and safe finalization are product requirements |

## 8. Final definition of success

Zapdrop succeeds when several trusted PCs can join the same private local job without internet access, exchange an immutable content snapshot, and distribute large files or folders through the fastest safe topology available. A user can send from one source to many recipients while another peer sends back at the same time. Each peer sees its own authorization, progress, destination, integrity result, retry state, and history. A tree or mesh can reduce repeated source uploads, but no relay can escape its capability scope. A repair-coded transfer can recover from loss, but no receiver can publish content without a verified snapshot proof.

This architecture transcends legacy Windows file sharing by replacing implicit shared-folder authority with explicit job authority, replacing path-centric copies with verifiable content objects, replacing one-to-one assumptions with bounded group scheduling, and replacing “the file appeared” with cryptographic completion proof. It remains honest about its limits: encryption can protect content without hiding all network metadata, CI loopback tests cannot replace physical-LAN qualification, and legacy operating systems require a separately supported compatibility profile rather than a broken modern GUI.

## References

[1]: https://datatracker.ietf.org/doc/html/rfc6762 "RFC 6762 - Multicast DNS"
[2]: https://datatracker.ietf.org/doc/html/rfc8446 "RFC 8446 - The Transport Layer Security Protocol Version 1.3"
[3]: https://datatracker.ietf.org/doc/html/rfc9000 "RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport"
[4]: https://datatracker.ietf.org/doc/html/rfc6330 "RFC 6330 - RaptorQ Forward Error Correction Scheme for Object Delivery"
[5]: https://docs.ipfs.tech/concepts/merkle-dag/ "IPFS Docs - Merkle Directed Acyclic Graphs"
[6]: https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-00.html "BBR Congestion Control"
[7]: https://v2.tauri.app/reference/webview-versions/ "Tauri Webview Versions"
[8]: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-supported-operating-systems "Microsoft Edge Supported Operating Systems"
[9]: https://v2.tauri.app/start/prerequisites/ "Tauri Prerequisites"
[10]: https://support.torproject.org/about-tor/security/ "Tor Project - Security"
