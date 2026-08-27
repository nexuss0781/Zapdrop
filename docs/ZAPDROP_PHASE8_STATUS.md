# Zapdrop Phase 8 Status

**Status:** Bounded direct fan-out scheduler implemented; physical multi-PC qualification continues.

Phase 8 now models a multi-recipient transfer as one parent send job with bounded child sessions. The existing recipient limit remains eight, while `SwarmScheduler` provides FIFO admission, a bounded waiting queue, a configurable active-recipient limit, shared token-bucket bandwidth pacing, bounded retry attempts, and queued progress events. The scheduler is passed into the existing per-recipient workers and does not alter the v1 wire format.

Each child retains independent progress, cancellation, retry outcome, and history, and child records carry an optional `parentId`. A parent history record and `transfer-parent-progress` event aggregate child completion, partial-success, failure, cancellation, recipient counts, and transferred bytes without hiding a failed recipient inside a successful group result. The frontend exposes parallelism, queue depth, retry count, and bandwidth controls, and displays parent aggregate progress.

The local `local_three_recipient_parent_harness` test exercises a one-active/two-waiting job with three child sessions, one simulated failure, one recipient cancellation, partial parent reconciliation, and active-count cleanup. The qualification script runs that harness in both the default and `swarm-v2` test configurations before the complete suites. This is deterministic local scheduler and accounting coverage, not evidence of a physical multi-PC transfer.

The remaining Phase 8 work is physical qualification with mixed file/folder jobs, failure injection against real recipients, and finer-grained per-recipient controls. Global disk/CPU budgets and cross-job fairness are not yet implemented; the current bandwidth and concurrency limits are per parent job. Tree and mesh forwarding remain disabled and are not implied by this slice.
