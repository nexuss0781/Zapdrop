# Zapdrop Phase 8 Status

**Status:** Direct fan-out accounting foundation implemented; scheduler qualification continues.

Phase 8 now models a multi-recipient transfer as one parent send job with bounded child sessions. The existing recipient limit remains eight, each child retains independent progress, cancellation, retry outcome, and history, and child records carry an optional `parentId`. A parent history record aggregates child completion, partial-success, failure, and cancellation states without hiding a failed recipient inside a successful group result.

The history schema remains backward-compatible through a defaulted optional field. Existing one-to-one and v1 records remain parentless. The parent record uses a reserved `swarm` peer identity and is reconciled only after all expected child sessions have recorded terminal outcomes.

The remaining Phase 8 work is a first-class UI parent-job view, global bandwidth and disk/CPU budgets, fairness scheduling beyond independent thread launch, queued recipients above the active-session limit, per-recipient retry/cancel commands, and mixed file/folder multi-PC qualification. Tree and mesh forwarding remain disabled and are not implied by this slice.
