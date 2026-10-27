# Guardian G27A — Local offline incident brief (source-only)

This is an **inert read-only consumer**, intentionally built in an independent
branch, separate from Claude Code's G27–G30 process-generation / IPC / recovery
implementation. It does **not** modify the shared PR #15 Writer branch,
the existing Operator session facade, the journal, or any Check / D1 module.

Example for an already-authorized local Operator facade:

    const { createGuardianOfflineIncidentBrief } =
      require('./guardian-local-offline-incident-brief.cjs');
    const brief = createGuardianOfflineIncidentBrief({
      operator: existingSession.operator, limit: 5, maxCaptureMs: 1000,
    });
    const snapshot = brief.capture(); // passive, synchronous; no disk writes

The bounded report includes only a validated local assessment priority,
journal SHA-256, event count, historical fault count, health freshness and
at most 10 events (eventId, ISO timestamp, FAILED/STOPPED, safe error code).
It excludes PID, secrets, process handles, raw journal entries, network
responses, credentials, incident evidence payloads, user-supplied fields
and all write/start/restart capabilities.

**Race boundary:** one assessment, then one bounded event query, then a second
assessment. The two assessments and the event-query header must agree on
protected journal SHA-256, row and fault count, Controller state and
classification. A missing/inconsistent/dynamic source, exceptions, a changed
journal, stale events, unexpected fields or excess capture duration returns
P0 with no event details. The resulting local report has a SHA-256 digest
over its allowlisted fields; this digest is **not a signature, remote
attestation or custody proof** and cannot establish process liveness.
No report can unblock HOLD, authorize automatic restart or launch a Check.

Tests cover a real owner-only temporary journal and Operator session as well
as forged metadata, dynamic getters, duplicate events, cross-snapshot races,
missing evidence, exceptions and delayed reads. This is an isolated source
development candidate only. Hosted D1, GitHub App issuer, real secrets,
merging/deploying and independent QA remain not proven.

The module does not own any future G27–G30 process-generation files and
should only be integrated after its source/head is reconciled with the
separately developed generation batch.
