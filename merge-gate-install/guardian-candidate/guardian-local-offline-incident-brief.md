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


## G27B — offline checksummed handoff verification (source-only)

guardian-local-offline-brief-verifier.cjs contains three **pure, inert**
operations: verifyBrief(input), makeBundle([briefs]) and verifyBundle(input).
They perform no D1/GitHub/network/file/process operations, never generate
or request credentials, and cannot start, stop, reset or authorize a Check.

Single-report verification reconstructs the G27A canonical fixed-order
report content, validates exact fields and types, rechecks its SHA-256,
sanitizes up to 10 terminal events, rejects duplicate event IDs and
suspicious accessors/proxies/prototypes. String input also rejects nested
duplicate JSON members, unusual UTF-8 and excessive byte lengths. Invalid
reports produce a minimal P0 NOT_VERIFIED / SOURCE_ONLY_HOLD receipt,
without echoing unsafe values. P0 source reports may be checksum-consistent,
but that does NOT convert them into a trusted/usable fault assertion.

A bounded handoff bundle accepts 1–8 nonduplicate, locally consistent
briefs, copies their allowed fields and computes a deterministic bundle
SHA-256. Verification requires all member digests, count and fixed bundle
metadata to agree before returning only the bundle/checksum receipt.
It does not establish that different journal snapshots form an append-only
history: that requires independent custody and protected source access.

All results declare LOCAL_UNAUTHENTICATED_OBSERVATION or
MATCH_LOCAL_CHECKSUM_ONLY, liveness NOT_PROVEN,
manualInterventionRequired=true, automaticRestartAllowed=false,
activationAllowed=false and releaseAuthority=NOT_ISSUED. No trust
upgrade, live Check, signature, custody, automatic restart or HOLD clearing
is possible. No production staging environment is accessed.

G27B is independent of Claude Code's reserved G27–G30 process-generation,
IPC binding and crash-recovery development, and should be integrated only
after reconciling exact heads and Writer ownership.
