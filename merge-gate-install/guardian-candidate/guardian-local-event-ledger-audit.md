# Guardian G27C — Complete local event ledger audit

**Scope:** A standalone, inert, read-only consumer of the already-existing
`Operator.recentEvents({ limit, cursor })` API from PR #15 at
`d4bdad51bdc67059d2da708fa64602186891debb`. This is intentionally
separate from PR #16 offline incident brief and Claude Code's G27–G30
process-generation, IPC and restart implementation.

## Usage

```js
const { createGuardianLocalLedgerAudit } =
  require('./guardian-local-event-ledger-audit.cjs');
const localAudit = createGuardianLocalLedgerAudit({
  operator: existingSession.operator,
  pageSize: 50,
  maxCaptureMs: 10000,
});
const result = localAudit.capture(); // no disk writes, network, or child control
```

This module traverses **all** existing bounded journal pages rather than a
sample, validates the fixed journal digest, exact expected cursor progression,
terminal/fault metadata, per-event schemas and IDs, whole-ledger failure count,
and first/latest fault identity. It produces an ordered-event SHA-256, code
counts, bounded event metadata and a source-only HOLD result. It never exports
whole raw journal records, process IDs, credentials or arbitrary user fields.

On a partial, missing, mutable, stale, reordered, malformed or inconsistent
page (or a slow scan), it returns a P0-equivalent NOT_VERIFIED result with
**zero** partial events, counts or digests. No result permits activation,
restart, release, deployment or Check issuance.

## Trust boundary

A local hash can detect drift across reads, but it is **not an authenticated
signature, append-only remote custody record, trusted process identity or
verified OS liveness**. Even MATCH_LOCAL_PAGES_ONLY is never production
approval. A malicious writer with permission to replace an entire local
journal and recompute matching data before the scan can defeat this check.
Do not call this an independent Security Review.

Limitations: up to 4096 events, page size 1–50, maximum capture time
100–30,000ms; each page re-reads the protected local journal. Intended only
for manual offline diagnostics. The module doesn't touch PR #15 shared Writer
code or the PR #16 brief/verifier source.
