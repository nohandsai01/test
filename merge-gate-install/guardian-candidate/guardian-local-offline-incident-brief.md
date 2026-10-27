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


## G27C — bounded offline cross-snapshot continuity checks

guardian-local-offline-brief-verifier.cjs now exposes **two more pure
read-only functions**: compareBriefHistory(older, newer) and
verifyBundleHistory(bundle). These consume only already checksum-checked
G27A briefs and G27B bundles. They do not read any D1 or GitHub state,
manage processes, persist data or modify the Operator.

- G27C compares both entire **bounded** journal histories in reverse
  chronological order (newest first) and checks whether the old event
  sequence is an identical suffix of the newer event sequence. It also
  validates monotonic entry count, fault-count deltas and the two protected
  SHA-256 journal digests. Same snapshot and compatible append are distinct
  classifications.
- When either journal contains more than 10 receipts, or either report has
  only a partial page, the result is **NOT_VERIFIED**. A bounded excerpt
  without an overlapping/complete baseline must not claim append integrity.
- Bundles of 2–8 checksum-valid reports are checked pairwise in caller
  order. On the first conflict, the entire series returns NOT_VERIFIED with
  no event data or partial matching pairs. Duplicate members, reordered
  history, changed digests, invalid dynamic properties and nested duplicate
  JSON keys remain rejected.
- Results are strictly LOCAL_STRUCTURAL_OBSERVATION_ONLY and
  SOURCE_ONLY_HOLD, not trust/chain custody proof. A checksum or a matched
  structural suffix does **not** cryptographically authenticate where a
  report came from; even a coherent fabricated history may pass. None of
  these exports can establish liveness, grant automatic restart, clear HOLD,
  issue a Check or authorize activation.

Separate tests construct actual disposable owner-only terminal journals
and capture successive G27A briefs before and after appends. They cover
clean append, fault append, bundle ordering, truncation, mixed journals,
reordering with recomputed local checksum, P0 inputs, hostile accessors
and non-leakage. This batch is independent of Claude Code's G27–G30
program-generation/IPC recovery work and does not alter the shared Writer.


## G27D — owner-only offline bundle intake and redacted rejection receipts

guardian-local-offline-intake.cjs provides one explicit, inert
createGuardianOfflineIntake({ directory, fileName, maxJournalBytes? })
factory. Import and construction do not write files, start processes or
contact external services. The caller must separately authorize an
owner-only local directory; only receive(JSON_TEXT) attempts to persist.

- receive accepts only a bounded UTF-8 JSON string (not arbitrary JS
  objects, streams, Buffer, provider Proxy or filesystem path). It invokes
  the existing G27B checksum verifier and G27C pairwise bounded history
  check; a locally compatible bundle is **QUARANTINED**, never accepted as
  trusted custody or cleared for runtime activation.
- Bounded classification distinguishes invalid input or checksums,
  incomplete journal history, structurally conflicting history and
  unverified source history. Each outcome is SOURCE_ONLY_HOLD, never
  auto-restart, never allows Check issuance or release authority.
- A receipt contains only a random event ID, timestamp, fixed decision/
  reason, and checksum of a locally validated bundle. It deliberately does
  not serialize incident events, file paths, raw input, PID, process
  identity, secrets, credentials or original error messages.
- Receipts are appended synchronously to a dedicated owner-only JSONL
  journal (0600 file, owner-only directory, O_NOFOLLOW/O_APPEND, fsync).
  Unsafe symlinks, weak permissions, oversized journal, changed directory
  identity or write uncertainty turn the result into
  GUARDIAN_INTAKE_STORAGE_UNVERIFIED with no persisted-success claim.
- Repeated identical submissions generate separate audit receipts; this
  is NOT a global anti-replay store or independently authenticated chain.
  Neither the file nor its SHA-256 constitutes tamper-proof custody.
  An external process supervisor or approved immutable receipt authority
  would be required for operational provenance.

Tests use real disposable local owner directories, G27A evidence capture,
G27B bundle generation and G27C history verification. They include altered
nested JSON, duplicate members, partial history, P0 source, JSON over-limit,
malicious objects, unsafe file modes, symlinks, directory permissions,
journal capacity and repeated submissions, all without modifying existing
Host/IPC/process-generation or Check-writing code.

## G27E — durable local batch dedup, exception query and handoff notes

A separate guardian-local-offline-casework.cjs module adds three bounded
explicit operations, without changing the G27D intake API, process
generation, IPC or Check-writing code.

- intakeMany([JSON_TEXT,...]) takes 1–8 offline G27B bundles and checks
  checksum and G27C structural history. Within one batch or later local
  process, a previously quarantined bundle SHA-256 becomes DUPLICATE
  referencing the first quarantine receipt ID. Invalid input remains
  REJECTED. No evidence is promoted to trusted custody.
- exceptions({limit?,cursor?}) queries redacted REJECTED, DUPLICATE
  and RETURNED annotations newest-first, 1–20 per page. The offset cursor
  binds to the complete journal digest and becomes stale after any change.
  No raw bundles, keys, actor identities or PIDs are exported.
- handoff({receiptId,transition}) annotates only previously QUARANTINED
  records. REQUESTED -> ACKNOWLEDGED/RETURNED -> (if returned) REQUESTED.
  Unknown, rejected, duplicate or out-of-order subjects are rejected.
  Local annotations are NOT authenticated human review or authorization.

Explicit writers use owner-only directories, 0600 files, single-write batch
append plus fsync, and an O_EXCL per-journal lock. A competing or stale lock
fails closed, never auto-recovers; an uncertain write retains its lock for
manual owner intervention. Reads verify complete UTF-8 JSON lines, exact
record shapes, monotonic event referents and transition history; failures
return NOT_VERIFIED / HOLD rather than a partial answer. Query methods
never take the write lock or perform a mutation.

This is local deduplication, NOT globally distributed exactly-once or a
tamperproof audit chain. Same-UID compromise and filesystem attacks are
outside the local-source proof. Every output remains SOURCE_ONLY_HOLD,
custodyVerified=false, liveness=NOT_PROVEN, activationAllowed=false,
automaticRestartAllowed=false and releaseAuthority=NOT_ISSUED.


## G27F — read-only casework journal integrity and unknown-lock diagnostics

guardian-local-casework-diagnostics.cjs exposes exactly one inert
createGuardianCaseworkDiagnostics({directory,fileName,maxJournalBytes?})
factory and one passive inspect() method. Neither import, construction
nor inspection creates files, writes bytes, acquires/releases a lock,
repairs or truncates the journal, reads sensitive lock contents, starts
processes or contacts hosted services.

- Reopens the existing owner-only casework journal using O_RDONLY and
  O_NOFOLLOW. Bounded complete reads cross-check descriptor/path
  device+inode, size, timestamps, file permissions, link count and
  directory identity before returning a SHA-256 of the local bytes.
- Every JSONL record is parsed with duplicate-member detection. The
  inspection validates all fixed receipt fields, event-ID uniqueness,
  deduplication against the first quarantined digest, handoff-to-original
  relationships and REQUESTED/ACKNOWLEDGED/RETURNED transition ordering.
  Only aggregate counts and the local journal hash are returned; not raw
  events, receipt IDs, reasons, file locations, credentials or messages.
- Separately reads only lock file metadata before and after the journal
  snapshot. A valid pre-existing lock is LOCK_PRESENT_UNVERIFIED,
  regardless of age. Lock symlinks/hardlinks/unsafe file modes become
  LOCK_UNSAFE. Lock creation, replacement or removal during a read
  produces CHANGED_DURING_READ. Neither absent lock nor valid journal
  makes the reader entitled to create or remove a lock.
- Truncated JSON, duplicate keys, altered event IDs, wrong dedup origin,
  unsupported transitions, unsafe file modes/links, oversized or partial
  journal, directory drift and races produce NOT_VERIFIED/SOURCE_ONLY_HOLD.
  Even a structurally consistent journal with no observed lock remains
  LOCAL_STRUCTURE_OBSERVED_ONLY, liveness NOT_PROVEN and custodyVerified
  false. No assertion of authorized human action or release readiness.
- This is NOT durable trusted provenance or a production lock recovery
  mechanism. No PID/age heuristic auto-unlocks: a live writer and an
  orphaned lock cannot be distinguished from lock metadata alone.

Tests cover disposable real owner-only casework journals, incoming
duplicates, handoff transitions, synthetic corruption, unsafe links and
permissions, simulated lock replacement during read, and byte-for-byte
nonmutation of journal and lock. No Claude G27–G30 process-generation,
IPC, Check writer or live D1 code is modified.

## G37 — Generation V2 Operator facade integration (source-only)

G37 stacks the independently completed PR #16 offline casework modules and
PR #17 complete event ledger audit on the G36 Generation V2 + protected
journal pair. The local Operator facade exposes two **read-only** capabilities:

- `captureOfflineIncidentBrief()` captures a small redacted local snapshot.
  The extended runtime assessment's `unterminatedGenerations` is validated
  and must remain equal across two observations. Original G27A v1 snapshots
  remain accepted only as their exact legacy shape, without arbitrary fields.
- `auditCompleteEventLedger()` audits up to 4096 cursor-paged terminal
  receipts, rejecting incomplete or changing local snapshots. It does not
  establish independent custody of the paired Generation V2 launch ledger.

Both operations construct inertly, perform no process control or writes,
and retain SOURCE_ONLY_HOLD, liveness NOT_PROVEN and NOT_ISSUED release
authority. The offline casework/quarantine modules remain separate APIs;
no casework directory, lock, account or real Check is created by the session.

The pair is not an atomic OS transaction and the summaries are not signed
attestations. Independent non-author QA is NOT_PROVEN. Source-only Draft:
no Merge, Deploy, production D1, credential, Ruleset or payment action.


## G38 — opt-in Operator casework + Generation V2 local observation

An Owner may configure both \`caseworkDirectory\` and \`caseworkFileName\`
when creating a local Operator session. The scope is pinned and validated
at construction; callers cannot pass an arbitrary directory to the Operator
method. When both are absent, the original Operator method surface is
unchanged. A partial scope is rejected.

\`operator.assessCaseworkGenerationEvidence()\` is read-only. It brackets a
full passive casework-journal + lock observation around generation-aware
runtime assessment, the redacted terminal brief and a complete cursor audit.
Casework diagnostics independently re-read the journal and compare inode,
metadata and SHA-256 across two reads. Inconsistent source, lock presence,
Generation count drift, changed terminal evidence, or mismatched local
snapshots produces P0 / NOT_VERIFIED without partial digests.

A successful local report says
\`LOCAL_COINCIDENT_OBSERVATIONS_ONLY\` — **not linked casework**.
Casework V1 stores only the bundle digest; it does not contain a
Generation V2 launch-ledger digest or a trusted cross-file transaction ID.
\`crossJournalBinding\`, \`generationLedgerBinding\`, liveness, custody
and release remain NOT_PROVEN / NOT_ISSUED. It never claims that manual
handoff is authorized, or that a casework receipt proves a specific
terminal failure. No files are created, unlocked, repaired or written
by the Observer. This does not eliminate ABA/races between observations.

Source only; Feature OFF; Launch HOLD; no Merge, Deploy, real Check,
credentials, trusted anchor enrollment or production D1.

## G39 — source-only cross-source aggregate contract hardening

The G38 opt-in Operator correlation now rejects an externally supplied brief
with a forged non-leading terminal event, a duplicate event ID, a sparse or
accessor-backed event slot, or a digest computed over unvalidated nested data.
Events are copied into plain descriptors before the brief SHA-256 comparison,
and UTC timestamps must round-trip exactly rather than normalize impossible
calendar dates. The separate complete-ledger audit aggregate must have valid,
distinct failure code rows whose totals match the counted failures, and
first/latest failures must match the summary and last-terminal relationship.
Malformed aggregates return P0/NOT_VERIFIED without exposing raw fields.

This is local structural validation, **not** a trusted casework-to-generation
transaction binding. Casework V1 still has no Generation V2 ledger digest.
Both binding fields remain NOT_PROVEN; all paths retain SOURCE_ONLY_HOLD.
No writer, IPC, credentials, Check or production pathway was added.
