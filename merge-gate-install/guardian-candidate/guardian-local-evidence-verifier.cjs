/**
 * G20: Independent, strictly read-only verification of a G19 local incident
 * evidence packet against one owner-owned JSONL journal snapshot.
 *
 * This module does NOT call Diagnostics or trust a packet's reported digest,
 * receipt counts, positions or neighbor objects. A MATCH is only a comparison
 * against local bytes at read time, never custody, process liveness, operator
 * authentication, restart permission, an authority grant or release.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');
const { generationLedgerName } =
  require('./guardian-local-receipt-journal.cjs');

const FILE_NAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ERROR_CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const EVENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TIMESTAMP = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const MAX_ENTRIES = 4096;
const MAX_LINE_BYTES = 512;
const STATES = new Set(['CREATED', 'STARTING', 'RUNNING',
  'STOPPING', 'STOPPED', 'FAILED']);
const RECEIPT_FIELDS = Object.freeze(['schemaVersion', 'eventId',
  'timestamp', 'state', 'errorCode', 'hostStopped', 'activationAllowed',
  'releaseAuthority', 'automaticRestartAllowed']);
// G27 v2 receipts carry the process generation they terminate.
const BOUND_RECEIPT_FIELDS = Object.freeze([...RECEIPT_FIELDS,
  'generationId']);
const GENERATION = /^[0-9a-f]{32}$/;
const EVENT_FIELDS = Object.freeze(['eventId', 'timestamp', 'state', 'errorCode']);
const BOUND_EVENT_FIELDS = Object.freeze([...EVENT_FIELDS, 'generationId']);
// Ordered exactly as G19's evidenceEnvelope uses for JSON/SHA-256.
const PACKET_FIELDS = Object.freeze(['schemaVersion', 'kind', 'authority',
  'status', 'availability', 'reason', 'sourceReason', 'processState',
  'liveness', 'manualInterventionRequired', 'journalEntries',
  'journalSha256', 'failureCount', 'eventSequence', 'selectedFailure',
  'previousReceipt', 'nextReceipt', 'firstFailure', 'latestFailure',
  'automaticRestartAllowed', 'activationAllowed', 'releaseAuthority']);
const BOUND_PACKET_FIELDS = Object.freeze([
  ...PACKET_FIELDS.slice(0, PACKET_FIELDS.indexOf('selectedFailure')),
  'generationId', 'launchLedgerSha256',
  ...PACKET_FIELDS.slice(PACKET_FIELDS.indexOf('selectedFailure')),
]);
const EVENT_KEYS = new Set(['selectedFailure', 'previousReceipt',
  'nextReceipt', 'firstFailure', 'latestFailure']);
const EXPECTED_PACKET_KEYS = Object.freeze([...PACKET_FIELDS,
  'evidenceSha256']);
const BOUND_PACKET_KEYS = Object.freeze([...BOUND_PACKET_FIELDS,
  'evidenceSha256']);

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function copyExactData(value, fields) {
  if (!object(value)) return null;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actualKeys = Reflect.ownKeys(descriptors);
    if (actualKeys.length !== fields.length ||
        actualKeys.some((key) => typeof key !== 'string' ||
          !fields.includes(key))) return null;
    const copy = Object.create(null);
    for (const field of fields) {
      const desc = descriptors[field];
      if (!desc || !Object.hasOwn(desc, 'value') || !desc.enumerable) {
        return null;
      }
      copy[field] = desc.value;
    }
    return copy;
  } catch (_) { return null; }
}
function asValidEvent(value, bound = false) {
  if (value === null) return null;
  const event = copyExactData(value, bound ? BOUND_EVENT_FIELDS : EVENT_FIELDS);
  if (!event || (bound && !(event.generationId === null ||
        (typeof event.generationId === 'string' &&
         GENERATION.test(event.generationId)))) ||
      typeof event.eventId !== 'string' ||
      !EVENT_ID.test(event.eventId) ||
      typeof event.timestamp !== 'string' ||
      !TIMESTAMP.test(event.timestamp) ||
      !Number.isFinite(Date.parse(event.timestamp)) ||
      !['FAILED', 'STOPPED'].includes(event.state) ||
      !(event.errorCode === null ||
        (typeof event.errorCode === 'string' &&
          ERROR_CODE.test(event.errorCode)))) return undefined;
  return event;
}
function validatePacket(value) {
  const fields = copyExactData(value, BOUND_PACKET_KEYS) ??
    copyExactData(value, EXPECTED_PACKET_KEYS);
  if (!fields) return null;
  const bound = Object.hasOwn(fields, 'generationId');
  for (const field of EVENT_KEYS) {
    const event = asValidEvent(fields[field], bound);
    if (event === undefined) return null;
    fields[field] = event;
  }
  if (fields.schemaVersion !== (bound ? 2 : 1) ||
      fields.kind !== (bound ? 'GUARDIAN_LOCAL_FAULT_EVIDENCE_V2' :
        'GUARDIAN_LOCAL_FAULT_EVIDENCE_V1') ||
      (bound && (typeof fields.generationId !== 'string' ||
        !GENERATION.test(fields.generationId) ||
        !SHA256.test(fields.launchLedgerSha256) ||
        fields.selectedFailure?.generationId !== fields.generationId)) ||
      fields.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
      fields.status !== 'SOURCE_ONLY_HOLD' ||
      fields.availability !== 'LOCAL_SNAPSHOT' ||
      fields.reason !== 'GUARDIAN_EVIDENCE_FAULT_RECORDED' ||
      fields.sourceReason !== 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED' ||
      !STATES.has(fields.processState) ||
      fields.liveness !== 'NOT_PROVEN' ||
      fields.manualInterventionRequired !== true ||
      fields.automaticRestartAllowed !== false ||
      fields.activationAllowed !== false ||
      fields.releaseAuthority !== 'NOT_ISSUED' ||
      !Number.isSafeInteger(fields.journalEntries) ||
      fields.journalEntries < 1 || fields.journalEntries > MAX_ENTRIES ||
      !Number.isSafeInteger(fields.failureCount) ||
      fields.failureCount < 1 ||
      fields.failureCount > fields.journalEntries ||
      !Number.isSafeInteger(fields.eventSequence) ||
      fields.eventSequence < 1 ||
      fields.eventSequence > fields.journalEntries ||
      !SHA256.test(fields.journalSha256) ||
      !SHA256.test(fields.evidenceSha256) ||
      fields.selectedFailure?.state !== 'FAILED' ||
      fields.firstFailure?.state !== 'FAILED' ||
      fields.latestFailure?.state !== 'FAILED') return null;
  // Hash the fixed-order, descriptor-snapshotted packet, NOT the provided
  // object's property iteration order or its own claimed evidenceSha256.
  const canonical = {};
  for (const field of (bound ? BOUND_PACKET_FIELDS : PACKET_FIELDS)) {
    canonical[field] = fields[field];
  }
  const hash = crypto.createHash('sha256')
    .update(JSON.stringify(canonical), 'utf8').digest('hex');
  if (hash !== fields.evidenceSha256) return null;
  return fields;
}
function validReceipt(row) {
  const bound = copyExactData(row, BOUND_RECEIPT_FIELDS);
  const record = bound ?? copyExactData(row, RECEIPT_FIELDS);
  if (!record || record.schemaVersion !== (bound ? 2 : 1) ||
      (bound && !(record.generationId === null ||
        (typeof record.generationId === 'string' &&
          GENERATION.test(record.generationId)))) ||
      typeof record.eventId !== 'string' || !EVENT_ID.test(record.eventId) ||
      typeof record.timestamp !== 'string' ||
      !TIMESTAMP.test(record.timestamp) ||
      !Number.isFinite(Date.parse(record.timestamp)) ||
      !['FAILED', 'STOPPED'].includes(record.state) ||
      !(record.errorCode === null ||
        (typeof record.errorCode === 'string' &&
          ERROR_CODE.test(record.errorCode))) ||
      record.hostStopped !== (record.state === 'STOPPED') ||
      record.activationAllowed !== false ||
      record.releaseAuthority !== 'NOT_ISSUED' ||
      record.automaticRestartAllowed !== false) return null;
  return record;
}
function sameEvent(packetEvent, row, bound) {
  const fields = bound ? BOUND_EVENT_FIELDS : EVENT_FIELDS;
  return packetEvent !== null && row !== undefined &&
    fields.every((key) => packetEvent[key] ===
      (key === 'generationId' ?
        (row.schemaVersion === 2 ? row.generationId : null) : row[key]));
}
function sameOptionalEvent(packetEvent, row, bound) {
  return row === undefined ? packetEvent === null :
    sameEvent(packetEvent, row, bound);
}
function outcome(reason, entries = 0, digest = null) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_EVIDENCE_COMPARISON_V1',
    status: 'SOURCE_ONLY_HOLD',
    comparison: reason === 'GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH' ?
      'MATCH_LOCAL_SNAPSHOT_ONLY' : 'NOT_VERIFIED',
    reason,
    inspectedEntries: entries,
    journalSha256: digest,
    custodyVerified: false,
    controllerStateVerified: false,
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function matchingIncident(packet, rows) {
  if (packet.journalEntries !== rows.length) return false;
  const failures = [];
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].state === 'FAILED') failures.push(i);
  }
  if (packet.failureCount !== failures.length ||
      failures.length === 0) return false;
  const index = packet.eventSequence - 1;
  if (rows[index]?.state !== 'FAILED') return false;
  const bound = packet.schemaVersion === 2;
  if (bound ? (rows[index].schemaVersion !== 2 ||
      rows[index].generationId !== packet.generationId) :
      rows[index].schemaVersion !== 1) return false;
  return sameEvent(packet.selectedFailure, rows[index], bound) &&
    sameOptionalEvent(packet.previousReceipt, rows[index - 1], bound) &&
    sameOptionalEvent(packet.nextReceipt, rows[index + 1], bound) &&
    sameEvent(packet.firstFailure, rows[failures[0]], bound) &&
    sameEvent(packet.latestFailure, rows[failures[failures.length - 1]], bound);
}

function createGuardianLocalEvidenceVerifier(options) {
  if (!object(options) ||
      Reflect.ownKeys(options).some((key) =>
        typeof key !== 'string' ||
        !['directory', 'fileName', 'maxBytes'].includes(key)) ||
      typeof options.directory !== 'string' ||
      !path.isAbsolute(options.directory) ||
      !FILE_NAME.test(options.fileName || '')) {
    throw new Error('GUARDIAN_EVIDENCE_VERIFIER_CONFIG_INVALID');
  }
  const maxBytes = options.maxBytes ?? 1_048_576;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024 ||
      maxBytes > 10_485_760) {
    throw new Error('GUARDIAN_EVIDENCE_VERIFIER_CONFIG_INVALID');
  }
  let directory, pinned;
  try {
    directory = fs.realpathSync(options.directory);
    const info = fs.lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink() ||
        (info.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' &&
          info.uid !== process.getuid())) throw new Error('unsafe');
    pinned = { dev: info.dev, ino: info.ino };
  } catch (_) {
    throw new Error('GUARDIAN_EVIDENCE_VERIFIER_DIRECTORY_UNVERIFIED');
  }
  const journal = path.join(directory, options.fileName);
  const ledger = path.join(directory, generationLedgerName(options.fileName));
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);

  function trustedDirectory() {
    try {
      const info = fs.lstatSync(directory);
      return info.isDirectory() && !info.isSymbolicLink() &&
        info.dev === pinned.dev && info.ino === pinned.ino &&
        (info.mode & 0o077) === 0 &&
        (typeof process.getuid !== 'function' ||
          info.uid === process.getuid());
    } catch (_) { return false; }
  }
  // The verifier never writes, repairs, truncates or reopens by a supplied
  // packet path. A local snapshot is always read from the owner-pinned file.
  function readLocalSnapshot() {
    if (!trustedDirectory()) return null;
    let fd;
    try {
      fd = fs.openSync(journal, flags);
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.size < 1 ||
          before.size > maxBytes || (before.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' &&
            before.uid !== process.getuid())) return null;
      const bytes = Buffer.alloc(before.size);
      let offset = 0;
      while (offset < bytes.length) {
        const count = fs.readSync(fd, bytes, offset,
          bytes.length - offset, offset);
        if (!Number.isInteger(count) || count <= 0) return null;
        offset += count;
      }
      const after = fs.fstatSync(fd);
      const visible = fs.lstatSync(journal);
      if (before.dev !== after.dev || before.ino !== after.ino ||
          before.size !== after.size ||
          before.mtimeMs !== after.mtimeMs ||
          before.ctimeMs !== after.ctimeMs ||
          visible.dev !== before.dev || visible.ino !== before.ino ||
          visible.isSymbolicLink() || !visible.isFile() ||
          (visible.mode & 0o077) !== 0 || !trustedDirectory() ||
          bytes[bytes.length - 1] !== 10 ||
          !Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes)) {
        return null;
      }
      const lines = bytes.toString('utf8').slice(0, -1).split('\n');
      if (lines.length === 0 || lines.length > MAX_ENTRIES) return null;
      const ids = new Set(), rows = [];
      for (const line of lines) {
        if (Buffer.byteLength(line) < 2 ||
            Buffer.byteLength(line) > MAX_LINE_BYTES) return null;
        const row = validReceipt(
          parseUniqueKeySourceLock(Buffer.from(line, 'utf8')));
        if (!row || ids.has(row.eventId)) return null;
        ids.add(row.eventId);
        rows.push(row);
      }
      if (!trustedDirectory()) return null;
      return {
        rows, bytes,
        fileIdentity: Object.freeze({ dev: before.dev, ino: before.ino }),
        digest: crypto.createHash('sha256').update(bytes).digest('hex'),
      };
    } catch (_) { return null; }
    finally { if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) {}
    } }
  }

  // Generation-bound packets must independently validate the current
  // pinned local launch ledger. A journal-only digest cannot prove that
  // a claimed generation was ever launched, or prevent replayed terminals.
  function verifyLedger(packet, rows) {
    if (packet.schemaVersion !== 2) return true; // explicit legacy v1 path
    if (!trustedDirectory()) return false;
    let fd;
    try {
      fd = fs.openSync(ledger, flags);
      const initial = fs.fstatSync(fd);
      if (!initial.isFile() || initial.size < 1 ||
          initial.size > maxBytes || initial.nlink !== 1 ||
          (initial.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' &&
           initial.uid !== process.getuid())) return false;
      const bytes = Buffer.alloc(initial.size);
      let off = 0;
      while (off < bytes.length) {
        const count = fs.readSync(fd, bytes, off,
          bytes.length - off, off);
        if (!Number.isInteger(count) || count <= 0) return false;
        off += count;
      }
      const after = fs.fstatSync(fd), visible = fs.lstatSync(ledger);
      if (initial.dev !== after.dev || initial.ino !== after.ino ||
          initial.size !== after.size || initial.mtimeMs !== after.mtimeMs ||
          initial.ctimeMs !== after.ctimeMs ||
          visible.dev !== initial.dev || visible.ino !== initial.ino ||
          visible.isSymbolicLink() || !visible.isFile() ||
          (visible.mode & 0o077) !== 0 || bytes.at(-1) !== 10 ||
          !Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes) ||
          crypto.createHash('sha256').update(bytes).digest('hex') !==
            packet.launchLedgerSha256) return false;
      const lines = bytes.toString('utf8').slice(0, -1).split('\n');
      if (lines.length === 0 || lines.length > MAX_ENTRIES) return false;
      const launched = new Set(), eventIds = new Set();
      const LAUNCH_FIELDS = ['schemaVersion', 'kind', 'eventId',
        'timestamp', 'generationId', 'activationAllowed',
        'releaseAuthority', 'automaticRestartAllowed'];
      for (const line of lines) {
        if (Buffer.byteLength(line) < 2 ||
            Buffer.byteLength(line) > MAX_LINE_BYTES) return false;
        const row = copyExactData(
          parseUniqueKeySourceLock(Buffer.from(line, 'utf8')),
          LAUNCH_FIELDS);
        if (!row || row.schemaVersion !== 1 ||
            row.kind !== 'GUARDIAN_GENERATION_LAUNCH_V1' ||
            typeof row.eventId !== 'string' ||
            !EVENT_ID.test(row.eventId) ||
            typeof row.timestamp !== 'string' ||
            !TIMESTAMP.test(row.timestamp) ||
            !Number.isFinite(Date.parse(row.timestamp)) ||
            typeof row.generationId !== 'string' ||
            !GENERATION.test(row.generationId) ||
            row.activationAllowed !== false ||
            row.releaseAuthority !== 'NOT_ISSUED' ||
            row.automaticRestartAllowed !== false ||
            launched.has(row.generationId) ||
            eventIds.has(row.eventId)) return false;
        launched.add(row.generationId);
        eventIds.add(row.eventId);
      }
      const terminated = new Set();
      for (const row of rows) {
        if (row.schemaVersion !== 2 || row.generationId === null) continue;
        if (!launched.has(row.generationId) ||
            terminated.has(row.generationId)) return false;
        terminated.add(row.generationId);
      }
      return launched.has(packet.generationId) &&
        trustedDirectory() ? Object.freeze({
          dev: initial.dev, ino: initial.ino,
          size: initial.size, mtimeMs: initial.mtimeMs,
          ctimeMs: initial.ctimeMs,
        }) : false;
    } catch (_) { return false; }
    finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch (_) {}
      }
    }
  }
  function verify(packet) {
    const received = validatePacket(packet);
    if (!received) return outcome('GUARDIAN_EVIDENCE_PACKET_INVALID');
    const snapshot = readLocalSnapshot();
    if (!snapshot) return outcome('GUARDIAN_EVIDENCE_LOCAL_SOURCE_UNVERIFIED');
    if (received.journalSha256 !== snapshot.digest) {
      return outcome('GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_STALE');
    }
    if (!matchingIncident(received, snapshot.rows)) {
      return outcome('GUARDIAN_EVIDENCE_PACKET_CONTENT_MISMATCH');
    }
    const firstLedger = verifyLedger(received, snapshot.rows);
    if (!firstLedger) {
      return outcome('GUARDIAN_EVIDENCE_GENERATION_LEDGER_UNVERIFIED');
    }
    if (received.schemaVersion === 2) {
      // G31: journal A -> ledger B -> journal A' -> ledger B'.
      // Any observable append/rewrite/replacement between paired reads
      // invalidates this packet rather than mixing two source versions.
      const journalAgain = readLocalSnapshot();
      const secondLedger = journalAgain ?
        verifyLedger(received, journalAgain.rows) : false;
      if (!journalAgain ||
          journalAgain.digest !== snapshot.digest ||
          journalAgain.fileIdentity.dev !== snapshot.fileIdentity.dev ||
          journalAgain.fileIdentity.ino !== snapshot.fileIdentity.ino ||
          !secondLedger ||
          Object.keys(firstLedger).some((key) =>
            firstLedger[key] !== secondLedger[key])) {
        return outcome('GUARDIAN_EVIDENCE_PAIR_CHANGED_DURING_READ');
      }
    }
    return outcome('GUARDIAN_EVIDENCE_LOCAL_SNAPSHOT_MATCH',
      snapshot.rows.length, snapshot.digest);
  }
  // A per-instance, memory-only append-continuity witness. This is neither
  // durable custody nor external attestation: a fresh process cannot
  // reconstruct observations made by an earlier process. The first reading
  // always establishes an UNTRUSTED baseline; subsequent reads require the
  // earlier validated bytes to remain an exact prefix of the newer file
  // on the SAME inode. All errors permanently latch this observer to HOLD.
  let previous = null;
  let latchedReason = null;

  function continuityResult(reason, continuity, observed, appendCount,
    priorDigest = previous?.digest ?? null) {
    return Object.freeze({
      schemaVersion: 1,
      kind: 'GUARDIAN_LOCAL_APPEND_CONTINUITY_V1',
      status: 'SOURCE_ONLY_HOLD',
      continuity, reason,
      observationSequence: previous?.sequence ?? 0,
      observedEntries: observed?.rows.length ?? 0,
      addedEntries: appendCount,
      journalSha256: observed?.digest ?? null,
      priorJournalSha256: priorDigest,
      localChainSha256: previous?.chainDigest ?? null,
      externalAnchorVerified: false,
      custodyVerified: false,
      controllerStateVerified: false,
      liveness: 'NOT_PROVEN',
      manualInterventionRequired: true,
      automaticRestartAllowed: false,
      activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
  }
  function observeContinuity() {
    if (latchedReason) {
      return continuityResult(latchedReason, 'NOT_VERIFIED', null, 0);
    }
    const snapshot = readLocalSnapshot();
    if (!snapshot) {
      // Before ANY baseline there is no historical observation to protect.
      // For example, a newly constructed owner session has no journal until
      // its first child has stopped. Stay HOLD, but permit a future FIRST
      // untrusted baseline. Once a baseline exists, a read fault is sticky.
      const reason = 'GUARDIAN_CONTINUITY_SOURCE_UNVERIFIED';
      if (previous) latchedReason = reason;
      return continuityResult(reason, 'NOT_VERIFIED', null, 0);
    }

    // No user-controlled cursor or digest is accepted: the anchor is only
    // the last snapshot this very observer has actually read and validated.
    if (previous) {
      if (snapshot.fileIdentity.dev !== previous.dev ||
          snapshot.fileIdentity.ino !== previous.ino) {
        latchedReason = 'GUARDIAN_CONTINUITY_FILE_REPLACED';
      } else if (snapshot.bytes.length < previous.byteLength ||
          snapshot.rows.length < previous.entryCount) {
        latchedReason = 'GUARDIAN_CONTINUITY_TRUNCATED';
      } else if (crypto.createHash('sha256')
        .update(snapshot.bytes.subarray(0, previous.byteLength))
        .digest('hex') !== previous.digest ||
        snapshot.bytes.length === previous.byteLength &&
          snapshot.rows.length !== previous.entryCount ||
        snapshot.bytes.length > previous.byteLength &&
          snapshot.rows.length <= previous.entryCount) {
        latchedReason = 'GUARDIAN_CONTINUITY_NON_APPEND_CHANGE';
      }
      if (latchedReason) {
        return continuityResult(latchedReason, 'NOT_VERIFIED', null, 0);
      }
      if (snapshot.digest === previous.digest) {
        // Read again, but do not invent a new custody step for an identical
        // journal snapshot. Unlike a signed ledger, observation count alone
        // would be meaningless here.
        return continuityResult('GUARDIAN_CONTINUITY_SNAPSHOT_UNCHANGED',
          'UNCHANGED_LOCAL_SNAPSHOT', snapshot, 0);
      }
    }
    const priorDigest = previous?.digest ?? null;
    const appendCount = previous ?
      snapshot.rows.length - previous.entryCount : 0;
    const chainDigest = crypto.createHash('sha256').update(JSON.stringify([
      'GUARDIAN_LOCAL_APPEND_CONTINUITY_V1',
      previous?.chainDigest ?? null,
      snapshot.digest,
      snapshot.rows.length,
      snapshot.bytes.length,
    ])).digest('hex');
    const sequence = (previous?.sequence ?? 0) + 1;
    const reason = previous ?
      'GUARDIAN_CONTINUITY_APPEND_OBSERVED' :
      'GUARDIAN_CONTINUITY_LOCAL_BASELINE';
    const continuity = previous ?
      'APPEND_ONLY_RELATIVE_TO_LOCAL_BASELINE' : 'BASELINE_ONLY';
    previous = Object.freeze({
      dev: snapshot.fileIdentity.dev,
      ino: snapshot.fileIdentity.ino,
      digest: snapshot.digest,
      byteLength: snapshot.bytes.length,
      entryCount: snapshot.rows.length,
      sequence,
      chainDigest,
    });
    return continuityResult(reason, continuity, snapshot, appendCount,
      priorDigest);
  }
  return Object.freeze({ verify, observeContinuity });
}

module.exports = { createGuardianLocalEvidenceVerifier };
