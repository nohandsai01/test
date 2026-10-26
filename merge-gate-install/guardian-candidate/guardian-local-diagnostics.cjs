/**
 * Local operator diagnostics over the owned process controller and its
 * append-only lifecycle journal. Source-only, read-only, default HOLD.
 *
 * Never claims process liveness, health, issuer authority or permission
 * to restart. An observation is NOT authenticated OS/process evidence.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');

const KEYS = new Set(['controller', 'directory', 'fileName', 'maxBytes']);
const NAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const REASONS = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING',
  'STOPPED', 'FAILED']);
const RECEIPT_KEYS = new Set(['schemaVersion', 'eventId', 'timestamp',
  'state', 'errorCode', 'hostStopped', 'activationAllowed',
  'releaseAuthority', 'automaticRestartAllowed']);
const MAX_ENTRIES = 4096;
const CONTROLLER_STATUS_FIELDS = new Set(['state', 'errorCode', 'pid',
  'activationAllowed', 'releaseAuthority', 'automaticRestartAllowed']);

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function ownFields(value, allowed) {
  return record(value) && Object.keys(value).length === allowed.size &&
    Object.keys(value).every((key) => allowed.has(key));
}
function validatedRecord(row) {
  if (!ownFields(row, RECEIPT_KEYS) || row.schemaVersion !== 1 ||
      typeof row.eventId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(row.eventId) ||
      typeof row.timestamp !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(row.timestamp) ||
      !Number.isFinite(Date.parse(row.timestamp)) ||
      !['STOPPED', 'FAILED'].includes(row.state) ||
      !(row.errorCode === null ||
        (typeof row.errorCode === 'string' && REASONS.test(row.errorCode))) ||
      row.hostStopped !== (row.state === 'STOPPED') ||
      row.activationAllowed !== false ||
      row.releaseAuthority !== 'NOT_ISSUED' ||
      row.automaticRestartAllowed !== false) {
    return false;
  }
  return true;
}
function report(reason, state, record, count, digest) {
  const safeState = STATES.has(state) ? state : 'UNVERIFIED';
  const safeLast = record ? Object.freeze({
    state: record.state, errorCode: record.errorCode,
    timestamp: record.timestamp,
    eventId: record.eventId,
  }) : null;
  const healthyCleanStop = reason === 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP' &&
    safeState === 'STOPPED' && safeLast?.state === 'STOPPED';
  return Object.freeze({
    schemaVersion: 1,
    status: 'SOURCE_ONLY_HOLD',
    reason,
    processState: safeState,
    liveness: 'NOT_PROVEN',
    journalEntries: count,
    journalSha256: digest,
    lastTerminal: safeLast,
    manualInterventionRequired: !healthyCleanStop,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function createGuardianLocalDiagnostics(options) {
  if (!record(options) || Object.keys(options).some((k) => !KEYS.has(k)) ||
      !options.controller || typeof options.controller.status !== 'function' ||
      typeof options.directory !== 'string' ||
      !path.isAbsolute(options.directory) ||
      !NAME.test(options.fileName || '')) {
    throw new Error('GUARDIAN_DIAGNOSTICS_CONFIG_INVALID');
  }
  const maxBytes = options.maxBytes ?? 1_048_576;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024 ||
      maxBytes > 10_485_760) {
    throw new Error('GUARDIAN_DIAGNOSTICS_CONFIG_INVALID');
  }
  const directory = fs.realpathSync(options.directory);
  const stats = fs.lstatSync(directory);
  if (!stats.isDirectory() || stats.isSymbolicLink() ||
      (stats.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && stats.uid !== process.getuid())) {
    throw new Error('GUARDIAN_DIAGNOSTICS_DIRECTORY_UNVERIFIED');
  }
  const file = path.join(directory, options.fileName);
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const pinnedDirectory = Object.freeze({
    dev: stats.dev, ino: stats.ino,
  });
  function directoryTrusted() {
    try {
      const current = fs.lstatSync(directory);
      return current.isDirectory() && !current.isSymbolicLink() &&
        current.dev === pinnedDirectory.dev &&
        current.ino === pinnedDirectory.ino &&
        (current.mode & 0o077) === 0 &&
        (typeof process.getuid !== 'function' ||
          current.uid === process.getuid());
    } catch (_) { return false; }
  }

function observed(reason, state, row, count, digest, rows = null) {
  return { observation: report(reason, state, row, count, digest), rows };
}
function shortEvent(row) {
  return Object.freeze({
    eventId: row.eventId, timestamp: row.timestamp,
    state: row.state, errorCode: row.errorCode,
  });
}
// Snapshot a caller-supplied options object without invoking accessors or
// repeatedly consulting a potentially mutable property. Reject symbols,
// nonenumerable unknown keys and accessor descriptors fail closed.
function ownData(value, allowed) {
  if (!record(value)) return null;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
      return null;
    }
    const snapshot = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!Object.hasOwn(descriptor, 'value')) return null;
      Object.defineProperty(snapshot, key, { value: descriptor.value,
        enumerable: true, writable: true, configurable: true });
    }
    return snapshot;
  } catch (_) { return null; }
}
function validatePageRequest(options) {
  const data = ownData(options, new Set(['limit', 'cursor']));
  if (!data) throw new Error('GUARDIAN_DIAGNOSTICS_PAGE_INVALID');
  const limit = data.limit === undefined ? 10 : data.limit;
  const rawCursor = data.cursor === undefined ? null : data.cursor;
  const cursor = rawCursor === null ? null : ownData(rawCursor,
    new Set(['journalSha256', 'before']));
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50 ||
      !(rawCursor === null || (cursor &&
        Object.keys(cursor).length === 2 &&
        typeof cursor.journalSha256 === 'string' &&
        /^[0-9a-f]{64}$/.test(cursor.journalSha256) &&
        Number.isSafeInteger(cursor.before) &&
        cursor.before >= 1 && cursor.before <= MAX_ENTRIES))) {
    throw new Error('GUARDIAN_DIAGNOSTICS_PAGE_INVALID');
  }
  return Object.freeze({ limit, cursor: cursor ? Object.freeze(cursor) : null });
}

// An incident query selects an actual FAILED receipt from one validated
// journal snapshot. The optional digest pins that exact local snapshot,
// rather than treating an earlier read as if it were still current.
const EVIDENCE_OPTIONS = new Set(['eventId', 'journalSha256']);
const EVENT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
function validateEvidenceRequest(input) {
  const data = ownData(input, EVIDENCE_OPTIONS);
  if (!data) throw new Error('GUARDIAN_EVIDENCE_REQUEST_INVALID');
  const eventId = data.eventId === undefined ? null : data.eventId;
  const expectedDigest = data.journalSha256 === undefined ?
    null : data.journalSha256;
  if (eventId !== null &&
      (typeof eventId !== 'string' || !EVENT_UUID.test(eventId)) ||
      expectedDigest !== null &&
      (typeof expectedDigest !== 'string' || !SHA256.test(expectedDigest))) {
    throw new Error('GUARDIAN_EVIDENCE_REQUEST_INVALID');
  }
  return Object.freeze({ eventId, expectedDigest });
}

function evidenceEnvelope(observation, reason, details = null) {
  const valid = details !== null;
  const fields = {
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_FAULT_EVIDENCE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    availability: valid ? 'LOCAL_SNAPSHOT' : 'UNAVAILABLE',
    reason,
    sourceReason: observation.reason,
    processState: observation.processState,
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    journalEntries: valid ? observation.journalEntries : 0,
    journalSha256: valid ? observation.journalSha256 : null,
    failureCount: valid ? details.failureCount : 0,
    eventSequence: valid ? details.eventSequence : null,
    selectedFailure: valid ? details.selectedFailure : null,
    previousReceipt: valid ? details.previousReceipt : null,
    nextReceipt: valid ? details.nextReceipt : null,
    firstFailure: valid ? details.firstFailure : null,
    latestFailure: valid ? details.latestFailure : null,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  };
  const evidenceSha256 = valid ? crypto.createHash('sha256')
    .update(JSON.stringify(fields), 'utf8').digest('hex') : null;
  return Object.freeze({ ...fields, evidenceSha256 });
}

  function safeController(controller) {
    try {
      // A Controller status is a local capability assertion. Never read a
      // mutable accessor repeatedly and accidentally report STOPPED from a
      // changing getter. Real controller statuses contain only these fields.
      const status = ownData(controller.status(), CONTROLLER_STATUS_FIELDS);
      return status && STATES.has(status.state) &&
        status.activationAllowed === false &&
        status.releaseAuthority === 'NOT_ISSUED' &&
        status.automaticRestartAllowed === false ?
        status.state : null;
    } catch (_) { return null; }
  }
  function readSnapshot() {
    const before = safeController(options.controller);
    if (before === null) return observed(
      'GUARDIAN_DIAGNOSTICS_CONTROLLER_UNVERIFIED', 'UNVERIFIED',
      null, 0, null);
    if (!directoryTrusted()) return observed(
      'GUARDIAN_DIAGNOSTICS_DIRECTORY_UNVERIFIED', before,
      null, 0, null);
    let fd;
    let buffer, st0, st1, currentPath;
    try {
      fd = fs.openSync(file, flags);
      st0 = fs.fstatSync(fd);
      if (!st0.isFile() || (st0.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' && st0.uid !== process.getuid()) ||
          st0.size < 1 || st0.size > maxBytes) {
        return observed('GUARDIAN_DIAGNOSTICS_FILE_UNVERIFIED',
          before, null, 0, null);
      }
      // Read the exact observed byte count and compare inode, size and
      // modification metadata afterwards; never silently use a partial read.
      buffer = Buffer.alloc(st0.size);
      let offset = 0;
      while (offset < buffer.length) {
        const n = fs.readSync(fd, buffer, offset, buffer.length - offset, offset);
        if (!Number.isInteger(n) || n <= 0) {
          throw new Error('short journal read');
        }
        offset += n;
      }
      st1 = fs.fstatSync(fd);
      currentPath = fs.lstatSync(file);
      if (st1.dev !== st0.dev || st1.ino !== st0.ino ||
          st1.size !== st0.size || st1.mtimeMs !== st0.mtimeMs ||
          st1.ctimeMs !== st0.ctimeMs ||
          currentPath.dev !== st0.dev || currentPath.ino !== st0.ino ||
          currentPath.isSymbolicLink() ||
          (currentPath.mode & 0o077) !== 0) {
        return observed('GUARDIAN_DIAGNOSTICS_CHANGED_DURING_READ',
          before, null, 0, null);
      }
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return observed('GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING',
          before, null, 0, null);
      }
      return observed('GUARDIAN_DIAGNOSTICS_READ_UNVERIFIED',
        before, null, 0, null);
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch (_) {}
      }
    }

    if (!buffer || !buffer.length || buffer[buffer.length - 1] !== 10 ||
        !Buffer.from(buffer.toString('utf8'), 'utf8').equals(buffer)) {
      return observed('GUARDIAN_DIAGNOSTICS_JOURNAL_INVALID',
        before, null, 0, null);
    }
    let rows;
    try {
      const lines = buffer.toString('utf8').slice(0, -1).split('\n');
      if (lines.length > MAX_ENTRIES || lines.some((line) =>
        Buffer.byteLength(line) < 2 || Buffer.byteLength(line) > 512)) {
        throw new Error('oversize or blank lines');
      }
      const ids = new Set();
      rows = lines.map((line) => {
        const parsed = parseUniqueKeySourceLock(Buffer.from(line, 'utf8'));
        if (!validatedRecord(parsed) || ids.has(parsed.eventId)) {
          throw new Error('invalid or duplicated receipt');
        }
        ids.add(parsed.eventId);
        return parsed;
      });
    } catch (_) {
      return observed('GUARDIAN_DIAGNOSTICS_JOURNAL_INVALID',
        before, null, 0, null);
    }

    if (!directoryTrusted()) {
      return observed('GUARDIAN_DIAGNOSTICS_DIRECTORY_UNVERIFIED',
        before, null, 0, null);
    }
    const after = safeController(options.controller);
    if (after !== before) {
      return observed('GUARDIAN_DIAGNOSTICS_CONTROLLER_CHANGED_DURING_READ',
        after ?? 'UNVERIFIED', null, 0, null);
    }
    const last = rows[rows.length - 1];
    const digest = crypto.createHash('sha256').update(buffer).digest('hex');
    // A later clean shutdown is an observation, not an independent
    // adjudication clearing any earlier recorded fault. Preserve manual HOLD.
    if (rows.some((entry) => entry.state === 'FAILED')) {
      return observed('GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED',
        before, last, rows.length, digest, rows);
    }
    if (before === 'STOPPED' && last.state === 'STOPPED') {
      return observed('GUARDIAN_DIAGNOSTICS_CLEAN_STOP',
        before, last, rows.length, digest, rows);
    }
    if (before === 'FAILED' || last.state === 'FAILED') {
      return observed('GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED',
        before, last, rows.length, digest, rows);
    }
    return observed('GUARDIAN_DIAGNOSTICS_INCONCLUSIVE',
      before, last, rows.length, digest, rows);
  }
  function inspect() { return readSnapshot().observation; }

  // A page never trusts previously cached rows. It validates the entire
  // bounded journal and current controller status on every read, then
  // includes the digest and an offset-bound cursor. A changed journal
  // invalidates the cursor instead of silently shifting the result window.
  function recentEvents(options = {}) {
    const { limit, cursor } = validatePageRequest(options);
    const { observation, rows } = readSnapshot();
    let chosen = observation;
    let entries = [], nextCursor = null;
    let incident = null;
    if (rows && cursor && (cursor.journalSha256 !== observation.journalSha256 ||
        cursor.before > rows.length)) {
      chosen = report('GUARDIAN_DIAGNOSTICS_CURSOR_STALE',
        observation.processState, null, 0, null);
    } else if (rows) {
      const before = cursor?.before ?? rows.length;
      const from = Math.max(0, before - limit);
      entries = rows.slice(from, before).reverse().map(shortEvent);
      const failures = rows.filter((row) => row.state === 'FAILED');
      incident = Object.freeze({
        failureCount: failures.length,
        firstFailure: failures.length ? shortEvent(failures[0]) : null,
        latestFailure: failures.length ? shortEvent(failures[failures.length - 1]) : null,
        manualInterventionRequired: observation.manualInterventionRequired,
      });
      if (from > 0) nextCursor = Object.freeze({
        journalSha256: observation.journalSha256, before: from,
      });
    }
    return Object.freeze({
      ...chosen,
      entries: Object.freeze(entries),
      nextCursor,
      incident,
    });
  }

  // Build a single bounded fault packet from the same protected read used
  // by inspect() and recentEvents(). Never splice evidence from separate
  // snapshots. This packet has a reproducible digest, not a signature or
  // tamper-proof provenance claim; local Owner/Operator ACLs still matter.
  function incidentEvidence(options = {}) {
    const { eventId, expectedDigest } = validateEvidenceRequest(options);
    const { observation, rows } = readSnapshot();
    if (!rows) {
      return evidenceEnvelope(observation,
        'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
    }
    if (expectedDigest !== null &&
        expectedDigest !== observation.journalSha256) {
      return evidenceEnvelope(observation,
        'GUARDIAN_EVIDENCE_SNAPSHOT_STALE');
    }
    const failureIndexes = [];
    for (let index = 0; index < rows.length; index++) {
      if (rows[index].state === 'FAILED') failureIndexes.push(index);
    }
    if (failureIndexes.length === 0) {
      return evidenceEnvelope(observation,
        'GUARDIAN_EVIDENCE_NO_RECORDED_FAILURE');
    }
    const index = eventId === null ?
      failureIndexes[failureIndexes.length - 1] :
      rows.findIndex((row) => row.eventId === eventId);
    if (index < 0) {
      return evidenceEnvelope(observation,
        'GUARDIAN_EVIDENCE_EVENT_NOT_FOUND');
    }
    if (rows[index].state !== 'FAILED') {
      return evidenceEnvelope(observation,
        'GUARDIAN_EVIDENCE_EVENT_NOT_FAILURE');
    }
    return evidenceEnvelope(observation,
      'GUARDIAN_EVIDENCE_FAULT_RECORDED', Object.freeze({
        failureCount: failureIndexes.length,
        eventSequence: index + 1,
        selectedFailure: shortEvent(rows[index]),
        previousReceipt: index > 0 ? shortEvent(rows[index - 1]) : null,
        nextReceipt: index + 1 < rows.length ?
          shortEvent(rows[index + 1]) : null,
        firstFailure: shortEvent(rows[failureIndexes[0]]),
        latestFailure: shortEvent(rows[failureIndexes[failureIndexes.length - 1]]),
      }));
  }
  // A single protected snapshot powers this bounded, read-only manual
  // triage recommendation. Priority indicates WHICH OWNER INVESTIGATION
  // TO PERFORM FIRST, not verified tampering or permission to reactivate.
  // All diagnostic fields come from the same stable journal read.
  function faultTriage() {
    const { observation, rows } = readSnapshot();
    let priority, classification, nextAction;
    let failureCount = 0, firstFailure = null, latestFailure = null;
    if (!rows) {
      if (observation.reason === 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING' &&
          observation.processState === 'CREATED') {
        priority = 'P2';
        classification = 'NO_LOCAL_BASELINE';
        nextAction = 'OWNER_VERIFY_FIRST_START_PREREQUISITES';
      } else {
        priority = 'P0';
        classification = 'EVIDENCE_UNVERIFIED';
        nextAction = 'OWNER_INVESTIGATE_LOCAL_EVIDENCE';
      }
    } else {
      for (const row of rows) {
        if (row.state === 'FAILED') {
          failureCount++;
          if (firstFailure === null) firstFailure = shortEvent(row);
          latestFailure = shortEvent(row);
        }
      }
      if (failureCount > 0) {
        // A later clean stop never suppresses a historical incident.
        priority = 'P1';
        classification = 'RECORDED_FAILURE';
        nextAction = 'OWNER_REVIEW_FAULT_HISTORY';
      } else if (observation.processState === 'FAILED') {
        priority = 'P1';
        classification = 'CONTROLLER_FAILED';
        nextAction = 'OWNER_INVESTIGATE_CONTROLLER_FAILURE';
      } else if (observation.reason === 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP' &&
          observation.processState === 'STOPPED') {
        priority = 'P3';
        classification = 'LOCAL_STOP_OBSERVED';
        nextAction = 'NO_LOCAL_FAULT_OBSERVED';
      } else {
        priority = 'P2';
        classification = 'PROCESS_STATE_UNPROVEN';
        nextAction = 'OWNER_RECONCILE_LIFECYCLE';
      }
    }
    const cleanStop = classification === 'LOCAL_STOP_OBSERVED';
    return Object.freeze({
      schemaVersion: 1,
      kind: 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1',
      authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
      status: 'SOURCE_ONLY_HOLD',
      priority, classification, nextAction,
      sourceReason: observation.reason,
      processState: observation.processState,
      liveness: 'NOT_PROVEN',
      journalEntries: rows ? rows.length : 0,
      journalSha256: rows ? observation.journalSha256 : null,
      failureCount,
      firstFailure,
      latestFailure,
      lastTerminal: rows ? observation.lastTerminal : null,
      manualInterventionRequired: !cleanStop,
      automaticRestartAllowed: false,
      activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
  }
  return Object.freeze({ inspect, recentEvents, incidentEvidence, faultTriage });
}

module.exports = { createGuardianLocalDiagnostics };
