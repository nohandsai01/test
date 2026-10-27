/**
 * Guardian G27B: validate / hand off minimal offline incident briefs.
 *
 * No I/O, signatures, keys, liveness, custody proof or authority. A matching
 * digest establishes only the consistency of a local, untrusted report.
 * Independent of process generation, IPC and recovery work (G27–G30).
 */
'use strict';

const crypto = require('node:crypto');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');
const F = Object.freeze([
  'schemaVersion', 'kind', 'authority', 'status', 'classification',
  'priority', 'processState', 'sourceReason', 'healthFreshness',
  'journalSha256', 'journalEntries', 'historicalFailureCount', 'events',
  'liveness', 'manualInterventionRequired', 'automaticRestartAllowed',
  'activationAllowed', 'releaseAuthority',
]);
const E = Object.freeze(['eventId', 'timestamp', 'state', 'errorCode']);
const B = Object.freeze([
  'schemaVersion', 'kind', 'authority', 'status', 'briefs',
  'count', 'liveness', 'manualInterventionRequired',
  'automaticRestartAllowed', 'activationAllowed', 'releaseAuthority',
]);
const SHA = /^[0-9a-f]{64}$/;
const CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TIMESTAMP = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const STATES = new Set(['CREATED','STARTING','RUNNING','STOPPING','STOPPED','FAILED']);
const REPORT_REASONS = new Set([
  'LOCAL_BRIEF_CONSISTENT','LOCAL_BRIEF_SOURCE_UNVERIFIED',
  'LOCAL_BRIEF_READ_FAILED','LOCAL_BRIEF_EVIDENCE_CHANGED',
]);
const PRIORITIES = new Set(['P0','P1','P2','P3']);
const FRESHNESS = new Set(['UNVERIFIED','RECENT','EXPIRED']);
const MAX_BUNDLE = 8;
const MAX_BYTES = 96_000;
function plain(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== keys.length || own.some((key) =>
      typeof key !== 'string' || !keys.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const clean = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
          descriptor.enumerable !== true) return null;
      Object.defineProperty(clean, key, {
        value: descriptor.value, enumerable: true,
        writable: false, configurable: false,
      });
    }
    return Object.freeze(clean);
  } catch (_) { return null; }
}
function safeArray(value, maximum) {
  try {
    if (!Array.isArray(value) || value.length < 1 ||
        value.length > maximum) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 ||
        keys.some((key) => key !== 'length' &&
          !/^(0|[1-9]\d*)$/.test(String(key)))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const copied = [];
    for (let i = 0; i < value.length; i++) {
      const d = descriptors[i];
      if (!d || !Object.hasOwn(d, 'value') || d.enumerable !== true) return null;
      copied.push(d.value);
    }
    return copied;
  } catch (_) { return null; }
}
function hash(value) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(value), 'utf8').digest('hex');
}
function utc(value) {
  if (typeof value !== 'string' || !TIMESTAMP.test(value)) return false;
  try { return new Date(value).toISOString() === value; }
  catch (_) { return false; }
}
function cleanEvent(value) {
  const x = plain(value, E);
  return x && typeof x.eventId === 'string' && UUID.test(x.eventId) &&
    utc(x.timestamp) && ['STOPPED','FAILED'].includes(x.state) &&
    (x.state === 'STOPPED' ? x.errorCode === null :
      typeof x.errorCode === 'string' && CODE.test(x.errorCode)) ? x : null;
}
function cleanBrief(raw) {
  const x = plain(raw, [...F,'briefSha256']);
  if (!x || x.schemaVersion !== 1 ||
      x.kind !== 'GUARDIAN_LOCAL_OPERATOR_INCIDENT_BRIEF_V1' ||
      x.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
      x.status !== 'SOURCE_ONLY_HOLD' ||
      !REPORT_REASONS.has(x.classification) ||
      !PRIORITIES.has(x.priority) || x.liveness !== 'NOT_PROVEN' ||
      x.manualInterventionRequired !== true ||
      x.automaticRestartAllowed !== false || x.activationAllowed !== false ||
      x.releaseAuthority !== 'NOT_ISSUED' ||
      typeof x.briefSha256 !== 'string' || !SHA.test(x.briefSha256)) return null;
  const accepted = x.classification === 'LOCAL_BRIEF_CONSISTENT';
  if (accepted) {
    if (x.priority === 'P0' || !STATES.has(x.processState) ||
        typeof x.sourceReason !== 'string' || !CODE.test(x.sourceReason) ||
        !FRESHNESS.has(x.healthFreshness) ||
        typeof x.journalSha256 !== 'string' || !SHA.test(x.journalSha256) ||
        !Number.isSafeInteger(x.journalEntries) ||
        x.journalEntries < 1 || x.journalEntries > 4096 ||
        !Number.isSafeInteger(x.historicalFailureCount) ||
        x.historicalFailureCount < 0 ||
        x.historicalFailureCount > x.journalEntries ||
        (x.priority === 'P3' &&
          (x.processState !== 'STOPPED' || x.historicalFailureCount !== 0))) return null;
  } else if (x.priority !== 'P0' || x.processState !== 'UNVERIFIED' ||
      x.sourceReason !== null || x.healthFreshness !== 'UNVERIFIED' ||
      x.journalSha256 !== null || x.journalEntries !== 0 ||
      x.historicalFailureCount !== 0) return null;
  const events = accepted ? safeArray(x.events, 10) :
    (Array.isArray(x.events) && x.events.length === 0 &&
     Reflect.ownKeys(x.events).length === 1 ? [] : null);
  if (!events || (accepted && events.length > x.journalEntries)) return null;
  const safeEvents = [];
  const ids = new Set();
  for (const e of events) {
    const item = cleanEvent(e);
    if (!item || ids.has(item.eventId)) return null;
    ids.add(item.eventId);
    safeEvents.push(item);
  }
  const content = {};
  for (const field of F) content[field] =
    field === 'events' ? Object.freeze(safeEvents) : x[field];
  if (hash(content) !== x.briefSha256) return null;
  return Object.freeze({ ...content, briefSha256: x.briefSha256 });
}
function verdict(reason, report = null) {
  const matched = reason === 'GUARDIAN_BRIEF_LOCAL_CHECKSUM_MATCH';
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_BRIEF_VERIFICATION_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    comparison: matched ? 'MATCH_LOCAL_CHECKSUM_ONLY' : 'NOT_VERIFIED',
    reason,
    briefSha256: matched ? report.briefSha256 : null,
    priority: matched ? report.priority : 'P0',
    journalSha256: matched ? report.journalSha256 : null,
    eventCount: matched ? report.events.length : 0,
    liveness: 'NOT_PROVEN', manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function verifyBrief(input) {
  try {
    if (typeof input === 'string' &&
        Buffer.byteLength(input, 'utf8') > MAX_BYTES) {
      return verdict('GUARDIAN_BRIEF_INVALID');
    }
    const data = typeof input === 'string' ? parseUniqueKeySourceLock(Buffer.from(input, 'utf8')) : input;
    const report = cleanBrief(data);
    return report ? verdict('GUARDIAN_BRIEF_LOCAL_CHECKSUM_MATCH', report) :
      verdict('GUARDIAN_BRIEF_INVALID');
  } catch (_) { return verdict('GUARDIAN_BRIEF_INVALID'); }
}
function makeBundle(briefs) {
  const items = safeArray(briefs, MAX_BUNDLE);
  if (!items) throw new Error('GUARDIAN_BRIEF_BUNDLE_INVALID');
  const copied = items.map(cleanBrief);
  if (copied.some((b) => b === null)) {
    throw new Error('GUARDIAN_BRIEF_BUNDLE_INVALID');
  }
  const unique = new Set(copied.map((b) => b.briefSha256));
  if (unique.size !== copied.length) {
    throw new Error('GUARDIAN_BRIEF_BUNDLE_DUPLICATED');
  }
  const body = {
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_BRIEF_BUNDLE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    briefs: Object.freeze(copied),
    count: copied.length,
    liveness: 'NOT_PROVEN', manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  };
  const digest = hash(body);
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BYTES) {
    throw new Error('GUARDIAN_BRIEF_BUNDLE_TOO_LARGE');
  }
  return Object.freeze({ ...body, bundleSha256: digest });
}
function verifyBundle(input) {
  try {
    if (typeof input === 'string' &&
        Buffer.byteLength(input, 'utf8') > MAX_BYTES) {
      return Object.freeze({ ...verdict('GUARDIAN_BRIEF_BUNDLE_INVALID'),
        bundleSha256: null, count: 0 });
    }
    const value = typeof input === 'string' ? parseUniqueKeySourceLock(Buffer.from(input, 'utf8')) : input;
    const data = plain(value, [...B,'bundleSha256']);
    if (!data || data.schemaVersion !== 1 ||
        data.kind !== 'GUARDIAN_LOCAL_BRIEF_BUNDLE_V1' ||
        data.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        data.status !== 'SOURCE_ONLY_HOLD' || data.liveness !== 'NOT_PROVEN' ||
        data.manualInterventionRequired !== true ||
        data.automaticRestartAllowed !== false ||
        data.activationAllowed !== false || data.releaseAuthority !== 'NOT_ISSUED' ||
        typeof data.bundleSha256 !== 'string' || !SHA.test(data.bundleSha256)) {
      throw new Error('invalid bundle');
    }
    const copied = safeArray(data.briefs, MAX_BUNDLE);
    if (!copied || copied.length !== data.count) throw new Error('invalid count');
    const all = copied.map(cleanBrief);
    if (all.some((b) => !b) ||
        new Set(all.map((x) => x.briefSha256)).size !== all.length) {
      throw new Error('invalid member');
    }
    const body = {};
    for (const field of B) body[field] =
      field === 'briefs' ? Object.freeze(all) : data[field];
    if (hash(body) !== data.bundleSha256 ||
        Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BYTES) {
      throw new Error('invalid digest');
    }
    return Object.freeze({
      schemaVersion: 1,
      kind: 'GUARDIAN_LOCAL_BRIEF_BUNDLE_VERIFICATION_V1',
      status: 'SOURCE_ONLY_HOLD',
      comparison: 'MATCH_LOCAL_CHECKSUM_ONLY',
      reason: 'GUARDIAN_BRIEF_BUNDLE_CHECKSUM_MATCH',
      bundleSha256: data.bundleSha256, count: all.length,
      briefDigests: Object.freeze(all.map((x) => x.briefSha256)),
      manualInterventionRequired: true,
      liveness: 'NOT_PROVEN', automaticRestartAllowed: false,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    });
  } catch (_) {
    return Object.freeze({
      schemaVersion: 1,
      kind: 'GUARDIAN_LOCAL_BRIEF_BUNDLE_VERIFICATION_V1',
      status: 'SOURCE_ONLY_HOLD',
      comparison: 'NOT_VERIFIED',
      reason: 'GUARDIAN_BRIEF_BUNDLE_INVALID',
      bundleSha256: null, count: 0, briefDigests: Object.freeze([]),
      manualInterventionRequired: true, liveness: 'NOT_PROVEN',
      automaticRestartAllowed: false, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
  }
}

/**
 * A checksum-valid brief is still unauthenticated. Continuity can be
 * observed STRUCTURALLY ONLY when both snapshots expose their entire
 * bounded journal (at most 10 terminal receipts). A partial latest-page
 * window is never enough to prove continuity or absence of removed rows.
 *
 * Events are newest first. The older complete array must equal the
 * older suffix of the newer complete array; all appended events must
 * account for the change in the recorded failure count. No trust upgrade.
 */
function sameEvent(a, b) {
  return E.every((field) => a[field] === b[field]);
}
function continuityReceipt(reason, older = null, newer = null, delta = 0) {
  const matched = reason === 'GUARDIAN_BRIEF_SAME_LOCAL_SNAPSHOT' ||
    reason === 'GUARDIAN_BRIEF_STRUCTURAL_APPEND_COMPATIBLE';
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_BRIEF_CONTINUITY_V1',
    status: 'SOURCE_ONLY_HOLD',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    comparison: matched ? 'LOCAL_STRUCTURAL_OBSERVATION_ONLY' : 'NOT_VERIFIED',
    reason,
    olderJournalSha256: matched ? older.journalSha256 : null,
    newerJournalSha256: matched ? newer.journalSha256 : null,
    olderEntryCount: matched ? older.journalEntries : 0,
    newerEntryCount: matched ? newer.journalEntries : 0,
    appendedEntries: matched ? delta : 0,
    liveness: 'NOT_PROVEN',
    custodyVerified: false,
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function compareVerifiedBriefs(older, newer) {
  if (!older || !newer || older.classification !== 'LOCAL_BRIEF_CONSISTENT' ||
      newer.classification !== 'LOCAL_BRIEF_CONSISTENT') {
    return continuityReceipt('GUARDIAN_BRIEF_CONTINUITY_SOURCE_UNVERIFIED');
  }
  // A bounded page with a hidden history is not a complete baseline.
  // The bundle may still be checksum-valid, but continuity is NOT_PROVEN.
  if (older.journalEntries > 10 || newer.journalEntries > 10 ||
      older.events.length !== older.journalEntries ||
      newer.events.length !== newer.journalEntries) {
    return continuityReceipt('GUARDIAN_BRIEF_CONTINUITY_INCOMPLETE_HISTORY');
  }
  const delta = newer.journalEntries - older.journalEntries;
  if (delta < 0 || delta > 10 ||
      newer.historicalFailureCount < older.historicalFailureCount ||
      (delta === 0 && (older.journalSha256 !== newer.journalSha256 ||
        older.historicalFailureCount !== newer.historicalFailureCount)) ||
      (delta > 0 && older.journalSha256 === newer.journalSha256)) {
    return continuityReceipt('GUARDIAN_BRIEF_CONTINUITY_CONFLICT');
  }
  // A duplicate UUID in different snapshots with changed event contents,
  // a reordering, or a truncated history is never a compatible append.
  for (let i = 0; i < older.events.length; i++) {
    if (!sameEvent(older.events[i], newer.events[i + delta])) {
      return continuityReceipt('GUARDIAN_BRIEF_CONTINUITY_CONFLICT');
    }
  }
  let newlyFailed = 0;
  for (let i = 0; i < delta; i++) {
    if (newer.events[i].state === 'FAILED') newlyFailed++;
  }
  if (newer.historicalFailureCount - older.historicalFailureCount !== newlyFailed) {
    return continuityReceipt('GUARDIAN_BRIEF_CONTINUITY_CONFLICT');
  }
  if (delta === 0) {
    return continuityReceipt('GUARDIAN_BRIEF_SAME_LOCAL_SNAPSHOT', older, newer);
  }
  return continuityReceipt('GUARDIAN_BRIEF_STRUCTURAL_APPEND_COMPATIBLE',
    older, newer, delta);
}
function readBrief(input) {
  try {
    if (typeof input === 'string' &&
        Buffer.byteLength(input, 'utf8') > MAX_BYTES) return null;
    const value = typeof input === 'string' ?
      parseUniqueKeySourceLock(Buffer.from(input, 'utf8')) : input;
    return cleanBrief(value);
  } catch (_) { return null; }
}
function compareBriefHistory(older, newer) {
  return compareVerifiedBriefs(readBrief(older), readBrief(newer));
}
function verifyBundleHistory(input) {
  try {
    if (typeof input === 'string' &&
        Buffer.byteLength(input, 'utf8') > MAX_BYTES) {
      throw new Error('oversize');
    }
    const obj = typeof input === 'string' ?
      parseUniqueKeySourceLock(Buffer.from(input, 'utf8')) : input;
    const validated = verifyBundle(obj);
    if (validated.comparison !== 'MATCH_LOCAL_CHECKSUM_ONLY') {
      throw new Error('invalid bundle digest');
    }
    const values = safeArray(obj.briefs, MAX_BUNDLE);
    if (!values || values.length < 2) {
      throw new Error('too few snapshots');
    }
    const normalized = values.map(cleanBrief);
    if (normalized.some((x) => !x)) throw new Error('invalid member');
    const comparisons = [];
    for (let i = 1; i < normalized.length; i++) {
      const result = compareVerifiedBriefs(normalized[i - 1], normalized[i]);
      if (result.comparison !== 'LOCAL_STRUCTURAL_OBSERVATION_ONLY') {
        return Object.freeze({
          schemaVersion: 1, kind: 'GUARDIAN_LOCAL_BRIEF_HISTORY_V1',
          status: 'SOURCE_ONLY_HOLD', reason: result.reason,
          comparison: 'NOT_VERIFIED',
          bundleSha256: null, comparisons: Object.freeze([]),
          liveness: 'NOT_PROVEN', custodyVerified: false,
          manualInterventionRequired: true,
          automaticRestartAllowed: false, activationAllowed: false,
          releaseAuthority: 'NOT_ISSUED',
        });
      }
      comparisons.push(result);
    }
    return Object.freeze({
      schemaVersion: 1, kind: 'GUARDIAN_LOCAL_BRIEF_HISTORY_V1',
      status: 'SOURCE_ONLY_HOLD',
      reason: 'GUARDIAN_BRIEF_BUNDLE_HISTORY_STRUCTURALLY_COMPATIBLE',
      comparison: 'LOCAL_STRUCTURAL_OBSERVATION_ONLY',
      bundleSha256: validated.bundleSha256,
      comparisons: Object.freeze(comparisons),
      liveness: 'NOT_PROVEN', custodyVerified: false,
      manualInterventionRequired: true,
      automaticRestartAllowed: false, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
  } catch (_) {
    return Object.freeze({
      schemaVersion: 1, kind: 'GUARDIAN_LOCAL_BRIEF_HISTORY_V1',
      status: 'SOURCE_ONLY_HOLD',
      reason: 'GUARDIAN_BRIEF_BUNDLE_HISTORY_UNVERIFIED',
      comparison: 'NOT_VERIFIED',
      bundleSha256: null, comparisons: Object.freeze([]),
      liveness: 'NOT_PROVEN', custodyVerified: false,
      manualInterventionRequired: true,
      automaticRestartAllowed: false, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
  }
}
module.exports = Object.freeze({
  verifyBrief, makeBundle, verifyBundle,
  compareBriefHistory, verifyBundleHistory,
});
