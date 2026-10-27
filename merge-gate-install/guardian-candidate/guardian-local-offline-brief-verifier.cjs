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
module.exports = Object.freeze({ verifyBrief, makeBundle, verifyBundle });
