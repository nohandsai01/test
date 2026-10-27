/**
 * Guardian G27A: offline, redacted, read-only incident brief.
 *
 * This is a source-only operator-side consumer of existing passive APIs,
 * distinct from G27-G30's program identity / IPC / crash-recovery work.
 * It never contacts D1 or GitHub, manages children, writes a journal, clears
 * a fault, or asserts production provenance.
 */
'use strict';

const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const SHA = /^[0-9a-f]{64}$/;
const CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const EVENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING', 'STOPPED', 'FAILED']);
const PRIORITIES = new Set(['P0', 'P1', 'P2', 'P3']);
const ASSESSMENT_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'authority', 'status', 'priority',
  'classification', 'nextAction', 'processState', 'triageReason',
  'healthFreshness', 'healthReason', 'healthSampleAgeMs',
  'healthMaxAgeMs', 'journalSha256', 'journalEntries',
  'historicalFailureCount', 'liveness', 'manualInterventionRequired',
  'automaticRestartAllowed', 'activationAllowed', 'releaseAuthority',
]);
const EVENT_FIELDS = Object.freeze(['eventId', 'timestamp', 'state', 'errorCode']);
const KEYS = Object.freeze(['operator', 'limit', 'maxCaptureMs']);

function exactData(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== names.length || own.some((key) =>
        typeof key !== 'string' || !names.includes(key))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = {};
    for (const key of names) {
      const d = descriptors[key];
      if (!d || !Object.hasOwn(d, 'value')) return null;
      Object.defineProperty(result, key, {
        value: d.value, enumerable: true, writable: false,
      });
    }
    return Object.freeze(result);
  } catch (_) { return null; }
}
function reasonString(x, max = 110) {
  return typeof x === 'string' && x.length >= 1 && x.length <= max &&
    /^[A-Z][A-Z0-9_]*$/.test(x);
}
function validAssessment(value) {
  const x = exactData(value, ASSESSMENT_FIELDS);
  if (!x || x.schemaVersion !== 1 ||
      x.kind !== 'GUARDIAN_LOCAL_RUNTIME_ASSESSMENT_V1' ||
      x.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
      x.status !== 'SOURCE_ONLY_HOLD' ||
      !PRIORITIES.has(x.priority) ||
      !reasonString(x.classification) || !reasonString(x.nextAction) ||
      !STATES.has(x.processState) ||
      !(x.triageReason === null || (typeof x.triageReason === 'string' && CODE.test(x.triageReason))) ||
      !['RECENT','EXPIRED','UNVERIFIED'].includes(x.healthFreshness) ||
      !(x.healthReason === null || (typeof x.healthReason === 'string' && CODE.test(x.healthReason))) ||
      !(x.healthSampleAgeMs === null ||
        (Number.isSafeInteger(x.healthSampleAgeMs) && x.healthSampleAgeMs >= 0)) ||
      !(x.healthMaxAgeMs === null ||
        (Number.isSafeInteger(x.healthMaxAgeMs) && x.healthMaxAgeMs >= 50 &&
         x.healthMaxAgeMs <= 30_000)) ||
      !(x.journalSha256 === null ||
        (typeof x.journalSha256 === 'string' && SHA.test(x.journalSha256))) ||
      !Number.isSafeInteger(x.journalEntries) || x.journalEntries < 0 ||
      x.journalEntries > 4096 ||
      !Number.isSafeInteger(x.historicalFailureCount) ||
      x.historicalFailureCount < 0 ||
      x.historicalFailureCount > x.journalEntries ||
      x.liveness !== 'NOT_PROVEN' ||
      x.manualInterventionRequired !== (x.priority !== 'P3') ||
      x.automaticRestartAllowed !== false ||
      x.activationAllowed !== false ||
      x.releaseAuthority !== 'NOT_ISSUED' ||
      (x.priority === 'P3' && (x.processState !== 'STOPPED' ||
        x.historicalFailureCount !== 0)) ||
      (x.healthFreshness === 'RECENT' && (!Number.isSafeInteger(x.healthSampleAgeMs) ||
        x.healthSampleAgeMs > x.healthMaxAgeMs))) return null;
  return x;
}
function validEvent(raw) {
  const e = exactData(raw, EVENT_FIELDS);
  if (!e || typeof e.eventId !== 'string' || !EVENT_ID.test(e.eventId) ||
      typeof e.timestamp !== 'string' || !UTC.test(e.timestamp) ||
      !Number.isFinite(Date.parse(e.timestamp)) ||
      !['FAILED', 'STOPPED'].includes(e.state) ||
      !(e.errorCode === null || (typeof e.errorCode === 'string' &&
        CODE.test(e.errorCode))) ||
      (e.state === 'STOPPED') !== (e.errorCode === null)) return null;
  return e;
}
function validPage(raw, limit) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  // The page provider may add metadata; never echo it. Reject unsafe getters
  // or prototype spoofing, then snapshot only known non-authorizing fields.
  let headers;
  try {
    const proto = Object.getPrototypeOf(raw);
    if (proto !== Object.prototype && proto !== null) return null;
    const d = Object.getOwnPropertyDescriptors(raw);
    const expected = ['schemaVersion', 'status', 'reason', 'processState',
      'journalSha256', 'journalEntries', 'liveness',
      'automaticRestartAllowed', 'activationAllowed', 'releaseAuthority',
      'entries', 'incident', 'nextCursor'];
    for (const key of expected) {
      if (!d[key] || !Object.hasOwn(d[key], 'value')) return null;
    }
    headers = Object.fromEntries(expected.map((key) => [key, d[key].value]));
  } catch (_) { return null; }
  if (headers.schemaVersion !== 1 || headers.status !== 'SOURCE_ONLY_HOLD' ||
      headers.releaseAuthority !== 'NOT_ISSUED' ||
      headers.activationAllowed !== false ||
      headers.automaticRestartAllowed !== false ||
      headers.liveness !== 'NOT_PROVEN' ||
      !CODE.test(headers.reason) ||
      !STATES.has(headers.processState) ||
      !(typeof headers.journalSha256 === 'string' && SHA.test(headers.journalSha256)) ||
      !Number.isSafeInteger(headers.journalEntries) ||
      headers.journalEntries < 1 || headers.journalEntries > 4096 ||
      !Array.isArray(headers.entries) ||
      headers.entries.length < 1 || headers.entries.length > limit) return null;
  const entries = [];
  const ids = new Set();
  const desc = Object.getOwnPropertyDescriptors(headers.entries);
  for (let index = 0; index < headers.entries.length; index++) {
    const item = desc[index]?.value;
    const e = validEvent(item);
    if (!e || ids.has(e.eventId)) return null;
    entries.push(e);
    ids.add(e.eventId);
  }
  // The first query always uses no cursor. Any cursor returned must be
  // identical to the observed local journal digest, never a remote pointer.
  if (headers.nextCursor !== null) {
    const c = exactData(headers.nextCursor, ['journalSha256','before']);
    if (!c || c.journalSha256 !== headers.journalSha256 ||
        !Number.isSafeInteger(c.before) || c.before < 1 ||
        c.before > headers.journalEntries) return null;
  }
  if (!headers.incident || typeof headers.incident !== 'object' ||
      Array.isArray(headers.incident)) return null;
  const incident = exactData(headers.incident, [
    'failureCount','firstFailure','latestFailure','manualInterventionRequired']);
  if (!incident || !Number.isSafeInteger(incident.failureCount) ||
      incident.failureCount < 0 || incident.failureCount > headers.journalEntries ||
      typeof incident.manualInterventionRequired !== 'boolean' ||
      !(incident.firstFailure === null || validEvent(incident.firstFailure)) ||
      !(incident.latestFailure === null || validEvent(incident.latestFailure)) ||
      (incident.failureCount === 0) !== (incident.firstFailure === null) ||
      (incident.failureCount === 0) !== (incident.latestFailure === null)) return null;
  return Object.freeze({
    reason: headers.reason, processState: headers.processState,
    journalSha256: headers.journalSha256,
    journalEntries: headers.journalEntries,
    failureCount: incident.failureCount,
    entries: Object.freeze(entries),
  });
}
function sameAssessment(a, b) {
  return !!a && !!b &&
    a.priority === b.priority && a.classification === b.classification &&
    a.nextAction === b.nextAction &&
    a.processState === b.processState &&
    a.triageReason === b.triageReason &&
    a.healthFreshness === b.healthFreshness &&
    a.journalSha256 === b.journalSha256 &&
    a.journalEntries === b.journalEntries &&
    a.historicalFailureCount === b.historicalFailureCount;
}
function frozenReport(classification, input = null) {
  const incident = input && classification === 'LOCAL_BRIEF_CONSISTENT';
  const content = {
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_OPERATOR_INCIDENT_BRIEF_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    classification,
    priority: incident ? input.assessment.priority : 'P0',
    processState: incident ? input.assessment.processState : 'UNVERIFIED',
    sourceReason: incident ? input.assessment.triageReason : null,
    healthFreshness: incident ? input.assessment.healthFreshness : 'UNVERIFIED',
    journalSha256: incident ? input.assessment.journalSha256 : null,
    journalEntries: incident ? input.assessment.journalEntries : 0,
    historicalFailureCount: incident ? input.assessment.historicalFailureCount : 0,
    events: Object.freeze(incident ? input.events : []),
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
  };
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify(content), 'utf8').digest('hex');
  return Object.freeze({ ...content, briefSha256: digest });
}
function createGuardianOfflineIncidentBrief({ operator, limit = 5,
  maxCaptureMs = 1000 } = {}) {
  if (!operator || typeof operator.assessRuntime !== 'function' ||
      typeof operator.recentEvents !== 'function' ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 10 ||
      !Number.isSafeInteger(maxCaptureMs) ||
      maxCaptureMs < 50 || maxCaptureMs > 5000) {
    throw new Error('GUARDIAN_LOCAL_BRIEF_CONFIG_INVALID');
  }
  // Check exactly the allowed own keys (if supplied) without inspecting
  // options' untrusted dynamic property accessors.
  const config = arguments[0];
  if (!config || typeof config !== 'object' || Array.isArray(config) ||
      Reflect.ownKeys(config).some((key) => typeof key !== 'string' ||
        !KEYS.includes(key))) {
    throw new Error('GUARDIAN_LOCAL_BRIEF_CONFIG_INVALID');
  }
  function capture() {
    const start = performance.now();
    let before, after, page;
    try {
      before = validAssessment(operator.assessRuntime());
      if (!before || before.priority === 'P0' ||
          before.journalSha256 === null) {
        return frozenReport('LOCAL_BRIEF_SOURCE_UNVERIFIED');
      }
      page = validPage(operator.recentEvents({ limit }), limit);
      after = validAssessment(operator.assessRuntime());
    } catch (_) {
      return frozenReport('LOCAL_BRIEF_READ_FAILED');
    }
    if (!before || !after || !page || !sameAssessment(before, after) ||
        before.priority === 'P0' || after.priority === 'P0' ||
        before.processState !== page.processState ||
        before.journalSha256 !== page.journalSha256 ||
        before.journalEntries !== page.journalEntries ||
        before.historicalFailureCount !== page.failureCount ||
        performance.now() - start > maxCaptureMs) {
      return frozenReport('LOCAL_BRIEF_EVIDENCE_CHANGED');
    }
    return frozenReport('LOCAL_BRIEF_CONSISTENT', {
      assessment: after, events: page.entries,
    });
  }
  return Object.freeze({ capture });
}
module.exports = { createGuardianOfflineIncidentBrief };
