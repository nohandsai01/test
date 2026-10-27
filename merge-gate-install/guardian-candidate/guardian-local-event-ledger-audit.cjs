/**
 * Guardian G27C — read-only complete local receipt ledger audit.
 *
 * Consumes the existing Operator.recentEvents() cursor protocol without
 * reading files itself. Protects against trusting a truncated, reordered,
 * stale, duplicate or partial sequence of otherwise valid pages. This is
 * only local diagnostic consistency: no signature, custody or liveness proof.
 *
 * No write, network, child-control, Check or D1 capabilities.
 */
'use strict';

const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');

const SHA = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const STATES = new Set(['CREATED','STARTING','RUNNING','STOPPING','STOPPED','FAILED']);
const PAGE_KEYS = Object.freeze([
  'schemaVersion','status','reason','processState','liveness',
  'journalEntries','journalSha256','lastTerminal',
  'manualInterventionRequired','automaticRestartAllowed',
  'activationAllowed','releaseAuthority','entries','nextCursor','incident',
]);
const EVENT_KEYS = Object.freeze(['eventId','timestamp','state','errorCode']);
const INCIDENT_KEYS = Object.freeze([
  'failureCount','firstFailure','latestFailure','manualInterventionRequired',
]);

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const names = Reflect.ownKeys(value);
    if (names.length !== keys.length || names.some((name) =>
        typeof name !== 'string' || !keys.includes(name))) return null;
    const desc = Object.getOwnPropertyDescriptors(value);
    const out = {};
    for (const name of keys) {
      const d = desc[name];
      if (!d || !Object.hasOwn(d,'value') || d.enumerable !== true) return null;
      Object.defineProperty(out, name, {
        value: d.value, enumerable: true, writable: false,
        configurable: false,
      });
    }
    return Object.freeze(out);
  } catch (_) { return null; }
}
function denseArray(value, max) {
  try {
    if (!Array.isArray(value) || value.length < 1 ||
        value.length > max) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1) return null;
    const out = [];
    for (let i = 0; i < value.length; i++) {
      const d = descriptors[i];
      if (!d || !Object.hasOwn(d,'value') || d.enumerable !== true) return null;
      out.push(d.value);
    }
    return out;
  } catch (_) { return null; }
}
function validIso(value) {
  if (typeof value !== 'string' || !ISO.test(value)) return false;
  try { return new Date(value).toISOString() === value; }
  catch (_) { return false; }
}
function validEvent(raw) {
  const x = exact(raw, EVENT_KEYS);
  if (!x || typeof x.eventId !== 'string' || !UUID.test(x.eventId) ||
      !validIso(x.timestamp) ||
      !['STOPPED','FAILED'].includes(x.state) ||
      !(x.errorCode === null ||
        (typeof x.errorCode === 'string' && CODE.test(x.errorCode)))) {
    return null;
  }
  return x;
}
function sameEvent(a, b) {
  return !!a && !!b && EVENT_KEYS.every((field) => a[field] === b[field]);
}
function validPage(raw, pageSize) {
  const x = exact(raw, PAGE_KEYS);
  if (!x || x.schemaVersion !== 1 || x.status !== 'SOURCE_ONLY_HOLD' ||
      typeof x.reason !== 'string' || !CODE.test(x.reason) ||
      !STATES.has(x.processState) ||
      x.liveness !== 'NOT_PROVEN' ||
      x.automaticRestartAllowed !== false ||
      x.activationAllowed !== false ||
      x.releaseAuthority !== 'NOT_ISSUED' ||
      typeof x.manualInterventionRequired !== 'boolean' ||
      !Number.isSafeInteger(x.journalEntries) ||
      x.journalEntries < 1 || x.journalEntries > 4096 ||
      typeof x.journalSha256 !== 'string' || !SHA.test(x.journalSha256)) return null;
  const entries = denseArray(x.entries,pageSize);
  if (!entries) return null;
  const events = entries.map(validEvent);
  if (events.some((event) => !event)) return null;
  const incident = exact(x.incident,INCIDENT_KEYS);
  if (!incident || !Number.isSafeInteger(incident.failureCount) ||
      incident.failureCount < 0 ||
      incident.failureCount > x.journalEntries ||
      incident.manualInterventionRequired !== x.manualInterventionRequired ||
      (incident.firstFailure === null) !== (incident.failureCount === 0) ||
      (incident.latestFailure === null) !== (incident.failureCount === 0)) return null;
  const firstFailure = incident.firstFailure === null ?
    null : validEvent(incident.firstFailure);
  const latestFailure = incident.latestFailure === null ?
    null : validEvent(incident.latestFailure);
  if (incident.failureCount !== 0 &&
      (!firstFailure || firstFailure.state !== 'FAILED' ||
       !latestFailure || latestFailure.state !== 'FAILED')) return null;
  const lastTerminal = validEvent(x.lastTerminal);
  if (!lastTerminal) return null;
  const cursor = x.nextCursor === null ?
    null : exact(x.nextCursor,['journalSha256','before']);
  if (x.nextCursor !== null &&
      (!cursor || cursor.journalSha256 !== x.journalSha256 ||
       !Number.isSafeInteger(cursor.before) ||
       cursor.before < 1 || cursor.before > x.journalEntries)) return null;
  return Object.freeze({
    reason:x.reason,
    processState:x.processState,
    journalEntries:x.journalEntries,
    journalSha256:x.journalSha256,
    manualInterventionRequired:x.manualInterventionRequired,
    failureCount:incident.failureCount,
    firstFailure,latestFailure,lastTerminal,cursor,
    events:Object.freeze(events),
  });
}
function unavailable(reason) {
  return Object.freeze({
    schemaVersion:1,kind:'GUARDIAN_LOCAL_EVENT_LEDGER_AUDIT_V1',
    authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status:'SOURCE_ONLY_HOLD',
    comparison:'NOT_VERIFIED',reason,
    journalSha256:null,orderedEventsSha256:null,
    processState:'UNVERIFIED',
    inspectedEntries:0,inspectedPages:0,
    failureCount:0,failureCodes:Object.freeze([]),
    firstFailure:null,latestFailure:null,lastTerminal:null,
    liveness:'NOT_PROVEN',manualInterventionRequired:true,
    automaticRestartAllowed:false,activationAllowed:false,
    releaseAuthority:'NOT_ISSUED',
  });
}
function captureComplete(operator, pageSize, maxCaptureMs) {
  const began=performance.now();
  const maxPages=Math.ceil(4096/pageSize);
  const hash=crypto.createHash('sha256');
  let baseline=null,cursor=null,seen=new Set();
  let pages=0,read=0,failures=0;
  let newestFailure=null,oldestFailure=null;
  const codes=new Map();
  try {
    for (;;) {
      if (pages>=maxPages || performance.now()-began>maxCaptureMs) {
        return unavailable('GUARDIAN_LEDGER_BOUNDS_EXCEEDED');
      }
      // A fresh, read-only protected journal read on every page; the
      // underlying diagnostic provider rejects stale cursor digests.
      const result=operator.recentEvents({limit:pageSize,cursor});
      const page=validPage(result,pageSize);
      if (!page) return unavailable('GUARDIAN_LEDGER_PAGE_UNVERIFIED');
      if (!baseline) {
        baseline=page;
      } else if (page.journalEntries!==baseline.journalEntries ||
          page.journalSha256!==baseline.journalSha256 ||
          page.processState!==baseline.processState ||
          page.reason!==baseline.reason ||
          page.manualInterventionRequired!==baseline.manualInterventionRequired ||
          page.failureCount!==baseline.failureCount ||
          !sameEvent(page.firstFailure,baseline.firstFailure) &&
            !(page.firstFailure===null && baseline.firstFailure===null) ||
          !sameEvent(page.latestFailure,baseline.latestFailure) &&
            !(page.latestFailure===null && baseline.latestFailure===null) ||
          !sameEvent(page.lastTerminal,baseline.lastTerminal)) {
        return unavailable('GUARDIAN_LEDGER_SNAPSHOT_CHANGED');
      }
      const remaining=baseline.journalEntries-read;
      const expectedRows=Math.min(pageSize,remaining);
      if (page.events.length!==expectedRows) {
        return unavailable('GUARDIAN_LEDGER_PAGE_INCOMPLETE');
      }
      if (pages===0 && !sameEvent(page.events[0],page.lastTerminal)) {
        return unavailable('GUARDIAN_LEDGER_TERMINAL_MISMATCH');
      }
      for (const event of page.events) {
        if (seen.has(event.eventId)) {
          return unavailable('GUARDIAN_LEDGER_DUPLICATE_EVENT');
        }
        seen.add(event.eventId);
        hash.update(JSON.stringify(event)+'\n','utf8');
        if (event.state==='FAILED') {
          failures++;
          if (!newestFailure) newestFailure=event;
          oldestFailure=event;
          const code=event.errorCode===null ? 'UNSPECIFIED' : event.errorCode;
          codes.set(code,(codes.get(code)||0)+1);
        }
      }
      read+=page.events.length;
      pages++;
      const expectedBefore=baseline.journalEntries-read;
      if (expectedBefore===0) {
        if (page.cursor!==null) {
          return unavailable('GUARDIAN_LEDGER_CURSOR_INCONSISTENT');
        }
        break;
      }
      if (!page.cursor || page.cursor.before!==expectedBefore ||
          page.cursor.journalSha256!==baseline.journalSha256) {
        return unavailable('GUARDIAN_LEDGER_CURSOR_INCONSISTENT');
      }
      cursor=Object.freeze({
        journalSha256:page.cursor.journalSha256,before:page.cursor.before,
      });
    }
    if (performance.now()-began>maxCaptureMs ||
        failures!==baseline.failureCount ||
        (failures===0 && (baseline.firstFailure!==null ||
          baseline.latestFailure!==null)) ||
        (failures>0 && (!sameEvent(oldestFailure,baseline.firstFailure) ||
          !sameEvent(newestFailure,baseline.latestFailure))) ||
        (failures>0 && baseline.manualInterventionRequired!==true)) {
      return unavailable('GUARDIAN_LEDGER_AGGREGATE_MISMATCH');
    }
    return Object.freeze({
      schemaVersion:1,kind:'GUARDIAN_LOCAL_EVENT_LEDGER_AUDIT_V1',
      authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
      status:'SOURCE_ONLY_HOLD',comparison:'MATCH_LOCAL_PAGES_ONLY',
      reason:'GUARDIAN_LEDGER_COMPLETE_LOCAL',
      journalSha256:baseline.journalSha256,
      orderedEventsSha256:hash.digest('hex'),
      processState:baseline.processState,
      inspectedEntries:read,inspectedPages:pages,
      failureCount:failures,
      failureCodes:Object.freeze([...codes.entries()]
        .sort(([a],[b])=>a.localeCompare(b))
        .map(([code,count])=>Object.freeze({code,count}))),
      firstFailure:oldestFailure,latestFailure:newestFailure,
      lastTerminal:baseline.lastTerminal,
      liveness:'NOT_PROVEN',manualInterventionRequired:true,
      automaticRestartAllowed:false,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED',
    });
  } catch (_) {
    return unavailable('GUARDIAN_LEDGER_READ_FAILED');
  }
}
function createGuardianLocalLedgerAudit(options) {
  const config=exact(options,['operator','pageSize','maxCaptureMs']);
  if (!config || !config.operator ||
      typeof config.operator!=='object' ||
      typeof config.operator.recentEvents!=='function' ||
      !Number.isSafeInteger(config.pageSize) ||
      config.pageSize<1 || config.pageSize>50 ||
      !Number.isSafeInteger(config.maxCaptureMs) ||
      config.maxCaptureMs<100 || config.maxCaptureMs>30_000) {
    throw new Error('GUARDIAN_LEDGER_CONFIG_INVALID');
  }
  return Object.freeze({
    capture:()=>captureComplete(config.operator,config.pageSize,
      config.maxCaptureMs),
  });
}
module.exports=Object.freeze({createGuardianLocalLedgerAudit});
