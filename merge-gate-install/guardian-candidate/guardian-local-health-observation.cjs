/**
 * G24: transient observation of child health-probe freshness.
 *
 * No I/O at import or construction. Only explicit probe() uses the existing
 * bounded child IPC/loopback probe. observe() is passive, never spawns,
 * signals, reads secrets or publishes Checks. A recent response is evidence
 * of a *past* local round trip, NEVER ongoing liveness or release authority.
 */
'use strict';

const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING',
  'STOPPED', 'FAILED']);
const RECEIPT_FIELDS = new Set(['schemaVersion', 'status', 'observation',
  'reason', 'processState', 'liveness', 'manualInterventionRequired',
  'activationAllowed', 'releaseAuthority', 'automaticRestartAllowed']);

function record(value) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value);
}
function statusSnapshot(value) {
  if (!record(value) || !STATES.has(value.state) ||
      !(value.pid === null ||
        (Number.isSafeInteger(value.pid) && value.pid > 0)) ||
      !(value.errorCode === null ||
        (typeof value.errorCode === 'string' &&
         /^GUARDIAN_[A-Z0-9_]{1,100}$/.test(value.errorCode))) ||
      value.activationAllowed !== false ||
      value.releaseAuthority !== 'NOT_ISSUED' ||
      value.automaticRestartAllowed !== false) return null;
  return Object.freeze({ state: value.state, pid: value.pid,
    errorCode: value.errorCode });
}
function isProbeReceipt(value) {
  return record(value) &&
    Object.keys(value).length === RECEIPT_FIELDS.size &&
    Object.keys(value).every((key) => RECEIPT_FIELDS.has(key)) &&
    value.schemaVersion === 1 && value.status === 'SOURCE_ONLY_HOLD' &&
    STATES.has(value.processState) &&
    typeof value.reason === 'string' &&
    /^GUARDIAN_[A-Z0-9_]{1,100}$/.test(value.reason) &&
    ['LOCAL_CHILD_HEALTH_VERIFIED', 'NOT_PROVEN'].includes(value.observation) &&
    value.liveness === (value.observation === 'LOCAL_CHILD_HEALTH_VERIFIED' ?
      'LOCAL_IPC_AND_LOOPBACK_ONLY' : 'NOT_PROVEN') &&
    value.manualInterventionRequired === true &&
    value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED' &&
    value.automaticRestartAllowed === false;
}
function safeSnapshot(controller) {
  try { return statusSnapshot(controller.status()); }
  catch (_) { return null; }
}
function probeDenied(reason, state) {
  return Object.freeze({
    schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
    observation: 'NOT_PROVEN', reason,
    processState: state?.state ?? 'FAILED',
    liveness: 'NOT_PROVEN', manualInterventionRequired: true,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  });
}
function observation(reason, state, freshness, sample, age, maxAgeMs) {
  return Object.freeze({
    schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
    observation: freshness === 'RECENT' ?
      'LOCAL_CHILD_HEALTH_OBSERVED_RECENTLY' : 'NOT_PROVEN',
    freshness, reason, processState: state?.state ?? 'UNVERIFIED',
    // Never translate an old probe into a live/current process assertion.
    liveness: 'NOT_PROVEN',
    sampledAt: sample?.time ?? null,
    ageMs: age, maxAgeMs,
    manualInterventionRequired: true, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
  });
}
function sameChild(a, b) {
  return !!a && !!b && a.state === 'RUNNING' && b.state === 'RUNNING' &&
    a.errorCode === null && b.errorCode === null &&
    Number.isSafeInteger(a.pid) && a.pid > 0 && a.pid === b.pid;
}

function createGuardianLocalHealthObservation({ controller,
  maxAgeMs = 1000 } = {}) {
  if (!controller || typeof controller.status !== 'function' ||
      typeof controller.probeRuntime !== 'function' ||
      !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 50 ||
      maxAgeMs > 30_000) {
    throw new Error('GUARDIAN_HEALTH_OBSERVATION_CONFIG_INVALID');
  }
  let sample = null;
  let inFlight = null;
  function observe() {
    const current = safeSnapshot(controller);
    if (!current) {
      sample = null;
      return observation('GUARDIAN_HEALTH_CONTROLLER_UNVERIFIED',
        null, 'UNVERIFIED', null, null, maxAgeMs);
    }
    if (current.state !== 'RUNNING') {
      sample = null;
      return observation('GUARDIAN_HEALTH_CHILD_NOT_RUNNING',
        current, 'UNVERIFIED', null, null, maxAgeMs);
    }
    if (!sample) {
      return observation('GUARDIAN_HEALTH_NO_VALID_SAMPLE',
        current, 'UNVERIFIED', null, null, maxAgeMs);
    }
    if (!sameChild(sample.status, current)) {
      sample = null;
      return observation('GUARDIAN_HEALTH_CHILD_STATE_CHANGED',
        current, 'UNVERIFIED', null, null, maxAgeMs);
    }
    const elapsed = process.hrtime.bigint() - sample.monotonic;
    if (elapsed < 0n) {
      sample = null;
      return observation('GUARDIAN_HEALTH_CLOCK_UNVERIFIED',
        current, 'UNVERIFIED', null, null, maxAgeMs);
    }
    const milliseconds = Number(elapsed / 1_000_000n);
    const age = Number.isSafeInteger(milliseconds) ?
      milliseconds : null;
    if (age === null || age > maxAgeMs) {
      sample = null;
      return observation('GUARDIAN_HEALTH_SAMPLE_EXPIRED',
        current, 'EXPIRED', null, age, maxAgeMs);
    }
    return observation('GUARDIAN_HEALTH_RECENT_SAMPLE_ONLY',
      current, 'RECENT', sample, age, maxAgeMs);
  }
  function probe() {
    if (inFlight) return inFlight;
    const before = safeSnapshot(controller);
    // Never delegate to the active IPC probe if the local state facade is
    // unverified; do not turn malformed controller data into success.
    if (!before) {
      sample = null;
      return Promise.resolve(probeDenied(
        'GUARDIAN_HEALTH_CONTROLLER_UNVERIFIED', null));
    }
    sample = null; // A new probe cannot inherit an earlier green sample.
    const promise = (async () => {
      let result;
      try { result = await controller.probeRuntime(); }
      catch (_) {
        return probeDenied('GUARDIAN_HEALTH_PROBE_EXCEPTION',
          safeSnapshot(controller));
      }
      const after = safeSnapshot(controller);
      let verifiedShape = false;
      try { verifiedShape = isProbeReceipt(result); } catch (_) {}
      if (!verifiedShape || !after) {
        return probeDenied('GUARDIAN_HEALTH_PROBE_UNVERIFIED', after);
      }
      if (result.observation === 'LOCAL_CHILD_HEALTH_VERIFIED') {
        if (!sameChild(before, after) ||
            result.processState !== 'RUNNING' ||
            result.reason !== 'GUARDIAN_CHILD_HEALTH_VERIFIED') {
          return probeDenied('GUARDIAN_HEALTH_CHILD_STATE_CHANGED', after);
        }
        sample = Object.freeze({
          status: after, time: new Date().toISOString(),
          monotonic: process.hrtime.bigint(),
        });
      }
      // The controller result itself always retains its SOURCE_ONLY_HOLD
      // contract. This facade only observes and never relaxes that result.
      return result;
    })();
    inFlight = promise;
    // Do not create a floating rejected Promise from finally().
    void promise.then(
      () => { if (inFlight === promise) inFlight = null; },
      () => { if (inFlight === promise) inFlight = null; });
    return promise;
  }
  return Object.freeze({ probe, observe });
}

module.exports = { createGuardianLocalHealthObservation };
