/**
 * G25: read-only operator runtime assessment joining local fault triage with
 * one transient child health observation.
 *
 * This is a best-effort local observation, NOT a liveness assertion or trusted
 * attestation. Reads never launch/probe/stop children, mutate a journal, issue
 * Checks, clear HOLD or allow recovery. A failed/mismatched snapshot is P0.
 */
'use strict';

const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING',
  'STOPPED', 'FAILED']);
const ERROR = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const SHA = /^[0-9a-f]{64}$/;
const GENERATION = /^[0-9a-f]{32}$/;
const CLASSIFICATIONS = Object.freeze({
  P0: Object.freeze({
    EVIDENCE_UNVERIFIED: 'OWNER_INVESTIGATE_LOCAL_EVIDENCE',
  }),
  P1: Object.freeze({
    RECORDED_FAILURE: 'OWNER_REVIEW_FAULT_HISTORY',
    UNTERMINATED_GENERATION: 'OWNER_RECONCILE_INTERRUPTED_GENERATION',
    CONTROLLER_FAILED: 'OWNER_INVESTIGATE_CONTROLLER_FAILURE',
  }),
  P2: Object.freeze({
    NO_LOCAL_BASELINE: 'OWNER_VERIFY_FIRST_START_PREREQUISITES',
    PROCESS_STATE_UNPROVEN: 'OWNER_RECONCILE_LIFECYCLE',
  }),
  P3: Object.freeze({
    LOCAL_STOP_OBSERVED: 'NO_LOCAL_FAULT_OBSERVED',
  }),
});

function record(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}
function safeState(controller) {
  try {
    const x = controller.status();
    if (!record(x)) return null;
    // Consume primitive values once; never copy caller-supplied arbitrary
    // properties or return a raw ChildProcess/controller object.
    const { state, pid, errorCode, activationAllowed, releaseAuthority,
      automaticRestartAllowed } = x;
    // A reused PID must never make two process generations look alike.
    const generationId = x.generationId ?? null;
    if (!STATES.has(state) ||
        !(generationId === null ||
          (typeof generationId === 'string' && GENERATION.test(generationId))) ||
        !(pid === null || (Number.isSafeInteger(pid) && pid > 0)) ||
        !(errorCode === null ||
          (typeof errorCode === 'string' && ERROR.test(errorCode))) ||
        activationAllowed !== false ||
        releaseAuthority !== 'NOT_ISSUED' ||
        automaticRestartAllowed !== false) return null;
    return Object.freeze({ state, pid, errorCode, generationId });
  } catch (_) {
    return null;
  }
}
function sameState(a, b) {
  return a && b && a.state === b.state && a.pid === b.pid &&
    a.errorCode === b.errorCode && a.generationId === b.generationId;
}
function safeTriage(x) {
  try {
    if (!record(x) || x.schemaVersion !== 1 ||
        x.kind !== 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1' ||
        x.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        x.status !== 'SOURCE_ONLY_HOLD' ||
        !Object.hasOwn(CLASSIFICATIONS, x.priority) ||
        !Object.hasOwn(CLASSIFICATIONS[x.priority], x.classification) ||
        x.nextAction !== CLASSIFICATIONS[x.priority][x.classification] ||
        !STATES.has(x.processState) ||
        typeof x.sourceReason !== 'string' || !ERROR.test(x.sourceReason) ||
        x.liveness !== 'NOT_PROVEN' ||
        !Number.isSafeInteger(x.journalEntries) || x.journalEntries < 0 ||
        !Number.isSafeInteger(x.failureCount) || x.failureCount < 0 ||
        x.failureCount > x.journalEntries ||
        !Number.isSafeInteger(x.unterminatedGenerations) ||
        x.unterminatedGenerations < 0 ||
        (x.classification === 'UNTERMINATED_GENERATION') !==
          (x.failureCount === 0 && x.unterminatedGenerations > 0) ||
        (x.priority === 'P3' && x.unterminatedGenerations !== 0) ||
        !(x.journalSha256 === null ||
          (typeof x.journalSha256 === 'string' && SHA.test(x.journalSha256))) ||
        x.manualInterventionRequired !== (x.priority !== 'P3') ||
        x.activationAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED' ||
        x.automaticRestartAllowed !== false ||
        (x.priority === 'P3' && (x.processState !== 'STOPPED' ||
          x.failureCount !== 0)) ||
        (x.classification === 'RECORDED_FAILURE' && x.failureCount === 0)) {
      return null;
    }
    return Object.freeze({
      priority: x.priority, classification: x.classification,
      nextAction: x.nextAction, sourceReason: x.sourceReason,
      processState: x.processState,
      journalEntries: x.journalEntries, journalSha256: x.journalSha256,
      failureCount: x.failureCount,
      unterminatedGenerations: x.unterminatedGenerations,
    });
  } catch (_) {
    return null;
  }
}
// A second independent journal read must describe the SAME protected
// receipt history and classification as the first. Neither PID nor a
// previously recent probe can establish continuous process liveness.
function sameTriage(a, b) {
  return !!a && !!b &&
    a.priority === b.priority &&
    a.classification === b.classification &&
    a.nextAction === b.nextAction &&
    a.sourceReason === b.sourceReason &&
    a.processState === b.processState &&
    a.journalEntries === b.journalEntries &&
    a.journalSha256 === b.journalSha256 &&
    a.failureCount === b.failureCount &&
    a.unterminatedGenerations === b.unterminatedGenerations;
}
function safeHealth(x) {
  try {
    if (!record(x) || x.schemaVersion !== 1 ||
        x.status !== 'SOURCE_ONLY_HOLD' ||
        !['RECENT', 'EXPIRED', 'UNVERIFIED'].includes(x.freshness) ||
        !(STATES.has(x.processState) ||
          x.processState === 'UNVERIFIED') ||
        typeof x.reason !== 'string' || !ERROR.test(x.reason) ||
        x.liveness !== 'NOT_PROVEN' ||
        x.manualInterventionRequired !== true ||
        x.activationAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED' ||
        x.automaticRestartAllowed !== false ||
        !Number.isSafeInteger(x.maxAgeMs) || x.maxAgeMs < 50 ||
        x.maxAgeMs > 30_000 ||
        !(x.ageMs === null ||
          (Number.isSafeInteger(x.ageMs) && x.ageMs >= 0)) ||
        !(x.sampledAt === null ||
          (typeof x.sampledAt === 'string' &&
           /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x.sampledAt) &&
           Number.isFinite(Date.parse(x.sampledAt)))) ||
        (x.freshness === 'RECENT' &&
          (x.observation !== 'LOCAL_CHILD_HEALTH_OBSERVED_RECENTLY' ||
           x.processState !== 'RUNNING' ||
           x.reason !== 'GUARDIAN_HEALTH_RECENT_SAMPLE_ONLY' ||
           x.ageMs === null || x.ageMs > x.maxAgeMs ||
           x.sampledAt === null)) ||
        (x.freshness === 'EXPIRED' &&
          (x.observation !== 'NOT_PROVEN' ||
           x.reason !== 'GUARDIAN_HEALTH_SAMPLE_EXPIRED' ||
           x.ageMs === null || x.ageMs <= x.maxAgeMs)) ||
        (x.freshness === 'UNVERIFIED' &&
          (x.observation !== 'NOT_PROVEN' || x.sampledAt !== null))) {
      return null;
    }
    return Object.freeze({
      freshness: x.freshness, reason: x.reason,
      processState: x.processState,
      ageMs: x.ageMs, maxAgeMs: x.maxAgeMs,
    });
  } catch (_) {
    return null;
  }
}
function envelope({ priority, classification, nextAction, processState,
  triage = null, health = null }) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_RUNTIME_ASSESSMENT_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    priority, classification, nextAction,
    processState,
    triageReason: triage?.sourceReason ?? null,
    healthFreshness: health?.freshness ?? 'UNVERIFIED',
    healthReason: health?.reason ?? null,
    healthSampleAgeMs: health?.ageMs ?? null,
    healthMaxAgeMs: health?.maxAgeMs ?? null,
    journalSha256: triage?.journalSha256 ?? null,
    journalEntries: triage?.journalEntries ?? 0,
    historicalFailureCount: triage?.failureCount ?? 0,
    unterminatedGenerations: triage?.unterminatedGenerations ?? 0,
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: priority !== 'P3',
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function denied(reason) {
  return envelope({
    priority: 'P0', classification: 'LOCAL_OBSERVATION_UNVERIFIED',
    nextAction: reason,
    processState: 'UNVERIFIED',
  });
}
function createGuardianLocalRuntimeAssessment({ controller, diagnostics,
  healthObservation } = {}) {
  if (!controller || typeof controller.status !== 'function' ||
      !diagnostics || typeof diagnostics.faultTriage !== 'function' ||
      !healthObservation || typeof healthObservation.observe !== 'function') {
    throw new Error('GUARDIAN_RUNTIME_ASSESSMENT_CONFIG_INVALID');
  }

  function assess() {
    // G26: bracket the health sample between two independent protected
    // journal reads, and bind both journal observations to the same
    // controller state/PID/errorCode at three read boundaries.
    // Not an atomic OS transaction: any observable inconsistency becomes
    // P0 while all results preserve SOURCE_ONLY_HOLD.
    const before = safeState(controller);
    if (!before) return denied('OWNER_VERIFY_CONTROLLER_STATUS');
    const startedAt = process.hrtime.bigint();
    let first, triage, health, middle, after;
    try {
      first = safeTriage(diagnostics.faultTriage());
      middle = safeState(controller);
      if (!first || !sameState(before, middle) ||
          first.processState !== before.state) {
        return denied('OWNER_INVESTIGATE_LOCAL_OBSERVATIONS');
      }
      health = safeHealth(healthObservation.observe());
      triage = safeTriage(diagnostics.faultTriage());
      after = safeState(controller);
    } catch (_) {
      return denied('OWNER_INVESTIGATE_LOCAL_OBSERVATIONS');
    }
    if (!sameState(before, middle) || !sameState(before, after) ||
        !sameTriage(first, triage) || !health ||
        triage.processState !== before.state ||
        health.processState !== before.state ||
        (before.state !== 'RUNNING' && health.freshness !== 'UNVERIFIED')) {
      return denied('OWNER_INVESTIGATE_LOCAL_OBSERVATIONS');
    }
    // Reading a second journal must not silently extend an earlier
    // RECENT sample past its max-age window.
    if (health.freshness === 'RECENT') {
      const elapsedMs = Number((process.hrtime.bigint() - startedAt) /
        1_000_000n);
      if (!Number.isSafeInteger(elapsedMs) || elapsedMs < 0 ||
          elapsedMs + health.ageMs > health.maxAgeMs) {
        return denied('OWNER_INVESTIGATE_LOCAL_OBSERVATIONS');
      }
    }
    let { priority, classification, nextAction } = triage;
    // P0/P1 are journal/controller investigation priorities. A recent
    // healthy round trip NEVER downgrades them; an old sample cannot issue
    // a health clearance or override an observed failure.
    if (priority === 'P2' && before.state === 'RUNNING' &&
        classification === 'PROCESS_STATE_UNPROVEN') {
      if (health.freshness === 'RECENT') {
        classification = 'RECENT_LOCAL_PROBE_ONLY';
        nextAction = 'OWNER_RECONCILE_RUNTIME_HEALTH';
      } else if (health.freshness === 'EXPIRED') {
        classification = 'LOCAL_PROBE_EXPIRED';
        nextAction = 'OWNER_REQUEST_FRESH_HEALTH_PROBE';
      } else {
        classification = 'NO_VERIFIED_HEALTH_SAMPLE';
        nextAction = 'OWNER_REQUEST_FRESH_HEALTH_PROBE';
      }
    }
    return envelope({
      priority, classification, nextAction, processState: before.state,
      triage, health,
    });
  }
  return Object.freeze({ assess });
}

module.exports = { createGuardianLocalRuntimeAssessment };
