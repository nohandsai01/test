/**
 * Operator-only terminal callback / journal persistence diagnosis.
 *
 * No fs access, writes, IPC, active probes, process control, credential reads,
 * or Check publication. Reports a failed Controller terminal callback without
 * pretending that any older journal receipt belongs to this generation.
 * All observations remain local/untrusted and strictly HOLD.
 */
'use strict';

const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING',
  'STOPPED', 'FAILED']);
const ERROR = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const SHA = /^[0-9a-f]{64}$/;
const GENERATION = /^[0-9a-f]{32}$/;
const STATUS_KEYS = Object.freeze(['state', 'errorCode', 'pid',
  'activationAllowed', 'releaseAuthority', 'automaticRestartAllowed']);
const TRIAGE_OPTIONAL_KEYS = Object.freeze([
  'unterminatedGenerations', 'concurrentGenerations']);
const TRIAGE_KEYS = Object.freeze(['schemaVersion', 'kind', 'authority',
  'status', 'priority', 'classification', 'nextAction', 'sourceReason',
  'processState', 'liveness', 'journalEntries', 'journalSha256',
  'failureCount', 'firstFailure', 'latestFailure', 'lastTerminal',
  'manualInterventionRequired', 'automaticRestartAllowed',
  'activationAllowed', 'releaseAuthority']);
const TRIAGE_CLASS = Object.freeze({
  P0: Object.freeze({ EVIDENCE_UNVERIFIED: 'OWNER_INVESTIGATE_LOCAL_EVIDENCE' }),
  P1: Object.freeze({
    RECORDED_FAILURE: 'OWNER_REVIEW_FAULT_HISTORY',
    CONTROLLER_FAILED: 'OWNER_INVESTIGATE_CONTROLLER_FAILURE',
    UNTERMINATED_GENERATION: 'OWNER_RECONCILE_INTERRUPTED_GENERATION',
  }),
  P2: Object.freeze({
    NO_LOCAL_BASELINE: 'OWNER_VERIFY_FIRST_START_PREREQUISITES',
    PROCESS_STATE_UNPROVEN: 'OWNER_RECONCILE_LIFECYCLE',
  }),
  P3: Object.freeze({ LOCAL_STOP_OBSERVED: 'NO_LOCAL_FAULT_OBSERVED' }),
});

function ownData(value, names, optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    const desc = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(desc);
    if (keys.length < names.length ||
        keys.length > names.length + optional.length ||
        keys.some((key) => typeof key !== 'string' ||
          (!names.includes(key) && !optional.includes(key)))) {
      return null;
    }
    const result = Object.create(null);
    for (const key of names) {
      if (!Object.hasOwn(desc, key) || !Object.hasOwn(desc[key], 'value')) {
        return null; // never invoke getters or accessor properties
      }
      result[key] = desc[key].value;
    }
    for (const key of optional) {
      if (Object.hasOwn(desc, key)) {
        if (!Object.hasOwn(desc[key], 'value')) return null;
        result[key] = desc[key].value;
      }
    }
    return result;
  } catch (_) { return null; }
}

function statusSnapshot(controller) {
  try {
    const x = ownData(controller.status(), STATUS_KEYS, ['generationId']);
    if (!x || !STATES.has(x.state) ||
        !(x.pid === null || (Number.isSafeInteger(x.pid) && x.pid > 0)) ||
        !(x.errorCode === null ||
          (typeof x.errorCode === 'string' && ERROR.test(x.errorCode))) ||
        x.activationAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED' ||
        x.automaticRestartAllowed !== false ||
        !(x.generationId === undefined || x.generationId === null ||
          (typeof x.generationId === 'string' &&
           GENERATION.test(x.generationId)))) return null;
    return Object.freeze({
      state: x.state, pid: x.pid, errorCode: x.errorCode,
      generationId: x.generationId ?? null,
    });
  } catch (_) { return null; }
}

function triageSnapshot(diagnostics) {
  try {
    const x = ownData(diagnostics.faultTriage(), TRIAGE_KEYS,
      TRIAGE_OPTIONAL_KEYS);
    if (!x || x.schemaVersion !== 1 ||
        x.kind !== 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1' ||
        x.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        x.status !== 'SOURCE_ONLY_HOLD' ||
        !Object.hasOwn(TRIAGE_CLASS, x.priority) ||
        !Object.hasOwn(TRIAGE_CLASS[x.priority], x.classification) ||
        x.nextAction !== TRIAGE_CLASS[x.priority][x.classification] ||
        !STATES.has(x.processState) ||
        typeof x.sourceReason !== 'string' || !ERROR.test(x.sourceReason) ||
        x.liveness !== 'NOT_PROVEN' ||
        !Number.isSafeInteger(x.journalEntries) || x.journalEntries < 0 ||
        !Number.isSafeInteger(x.failureCount) || x.failureCount < 0 ||
        x.failureCount > x.journalEntries ||
        !(x.journalSha256 === null ||
          (typeof x.journalSha256 === 'string' && SHA.test(x.journalSha256))) ||
        (x.journalEntries === 0) !== (x.journalSha256 === null) ||
        x.manualInterventionRequired !== (x.priority !== 'P3') ||
        x.activationAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED' ||
        x.automaticRestartAllowed !== false ||
        (x.unterminatedGenerations !== undefined &&
          (!Number.isSafeInteger(x.unterminatedGenerations) ||
           x.unterminatedGenerations < 0)) ||
        (x.concurrentGenerations !== undefined &&
          (!Number.isSafeInteger(x.concurrentGenerations) ||
           x.concurrentGenerations < 0))) return null;
    return Object.freeze({
      unterminatedGenerations: x.unterminatedGenerations ?? null,
      concurrentGenerations: x.concurrentGenerations ?? null,
      priority: x.priority, sourceReason: x.sourceReason,
      processState: x.processState, journalEntries: x.journalEntries,
      journalSha256: x.journalSha256, failureCount: x.failureCount,
      classification: x.classification,
    });
  } catch (_) { return null; }
}

function sameStatus(a, b) {
  return a && b && a.state === b.state && a.pid === b.pid &&
    a.errorCode === b.errorCode &&
    a.generationId === b.generationId;
}
function sameTriage(a, b) {
  return a && b && Object.keys(a).every((key) => a[key] === b[key]);
}
function report(priority, classification, nextAction, state = null,
  triage = null, errorCode = null) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_TERMINAL_PERSISTENCE_DIAGNOSIS_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    priority, classification, nextAction,
    processState: state ?? 'UNVERIFIED',
    controllerErrorCode: errorCode,
    journalReason: triage?.sourceReason ?? null,
    journalEntries: triage?.journalEntries ?? 0,
    journalSha256: triage?.journalSha256 ?? null,
    historicalFailureCount: triage?.failureCount ?? 0,
    terminalPersistence: 'NOT_PROVEN',
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function unverified() {
  return report('P0', 'OBSERVATIONS_INCONSISTENT',
    'OWNER_INVESTIGATE_LOCAL_EVIDENCE');
}

function createGuardianLocalTerminalPersistence(options = {}) {
  // Reject null, unknown options and accessor-supplied capabilities without
  // invoking an external getter during construction.
  const config = ownData(options, ['controller', 'diagnostics']);
  let controller, diagnostics;
  try {
    if (!config) throw new Error('untrusted configuration');
    controller = config.controller;
    diagnostics = config.diagnostics;
    if (!controller || !diagnostics ||
        typeof Object.getOwnPropertyDescriptor(controller, 'status')?.value !==
          'function' ||
        typeof Object.getOwnPropertyDescriptor(diagnostics, 'faultTriage')?.value !==
          'function') throw new Error('untrusted capability');
  } catch (_) {
    throw new Error('GUARDIAN_TERMINAL_PERSISTENCE_CONFIG_INVALID');
  }
  function diagnose() {
    // Bracket two protected journal snapshots with three Controller reads.
    // A concurrent append, PID/error transition or evidence degradation
    // cannot silently create an actionable "normal terminal" verdict.
    const before = statusSnapshot(controller);
    if (!before) return unverified();
    const first = triageSnapshot(diagnostics);
    const middle = statusSnapshot(controller);
    if (!first || !sameStatus(before, middle) ||
        first.processState !== before.state) return unverified();
    const second = triageSnapshot(diagnostics);
    const after = statusSnapshot(controller);
    if (!second || !sameStatus(before, after) ||
        !sameTriage(first, second) ||
        second.processState !== before.state) return unverified();
    if (before.state === 'FAILED' &&
        before.errorCode === 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED') {
      // Cannot distinguish a journal write failure from an invalid or
      // throwing Owner terminal callback. Do not claim a specific root cause.
      // Earlier receipts (even STOPPED ones) cannot clear this failure.
      return report('P0', 'TERMINAL_CALLBACK_FAILURE_OBSERVED',
        'OWNER_INVESTIGATE_TERMINAL_RECEIPT_PATH',
        before.state, second, before.errorCode);
    }
    return report(second.priority, 'CALLBACK_FAILURE_NOT_OBSERVED',
      'OWNER_RECONCILE_TERMINAL_RECEIPTS',
      before.state, second, before.errorCode);
  }
  return Object.freeze({ diagnose });
}
module.exports = { createGuardianLocalTerminalPersistence };
