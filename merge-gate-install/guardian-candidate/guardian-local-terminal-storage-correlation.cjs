/**
 * Operator-only correlation of terminal callback failure and local journal
 * storage pressure. Independent, bounded double snapshots; no I/O here.
 *
 * A storage warning coincident with a callback failure is NOT proof of
 * causation. No result grants restart, release, custody or Check authority.
 */
'use strict';

const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING',
  'STOPPED', 'FAILED']);
const CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const SHA = /^[0-9a-f]{64}$/;
const GENERATION = /^[0-9a-f]{32}$/;
const LEVEL = { P0: 0, P1: 1, P2: 2, P3: 3 };
const STATUS = ['state', 'pid', 'errorCode', 'activationAllowed',
  'releaseAuthority', 'automaticRestartAllowed'];
const TERMINAL = ['schemaVersion', 'kind', 'authority', 'status', 'priority',
  'classification', 'nextAction', 'processState', 'controllerErrorCode',
  'journalReason', 'journalEntries', 'journalSha256',
  'historicalFailureCount', 'terminalPersistence', 'liveness',
  'manualInterventionRequired', 'automaticRestartAllowed',
  'activationAllowed', 'releaseAuthority'];
const STORAGE = ['schemaVersion', 'kind', 'authority', 'status', 'priority',
  'classification', 'nextAction', 'processState', 'journalBudgetPriority',
  'filesystemAvailableMiBCappedAt64', 'filesystemFreeSpace',
  'filesystemReservation', 'appendReadiness', 'liveness',
  'manualInterventionRequired', 'automaticRestartAllowed',
  'activationAllowed', 'releaseAuthority'];
const STORAGE_CLASS = Object.freeze({
  STORAGE_PRESSURE_UNVERIFIED: ['P0', 'OWNER_INVESTIGATE_LOCAL_STORAGE'],
  FILESYSTEM_FREE_CAPACITY_CRITICAL: ['P1', 'OWNER_INVESTIGATE_LOCAL_STORAGE'],
  JOURNAL_FILE_LIMIT_AT_RISK: ['P1', 'OWNER_REVIEW_JOURNAL_LIMIT'],
  FILESYSTEM_FREE_CAPACITY_LOW: ['P2', 'OWNER_PLAN_LOCAL_STORAGE'],
  JOURNAL_BUDGET_NEEDS_ATTENTION: ['P2', 'OWNER_REVIEW_JOURNAL_LIMIT'],
  LOCAL_STORAGE_HEADROOM_SNAPSHOT_ONLY: ['P3', 'OWNER_CONTINUE_MANUAL_HOLD'],
});
const TERMINAL_CLASS = Object.freeze({
  OBSERVATIONS_INCONSISTENT: 'OWNER_INVESTIGATE_LOCAL_EVIDENCE',
  TERMINAL_CALLBACK_FAILURE_OBSERVED: 'OWNER_INVESTIGATE_TERMINAL_RECEIPT_PATH',
  CALLBACK_FAILURE_NOT_OBSERVED: 'OWNER_RECONCILE_TERMINAL_RECEIPTS',
});

// Strict own-data snapshots reject accessors, symbols, unexpected keys and
// malformed Proxy descriptors. Never copy arbitrary or nested input to output.
function data(value, required, optional = []) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length < required.length ||
        keys.length > required.length + optional.length ||
        keys.some((k) => typeof k !== 'string' ||
          (!required.includes(k) && !optional.includes(k)))) return null;
    const result = Object.create(null);
    for (const key of required) {
      if (!Object.hasOwn(descriptors, key) ||
          !Object.hasOwn(descriptors[key], 'value')) return null;
      result[key] = descriptors[key].value;
    }
    for (const key of optional) {
      if (Object.hasOwn(descriptors, key)) {
        if (!Object.hasOwn(descriptors[key], 'value')) return null;
        result[key] = descriptors[key].value;
      }
    }
    return result;
  } catch (_) { return null; }
}
function statusOf(controller) {
  try {
    const s = data(controller.status(), STATUS, ['generationId']);
    if (!s || !STATES.has(s.state) ||
        !(s.pid === null || (Number.isSafeInteger(s.pid) && s.pid > 0)) ||
        !(s.errorCode === null ||
          (typeof s.errorCode === 'string' && CODE.test(s.errorCode))) ||
        !(s.generationId == null ||
          (typeof s.generationId === 'string' &&
            GENERATION.test(s.generationId))) ||
        s.activationAllowed !== false || s.automaticRestartAllowed !== false ||
        s.releaseAuthority !== 'NOT_ISSUED') return null;
    return Object.freeze({
      state: s.state, pid: s.pid, errorCode: s.errorCode,
      generationId: s.generationId ?? null,
    });
  } catch (_) { return null; }
}
function terminalOf(service) {
  try {
    const t = data(service.diagnose(), TERMINAL);
    if (!t || t.schemaVersion !== 1 ||
        t.kind !== 'GUARDIAN_LOCAL_TERMINAL_PERSISTENCE_DIAGNOSIS_V1' ||
        t.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        t.status !== 'SOURCE_ONLY_HOLD' ||
        !Object.hasOwn(LEVEL, t.priority) ||
        !Object.hasOwn(TERMINAL_CLASS, t.classification) ||
        t.nextAction !== TERMINAL_CLASS[t.classification] ||
        !(STATES.has(t.processState) || t.processState === 'UNVERIFIED') ||
        !(t.controllerErrorCode === null ||
          (typeof t.controllerErrorCode === 'string' &&
            CODE.test(t.controllerErrorCode))) ||
        !(t.journalReason === null ||
          (typeof t.journalReason === 'string' && CODE.test(t.journalReason))) ||
        !Number.isSafeInteger(t.journalEntries) || t.journalEntries < 0 ||
        !Number.isSafeInteger(t.historicalFailureCount) ||
        t.historicalFailureCount < 0 ||
        t.historicalFailureCount > t.journalEntries ||
        !(t.journalSha256 === null ||
          (typeof t.journalSha256 === 'string' && SHA.test(t.journalSha256))) ||
        t.terminalPersistence !== 'NOT_PROVEN' ||
        t.liveness !== 'NOT_PROVEN' ||
        t.manualInterventionRequired !== true ||
        t.automaticRestartAllowed !== false ||
        t.activationAllowed !== false ||
        t.releaseAuthority !== 'NOT_ISSUED') return null;
    if (t.classification === 'OBSERVATIONS_INCONSISTENT' &&
        (t.priority !== 'P0' || t.processState !== 'UNVERIFIED' ||
          t.controllerErrorCode !== null)) return null;
    if (t.classification === 'TERMINAL_CALLBACK_FAILURE_OBSERVED' &&
        (t.priority !== 'P0' || t.processState !== 'FAILED' ||
          t.controllerErrorCode !== 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED')) {
      return null;
    }
    if (t.classification === 'CALLBACK_FAILURE_NOT_OBSERVED' &&
        (t.processState === 'UNVERIFIED' ||
          t.controllerErrorCode === 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED' ||
          (t.priority === 'P3' && t.processState !== 'STOPPED'))) return null;
    return Object.freeze(t);
  } catch (_) { return null; }
}
function storageOf(service) {
  try {
    const s = data(service.assess(), STORAGE);
    const expectation = s && STORAGE_CLASS[s.classification];
    if (!s || !expectation || s.schemaVersion !== 1 ||
        s.kind !== 'GUARDIAN_LOCAL_STORAGE_PRESSURE_V1' ||
        s.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        s.status !== 'SOURCE_ONLY_HOLD' ||
        s.priority !== expectation[0] || s.nextAction !== expectation[1] ||
        !(STATES.has(s.processState) || s.processState === 'UNVERIFIED') ||
        s.filesystemReservation !== 'NOT_PROVEN' ||
        s.appendReadiness !== 'NOT_PROVEN' ||
        s.liveness !== 'NOT_PROVEN' ||
        s.manualInterventionRequired !== true ||
        s.automaticRestartAllowed !== false ||
        s.activationAllowed !== false ||
        s.releaseAuthority !== 'NOT_ISSUED') return null;
    if (s.priority === 'P0') {
      if (s.processState !== 'UNVERIFIED' ||
          s.journalBudgetPriority !== 'UNVERIFIED' ||
          s.filesystemFreeSpace !== 'NOT_VERIFIED' ||
          s.filesystemAvailableMiBCappedAt64 !== null) return null;
    } else if (!STATES.has(s.processState) ||
        !['P1', 'P2', 'P3'].includes(s.journalBudgetPriority) ||
        s.filesystemFreeSpace !== 'LOCAL_STATFS_SNAPSHOT_ONLY' ||
        !Number.isSafeInteger(s.filesystemAvailableMiBCappedAt64) ||
        s.filesystemAvailableMiBCappedAt64 < 0 ||
        s.filesystemAvailableMiBCappedAt64 > 64) return null;
    return Object.freeze(s);
  } catch (_) { return null; }
}
function equal(a, b) {
  return !!a && !!b && Object.keys(a).length === Object.keys(b).length &&
    Object.keys(a).every((key) => a[key] === b[key]);
}
function report(priority, classification, action, state = 'UNVERIFIED',
  terminal = null, storage = null) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_TERMINAL_STORAGE_CORRELATION_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    priority, classification, nextAction: action, processState: state,
    terminalPriority: terminal?.priority ?? 'UNVERIFIED',
    storagePriority: storage?.priority ?? 'UNVERIFIED',
    terminalCallbackObserved:
      terminal?.classification === 'TERMINAL_CALLBACK_FAILURE_OBSERVED',
    localStorageRiskObserved:
      !!storage && ['P1', 'P2'].includes(storage.priority),
    causalLinkVerified: false,
    snapshotConsistency: terminal && storage ?
      'STABLE_LOCAL_SAMPLES_ONLY' : 'NOT_VERIFIED',
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function denied() {
  return report('P0', 'CORRELATION_EVIDENCE_UNVERIFIED',
    'OWNER_INVESTIGATE_LOCAL_EVIDENCE');
}
function createGuardianLocalTerminalStorageCorrelation(options) {
  const config = data(options, ['controller', 'terminalPersistence',
    'storagePressure']);
  try {
    if (!config ||
        typeof Object.getOwnPropertyDescriptor(config.controller,
          'status')?.value !== 'function' ||
        typeof Object.getOwnPropertyDescriptor(config.terminalPersistence,
          'diagnose')?.value !== 'function' ||
        typeof Object.getOwnPropertyDescriptor(config.storagePressure,
          'assess')?.value !== 'function') throw new Error('invalid');
  } catch (_) {
    throw new Error('GUARDIAN_LOCAL_TERMINAL_STORAGE_CONFIG_INVALID');
  }
  function assess() {
    const before = statusOf(config.controller);
    if (!before) return denied();
    const firstTerminal = terminalOf(config.terminalPersistence);
    const firstStorage = storageOf(config.storagePressure);
    const middle = statusOf(config.controller);
    if (!firstTerminal || !firstStorage || !equal(before, middle)) return denied();
    const secondStorage = storageOf(config.storagePressure);
    const secondTerminal = terminalOf(config.terminalPersistence);
    const after = statusOf(config.controller);
    if (!secondStorage || !secondTerminal || !equal(before, after) ||
        !equal(firstTerminal, secondTerminal) ||
        !equal(firstStorage, secondStorage) ||
        firstTerminal.processState !== before.state ||
        firstStorage.processState !== before.state) return denied();
    if (firstTerminal.priority === 'P0' || firstStorage.priority === 'P0') {
      if (firstTerminal.classification === 'TERMINAL_CALLBACK_FAILURE_OBSERVED' &&
          firstStorage.priority !== 'P0') {
        return report('P0', firstStorage.priority === 'P3' ?
          'TERMINAL_CALLBACK_FAILURE_ONLY_OBSERVED' :
          'TERMINAL_CALLBACK_WITH_STORAGE_RISK_OBSERVED',
        'OWNER_INVESTIGATE_TERMINAL_RECEIPT_PATH',
        before.state, firstTerminal, firstStorage);
      }
      return report('P0', 'CORRELATION_EVIDENCE_UNVERIFIED',
        'OWNER_INVESTIGATE_LOCAL_EVIDENCE',
        before.state, firstTerminal, firstStorage);
    }
    const priority = LEVEL[firstTerminal.priority] <
      LEVEL[firstStorage.priority] ?
      firstTerminal.priority : firstStorage.priority;
    const classification = priority === 'P1' ?
      'RECORDED_FAULT_OR_STORAGE_PRESSURE' : priority === 'P2' ?
      'LOCAL_MONITORING_REQUIRED' : 'NO_LOCAL_RISK_OBSERVED';
    const nextAction = priority === 'P1' ?
      'OWNER_REVIEW_LOCAL_FAULT_AND_STORAGE' : priority === 'P2' ?
      'OWNER_REVIEW_LOCAL_CAPACITY_AND_LIFECYCLE' :
      'OWNER_CONTINUE_MANUAL_HOLD';
    return report(priority, classification, nextAction, before.state,
      firstTerminal, firstStorage);
  }
  return Object.freeze({ assess });
}
module.exports = { createGuardianLocalTerminalStorageCorrelation };
