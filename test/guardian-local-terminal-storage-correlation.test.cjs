'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalTerminalStorageCorrelation } =
  require('../merge-gate-install/guardian-candidate/guardian-local-terminal-storage-correlation.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

function status(overrides = {}) {
  return {
    state: 'STOPPED', pid: null, errorCode: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false, ...overrides,
  };
}
function terminal(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_TERMINAL_PERSISTENCE_DIAGNOSIS_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD', priority: 'P3',
    classification: 'CALLBACK_FAILURE_NOT_OBSERVED',
    nextAction: 'OWNER_RECONCILE_TERMINAL_RECEIPTS',
    processState: 'STOPPED', controllerErrorCode: null,
    journalReason: 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP',
    journalEntries: 1, journalSha256: 'a'.repeat(64),
    historicalFailureCount: 0, terminalPersistence: 'NOT_PROVEN',
    liveness: 'NOT_PROVEN', manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', ...overrides,
  };
}
function storage(overrides = {}) {
  return {
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_STORAGE_PRESSURE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD', priority: 'P3',
    classification: 'LOCAL_STORAGE_HEADROOM_SNAPSHOT_ONLY',
    nextAction: 'OWNER_CONTINUE_MANUAL_HOLD', processState: 'STOPPED',
    journalBudgetPriority: 'P3', filesystemAvailableMiBCappedAt64: 64,
    filesystemFreeSpace: 'LOCAL_STATFS_SNAPSHOT_ONLY',
    filesystemReservation: 'NOT_PROVEN', appendReadiness: 'NOT_PROVEN',
    liveness: 'NOT_PROVEN', manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', ...overrides,
  };
}
function construct(controller = { status: () => status() },
  persist = { diagnose: () => terminal() },
  capacity = { assess: () => storage() }) {
  return createGuardianLocalTerminalStorageCorrelation({
    controller, terminalPersistence: persist, storagePressure: capacity,
  });
}
function hold(r) {
  assert.equal(r.schemaVersion, 1);
  assert.equal(r.kind, 'GUARDIAN_LOCAL_TERMINAL_STORAGE_CORRELATION_V1');
  assert.equal(r.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(r.status, 'SOURCE_ONLY_HOLD');
  assert.equal(r.causalLinkVerified, false);
  assert.equal(r.liveness, 'NOT_PROVEN');
  assert.equal(r.manualInterventionRequired, true);
  assert.equal(r.automaticRestartAllowed, false);
  assert.equal(r.activationAllowed, false);
  assert.equal(r.releaseAuthority, 'NOT_ISSUED');
  assert.ok(Object.isFrozen(r));
  for (const key of ['pid', 'path', 'directory', 'journalSha256',
    'token', 'secret', 'start', 'stop', 'publishCheck']) {
    assert.equal(Object.hasOwn(r, key), false);
  }
}
function callback() {
  return terminal({
    priority: 'P0', processState: 'FAILED',
    classification: 'TERMINAL_CALLBACK_FAILURE_OBSERVED',
    nextAction: 'OWNER_INVESTIGATE_TERMINAL_RECEIPT_PATH',
    controllerErrorCode: 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED',
  });
}
function failedState() {
  return status({ state: 'FAILED',
    errorCode: 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED' });
}
function criticalStorage() {
  return storage({
    priority: 'P1', classification: 'FILESYSTEM_FREE_CAPACITY_CRITICAL',
    nextAction: 'OWNER_INVESTIGATE_LOCAL_STORAGE',
    filesystemAvailableMiBCappedAt64: 0,
  });
}

test('construction is inert and exposes one frozen read-only method', () => {
  let read = 0;
  const x = construct({ status() { read++; return status(); } },
    { diagnose() { read++; return terminal(); } },
    { assess() { read++; return storage(); } });
  assert.deepEqual(Object.keys(x), ['assess']);
  assert.ok(Object.isFrozen(x));
  assert.equal(read, 0);
  const r = x.assess();
  hold(r);
  assert.equal(read, 7); // 3 Controller, 2 terminal, 2 capacity
  assert.equal(r.priority, 'P3');
  assert.equal(r.classification, 'NO_LOCAL_RISK_OBSERVED');
  assert.equal(r.snapshotConsistency, 'STABLE_LOCAL_SAMPLES_ONLY');
});

test('terminal callback failure remains P0 with abundant disk capacity', () => {
  const r = construct({ status: failedState },
    { diagnose: callback },
    { assess: () => storage({ processState: 'FAILED' }) }).assess();
  hold(r);
  assert.equal(r.priority, 'P0');
  assert.equal(r.classification, 'TERMINAL_CALLBACK_FAILURE_ONLY_OBSERVED');
  assert.equal(r.terminalCallbackObserved, true);
  assert.equal(r.localStorageRiskObserved, false);
});

test('concurrent callback fault and near-full disk is correlation, not cause', () => {
  const disk = criticalStorage();
  const r = construct({ status: failedState },
    { diagnose: callback }, { assess: () => ({
      ...disk, processState: 'FAILED',
    }) }).assess();
  hold(r);
  assert.equal(r.priority, 'P0');
  assert.equal(r.classification,
    'TERMINAL_CALLBACK_WITH_STORAGE_RISK_OBSERVED');
  assert.equal(r.localStorageRiskObserved, true);
  assert.equal(r.terminalCallbackObserved, true);
  assert.equal(r.causalLinkVerified, false);
});

test('local low storage does not suppress a recorded historical fault', () => {
  const r = construct(undefined,
    { diagnose: () => terminal({
      priority: 'P1', classification: 'CALLBACK_FAILURE_NOT_OBSERVED',
      historicalFailureCount: 1,
    }) },
    { assess: () => storage({
      priority: 'P2', classification: 'FILESYSTEM_FREE_CAPACITY_LOW',
      nextAction: 'OWNER_PLAN_LOCAL_STORAGE',
      filesystemAvailableMiBCappedAt64: 4,
    }) }).assess();
  hold(r);
  assert.equal(r.priority, 'P1');
  assert.equal(r.classification, 'RECORDED_FAULT_OR_STORAGE_PRESSURE');
});

test('critical storage forces P1 even after a clean local stop', () => {
  const r = construct(undefined, undefined,
    { assess: criticalStorage }).assess();
  hold(r);
  assert.equal(r.priority, 'P1');
  assert.equal(r.terminalPriority, 'P3');
  assert.equal(r.storagePriority, 'P1');
});

test('capacity P2 on clean stop cannot become P3 by terminal receipt', () => {
  const r = construct(undefined, undefined, { assess: () => storage({
    priority: 'P2', classification: 'JOURNAL_BUDGET_NEEDS_ATTENTION',
    nextAction: 'OWNER_REVIEW_JOURNAL_LIMIT',
    journalBudgetPriority: 'P2',
  }) }).assess();
  hold(r);
  assert.equal(r.priority, 'P2');
  assert.equal(r.classification, 'LOCAL_MONITORING_REQUIRED');
});

test('storage observation unverified dominates healthy terminal history', () => {
  const r = construct(undefined, undefined, { assess: () => storage({
    priority: 'P0', classification: 'STORAGE_PRESSURE_UNVERIFIED',
    nextAction: 'OWNER_INVESTIGATE_LOCAL_STORAGE',
    processState: 'UNVERIFIED', journalBudgetPriority: 'UNVERIFIED',
    filesystemAvailableMiBCappedAt64: null,
    filesystemFreeSpace: 'NOT_VERIFIED',
  }) }).assess();
  hold(r);
  assert.equal(r.priority, 'P0');
  assert.equal(r.classification, 'CORRELATION_EVIDENCE_UNVERIFIED');
  assert.equal(r.snapshotConsistency, 'NOT_VERIFIED'); // cross-source mismatch
});

test('terminal observation inconsistency cannot yield a clear verdict', () => {
  const r = construct(undefined, { diagnose: () => terminal({
    priority: 'P0', classification: 'OBSERVATIONS_INCONSISTENT',
    nextAction: 'OWNER_INVESTIGATE_LOCAL_EVIDENCE',
    processState: 'UNVERIFIED', controllerErrorCode: null,
  }) }).assess();
  hold(r);
  assert.equal(r.priority, 'P0');
  assert.equal(r.terminalPriority, 'UNVERIFIED');
});

test('Controller PID and generation drift between reads fail closed', () => {
  for (const field of ['pid', 'generationId', 'state', 'errorCode']) {
    let n = 0;
    const c = { status() {
      ++n;
      if (field === 'pid') return status({ pid: n < 3 ? 44 : 45 });
      if (field === 'generationId') return status({
        generationId: (n < 3 ? 'a' : 'b').repeat(32),
      });
      if (field === 'state') return status({ state: n < 3 ? 'STOPPED' : 'FAILED' });
      return status({ errorCode: n < 3 ? null : 'GUARDIAN_CHILD_PROBE_TIMEOUT' });
    } };
    const r = construct(c).assess();
    hold(r);
    assert.equal(r.priority, 'P0', field);
    assert.equal(r.processState, 'UNVERIFIED', field);
  }
});

test('second terminal receipt changes mid-read, reject entire correlation', () => {
  let n = 0;
  const r = construct(undefined, { diagnose() {
    return terminal({ journalSha256: (++n === 1 ? 'a' : 'b').repeat(64) });
  } }).assess();
  hold(r);
  assert.equal(r.priority, 'P0');
  assert.equal(r.terminalPriority, 'UNVERIFIED');
});

test('second storage reading changes mid-read, reject correlation', () => {
  let n = 0;
  const r = construct(undefined, undefined, { assess() {
    return storage({ filesystemAvailableMiBCappedAt64: ++n === 1 ? 64 : 32 });
  } }).assess();
  hold(r);
  assert.equal(r.priority, 'P0');
  assert.equal(r.storagePriority, 'UNVERIFIED');
});

test('untrusted receipt authority and unknown extra fields fail closed', () => {
  for (const override of [
    { activationAllowed: true }, { releaseAuthority: 'RELEASED' },
    { token: 'SECRET' }, { journalSha256: 'invalid' },
    { priority: '__proto__' }, { classification: 'INJECTED' },
  ]) {
    const r = construct(undefined,
      { diagnose: () => terminal(override) }).assess();
    hold(r);
    assert.equal(r.priority, 'P0');
    assert.equal(JSON.stringify(r).includes('SECRET'), false);
  }
  for (const override of [
    { activationAllowed: true }, { appendReadiness: 'READY' },
    { secret: 'SECRET' }, { filesystemAvailableMiBCappedAt64: -1 },
    { priority: '__proto__' }, { nextAction: 'OWNER_CLEAR_HOLD' },
  ]) {
    const r = construct(undefined, undefined,
      { assess: () => storage(override) }).assess();
    hold(r);
    assert.equal(r.priority, 'P0');
    assert.equal(JSON.stringify(r).includes('SECRET'), false);
  }
});

test('accessor and thrown dependency never leak untrusted exception strings', () => {
  const forged = terminal();
  Object.defineProperty(forged, 'priority', {
    enumerable: true, get() { throw Error('SYNTHETIC_SECRET'); },
  });
  for (const p of [
    { diagnose: () => forged },
    { diagnose: () => { throw Error('SYNTHETIC_SECRET'); } },
  ]) {
    const r = construct(undefined, p).assess();
    hold(r);
    assert.equal(r.priority, 'P0');
    assert.equal(JSON.stringify(r).includes('SYNTHETIC_SECRET'), false);
  }
});

test('invalid dependency configuration is rejected without invoking getters', () => {
  for (const candidate of [null, {}, {
    controller: {}, terminalPersistence: {}, storagePressure: {},
  }, {
    controller: { status: true },
    terminalPersistence: { diagnose() {} }, storagePressure: { assess() {} },
  }]) {
    assert.throws(() => createGuardianLocalTerminalStorageCorrelation(candidate),
      /GUARDIAN_LOCAL_TERMINAL_STORAGE_CONFIG_INVALID/);
  }
  const injected = {
    controller: { status() {} }, terminalPersistence: { diagnose() {} },
    storagePressure: { assess() {} },
  };
  Object.defineProperty(injected, 'controller', {
    enumerable: true, get() { throw Error('SECRET'); },
  });
  assert.throws(() => createGuardianLocalTerminalStorageCorrelation(injected),
    /GUARDIAN_LOCAL_TERMINAL_STORAGE_CONFIG_INVALID/);
});

test('Operator real session has no mutation or release capability', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-correlation-'));
  const entrypoint = path.join(__dirname, 'guardian-protected-worker-child.cjs');
  const journal = path.join(directory, 'guardian-correlation.jsonl');
  try {
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(entrypoint), entrypoint, directory,
      fileName: path.basename(journal), maxJournalBytes: 4096,
    });
    assert.equal(fs.existsSync(journal), false);
    assert.equal(Object.hasOwn(session.owner, 'assessTerminalStorage'), false);
    for (const name of ['start', 'stop', 'reset', 'publishCheck', 'clear']) {
      assert.equal(Object.hasOwn(session.operator, name), false);
    }
    const before = fs.readdirSync(directory);
    const r = session.operator.assessTerminalStorage();
    hold(r);
    assert.equal(r.priority, 'P2');
    assert.equal(r.processState, 'CREATED');
    assert.equal(session.owner.status().state, 'CREATED');
    assert.deepEqual(fs.readdirSync(directory), before);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
