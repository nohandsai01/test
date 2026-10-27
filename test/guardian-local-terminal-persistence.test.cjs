'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createGuardianLocalTerminalPersistence } =
  require('../merge-gate-install/guardian-candidate/guardian-local-terminal-persistence.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

function status(overrides = {}) {
  return {
    state: 'CREATED', errorCode: null, pid: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false, ...overrides,
  };
}
function triage(overrides = {}) {
  return {
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION', status: 'SOURCE_ONLY_HOLD',
    priority: 'P2', classification: 'NO_LOCAL_BASELINE',
    nextAction: 'OWNER_VERIFY_FIRST_START_PREREQUISITES',
    sourceReason: 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING',
    processState: 'CREATED', liveness: 'NOT_PROVEN',
    journalEntries: 0, journalSha256: null, failureCount: 0,
    firstFailure: null, latestFailure: null, lastTerminal: null,
    manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', ...overrides,
  };
}
function construct(state = status(), report = triage()) {
  const controller = { status: () => state };
  const diagnostics = { faultTriage: () => report };
  return createGuardianLocalTerminalPersistence({ controller, diagnostics });
}
function hold(result) {
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.kind, 'GUARDIAN_LOCAL_TERMINAL_PERSISTENCE_DIAGNOSIS_V1');
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  assert.equal(result.activationAllowed, false);
  assert.equal(result.automaticRestartAllowed, false);
  assert.equal(result.manualInterventionRequired, true);
  assert.equal(result.terminalPersistence, 'NOT_PROVEN');
  assert.equal(result.liveness, 'NOT_PROVEN');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.hasOwn(result, 'pid'), false);
}
const cleanStop = () => triage({
  priority: 'P3', classification: 'LOCAL_STOP_OBSERVED',
  nextAction: 'NO_LOCAL_FAULT_OBSERVED',
  sourceReason: 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP',
  processState: 'STOPPED',
  journalEntries: 1, journalSha256: 'a'.repeat(64),
  manualInterventionRequired: false,
});
const recordedFailure = () => triage({
  priority: 'P1', classification: 'RECORDED_FAILURE',
  nextAction: 'OWNER_REVIEW_FAULT_HISTORY',
  sourceReason: 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED',
  processState: 'FAILED',
  journalEntries: 2, journalSha256: 'b'.repeat(64), failureCount: 1,
});

test('construction is inert; exported capability is only frozen diagnose()', () => {
  let reads = 0;
  const wrapper = createGuardianLocalTerminalPersistence({
    controller: { status() { reads++; return status(); } },
    diagnostics: { faultTriage() { reads++; return triage(); } },
  });
  assert.deepEqual(Object.keys(wrapper), ['diagnose']);
  assert.ok(Object.isFrozen(wrapper));
  assert.equal(reads, 0);
  hold(wrapper.diagnose());
  assert.equal(reads, 5); // 3 status observations, 2 journal observations
});
test('invalid dependencies rejected before reading', () => {
  for (const invalid of [null, {}, { controller: {}, diagnostics: {} },
    { controller: { status: true }, diagnostics: { faultTriage() {} } }]) {
    assert.throws(() => createGuardianLocalTerminalPersistence(invalid),
      /GUARDIAN_TERMINAL_PERSISTENCE_CONFIG_INVALID/);
  }
});
test('FAILED terminal callback with missing journal is P0, not clean stop', () => {
  const result = construct(
    status({ state: 'FAILED',
      errorCode: 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED' }),
    triage({ priority: 'P0', classification: 'EVIDENCE_UNVERIFIED',
      nextAction: 'OWNER_INVESTIGATE_LOCAL_EVIDENCE',
      processState: 'FAILED' }),
  ).diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'TERMINAL_CALLBACK_FAILURE_OBSERVED');
  assert.equal(result.nextAction, 'OWNER_INVESTIGATE_TERMINAL_RECEIPT_PATH');
  assert.equal(result.journalReason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
  assert.equal(result.controllerErrorCode,
    'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED');
});
test('older recorded failures cannot clear a failed terminal callback', () => {
  const result = construct(
    status({ state: 'FAILED', pid: 923,
      errorCode: 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED' }),
    recordedFailure(),
  ).diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'TERMINAL_CALLBACK_FAILURE_OBSERVED');
  assert.equal(result.journalSha256, 'b'.repeat(64));
  assert.equal(result.historicalFailureCount, 1);
});
test('clean local stop is not independently certified terminal durability', () => {
  const result = construct(status({ state: 'STOPPED' }), cleanStop()).diagnose();
  hold(result);
  assert.equal(result.priority, 'P3');
  assert.equal(result.classification, 'CALLBACK_FAILURE_NOT_OBSERVED');
  assert.equal(result.nextAction, 'OWNER_RECONCILE_TERMINAL_RECEIPTS');
  assert.equal(result.terminalPersistence, 'NOT_PROVEN');
});
test('different failed Controller reason is preserved without guessing write cause', () => {
  const result = construct(
    status({ state: 'FAILED', errorCode: 'GUARDIAN_CHILD_PROBE_TIMEOUT' }),
    recordedFailure(),
  ).diagnose();
  hold(result);
  assert.equal(result.priority, 'P1');
  assert.equal(result.classification, 'CALLBACK_FAILURE_NOT_OBSERVED');
  assert.equal(result.controllerErrorCode, 'GUARDIAN_CHILD_PROBE_TIMEOUT');
});
test('PID drift with unchanged RUNNING label rejects the observation', () => {
  let reads = 0;
  const wrapper = createGuardianLocalTerminalPersistence({
    controller: { status: () => status({
      state: 'RUNNING', pid: reads++ === 0 ? 1 : 2,
    }) },
    diagnostics: { faultTriage: () => triage({
      priority: 'P2', classification: 'PROCESS_STATE_UNPROVEN',
      nextAction: 'OWNER_RECONCILE_LIFECYCLE',
      sourceReason: 'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE',
      processState: 'RUNNING',
    }) },
  });
  const result = wrapper.diagnose();
  hold(result);
  assert.equal(result.classification, 'OBSERVATIONS_INCONSISTENT');
  assert.equal(result.priority, 'P0');
  assert.equal(result.processState, 'UNVERIFIED');
});
test('journal digest changes between bounded reads reject the observation', () => {
  let reads = 0;
  const wrapper = createGuardianLocalTerminalPersistence({
    controller: { status: () => status({ state: 'STOPPED' }) },
    diagnostics: { faultTriage: () => {
      const x = cleanStop();
      return { ...x, journalSha256: (reads++ ? 'b' : 'a').repeat(64) };
    } },
  });
  const result = wrapper.diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.journalSha256, null);
});
test('Controller errorCode drift without state change rejects the observation', () => {
  let reads = 0;
  const wrapper = createGuardianLocalTerminalPersistence({
    controller: { status: () => status({
      state: 'FAILED',
      errorCode: reads++ ? 'GUARDIAN_CHILD_PROBE_TIMEOUT' :
        'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED',
    }) },
    diagnostics: { faultTriage: recordedFailure },
  });
  const result = wrapper.diagnose();
  hold(result);
  assert.equal(result.classification, 'OBSERVATIONS_INCONSISTENT');
  assert.equal(result.controllerErrorCode, null);
});
test('getter-backed Controller status and triage fail closed without leaking', () => {
  const unsafeStatus = status();
  Object.defineProperty(unsafeStatus, 'state', {
    enumerable: true, get() { throw Error('SECRET'); },
  });
  let result = construct(unsafeStatus, triage()).diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(JSON.stringify(result).includes('SECRET'), false);
  const unsafeTriage = triage();
  Object.defineProperty(unsafeTriage, 'priority', {
    enumerable: true, get() { throw Error('SECRET'); },
  });
  result = construct(status(), unsafeTriage).diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(JSON.stringify(result).includes('SECRET'), false);
});
test('malformed authority, journal digest, triage class and extra keys fail closed', () => {
  const cases = [
    status({ activationAllowed: true }),
    status({ releaseAuthority: 'ISSUED' }),
    status({ pid: '999' }),
    status({ injected: 'secret' }),
  ];
  for (const input of cases) {
    const r = construct(input, triage()).diagnose();
    hold(r);
    assert.equal(r.priority, 'P0');
  }
  for (const input of [
    triage({ priority: 'P3', classification: 'LOCAL_STOP_OBSERVED',
      nextAction: 'NO_LOCAL_FAULT_OBSERVED' }),
    triage({ journalSha256: 'z'.repeat(64) }),
    triage({ journalEntries: 1 }),
    triage({ injected: 'secret' }),
  ]) {
    const r = construct(status(), input).diagnose();
    hold(r);
    assert.equal(r.priority, 'P0');
  }
});

test('newer generation-bound status and triage counters remain read-only HOLD', () => {
  const state = status({ state: 'FAILED', generationId: '1'.repeat(32),
    errorCode: 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED' });
  const report = { ...recordedFailure(), unterminatedGenerations: 1,
    concurrentGenerations: 0 };
  const result = construct(state, report).diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'TERMINAL_CALLBACK_FAILURE_OBSERVED');
  assert.equal(Object.hasOwn(result, 'generationId'), false);
  assert.equal(Object.hasOwn(result, 'unterminatedGenerations'), false);
});
test('generation switch with identical PID and state fails closed', () => {
  let reads = 0;
  const wrapper = createGuardianLocalTerminalPersistence({
    controller: { status: () => status({
      state: 'FAILED',
      errorCode: 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED',
      generationId: (++reads === 1 ? 'a' : 'b').repeat(32),
      pid: 999,
    }) },
    diagnostics: { faultTriage: recordedFailure },
  });
  const result = wrapper.diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'OBSERVATIONS_INCONSISTENT');
});
test('concurrent-generation counter drift and bad counts fail closed', () => {
  let reads = 0;
  const wrapper = createGuardianLocalTerminalPersistence({
    controller: { status: () => status({ state: 'FAILED',
      generationId: 'b'.repeat(32), errorCode:
      'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED' }) },
    diagnostics: { faultTriage: () => ({
      ...recordedFailure(), unterminatedGenerations: 0,
      concurrentGenerations: reads++,
    }) },
  });
  const result = wrapper.diagnose();
  hold(result);
  assert.equal(result.priority, 'P0');
  for (const bad of [-1, 0.5, '0']) {
    const r = construct(status(), triage({
      unterminatedGenerations: bad, concurrentGenerations: 0,
    })).diagnose();
    hold(r);
    assert.equal(r.priority, 'P0');
  }
});
test('generation-interrupted triage remains P1, never a terminal certificate', () => {
  const result = construct(status({ state: 'STOPPED',
    generationId: 'c'.repeat(32) }), triage({
    priority: 'P1', classification: 'UNTERMINATED_GENERATION',
    nextAction: 'OWNER_RECONCILE_INTERRUPTED_GENERATION',
    processState: 'STOPPED',
    sourceReason: 'GUARDIAN_DIAGNOSTICS_GENERATION_UNTERMINATED',
    unterminatedGenerations: 1, concurrentGenerations: 0,
    journalEntries: 1, journalSha256: 'c'.repeat(64),
  })).diagnose();
  hold(result);
  assert.equal(result.priority, 'P1');
  assert.equal(result.classification, 'CALLBACK_FAILURE_NOT_OBSERVED');
});

test('Operator facade real child: missed terminal journal write is diagnosed only', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-persist-'));
  try {
    const session = createGuardianLocalOperatorSession({
      cwd: __dirname,
      entrypoint: path.join(__dirname, 'guardian-protected-worker-child.cjs'),
      directory, fileName: 'guardian-terminal.jsonl',
      startupTimeoutMs: 4000, shutdownTimeoutMs: 500,
    });
    assert.equal(Object.hasOwn(session.owner, 'diagnoseTerminalPersistence'), false);
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
    await session.owner.start();
    // A directory at the receipt pathname rejects O_APPEND as a file.
    // This is an isolated tmp fixture, never the production Guardian journal.
    const target = path.join(directory, 'guardian-terminal.jsonl');
    fs.mkdirSync(target, { mode: 0o700 });
    const end = await session.owner.stop();
    assert.equal(end.state, 'FAILED');
    assert.equal(end.errorCode, 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED');
    const result = session.operator.diagnoseTerminalPersistence();
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.classification, 'TERMINAL_CALLBACK_FAILURE_OBSERVED');
    assert.equal(fs.lstatSync(target).isDirectory(), true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
