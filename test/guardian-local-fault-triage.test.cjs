'use strict';
// G22: bounded manual fault-triage readout, zero release/restart capabilities.
// All fixtures use disposable owner-only local files, never hosted D1/App.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianLocalDiagnostics } =
  require('../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const premature = path.join(__dirname, 'guardian-local-controller-child.cjs');
function workspace(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nh-guardian-triage-'));
  return Promise.resolve().then(() => fn(directory)).finally(() =>
    fs.rmSync(directory, { recursive: true, force: true }));
}
function cfg(directory) {
  return { directory, fileName: 'guardian-triage.jsonl',
    cwd: path.dirname(worker), entrypoint: worker,
    startupTimeoutMs: 4000, shutdownTimeoutMs: 600 };
}
function writeJournal(directory, receipt) {
  const storage = createGuardianLocalReceiptJournal({
    directory, fileName: 'guardian-triage.jsonl',
  });
  storage.append(receipt);
}
function stopped() {
  return { state: 'STOPPED', errorCode: null, hostStopped: true,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false };
}
function failed(code = 'GUARDIAN_CHILD_EXIT_UNVERIFIED') {
  return { state: 'FAILED', errorCode: code, hostStopped: false,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false };
}
function ctrl(state = 'STOPPED') {
  return { status() { return {
    state, errorCode: null, pid: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  }; } };
}
function localTriage(directory, controller) {
  const instance = createGuardianLocalDiagnostics({
    directory, fileName: 'guardian-triage.jsonl', controller,
  });
  return instance.faultTriage();
}
function holds(value) {
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1');
  assert.equal(value.status, 'SOURCE_ONLY_HOLD');
  assert.equal(value.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(value.liveness, 'NOT_PROVEN');
  assert.equal(value.activationAllowed, false);
  assert.equal(value.releaseAuthority, 'NOT_ISSUED');
  assert.equal(value.automaticRestartAllowed, false);
  assert.ok(Object.isFrozen(value));
  assert.match(value.priority, /^P[0-3]$/);
}

test('Owner and Operator construction inert; no journal baseline is a bounded P2 suggestion', async () => {
  await workspace(async (directory) => {
    const session = createGuardianLocalOperatorSession(cfg(directory));
    assert.equal(typeof session.operator.faultTriage, 'function');
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
    assert.equal(Object.hasOwn(session.operator, 'start'), false);
    assert.equal(Object.hasOwn(session.operator, 'clearHold'), false);
    assert.equal(fs.readdirSync(directory).length, 0);
    const recommendation = session.operator.faultTriage();
    holds(recommendation);
    assert.equal(recommendation.priority, 'P2');
    assert.equal(recommendation.classification, 'NO_LOCAL_BASELINE');
    assert.equal(recommendation.nextAction, 'OWNER_VERIFY_FIRST_START_PREREQUISITES');
    assert.equal(recommendation.manualInterventionRequired, true);
    assert.equal(recommendation.journalSha256, null);
    assert.equal(recommendation.failureCount, 0);
    assert.equal(recommendation.lastTerminal, null);
    assert.equal(fs.readdirSync(directory).length, 0);
  });
});

test('real protected child start/stop yields a clean local observation but no authority', async () => {
  await workspace(async (directory) => {
    const session = createGuardianLocalOperatorSession(cfg(directory));
    assert.equal((await session.owner.start()).state, 'RUNNING');
    const during = session.operator.faultTriage();
    holds(during);
    assert.equal(during.priority, 'P0');
    assert.equal(during.classification, 'EVIDENCE_UNVERIFIED');
    assert.equal(during.manualInterventionRequired, true);
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const after = session.operator.faultTriage();
    holds(after);
    assert.equal(after.priority, 'P3');
    assert.equal(after.classification, 'LOCAL_STOP_OBSERVED');
    assert.equal(after.nextAction, 'NO_LOCAL_FAULT_OBSERVED');
    assert.equal(after.failureCount, 0);
    assert.equal(after.journalEntries, 1);
    assert.match(after.journalSha256, /^[a-f0-9]{64}$/);
    assert.equal(after.manualInterventionRequired, false);
    assert.equal(after.lastTerminal.state, 'STOPPED');
    assert.ok(Object.isFrozen(after.lastTerminal));
  });
});

test('history with FAILED then STOPPED remains P1 incident, never downgraded by a later clean process', async () => {
  await workspace(async (directory) => {
    const storage = createGuardianLocalReceiptJournal({
      directory, fileName: 'guardian-triage.jsonl',
    });
    storage.append(stopped());
    storage.append(failed('GUARDIAN_CHILD_NONZERO_EXIT'));
    storage.append(failed('GUARDIAN_CHILD_PROTOCOL_INVALID'));
    storage.append(stopped());
    const result = localTriage(directory, ctrl('STOPPED'));
    holds(result);
    assert.equal(result.priority, 'P1');
    assert.equal(result.classification, 'RECORDED_FAILURE');
    assert.equal(result.nextAction, 'OWNER_REVIEW_FAULT_HISTORY');
    assert.equal(result.failureCount, 2);
    assert.equal(result.journalEntries, 4);
    assert.equal(result.firstFailure.errorCode, 'GUARDIAN_CHILD_NONZERO_EXIT');
    assert.equal(result.latestFailure.errorCode, 'GUARDIAN_CHILD_PROTOCOL_INVALID');
    assert.equal(result.lastTerminal.state, 'STOPPED');
    assert.equal(result.manualInterventionRequired, true);
    assert.ok(Object.isFrozen(result.firstFailure));
    assert.ok(Object.isFrozen(result.latestFailure));
  });
});

test('FAILED controller with only STOPPED receipt is P1 and never considered a clean stop', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, stopped());
    const result = localTriage(directory, ctrl('FAILED'));
    holds(result);
    assert.equal(result.priority, 'P1');
    assert.equal(result.classification, 'CONTROLLER_FAILED');
    assert.equal(result.nextAction, 'OWNER_INVESTIGATE_CONTROLLER_FAILURE');
    assert.equal(result.failureCount, 0);
    assert.equal(result.manualInterventionRequired, true);
  });
});

test('in-flight states with a valid prior STOPPED receipt stay P2/NOT_PROVEN', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, stopped());
    for (const state of ['CREATED', 'STARTING', 'RUNNING', 'STOPPING']) {
      const result = localTriage(directory, ctrl(state));
      holds(result);
      assert.equal(result.priority, 'P2');
      assert.equal(result.classification, 'PROCESS_STATE_UNPROVEN');
      assert.equal(result.nextAction, 'OWNER_RECONCILE_LIFECYCLE');
      assert.equal(result.manualInterventionRequired, true);
    }
  });
});

test('corrupt, truncated, duplicate-key and missing evidence are P0; raw bytes never returned', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, stopped());
    const name = path.join(directory, 'guardian-triage.jsonl');
    const original = fs.readFileSync(name, 'utf8');
    for (const invalid of [
      original.slice(0, -1),
      original.replace('"schemaVersion":1,',
        '"schemaVersion":1,"schemaVersion":1,'),
      '{"token":"SECRET_KEY_MUST_NOT_LEAK"}\n',
      original + 'not-json\n',
    ]) {
      fs.writeFileSync(name, invalid);
      const result = localTriage(directory, ctrl('STOPPED'));
      holds(result);
      assert.equal(result.priority, 'P0');
      assert.equal(result.classification, 'EVIDENCE_UNVERIFIED');
      assert.equal(result.nextAction, 'OWNER_INVESTIGATE_LOCAL_EVIDENCE');
      assert.equal(result.journalEntries, 0);
      assert.equal(result.journalSha256, null);
      assert.equal(result.lastTerminal, null);
      assert.equal(JSON.stringify(result).includes('SECRET_KEY_MUST_NOT_LEAK'), false);
    }
    fs.unlinkSync(name);
    const missing = localTriage(directory, ctrl('STOPPED'));
    holds(missing);
    assert.equal(missing.priority, 'P0');
    assert.equal(missing.classification, 'EVIDENCE_UNVERIFIED');
    assert.equal(missing.sourceReason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
  });
});

test('untrusted permissions and symlink journal cannot claim clean stop', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, stopped());
    const name = path.join(directory, 'guardian-triage.jsonl');
    fs.chmodSync(name, 0o644);
    let result = localTriage(directory, ctrl());
    holds(result);
    assert.equal(result.priority, 'P0');
    fs.chmodSync(name, 0o600);
    fs.unlinkSync(name);
    fs.symlinkSync('/dev/null', name);
    result = localTriage(directory, ctrl());
    holds(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.manualInterventionRequired, true);
  });
});

test('untrusted controller status and status drift cannot be promoted to P3', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, stopped());
    const fakeStatus = { state: 'STOPPED', errorCode: null, pid: null,
      activationAllowed: true, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false };
    let result = localTriage(directory, { status() { return fakeStatus; } });
    holds(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.processState, 'UNVERIFIED');
    let visits = 0;
    result = localTriage(directory, { status() {
      visits++;
      return ctrl(visits === 1 ? 'STOPPED' : 'RUNNING').status();
    } });
    holds(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.sourceReason,
      'GUARDIAN_DIAGNOSTICS_CONTROLLER_CHANGED_DURING_READ');
    let accessorReads = 0;
    const getterState = { get state() {
      accessorReads++;
      return 'STOPPED';
    }, errorCode: null, pid: null, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false };
    result = localTriage(directory, { status() { return getterState; } });
    holds(result);
    assert.equal(result.priority, 'P0');
    assert.equal(accessorReads, 0);
  });
});

test('operator fault triage calls never alter the owner-only journal or its metadata', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, failed());
    const session = createGuardianLocalOperatorSession(cfg(directory));
    const location = path.join(directory, 'guardian-triage.jsonl');
    const original = fs.readFileSync(location);
    const before = fs.statSync(location);
    const a = session.operator.faultTriage();
    const b = session.operator.faultTriage();
    holds(a);
    assert.deepEqual(a, b);
    assert.equal(a.priority, 'P1');
    assert.deepEqual(fs.readFileSync(location), original);
    const after = fs.statSync(location);
    assert.equal(before.mtimeMs, after.mtimeMs);
    assert.equal(before.size, after.size);
  });
});

test('triage never includes PID, filesystem paths, secrets or authorization actions', async () => {
  await workspace(async (directory) => {
    writeJournal(directory, failed());
    const result = localTriage(directory, {
      status() { return { ...ctrl('FAILED').status(), pid: 12345 }; },
    });
    holds(result);
    const json = JSON.stringify(result);
    assert.equal(json.includes(directory), false);
    assert.equal(json.includes('12345'), false);
    assert.equal(json.includes('start()'), false);
    assert.equal(json.includes('stop()'), false);
    assert.equal(json.includes('token'), false);
    assert.deepEqual(Object.keys(result).sort(), [
      'schemaVersion', 'kind', 'authority', 'status',
      'priority', 'classification', 'nextAction', 'sourceReason',
      'processState', 'liveness', 'journalEntries', 'journalSha256',
      'failureCount', 'unterminatedGenerations', 'firstFailure',
      'latestFailure', 'lastTerminal',
      'manualInterventionRequired', 'automaticRestartAllowed',
      'activationAllowed', 'releaseAuthority',
    ].sort());
  });
});
