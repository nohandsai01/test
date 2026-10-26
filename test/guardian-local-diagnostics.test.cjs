'use strict';
// Read-only diagnostics over genuine owner-only journal and local child
// controller state. All tests are offline, with disposable temp paths.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createGuardianLocalDiagnostics } =
  require('../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalProcessController } =
  require('../merge-gate-install/guardian-candidate/guardian-local-process-controller.cjs');
const fixtureScript = path.join(__dirname, 'guardian-local-controller-child.cjs');
const workerScript = path.join(__dirname, 'guardian-protected-worker-child.cjs');

function temp(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nh-diagnostics-'));
  return Promise.resolve().then(() => fn(directory))
    .finally(() => fs.rmSync(directory, { recursive: true, force: true }));
}
function journal(directory, extra = {}) {
  return createGuardianLocalReceiptJournal({
    directory, fileName: 'guardian-test.jsonl', ...extra,
  });
}
function controller(state, extra = {}) {
  return { status: () => ({
    state, activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
    ...extra,
  }) };
}
function inspect(directory, ctrl, extra = {}) {
  return createGuardianLocalDiagnostics({
    directory, fileName: 'guardian-test.jsonl',
    controller: ctrl, ...extra,
  }).inspect();
}
function goodStop() {
  return Object.freeze({
    state: 'STOPPED', errorCode: null, hostStopped: true,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  });
}
function failure(code = 'GUARDIAN_CHILD_EXIT_UNVERIFIED') {
  return Object.freeze({
    state: 'FAILED', errorCode: code, hostStopped: false,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  });
}
function hold(report) {
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.status, 'SOURCE_ONLY_HOLD');
  assert.equal(report.liveness, 'NOT_PROVEN');
  assert.equal(report.automaticRestartAllowed, false);
  assert.equal(report.activationAllowed, false);
  assert.equal(report.releaseAuthority, 'NOT_ISSUED');
  assert.ok(Object.isFrozen(report));
}
function file(directory) { return path.join(directory, 'guardian-test.jsonl'); }
async function realChild(entrypoint, directory, callback) {
  const ctrl = createGuardianLocalProcessController({
    cwd: path.dirname(entrypoint), entrypoint,
    startupTimeoutMs: 4000, shutdownTimeoutMs: 600,
    onTerminal: callback,
  });
  const start = await ctrl.start();
  assert.equal(start.state, 'RUNNING');
  return ctrl;
}

test('construction and import are inert: no file created, no controller start', async () => {
  await temp(async (directory) => {
    let statusCalls = 0;
    const ctrl = { status() {
      statusCalls++;
      return controller('CREATED').status();
    } };
    const diag = createGuardianLocalDiagnostics({
      directory, fileName: 'guardian-test.jsonl', controller: ctrl,
    });
    assert.equal(statusCalls, 0);
    assert.deepEqual(Object.keys(diag), ['inspect']);
    assert.ok(Object.isFrozen(diag));
    assert.equal(fs.existsSync(file(directory)), false);
    const result = diag.inspect();
    hold(result);
    assert.equal(result.processState, 'CREATED');
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal(result.manualInterventionRequired, true);
    assert.equal(fs.existsSync(file(directory)), false);
  });
});

test('clean, real owner journal + stopped controller yields nonauthorizing clean-stop observation', async () => {
  await temp(async (directory) => {
    const store = journal(directory);
    store.append(goodStop());
    const result = inspect(directory, controller('STOPPED'));
    hold(result);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP');
    assert.equal(result.manualInterventionRequired, false);
    assert.equal(result.journalEntries, 1);
    assert.match(result.journalSha256, /^[0-9a-f]{64}$/);
    assert.equal(result.lastTerminal.state, 'STOPPED');
    assert.equal(result.lastTerminal.errorCode, null);
    assert.ok(Object.isFrozen(result.lastTerminal));
    assert.deepEqual(Object.keys(result.lastTerminal).sort(),
      ['state', 'errorCode', 'timestamp', 'eventId'].sort());
    assert.equal(JSON.stringify(result).includes('PRIVATE KEY'), false);
  });
});

test('failure receipt causes manual intervention even if current controller says RUNNING', async () => {
  await temp(async (directory) => {
    journal(directory).append(failure());
    for (const status of ['FAILED', 'RUNNING', 'CREATED', 'STOPPED']) {
      const result = inspect(directory, controller(status));
      hold(result);
      assert.equal(result.manualInterventionRequired, true);
      assert.equal(result.lastTerminal.state, 'FAILED');
      assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
    }
  });
});

test('later clean stop after a prior fault is a distinct recorded local observation, not an unlock', async () => {
  await temp(async (directory) => {
    const store = journal(directory);
    store.append(failure());
    store.append(goodStop());
    const result = inspect(directory, controller('STOPPED'));
    hold(result);
    assert.equal(result.journalEntries, 2);
    assert.equal(result.lastTerminal.state, 'STOPPED');
    assert.equal(result.manualInterventionRequired, true);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
    assert.equal(result.releaseAuthority, 'NOT_ISSUED');
    assert.equal(result.liveness, 'NOT_PROVEN');
    assert.equal(fs.readFileSync(file(directory), 'utf8').trim().split('\n').length, 2);
  });
});

test('running and stopping controllers never report a clean stopped system', async () => {
  await temp(async (directory) => {
    journal(directory).append(goodStop());
    for (const status of ['CREATED','STARTING','RUNNING','STOPPING']) {
      const result = inspect(directory, controller(status));
      hold(result);
      assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE');
      assert.equal(result.manualInterventionRequired, true);
    }
  });
});

test('missing, corrupt, partial and duplicate evidence fail closed without exposing raw bytes', async () => {
  await temp(async (directory) => {
    journal(directory).append(goodStop());
    const original = fs.readFileSync(file(directory));
    const examples = [
      original.subarray(0, original.length - 1),
      Buffer.from('{bad json}\\n'),
      Buffer.from('{}\\n'),
      Buffer.concat([original, original]),
      Buffer.from(original.toString('utf8').replace('"schemaVersion":1,',
        '"schemaVersion":1,"schemaVersion":1,')),
      Buffer.from(original.toString('utf8').replace('"releaseAuthority":"NOT_ISSUED"',
        '"releaseAuthority":"ISSUED"')),
      Buffer.from(original.toString('utf8').replace('"errorCode":null',
        '"errorCode":"MY_SECRET_VALUE"')),
      Buffer.from('{"token":"EXFILTRATE"}\\n'),
    ];
    for (const bytes of examples) {
      fs.writeFileSync(file(directory), bytes);
      const result = inspect(directory, controller('STOPPED'));
      hold(result);
      assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_INVALID');
      assert.equal(result.manualInterventionRequired, true);
      assert.equal(result.lastTerminal, null);
      assert.equal(JSON.stringify(result).includes('EXFILTRATE'), false);
      assert.equal(result.journalSha256, null);
    }
  });
});

test('owner-only storage, symlink and missing file do not create false clean status', async () => {
  await temp(async (directory) => {
    const store = journal(directory);
    store.append(goodStop());
    const target = file(directory);
    fs.chmodSync(target, 0o644);
    let result = inspect(directory, controller('STOPPED'));
    hold(result);
    assert.equal(result.manualInterventionRequired, true);
    fs.chmodSync(target, 0o600);
    fs.unlinkSync(target);
    fs.symlinkSync('/dev/null', target);
    result = inspect(directory, controller('STOPPED'));
    hold(result);
    assert.equal(result.manualInterventionRequired, true);
    fs.unlinkSync(target);
    result = inspect(directory, controller('STOPPED'));
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal(result.manualInterventionRequired, true);
  });
});

test('invalid owner directory and constructor settings reject before inspection', async () => {
  await temp(async (directory) => {
    const ctrl = controller('STOPPED');
    for (const options of [
      { directory: 'relative/path' },
      { fileName: '../secret.jsonl' },
      { fileName: 'other.txt' },
      { controller: {} },
      { maxBytes: 0 },
      { maxBytes: 100000000 },
      { untrusted: true },
    ]) {
      assert.throws(() => createGuardianLocalDiagnostics({
        controller: ctrl, directory, fileName: 'guardian-test.jsonl',
        ...options,
      }));
    }
    fs.chmodSync(directory, 0o777);
    try {
      assert.throws(() => createGuardianLocalDiagnostics({
        controller: ctrl, directory, fileName: 'guardian-test.jsonl',
      }), /GUARDIAN_DIAGNOSTICS_DIRECTORY_UNVERIFIED/);
    } finally { fs.chmodSync(directory, 0o700); }
  });
});

test('controller returning forged authorization or throwing produces manual HOLD', async () => {
  await temp(async (directory) => {
    journal(directory).append(goodStop());
    const invalid = [
      { state: 'STOPPED', activationAllowed: true,
        releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false },
      { state: 'STOPPED', activationAllowed: false,
        releaseAuthority: 'ISSUED', automaticRestartAllowed: false },
      { state: 'STOPPED', activationAllowed: false,
        releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: true },
    ];
    for (const item of invalid) {
      const result = inspect(directory, { status() { return item; } });
      assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_CONTROLLER_UNVERIFIED');
      assert.equal(result.manualInterventionRequired, true);
      hold(result);
    }
    const bad = inspect(directory, { status() { throw new Error('secret'); } });
    assert.equal(bad.lastTerminal, null);
    assert.equal(JSON.stringify(bad).includes('secret'), false);
    hold(bad);
  });
});

test('controller state drift during journal read fails closed', async () => {
  await temp(async (directory) => {
    journal(directory).append(goodStop());
    let reads = 0;
    const ctrl = { status() {
      reads++;
      return controller(reads === 1 ? 'STOPPED' : 'RUNNING').status();
    } };
    const result = inspect(directory, ctrl);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_CONTROLLER_CHANGED_DURING_READ');
    assert.equal(result.manualInterventionRequired, true);
    hold(result);
  });
});

test('journal size exceeds protected quota and cannot be interpreted as clean', async () => {
  await temp(async (directory) => {
    const store = journal(directory);
    while (fs.statSync(directory).isDirectory() &&
        (!fs.existsSync(file(directory)) ||
         fs.statSync(file(directory)).size < 1500)) {
      store.append(goodStop());
    }
    const result = inspect(directory, controller('STOPPED'), { maxBytes: 1024 });
    hold(result);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_FILE_UNVERIFIED');
    assert.equal(result.manualInterventionRequired, true);
  });
});

test('real Protected Host child terminal is observable after process exit without changing D1', async () => {
  await temp(async (directory) => {
    const store = journal(directory);
    const child = await realChild(workerScript, directory, store.append);
    assert.equal((await child.stop()).state, 'STOPPED');
    const result = inspect(directory, child);
    hold(result);
    assert.equal(result.processState, 'STOPPED');
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP');
    assert.equal(result.journalEntries, 1);
    assert.equal(result.manualInterventionRequired, false);
    assert.equal(result.lastTerminal.state, 'STOPPED');
    assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  });
});

test('abnormal owned child exit is visible in persisted diagnostics after restart of reader', async () => {
  await temp(async (directory) => {
    const copied = path.join(directory, 'premature-exit.cjs');
    fs.copyFileSync(fixtureScript, copied);
    const store = journal(directory);
    const child = createGuardianLocalProcessController({
      cwd: directory, entrypoint: copied, onTerminal: store.append,
    });
    await assert.rejects(child.start(),
      { code: 'GUARDIAN_CHILD_EXIT_BEFORE_READY' });
    const instanceOne = inspect(directory, child);
    const instanceTwo = inspect(directory, child);
    hold(instanceTwo);
    assert.equal(instanceOne.journalSha256, instanceTwo.journalSha256);
    assert.equal(instanceTwo.reason, 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
    assert.equal(instanceTwo.processState, 'FAILED');
    assert.equal(instanceTwo.lastTerminal.errorCode,
      'GUARDIAN_CHILD_EXIT_BEFORE_READY');
    assert.equal(instanceTwo.manualInterventionRequired, true);
  });
});
