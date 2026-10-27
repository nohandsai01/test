'use strict';
// Independent local child-process/Protected Host integration, no live App/D1.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createGuardianChildRuntime } =
  require('../merge-gate-install/guardian-candidate/guardian-child-runtime.cjs');
const { createGuardianLocalProcessController } =
  require('../merge-gate-install/guardian-candidate/guardian-local-process-controller.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const validFixture = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const standaloneFixture = path.join(__dirname, 'guardian-local-controller-child.cjs');
function temporary(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nohands-guardian-receipts-'));
  return Promise.resolve().then(() => fn(directory))
    .finally(() => fs.rmSync(directory, { recursive: true, force: true }));
}
function journal(directory, props = {}) {
  return createGuardianLocalReceiptJournal({
    directory, fileName: 'guardian-lifecycle.jsonl', ...props,
  });
}
function observe(directory) {
  const lines = fs.readFileSync(
    path.join(directory, 'guardian-lifecycle.jsonl'), 'utf8').trim().split('\n');
  return lines.map((line) => JSON.parse(line));
}
function controller(entrypoint, onTerminal, overrides = {}) {
  return createGuardianLocalProcessController({
    cwd: path.dirname(entrypoint), entrypoint,
    startupTimeoutMs: 4000, shutdownTimeoutMs: 600,
    onTerminal, ...overrides,
  });
}
function assertHold(r) {
  assert.equal(r.activationAllowed, false);
  assert.equal(r.releaseAuthority, 'NOT_ISSUED');
  assert.equal(r.automaticRestartAllowed, false);
}
async function fakeHealth({ response, noResponse = false }, fn) {
  const server = http.createServer((_, res) => {
    if (noResponse) return;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(response));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { return await fn(server.address().port); }
  finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

test('import and child runtime construction never open a listener or send IPC', () => {
  let sent = 0, built = 0;
  const source = { connected: true, send: () => { sent++; },
    disconnect: () => {} };
  const runtime = createGuardianChildRuntime({
    ipc: source,
    createRunner() { built++; throw new Error('must be inert'); },
  });
  assert.deepEqual(Object.keys(runtime).sort(), ['start', 'status']);
  assert.equal(Object.isFrozen(runtime), true);
  assert.equal(runtime.status().state, 'CREATED');
  assert.equal(runtime.status().healthVerified, false);
  assert.equal(sent, 0);
  assert.equal(built, 0);
});

test('real source-only Protected Host child starts, health-checks then terminates with durable parent receipt', async () => {
  await temporary(async (directory) => {
    const store = journal(directory);
    const controllerInstance = controller(validFixture, store.append);
    const before = controllerInstance.status();
    assert.equal(before.state, 'CREATED');
    assertHold(before);
    const active = await controllerInstance.start();
    assert.equal(active.state, 'RUNNING');
    assertHold(active);
    assert.ok(active.pid > 0);
    const end = await controllerInstance.stop();
    assert.equal(end.state, 'STOPPED');
    assertHold(end);
    const saved = observe(directory);
    assert.equal(saved.length, 1);
    // G27: a controller-produced receipt is bound to its generation.
    assert.equal(saved[0].schemaVersion, 2);
    assert.equal(saved[0].generationId, end.generationId);
    assert.match(saved[0].generationId, /^[0-9a-f]{32}$/);
    assert.equal(saved[0].state, 'STOPPED');
    assert.equal(saved[0].errorCode, null);
    assert.equal(saved[0].hostStopped, true);
    assertHold(saved[0]);
    assert.deepEqual(Object.keys(saved[0]).sort(), [
      'activationAllowed', 'automaticRestartAllowed', 'errorCode',
      'eventId', 'generationId', 'hostStopped', 'releaseAuthority',
      'schemaVersion', 'state', 'timestamp',
    ].sort());
    const file = path.join(directory, 'guardian-lifecycle.jsonl');
    assert.equal(fs.statSync(file).mode & 0o077, 0);
    await assert.rejects(controllerInstance.start(),
      { code: 'GUARDIAN_CHILD_STATE_INVALID' });
  });
});

test('separate isolated child runs append to the same durable journal without overwriting previous evidence', async () => {
  await temporary(async (directory) => {
    const store = journal(directory);
    for (let i = 0; i < 2; i++) {
      const child = controller(validFixture, store.append);
      assert.equal((await child.start()).state, 'RUNNING');
      assert.equal((await child.stop()).state, 'STOPPED');
    }
    const saved = observe(directory);
    assert.equal(saved.length, 2);
    assert.equal(new Set(saved.map((row) => row.eventId)).size, 2);
    assert.ok(saved.every((row) => row.state === 'STOPPED'));
  });
});

test('unexpected child exit creates one durable FAILED receipt and no automatic restart', async () => {
  await temporary(async (directory) => {
    const name = path.join(directory, 'premature-exit.cjs');
    fs.copyFileSync(standaloneFixture, name);
    const store = journal(directory);
    const child = controller(name, store.append);
    await assert.rejects(child.start(),
      { code: 'GUARDIAN_CHILD_EXIT_BEFORE_READY' });
    assert.equal(child.status().state, 'FAILED');
    assertHold(child.status());
    const saved = observe(directory);
    assert.equal(saved.length, 1);
    assert.equal(saved[0].state, 'FAILED');
    assert.equal(saved[0].hostStopped, false);
    assertHold(saved[0]);
  });
});

test('invalid child lifecycle frame is durable FAILED and does not supply authority', async () => {
  await temporary(async (directory) => {
    const name = path.join(directory, 'malformed-ready.cjs');
    fs.copyFileSync(standaloneFixture, name);
    const store = journal(directory);
    const child = controller(name, store.append);
    await assert.rejects(child.start(),
      { code: 'GUARDIAN_CHILD_PROTOCOL_INVALID' });
    assert.equal(child.status().state, 'FAILED');
    assert.equal(observe(directory)[0].errorCode,
      'GUARDIAN_CHILD_PROTOCOL_INVALID');
  });
});

test('child health probe cannot emit READY on false health and calls runner.stop', async () => {
  await fakeHealth({ response: { running: true, feature: 'ACTIVE',
    releaseAuthority: 'ISSUED' } }, async (port) => {
    let stopped = 0, readySent = 0;
    const ipc = { connected: true,
      send(frame, callback) { if (frame.event === 'READY') readySent++; callback?.(); },
      disconnect() { this.connected = false; },
    };
    const runtime = createGuardianChildRuntime({ ipc,
      createRunner: ({ onTerminal }) => ({
        async start() {},
        async stop() {
          stopped++;
          onTerminal({ state: 'STOPPED', hostStopped: true,
            activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
        },
        status() { return {
          state: 'RUNNING', activationAllowed: false,
          releaseAuthority: 'NOT_ISSUED',
          loopback: { address: '127.0.0.1', port },
        }; },
      }),
    });
    await assert.rejects(runtime.start(),
      { code: 'GUARDIAN_CHILD_RUNTIME_START_UNVERIFIED' });
    assert.equal(readySent, 0);
    assert.equal(stopped, 1);
    assertHold({ ...runtime.status(), automaticRestartAllowed: false });
  });
});

test('stalled loopback health probe has a deadline and never produces READY', async () => {
  await fakeHealth({ noResponse: true }, async (port) => {
    let writes = 0, stops = 0;
    const runtime = createGuardianChildRuntime({
      ipc: { connected: true,
        send(frame, cb) { if (frame.event === 'READY') writes++; cb?.(); },
        disconnect() {},
      },
      healthTimeoutMs: 75,
      createRunner: ({ onTerminal }) => ({
        async start() {},
        async stop() {
          stops++;
          onTerminal({ state: 'FAILED', hostStopped: false });
        },
        status() { return { state: 'RUNNING',
          activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
          loopback: { address: '127.0.0.1', port },
        }; },
      }),
    });
    await assert.rejects(runtime.start(),
      { code: 'GUARDIAN_CHILD_RUNTIME_START_UNVERIFIED' });
    assert.equal(writes, 0);
    assert.equal(stops, 1);
  });
});

test('journal rejects extra keys, secret fields, unsafe dirs and symlink targets', async () => {
  await temporary(async (directory) => {
    const storage = journal(directory);
    const good = {
      state: 'FAILED', errorCode: 'GUARDIAN_CHILD_EXIT_UNVERIFIED',
      hostStopped: false, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
    };
    assert.throws(() => storage.append({ ...good, token: 'not-allowed' }),
      { code: 'GUARDIAN_JOURNAL_RECEIPT_INVALID' });
    assert.throws(() => storage.append({ ...good, releaseAuthority: 'ISSUED' }),
      { code: 'GUARDIAN_JOURNAL_RECEIPT_INVALID' });
    assert.equal(storage.append(good).persisted, true);
    assert.equal(observe(directory).length, 1);
    const file = path.join(directory, 'guardian-lifecycle.jsonl');
    fs.unlinkSync(file);
    fs.symlinkSync('/dev/null', file);
    assert.throws(() => storage.append(good),
      { code: 'GUARDIAN_JOURNAL_WRITE_FAILED' });
  });
  await temporary(async (directory) => {
    fs.chmodSync(directory, 0o777);
    try {
      assert.throws(() => journal(directory),
        { code: 'GUARDIAN_JOURNAL_DIRECTORY_UNVERIFIED' });
    } finally { fs.chmodSync(directory, 0o700); }
  });
});

test('journal storage exception causes FAIL-CLOSED controller terminal state', async () => {
  await temporary(async (directory) => {
    const lockedDir = path.join(directory, 'guardian-lifecycle.jsonl');
    fs.mkdirSync(lockedDir);
    const store = journal(directory);
    const child = controller(validFixture, store.append);
    await child.start();
    const outcome = await child.stop();
    assert.equal(outcome.state, 'FAILED');
    assert.equal(outcome.errorCode, 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED');
    assertHold(outcome);
  });
});

test('invalid runtime configuration is rejected without opening a socket', () => {
  for (const opts of [
    {}, { createRunner() {} },
    { createRunner() {}, ipc: { send() {} } },
    { createRunner() {}, ipc: { send() {}, disconnect() {} }, healthTimeoutMs: 0 },
  ]) {
    assert.throws(() => createGuardianChildRuntime(opts),
      { code: 'GUARDIAN_CHILD_RUNTIME_CONFIG_INVALID' });
  }
});


test('a crashed child after READY persists FAILED without deleting a prior clean receipt', async () => {
  await temporary(async (directory) => {
    const store = journal(directory);
    const initial = controller(validFixture, store.append);
    await initial.start();
    assert.equal((await initial.stop()).state, 'STOPPED');
    const crashFixture = path.join(directory, 'unexpected-exit.cjs');
    fs.copyFileSync(standaloneFixture, crashFixture);
    const crashed = controller(crashFixture, store.append);
    await crashed.start();
    const until = Date.now() + 1000;
    while (crashed.status().state === 'RUNNING' && Date.now() < until) {
      await new Promise((resolve) => setTimeout(resolve, 4));
    }
    assert.equal(crashed.status().state, 'FAILED');
    assertHold(crashed.status());
    const rows = observe(directory);
    assert.equal(rows.length, 2);
    assert.deepEqual(rows.map((row) => row.state), ['STOPPED', 'FAILED']);
    assert.equal(rows[1].hostStopped, false);
    assert.equal(rows[1].automaticRestartAllowed, false);
  });
});
