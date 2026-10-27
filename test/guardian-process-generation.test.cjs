'use strict';
// G27-G30: durable process generation identity, IPC binding, cross-process
// crash evidence and fail-closed negatives. Offline, disposable temp paths;
// no Cloudflare D1, GitHub App, Check publication or deploy.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { EventEmitter } = require('node:events');
const candidate = '../merge-gate-install/guardian-candidate/';
const { createGuardianLocalProcessController } =
  require(candidate + 'guardian-local-process-controller.cjs');
const { createGuardianChildRuntime } =
  require(candidate + 'guardian-child-runtime.cjs');
const { createGuardianLocalReceiptJournal, generationLedgerName } =
  require(candidate + 'guardian-local-receipt-journal.cjs');
const { createGuardianLocalDiagnostics } =
  require(candidate + 'guardian-local-diagnostics.cjs');
const { createGuardianLocalHealthObservation } =
  require(candidate + 'guardian-local-health-observation.cjs');
const { createGuardianLocalRuntimeAssessment } =
  require(candidate + 'guardian-local-runtime-assessment.cjs');
const { createGuardianLocalOperatorSession } =
  require(candidate + 'guardian-local-operator-session.cjs');

const controllerFixture = path.join(__dirname, 'guardian-local-controller-child.cjs');
const probeFixture = path.join(__dirname, 'guardian-health-probe-child.cjs');
const crashParent = path.join(__dirname, 'guardian-generation-crash-parent.cjs');
const FILE = 'guardian-generation.jsonl';
const GEN = /^[0-9a-f]{32}$/;
const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V2';

async function temp(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g27-'));
  try { return await fn(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function fixture(directory, scenario, source = controllerFixture) {
  const entrypoint = path.join(directory, scenario + '.cjs');
  fs.copyFileSync(source, entrypoint);
  return entrypoint;
}
function controller(entrypoint, extra = {}) {
  const seen = [], launches = [];
  const ctrl = createGuardianLocalProcessController({
    cwd: path.dirname(entrypoint), entrypoint,
    startupTimeoutMs: 1500, shutdownTimeoutMs: 400,
    onTerminal: (receipt) => seen.push(receipt),
    onLaunch: (launch) => launches.push(launch),
    ...extra,
  });
  return { ctrl, seen, launches };
}
function journalRows(directory, name = FILE) {
  const target = path.join(directory, name);
  if (!fs.existsSync(target)) return [];
  return fs.readFileSync(target, 'utf8').trim().split('\n')
    .filter(Boolean).map((line) => JSON.parse(line));
}
function stopReceipt(generationId, state = 'STOPPED', errorCode = null) {
  return Object.freeze({
    state, errorCode, hostStopped: state === 'STOPPED',
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false, generationId,
  });
}
function launch(generationId) {
  return Object.freeze({ generationId, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED' });
}
function fakeController(state, generationId, pid = 4242) {
  return { status: () => ({
    state, pid: state === 'CREATED' ? null : pid, errorCode: null,
    generationId, activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  }) };
}
function triageFor(directory, ctrl) {
  return createGuardianLocalDiagnostics({
    controller: ctrl, directory, fileName: FILE,
  }).faultTriage();
}
function assertHold(value) {
  assert.equal(value.status, 'SOURCE_ONLY_HOLD');
  assert.equal(value.activationAllowed, false);
  assert.equal(value.releaseAuthority, 'NOT_ISSUED');
  assert.equal(value.automaticRestartAllowed, false);
}
const randomGeneration = () => crypto.randomBytes(16).toString('hex');

// ---------------------------------------------------------------- G27 --

test('G27: every start issues a fresh generation recorded before spawn and bound to READY/terminal', async () => {
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'normal');
    const ids = new Set();
    for (let i = 0; i < 3; i++) {
      const { ctrl, seen, launches } = controller(entrypoint);
      assert.equal(ctrl.status().generationId, null);
      const ready = await ctrl.start();
      assert.equal(ready.state, 'RUNNING');
      assert.match(ready.generationId, GEN);
      assert.equal(launches.length, 1);
      assert.equal(launches[0].generationId, ready.generationId);
      assert.equal(Object.isFrozen(launches[0]), true);
      const stopped = await ctrl.stop();
      assert.equal(stopped.state, 'STOPPED');
      assert.equal(stopped.generationId, ready.generationId);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].generationId, ready.generationId);
      ids.add(ready.generationId);
    }
    assert.equal(ids.size, 3);
  });
});

test('G27: launch evidence failure refuses to spawn and never reports RUNNING', async () => {
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'normal');
    for (const onLaunch of [
      () => { throw new Error('synthetic ledger write failure'); },
      async () => {},
    ]) {
      const { ctrl, seen } = controller(entrypoint, { onLaunch });
      await assert.rejects(ctrl.start(),
        { code: 'GUARDIAN_CHILD_LAUNCH_RECORD_FAILED' });
      const status = ctrl.status();
      assert.equal(status.state, 'FAILED');
      assert.equal(status.pid, null);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].hostStopped, false);
      assert.equal(seen[0].generationId, status.generationId);
      assertHold({ ...status, status: 'SOURCE_ONLY_HOLD' });
    }
    assert.throws(() => createGuardianLocalProcessController({
      cwd: directory, entrypoint, onTerminal() {}, onLaunch: 'not a function',
    }), { code: 'GUARDIAN_CHILD_CONFIG_INVALID' });
  });
});

test('G27: stop before start yields an unbound receipt and never a generation', async () => {
  await temp(async (directory) => {
    const { ctrl, seen, launches } = controller(fixture(directory, 'normal'));
    assert.equal((await ctrl.stop()).state, 'STOPPED');
    assert.equal(seen[0].generationId, null);
    assert.equal(launches.length, 0);
  });
});

// ---------------------------------------------------------------- G28 --

test('G28: READY for a foreign generation is a GENERATION_MISMATCH, never RUNNING', async () => {
  await temp(async (directory) => {
    const { ctrl, seen } = controller(fixture(directory, 'wrong-generation-ready'));
    await assert.rejects(ctrl.start(), { code: 'GUARDIAN_CHILD_GENERATION_MISMATCH' });
    assert.equal(ctrl.status().state, 'FAILED');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_GENERATION_MISMATCH');
    assert.equal(seen[0].hostStopped, false);
  });
});

test('G28: READY without the HELLO/BIND handshake is rejected even if it guesses a generation', async () => {
  await temp(async (directory) => {
    const { ctrl, seen } = controller(fixture(directory, 'unbound-ready'));
    await assert.rejects(ctrl.start(), { code: 'GUARDIAN_CHILD_PROTOCOL_INVALID' });
    assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_PROTOCOL_INVALID');
  });
});

test('G28: a second HELLO (rebind attempt) is a protocol failure', async () => {
  await temp(async (directory) => {
    const { ctrl, seen } = controller(fixture(directory, 'double-hello'));
    await assert.rejects(ctrl.start(), { code: 'GUARDIAN_CHILD_PROTOCOL_INVALID' });
    assert.equal(ctrl.status().state, 'FAILED');
    assert.equal(seen.length, 1);
  });
});

test('G28: a TERMINAL frame for another generation can never produce a clean STOPPED', async () => {
  await temp(async (directory) => {
    const { ctrl, seen } = controller(fixture(directory, 'foreign-terminal'));
    await ctrl.start();
    const final = await ctrl.stop();
    assert.equal(final.state, 'FAILED');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].state, 'FAILED');
    assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_GENERATION_MISMATCH');
  });
});

test('G28: a health result echoing the right challenge under another generation fails closed', async () => {
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'probe-wrong-generation', probeFixture);
    const { ctrl, seen } = controller(entrypoint, { healthProbeTimeoutMs: 300 });
    try {
      await ctrl.start();
      const result = await ctrl.probeRuntime();
      assert.equal(result.observation, 'NOT_PROVEN');
      assert.equal(ctrl.status().state, 'FAILED');
      assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_GENERATION_MISMATCH');
    } finally { await ctrl.stop(); }
  });
});

test('G28: replaying an already-answered health result is a protocol failure, not a second proof', async () => {
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'probe-replay', probeFixture);
    const { ctrl, seen } = controller(entrypoint, { healthProbeTimeoutMs: 300 });
    try {
      await ctrl.start();
      const first = await ctrl.probeRuntime();
      assert.equal(first.observation, 'LOCAL_CHILD_HEALTH_VERIFIED');
      assert.equal(first.generationId, ctrl.status().generationId);
      const second = await ctrl.probeRuntime();
      assert.equal(second.observation, 'NOT_PROVEN');
      assert.equal(ctrl.status().state, 'FAILED');
      assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_PROTOCOL_INVALID');
    } finally { await ctrl.stop(); }
  });
});

test('G28: child runtime binds once, ignores rebind, and never answers another generation', async () => {
  const server = http.createServer((_, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ running: true, feature: 'OFF_OR_SOURCE_ONLY',
      releaseAuthority: 'NOT_ISSUED' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    const ipc = new EventEmitter();
    ipc.connected = true;
    const sent = [];
    const generation = randomGeneration();
    ipc.send = (frame, callback) => {
      sent.push(frame);
      callback?.();
      if (frame.event === 'HELLO') {
        setImmediate(() => {
          ipc.emit('message', { protocol: PROTOCOL, event: 'BIND', generation,
            activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
          ipc.emit('message', { protocol: PROTOCOL, event: 'BIND',
            generation: randomGeneration(),
            activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
        });
      }
    };
    ipc.disconnect = () => { ipc.connected = false; };
    const runtime = createGuardianChildRuntime({ ipc,
      createRunner: () => ({
        async start() {}, async stop() {},
        status: () => ({ state: 'RUNNING', activationAllowed: false,
          releaseAuthority: 'NOT_ISSUED',
          loopback: { address: '127.0.0.1', port } }),
      }),
    });
    const started = await runtime.start();
    assert.equal(started.state, 'RUNNING');
    assert.equal(runtime.status().generationBound, true);
    const ready = sent.find((frame) => frame.event === 'READY');
    assert.equal(ready.generation, generation);
    const probe = (gen, challenge) => ipc.emit('message', {
      protocol: PROTOCOL, event: 'HEALTH_PROBE', generation: gen, challenge,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
    probe(randomGeneration(), 'a'.repeat(32));
    probe(generation, 'b'.repeat(32));
    const until = Date.now() + 2000;
    while (!sent.some((f) => f.event === 'HEALTH_RESULT') && Date.now() < until) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    const results = sent.filter((frame) => frame.event === 'HEALTH_RESULT');
    assert.equal(results.length, 1);
    assert.equal(results[0].challenge, 'b'.repeat(32));
    assert.equal(results[0].generation, generation);
    assert.equal(results[0].healthy, true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('G28: child runtime without a BIND never sends READY and stops its runner', async () => {
  const server = http.createServer((_, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ running: true, feature: 'OFF_OR_SOURCE_ONLY',
      releaseAuthority: 'NOT_ISSUED' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    const ipc = new EventEmitter();
    ipc.connected = true;
    const sent = [];
    ipc.send = (frame, callback) => { sent.push(frame); callback?.(); };
    ipc.disconnect = () => { ipc.connected = false; };
    let stops = 0;
    const runtime = createGuardianChildRuntime({ ipc, bindTimeoutMs: 60,
      createRunner: () => ({
        async start() {}, async stop() { stops++; },
        status: () => ({ state: 'RUNNING', activationAllowed: false,
          releaseAuthority: 'NOT_ISSUED',
          loopback: { address: '127.0.0.1', port } }),
      }),
    });
    await assert.rejects(runtime.start(),
      { code: 'GUARDIAN_CHILD_RUNTIME_START_UNVERIFIED' });
    assert.equal(stops, 1);
    assert.deepEqual(sent.map((frame) => frame.event), ['HELLO']);
    assert.equal(runtime.status().generationBound, false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('G28: PID reuse by a new generation invalidates an earlier health sample', async () => {
  const first = randomGeneration();
  let current = fakeController('RUNNING', first, 7777);
  const ctrl = {
    status: () => current.status(),
    probeRuntime: async () => Object.freeze({
      schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
      observation: 'LOCAL_CHILD_HEALTH_VERIFIED',
      reason: 'GUARDIAN_CHILD_HEALTH_VERIFIED', processState: 'RUNNING',
      generationId: first, liveness: 'LOCAL_IPC_AND_LOOPBACK_ONLY',
      manualInterventionRequired: true, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
    }),
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl,
    maxAgeMs: 5000 });
  await observer.probe();
  assert.equal(observer.observe().freshness, 'RECENT');
  // Same PID, same RUNNING state, different process generation.
  current = fakeController('RUNNING', randomGeneration(), 7777);
  const after = observer.observe();
  assert.equal(after.freshness, 'UNVERIFIED');
  assert.equal(after.reason, 'GUARDIAN_HEALTH_CHILD_STATE_CHANGED');
  // And the stale sample is gone for good, even if the old identity returns.
  current = fakeController('RUNNING', first, 7777);
  assert.equal(observer.observe().reason, 'GUARDIAN_HEALTH_NO_VALID_SAMPLE');
});

test('G28: a verified probe receipt for another generation never becomes a sample', async () => {
  const live = randomGeneration();
  const ctrl = {
    status: () => fakeController('RUNNING', live).status(),
    probeRuntime: async () => Object.freeze({
      schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
      observation: 'LOCAL_CHILD_HEALTH_VERIFIED',
      reason: 'GUARDIAN_CHILD_HEALTH_VERIFIED', processState: 'RUNNING',
      generationId: randomGeneration(), liveness: 'LOCAL_IPC_AND_LOOPBACK_ONLY',
      manualInterventionRequired: true, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
    }),
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  const result = await observer.probe();
  assert.equal(result.observation, 'NOT_PROVEN');
  assert.equal(result.reason, 'GUARDIAN_HEALTH_CHILD_STATE_CHANGED');
  assert.equal(observer.observe().freshness, 'UNVERIFIED');
});

test('G28: runtime assessment is P0 when the generation changes under an unchanged PID', () => {
  const generations = [randomGeneration(), randomGeneration()];
  let reads = 0;
  const ctrl = { status() {
    reads++;
    return fakeController('RUNNING', generations[reads > 1 ? 1 : 0], 9000).status();
  } };
  const diagnostics = { faultTriage: () => { throw new Error('unreachable'); } };
  const healthObservation = { observe: () => { throw new Error('unreachable'); } };
  const triage = Object.freeze({
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION', status: 'SOURCE_ONLY_HOLD',
    priority: 'P2', classification: 'PROCESS_STATE_UNPROVEN',
    nextAction: 'OWNER_RECONCILE_LIFECYCLE',
    sourceReason: 'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE', processState: 'RUNNING',
    liveness: 'NOT_PROVEN', journalEntries: 1, journalSha256: 'a'.repeat(64),
    failureCount: 0, unterminatedGenerations: 0,
    manualInterventionRequired: true, automaticRestartAllowed: false,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
  });
  diagnostics.faultTriage = () => triage;
  const result = createGuardianLocalRuntimeAssessment({
    controller: ctrl, diagnostics, healthObservation,
  }).assess();
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'LOCAL_OBSERVATION_UNVERIFIED');
  assertHold(result);
});

// ------------------------------------------------------------ G29/G30 --

test('G29: journal writes v2 bound receipts and an owner-only launch ledger; rejects malformed input', async () => {
  await temp(async (directory) => {
    const store = createGuardianLocalReceiptJournal({ directory, fileName: FILE });
    const id = randomGeneration();
    assert.equal(store.recordLaunch(launch(id)).persisted, true);
    assert.equal(store.append(stopReceipt(id)).persisted, true);
    const [row] = journalRows(directory);
    assert.equal(row.schemaVersion, 2);
    assert.equal(row.generationId, id);
    const ledgerName = generationLedgerName(FILE);
    assert.equal(ledgerName, 'guardian-generation.generations.jsonl');
    const [entry] = journalRows(directory, ledgerName);
    assert.equal(entry.kind, 'GUARDIAN_GENERATION_LAUNCH_V1');
    assert.equal(entry.generationId, id);
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(path.join(directory, ledgerName)).mode & 0o077, 0);
    }
    for (const bad of ['ABC', 'g'.repeat(32), 42, undefined]) {
      assert.throws(() => store.recordLaunch(launch(bad)),
        { code: 'GUARDIAN_JOURNAL_LAUNCH_INVALID' });
      assert.throws(() => store.append(stopReceipt(bad)),
        { code: 'GUARDIAN_JOURNAL_RECEIPT_INVALID' });
    }
    assert.throws(() => store.recordLaunch({ ...launch(id), extra: true }),
      { code: 'GUARDIAN_JOURNAL_LAUNCH_INVALID' });
    assert.throws(() => store.recordLaunch({ ...launch(id), releaseAuthority: 'ISSUED' }),
      { code: 'GUARDIAN_JOURNAL_LAUNCH_INVALID' });
  });
});

test('G29: a launched generation without a terminal receipt is durable P1 HOLD, never cleared by later clean runs', async () => {
  await temp(async (directory) => {
    const store = createGuardianLocalReceiptJournal({ directory, fileName: FILE });
    const crashed = randomGeneration();
    store.recordLaunch(launch(crashed)); // parent died before any terminal
    const fresh = triageFor(directory, fakeController('CREATED', null));
    assert.equal(fresh.priority, 'P1');
    assert.equal(fresh.classification, 'UNTERMINATED_GENERATION');
    assert.equal(fresh.nextAction, 'OWNER_RECONCILE_INTERRUPTED_GENERATION');
    assert.equal(fresh.unterminatedGenerations, 1);
    assert.equal(fresh.manualInterventionRequired, true);
    assertHold(fresh);
    for (let i = 0; i < 3; i++) {
      const clean = randomGeneration();
      store.recordLaunch(launch(clean));
      store.append(stopReceipt(clean));
      const later = triageFor(directory, fakeController('STOPPED', clean));
      assert.equal(later.priority, 'P1');
      assert.equal(later.classification, 'UNTERMINATED_GENERATION');
      assert.equal(later.unterminatedGenerations, 1);
      assert.equal(later.failureCount, 0);
    }
  });
});

test('G29: the controller\'s own live generation is not mistaken for a crash', async () => {
  await temp(async (directory) => {
    const store = createGuardianLocalReceiptJournal({ directory, fileName: FILE });
    const done = randomGeneration(), live = randomGeneration();
    store.recordLaunch(launch(done));
    store.append(stopReceipt(done));
    store.recordLaunch(launch(live));
    const running = triageFor(directory, fakeController('RUNNING', live));
    assert.equal(running.priority, 'P2');
    assert.equal(running.unterminatedGenerations, 0);
    // Once that controller is terminal without a receipt, it is unterminated.
    const lost = triageFor(directory, fakeController('FAILED', live));
    assert.equal(lost.priority, 'P1');
    assert.equal(lost.classification, 'UNTERMINATED_GENERATION');
  });
});

test('G30: replayed, unknown, reused or unledgered generation evidence is P0 fail-closed', async () => {
  const cases = {
    'duplicate terminal (replay)': (store) => {
      const id = randomGeneration();
      store.recordLaunch(launch(id));
      store.append(stopReceipt(id));
      store.append(stopReceipt(id));
    },
    'terminal for a never-launched generation': (store) => {
      store.recordLaunch(launch(randomGeneration()));
      store.append(stopReceipt(randomGeneration()));
    },
    'reused generation in the ledger': (store) => {
      const id = randomGeneration();
      store.recordLaunch(launch(id));
      store.append(stopReceipt(id));
      store.recordLaunch(launch(id));
    },
    'bound receipt with no ledger at all': (store) => {
      store.append(stopReceipt(randomGeneration()));
    },
  };
  for (const [name, arrange] of Object.entries(cases)) {
    await temp(async (directory) => {
      arrange(createGuardianLocalReceiptJournal({ directory, fileName: FILE }));
      const ctrl = fakeController('STOPPED', null);
      const triage = triageFor(directory, ctrl);
      assert.equal(triage.priority, 'P0', name);
      assert.equal(triage.classification, 'EVIDENCE_UNVERIFIED', name);
      const inspected = createGuardianLocalDiagnostics({
        controller: ctrl, directory, fileName: FILE }).inspect();
      assert.equal(inspected.reason,
        'GUARDIAN_DIAGNOSTICS_GENERATION_INCONSISTENT', name);
      assert.equal(inspected.manualInterventionRequired, true, name);
    });
  }
});

test('G30: a live controller generation absent from the ledger is P0', async () => {
  await temp(async (directory) => {
    const store = createGuardianLocalReceiptJournal({ directory, fileName: FILE });
    const id = randomGeneration();
    store.recordLaunch(launch(id));
    store.append(stopReceipt(id));
    const triage = triageFor(directory, fakeController('RUNNING', randomGeneration()));
    assert.equal(triage.priority, 'P0');
  });
});

test('G30: corrupted ledger bytes are P0 and never treated as missing', async () => {
  await temp(async (directory) => {
    const store = createGuardianLocalReceiptJournal({ directory, fileName: FILE });
    const id = randomGeneration();
    store.recordLaunch(launch(id));
    store.append(stopReceipt(id));
    fs.appendFileSync(path.join(directory, generationLedgerName(FILE)),
      '{"schemaVersion":1}\n');
    const inspected = createGuardianLocalDiagnostics({
      controller: fakeController('STOPPED', id), directory, fileName: FILE,
    }).inspect();
    assert.equal(inspected.reason,
      'GUARDIAN_DIAGNOSTICS_GENERATION_LEDGER_UNVERIFIED');
    assert.equal(triageFor(directory, fakeController('STOPPED', id)).priority, 'P0');
  });
});

test('G30: a controller generation that changes during a diagnostics read is rejected', async () => {
  await temp(async (directory) => {
    const store = createGuardianLocalReceiptJournal({ directory, fileName: FILE });
    const a = randomGeneration(), b = randomGeneration();
    store.recordLaunch(launch(a));
    store.recordLaunch(launch(b));
    let reads = 0;
    const ctrl = { status: () => fakeController('RUNNING', reads++ ? b : a).status() };
    const inspected = createGuardianLocalDiagnostics({
      controller: ctrl, directory, fileName: FILE }).inspect();
    assert.equal(inspected.reason,
      'GUARDIAN_DIAGNOSTICS_CONTROLLER_CHANGED_DURING_READ');
  });
});

test('G30: concurrent sessions on one journal get distinct generations and reconcile cleanly once stopped', async () => {
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'normal');
    const sessions = Array.from({ length: 3 }, () =>
      createGuardianLocalOperatorSession({
        directory, fileName: FILE, cwd: directory, entrypoint,
        startupTimeoutMs: 2000, shutdownTimeoutMs: 600,
      }));
    const started = await Promise.all(sessions.map((s) => s.owner.start()));
    const ids = started.map((ready) => ready.generationId);
    assert.equal(new Set(ids).size, 3);
    ids.forEach((id) => assert.match(id, GEN));
    // While siblings are live, each Operator sees the others as unterminated.
    assert.equal(sessions[0].operator.faultTriage().priority, 'P1');
    const stopped = await Promise.all(sessions.map((s) => s.owner.stop()));
    stopped.forEach((s) => assert.equal(s.state, 'STOPPED'));
    const rows = journalRows(directory);
    assert.deepEqual(rows.map((row) => row.generationId).sort(), [...ids].sort());
    for (const session of sessions) {
      const triage = session.operator.faultTriage();
      assert.equal(triage.priority, 'P3');
      assert.equal(triage.unterminatedGenerations, 0);
      assertHold(triage);
    }
  });
});

test('G29: real Owner parent SIGKILL leaves durable crash evidence a new session cannot clear', async () => {
  if (process.platform === 'win32') return; // POSIX signal semantics only
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'orphan-exit');
    const parent = spawn(process.execPath, [crashParent, directory, FILE, entrypoint],
      { stdio: ['ignore', 'pipe', 'ignore'] });
    let output = '';
    parent.stdout.on('data', (chunk) => { output += chunk; });
    const [code, signal] = await new Promise((resolve) =>
      parent.once('exit', (...args) => resolve(args)));
    assert.equal(code, null);
    assert.equal(signal, 'SIGKILL');
    const match = /^STARTED ([0-9a-f]{32})$/m.exec(output);
    assert.ok(match, 'crash parent reached RUNNING before dying');
    const crashed = match[1];
    assert.deepEqual(journalRows(directory), []);
    const ledger = journalRows(directory, generationLedgerName(FILE));
    assert.deepEqual(ledger.map((row) => row.generationId), [crashed]);

    const session = createGuardianLocalOperatorSession({
      directory, fileName: FILE, cwd: directory, entrypoint,
      startupTimeoutMs: 2000, shutdownTimeoutMs: 600,
    });
    const before = session.operator.faultTriage();
    assert.equal(before.priority, 'P1');
    assert.equal(before.classification, 'UNTERMINATED_GENERATION');
    // A new, perfectly healthy generation does not erase the crash.
    const ready = await session.owner.start();
    assert.notEqual(ready.generationId, crashed);
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const after = session.operator.faultTriage();
    assert.equal(after.priority, 'P1');
    assert.equal(after.classification, 'UNTERMINATED_GENERATION');
    assert.equal(after.unterminatedGenerations, 1);
    const assessment = session.operator.assessRuntime();
    assert.equal(assessment.priority, 'P1');
    assert.equal(assessment.unterminatedGenerations, 1);
    assertHold(assessment);
  });
});

test('G29: the Operator facade stays read-only and observing never mutates evidence', async () => {
  await temp(async (directory) => {
    const entrypoint = fixture(directory, 'normal');
    const session = createGuardianLocalOperatorSession({
      directory, fileName: FILE, cwd: directory, entrypoint,
      startupTimeoutMs: 2000, shutdownTimeoutMs: 600,
    });
    for (const name of ['start', 'stop', 'reset', 'restart', 'recordLaunch', 'append']) {
      assert.equal(Object.hasOwn(session.operator, name), false, name);
    }
    await session.owner.start();
    await session.owner.stop();
    const digest = (name) => crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(directory, name))).digest('hex');
    const before = [digest(FILE), digest(generationLedgerName(FILE))];
    session.operator.inspect();
    session.operator.faultTriage();
    session.operator.assessRuntime();
    session.operator.recentEvents();
    await session.operator.probeRuntime();
    assert.deepEqual([digest(FILE), digest(generationLedgerName(FILE))], before);
  });
});
