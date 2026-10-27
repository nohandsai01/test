'use strict';
// G23 local active child-health probe; no hosted D1, Check write or deploy.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalProcessController } =
  require('../merge-gate-install/guardian-candidate/guardian-local-process-controller.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const protectedChild = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const scriptedChild = path.join(__dirname, 'guardian-health-probe-child.cjs');
function sleep(ms) { return new Promise((done) => setTimeout(done, ms)); }
async function temp(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-health-probe-'));
  try { return await fn(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function child(directory, mode, timeout = 300) {
  const entrypoint = path.join(directory, mode + '.cjs');
  fs.copyFileSync(scriptedChild, entrypoint);
  const seen = [];
  const controller = createGuardianLocalProcessController({
    cwd: directory, entrypoint,
    onTerminal: (receipt) => seen.push(receipt),
    startupTimeoutMs: 1200, shutdownTimeoutMs: 300,
    healthProbeTimeoutMs: timeout,
  });
  return { controller, seen };
}
function hold(receipt) {
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.status, 'SOURCE_ONLY_HOLD');
  assert.equal(receipt.activationAllowed, false);
  assert.equal(receipt.releaseAuthority, 'NOT_ISSUED');
  assert.equal(receipt.automaticRestartAllowed, false);
  assert.equal(receipt.manualInterventionRequired, true);
  assert.equal(Object.isFrozen(receipt), true);
  assert.equal(Object.hasOwn(receipt, 'pid'), false);
  assert.equal(Object.hasOwn(receipt, 'token'), false);
}
function verified(value) {
  hold(value);
  assert.equal(value.observation, 'LOCAL_CHILD_HEALTH_VERIFIED');
  assert.equal(value.reason, 'GUARDIAN_CHILD_HEALTH_VERIFIED');
  assert.equal(value.liveness, 'LOCAL_IPC_AND_LOOPBACK_ONLY');
}
function unverified(value) {
  hold(value);
  assert.equal(value.observation, 'NOT_PROVEN');
  assert.equal(value.liveness, 'NOT_PROVEN');
}

test('real protected worker answers an active IPC + loopback health query only after READY', async () => {
  await temp(async (directory) => {
    const args = {
      directory, fileName: 'guardian-health.jsonl',
      cwd: path.dirname(protectedChild), entrypoint: protectedChild,
      startupTimeoutMs: 4000, shutdownTimeoutMs: 900,
      healthProbeTimeoutMs: 3000,
    };
    const session = createGuardianLocalOperatorSession(args);
    assert.equal(Object.hasOwn(session.operator, 'start'), false);
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
    assert.equal(Object.hasOwn(session.operator, 'reset'), false);
    const before = await session.operator.probeRuntime();
    unverified(before);
    assert.equal(before.processState, 'CREATED');
    assert.equal(fs.readdirSync(directory).length, 0);
    await session.owner.start();
    const actual = await session.operator.probeRuntime();
    verified(actual);
    assert.equal(actual.processState, 'RUNNING');
    assert.equal(fs.readdirSync(directory).length, 1); // generation ledger only
    // A second health probe checks afresh, rather than trusting READY forever.
    verified(await session.operator.probeRuntime());
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const after = await session.operator.probeRuntime();
    unverified(after);
    assert.equal(after.processState, 'STOPPED');
    assert.equal(fs.readdirSync(directory).length, 2); // journal + generation ledger
  });
});

test('concurrent active probes coalesce into one bounded child request', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-normal');
    try {
      await controller.start();
      const a = controller.probeRuntime();
      const b = controller.probeRuntime();
      const c = controller.probeRuntime();
      assert.strictEqual(a, b);
      assert.strictEqual(b, c);
      const results = await Promise.all([a, b, c]);
      results.forEach(verified);
      assert.equal(seen.length, 0);
      assert.equal(controller.status().state, 'RUNNING');
    } finally { await controller.stop(); }
  });
});

test('explicit child HEALTH=false never produces verified status or releases HOLD', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-unhealthy');
    try {
      await controller.start();
      const response = await controller.probeRuntime();
      unverified(response);
      assert.equal(response.reason, 'GUARDIAN_CHILD_HEALTH_UNVERIFIED');
      assert.equal(controller.status().state, 'RUNNING');
      const again = await controller.probeRuntime();
      unverified(again);
      assert.equal(again.reason, 'GUARDIAN_CHILD_PROBE_UNAVAILABLE');
      assert.equal(seen.length, 0);
    } finally { await controller.stop(); }
  });
});

test('unresponsive child probe reaches deadline, latches uncertain without auto-restart', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-unresponsive', 65);
    try {
      await controller.start();
      const start = Date.now();
      const result = await controller.probeRuntime();
      unverified(result);
      assert.equal(result.reason, 'GUARDIAN_CHILD_PROBE_TIMEOUT');
      assert.ok(Date.now() - start < 600);
      assert.equal(controller.status().state, 'RUNNING');
      assert.equal((await controller.probeRuntime()).reason,
        'GUARDIAN_CHILD_PROBE_UNAVAILABLE');
      assert.equal(seen.length, 0);
    } finally { await controller.stop(); }
  });
});

test('late reply to a timed-out exact challenge cannot resurrect verified liveness', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-late', 60);
    try {
      await controller.start();
      const result = await controller.probeRuntime();
      unverified(result);
      assert.equal(result.reason, 'GUARDIAN_CHILD_PROBE_TIMEOUT');
      await sleep(175);
      assert.equal(controller.status().state, 'RUNNING');
      assert.equal(seen.length, 0);
      unverified(await controller.probeRuntime());
    } finally { await controller.stop(); }
  });
});

test('forged nonce cannot satisfy owner challenge; invalid protocol latches controller FAILED', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-forged');
    try {
      await controller.start();
      const result = await controller.probeRuntime();
      unverified(result);
      assert.equal(result.reason, 'GUARDIAN_CHILD_PROBE_TERMINATED');
      assert.equal(controller.status().state, 'FAILED');
      assert.equal(seen.length, 1);
      assert.equal(seen[0].state, 'FAILED');
      assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_PROTOCOL_INVALID');
      assert.equal(seen[0].hostStopped, false);
    } finally { await controller.stop(); }
  });
});

test('unrecognized field in health response is protocol failure, not an accepted observation', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-extra-field');
    try {
      await controller.start();
      const result = await controller.probeRuntime();
      unverified(result);
      assert.equal(controller.status().state, 'FAILED');
      assert.equal(seen.length, 1);
      assert.equal(seen[0].errorCode, 'GUARDIAN_CHILD_PROTOCOL_INVALID');
    } finally { await controller.stop(); }
  });
});

test('unsolicited health reply cannot spoof a RUNNING observation', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-unsolicited');
    try {
      await controller.start();
      await sleep(95);
      assert.equal(controller.status().state, 'FAILED');
      assert.equal(seen.length, 1);
      const result = await controller.probeRuntime();
      unverified(result);
    } finally { await controller.stop(); }
  });
});

test('Owner stop racing a pending probe returns NOT_PROVEN without delaying termination', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-stopping', 250);
    await controller.start();
    const inFlight = controller.probeRuntime();
    const stopping = controller.stop();
    const probe = await inFlight;
    unverified(probe);
    assert.equal(probe.reason, 'GUARDIAN_CHILD_PROBE_STOPPING');
    assert.equal((await stopping).state, 'STOPPED');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].state, 'STOPPED');
  });
});

test('probe constructor timeout limits are fail-closed before child spawn', async () => {
  await temp(async (directory) => {
    const entrypoint = path.join(directory, 'probe-normal.cjs');
    fs.copyFileSync(scriptedChild, entrypoint);
    for (const healthProbeTimeoutMs of [-1, 0, 49, 5001, '300', 200.5]) {
      assert.throws(() => createGuardianLocalProcessController({
        cwd: directory, entrypoint,
        healthProbeTimeoutMs, onTerminal: () => {},
      }), /GUARDIAN_CHILD_TIMEOUT_INVALID/);
    }
    assert.equal(fs.readdirSync(directory).length, 1);
  });
});

test('no health probe can start or restart child after explicit owner stop', async () => {
  await temp(async (directory) => {
    const { controller, seen } = child(directory, 'probe-normal');
    const result = await controller.stop();
    assert.equal(result.state, 'STOPPED');
    const health = await controller.probeRuntime();
    unverified(health);
    assert.equal(health.processState, 'STOPPED');
    assert.equal(seen.length, 1);
    await assert.rejects(controller.start(), { code: 'GUARDIAN_CHILD_STATE_INVALID' });
  });
});
