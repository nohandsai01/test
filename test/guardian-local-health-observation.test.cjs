'use strict';
// G24 passive freshness snapshots of bounded Guardian child health probes.
// Source-only fixtures: no Cloudflare D1, real GitHub App, Check or deploy.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalHealthObservation } =
  require('../merge-gate-install/guardian-candidate/guardian-local-health-observation.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');

function controllerStatus(state = 'RUNNING', pid = 2222) {
  return {
    state, pid, errorCode: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  };
}
function successfulProbe() {
  return Object.freeze({
    schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
    observation: 'LOCAL_CHILD_HEALTH_VERIFIED',
    reason: 'GUARDIAN_CHILD_HEALTH_VERIFIED',
    processState: 'RUNNING', liveness: 'LOCAL_IPC_AND_LOOPBACK_ONLY',
    manualInterventionRequired: true, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
  });
}
function failedProbe() {
  return Object.freeze({
    schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
    observation: 'NOT_PROVEN', reason: 'GUARDIAN_CHILD_HEALTH_UNVERIFIED',
    processState: 'RUNNING', liveness: 'NOT_PROVEN',
    manualInterventionRequired: true, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
  });
}
function hold(value) {
  assert.equal(value.status, 'SOURCE_ONLY_HOLD');
  assert.equal(value.activationAllowed, false);
  assert.equal(value.releaseAuthority, 'NOT_ISSUED');
  assert.equal(value.automaticRestartAllowed, false);
  assert.equal(value.manualInterventionRequired, true);
  assert.ok(Object.isFrozen(value));
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function temp(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g24-'));
  try { await fn(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test('construction and passive inspect perform zero child IPC or status reads', () => {
  let calls = 0;
  const ctrl = {
    status() { calls++; return controllerStatus(); },
    async probeRuntime() { throw new Error('should not invoke'); },
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  assert.ok(Object.isFrozen(observer));
  assert.deepEqual(Object.keys(observer).sort(), ['observe', 'probe']);
  assert.equal(calls, 0);
  const state = observer.observe();
  assert.equal(calls, 1);
  assert.equal(state.reason, 'GUARDIAN_HEALTH_NO_VALID_SAMPLE');
  hold(state);
  assert.equal(state.freshness, 'UNVERIFIED');
  assert.equal(state.liveness, 'NOT_PROVEN');
});

test('fresh success means historical IPC and loopback evidence, not live authority', async () => {
  let issued = 0;
  const ctrl = {
    status() { return controllerStatus(); },
    async probeRuntime() { issued++; return successfulProbe(); },
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl, maxAgeMs: 300 });
  hold(await observer.probe());
  const snapshot = observer.observe();
  hold(snapshot);
  assert.equal(snapshot.freshness, 'RECENT');
  assert.equal(snapshot.observation, 'LOCAL_CHILD_HEALTH_OBSERVED_RECENTLY');
  assert.equal(snapshot.liveness, 'NOT_PROVEN');
  assert.equal(snapshot.reason, 'GUARDIAN_HEALTH_RECENT_SAMPLE_ONLY');
  assert.ok(snapshot.ageMs >= 0 && snapshot.ageMs <= 300);
  assert.equal(snapshot.maxAgeMs, 300);
  assert.match(snapshot.sampledAt, /^\d{4}-\d\d-\d\dT/);
  assert.equal(issued, 1);
  assert.equal(Object.hasOwn(snapshot, 'pid'), false);
  assert.equal(Object.hasOwn(snapshot, 'rawPayload'), false);
  assert.equal(Object.hasOwn(snapshot, 'restart'), false);
});

test('observation automatically expires with monotonic age; passive reads never re-probe', async () => {
  let issued = 0;
  const ctrl = {
    status: () => controllerStatus(),
    probeRuntime: async () => { issued++; return successfulProbe(); },
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl, maxAgeMs: 50 });
  await observer.probe();
  assert.equal(observer.observe().freshness, 'RECENT');
  await sleep(83);
  const expired = observer.observe();
  hold(expired);
  assert.equal(expired.freshness, 'EXPIRED');
  assert.equal(expired.observation, 'NOT_PROVEN');
  assert.equal(expired.reason, 'GUARDIAN_HEALTH_SAMPLE_EXPIRED');
  assert.equal(expired.sampledAt, null);
  assert.equal(observer.observe().reason, 'GUARDIAN_HEALTH_NO_VALID_SAMPLE');
  assert.equal(issued, 1);
});

test('controller stops, fails, changes PID or error code: no cached success survives', async () => {
  for (const change of [
    { state: 'STOPPING' }, { state: 'STOPPED' },
    { state: 'FAILED' }, { pid: 3333 },
    { errorCode: 'GUARDIAN_CHILD_PROBE_TIMEOUT' },
  ]) {
    let state = controllerStatus();
    const ctrl = {
      status: () => state,
      probeRuntime: async () => successfulProbe(),
    };
    const observer = createGuardianLocalHealthObservation({ controller: ctrl });
    await observer.probe();
    assert.equal(observer.observe().freshness, 'RECENT');
    state = { ...state, ...change };
    const after = observer.observe();
    hold(after);
    assert.equal(after.freshness, 'UNVERIFIED');
    assert.equal(after.observation, 'NOT_PROVEN');
    assert.equal(after.liveness, 'NOT_PROVEN');
    assert.ok(after.reason === 'GUARDIAN_HEALTH_CHILD_STATE_CHANGED' ||
      after.reason === 'GUARDIAN_HEALTH_CHILD_NOT_RUNNING');
    // Restoring the state alone cannot restore expired evidence.
    state = controllerStatus();
    assert.equal(observer.observe().freshness, 'UNVERIFIED');
  }
});

test('child PID changes during probe: verified frame is downgraded to NOT_PROVEN', async () => {
  let state = controllerStatus();
  const ctrl = {
    status: () => state,
    async probeRuntime() {
      state = controllerStatus('RUNNING', 9999);
      return successfulProbe();
    },
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  const response = await observer.probe();
  hold(response);
  assert.equal(response.observation, 'NOT_PROVEN');
  assert.equal(response.reason, 'GUARDIAN_HEALTH_CHILD_STATE_CHANGED');
  assert.equal(observer.observe().freshness, 'UNVERIFIED');
});

test('malformed controller or forged child response is not cached or exposed', async () => {
  let invoked = 0;
  const badController = {
    status() { return { ...controllerStatus(), activationAllowed: true }; },
    probeRuntime() { invoked++; return Promise.resolve(successfulProbe()); },
  };
  const blocked = createGuardianLocalHealthObservation({ controller: badController });
  const result = await blocked.probe();
  hold(result);
  assert.equal(invoked, 0);
  assert.equal(result.observation, 'NOT_PROVEN');
  assert.equal(blocked.observe().freshness, 'UNVERIFIED');

  const ctrl = {
    status: () => controllerStatus(),
    probeRuntime: () => Promise.resolve({ ...successfulProbe(), token: 'SECRET' }),
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  const forged = await observer.probe();
  hold(forged);
  assert.equal(forged.reason, 'GUARDIAN_HEALTH_PROBE_UNVERIFIED');
  assert.equal(JSON.stringify(forged).includes('SECRET'), false);
  assert.equal(observer.observe().observation, 'NOT_PROVEN');
});

test('negative health response invalidates prior green; does not grant auto retry', async () => {
  let calls = 0;
  const ctrl = {
    status: () => controllerStatus(),
    probeRuntime: () => Promise.resolve(++calls === 1 ?
      successfulProbe() : failedProbe()),
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  assert.equal((await observer.probe()).observation, 'LOCAL_CHILD_HEALTH_VERIFIED');
  assert.equal(observer.observe().freshness, 'RECENT');
  const failed = await observer.probe();
  hold(failed);
  assert.equal(failed.observation, 'NOT_PROVEN');
  assert.equal(observer.observe().freshness, 'UNVERIFIED');
  assert.equal(calls, 2);
});

test('concurrent operator probes coalesce and passive inspect stays unverified in flight', async () => {
  let calls = 0, release;
  const ctrl = {
    status: () => controllerStatus(),
    probeRuntime() {
      calls++;
      return new Promise((resolve) => { release = resolve; });
    },
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  const a = observer.probe();
  const b = observer.probe();
  assert.strictEqual(a, b);
  assert.equal(calls, 1);
  assert.equal(observer.observe().freshness, 'UNVERIFIED');
  release(successfulProbe());
  const both = await Promise.all([a, b]);
  both.forEach(hold);
  assert.equal(observer.observe().freshness, 'RECENT');
});

test('unexpected probe exception remains hold and does not leak exception text', async () => {
  const ctrl = {
    status: () => controllerStatus(),
    async probeRuntime() { throw new Error('PRIVATE TOKEN SHOULD NOT LEAK'); },
  };
  const observer = createGuardianLocalHealthObservation({ controller: ctrl });
  const result = await observer.probe();
  hold(result);
  assert.equal(result.reason, 'GUARDIAN_HEALTH_PROBE_EXCEPTION');
  assert.equal(JSON.stringify(result).includes('TOKEN'), false);
  assert.equal(observer.observe().freshness, 'UNVERIFIED');
});

test('malformed maxAge configuration rejected prior to any IO', () => {
  const ctrl = {
    status: () => controllerStatus(),
    async probeRuntime() { return successfulProbe(); },
  };
  for (const maxAgeMs of [0, 49, -1, 30001, NaN, '500', 25.4, null]) {
    assert.throws(() => createGuardianLocalHealthObservation({
      controller: ctrl, maxAgeMs,
    }), /GUARDIAN_HEALTH_OBSERVATION_CONFIG_INVALID/);
  }
});

test('real Protected Host: probe is sampled then invalidated after Owner stop', async () => {
  await temp(async (directory) => {
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(worker), entrypoint: worker,
      directory, fileName: 'guardian-health-g24.jsonl',
      startupTimeoutMs: 4000, shutdownTimeoutMs: 900,
      healthProbeTimeoutMs: 3000, healthObservationMaxAgeMs: 1000,
    });
    const before = session.operator.observeRuntimeHealth();
    hold(before);
    assert.equal(before.freshness, 'UNVERIFIED');
    assert.equal(fs.readdirSync(directory).length, 0);
    await session.owner.start();
    const health = await session.operator.probeRuntime();
    hold(health);
    assert.equal(health.observation, 'LOCAL_CHILD_HEALTH_VERIFIED');
    const recent = session.operator.observeRuntimeHealth();
    hold(recent);
    assert.equal(recent.freshness, 'RECENT');
    assert.equal(recent.liveness, 'NOT_PROVEN');
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const after = session.operator.observeRuntimeHealth();
    hold(after);
    assert.equal(after.freshness, 'UNVERIFIED');
    assert.equal(after.reason, 'GUARDIAN_HEALTH_CHILD_NOT_RUNNING');
    assert.equal(fs.readdirSync(directory).length, 1);
    assert.equal((await session.operator.probeRuntime()).observation, 'NOT_PROVEN');
  });
});
