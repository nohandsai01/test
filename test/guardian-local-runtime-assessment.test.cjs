'use strict';
// G25: passive fusion of fault triage and transient local probe freshness.
// Offline-only: no production D1, hosted identity, Check writer or deploy.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalRuntimeAssessment } =
  require('../merge-gate-install/guardian-candidate/guardian-local-runtime-assessment.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const sha = 'f'.repeat(64);

function controllerStatus(state = 'RUNNING', pid = 2222) {
  return Object.freeze({
    state, pid, errorCode: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  });
}
function triage(priority = 'P2', options = {}) {
  const classes = {
    P0: ['EVIDENCE_UNVERIFIED', 'OWNER_INVESTIGATE_LOCAL_EVIDENCE'],
    P1: ['RECORDED_FAILURE', 'OWNER_REVIEW_FAULT_HISTORY'],
    P2: ['PROCESS_STATE_UNPROVEN', 'OWNER_RECONCILE_LIFECYCLE'],
    P3: ['LOCAL_STOP_OBSERVED', 'NO_LOCAL_FAULT_OBSERVED'],
  };
  const [classification, nextAction] = classes[priority];
  return Object.freeze({
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_FAULT_TRIAGE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    priority, classification, nextAction,
    sourceReason: 'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE',
    processState: priority === 'P3' ? 'STOPPED' : 'RUNNING',
    liveness: 'NOT_PROVEN', journalEntries: 2, journalSha256: sha,
    failureCount: priority === 'P1' ? 1 : 0,
    manualInterventionRequired: priority !== 'P3',
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
    ...options,
  });
}
function health(freshness = 'RECENT', options = {}) {
  const observed = freshness === 'RECENT';
  return Object.freeze({
    schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
    observation: observed ?
      'LOCAL_CHILD_HEALTH_OBSERVED_RECENTLY' : 'NOT_PROVEN',
    freshness,
    reason: observed ? 'GUARDIAN_HEALTH_RECENT_SAMPLE_ONLY' :
      freshness === 'EXPIRED' ?
        'GUARDIAN_HEALTH_SAMPLE_EXPIRED' :
        'GUARDIAN_HEALTH_NO_VALID_SAMPLE',
    processState: 'RUNNING', liveness: 'NOT_PROVEN',
    sampledAt: observed ? '2026-10-27T01:00:00.000Z' : null,
    ageMs: observed ? 5 : freshness === 'EXPIRED' ? 65 : null,
    maxAgeMs: 50,
    manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
    ...options,
  });
}
function harness(state, triageResult, healthResult) {
  const track = { status: 0, triage: 0, health: 0, probe: 0 };
  const controller = { status() {
    track.status++; return state();
  } };
  const diagnostics = { faultTriage() {
    track.triage++; return triageResult();
  } };
  const observation = { observe() {
    track.health++; return healthResult();
  }, probe() { track.probe++; throw new Error('must not probe'); } };
  return {
    track, assessment: createGuardianLocalRuntimeAssessment({
      controller, diagnostics, healthObservation: observation,
    }),
  };
}
function assertHold(result) {
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.kind, 'GUARDIAN_LOCAL_RUNTIME_ASSESSMENT_V1');
  assert.equal(result.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.liveness, 'NOT_PROVEN');
  assert.equal(result.activationAllowed, false);
  assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  assert.equal(result.automaticRestartAllowed, false);
  assert.ok(Object.isFrozen(result));
  assert.equal(Object.hasOwn(result, 'pid'), false);
  assert.equal(Object.hasOwn(result, 'restart'), false);
  assert.equal(Object.hasOwn(result, 'rawJournal'), false);
}
function observe(t = triage(), h = health(), state = controllerStatus()) {
  return harness(() => state, () => t, () => h).assessment.assess();
}
async function tmp(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g25-'));
  try { return await fn(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test('inert construction and passive assessment never start, probe or mutate', () => {
  const { track, assessment } = harness(
    () => controllerStatus(), () => triage(), () => health());
  assert.equal(track.status, 0);
  assert.equal(track.triage, 0);
  assert.equal(track.health, 0);
  assert.deepEqual(Object.keys(assessment), ['assess']);
  assert.ok(Object.isFrozen(assessment));
  const result = assessment.assess();
  assertHold(result);
  assert.equal(track.status, 2);
  assert.equal(track.triage, 1);
  assert.equal(track.health, 1);
  assert.equal(track.probe, 0);
  assert.equal(result.priority, 'P2');
  assert.equal(result.classification, 'RECENT_LOCAL_PROBE_ONLY');
  assert.equal(result.nextAction, 'OWNER_RECONCILE_RUNTIME_HEALTH');
  assert.equal(result.manualInterventionRequired, true);
  assert.equal(result.healthFreshness, 'RECENT');
  assert.equal(result.healthSampleAgeMs, 5);
  assert.equal(result.journalEntries, 2);
  assert.equal(result.journalSha256, sha);
});

test('stale sample and missing sample generate distinct manual actions', () => {
  for (const freshness of ['EXPIRED', 'UNVERIFIED']) {
    const result = observe(triage(), health(freshness));
    assertHold(result);
    assert.equal(result.priority, 'P2');
    assert.equal(result.classification, freshness === 'EXPIRED' ?
      'LOCAL_PROBE_EXPIRED' : 'NO_VERIFIED_HEALTH_SAMPLE');
    assert.equal(result.nextAction, 'OWNER_REQUEST_FRESH_HEALTH_PROBE');
    assert.equal(result.manualInterventionRequired, true);
    assert.equal(result.healthFreshness, freshness);
  }
});

test('P0 evidence integrity remains P0 despite RECENT local probe', () => {
  const result = observe(triage('P0'), health());
  assertHold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'EVIDENCE_UNVERIFIED');
  assert.equal(result.nextAction, 'OWNER_INVESTIGATE_LOCAL_EVIDENCE');
  assert.equal(result.healthFreshness, 'RECENT');
  assert.equal(result.manualInterventionRequired, true);
});

test('P1 recorded failure remains P1 despite RECENT local probe', () => {
  const result = observe(triage('P1'), health());
  assertHold(result);
  assert.equal(result.priority, 'P1');
  assert.equal(result.classification, 'RECORDED_FAILURE');
  assert.equal(result.historicalFailureCount, 1);
  assert.equal(result.nextAction, 'OWNER_REVIEW_FAULT_HISTORY');
  assert.equal(result.manualInterventionRequired, true);
});

test('clean stopped state can be locally P3 but never says live/authorized', () => {
  const result = observe(
    triage('P3', { sourceReason: 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP' }),
    health('UNVERIFIED', {
      processState: 'STOPPED', reason: 'GUARDIAN_HEALTH_CHILD_NOT_RUNNING',
    }),
    controllerStatus('STOPPED'));
  assertHold(result);
  assert.equal(result.priority, 'P3');
  assert.equal(result.classification, 'LOCAL_STOP_OBSERVED');
  assert.equal(result.manualInterventionRequired, false);
  assert.equal(result.healthFreshness, 'UNVERIFIED');
});

test('missing journal on CREATED is P2, never a fabricated clean run', () => {
  const result = observe(triage('P2', {
    classification: 'NO_LOCAL_BASELINE',
    nextAction: 'OWNER_VERIFY_FIRST_START_PREREQUISITES',
    sourceReason: 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING',
    journalEntries: 0, journalSha256: null, processState: 'CREATED',
  }), health('UNVERIFIED', {
    processState: 'CREATED', reason: 'GUARDIAN_HEALTH_CHILD_NOT_RUNNING',
  }), controllerStatus('CREATED', null));
  assertHold(result);
  assert.equal(result.priority, 'P2');
  assert.equal(result.classification, 'NO_LOCAL_BASELINE');
  assert.equal(result.journalEntries, 0);
  assert.equal(result.healthFreshness, 'UNVERIFIED');
  assert.equal(result.manualInterventionRequired, true);
});

test('state or PID changing between reads produces P0, not previous green sample', () => {
  let count = 0;
  const { assessment } = harness(
    () => controllerStatus('RUNNING', ++count === 1 ? 111 : 222),
    () => triage(), () => health());
  const result = assessment.assess();
  assertHold(result);
  assert.equal(result.priority, 'P0');
  assert.equal(result.classification, 'LOCAL_OBSERVATION_UNVERIFIED');
  assert.equal(result.processState, 'UNVERIFIED');
  assert.equal(result.journalSha256, null);
  assert.equal(result.healthFreshness, 'UNVERIFIED');
  assert.equal(result.manualInterventionRequired, true);
});

test('triage/health controller state disagreement produces P0', () => {
  for (const [t, h] of [
    [triage('P3'), health()],
    [triage('P2'), health('UNVERIFIED', { processState: 'STOPPED' })],
  ]) {
    const result = observe(t, h, controllerStatus());
    assertHold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.classification, 'LOCAL_OBSERVATION_UNVERIFIED');
  }
});

test('invalid triage shape/authority never escapes through operator result', () => {
  for (const altered of [
    { activationAllowed: true },
    { releaseAuthority: 'ISSUED' },
    { automaticRestartAllowed: true },
    { priority: 'P3', classification: 'LOCAL_STOP_OBSERVED',
      nextAction: 'NO_LOCAL_FAULT_OBSERVED', processState: 'RUNNING',
      manualInterventionRequired: false },
    { journalSha256: 'forged' },
    { failureCount: 9000 },
  ]) {
    const result = observe(triage('P2', altered), health());
    assertHold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.journalSha256, null);
  }
});

test('untrusted health shape/expiry cannot turn into a green report', () => {
  for (const altered of [
    { activationAllowed: true },
    { liveness: 'TRUSTED' },
    { manualInterventionRequired: false },
    { releaseAuthority: 'ISSUED' },
    { freshness: 'RECENT', ageMs: 500 },
    { freshness: 'EXPIRED', ageMs: 2 },
    { freshness: 'RECENT', sampledAt: null },
    { freshness: 'RECENT', processState: 'STOPPED' },
  ]) {
    const result = observe(triage(), health('RECENT', altered));
    assertHold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.healthFreshness, 'UNVERIFIED');
  }
});

test('status exceptions and getter exceptions fail closed without leaking errors', () => {
  const exception = harness(
    () => { throw new Error('PRIVATE_KEY_DO_NOT_LOG'); },
    () => triage(), () => health()).assessment.assess();
  assertHold(exception);
  assert.equal(exception.priority, 'P0');
  assert.equal(exception.journalEntries, 0);
  assert.equal(JSON.stringify(exception).includes('PRIVATE_KEY'), false);

  const diagnosticsThrow = harness(
    () => controllerStatus(),
    () => { throw new Error('private token'); },
    () => health()).assessment.assess();
  assertHold(diagnosticsThrow);
  assert.equal(diagnosticsThrow.priority, 'P0');
  assert.equal(JSON.stringify(diagnosticsThrow).includes('token'), false);

  const invalidController = observe(triage(), health(),
    { ...controllerStatus(), activationAllowed: true });
  assertHold(invalidController);
  assert.equal(invalidController.priority, 'P0');
});

test('constructor rejects inert configurations without starting anything', () => {
  const ctrl = { status: () => controllerStatus() };
  const diag = { faultTriage: () => triage() };
  const healthObservation = { observe: () => health() };
  for (const x of [
    {}, { controller: ctrl },
    { controller: ctrl, diagnostics: diag },
    { controller: ctrl, diagnostics: {}, healthObservation },
    { controller: ctrl, diagnostics: diag, healthObservation: {} },
  ]) {
    assert.throws(() => createGuardianLocalRuntimeAssessment(x),
      /GUARDIAN_RUNTIME_ASSESSMENT_CONFIG_INVALID/);
  }
});

test('real protected child lifecycle keeps Operator-only assessment passive and HOLD', async () => {
  await tmp(async (directory) => {
    function session() {
      return createGuardianLocalOperatorSession({
        cwd: path.dirname(worker), entrypoint: worker,
        directory, fileName: 'guardian-runtime-g25.jsonl',
        startupTimeoutMs: 4000, shutdownTimeoutMs: 900,
        healthProbeTimeoutMs: 3000, healthObservationMaxAgeMs: 75,
      });
    }
    const prior = session();
    const baseline = prior.operator.assessRuntime();
    assertHold(baseline);
    assert.equal(baseline.classification, 'NO_LOCAL_BASELINE');
    assert.equal(fs.readdirSync(directory).length, 0);
    await prior.owner.start();
    assert.equal((await prior.owner.stop()).state, 'STOPPED');

    const running = session();
    const before = running.operator.assessRuntime();
    assertHold(before);
    assert.equal(before.priority, 'P2');
    assert.equal(before.healthFreshness, 'UNVERIFIED');
    await running.owner.start();
    const noProbe = running.operator.assessRuntime();
    assertHold(noProbe);
    assert.equal(noProbe.classification, 'NO_VERIFIED_HEALTH_SAMPLE');
    const probe = await running.operator.probeRuntime();
    assert.equal(probe.observation, 'LOCAL_CHILD_HEALTH_VERIFIED');
    const recent = running.operator.assessRuntime();
    assertHold(recent);
    assert.equal(recent.classification, 'RECENT_LOCAL_PROBE_ONLY');
    assert.equal(recent.healthFreshness, 'RECENT');
    assert.equal(recent.priority, 'P2');
    assert.equal(recent.manualInterventionRequired, true);
    await new Promise((resolve) => setTimeout(resolve, 96));
    const stale = running.operator.assessRuntime();
    assertHold(stale);
    assert.equal(stale.healthFreshness, 'EXPIRED');
    assert.equal(stale.classification, 'LOCAL_PROBE_EXPIRED');
    assert.equal((await running.owner.stop()).state, 'STOPPED');
    const stopped = running.operator.assessRuntime();
    assertHold(stopped);
    assert.equal(stopped.priority, 'P3');
    assert.equal(stopped.healthFreshness, 'UNVERIFIED');
    assert.equal(stopped.manualInterventionRequired, false);
    assert.equal(fs.readdirSync(directory).length, 1);
  });
});
