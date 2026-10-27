'use strict';
// G21: in-process, relative, unanchored append-continuity observations.
// Source only. No live D1, GitHub App, signing keys, network or Check writes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalEvidenceVerifier } =
  require('../merge-gate-install/guardian-candidate/guardian-local-evidence-verifier.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const NAME = 'guardian-continuity.jsonl';
const CHILD = path.join(__dirname, 'guardian-protected-worker-child.cjs');
async function temporary(work) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g21-'));
  try { return await work(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function journalPath(directory) { return path.join(directory, NAME); }
function writer(directory) {
  return createGuardianLocalReceiptJournal({ directory, fileName: NAME });
}
function observer(directory) {
  return createGuardianLocalEvidenceVerifier({ directory, fileName: NAME });
}
function receipt(state = 'STOPPED') {
  return Object.freeze({
    state,
    errorCode: state === 'FAILED' ? 'GUARDIAN_CHILD_EXIT_UNVERIFIED' : null,
    hostStopped: state === 'STOPPED',
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  });
}
function append(directory, ...states) {
  const storage = writer(directory);
  for (const state of states) storage.append(receipt(state));
}
function check(result) {
  assert.equal(result.kind, 'GUARDIAN_LOCAL_APPEND_CONTINUITY_V1');
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.liveness, 'NOT_PROVEN');
  assert.equal(result.externalAnchorVerified, false);
  assert.equal(result.custodyVerified, false);
  assert.equal(result.controllerStateVerified, false);
  assert.equal(result.manualInterventionRequired, true);
  assert.equal(result.automaticRestartAllowed, false);
  assert.equal(result.activationAllowed, false);
  assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  assert.ok(Object.isFrozen(result));
  for (const key of ['token', 'secret', 'rawJournal', 'pid', 'path', 'privateKey',
    'reset', 'approve', 'release']) {
    assert.equal(Object.hasOwn(result, key), false);
  }
}
function expectResult(result, reason, continuity) {
  check(result);
  assert.equal(result.reason, reason);
  assert.equal(result.continuity, continuity);
}
function sessionArgs(directory) {
  return {
    directory, fileName: NAME,
    cwd: path.dirname(CHILD), entrypoint: CHILD,
    startupTimeoutMs: 4000, shutdownTimeoutMs: 600,
  };
}

test('construction is inert; a missing journal cannot establish custody or create a file', async () => {
  await temporary(async (directory) => {
    const reader = observer(directory);
    assert.deepEqual(Object.keys(reader).sort(), ['observeContinuity', 'verify']);
    assert.ok(Object.isFrozen(reader));
    assert.equal(fs.readdirSync(directory).length, 0);
    const result = reader.observeContinuity();
    expectResult(result, 'GUARDIAN_CONTINUITY_SOURCE_UNVERIFIED', 'NOT_VERIFIED');
    assert.equal(result.observationSequence, 0);
    assert.equal(result.localChainSha256, null);
    assert.equal(fs.readdirSync(directory).length, 0);
    append(directory, 'STOPPED');
    const baseline = reader.observeContinuity();
    expectResult(baseline, 'GUARDIAN_CONTINUITY_LOCAL_BASELINE',
      'BASELINE_ONLY');
    assert.equal(baseline.observationSequence, 1);
    assert.equal(baseline.custodyVerified, false);
  });
});

test('first reading only establishes an untrusted local baseline and never grants activation', async () => {
  await temporary(async (directory) => {
    append(directory, 'STOPPED', 'FAILED');
    const reader = observer(directory);
    const baseline = reader.observeContinuity();
    expectResult(baseline, 'GUARDIAN_CONTINUITY_LOCAL_BASELINE', 'BASELINE_ONLY');
    assert.equal(baseline.observationSequence, 1);
    assert.equal(baseline.observedEntries, 2);
    assert.equal(baseline.addedEntries, 0);
    assert.equal(baseline.priorJournalSha256, null);
    assert.match(baseline.localChainSha256, /^[0-9a-f]{64}$/);
    assert.match(baseline.journalSha256, /^[0-9a-f]{64}$/);
    assert.equal(baseline.custodyVerified, false);
  });
});

test('unchanged read does not mint an artificial chain step or modify journal bytes', async () => {
  await temporary(async (directory) => {
    append(directory, 'FAILED');
    const reader = observer(directory);
    const before = fs.readFileSync(journalPath(directory));
    const metadata = fs.statSync(journalPath(directory));
    const first = reader.observeContinuity();
    const second = reader.observeContinuity();
    expectResult(second, 'GUARDIAN_CONTINUITY_SNAPSHOT_UNCHANGED',
      'UNCHANGED_LOCAL_SNAPSHOT');
    assert.equal(first.observationSequence, second.observationSequence);
    assert.equal(first.localChainSha256, second.localChainSha256);
    assert.equal(first.journalSha256, second.journalSha256);
    assert.equal(second.addedEntries, 0);
    assert.deepEqual(fs.readFileSync(journalPath(directory)), before);
    assert.equal(fs.statSync(journalPath(directory)).mtimeMs, metadata.mtimeMs);
  });
});

test('real append to identical inode preserves observed prefix and advances chain exactly once', async () => {
  await temporary(async (directory) => {
    append(directory, 'FAILED');
    const reader = observer(directory);
    const base = reader.observeContinuity();
    append(directory, 'STOPPED', 'FAILED');
    const second = reader.observeContinuity();
    expectResult(second, 'GUARDIAN_CONTINUITY_APPEND_OBSERVED',
      'APPEND_ONLY_RELATIVE_TO_LOCAL_BASELINE');
    assert.equal(second.observedEntries, 3);
    assert.equal(second.addedEntries, 2);
    assert.equal(second.observationSequence, 2);
    assert.equal(second.priorJournalSha256, base.journalSha256);
    assert.notEqual(second.localChainSha256, base.localChainSha256);
    assert.notEqual(second.journalSha256, base.journalSha256);
    const again = reader.observeContinuity();
    assert.equal(again.localChainSha256, second.localChainSha256);
    assert.equal(again.observationSequence, 2);
    append(directory, 'STOPPED');
    const third = reader.observeContinuity();
    assert.equal(third.observationSequence, 3);
    assert.equal(third.addedEntries, 1);
    assert.equal(third.priorJournalSha256, second.journalSha256);
  });
});

test('valid shorter history on SAME inode latches TRUNCATED and does not recover on append', async () => {
  await temporary(async (directory) => {
    append(directory, 'STOPPED', 'FAILED', 'STOPPED');
    const reader = observer(directory);
    reader.observeContinuity();
    const lines = fs.readFileSync(journalPath(directory), 'utf8').split('\n');
    fs.writeFileSync(journalPath(directory), lines[0] + '\n');
    const problem = reader.observeContinuity();
    expectResult(problem, 'GUARDIAN_CONTINUITY_TRUNCATED', 'NOT_VERIFIED');
    assert.equal(problem.observedEntries, 0);
    append(directory, 'STOPPED', 'STOPPED', 'STOPPED');
    const stuck = reader.observeContinuity();
    expectResult(stuck, 'GUARDIAN_CONTINUITY_TRUNCATED', 'NOT_VERIFIED');
    assert.equal(stuck.localChainSha256, problem.localChainSha256);
    assert.equal(stuck.observationSequence, problem.observationSequence);
  });
});

test('valid but altered historical UUID on SAME inode latches NON_APPEND_CHANGE', async () => {
  await temporary(async (directory) => {
    append(directory, 'STOPPED', 'FAILED');
    const reader = observer(directory);
    reader.observeContinuity();
    const filepath = journalPath(directory);
    const text = fs.readFileSync(filepath, 'utf8');
    const firstId = JSON.parse(text.split('\n')[0]).eventId;
    const nextId = (firstId[0] === 'a' ? 'b' : 'a') + firstId.slice(1);
    fs.writeFileSync(filepath, text.replace(firstId, nextId));
    const problem = reader.observeContinuity();
    expectResult(problem, 'GUARDIAN_CONTINUITY_NON_APPEND_CHANGE', 'NOT_VERIFIED');
    assert.equal(problem.addedEntries, 0);
    assert.equal(problem.journalSha256, null);
    assert.ok(problem.localChainSha256);
  });
});

test('replaced file inode with individually valid bytes never passes as continuous', async () => {
  await temporary(async (directory) => {
    append(directory, 'STOPPED');
    const reader = observer(directory);
    const base = reader.observeContinuity();
    const filepath = journalPath(directory);
    fs.renameSync(filepath, path.join(directory, 'old-journal'));
    // A byte-identical copy is still a new inode, never a trusted continuation.
    fs.copyFileSync(path.join(directory, 'old-journal'), filepath);
    fs.chmodSync(filepath, 0o600);
    const result = reader.observeContinuity();
    expectResult(result, 'GUARDIAN_CONTINUITY_FILE_REPLACED', 'NOT_VERIFIED');
    assert.equal(result.localChainSha256, base.localChainSha256);
  });
});

test('malformed appended line, duplicate JSON member and lax file permissions each latch source failure', async () => {
  for (const attack of [
    (file) => fs.appendFileSync(file, '{"unknown":"secret"}\n'),
    (file) => {
      const contents = fs.readFileSync(file, 'utf8');
      fs.writeFileSync(file, contents.replace(
        '"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'));
    },
    (file) => fs.chmodSync(file, 0o644),
  ]) {
    await temporary(async (directory) => {
      append(directory, 'FAILED');
      const reader = observer(directory);
      reader.observeContinuity();
      attack(journalPath(directory));
      const failed = reader.observeContinuity();
      expectResult(failed, 'GUARDIAN_CONTINUITY_SOURCE_UNVERIFIED', 'NOT_VERIFIED');
      fs.chmodSync(journalPath(directory), 0o600);
      fs.unlinkSync(journalPath(directory));
      append(directory, 'STOPPED');
      const stuck = reader.observeContinuity();
      assert.equal(stuck.reason, failed.reason);
      assert.equal(stuck.localChainSha256, failed.localChainSha256);
    });
  }
});

test('a new verifier has NO durable provenance from the previous process', async () => {
  await temporary(async (directory) => {
    append(directory, 'STOPPED');
    const first = observer(directory);
    const firstBaseline = first.observeContinuity();
    append(directory, 'STOPPED');
    const continued = first.observeContinuity();
    assert.equal(continued.observationSequence, 2);
    const second = observer(directory);
    const secondBaseline = second.observeContinuity();
    expectResult(secondBaseline, 'GUARDIAN_CONTINUITY_LOCAL_BASELINE',
      'BASELINE_ONLY');
    assert.equal(secondBaseline.observationSequence, 1);
    assert.notEqual(secondBaseline.localChainSha256, continued.localChainSha256);
    assert.notEqual(secondBaseline.journalSha256, firstBaseline.journalSha256);
  });
});

test('operator facade is read-only and binds its continuity to the owned journal', async () => {
  await temporary(async (directory) => {
    const session = createGuardianLocalOperatorSession(sessionArgs(directory));
    assert.equal(Object.hasOwn(session.operator, 'observeLocalContinuity'), true);
    assert.equal(Object.hasOwn(session.operator, 'start'), false);
    assert.equal(Object.hasOwn(session.operator, 'reset'), false);
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
    assert.equal(Object.isFrozen(session.operator), true);
    assert.equal((await session.owner.start()).state, 'RUNNING');
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const first = session.operator.observeLocalContinuity();
    expectResult(first, 'GUARDIAN_CONTINUITY_LOCAL_BASELINE', 'BASELINE_ONLY');
    const secondSession = createGuardianLocalOperatorSession(sessionArgs(directory));
    assert.equal((await secondSession.owner.start()).state, 'RUNNING');
    assert.equal((await secondSession.owner.stop()).state, 'STOPPED');
    const second = session.operator.observeLocalContinuity();
    expectResult(second, 'GUARDIAN_CONTINUITY_APPEND_OBSERVED',
      'APPEND_ONLY_RELATIVE_TO_LOCAL_BASELINE');
    assert.equal(second.addedEntries, 1);
    assert.equal(session.owner.status().state, 'STOPPED');
    assert.equal(second.custodyVerified, false);
  });
});
