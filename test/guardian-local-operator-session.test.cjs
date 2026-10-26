'use strict';
// Isolated real child process + owner-only durable read receipts.
// No real GitHub App, D1 provisioning, Check write, or deployment.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const normalChild = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const faultyChild = path.join(__dirname, 'guardian-local-controller-child.cjs');

async function fixture(fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-local-session-'));
  try {
    return await fn({
      directory, fileName: 'guardian-terminal.jsonl',
      cwd: path.dirname(normalChild), entrypoint: normalChild,
      startupTimeoutMs: 4000, shutdownTimeoutMs: 500,
    });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function holds(value) {
  assert.equal(value.status, 'SOURCE_ONLY_HOLD');
  assert.equal(value.liveness, 'NOT_PROVEN');
  assert.equal(value.releaseAuthority, 'NOT_ISSUED');
  assert.equal(value.activationAllowed, false);
  assert.equal(value.automaticRestartAllowed, false);
  assert.equal(Object.isFrozen(value), true);
}

test('owner and Operator have distinct frozen capabilities, construction inert', async () => {
  await fixture(async (args) => {
    const session = createGuardianLocalOperatorSession(args);
    assert.deepEqual(Object.keys(session).sort(), ['operator', 'owner']);
    assert.ok(Object.isFrozen(session));
    assert.ok(Object.isFrozen(session.owner));
    assert.ok(Object.isFrozen(session.operator));
    assert.deepEqual(Object.keys(session.owner).sort(), ['start', 'status', 'stop']);
    assert.deepEqual(Object.keys(session.operator), ['inspect']);
    assert.equal(session.owner.status().state, 'CREATED');
    const before = session.operator.inspect();
    holds(before);
    assert.equal(before.manualInterventionRequired, true);
    assert.equal(before.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal(fs.existsSync(path.join(args.directory, args.fileName)), false);
    assert.equal(Object.hasOwn(session.operator, 'start'), false);
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
  });
});

test('real Protected Host child lifecycle is observable only, not releasable', async () => {
  await fixture(async (args) => {
    const session = createGuardianLocalOperatorSession(args);
    assert.equal((await session.owner.start()).state, 'RUNNING');
    const running = session.operator.inspect();
    holds(running);
    assert.equal(running.processState, 'RUNNING');
    assert.equal(running.manualInterventionRequired, true);
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const finished = session.operator.inspect();
    holds(finished);
    assert.equal(finished.reason, 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP');
    assert.equal(finished.manualInterventionRequired, false);
    assert.equal(finished.lastTerminal.state, 'STOPPED');
    assert.equal(finished.journalEntries, 1);
    assert.equal(Object.hasOwn(session.operator, 'resetFault'), false);
  });
});

test('read-only query cannot clear historical failure when a later child shuts down', async () => {
  await fixture(async (args) => {
    const failedScript = path.join(args.directory, 'premature-exit.cjs');
    fs.copyFileSync(faultyChild, failedScript);
    const broken = createGuardianLocalOperatorSession({
      ...args, cwd: args.directory, entrypoint: failedScript,
    });
    await assert.rejects(broken.owner.start(),
      { code: 'GUARDIAN_CHILD_EXIT_BEFORE_READY' });
    const first = broken.operator.inspect();
    holds(first);
    assert.equal(first.manualInterventionRequired, true);
    assert.equal(first.lastTerminal.state, 'FAILED');
    const healthy = createGuardianLocalOperatorSession(args);
    await healthy.owner.start();
    await healthy.owner.stop();
    const later = healthy.operator.inspect();
    holds(later);
    assert.equal(later.journalEntries, 2);
    assert.equal(later.lastTerminal.state, 'STOPPED');
    assert.equal(later.manualInterventionRequired, true);
    assert.equal(later.reason, 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
  });
});

test('read-only inspect never mutates journal, even on repeated requests', async () => {
  await fixture(async (args) => {
    const session = createGuardianLocalOperatorSession(args);
    await session.owner.start();
    await session.owner.stop();
    const location = path.join(args.directory, args.fileName);
    const original = fs.readFileSync(location);
    const mtime = fs.statSync(location).mtimeMs;
    const a = session.operator.inspect();
    const b = session.operator.inspect();
    assert.deepEqual(a, b);
    assert.deepEqual(fs.readFileSync(location), original);
    assert.equal(fs.statSync(location).mtimeMs, mtime);
  });
});

test('journal corruption fails closed and cannot be repaired by an Operator read', async () => {
  await fixture(async (args) => {
    const session = createGuardianLocalOperatorSession(args);
    await session.owner.start();
    await session.owner.stop();
    const location = path.join(args.directory, args.fileName);
    fs.appendFileSync(location, '{ "extra": "malformed" }');
    const before = fs.readFileSync(location);
    const result = session.operator.inspect();
    holds(result);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_INVALID');
    assert.equal(result.manualInterventionRequired, true);
    assert.deepEqual(fs.readFileSync(location), before);
    assert.equal(result.lastTerminal, null);
  });
});

test('untrusted options fail before spawning a child or creating a receipt', async () => {
  await fixture(async (args) => {
    for (const invalid of [
      { fileName: '../../credentials' },
      { entrypoint: '/usr/local/bin/missing' },
      { directory: path.join(args.directory, 'missing') },
      { maxJournalBytes: 4 },
      { startupTimeoutMs: '5' },
      { unexpectedProviderKey: true },
    ]) {
      assert.throws(() => createGuardianLocalOperatorSession({
        ...args, ...invalid,
      }));
    }
    assert.equal(fs.readdirSync(args.directory).length, 0);
  });
});

test('journal cannot be replaced by a symlink to cause a false clean stop', async () => {
  await fixture(async (args) => {
    const session = createGuardianLocalOperatorSession(args);
    await session.owner.start();
    await session.owner.stop();
    const location = path.join(args.directory, args.fileName);
    fs.unlinkSync(location);
    fs.symlinkSync('/dev/null', location);
    const result = session.operator.inspect();
    holds(result);
    assert.equal(result.manualInterventionRequired, true);
    assert.notEqual(result.reason, 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP');
  });
});
