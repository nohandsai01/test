'use strict';
// Source-only, read-only fault evidence: bounded incident context and
// reproducible local SHA-256, never an authorization or custody proof.
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
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const realWorker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const failedWorker = path.join(__dirname, 'guardian-local-controller-child.cjs');
const journalName = 'guardian-fault-evidence.jsonl';
function journalPath(directory) { return path.join(directory, journalName); }
async function temp(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nh-fault-packet-'));
  try { return await callback(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function journal(directory) {
  return createGuardianLocalReceiptJournal({ directory, fileName: journalName });
}
function receipt(state = 'STOPPED') {
  return state === 'STOPPED' ? {
    state, errorCode: null, hostStopped: true,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  } : {
    state: 'FAILED', errorCode: 'GUARDIAN_CHILD_EXIT_UNVERIFIED',
    hostStopped: false, activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  };
}
function controller(state = 'STOPPED') {
  return { status: () => ({
    state, activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  }) };
}
function reader(directory, ctrl = controller()) {
  return createGuardianLocalDiagnostics({
    directory, fileName: journalName, controller: ctrl,
  });
}
function assertHold(packet) {
  assert.equal(packet.schemaVersion, 1);
  assert.equal(packet.kind, 'GUARDIAN_LOCAL_FAULT_EVIDENCE_V1');
  assert.equal(packet.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(packet.status, 'SOURCE_ONLY_HOLD');
  assert.equal(packet.liveness, 'NOT_PROVEN');
  assert.equal(packet.manualInterventionRequired, true);
  assert.equal(packet.releaseAuthority, 'NOT_ISSUED');
  assert.equal(packet.activationAllowed, false);
  assert.equal(packet.automaticRestartAllowed, false);
  assert.ok(Object.isFrozen(packet));
}
function minimalReceipt(row) {
  if (row === null) return;
  assert.ok(Object.isFrozen(row));
  assert.deepEqual(Object.keys(row).sort(),
    ['eventId', 'timestamp', 'state', 'errorCode'].sort());
}
function frozenSafe(packet) {
  assertHold(packet);
  minimalReceipt(packet.firstFailure);
  minimalReceipt(packet.latestFailure);
  minimalReceipt(packet.selectedFailure);
  minimalReceipt(packet.previousReceipt);
  minimalReceipt(packet.nextReceipt);
  assert.equal(Object.hasOwn(packet, 'pid'), false);
  assert.equal(Object.hasOwn(packet, 'token'), false);
  assert.equal(Object.hasOwn(packet, 'privateKey'), false);
}

test('construction is inert; missing evidence returns non-authorizing UNAVAILABLE and no writes', async () => {
  await temp(async (directory) => {
    let statusReads = 0;
    const ctrl = { status() { statusReads++; return controller('CREATED').status(); } };
    const diagnostic = reader(directory, ctrl);
    assert.equal(statusReads, 0);
    assert.deepEqual(Object.keys(diagnostic).sort(),
      ['inspect', 'recentEvents', 'incidentEvidence'].sort());
    const packet = diagnostic.incidentEvidence();
    assertHold(packet);
    assert.equal(packet.availability, 'UNAVAILABLE');
    assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
    assert.equal(packet.sourceReason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal(packet.selectedFailure, null);
    assert.equal(packet.evidenceSha256, null);
    assert.equal(packet.journalSha256, null);
    assert.equal(statusReads, 1);
    assert.equal(fs.readdirSync(directory).length, 0);
  });
});

test('one validated snapshot yields stable hashed fault evidence with precise preceding/following receipts', async () => {
  await temp(async (directory) => {
    const writer = journal(directory);
    for (const state of ['STOPPED','FAILED','STOPPED','FAILED','STOPPED']) {
      writer.append(receipt(state));
    }
    const raw = fs.readFileSync(journalPath(directory));
    const rows = raw.toString('utf8').trim().split('\n').map(JSON.parse);
    const source = reader(directory);
    const packet = source.incidentEvidence();
    frozenSafe(packet);
    assert.equal(packet.availability, 'LOCAL_SNAPSHOT');
    assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_FAULT_RECORDED');
    assert.equal(packet.sourceReason, 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
    assert.equal(packet.journalEntries, 5);
    assert.equal(packet.failureCount, 2);
    assert.equal(packet.eventSequence, 4);
    assert.equal(packet.selectedFailure.eventId, rows[3].eventId);
    assert.equal(packet.firstFailure.eventId, rows[1].eventId);
    assert.equal(packet.latestFailure.eventId, rows[3].eventId);
    assert.equal(packet.previousReceipt.eventId, rows[2].eventId);
    assert.equal(packet.nextReceipt.eventId, rows[4].eventId);
    assert.equal(packet.selectedFailure.state, 'FAILED');
    assert.equal(packet.previousReceipt.state, 'STOPPED');
    assert.equal(packet.nextReceipt.state, 'STOPPED');
    assert.equal(packet.journalSha256,
      crypto.createHash('sha256').update(raw).digest('hex'));
    assert.match(packet.evidenceSha256, /^[0-9a-f]{64}$/);
    const { evidenceSha256, ...data } = packet;
    assert.equal(evidenceSha256,
      crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex'));
    assert.deepEqual(source.incidentEvidence(), packet);
    assert.equal(source.incidentEvidence({
      journalSha256: packet.journalSha256,
    }).evidenceSha256, packet.evidenceSha256);
    assert.deepEqual(fs.readFileSync(journalPath(directory)), raw);
  });
});

test('select exact historical fault and bind to digest without switching to latest', async () => {
  await temp(async (directory) => {
    const writer = journal(directory);
    for (const state of ['FAILED', 'STOPPED', 'FAILED', 'STOPPED']) {
      writer.append(receipt(state));
    }
    const rows = fs.readFileSync(journalPath(directory), 'utf8').trim()
      .split('\n').map(JSON.parse);
    const source = reader(directory);
    const current = source.inspect().journalSha256;
    const packet = source.incidentEvidence({
      eventId: rows[0].eventId, journalSha256: current,
    });
    frozenSafe(packet);
    assert.equal(packet.availability, 'LOCAL_SNAPSHOT');
    assert.equal(packet.selectedFailure.eventId, rows[0].eventId);
    assert.equal(packet.eventSequence, 1);
    assert.equal(packet.previousReceipt, null);
    assert.equal(packet.nextReceipt.eventId, rows[1].eventId);
    assert.equal(packet.failureCount, 2);
    assert.equal(packet.latestFailure.eventId, rows[2].eventId);
    assert.notEqual(packet.selectedFailure.eventId, packet.latestFailure.eventId);
  });
});

test('a stale snapshot digest never returns event details, even if new data is valid', async () => {
  await temp(async (directory) => {
    const writer = journal(directory);
    writer.append(receipt('FAILED'));
    const source = reader(directory);
    const before = source.incidentEvidence();
    writer.append(receipt('STOPPED'));
    const packet = source.incidentEvidence({
      eventId: before.selectedFailure.eventId,
      journalSha256: before.journalSha256,
    });
    frozenSafe(packet);
    assert.equal(packet.availability, 'UNAVAILABLE');
    assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SNAPSHOT_STALE');
    assert.equal(packet.selectedFailure, null);
    assert.equal(packet.firstFailure, null);
    assert.equal(packet.latestFailure, null);
    assert.equal(packet.journalEntries, 0);
    assert.equal(packet.journalSha256, null);
    assert.equal(packet.evidenceSha256, null);
    assert.equal(source.incidentEvidence().failureCount, 1);
  });
});

test('unrecorded fault, missing event ID and selecting a clean stop never produce a false incident packet', async () => {
  await temp(async (directory) => {
    const writer = journal(directory);
    writer.append(receipt('STOPPED'));
    let result = reader(directory).incidentEvidence();
    assertHold(result);
    assert.equal(result.availability, 'UNAVAILABLE');
    assert.equal(result.reason, 'GUARDIAN_EVIDENCE_NO_RECORDED_FAILURE');
    assert.equal(result.selectedFailure, null);
    assert.equal(result.evidenceSha256, null);
    writer.append(receipt('FAILED'));
    const source = reader(directory);
    result = source.incidentEvidence({
      eventId: '00000000-0000-4000-8000-000000000001',
    });
    assertHold(result);
    assert.equal(result.reason, 'GUARDIAN_EVIDENCE_EVENT_NOT_FOUND');
    assert.equal(result.selectedFailure, null);
    assert.equal(result.evidenceSha256, null);
    const first = JSON.parse(
      fs.readFileSync(journalPath(directory), 'utf8').split('\n')[0]);
    result = source.incidentEvidence({ eventId: first.eventId });
    assertHold(result);
    assert.equal(result.reason, 'GUARDIAN_EVIDENCE_EVENT_NOT_FAILURE');
    assert.equal(result.selectedFailure, null);
    assert.equal(result.evidenceSha256, null);
  });
});

test('invalid query fields, hostile accessors, symbols and Proxy never invoke user getters', async () => {
  await temp(async (directory) => {
    journal(directory).append(receipt('FAILED'));
    const diagnostic = reader(directory);
    let invoked = 0;
    const withGetter = {};
    Object.defineProperty(withGetter, 'eventId', {
      enumerable: true, get() { invoked++; return null; },
    });
    const symbol = { [Symbol('secret')]: 'value' };
    const trap = new Proxy({}, {
      ownKeys() { throw new Error('PRIVATE_TOKEN'); },
    });
    const invalid = [
      null, 0, 'event', [], withGetter, symbol, trap,
      { eventId: 'bad' },
      { eventId: 5 },
      { eventId: {} },
      { journalSha256: 'a'.repeat(63) },
      { journalSha256: 'z'.repeat(64) },
      { journalSha256: 8 },
      { secretKey: 'PRIVATE_TOKEN' },
      { eventId: undefined, journalSha256: 'a'.repeat(64), extra: 1 },
    ];
    const unchanged = fs.readFileSync(journalPath(directory));
    for (const options of invalid) {
      assert.throws(() => diagnostic.incidentEvidence(options),
        { message: 'GUARDIAN_EVIDENCE_REQUEST_INVALID' });
    }
    assert.equal(invoked, 0);
    assert.deepEqual(fs.readFileSync(journalPath(directory)), unchanged);
  });
});

test('malformed, duplicate, truncated, modified-permissions and symlink journal always return empty evidence', async () => {
  await temp(async (directory) => {
    const writer = journal(directory);
    writer.append(receipt('FAILED'));
    const original = fs.readFileSync(journalPath(directory));
    const samples = [
      Buffer.from(original.toString('utf8').slice(0, -1)),
      Buffer.from('{}\n'),
      Buffer.from(original.toString('utf8').replace(
        '"state":"FAILED"', '"state":"FAILED","state":"STOPPED"')),
      Buffer.from(original.toString('utf8').replace(
        '"releaseAuthority":"NOT_ISSUED"', '"releaseAuthority":"ISSUED"')),
      Buffer.from('{"PRIVATE_TOKEN":"do not print"}\n'),
      Buffer.concat([original, original]),
    ];
    for (const bytes of samples) {
      fs.writeFileSync(journalPath(directory), bytes);
      const packet = reader(directory).incidentEvidence();
      frozenSafe(packet);
      assert.equal(packet.availability, 'UNAVAILABLE');
      assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
      assert.equal(packet.journalSha256, null);
      assert.equal(packet.evidenceSha256, null);
      assert.equal(packet.selectedFailure, null);
      assert.equal(JSON.stringify(packet).includes('PRIVATE_TOKEN'), false);
    }
    fs.writeFileSync(journalPath(directory), original);
    fs.chmodSync(journalPath(directory), 0o644);
    let packet = reader(directory).incidentEvidence();
    frozenSafe(packet);
    assert.equal(packet.availability, 'UNAVAILABLE');
    fs.chmodSync(journalPath(directory), 0o600);
    fs.unlinkSync(journalPath(directory));
    fs.symlinkSync('/dev/null', journalPath(directory));
    packet = reader(directory).incidentEvidence();
    frozenSafe(packet);
    assert.equal(packet.selectedFailure, null);
  });
});

test('unverified controller or changed status refuses incident evidence', async () => {
  await temp(async (directory) => {
    journal(directory).append(receipt('FAILED'));
    const bad = { status() { return {
      state: 'STOPPED', releaseAuthority: 'ISSUED',
      activationAllowed: true, automaticRestartAllowed: true,
    }; } };
    let packet = reader(directory, bad).incidentEvidence();
    frozenSafe(packet);
    assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
    let reads = 0;
    const drift = { status() {
      reads++;
      return controller(reads === 1 ? 'STOPPED' : 'RUNNING').status();
    } };
    packet = reader(directory, drift).incidentEvidence();
    frozenSafe(packet);
    assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
    assert.equal(packet.sourceReason,
      'GUARDIAN_DIAGNOSTICS_CONTROLLER_CHANGED_DURING_READ');
    assert.equal(packet.evidenceSha256, null);
  });
});

test('Operator can read exact incident but cannot acknowledge, clear, start, stop, publish or restart', async () => {
  await temp(async (directory) => {
    const damaged = path.join(directory, 'premature-exit.cjs');
    fs.copyFileSync(failedWorker, damaged);
    const broken = createGuardianLocalOperatorSession({
      directory, fileName: journalName,
      cwd: directory, entrypoint: damaged,
      startupTimeoutMs: 1500, shutdownTimeoutMs: 500,
    });
    assert.deepEqual(Object.keys(broken.operator).sort(),
      ['inspect', 'recentEvents', 'incidentEvidence', 'verifyIncidentEvidence', 'observeLocalContinuity'].sort());
    assert.equal(Object.hasOwn(broken.operator, 'acknowledge'), false);
    assert.equal(Object.hasOwn(broken.operator, 'start'), false);
    assert.equal(Object.hasOwn(broken.operator, 'stop'), false);
    assert.equal(Object.hasOwn(broken.operator, 'clear'), false);
    assert.equal(Object.hasOwn(broken.operator, 'restart'), false);
    assert.equal(Object.hasOwn(broken.operator, 'publishCheck'), false);
    await assert.rejects(broken.owner.start(),
      { code: 'GUARDIAN_CHILD_EXIT_BEFORE_READY' });
    const failed = broken.operator.incidentEvidence();
    frozenSafe(failed);
    assert.equal(failed.availability, 'LOCAL_SNAPSHOT');
    assert.equal(failed.selectedFailure.errorCode,
      'GUARDIAN_CHILD_EXIT_BEFORE_READY');
    assert.equal(failed.eventSequence, 1);
    const fixed = createGuardianLocalOperatorSession({
      directory, fileName: journalName,
      cwd: path.dirname(realWorker), entrypoint: realWorker,
      startupTimeoutMs: 4000, shutdownTimeoutMs: 600,
    });
    await fixed.owner.start();
    await fixed.owner.stop();
    const later = fixed.operator.incidentEvidence({
      eventId: failed.selectedFailure.eventId,
    });
    frozenSafe(later);
    assert.equal(later.journalEntries, 2);
    assert.equal(later.failureCount, 1);
    assert.equal(later.selectedFailure.state, 'FAILED');
    assert.equal(later.nextReceipt.state, 'STOPPED');
    assert.equal(later.manualInterventionRequired, true);
    const bytes = fs.readFileSync(journalPath(directory));
    const repeat = fixed.operator.incidentEvidence({
      eventId: failed.selectedFailure.eventId,
    });
    assert.deepEqual(later, repeat);
    assert.deepEqual(fs.readFileSync(journalPath(directory)), bytes);
  });
});


test('Controller status accessors are never invoked or promoted to a clean fault packet', async () => {
  await temp(async (directory) => {
    journal(directory).append(receipt('FAILED'));
    let reads = 0;
    const malicious = { status() {
      const value = {
        releaseAuthority: 'NOT_ISSUED', activationAllowed: false,
        automaticRestartAllowed: false,
      };
      Object.defineProperty(value, 'state', {
        enumerable: true, get() { reads++; return 'STOPPED'; },
      });
      return value;
    } };
    const diagnostic = reader(directory, malicious);
    const packet = diagnostic.incidentEvidence();
    frozenSafe(packet);
    assert.equal(packet.availability, 'UNAVAILABLE');
    assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
    assert.equal(packet.sourceReason, 'GUARDIAN_DIAGNOSTICS_CONTROLLER_UNVERIFIED');
    assert.equal(packet.selectedFailure, null);
    assert.equal(reads, 0);
    const page = diagnostic.recentEvents();
    assert.deepEqual(page.entries, []);
    assert.equal(page.reason, 'GUARDIAN_DIAGNOSTICS_CONTROLLER_UNVERIFIED');
  });
});

test('directory permissions or inode changes AFTER construction fail closed', async () => {
  await temp(async (directory) => {
    journal(directory).append(receipt('FAILED'));
    const diagnostic = reader(directory);
    assert.equal(diagnostic.incidentEvidence().availability, 'LOCAL_SNAPSHOT');
    fs.chmodSync(directory, 0o777);
    try {
      const packet = diagnostic.incidentEvidence();
      frozenSafe(packet);
      assert.equal(packet.reason, 'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
      assert.equal(packet.sourceReason, 'GUARDIAN_DIAGNOSTICS_DIRECTORY_UNVERIFIED');
      assert.equal(packet.selectedFailure, null);
      assert.equal(packet.journalSha256, null);
    } finally { fs.chmodSync(directory, 0o700); }
    const moved = directory + '-renamed';
    fs.renameSync(directory, moved);
    try {
      fs.mkdirSync(directory, 0o700);
      fs.writeFileSync(journalPath(directory),
        fs.readFileSync(journalPath(moved)), { mode: 0o600 });
      const packet = diagnostic.incidentEvidence();
      frozenSafe(packet);
      assert.equal(packet.availability, 'UNAVAILABLE');
      assert.equal(packet.sourceReason, 'GUARDIAN_DIAGNOSTICS_DIRECTORY_UNVERIFIED');
      assert.equal(packet.selectedFailure, null);
      assert.equal(packet.evidenceSha256, null);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
      fs.renameSync(moved, directory);
    }
    assert.equal(diagnostic.incidentEvidence().availability, 'LOCAL_SNAPSHOT');
  });
});
