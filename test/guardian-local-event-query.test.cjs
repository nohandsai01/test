'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalDiagnostics } =
  require('../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
async function withTmp(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nh-guardian-event-query-'));
  try { return await callback(directory); }
  finally { fs.rmSync(directory, { force: true, recursive: true }); }
}
function makeJournal(directory) {
  return createGuardianLocalReceiptJournal({
    directory, fileName: 'guardian-events.jsonl',
  });
}
function makeDiagnostics(directory, processState = 'STOPPED', status = null) {
  return createGuardianLocalDiagnostics({
    directory, fileName: 'guardian-events.jsonl',
    controller: { status: status ?? (() => ({
      state: processState, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
    })) },
  });
}
function good() {
  return {
    state: 'STOPPED', errorCode: null, hostStopped: true,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  };
}
function bad() {
  return {
    state: 'FAILED', errorCode: 'GUARDIAN_CHILD_EXIT_UNVERIFIED',
    hostStopped: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false,
  };
}
function assertHold(result) {
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.releaseAuthority, 'NOT_ISSUED');
  assert.equal(result.activationAllowed, false);
  assert.equal(result.automaticRestartAllowed, false);
  assert.equal(result.liveness, 'NOT_PROVEN');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.entries));
}
function assertMinimal(row) {
  assert.deepEqual(Object.keys(row).sort(), [
    'errorCode', 'eventId', 'state', 'timestamp',
  ]);
  assert.ok(Object.isFrozen(row));
}

test('read-only event query does not create journal, mutate controller or grant authority', async () => {
  await withTmp(async (directory) => {
    let called = 0;
    const diagnostic = makeDiagnostics(directory, 'CREATED', () => {
      called++;
      return { state: 'CREATED', releaseAuthority: 'NOT_ISSUED',
        activationAllowed: false, automaticRestartAllowed: false };
    });
    const result = diagnostic.recentEvents();
    assertHold(result);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal(result.manualInterventionRequired, true);
    assert.equal(result.entries.length, 0);
    assert.equal(result.journalSha256, null);
    assert.equal(result.nextCursor, null);
    assert.equal(result.incident, null);
    assert.equal(called, 1);
    assert.equal(fs.readdirSync(directory).length, 0);
  });
});

test('bounded pages cover every event once, newest first, with fixed digest cursor', async () => {
  await withTmp(async (directory) => {
    const writer = makeJournal(directory);
    for (let i = 0; i < 7; i++) writer.append(good());
    const digestBefore = fs.readFileSync(path.join(directory, 'guardian-events.jsonl'));
    const diagnostics = makeDiagnostics(directory);
    let cursor = null;
    const events = [];
    for (let pageNo = 0; pageNo < 3; pageNo++) {
      const page = diagnostics.recentEvents({ limit: 3, cursor });
      assertHold(page);
      assert.equal(page.reason, 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP');
      assert.equal(page.journalEntries, 7);
      assert.equal(page.manualInterventionRequired, false);
      assert.match(page.journalSha256, /^[0-9a-f]{64}$/);
      assert.equal(page.incident.failureCount, 0);
      assert.equal(page.incident.manualInterventionRequired, false);
      assert.ok(Object.isFrozen(page.incident));
      assert.equal(page.incident.firstFailure, null);
      assert.equal(page.incident.latestFailure, null);
      for (const item of page.entries) { assertMinimal(item); events.push(item.eventId); }
      cursor = page.nextCursor;
      if (cursor) assert.ok(Object.isFrozen(cursor));
    }
    assert.equal(cursor, null);
    assert.equal(events.length, 7);
    assert.equal(new Set(events).size, 7);
    const file = path.join(directory, 'guardian-events.jsonl');
    assert.deepEqual(fs.readFileSync(file), digestBefore);
    const rawIDs = digestBefore.toString('utf8').trim().split('\n')
      .map((line) => JSON.parse(line).eventId);
    assert.deepEqual(events, rawIDs.reverse());
  });
});

test('a stale cursor after an append fails closed with no partial events', async () => {
  await withTmp(async (directory) => {
    const writer = makeJournal(directory);
    writer.append(good());
    writer.append(good());
    writer.append(good());
    const diagnostics = makeDiagnostics(directory);
    const page = diagnostics.recentEvents({ limit: 1 });
    assert.ok(page.nextCursor);
    const oldDigest = page.journalSha256;
    writer.append(good());
    const stale = diagnostics.recentEvents({
      limit: 2, cursor: page.nextCursor,
    });
    assertHold(stale);
    assert.equal(stale.reason, 'GUARDIAN_DIAGNOSTICS_CURSOR_STALE');
    assert.equal(stale.manualInterventionRequired, true);
    assert.deepEqual(stale.entries, []);
    assert.equal(stale.journalEntries, 0);
    assert.equal(stale.journalSha256, null);
    assert.equal(stale.nextCursor, null);
    assert.equal(stale.incident, null);
    assert.notEqual(diagnostics.recentEvents().journalSha256, oldDigest);
  });
});

test('a historical failure remains in incident evidence even after clean terminal', async () => {
  await withTmp(async (directory) => {
    const writer = makeJournal(directory);
    writer.append(good());
    writer.append(bad());
    writer.append(good());
    const diagnostics = makeDiagnostics(directory);
    const first = diagnostics.recentEvents({ limit: 1 });
    assertHold(first);
    assert.equal(first.entries.length, 1);
    assert.equal(first.entries[0].state, 'STOPPED');
    assert.equal(first.lastTerminal.state, 'STOPPED');
    assert.equal(first.reason, 'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
    assert.equal(first.manualInterventionRequired, true);
    assert.equal(first.incident.failureCount, 1);
    assertMinimal(first.incident.firstFailure);
    assertMinimal(first.incident.latestFailure);
    assert.equal(first.incident.firstFailure.state, 'FAILED');
    assert.equal(first.incident.manualInterventionRequired, true);
    const older = diagnostics.recentEvents({ limit: 2, cursor: first.nextCursor });
    assert.deepEqual(older.entries.map((entry) => entry.state), ['FAILED', 'STOPPED']);
    assert.equal(older.nextCursor, null);
    assert.equal(older.incident.failureCount, 1);
    assert.equal(first.incident.firstFailure.eventId,
      older.incident.latestFailure.eventId);
    assert.ok(!Object.hasOwn(diagnostics, 'clear'));
  });
});

test('corrupt, duplicate-key or truncated evidence returns no event details', async () => {
  await withTmp(async (directory) => {
    const writer = makeJournal(directory);
    writer.append(good());
    writer.append(bad());
    const file = path.join(directory, 'guardian-events.jsonl');
    const original = fs.readFileSync(file, 'utf8');
    for (const content of [
      original.slice(0, -1),
      original.replace('"schemaVersion":1,', '"schemaVersion":1,"schemaVersion":1,'),
      original.replace('"releaseAuthority":"NOT_ISSUED"', '"releaseAuthority":"ISSUED"'),
      original + '{"secret":"PRIVATE_KEY"}\n',
      original + original,
    ]) {
      fs.writeFileSync(file, content);
      const page = makeDiagnostics(directory).recentEvents({ limit: 50 });
      assertHold(page);
      assert.equal(page.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_INVALID');
      assert.equal(page.manualInterventionRequired, true);
      assert.equal(page.journalSha256, null);
      assert.equal(page.incident, null);
      assert.deepEqual(page.entries, []);
      assert.ok(!JSON.stringify(page).includes('PRIVATE_KEY'));
    }
  });
});

test('invalid limit, cursor type, extra cursor fields and out-of-range offset reject', async () => {
  await withTmp(async (directory) => {
    makeJournal(directory).append(good());
    const query = makeDiagnostics(directory);
    const malformed = [
      null, 1, [], '5', { limit: 0 }, { limit: 51 },
      { limit: 1.5 }, { limit: '5' }, { limit: Number.MAX_SAFE_INTEGER },
      { extra: 'override' }, { cursor: {} },
      { cursor: { journalSha256: 'a'.repeat(64), before: 0 } },
      { cursor: { journalSha256: 'a'.repeat(64), before: 99999 } },
      { cursor: { journalSha256: 'a'.repeat(64), before: 1, extra: 1 } },
    ];
    const before = fs.readFileSync(path.join(directory, 'guardian-events.jsonl'));
    for (const opts of malformed) {
      assert.throws(() => query.recentEvents(opts), /GUARDIAN_DIAGNOSTICS_PAGE_INVALID/);
    }
    assert.deepEqual(fs.readFileSync(path.join(directory, 'guardian-events.jsonl')), before);
    const forged = query.recentEvents({
      limit: 1, cursor: { journalSha256: 'b'.repeat(64), before: 1 },
    });
    assertHold(forged);
    assert.equal(forged.reason, 'GUARDIAN_DIAGNOSTICS_CURSOR_STALE');
  });
});

test('Operator exposes bounded event query but never process control or failure clearing', async () => {
  await withTmp(async (directory) => {
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(worker), entrypoint: worker,
      directory, fileName: 'guardian-events.jsonl',
      startupTimeoutMs: 4000, shutdownTimeoutMs: 600,
    });
    assert.deepEqual(Object.keys(session.operator).sort(), ['faultTriage', 'incidentEvidence', 'inspect', 'observeLocalContinuity', 'recentEvents', 'verifyIncidentEvidence']);
    assert.ok(!Object.hasOwn(session.operator, 'start'));
    assert.ok(!Object.hasOwn(session.operator, 'stop'));
    assert.ok(!Object.hasOwn(session.operator, 'clear'));
    const before = session.operator.recentEvents();
    assertHold(before);
    assert.equal(before.reason, 'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal((await session.owner.start()).state, 'RUNNING');
    const running = session.operator.recentEvents();
    assertHold(running);
    assert.equal(running.manualInterventionRequired, true);
    assert.equal((await session.owner.stop()).state, 'STOPPED');
    const file = path.join(directory, 'guardian-events.jsonl');
    const content = fs.readFileSync(file);
    const mtime = fs.statSync(file).mtimeMs;
    const end = session.operator.recentEvents({ limit: 1 });
    assertHold(end);
    assert.equal(end.reason, 'GUARDIAN_DIAGNOSTICS_CLEAN_STOP');
    assert.equal(end.entries.length, 1);
    assert.equal(end.entries[0].state, 'STOPPED');
    assert.deepEqual(fs.readFileSync(file), content);
    assert.equal(fs.statSync(file).mtimeMs, mtime);
  });
});

test('failed operator controller validation cannot disclose stored receipts', async () => {
  await withTmp(async (directory) => {
    makeJournal(directory).append(bad());
    const status = () => ({
      state: 'STOPPED', activationAllowed: true,
      releaseAuthority: 'ISSUED', automaticRestartAllowed: true,
    });
    const query = makeDiagnostics(directory, 'STOPPED', status);
    const result = query.recentEvents({ limit: 5 });
    assertHold(result);
    assert.equal(result.reason, 'GUARDIAN_DIAGNOSTICS_CONTROLLER_UNVERIFIED');
    assert.deepEqual(result.entries, []);
    assert.equal(result.incident, null);
    assert.equal(result.journalSha256, null);
  });
});


test('event query refuses accessor and Proxy traps without side effects or leaked event rows', async () => {
  await withTmp(async (directory) => {
    makeJournal(directory).append(good());
    const diagnostics = makeDiagnostics(directory);
    let accessed = 0;
    const withGetter = {};
    Object.defineProperty(withGetter, 'limit', {
      enumerable: true, get() { accessed++; return 2; },
    });
    assert.throws(() => diagnostics.recentEvents(withGetter),
      /GUARDIAN_DIAGNOSTICS_PAGE_INVALID/);
    const withCursorGetter = { limit: 1, cursor: {} };
    Object.defineProperty(withCursorGetter.cursor, 'before', {
      enumerable: true, get() { accessed++; return 1; },
    });
    withCursorGetter.cursor.journalSha256 = 'a'.repeat(64);
    assert.throws(() => diagnostics.recentEvents(withCursorGetter),
      /GUARDIAN_DIAGNOSTICS_PAGE_INVALID/);
    const throwsFromDescriptor = new Proxy({}, {
      ownKeys() { throw new Error('PRIVATE_CREDENTIAL'); },
    });
    assert.throws(() => diagnostics.recentEvents(throwsFromDescriptor),
      { message: 'GUARDIAN_DIAGNOSTICS_PAGE_INVALID' });
    assert.equal(accessed, 0);
    const clean = diagnostics.recentEvents({ limit: 1 });
    assertHold(clean);
    assert.equal(clean.entries.length, 1);
  });
});
