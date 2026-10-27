'use strict';
// Source-only local handoff receipt classification, no production mutation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createGuardianOfflineIntake } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-intake.cjs');
const { makeBundle, verifyBundleHistory } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs');
const { createGuardianOfflineIncidentBrief } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
function good() {
  return { state: 'STOPPED', errorCode: null, hostStopped: true,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false };
}
function bad() {
  return { state: 'FAILED', errorCode: 'GUARDIAN_CHILD_EXIT_UNVERIFIED',
    hostStopped: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED', automaticRestartAllowed: false };
}
async function withFixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-intake-'));
  const evidenceDir = path.join(root, 'evidence');
  const inboxDir = path.join(root, 'inbox');
  fs.mkdirSync(evidenceDir, { mode: 0o700 });
  fs.mkdirSync(inboxDir, { mode: 0o700 });
  const eventName = 'guardian-source-events.jsonl';
  const journal = createGuardianLocalReceiptJournal({
    directory: evidenceDir, fileName: eventName,
  });
  const operator = createGuardianLocalOperatorSession({
    cwd: path.dirname(worker), entrypoint: worker,
    directory: evidenceDir, fileName: eventName,
    startupTimeoutMs: 4000, shutdownTimeoutMs: 900,
  }).operator;
  const capture = () => createGuardianOfflineIncidentBrief({
    operator, limit: 10,
  }).capture();
  const inputName = 'guardian-owner-intake.jsonl';
  const create = (extra = {}) => createGuardianOfflineIntake({
    directory: inboxDir, fileName: inputName, ...extra,
  });
  const readReceipts = () => {
    const filename = path.join(inboxDir, inputName);
    return fs.existsSync(filename) ?
      fs.readFileSync(filename, 'utf8').trim().split('\n')
        .filter(Boolean).map(JSON.parse) : [];
  };
  try {
    return await run({
      root, inboxDir, journal, capture, create,
      readReceipts, inputName,
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
function assertHold(value) {
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, 'GUARDIAN_LOCAL_OFFLINE_INTAKE_V1');
  assert.equal(value.status, 'SOURCE_ONLY_HOLD');
  assert.equal(value.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(value.custodyVerified, false);
  assert.equal(value.liveness, 'NOT_PROVEN');
  assert.equal(value.manualInterventionRequired, true);
  assert.equal(value.automaticRestartAllowed, false);
  assert.equal(value.activationAllowed, false);
  assert.equal(value.releaseAuthority, 'NOT_ISSUED');
  assert.equal(Object.isFrozen(value), true);
  for (const field of ['raw', 'events', 'pid', 'privateKey',
    'token', 'restart', 'checkWriter', 'clearHold']) {
    assert.equal(Object.hasOwn(value, field), false);
  }
}
function checkRecord(row) {
  assert.deepEqual(Object.keys(row).sort(), [
    'schemaVersion','kind','receiptId','timestamp','decision','reason',
    'bundleSha256','custodyVerified','liveness','automaticRestartAllowed',
    'activationAllowed','releaseAuthority',
  ].sort());
  assert.equal(row.kind, 'GUARDIAN_LOCAL_OFFLINE_INTAKE_RECORD_V1');
  assert.equal(row.releaseAuthority, 'NOT_ISSUED');
  assert.equal(row.activationAllowed, false);
  assert.equal(row.custodyVerified, false);
  assert.equal(row.automaticRestartAllowed, false);
  assert.match(row.receiptId, /^[0-9a-f-]{36}$/);
}
function validPair(f) {
  f.journal.append(good());
  const a = f.capture();
  f.journal.append(bad());
  const b = f.capture();
  assert.equal(verifyBundleHistory(makeBundle([a,b])).comparison,
    'LOCAL_STRUCTURAL_OBSERVATION_ONLY');
  return { a, b, json: JSON.stringify(makeBundle([a,b])) };
}

test('inert construction does not open inbox or modify source evidence', async () => {
  await withFixture(async (f) => {
    const before = fs.readdirSync(f.inboxDir);
    const receiver = f.create();
    assert.equal(Object.isFrozen(receiver), true);
    assert.deepEqual(Object.keys(receiver), ['receive']);
    assert.deepEqual(fs.readdirSync(f.inboxDir), before);
    assert.deepEqual(f.readReceipts(), []);
  });
});

test('compatible full-history bundle becomes QUARANTINED with one durable redacted receipt', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const original = f.journal && fs.readdirSync(f.inboxDir).length;
    assert.equal(original, 0);
    const input = f.create();
    const result = input.receive(json);
    assertHold(result);
    assert.equal(result.decision, 'QUARANTINED');
    assert.equal(result.reason, 'GUARDIAN_INTAKE_LOCAL_HISTORY_QUARANTINED');
    assert.match(result.bundleSha256, /^[0-9a-f]{64}$/);
    assert.match(result.receiptSha256, /^[0-9a-f]{64}$/);
    const file = path.join(f.inboxDir, f.inputName);
    const bytes = fs.readFileSync(file);
    assert.equal(bytes.toString('utf8').split('\n').length, 2);
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),
      result.receiptSha256);
    assert.equal(fs.statSync(file).mode & 0o077, 0);
    const rows = f.readReceipts();
    assert.equal(rows.length, 1);
    checkRecord(rows[0]);
    assert.equal(rows[0].receiptId, result.receiptId);
    assert.equal(rows[0].bundleSha256, result.bundleSha256);
    assert.equal(rows[0].decision, 'QUARANTINED');
    assert.ok(!bytes.toString('utf8').includes('"events"'));
    assert.ok(!bytes.toString('utf8').includes('PRIVATE KEY'));
  });
});

test('separate intakes append independent local HOLD receipts without overwrite or auto-restart', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const intake1 = f.create(), intake2 = f.create();
    const a = intake1.receive(json);
    const b = intake2.receive(json);
    assertHold(a);
    assertHold(b);
    assert.equal(a.decision, 'QUARANTINED');
    assert.equal(b.decision, 'QUARANTINED');
    assert.notEqual(a.receiptId, b.receiptId);
    assert.equal(f.readReceipts().length, 2);
    assert.deepEqual(f.readReceipts().map((row) => row.decision),
      ['QUARANTINED', 'QUARANTINED']);
  });
});

test('invalid checksum, modified nested event, duplicate JSON key rejected and rejection logged', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const examples = [
      [json.replace('"bundleSha256":"','"bundleSha256":"1'),
        'GUARDIAN_INTAKE_BUNDLE_INVALID'],
      [json.replace('"count":2','"count":2,"count":2'),
        'GUARDIAN_INTAKE_INPUT_INVALID'],
      [json.replace('"state":"STOPPED"','"state":"STOPPED","state":"FAILED"'),
        'GUARDIAN_INTAKE_INPUT_INVALID'],
      [json.replace('"automaticRestartAllowed":false',
        '"automaticRestartAllowed":true'),
        'GUARDIAN_INTAKE_BUNDLE_INVALID'],
      [json + ' INJECTED_PRIVATE_KEY', 'GUARDIAN_INTAKE_INPUT_INVALID'],
    ];
    const intake = f.create();
    for (const [source, expected] of examples) {
      const r = intake.receive(source);
      assertHold(r);
      assert.equal(r.decision, 'REJECTED');
      assert.equal(r.reason, expected);
      assert.equal(r.bundleSha256, null);
    }
    assert.equal(f.readReceipts().length, examples.length);
    assert.ok(!fs.readFileSync(path.join(f.inboxDir, f.inputName), 'utf8')
      .includes('INJECTED_PRIVATE_KEY'));
  });
});

test('checksum-valid contradictory snapshot order is rejected with a bounded reason', async () => {
  await withFixture(async (f) => {
    const { a, b } = validPair(f);
    const invalidHistory = JSON.stringify(makeBundle([b, a]));
    const result = f.create().receive(invalidHistory);
    assertHold(result);
    assert.equal(result.decision, 'REJECTED');
    assert.equal(result.reason, 'GUARDIAN_INTAKE_HISTORY_CONFLICT');
    assert.match(result.bundleSha256, /^[0-9a-f]{64}$/);
    assert.equal(f.readReceipts()[0].reason,
      'GUARDIAN_INTAKE_HISTORY_CONFLICT');
  });
});

test('partial journal window is rejected as incomplete with no false acceptance', async () => {
  await withFixture(async (f) => {
    f.journal.append(good());
    const older = f.capture();
    for (let i=0; i<10; i++) f.journal.append(good());
    const recent = f.capture();
    const bundle = JSON.stringify(makeBundle([older, recent]));
    const result = f.create().receive(bundle);
    assertHold(result);
    assert.equal(result.decision, 'REJECTED');
    assert.equal(result.reason, 'GUARDIAN_INTAKE_HISTORY_INCOMPLETE');
    assert.equal(f.readReceipts()[0].decision, 'REJECTED');
  });
});

test('P0 checksum-consistent source never leaves quarantine for acceptance', async () => {
  await withFixture(async (f) => {
    const p0 = f.capture(); // source journal is missing
    f.journal.append(good());
    const later = f.capture();
    const raw = JSON.stringify(makeBundle([p0, later]));
    const result = f.create().receive(raw);
    assertHold(result);
    assert.equal(result.decision, 'REJECTED');
    assert.equal(result.reason, 'GUARDIAN_INTAKE_HISTORY_UNVERIFIED');
  });
});

test('oversized, wrong type, malformed or empty input creates sanitized rejected receipts', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const input = f.create();
    for (const unsafe of [
      undefined, null, 123, Buffer.from(json),
      {}, [], '', ' ', '{', ' '.repeat(96_001),
      new Proxy({}, {get(){throw new Error('TOKEN_INJECT');}}),
    ]) {
      const output = input.receive(unsafe);
      assertHold(output);
      assert.equal(output.decision, 'REJECTED');
      assert.equal(output.reason, 'GUARDIAN_INTAKE_INPUT_INVALID');
      assert.equal(JSON.stringify(output).includes('TOKEN_INJECT'), false);
    }
    assert.equal(f.readReceipts().length, 11);
  });
});

test('symlink or unsafe permissioned receipt path fails closed with no raw leakage', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const target = path.join(f.inboxDir, f.inputName);
    fs.symlinkSync('/dev/null', target);
    const output = f.create().receive(json);
    assertHold(output);
    assert.equal(output.decision, 'REJECTED');
    assert.equal(output.reason, 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED');
    assert.equal(output.receiptId, null);
    assert.equal(output.receiptSha256, null);
    fs.unlinkSync(target);
    fs.writeFileSync(target, '');
    fs.chmodSync(target, 0o644);
    const again = f.create().receive(json);
    assert.equal(again.reason, 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED');
    assert.equal(fs.readFileSync(target, 'utf8'), '');
  });
});

test('journal capacity exceeded becomes storage-unverified instead of success', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const i = f.create({ maxJournalBytes: 1024 });
    const accepted = [];
    for (let n=0; n<8; n++) accepted.push(i.receive(json));
    assert.ok(accepted.some((row) =>
      row.reason === 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED'));
    assert.ok(accepted.every((row) => row.status === 'SOURCE_ONLY_HOLD'));
    assert.ok(accepted.some((row) => row.decision === 'QUARANTINED'));
    assert.ok(f.readReceipts().length < 8);
  });
});

test('new owner directory permissions cannot silently allow insecure journaling', async () => {
  await withFixture(async (f) => {
    const { json } = validPair(f);
    const intake = f.create();
    fs.chmodSync(f.inboxDir, 0o777);
    try {
      const result = intake.receive(json);
      assertHold(result);
      assert.equal(result.reason, 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED');
      assert.equal(f.readReceipts().length, 0);
      assert.throws(() => f.create(),
        { code: 'GUARDIAN_INTAKE_DIRECTORY_UNVERIFIED' });
    } finally { fs.chmodSync(f.inboxDir, 0o700); }
  });
});

test('intake refuses extra config, invalid filename or cwd without writing anything', async () => {
  await withFixture(async (f) => {
    const broken = [
      { unsafe: true }, { fileName: '../evil.jsonl' },
      { fileName: 'bad.txt' }, { maxJournalBytes: 1 },
      { maxJournalBytes: Infinity }, { directory: 'relative/path' },
    ];
    for (const extra of broken) {
      assert.throws(() => f.create(extra));
    }
    assert.deepEqual(f.readReceipts(), []);
  });
});
