'use strict';
// G36A source-only integration: generation V2 launch ledger inherits G35
// receipt-journal inode, permission and in-place byte continuity guards.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  createGuardianLocalReceiptJournal,
  generationLedgerName,
  observeLocalActiveGenerations,
} = require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const NAME = 'guardian-g36-integration.jsonl';
const IDS = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
const OWNER = Object.freeze({ activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
const LEGACY = Object.freeze({
  state: 'STOPPED', errorCode: null, hostStopped: true,
  ...OWNER, automaticRestartAllowed: false,
});
const launch = (generationId) => ({ generationId, ...OWNER });
const terminal = (generationId) => ({ ...LEGACY, generationId });
const rows = (file) => fs.readFileSync(file, 'utf8').trimEnd().split('\n').map(JSON.parse);

function withSandbox(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g36-'));
  const directory = path.join(root, 'owner');
  fs.mkdirSync(directory, { mode: 0o700 });
  const receipt = path.join(directory, NAME);
  const ledger = path.join(directory, generationLedgerName(NAME));
  try {
    const writer = createGuardianLocalReceiptJournal({ directory, fileName: NAME });
    return fn({ directory, receipt, ledger, writer });
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
}
const failsClosed = (fn) => assert.throws(fn, { code: 'GUARDIAN_JOURNAL_WRITE_FAILED' });
function sameInodeRewrite(file) {
  const old = fs.readFileSync(file, 'utf8');
  const parsed = JSON.parse(old.split('\n')[0]);
  const replacement = old.replace(parsed.eventId,
    (parsed.eventId[0] === 'a' ? 'b' : 'a') + parsed.eventId.slice(1));
  assert.equal(Buffer.byteLength(replacement), Buffer.byteLength(old));
  const prior = fs.statSync(file);
  const fd = fs.openSync(file, 'r+');
  try { assert.equal(fs.writeSync(fd, Buffer.from(replacement), 0, Buffer.byteLength(replacement), 0), Buffer.byteLength(replacement)); }
  finally { fs.closeSync(fd); }
  assert.equal(fs.statSync(file).ino, prior.ino);
  return fs.readFileSync(file);
}

test('G36A legacy/v2 receipts and launch ledger coexist; live witness retires', () => {
  withSandbox(({ directory, receipt, ledger, writer }) => {
    assert.equal(fs.existsSync(receipt), false);
    assert.equal(fs.existsSync(ledger), false);
    writer.append(LEGACY);
    writer.recordLaunch(launch(IDS[0]));
    assert.equal(writer.recordReady(launch(IDS[0])).witnessed, true);
    assert.deepEqual(observeLocalActiveGenerations(fs.realpathSync(directory), NAME), [IDS[0]]);
    writer.append(terminal(IDS[0]));
    writer.recordLaunch(launch(IDS[1]));
    writer.append(terminal(IDS[1]));
    assert.deepEqual(observeLocalActiveGenerations(fs.realpathSync(directory), NAME), []);
    assert.deepEqual(rows(receipt).map(r => r.schemaVersion), [1, 2, 2]);
    assert.deepEqual(rows(ledger).map(r => r.generationId), IDS.slice(0, 2));
    for (const file of [receipt, ledger]) {
      assert.equal(fs.statSync(file).mode & 0o077, 0);
      assert.equal(fs.statSync(file).nlink, 1);
    }
  });
});

test('G36A launch ledger rejects same-inode equal-length rewrite after committed launch', () => {
  withSandbox(({ writer, ledger }) => {
    writer.recordLaunch(launch(IDS[0]));
    const changed = sameInodeRewrite(ledger);
    failsClosed(() => writer.recordLaunch(launch(IDS[1])));
    assert.ok(fs.readFileSync(ledger).equals(changed));
    assert.equal(rows(ledger).length, 1);
  });
});

test('G36A launch ledger refuses whole-record truncation even with valid final newline', () => {
  withSandbox(({ writer, ledger }) => {
    writer.recordLaunch(launch(IDS[0]));
    writer.recordLaunch(launch(IDS[1]));
    const before = fs.readFileSync(ledger);
    const boundary = before.indexOf(10) + 1;
    assert.ok(boundary > 1 && boundary < before.length);
    fs.truncateSync(ledger, boundary);
    const changed = fs.readFileSync(ledger);
    failsClosed(() => writer.recordLaunch(launch(IDS[2])));
    assert.ok(fs.readFileSync(ledger).equals(changed));
  });
});

test('G36A launch ledger refuses unobserved external append', () => {
  withSandbox(({ writer, ledger }) => {
    writer.recordLaunch(launch(IDS[0]));
    const line = fs.readFileSync(ledger);
    fs.appendFileSync(ledger, line);
    const changed = fs.readFileSync(ledger);
    failsClosed(() => writer.recordLaunch(launch(IDS[1])));
    assert.ok(fs.readFileSync(ledger).equals(changed));
  });
});

test('G36A generation ledger refuses byte-identical inode replacement', () => {
  withSandbox(({ writer, directory, ledger }) => {
    writer.recordLaunch(launch(IDS[0]));
    const before = fs.readFileSync(ledger);
    const replacement = path.join(directory, 'temporary-private-file');
    fs.writeFileSync(replacement, before, { mode: 0o600 });
    fs.renameSync(replacement, ledger);
    failsClosed(() => writer.recordLaunch(launch(IDS[1])));
    assert.ok(fs.readFileSync(ledger).equals(before));
  });
});

test('G36A generation ledger refuses hardlink and never alters linked contents', () => {
  withSandbox(({ writer, directory, ledger }) => {
    writer.recordLaunch(launch(IDS[0]));
    const link = path.join(directory, 'hardlink');
    fs.linkSync(ledger, link);
    const before = fs.readFileSync(ledger);
    failsClosed(() => writer.recordLaunch(launch(IDS[1])));
    assert.ok(fs.readFileSync(ledger).equals(before));
    assert.ok(fs.readFileSync(link).equals(before));
  });
});

test('G36A generation ledger does not follow substituted symlink', () => {
  withSandbox(({ writer, directory, ledger }) => {
    writer.recordLaunch(launch(IDS[0]));
    const victim = path.join(directory, 'victim');
    fs.writeFileSync(victim, 'NEVER_TOUCH\n', { mode: 0o600 });
    fs.unlinkSync(ledger);
    fs.symlinkSync(victim, ledger);
    failsClosed(() => writer.recordLaunch(launch(IDS[1])));
    assert.equal(fs.readFileSync(victim, 'utf8'), 'NEVER_TOUCH\n');
  });
});

test('G36A v2 journal terminal refuses same-inode equal-length rewrite', () => {
  withSandbox(({ writer, receipt }) => {
    writer.recordLaunch(launch(IDS[0]));
    writer.append(terminal(IDS[0]));
    const changed = sameInodeRewrite(receipt);
    failsClosed(() => writer.append(terminal(IDS[1])));
    assert.ok(fs.readFileSync(receipt).equals(changed));
  });
});
