'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { createGuardianLocalBaselineWitness } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-baseline-witness.cjs');
const { createGuardianLocalReceiptJournal, generationLedgerName } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const FILE = 'guardian-g32-baseline.jsonl';
function id() { return crypto.randomBytes(16).toString('hex'); }
async function temporary(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g32-'));
  try {
    const writer = createGuardianLocalReceiptJournal({
      directory: dir, fileName: FILE,
    });
    const journal = path.join(fs.realpathSync(dir), FILE);
    const ledger = path.join(fs.realpathSync(dir), generationLedgerName(FILE));
    const create = (extras = {}) => createGuardianLocalBaselineWitness({
      directory: dir, fileName: FILE, ...extras,
    });
    const pair = (state = 'FAILED') => {
      const generationId = id();
      writer.recordLaunch({ generationId, activationAllowed: false,
        releaseAuthority: 'NOT_ISSUED' });
      writer.append({
        generationId, state, errorCode: state === 'FAILED' ?
          'GUARDIAN_CHILD_EXIT_UNVERIFIED' : null,
        hostStopped: state === 'STOPPED',
        activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
        automaticRestartAllowed: false,
      });
    };
    return await fn({ dir, writer, journal, ledger, create, pair });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
function hold(r) {
  assert.equal(r.schemaVersion, 1);
  assert.equal(r.kind, 'GUARDIAN_LOCAL_GENERATION_BASELINE_V1');
  assert.equal(r.status, 'SOURCE_ONLY_HOLD');
  assert.equal(r.externalAnchorVerified, false);
  assert.equal(r.custodyVerified, false);
  assert.equal(r.historicalCompletenessVerified, false);
  assert.equal(r.liveness, 'NOT_PROVEN');
  assert.equal(r.manualInterventionRequired, true);
  assert.equal(r.automaticRestartAllowed, false);
  assert.equal(r.activationAllowed, false);
  assert.equal(r.releaseAuthority, 'NOT_ISSUED');
  assert.ok(Object.isFrozen(r));
  for (const key of ['pid', 'token', 'privateKey', 'rawJournal',
    'approve', 'restart', 'reset', 'clearHold', 'publishCheck']) {
    assert.equal(Object.hasOwn(r, key), false);
  }
}
function noFiles(dir) { return fs.readdirSync(dir).length === 0; }

test('inert construction and unanchored dual absence never establish fresh-install trust', async () => {
  await temporary(async (f) => {
    const witness = f.create();
    assert.ok(Object.isFrozen(witness));
    assert.deepEqual(Object.keys(witness), ['inspect']);
    assert.equal(noFiles(f.dir), true);
    for (let i=0;i<2;i++) {
      const r = witness.inspect();
      hold(r);
      assert.equal(r.reason, 'GUARDIAN_BASELINE_UNATTESTED_DUAL_ABSENCE');
      assert.equal(r.comparison, 'NOT_VERIFIED');
      assert.equal(r.observationSequence, 0);
    }
    assert.equal(noFiles(f.dir), true);
  });
});

test('first valid pair remains unanchored; repeated observations prove only local memory continuity', async () => {
  await temporary(async (f) => {
    f.pair();
    const witness = f.create();
    const before = [fs.readFileSync(f.journal), fs.readFileSync(f.ledger)];
    const a = witness.inspect(), b = witness.inspect();
    hold(a); hold(b);
    assert.equal(a.reason, 'GUARDIAN_BASELINE_UNANCHORED_FIRST_PAIR');
    assert.equal(b.reason, 'GUARDIAN_BASELINE_EPHEMERAL_APPEND_OBSERVED');
    assert.equal(a.comparison, 'LOCAL_MEMORY_ONLY');
    assert.equal(b.comparison, 'LOCAL_MEMORY_ONLY');
    assert.equal(a.observationSequence, 1);
    assert.equal(b.observationSequence, 2);
    assert.match(a.journalSha256, /^[0-9a-f]{64}$/);
    assert.match(a.ledgerSha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(fs.readFileSync(f.journal), before[0]);
    assert.deepEqual(fs.readFileSync(f.ledger), before[1]);
  });
});

test('valid ledger/journal append advances only a local untrusted observer', async () => {
  await temporary(async (f) => {
    f.pair();
    const w = f.create(), previous = w.inspect();
    f.pair('STOPPED');
    const newState = w.inspect();
    hold(newState);
    assert.equal(newState.reason, 'GUARDIAN_BASELINE_EPHEMERAL_APPEND_OBSERVED');
    assert.equal(newState.observationSequence, 2);
    assert.ok(newState.journalBytes > previous.journalBytes);
    assert.ok(newState.ledgerBytes > previous.ledgerBytes);
    assert.notEqual(newState.journalSha256, previous.journalSha256);
    assert.notEqual(newState.ledgerSha256, previous.ledgerSha256);
  });
});

test('both stores deleted after first observation latch loss permanently', async () => {
  await temporary(async (f) => {
    f.pair();
    const witness = f.create();
    assert.equal(witness.inspect().observationSequence, 1);
    const bytes = [fs.readFileSync(f.journal), fs.readFileSync(f.ledger)];
    fs.unlinkSync(f.journal); fs.unlinkSync(f.ledger);
    const failed = witness.inspect();
    hold(failed);
    assert.equal(failed.reason,
      'GUARDIAN_BASELINE_BOTH_REMOVED_AFTER_OBSERVATION');
    assert.equal(failed.comparison, 'NOT_VERIFIED');
    assert.equal(failed.journalSha256, null);
    fs.writeFileSync(f.journal, bytes[0], { mode: 0o600 });
    fs.writeFileSync(f.ledger, bytes[1], { mode: 0o600 });
    assert.equal(witness.inspect().reason,
      'GUARDIAN_BASELINE_BOTH_REMOVED_AFTER_OBSERVATION');
    // A new, unanchored observer cannot detect deletion prior to its birth.
    const restarted = f.create().inspect();
    hold(restarted);
    assert.equal(restarted.reason, 'GUARDIAN_BASELINE_UNANCHORED_FIRST_PAIR');
  });
});

test('one store disappearing after baseline is fail-closed and sticky', async () => {
  await temporary(async (f) => {
    f.pair();
    const witness = f.create();
    witness.inspect();
    fs.unlinkSync(f.ledger);
    const r = witness.inspect();
    hold(r);
    assert.equal(r.reason, 'GUARDIAN_BASELINE_PARTIAL_REMOVAL');
    assert.equal(r.ledgerSha256, null);
    assert.equal(witness.inspect().reason, 'GUARDIAN_BASELINE_PARTIAL_REMOVAL');
  });
});

test('ledger created before first terminal receipt is incomplete, not a trusted baseline', async () => {
  await temporary(async (f) => {
    f.writer.recordLaunch({ generationId: id(),
      activationAllowed:false, releaseAuthority:'NOT_ISSUED' });
    const w = f.create();
    const r = w.inspect(); hold(r);
    assert.equal(r.reason, 'GUARDIAN_BASELINE_PAIR_INCOMPLETE');
    assert.equal(r.observationSequence, 0);
    assert.equal(r.comparison, 'NOT_VERIFIED');
  });
});

test('journal truncated or replaced after baseline fails without a local approval', async () => {
  await temporary(async (f) => {
    f.pair(); const w = f.create(); w.inspect();
    const old = fs.readFileSync(f.journal);
    fs.truncateSync(f.journal, old.length - 1);
    const broken = w.inspect(); hold(broken);
    assert.equal(broken.comparison, 'NOT_VERIFIED');
    assert.equal(broken.journalSha256, null);
    assert.equal(w.inspect().reason, broken.reason);
  });
});

test('same bytes on new inode is still a broken baseline chain', async () => {
  await temporary(async (f) => {
    f.pair(); const w = f.create(); w.inspect();
    const bytes = fs.readFileSync(f.ledger);
    const oldInode = fs.statSync(f.ledger).ino;
    fs.renameSync(f.ledger, f.ledger + '.old');
    fs.writeFileSync(f.ledger, bytes, { mode: 0o600 });
    assert.notEqual(fs.statSync(f.ledger).ino, oldInode);
    const r = w.inspect(); hold(r);
    assert.equal(r.reason, 'GUARDIAN_BASELINE_CONTINUITY_BROKEN');
    assert.equal(r.comparison, 'NOT_VERIFIED');
  });
});

test('unknown/replayed generation journal is never used to establish a baseline', async () => {
  await temporary(async (f) => {
    f.pair();
    fs.appendFileSync(f.journal, fs.readFileSync(f.journal));
    const w = f.create();
    const r = w.inspect(); hold(r);
    assert.equal(r.reason, 'GUARDIAN_BASELINE_RECONCILIATION_UNVERIFIED');
    assert.equal(r.observationSequence, 0);
  });
});

test('unsafe modes, journal symlink and corrupt UTF-8 are not a basis of local continuity', async () => {
  await temporary(async (f) => {
    f.pair();
    const w = f.create();
    fs.chmodSync(f.journal, 0o644);
    assert.equal(w.inspect().reason, 'GUARDIAN_BASELINE_PAIR_UNVERIFIED');
    fs.chmodSync(f.journal, 0o600);
    // Error latched; cannot auto-recover the same witness.
    assert.equal(w.inspect().reason, 'GUARDIAN_BASELINE_PAIR_UNVERIFIED');
    const newer = f.create();
    fs.unlinkSync(f.journal);
    fs.symlinkSync('/dev/null', f.journal);
    const r = newer.inspect(); hold(r);
    assert.equal(r.comparison, 'NOT_VERIFIED');
    assert.equal(r.reason, 'GUARDIAN_BASELINE_PAIR_UNVERIFIED');
  });
});

test('in-place pair mutation during inspection becomes a permanent HOLD', async () => {
  await temporary(async (f) => {
    f.pair();
    const w = f.create();
    const original = fs.openSync;
    let opens = 0, changed = false;
    try {
      fs.openSync = function(filename, ...args) {
        if (typeof filename === 'string' &&
            path.resolve(filename) === path.resolve(f.journal)) {
          opens++;
          if (opens === 3) {
            changed = true;
            f.pair('STOPPED');
          }
        }
        return original.call(this, filename, ...args);
      };
      const observed = w.inspect();
      hold(observed);
      assert.equal(changed, true);
      assert.equal(observed.reason, 'GUARDIAN_BASELINE_PAIR_CHANGED_DURING_READ');
      assert.equal(observed.comparison, 'NOT_VERIFIED');
    } finally { fs.openSync = original; }
    assert.equal(w.inspect().reason, 'GUARDIAN_BASELINE_PAIR_CHANGED_DURING_READ');
  });
});

test('hostile constructor accessors and unsupported paths reject before reads', async () => {
  await temporary(async (f) => {
    for (const config of [
      { directory:'relative', fileName:FILE },
      { directory:f.dir, fileName:'../escape.jsonl' },
      { directory:f.dir, fileName:FILE, maxBytes:1 },
      { directory:f.dir, fileName:FILE, extra:'PRIVATE_TOKEN' },
      new Proxy({}, { ownKeys(){throw new Error('SECRET');} }),
    ]) assert.throws(() => createGuardianLocalBaselineWitness(config));
    assert.equal(noFiles(f.dir), true);
  });
});
