'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalJournalBudget } =
  require('../merge-gate-install/guardian-candidate/guardian-local-journal-budget.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const JOURNAL = 'guardian-budget.jsonl';
const LIMIT = 4096;
const child = path.join(__dirname, 'guardian-protected-worker-child.cjs');

function status(extra = {}) {
  return {
    state: 'CREATED', errorCode: null, pid: null,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false, ...extra,
  };
}
function config(directory, controller = { status: () => status() }) {
  return { controller, directory, fileName: JOURNAL, maxBytes: LIMIT };
}
async function temporary(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-budget-'));
  try { await fn(dir, path.join(dir, JOURNAL)); }
  finally { fs.chmodSync(dir, 0o700);
    fs.rmSync(dir, { recursive: true, force: true }); }
}
function file(target, n) {
  fs.writeFileSync(target, Buffer.alloc(n, 0x20), { mode: 0o600 });
  fs.chmodSync(target, 0o600);
}
function hold(value) {
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, 'GUARDIAN_LOCAL_JOURNAL_BUDGET_V1');
  assert.equal(value.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(value.status, 'SOURCE_ONLY_HOLD');
  assert.equal(value.filesystemFreeSpace, 'NOT_VERIFIED');
  assert.equal(value.appendReadiness, 'NOT_PROVEN');
  assert.equal(value.liveness, 'NOT_PROVEN');
  assert.equal(value.releaseAuthority, 'NOT_ISSUED');
  assert.equal(value.activationAllowed, false);
  assert.equal(value.automaticRestartAllowed, false);
  assert.equal(value.manualInterventionRequired, true);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.hasOwn(value, 'pid'), false);
  assert.equal(Object.hasOwn(value, 'directory'), false);
  assert.equal(Object.hasOwn(value, 'path'), false);
}
function diagnose(directory, controller) {
  return createGuardianLocalJournalBudget(
    config(directory, controller)).assess();
}

test('construction is inert, read-only and exposes only frozen assess()', async () => {
  await temporary((directory, target) => {
    let statusReads = 0;
    const budget = createGuardianLocalJournalBudget(config(directory, {
      status() { statusReads++; return status(); },
    }));
    assert.equal(fs.existsSync(target), false);
    assert.equal(statusReads, 0);
    assert.ok(Object.isFrozen(budget));
    assert.deepEqual(Object.keys(budget), ['assess']);
    const result = budget.assess();
    hold(result);
    assert.equal(result.priority, 'P2');
    assert.equal(result.classification, 'JOURNAL_BASELINE_NOT_CREATED');
    assert.equal(result.journalFileBytes, null);
    assert.equal(result.journalLimitRemainingBytes, null);
    assert.equal(fs.existsSync(target), false);
    assert.equal(statusReads, 3);
  });
});

test('non-CREATED state without a journal is P0, not a valid first start', async () => {
  await temporary((directory) => {
    const result = diagnose(directory, { status: () =>
      status({ state: 'STOPPED' }) });
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.classification, 'JOURNAL_BUDGET_UNVERIFIED');
  });
});

test('only reports local file-limit headroom; never filesystem free space', async () => {
  await temporary((directory, target) => {
    file(target, 1000);
    const before = fs.readFileSync(target);
    const mtime = fs.statSync(target).mtimeMs;
    const result = diagnose(directory);
    hold(result);
    assert.equal(result.priority, 'P3');
    assert.equal(result.classification, 'JOURNAL_FILE_LIMIT_HEADROOM_ONLY');
    assert.equal(result.journalFileBytes, 1000);
    assert.equal(result.journalLimitBytes, LIMIT);
    assert.equal(result.journalLimitRemainingBytes, LIMIT - 1000);
    assert.equal(result.maximumReceiptBytes, 512);
    assert.deepEqual(fs.readFileSync(target), before);
    assert.equal(fs.statSync(target).mtimeMs, mtime);
  });
});

test('near limit is P2 and under maximum receipt headroom is P1', async () => {
  await temporary((directory, target) => {
    file(target, LIMIT - 1500);
    const near = diagnose(directory);
    hold(near);
    assert.equal(near.priority, 'P2');
    assert.equal(near.classification, 'JOURNAL_LIMIT_NEAR');
    assert.equal(near.journalLimitRemainingBytes, 1500);
    file(target, LIMIT - 511);
    const critical = diagnose(directory);
    hold(critical);
    assert.equal(critical.priority, 'P1');
    assert.equal(critical.classification, 'JOURNAL_LIMIT_AT_RISK');
    assert.equal(critical.journalLimitRemainingBytes, 511);
  });
});

test('oversize and unreadable journal metadata fail closed', async () => {
  await temporary((directory, target) => {
    file(target, LIMIT + 1);
    const result = diagnose(directory);
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.journalFileBytes, null);
  });
});

test('symbolic-link target is rejected without following or disclosing it', async () => {
  await temporary((directory, target) => {
    const canary = path.join(directory, 'synthetic-canary.txt');
    fs.writeFileSync(canary, 'NONPRODUCTION_SYNTHETIC', { mode: 0o600 });
    fs.symlinkSync(canary, target);
    const result = diagnose(directory);
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.journalFileBytes, null);
    assert.equal(JSON.stringify(result).includes('SYNTHETIC'), false);
    assert.equal(fs.readFileSync(canary, 'utf8'),
      'NONPRODUCTION_SYNTHETIC');
  });
});

test('hard-linked journal and group-readable journal are rejected', async () => {
  await temporary((directory, target) => {
    file(target, 100);
    const hardlink = path.join(directory, 'guardian-hardlink.jsonl');
    fs.linkSync(target, hardlink);
    hold(diagnose(directory));
    assert.equal(diagnose(directory).priority, 'P0');
    fs.unlinkSync(hardlink);
    fs.chmodSync(target, 0o644);
    const result = diagnose(directory);
    hold(result);
    assert.equal(result.priority, 'P0');
  });
});

test('world-accessible or symlinked evidence directory is P0', async () => {
  await temporary((directory, target) => {
    file(target, 100);
    fs.chmodSync(directory, 0o755);
    const wide = diagnose(directory);
    hold(wide);
    assert.equal(wide.priority, 'P0');
    fs.chmodSync(directory, 0o700);
    const alias = path.join(directory, 'alias');
    fs.symlinkSync(directory, alias);
    const linked = createGuardianLocalJournalBudget({
      controller: { status: () => status() },
      directory: alias, fileName: JOURNAL, maxBytes: LIMIT,
    }).assess();
    hold(linked);
    assert.equal(linked.priority, 'P0');
  });
});

test('an append between file observations invalidates the result', async () => {
  await temporary((directory, target) => {
    file(target, 100);
    let calls = 0;
    const controller = { status() {
      if (++calls === 2) fs.appendFileSync(target, 'X');
      return status();
    } };
    const result = diagnose(directory, controller);
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.journalFileBytes, null);
    assert.equal(fs.statSync(target).size, 101);
    assert.equal(calls, 3);
  });
});

test('a same-size file replacement during observation invalidates result', async () => {
  await temporary((directory, target) => {
    file(target, 100);
    const replacement = path.join(directory, 'replacement');
    file(replacement, 100);
    let calls = 0;
    const controller = { status() {
      if (++calls === 2) fs.renameSync(replacement, target);
      return status();
    } };
    const result = diagnose(directory, controller);
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(result.journalFileBytes, null);
  });
});

test('status and generation transitions fail closed without disclosing PID', async () => {
  await temporary((directory, target) => {
    file(target, 100);
    let calls = 0;
    const controller = { status() {
      return status({ generationId: (++calls === 1 ?
        'a'.repeat(32) : 'b'.repeat(32)) });
    } };
    const result = diagnose(directory, controller);
    hold(result);
    assert.equal(result.priority, 'P0');
    assert.equal(calls, 2);
  });
});

test('accessors and unsafe configuration are rejected before reading', async () => {
  await temporary((directory, target) => {
    for (const invalid of [
      null, {}, { ...config(directory), maxBytes: 3 },
      { ...config(directory), maxBytes: 10_485_761 },
      { ...config(directory), fileName: '../key.env' },
      { ...config(directory), directory: 'relative' },
      { ...config(directory), unwanted: 1 },
      { ...config(directory), controller: { status: 1 } },
      Object.defineProperty({ ...config(directory) }, 'directory',
        { enumerable: true, get() { throw Error('must not run'); } }),
    ]) {
      assert.throws(() => createGuardianLocalJournalBudget(invalid),
        /GUARDIAN_JOURNAL_BUDGET_CONFIG_INVALID/);
    }
    assert.equal(fs.existsSync(target), false);
    file(target, 100);
    const result = diagnose(directory, { status: () =>
      Object.defineProperty(status(), 'state', {
        enumerable: true, get() { throw Error('untrusted'); },
      }) });
    hold(result);
    assert.equal(result.priority, 'P0');
  });
});

test('Operator facade provides read-only budget without weakening fault triage', async () => {
  await temporary((directory, target) => {
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(child), entrypoint: child, directory,
      fileName: JOURNAL, maxJournalBytes: LIMIT,
    });
    assert.equal(fs.existsSync(target), false);
    assert.equal(Object.hasOwn(session.owner, 'assessJournalBudget'), false);
    assert.equal(Object.hasOwn(session.operator, 'start'), false);
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
    assert.equal(Object.hasOwn(session.operator, 'publishCheck'), false);
    const absent = session.operator.assessJournalBudget();
    hold(absent);
    assert.equal(absent.classification, 'JOURNAL_BASELINE_NOT_CREATED');
    file(target, 1000); // metadata-only observation, not trusted receipt
    const budget = session.operator.assessJournalBudget();
    hold(budget);
    assert.equal(budget.priority, 'P3');
    const triage = session.operator.faultTriage();
    assert.equal(triage.status, 'SOURCE_ONLY_HOLD');
    assert.equal(triage.priority, 'P0'); // invalid receipts remain rejected
    assert.equal(session.owner.status().state, 'CREATED');
  });
});
