'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createGuardianLocalStoragePressure } =
  require('../merge-gate-install/guardian-candidate/guardian-local-storage-pressure.cjs');
const { createGuardianLocalJournalBudget } =
  require('../merge-gate-install/guardian-candidate/guardian-local-journal-budget.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const JOURNAL = 'guardian-storage.jsonl';
const LIMIT = 4096;
const child = path.join(__dirname, 'guardian-protected-worker-child.cjs');

function status(extra = {}) {
  return {
    state: 'CREATED', errorCode: null, pid: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false, ...extra,
  };
}
async function temporary(callback) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-storage-'));
  try { await callback(dir, path.join(dir, JOURNAL)); }
  finally {
    fs.chmodSync(dir, 0o700);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
function journal(target, bytes) {
  fs.writeFileSync(target, Buffer.alloc(bytes, 0x20), { mode: 0o600 });
  fs.chmodSync(target, 0o600);
}
function create(directory, controller = { status: () => status() }) {
  const budget = createGuardianLocalJournalBudget({
    controller, directory, fileName: JOURNAL, maxBytes: LIMIT,
  });
  return createGuardianLocalStoragePressure({
    controller, directory, journalBudget: budget,
  });
}
function hold(receipt) {
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.kind, 'GUARDIAN_LOCAL_STORAGE_PRESSURE_V1');
  assert.equal(receipt.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(receipt.status, 'SOURCE_ONLY_HOLD');
  assert.equal(receipt.filesystemReservation, 'NOT_PROVEN');
  assert.equal(receipt.appendReadiness, 'NOT_PROVEN');
  assert.equal(receipt.liveness, 'NOT_PROVEN');
  assert.equal(receipt.manualInterventionRequired, true);
  assert.equal(receipt.activationAllowed, false);
  assert.equal(receipt.automaticRestartAllowed, false);
  assert.equal(receipt.releaseAuthority, 'NOT_ISSUED');
  assert.ok(Object.isFrozen(receipt));
  for (const key of ['pid', 'path', 'directory', 'token', 'secret',
    'availableBytes']) assert.equal(Object.hasOwn(receipt, key), false);
}
async function fakeStatfs(replace, callback) {
  const original = fs.statfsSync;
  let calls = 0;
  fs.statfsSync = (...args) => {
    const result = original(...args);
    return replace(result, ++calls);
  };
  try { await callback(() => calls); }
  finally { fs.statfsSync = original; }
}
const volume = (stat, bavail) => ({
  ...stat,
  bsize: 4096n,
  blocks: 20000n,
  bfree: bavail,
  bavail,
});

test('constructor and isolated Operator query are inert, frozen, read-only', async () => {
  await temporary((directory, target) => {
    let reads = 0;
    const instance = create(directory, {
      status() { reads++; return status(); },
    });
    assert.equal(fs.existsSync(target), false);
    assert.equal(reads, 0);
    assert.deepEqual(Object.keys(instance), ['assess']);
    assert.ok(Object.isFrozen(instance));
    const receipt = instance.assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P2');
    assert.equal(receipt.classification, 'JOURNAL_BUDGET_NEEDS_ATTENTION');
    assert.equal(receipt.journalBudgetPriority, 'P2');
    assert.equal(receipt.filesystemFreeSpace, 'LOCAL_STATFS_SNAPSHOT_ONLY');
    assert.equal(fs.existsSync(target), false);
    assert.equal(reads, 9);
  });
});

test('stable protected file and ample disk produce snapshot-only P3', async () => {
  await temporary((directory, target) => {
    journal(target, 1000);
    const before = fs.readFileSync(target);
    const mtime = fs.statSync(target).mtimeMs;
    const receipt = create(directory).assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P3');
    assert.equal(receipt.classification,
      'LOCAL_STORAGE_HEADROOM_SNAPSHOT_ONLY');
    assert.equal(receipt.journalBudgetPriority, 'P3');
    assert.equal(receipt.filesystemAvailableMiBCappedAt64, 64);
    assert.deepEqual(fs.readFileSync(target), before);
    assert.equal(fs.statSync(target).mtimeMs, mtime);
  });
});

test('zero available allocation bytes are P1 without claiming a disk reservation', async () => {
  await temporary(async (directory, target) => {
    journal(target, 1000);
    await fakeStatfs((stat) => volume(stat, 0n), () => {
      const receipt = create(directory).assess();
      hold(receipt);
      assert.equal(receipt.priority, 'P1');
      assert.equal(receipt.classification,
        'FILESYSTEM_FREE_CAPACITY_CRITICAL');
      assert.equal(receipt.filesystemAvailableMiBCappedAt64, 0);
    });
  });
});

test('capacity under one MiB is P1 and below eight MiB is P2', async () => {
  await temporary(async (directory, target) => {
    journal(target, 1000);
    await fakeStatfs((stat) => volume(stat, 128n), () => {
      const receipt = create(directory).assess();
      hold(receipt);
      assert.equal(receipt.priority, 'P1');
    });
    await fakeStatfs((stat) => volume(stat, 1024n), () => {
      const receipt = create(directory).assess();
      hold(receipt);
      assert.equal(receipt.priority, 'P2');
      assert.equal(receipt.classification, 'FILESYSTEM_FREE_CAPACITY_LOW');
      assert.equal(receipt.filesystemAvailableMiBCappedAt64, 4);
    });
  });
});

test('journal file limit remains P1 even when filesystem has free blocks', async () => {
  await temporary((directory, target) => {
    journal(target, LIMIT - 200);
    const receipt = create(directory).assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P1');
    assert.equal(receipt.classification, 'JOURNAL_FILE_LIMIT_AT_RISK');
    assert.equal(receipt.journalBudgetPriority, 'P1');
  });
});

test('journal near limit is P2 when capacity is otherwise healthy', async () => {
  await temporary((directory, target) => {
    journal(target, LIMIT - 1024);
    const receipt = create(directory).assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P2');
    assert.equal(receipt.classification, 'JOURNAL_BUDGET_NEEDS_ATTENTION');
  });
});

test('read errors and inconsistent/malformed filesystem figures fail closed', async () => {
  await temporary(async (directory, target) => {
    journal(target, 1000);
    await fakeStatfs(() => {
      throw new Error('SECRET_SYNTHETIC_PATH_DO_NOT_LOG');
    }, () => {
      const receipt = create(directory).assess();
      hold(receipt);
      assert.equal(receipt.priority, 'P0');
      assert.equal(receipt.filesystemFreeSpace, 'NOT_VERIFIED');
      assert.equal(JSON.stringify(receipt).includes('SECRET'), false);
    });
    for (const malformed of [
      { bsize: 0n }, { bavail: -1n }, { blocks: -1n },
      { bfree: 1n, bavail: 2n }, { type: 'forged' },
    ]) {
      await fakeStatfs((stat) => ({ ...stat, ...malformed }), () => {
        const receipt = create(directory).assess();
        hold(receipt);
        assert.equal(receipt.priority, 'P0');
      });
    }
  });
});

test('filesystem type switching between samples is not accepted', async () => {
  await temporary(async (directory, target) => {
    journal(target, 1000);
    await fakeStatfs((stat, n) => ({
      ...stat, type: stat.type + (n === 2 ? 1n : 0n),
    }), (count) => {
      const receipt = create(directory).assess();
      hold(receipt);
      assert.equal(receipt.priority, 'P0');
      assert.equal(count(), 2);
    });
  });
});

test('diminishing free space chooses the lower of two valid samples', async () => {
  await temporary(async (directory, target) => {
    journal(target, 1000);
    await fakeStatfs((stat, n) => volume(stat, n === 1 ? 5000n : 50n),
      () => {
        const receipt = create(directory).assess();
        hold(receipt);
        assert.equal(receipt.priority, 'P1');
        assert.equal(receipt.filesystemAvailableMiBCappedAt64, 0);
      });
  });
});

test('protected directory permission and symlink violations are P0', async () => {
  await temporary((directory, target) => {
    journal(target, 1000);
    fs.chmodSync(directory, 0o755);
    assert.equal(create(directory).assess().priority, 'P0');
    fs.chmodSync(directory, 0o700);
    const alias = path.join(directory, 'alias');
    fs.symlinkSync(directory, alias);
    const receipt = create(alias).assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P0');
  });
});

test('untrusted journal file, including a hard link, forces P0', async () => {
  await temporary((directory, target) => {
    journal(target, 1000);
    const second = path.join(directory, 'guardian-copy.jsonl');
    fs.linkSync(target, second);
    const receipt = create(directory).assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P0');
    assert.equal(receipt.journalBudgetPriority, 'UNVERIFIED');
  });
});

test('journal append during sampling invalidates the combined evidence', async () => {
  await temporary(async (directory, target) => {
    journal(target, 1000);
    await fakeStatfs((stat, n) => {
      if (n === 1) fs.appendFileSync(target, 'X');
      return stat;
    }, () => {
      const receipt = create(directory).assess();
      hold(receipt);
      assert.equal(receipt.priority, 'P0');
      assert.equal(receipt.filesystemFreeSpace, 'NOT_VERIFIED');
    });
  });
});

test('Controller state/PID/generation drift cannot be promoted to healthy', async () => {
  await temporary((directory, target) => {
    journal(target, 1000);
    let calls = 0;
    const controller = {
      status() {
        calls++;
        return status({ generationId:
          calls <= 4 ? 'a'.repeat(32) : 'b'.repeat(32) });
      },
    };
    const receipt = create(directory, controller).assess();
    hold(receipt);
    assert.equal(receipt.priority, 'P0');
    assert.equal(receipt.processState, 'UNVERIFIED');
  });
});

test('forged budget authority and dynamic configuration getters fail closed', async () => {
  await temporary((directory, target) => {
    journal(target, 1000);
    const controller = { status: () => status() };
    const real = createGuardianLocalJournalBudget({
      controller, directory, fileName: JOURNAL, maxBytes: LIMIT,
    });
    const forged = { assess: () => ({
      ...real.assess(), activationAllowed: true,
    }) };
    const result = createGuardianLocalStoragePressure({
      controller, directory, journalBudget: forged,
    }).assess();
    hold(result);
    assert.equal(result.priority, 'P0');
    const options = Object.defineProperty({
      controller, directory, journalBudget: real,
    }, 'directory', {
      enumerable: true,
      get() { throw Error('synthetic secret getter'); },
    });
    assert.throws(() => createGuardianLocalStoragePressure(options),
      /GUARDIAN_LOCAL_STORAGE_CONFIG_INVALID/);
    assert.throws(() => createGuardianLocalStoragePressure({
      controller, directory: '../relative', journalBudget: real,
    }), /GUARDIAN_LOCAL_STORAGE_CONFIG_INVALID/);
  });
});

test('Operator facade offers storage query without owner control or IPC', async () => {
  await temporary((directory, target) => {
    const session = createGuardianLocalOperatorSession({
      cwd: path.dirname(child), entrypoint: child, directory,
      fileName: JOURNAL, maxJournalBytes: LIMIT,
    });
    assert.equal(fs.existsSync(target), false);
    assert.equal(Object.hasOwn(session.owner, 'assessJournalStorage'), false);
    assert.equal(Object.hasOwn(session.operator, 'start'), false);
    assert.equal(Object.hasOwn(session.operator, 'stop'), false);
    assert.equal(Object.hasOwn(session.operator, 'publishCheck'), false);
    const receipt = session.operator.assessJournalStorage();
    hold(receipt);
    assert.equal(receipt.priority, 'P2');
    assert.equal(session.owner.status().state, 'CREATED');
    assert.equal(fs.existsSync(target), false);
  });
});
