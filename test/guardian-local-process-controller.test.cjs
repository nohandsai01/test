'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalProcessController } =
  require('../merge-gate-install/guardian-candidate/guardian-local-process-controller.cjs');

const fixturePath = path.join(__dirname, 'guardian-local-controller-child.cjs');
const receipts = [];
function withScript(name, fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-process-manager-'));
  const entrypoint = path.join(directory, name + '.cjs');
  fs.copyFileSync(fixturePath, entrypoint);
  return Promise.resolve().then(() => fn({
    entrypoint, cwd: directory,
  })).finally(() => fs.rmSync(directory, { recursive: true, force: true }));
}
function create(file, overrides = {}) {
  const seen = [];
  const controller = createGuardianLocalProcessController({
    ...file,
    startupTimeoutMs: 500, shutdownTimeoutMs: 150,
    onTerminal: (receipt) => seen.push(receipt),
    ...overrides,
  });
  return { controller, seen };
}
const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));
async function observe(condition, maximum = 600) {
  const started = Date.now();
  while (!condition()) {
    if (Date.now() - started > maximum) {
      throw new Error('synthetic child event not observed');
    }
    await delay(3);
  }
}

test('parent construction is inert and exposes no credential or arbitrary child writer', async () => {
  await withScript('normal', async (file) => {
    const { controller, seen } = create(file);
    assert.deepEqual(Object.keys(controller).sort(), ['probeRuntime', 'start', 'status', 'stop']);
    assert.equal(Object.isFrozen(controller), true);
    assert.equal(controller.status().state, 'CREATED');
    assert.equal(controller.status().pid, null);
    assert.equal(controller.status().automaticRestartAllowed, false);
    assert.equal(controller.status().releaseAuthority, 'NOT_ISSUED');
    assert.equal(seen.length, 0);
  });
});

test('actual owned Node child starts on IPC READY, stops by SIGTERM with one verified terminal', async () => {
  await withScript('normal', async (file) => {
    const { controller, seen } = create(file);
    try {
      const ready = await controller.start();
      assert.equal(ready.state, 'RUNNING');
      assert.ok(ready.pid > 0);
      assert.equal(ready.releaseAuthority, 'NOT_ISSUED');
      const stop = await controller.stop();
      assert.equal(stop.state, 'STOPPED');
      assert.equal(stop.automaticRestartAllowed, false);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].hostStopped, true);
      assert.equal(seen[0].activationAllowed, false);
      await assert.rejects(controller.start(),
        { code: 'GUARDIAN_CHILD_STATE_INVALID' });
    } finally {
      await controller.stop();
    }
  });
});

test('duplicate stop coalesces into a single terminal receipt', async () => {
  await withScript('normal', async (file) => {
    const { controller, seen } = create(file);
    await controller.start();
    const [a, b, c] = await Promise.all([
      controller.stop(), controller.stop(), controller.stop(),
    ]);
    assert.deepEqual([a.state, b.state, c.state], ['STOPPED', 'STOPPED', 'STOPPED']);
    assert.equal(seen.length, 1);
  });
});

test('premature process exit cannot return a READY success or auto-restart', async () => {
  await withScript('premature-exit', async (file) => {
    const { controller, seen } = create(file);
    await assert.rejects(controller.start(),
      { code: 'GUARDIAN_CHILD_EXIT_BEFORE_READY' });
    assert.equal(controller.status().state, 'FAILED');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].hostStopped, false);
    assert.equal(controller.status().automaticRestartAllowed, false);
  });
});

test('starting child that never sends READY fails before deadline and is signaled', async () => {
  await withScript('stalled-start', async (file) => {
    const { controller, seen } = create(file, { startupTimeoutMs: 100 });
    const started = Date.now();
    await assert.rejects(controller.start(),
      { code: 'GUARDIAN_CHILD_START_TIMEOUT' });
    assert.ok(Date.now() - started < 800);
    assert.equal(controller.status().state, 'FAILED');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].hostStopped, false);
  });
});

test('invalid or spoofed READY frame is rejected fail-closed', async () => {
  await withScript('malformed-ready', async (file) => {
    const { controller, seen } = create(file);
    await assert.rejects(controller.start(),
      { code: 'GUARDIAN_CHILD_PROTOCOL_INVALID' });
    assert.equal(controller.status().state, 'FAILED');
    assert.equal(seen[0].hostStopped, false);
  });
});

test('duplicate READY cannot authorize a second start or check', async () => {
  await withScript('duplicate-ready', async (file) => {
    const { controller, seen } = create(file);
    try {
      try { await controller.start(); } catch (_) {}
      await observe(() => seen.length > 0);
      assert.equal(controller.status().state, 'FAILED');
      assert.equal(seen.length, 1);
      assert.equal(controller.status().automaticRestartAllowed, false);
    } finally { await controller.stop(); }
  });
});

test('unprompted child exit after READY yields FAILED, not STOPPED', async () => {
  await withScript('unexpected-exit', async (file) => {
    const { controller, seen } = create(file);
    try {
      await controller.start();
      await observe(() => seen.length > 0);
      assert.equal(seen[0].hostStopped, false);
      assert.equal(controller.status().state, 'FAILED');
      assert.equal(controller.status().automaticRestartAllowed, false);
    } finally { await controller.stop(); }
  });
});

test('false terminal receipt can never be treated as clean STOPPED', async () => {
  await withScript('bad-terminal', async (file) => {
    const { controller, seen } = create(file);
    await controller.start();
    const final = await controller.stop();
    assert.equal(final.state, 'FAILED');
    assert.equal(seen[0].hostStopped, false);
    assert.ok(seen[0].errorCode);
  });
});

test('owned child that ignores SIGTERM is force-stopped within deadline and never auto-restarted', async () => {
  await withScript('ignore-stop', async (file) => {
    const { controller, seen } = create(file, { shutdownTimeoutMs: 75 });
    await controller.start();
    const started = Date.now();
    const final = await controller.stop();
    assert.ok(Date.now() - started < 1000);
    assert.equal(final.state, 'FAILED');
    assert.equal(final.errorCode, 'GUARDIAN_CHILD_STOP_TIMEOUT');
    assert.equal(seen.length, 1);
    assert.equal(seen[0].hostStopped, false);
    assert.equal(final.automaticRestartAllowed, false);
  });
});

test('a STOP request racing startup never claims a running protected host', async () => {
  await withScript('stalled-start', async (file) => {
    const { controller, seen } = create(file, {
      startupTimeoutMs: 250, shutdownTimeoutMs: 150,
    });
    const starting = controller.start().catch((error) => error.code);
    const stopping = controller.stop();
    const [result, outcome] = await Promise.all([starting, stopping]);
    assert.notEqual(result?.state, 'RUNNING');
    assert.notEqual(outcome.state, 'RUNNING');
    assert.equal(outcome.releaseAuthority, 'NOT_ISSUED');
    assert.equal(seen.length, 1);
  });
});

test('invalid config and writable or symlinked/untrusted entrypoints rejected before spawn', async () => {
  await withScript('normal', async (file) => {
    const handler = () => {};
    for (const delta of [
      { cwd: 'relative/path' },
      { entrypoint: 'relative.cjs' },
      { entrypoint: path.join(file.cwd, 'missing.cjs') },
      { startupTimeoutMs: -1 },
      { shutdownTimeoutMs: 30001 },
      { untrusted: 'arbitrary injection' },
      { onTerminal: null },
    ]) {
      assert.throws(() => createGuardianLocalProcessController({
        ...file, onTerminal: handler, ...delta,
      }));
    }
    const outside = path.join(os.tmpdir(), 'not-guardian.cjs');
    assert.throws(() => createGuardianLocalProcessController({
      ...file, entrypoint: outside, onTerminal: handler,
    }));
    const alias = path.join(file.cwd, 'alias.cjs');
    fs.symlinkSync(file.entrypoint, alias);
    assert.throws(() => createGuardianLocalProcessController({
      ...file, entrypoint: alias, onTerminal: handler,
    }));
  });
});

test('parent callback is called exactly once; its exceptions keep FAILED state', async () => {
  await withScript('normal', async (file) => {
    const controller = createGuardianLocalProcessController({
      ...file,
      onTerminal: () => { throw new Error('synthetic receipt write failed'); },
    });
    await controller.start();
    const outcome = await controller.stop();
    assert.equal(outcome.state, 'FAILED');
    assert.equal(outcome.errorCode, 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED');
  });
});


test('same-inode executable rewrite after construction fails before child spawn', async () => {
  await withScript('normal', async (file) => {
    const { controller, seen } = create(file);
    fs.appendFileSync(file.entrypoint, '\n// synthetic changed source bytes\n');
    await assert.rejects(controller.start(),
      { code: 'GUARDIAN_CHILD_ENTRYPOINT_CHANGED' });
    assert.equal(controller.status().state, 'FAILED');
    assert.equal(controller.status().pid, null);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].hostStopped, false);
  });
});

test('owned Node child does not inherit parent secret or NODE_OPTIONS', async () => {
  const prior = process.env.NOHANDS_TEST_SECRET;
  await withScript('env-isolation', async (file) => {
    process.env.NOHANDS_TEST_SECRET = 'synthetic-should-never-pass';
    const { controller, seen } = create(file);
    try {
      assert.equal((await controller.start()).state, 'RUNNING');
      assert.equal((await controller.stop()).state, 'STOPPED');
      assert.equal(seen.length, 1);
    } finally {
      if (prior === undefined) delete process.env.NOHANDS_TEST_SECRET;
      else process.env.NOHANDS_TEST_SECRET = prior;
      await controller.stop();
    }
  });
});

test('explicit stop before child start cannot launch or restart it afterwards', async () => {
  await withScript('normal', async (file) => {
    const { controller, seen } = create(file);
    const result = await controller.stop();
    assert.equal(result.state, 'STOPPED');
    assert.equal(result.pid, null);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].releaseAuthority, 'NOT_ISSUED');
    await assert.rejects(controller.start(),
      { code: 'GUARDIAN_CHILD_STATE_INVALID' });
  });
});
