'use strict';

// No OS signals are delivered. Synthetic EventEmitter stands for the owner
// process manager; tests use only temporary loopback listeners and no GitHub
// App, D1 provisioning, Check writers or real credentials.
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const { createGuardianProcessSupervisor } =
  require('../merge-gate-install/guardian-candidate/guardian-process-supervisor.cjs');

function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, bad) => {
    resolve = ok; reject = bad;
  });
  return { promise, resolve, reject };
}
function fakeHost(overrides = {}) {
  const state = { current: 'CREATED', starts: 0, stops: 0 };
  const host = {
    start: async () => {
      state.starts++;
      state.current = 'RUNNING';
      return { state: 'RUNNING' };
    },
    stop: async () => {
      state.stops++;
      state.current = 'STOPPED';
      return { state: 'STOPPED' };
    },
    status: () => ({
      state: state.current,
      activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    }),
    ...overrides,
  };
  return { host, state };
}
function context(host, other = {}) {
  const source = new EventEmitter();
  const reports = [];
  const supervisor = createGuardianProcessSupervisor({
    host, signalSource: source,
    onTerminal: (receipt) => reports.push(receipt),
    ...other,
  });
  return { supervisor, source, reports };
}
async function condition(check) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (check()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('condition never became true');
}

test('module construction is inert: no signals, host starts or listeners', () => {
  const { host, state } = fakeHost();
  const ctx = context(host);
  assert.equal(state.starts, 0);
  assert.equal(ctx.source.listenerCount('SIGTERM'), 0);
  assert.equal(ctx.source.listenerCount('SIGINT'), 0);
  assert.equal(ctx.supervisor.status().state, 'CREATED');
  assert.equal(ctx.supervisor.status().activationAllowed, false);
  assert.equal(ctx.supervisor.status().releaseAuthority, 'NOT_ISSUED');
  assert.equal(ctx.reports.length, 0);
});

test('manual full start and stop installs then removes signals with one HOLD receipt', async () => {
  const { host, state } = fakeHost();
  const { supervisor, source, reports } = context(host);
  const ready = await supervisor.start();
  assert.equal(ready.state, 'RUNNING');
  assert.equal(source.listenerCount('SIGTERM'), 1);
  assert.equal(source.listenerCount('SIGINT'), 1);
  const stopped = await supervisor.stop();
  assert.equal(stopped.state, 'STOPPED');
  assert.equal(state.starts, 1);
  assert.equal(state.stops, 1);
  assert.equal(source.listenerCount('SIGTERM'), 0);
  assert.equal(source.listenerCount('SIGINT'), 0);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].hostStopped, true);
  assert.equal(reports[0].releaseAuthority, 'NOT_ISSUED');
  assert.equal(reports[0].activationAllowed, false);
  assert.equal((await supervisor.stop()).state, 'STOPPED');
  assert.equal(reports.length, 1);
});

test('SIGTERM performs shutdown once and never requests process.exit', async () => {
  const { host, state } = fakeHost();
  const { supervisor, source, reports } = context(host);
  await supervisor.start();
  source.emit('SIGTERM');
  await condition(() => reports.length === 1);
  assert.equal(reports[0].reason, 'SIGTERM');
  assert.equal(reports[0].hostStopped, true);
  assert.equal(state.stops, 1);
  assert.equal(supervisor.status().state, 'STOPPED');
});

test('SIGINT and SIGTERM raced during shutdown share a single host.stop', async () => {
  const stopping = deferred();
  const { host, state } = fakeHost({
    stop: async () => {
      state.stops++;
      await stopping.promise;
      state.current = 'STOPPED';
    },
  });
  const { supervisor, source, reports } = context(host);
  await supervisor.start();
  source.emit('SIGINT');
  source.emit('SIGTERM');
  source.emit('SIGINT');
  assert.equal(state.stops, 0);
  await condition(() => state.stops === 1);
  stopping.resolve();
  await condition(() => reports.length === 1);
  assert.equal(state.stops, 1);
  assert.equal(reports[0].reason, 'SIGINT');
  assert.equal(supervisor.status().state, 'STOPPED');
});

test('SIGTERM during asynchronous startup stops before reporting running', async () => {
  const starting = deferred();
  const { host, state } = fakeHost({
    start: async () => {
      state.starts++;
      await starting.promise;
      state.current = 'RUNNING';
    },
  });
  const { supervisor, source, reports } = context(host);
  const pending = supervisor.start();
  source.emit('SIGTERM');
  assert.equal(supervisor.status().state, 'STOPPING');
  starting.resolve();
  const startOutcome = await pending;
  assert.notEqual(startOutcome.state, 'RUNNING');
  await condition(() => reports.length === 1);
  assert.equal(reports[0].state, 'STOPPED');
  assert.equal(state.stops, 1);
  assert.equal(source.listenerCount('SIGTERM'), 0);
});

test('startup rejection fails closed and unregisters both signals', async () => {
  const { host } = fakeHost({
    start: async () => { throw new Error('synthetic protected host failed'); },
  });
  const { supervisor, source, reports } = context(host);
  await assert.rejects(supervisor.start(),
    { code: 'GUARDIAN_SUPERVISOR_START_FAILED' });
  assert.equal(supervisor.status().state, 'FAILED');
  assert.equal(supervisor.status().activationAllowed, false);
  assert.equal(source.listenerCount('SIGTERM'), 0);
  assert.equal(source.listenerCount('SIGINT'), 0);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].hostStopped, false);
});

test('a host reporting RUNNING without HOLD contract is refused', async () => {
  const { host } = fakeHost({
    status: () => ({ state: 'RUNNING', activationAllowed: true,
      releaseAuthority: 'ISSUED' }),
  });
  const { supervisor, source, reports } = context(host);
  await assert.rejects(supervisor.start(),
    { code: 'GUARDIAN_SUPERVISOR_HOST_NOT_READY' });
  assert.equal(supervisor.status().state, 'FAILED');
  assert.equal(source.listenerCount('SIGTERM'), 0);
  assert.equal(reports[0].hostStopped, false);
});

test('failed host.stop cannot be called a clean exit', async () => {
  const { host, state } = fakeHost({
    stop: async () => {
      state.stops++;
      throw new Error('synthetic host stop error');
    },
  });
  const { supervisor, source, reports } = context(host);
  await supervisor.start();
  const stopped = await supervisor.stop();
  assert.equal(stopped.state, 'FAILED');
  assert.equal(stopped.terminalCode, 'GUARDIAN_SUPERVISOR_STOP_FAILED');
  assert.equal(reports[0].hostStopped, false);
  assert.equal(reports.length, 1);
  assert.equal(source.listenerCount('SIGTERM'), 0);
});

test('a nonresponsive shutdown is bounded and never reported STOPPED', async () => {
  const { host, state } = fakeHost({
    stop: async () => {
      state.stops++;
      return new Promise(() => {});
    },
  });
  const { supervisor, source, reports } = context(host, { stopDeadlineMs: 50 });
  await supervisor.start();
  const started = performance.now();
  const result = await supervisor.stop();
  assert.ok(performance.now() - started < 900);
  assert.equal(result.state, 'FAILED');
  assert.equal(result.terminalCode, 'GUARDIAN_SUPERVISOR_STOP_TIMEOUT');
  assert.equal(reports.length, 1);
  assert.equal(reports[0].hostStopped, false);
  assert.equal(source.listenerCount('SIGTERM'), 0);
});

test('host lying about shutdown state is never a clean process exit', async () => {
  const { host, state } = fakeHost({
    stop: async () => {
      state.stops++;
      state.current = 'RUNNING';
    },
  });
  const { supervisor, reports } = context(host);
  await supervisor.start();
  const result = await supervisor.stop();
  assert.equal(result.state, 'FAILED');
  assert.equal(result.terminalCode, 'GUARDIAN_SUPERVISOR_STOP_UNVERIFIED');
  assert.equal(reports[0].hostStopped, false);
});

test('startup signal attachment failure leaves no claim of RUNNING', async () => {
  class ThrowingEmitter extends EventEmitter {
    on(name, listener) {
      if (name === 'SIGINT') throw new Error('synthetic signal attach failure');
      return super.on(name, listener);
    }
  }
  const source = new ThrowingEmitter();
  const { host, state } = fakeHost();
  const reports = [];
  const supervisor = createGuardianProcessSupervisor({
    host, signalSource: source, onTerminal: (x) => reports.push(x),
  });
  await assert.rejects(supervisor.start(),
    { code: 'GUARDIAN_SUPERVISOR_ATTACH_FAILED' });
  assert.equal(state.starts, 0);
  assert.equal(source.listenerCount('SIGTERM'), 0);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].state, 'FAILED');
});

test('exception in terminal handler leaves failure state rather than silent success', async () => {
  const { host } = fakeHost();
  const source = new EventEmitter();
  const supervisor = createGuardianProcessSupervisor({
    host, signalSource: source,
    onTerminal: () => { throw new Error('synthetic parent crashed'); },
  });
  await supervisor.start();
  await supervisor.stop();
  assert.equal(supervisor.status().state, 'FAILED');
  assert.equal(supervisor.status().terminalCode,
    'GUARDIAN_SUPERVISOR_TERMINAL_HANDLER_FAILED');
  assert.equal(source.listenerCount('SIGINT'), 0);
});

test('explicit stop before start never opens a socket or installs signals', async () => {
  const { host, state } = fakeHost();
  const { supervisor, source, reports } = context(host);
  const stopped = await supervisor.stop();
  assert.equal(stopped.state, 'STOPPED');
  assert.equal(reports.length, 1);
  assert.equal(state.starts, 0);
  assert.equal(state.stops, 0);
  assert.equal(source.listenerCount('SIGTERM'), 0);
  await assert.rejects(supervisor.start(),
    { code: 'GUARDIAN_SUPERVISOR_STATE_INVALID' });
});

test('invalid config, stop reason and repeated starts fail closed', async () => {
  const { host } = fakeHost();
  for (const config of [
    {}, { host }, { host, onTerminal: null },
    { host, onTerminal() {}, unexpected: true },
    { host, onTerminal() {}, stopDeadlineMs: 0 },
    { host, onTerminal() {}, stopDeadlineMs: 30001 },
    { host, onTerminal() {}, stopDeadlineMs: '100' },
    { host, onTerminal() {}, signalSource: {} },
  ]) {
    assert.throws(() => createGuardianProcessSupervisor(config));
  }
  const { supervisor } = context(host);
  await assert.rejects(supervisor.stop('SIGHUP'),
    { code: 'GUARDIAN_SUPERVISOR_STOP_REASON_INVALID' });
  await supervisor.start();
  await assert.rejects(supervisor.start(),
    { code: 'GUARDIAN_SUPERVISOR_STATE_INVALID' });
  await supervisor.stop();
});

test('two supervisors using one process source clean up handlers independently', async () => {
  const emitter = new EventEmitter(), records = [];
  const a = fakeHost(), b = fakeHost();
  const first = createGuardianProcessSupervisor({
    host: a.host, signalSource: emitter, onTerminal: (x) => records.push(x),
  });
  const second = createGuardianProcessSupervisor({
    host: b.host, signalSource: emitter, onTerminal: (x) => records.push(x),
  });
  await Promise.all([first.start(), second.start()]);
  assert.equal(emitter.listenerCount('SIGTERM'), 2);
  emitter.emit('SIGTERM');
  await condition(() => records.length === 2);
  assert.equal(a.state.stops, 1);
  assert.equal(b.state.stops, 1);
  assert.equal(emitter.listenerCount('SIGTERM'), 0);
  assert.equal(records.every((x) => x.hostStopped), true);
});

test('real loopback listener is stopped after the synthetic process signal', async () => {
  const actual = http.createServer((_, response) => response.end('hold'));
  const state = { current: 'CREATED', starts: 0, stops: 0 };
  const host = {
    async start() {
      state.starts++;
      await new Promise((resolve) => actual.listen(0, '127.0.0.1', resolve));
      state.current = 'RUNNING';
    },
    async stop() {
      state.stops++;
      await new Promise((resolve) => actual.close(resolve));
      state.current = 'STOPPED';
    },
    status() {
      return { state: state.current, activationAllowed: false,
        releaseAuthority: 'NOT_ISSUED' };
    },
  };
  const { supervisor, source, reports } = context(host, { stopDeadlineMs: 500 });
  try {
    await supervisor.start();
    assert.ok(actual.listening);
    source.emit('SIGINT');
    await condition(() => reports.length === 1);
    assert.equal(reports[0].hostStopped, true);
    assert.equal(actual.listening, false);
    assert.equal(state.stops, 1);
  } finally {
    if (actual.listening) await new Promise((resolve) => actual.close(resolve));
  }
});


test('startup that opened a resource before failing triggers bounded cleanup', async () => {
  const state = { current: 'CREATED', starts: 0, stops: 0 };
  const { host } = fakeHost({
    start: async () => {
      state.starts++;
      state.current = 'RUNNING';
      throw new Error('startup failed after listener opened');
    },
    stop: async () => {
      state.stops++;
      state.current = 'STOPPED';
    },
  });
  const { supervisor, source, reports } = context(host);
  await assert.rejects(supervisor.start(),
    { code: 'GUARDIAN_SUPERVISOR_START_FAILED' });
  assert.equal(state.starts, 1);
  assert.equal(state.stops, 1);
  assert.equal(state.current, 'STOPPED');
  assert.equal(supervisor.status().state, 'FAILED');
  assert.equal(source.listenerCount('SIGTERM'), 0);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].hostStopped, false);
});

test('an uncooperative startup cleanup times out without false STOPPED', async () => {
  const { host, state } = fakeHost({
    start: async () => { throw new Error('partially started'); },
    stop: async () => {
      state.stops++;
      return new Promise(() => {});
    },
  });
  const { supervisor, reports } = context(host, { stopDeadlineMs: 50 });
  await assert.rejects(supervisor.start(), {
    code: 'GUARDIAN_SUPERVISOR_START_CLEANUP_UNVERIFIED',
  });
  assert.equal(state.stops, 1);
  assert.equal(supervisor.status().state, 'FAILED');
  assert.equal(reports.length, 1);
  assert.equal(reports[0].hostStopped, false);
});

test('signal handler detach failure must not be reported as a clean stop', async () => {
  class BrokenOffEmitter extends EventEmitter {
    removeListener(name, cb) {
      if (name === 'SIGINT') {
        super.removeListener(name, cb);
        throw new Error('synthetic off failed');
      }
      return super.removeListener(name, cb);
    }
  }
  const { host } = fakeHost();
  const source = new BrokenOffEmitter();
  const reports = [];
  const supervisor = createGuardianProcessSupervisor({
    host, signalSource: source, onTerminal: (receipt) => reports.push(receipt),
  });
  await supervisor.start();
  const stopped = await supervisor.stop();
  assert.equal(stopped.state, 'FAILED');
  assert.equal(stopped.terminalCode, 'GUARDIAN_SUPERVISOR_DETACH_FAILED');
  assert.equal(reports[0].hostStopped, false);
  assert.equal(reports.length, 1);
});

test('async process-manager termination callback fails closed', async () => {
  const { host } = fakeHost();
  const source = new EventEmitter();
  const supervisor = createGuardianProcessSupervisor({
    host, signalSource: source,
    onTerminal: () => Promise.reject(new Error('synthetic owner callback rejects')),
  });
  await supervisor.start();
  const result = await supervisor.stop();
  assert.equal(result.state, 'FAILED');
  assert.equal(result.terminalCode,
    'GUARDIAN_SUPERVISOR_TERMINAL_HANDLER_FAILED');
  assert.equal(source.listenerCount('SIGTERM'), 0);
});


test('real Node child process handles OS SIGTERM and SIGINT with bounded loopback closure', async () => {
  const { spawn } = require('node:child_process');
  const path = require('node:path');
  const fixture = path.join(__dirname, 'guardian-process-signal-child.cjs');
  for (const signal of ['SIGTERM', 'SIGINT']) {
    const child = spawn(process.execPath, [fixture], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH },
    });
    let stdout = '', stderr = '', signaled = false;
    const response = new Promise((resolve, reject) => {
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (fragment) => {
        stdout += fragment;
        if (!signaled && stdout.includes('READY\n')) {
          signaled = true;
          child.kill(signal);
        }
      });
      child.stderr.on('data', (fragment) => { stderr += fragment; });
      child.on('error', reject);
      child.on('exit', (code, receivedSignal) => resolve({
        code, receivedSignal,
      }));
    });
    const deadline = setTimeout(() => child.kill('SIGKILL'), 1500);
    try {
      const result = await response;
      assert.equal(result.code, 0, stderr);
      assert.equal(result.receivedSignal, null);
      assert.equal(signaled, true, stderr);
      const receipts = stdout.split('\n').filter((row) =>
        row.startsWith('TERMINAL:'));
      assert.equal(receipts.length, 1, stdout);
      const receipt = JSON.parse(receipts[0].slice('TERMINAL:'.length));
      assert.equal(receipt.state, 'STOPPED');
      assert.equal(receipt.reason, signal);
      assert.equal(receipt.hostStopped, true);
      assert.equal(receipt.activationAllowed, false);
      assert.equal(receipt.releaseAuthority, 'NOT_ISSUED');
    } finally {
      clearTimeout(deadline);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
  }
});
