/**
 * Inert, owner-controlled local child process controller for Guardian.
 * It never starts a child at import/construction. Only start() spawns the
 * pinned local executable. No shell, inherited credentials, network service
 * configuration, production deployment or automatic restart.
 *
 * A child reports READY/TERMINAL over its private IPC channel. This is a
 * lifecycle receipt from the owned child, NOT an authorization assertion:
 * the actual Protected Host is still responsible for all preflight gates.
 */
'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V1';
const ALLOWED = new Set(['entrypoint', 'cwd', 'startupTimeoutMs',
  'shutdownTimeoutMs', 'onTerminal']);
const MIN_WAIT = 50;
const MAX_WAIT = 30_000;

class GuardianChildControllerError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
    this.name = 'GuardianChildControllerError';
  }
}
function object(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function ownShape(x, fields) {
  return object(x) && Object.keys(x).length === fields.length &&
    fields.every((f) => Object.hasOwn(x, f));
}
function bounded(value, fallback) {
  if (value === undefined) return fallback;
  return Number.isSafeInteger(value) && value >= MIN_WAIT && value <= MAX_WAIT ?
    value : null;
}
function validatedEntrypoint(name, directory) {
  if (typeof name !== 'string' || !path.isAbsolute(name) ||
      name.includes('\0') || name.length > 4096) return null;
  try {
    // macOS /tmp is an ancestor symlink to /private/tmp. Canonicalize the
    // parent path, while rejecting a symlink at the executable itself.
    const info = fs.lstatSync(name);
    const actual = fs.realpathSync(name);
    if (!info.isFile() || info.isSymbolicLink() ||
        !actual.startsWith(directory + path.sep) ||
        !Number.isSafeInteger(info.size) || info.size <= 0 ||
        info.size > 1_000_000) return null;
    // Pin bytes as well as path/inode: rewriting the same inode between
    // construction and start is not an authorized executable update.
    const digest = crypto.createHash('sha256')
      .update(fs.readFileSync(name)).digest('hex');
    return Object.freeze({ actual, dev: info.dev, ino: info.ino,
      size: info.size, sha256: digest });
  } catch (_) { return null; }
}
function makeReceipt(state, code) {
  return Object.freeze({
    state, errorCode: code,
    hostStopped: state === 'STOPPED',
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  });
}
function readyFrame(value) {
  return ownShape(value, ['protocol', 'event', 'state',
    'activationAllowed', 'releaseAuthority']) &&
    value.protocol === PROTOCOL && value.event === 'READY' &&
    value.state === 'RUNNING' && value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED';
}
function terminalFrame(value) {
  return ownShape(value, ['protocol', 'event', 'state', 'hostStopped',
    'activationAllowed', 'releaseAuthority']) &&
    value.protocol === PROTOCOL && value.event === 'TERMINAL' &&
    value.state === 'STOPPED' && value.hostStopped === true &&
    value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED';
}

/**
 * The executable entrypoint must be a regular (not symlinked) file inside a
 * real owner-pinned directory. The parent never receives or forwards secrets.
 * Parent only owns the child it spawned and never sends a signal to any PID
 * supplied by a provider or JSON message.
 */
function createGuardianLocalProcessController(options) {
  if (!object(options) || Object.keys(options).some((x) => !ALLOWED.has(x)) ||
      typeof options.cwd !== 'string' || !path.isAbsolute(options.cwd) ||
      typeof options.entrypoint !== 'string' ||
      typeof options.onTerminal !== 'function') {
    throw new GuardianChildControllerError('GUARDIAN_CHILD_CONFIG_INVALID');
  }
  let canonicalCwd;
  try {
    canonicalCwd = fs.realpathSync(options.cwd);
    if (!fs.statSync(canonicalCwd).isDirectory()) throw new Error('not directory');
  } catch (_) {
    throw new GuardianChildControllerError('GUARDIAN_CHILD_CWD_UNVERIFIED');
  }
  const pinnedFile = validatedEntrypoint(options.entrypoint, canonicalCwd);
  if (!pinnedFile) {
    throw new GuardianChildControllerError('GUARDIAN_CHILD_ENTRYPOINT_UNVERIFIED');
  }
  const startupMs = bounded(options.startupTimeoutMs, 5000);
  const shutdownMs = bounded(options.shutdownTimeoutMs, 3000);
  if (startupMs === null || shutdownMs === null) {
    throw new GuardianChildControllerError('GUARDIAN_CHILD_TIMEOUT_INVALID');
  }

  let state = 'CREATED';
  let child = null, expectedExit = false, gotReady = false, gotTerminal = false;
  let failure = null, notified = false, startPromise = null, stopPromise = null;
  let faultKillTimer = null;
  let settleStart, rejectStart, settleExit;
  const exited = new Promise((resolve) => { settleExit = resolve; });
  function stateView() {
    return Object.freeze({
      state, errorCode: failure,
      pid: child?.pid ?? null,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    });
  }
  function finish(stateName, code) {
    if (notified) return;
    state = stateName;
    failure = code ?? null;
    notified = true;
    const receipt = makeReceipt(state, failure);
    try {
      const value = options.onTerminal(receipt);
      if (value && typeof value.then === 'function') {
        Promise.resolve(value).catch(() => {});
        throw new Error('asynchronous terminal callback forbidden');
      }
    } catch (_) {
      state = 'FAILED';
      failure = 'GUARDIAN_CHILD_TERMINAL_CALLBACK_FAILED';
    }
  }
  function fail(code) {
    if (notified) return;
    const wasStarting = state === 'STARTING';
    failure = code;
    state = 'FAILED';
    if (wasStarting) {
      rejectStart?.(new GuardianChildControllerError(code));
    }
    // Only the already-owned child may be signaled; do not kill a process by
    // PID from any IPC message. Escalation is bounded in the explicit close.
    if (child && child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGTERM'); } catch (_) {}
      // A protocol-invalid child might ignore SIGTERM. Escalate only against
      // the owned ChildProcess object, never against a supplied PID.
      if (!faultKillTimer) {
        faultKillTimer = setTimeout(() => {
          try {
            if (child.exitCode === null && child.signalCode === null) {
              child.kill('SIGKILL');
            }
          } catch (_) {}
        }, shutdownMs);
      }
    }
    finish('FAILED', code);
  }
  function onMessage(payload) {
    // An unknown frame is a protocol failure, not an event to ignore.
    if (!gotReady && readyFrame(payload) && !gotTerminal) {
      gotReady = true;
      if (!expectedExit && !notified) {
        state = 'RUNNING';
        settleStart?.(stateView());
      }
      return;
    }
    if (gotReady && !gotTerminal && terminalFrame(payload)) {
      gotTerminal = true;
      return;
    }
    fail('GUARDIAN_CHILD_PROTOCOL_INVALID');
  }
  function onExit(code, signal) {
    if (faultKillTimer) clearTimeout(faultKillTimer);
    faultKillTimer = null;
    settleExit?.();
    if (!gotReady || expectedExit) {
      rejectStart?.(new GuardianChildControllerError(
        expectedExit ? 'GUARDIAN_CHILD_START_CANCELLED' :
          'GUARDIAN_CHILD_EXIT_BEFORE_READY'));
    }
    if (notified) return;
    if (code === 0 && signal === null && expectedExit && gotTerminal) {
      finish('STOPPED', null);
      return;
    }
    finish('FAILED', !gotReady ?
      'GUARDIAN_CHILD_EXIT_BEFORE_READY' : gotTerminal && code !== 0 ?
        'GUARDIAN_CHILD_NONZERO_EXIT' : 'GUARDIAN_CHILD_EXIT_UNVERIFIED');
  }
  function onError() {
    rejectStart?.(new GuardianChildControllerError('GUARDIAN_CHILD_SPAWN_FAILED'));
    fail('GUARDIAN_CHILD_SPAWN_FAILED');
  }

  async function start() {
    if (state !== 'CREATED') {
      throw new GuardianChildControllerError('GUARDIAN_CHILD_STATE_INVALID');
    }
    state = 'STARTING';
    startPromise = new Promise((resolve, reject) => {
      settleStart = resolve;
      rejectStart = reject;
    });
    try {
      // Reject changed files between inert construction and explicit start.
      // A production owner must additionally pin the executable to a trusted
      // immutable build artifact; no source file is selected from PR input.
      const currentFile = validatedEntrypoint(options.entrypoint, canonicalCwd);
      if (!currentFile || currentFile.actual !== pinnedFile.actual ||
          currentFile.dev !== pinnedFile.dev ||
          currentFile.ino !== pinnedFile.ino ||
          currentFile.size !== pinnedFile.size ||
          currentFile.sha256 !== pinnedFile.sha256) {
        throw new GuardianChildControllerError('GUARDIAN_CHILD_ENTRYPOINT_CHANGED');
      }
      child = spawn(process.execPath, [options.entrypoint], {
        cwd: canonicalCwd,
        shell: false, detached: false,
        execArgv: [],
        // Explicit no-inherited-secret environment, no argv credentials.
        env: Object.freeze({ NODE_ENV: 'test', PATH: '/usr/bin:/bin' }),
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      });
      child.on('message', onMessage);
      child.once('error', onError);
      child.once('exit', onExit);
    } catch (error) {
      const code = error instanceof GuardianChildControllerError ?
        error.code : 'GUARDIAN_CHILD_SPAWN_FAILED';
      fail(code);
      rejectStart?.(new GuardianChildControllerError(code));
    }
    let timer;
    try {
      return await Promise.race([
        startPromise,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new GuardianChildControllerError(
            'GUARDIAN_CHILD_START_TIMEOUT')), startupMs);
        }),
      ]);
    } catch (error) {
      if (!notified) fail(error.code ?? 'GUARDIAN_CHILD_START_FAILED');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async function stop() {
    if (stopPromise) return stopPromise;
    if (state === 'CREATED') {
      finish('STOPPED', null);
      return stateView();
    }
    if (notified) return stateView();
    expectedExit = true;
    state = 'STOPPING';
    stopPromise = (async () => {
      try { child?.kill('SIGTERM'); } catch (_) {}
      let timer;
      let forced = false;
      try {
        await Promise.race([
          exited,
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new GuardianChildControllerError(
              'GUARDIAN_CHILD_STOP_TIMEOUT')), shutdownMs);
          }),
        ]);
      } catch (_) {
        forced = true;
        // Emergency escalation applies ONLY to our own child, never a remote
        // process. A forced kill can never be reported as clean STOPPED.
        try { child?.kill('SIGKILL'); } catch (_) {}
        fail('GUARDIAN_CHILD_STOP_TIMEOUT');
        // Do not block the owner process manager on a misbehaving child.
      } finally { clearTimeout(timer); }
      if (!notified) {
        finish('FAILED', forced ? 'GUARDIAN_CHILD_STOP_TIMEOUT' :
          'GUARDIAN_CHILD_TERMINAL_MISSING');
      }
      return stateView();
    })();
    return stopPromise;
  }

  return Object.freeze({ start, stop, status: stateView });
}

module.exports = { createGuardianLocalProcessController,
  GuardianChildControllerError };
