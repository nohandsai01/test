/**
 * Inert, owner-controlled local child process controller for Guardian.
 * It never starts a child at import/construction. Only start() spawns the
 * pinned local executable. No shell, inherited credentials, network service
 * configuration, production deployment or automatic restart.
 *
 * A child reports READY/TERMINAL over its private IPC channel. This is a
 * lifecycle receipt from the owned child, NOT an authorization assertion:
 * the actual Protected Host is still responsible for all preflight gates.
 *
 * G27: every start() issues one fresh, never-reused process generation.
 * The optional synchronous onLaunch callback must durably record it BEFORE
 * spawn. The child learns it only via HELLO -> BIND over private IPC and
 * every later READY/HEALTH_RESULT/TERMINAL frame must carry the same value.
 * A PID is an OS handle that can be reused; the generation is the identity.
 */
'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V2';
const ALLOWED = new Set(['entrypoint', 'cwd', 'startupTimeoutMs',
  'shutdownTimeoutMs', 'healthProbeTimeoutMs', 'onTerminal', 'onLaunch']);
const MIN_WAIT = 50;
const MAX_WAIT = 30_000;
const GENERATION = /^[0-9a-f]{32}$/;
// In-process uniqueness guard on top of 128 random bits. Durable reuse
// across parent restarts is detected by the owner generation ledger.
const issuedGenerations = new Set();

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
function makeReceipt(state, code, generationId) {
  return Object.freeze({
    state, errorCode: code,
    hostStopped: state === 'STOPPED',
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
    generationId,
  });
}
function newGeneration() {
  for (;;) {
    const id = crypto.randomBytes(16).toString('hex');
    if (!issuedGenerations.has(id)) {
      issuedGenerations.add(id);
      return id;
    }
  }
}
// Frame classifiers check SHAPE only. A well-formed frame carrying another
// generation is a distinct, stronger failure than a malformed frame.
function helloFrame(value) {
  return ownShape(value, ['protocol', 'event', 'activationAllowed',
    'releaseAuthority']) &&
    value.protocol === PROTOCOL && value.event === 'HELLO' &&
    value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED';
}
function readyFrame(value) {
  return ownShape(value, ['protocol', 'event', 'generation', 'state',
    'activationAllowed', 'releaseAuthority']) &&
    value.protocol === PROTOCOL && value.event === 'READY' &&
    typeof value.generation === 'string' &&
    value.state === 'RUNNING' && value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED';
}
function healthFrame(value) {
  return ownShape(value, ['protocol', 'event', 'generation', 'challenge',
    'healthy', 'activationAllowed', 'releaseAuthority']) &&
    value.protocol === PROTOCOL && value.event === 'HEALTH_RESULT' &&
    typeof value.generation === 'string' &&
    typeof value.challenge === 'string' &&
    /^[0-9a-f]{32}$/.test(value.challenge) &&
    typeof value.healthy === 'boolean' &&
    value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED';
}
function terminalFrame(value) {
  return ownShape(value, ['protocol', 'event', 'generation', 'state',
    'hostStopped', 'activationAllowed', 'releaseAuthority']) &&
    value.protocol === PROTOCOL && value.event === 'TERMINAL' &&
    typeof value.generation === 'string' &&
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
      typeof options.onTerminal !== 'function' ||
      (options.onLaunch !== undefined &&
        typeof options.onLaunch !== 'function')) {
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
  const healthProbeMs = bounded(options.healthProbeTimeoutMs, 3000);
  if (startupMs === null || shutdownMs === null ||
      healthProbeMs === null || healthProbeMs > 5000) {
    throw new GuardianChildControllerError('GUARDIAN_CHILD_TIMEOUT_INVALID');
  }

  let state = 'CREATED';
  let child = null, expectedExit = false, gotReady = false, gotTerminal = false;
  let failure = null, notified = false, startPromise = null, stopPromise = null;
  let faultKillTimer = null;
  let probe = null, expiredChallenge = null, probeBlocked = false;
  // generation is assigned exactly once per controller, at start(); bound
  // becomes true only after BIND was handed to the owned child's IPC.
  let generation = null, bound = false;
  let settleStart, rejectStart, settleExit;
  const exited = new Promise((resolve) => { settleExit = resolve; });
  function stateView() {
    return Object.freeze({
      state, errorCode: failure,
      pid: child?.pid ?? null,
      generationId: generation,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    });
  }
  function probeReceipt(healthy, reason) {
    return Object.freeze({
      schemaVersion: 1, status: 'SOURCE_ONLY_HOLD',
      observation: healthy ? 'LOCAL_CHILD_HEALTH_VERIFIED' : 'NOT_PROVEN',
      reason,
      processState: state,
      generationId: generation,
      liveness: healthy ? 'LOCAL_IPC_AND_LOOPBACK_ONLY' : 'NOT_PROVEN',
      manualInterventionRequired: true,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    });
  }
  function settleProbe(reason) {
    if (!probe) return;
    const current = probe;
    probe = null;
    expiredChallenge = current.challenge;
    probeBlocked = true;
    clearTimeout(current.timer);
    current.resolve(probeReceipt(false, reason));
  }
  function finish(stateName, code) {
    if (notified) return;
    settleProbe('GUARDIAN_CHILD_PROBE_TERMINATED');
    state = stateName;
    failure = code ?? null;
    notified = true;
    const receipt = makeReceipt(state, failure, generation);
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
  function onHello() {
    // Exactly one HELLO, only while starting, answered with the generation
    // this parent issued. Nothing in the child's frame selects the value.
    if (bound || gotReady || state !== 'STARTING' || expectedExit) {
      fail('GUARDIAN_CHILD_PROTOCOL_INVALID');
      return;
    }
    bound = true;
    try {
      child.send({
        protocol: PROTOCOL, event: 'BIND', generation,
        activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      }, (error) => { if (error) fail('GUARDIAN_CHILD_BIND_IPC_FAILED'); });
    } catch (_) {
      fail('GUARDIAN_CHILD_BIND_IPC_FAILED');
    }
  }
  function onMessage(payload) {
    if (helloFrame(payload)) {
      onHello();
      return;
    }
    // Every post-BIND frame is bound to this controller's generation. A
    // frame for another (older or forged) generation is never reinterpreted,
    // even as an ignorable late probe reply: it is fail-closed.
    if ((readyFrame(payload) || healthFrame(payload) ||
         terminalFrame(payload)) &&
        (!bound || payload.generation !== generation)) {
      fail(bound ? 'GUARDIAN_CHILD_GENERATION_MISMATCH' :
        'GUARDIAN_CHILD_PROTOCOL_INVALID');
      return;
    }
    // Child health results are valid only for a current owner-generated
    // random challenge. A delayed reply to one expired request is ignored;
    // all unsolicited or malformed frames are protocol violations.
    if (healthFrame(payload)) {
      if (probe && payload.challenge === probe.challenge &&
          state === 'RUNNING' && !notified && !expectedExit) {
        const current = probe;
        probe = null;
        clearTimeout(current.timer);
        if (!payload.healthy) probeBlocked = true;
        current.resolve(probeReceipt(payload.healthy,
          payload.healthy ? 'GUARDIAN_CHILD_HEALTH_VERIFIED' :
            'GUARDIAN_CHILD_HEALTH_UNVERIFIED'));
        return;
      }
      if (expiredChallenge === payload.challenge) {
        expiredChallenge = null;
        return;
      }
      fail('GUARDIAN_CHILD_PROTOCOL_INVALID');
      return;
    }
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
    generation = newGeneration();
    try {
      // Durable launch evidence precedes the child. If it cannot be
      // recorded synchronously, no process is spawned for this generation.
      if (options.onLaunch) {
        let value;
        try {
          value = options.onLaunch(Object.freeze({ generationId: generation,
            activationAllowed: false, releaseAuthority: 'NOT_ISSUED' }));
        } catch (_) {
          throw new GuardianChildControllerError(
            'GUARDIAN_CHILD_LAUNCH_RECORD_FAILED');
        }
        if (value && typeof value.then === 'function') {
          Promise.resolve(value).catch(() => {});
          throw new GuardianChildControllerError(
            'GUARDIAN_CHILD_LAUNCH_RECORD_FAILED');
        }
      }
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

  // One bounded, coalesced, read-only active probe. Unlike a PID check,
  // this verifies a round trip through the child IPC and its loopback
  // health endpoint. It never grants authorization or signals a process.
  function probeRuntime() {
    if (state !== 'RUNNING' || !child || !gotReady ||
        expectedExit || notified || gotTerminal || probeBlocked) {
      return Promise.resolve(probeReceipt(false,
        'GUARDIAN_CHILD_PROBE_UNAVAILABLE'));
    }
    if (probe) return probe.promise;
    const challenge = crypto.randomBytes(16).toString('hex');
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    const current = { challenge, promise, resolve, timer: null };
    probe = current;
    current.timer = setTimeout(() => {
      if (probe === current) {
        settleProbe('GUARDIAN_CHILD_PROBE_TIMEOUT');
      }
    }, healthProbeMs);
    try {
      child.send({
        protocol: PROTOCOL, event: 'HEALTH_PROBE', generation, challenge,
        activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      }, (error) => {
        if (error && probe === current) {
          settleProbe('GUARDIAN_CHILD_PROBE_IPC_FAILED');
        }
      });
    } catch (_) {
      settleProbe('GUARDIAN_CHILD_PROBE_IPC_FAILED');
    }
    return promise;
  }

  async function stop() {
    if (stopPromise) return stopPromise;
    settleProbe('GUARDIAN_CHILD_PROBE_STOPPING');
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

  return Object.freeze({ start, stop, status: stateView, probeRuntime });
}

module.exports = { createGuardianLocalProcessController,
  GuardianChildControllerError, GUARDIAN_CHILD_PROTOCOL: PROTOCOL,
  GUARDIAN_GENERATION_PATTERN: GENERATION };
