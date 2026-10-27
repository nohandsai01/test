/**
 * Inert process-manager adapter for the isolated Guardian protected host.
 *
 * This module never opens a listener, installs signal handlers at import,
 * calls process.exit/kill, publishes a Check, or manages credentials.
 * The owner-run process manager injects a validated Protected Host instance,
 * explicitly calls start(), and handles onTerminal receipts (including
 * fatal-stop receipts) to decide external process termination.
 */
'use strict';

const { EventEmitter } = require('node:events');

const SIGNALS = Object.freeze(['SIGTERM', 'SIGINT']);
const FIELDS = new Set(['host', 'signalSource', 'onTerminal',
  'stopDeadlineMs']);
const MIN_STOP_MS = 50;
const MAX_STOP_MS = 30_000;

class GuardianSupervisorError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GuardianSupervisorError';
    this.code = code;
  }
}
function validRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function safeHostSnapshot(host) {
  try {
    const s = host.status();
    if (!validRecord(s) || typeof s.state !== 'string' ||
        s.activationAllowed !== false ||
        s.releaseAuthority !== 'NOT_ISSUED') return null;
    const address = s.address;
    const loopback = validRecord(address) &&
      ['127.0.0.1', '::1'].includes(address.address) &&
      Number.isSafeInteger(address.port) && address.port > 0 &&
      address.port <= 65535 ?
      Object.freeze({ address: address.address, port: address.port }) : null;
    return Object.freeze({ state: s.state, loopback });
  } catch (_) { return null; }
}
function underDeadline(operation, milliseconds) {
  let timeout;
  return Promise.race([
    Promise.resolve().then(operation),
    new Promise((_, reject) => {
      timeout = setTimeout(() => reject(
        new GuardianSupervisorError('GUARDIAN_SUPERVISOR_STOP_TIMEOUT')),
      milliseconds);
    }),
  ]).finally(() => clearTimeout(timeout));
}

function createGuardianProcessSupervisor(configuration) {
  if (!validRecord(configuration) ||
      Object.keys(configuration).some((key) => !FIELDS.has(key)) ||
      !configuration.host ||
      typeof configuration.host.start !== 'function' ||
      typeof configuration.host.stop !== 'function' ||
      typeof configuration.host.status !== 'function' ||
      typeof configuration.onTerminal !== 'function') {
    throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_CONFIG_INVALID');
  }
  const source = configuration.signalSource === undefined ?
    process : configuration.signalSource;
  if (!(source instanceof EventEmitter) &&
      (!source || typeof source.on !== 'function' ||
        typeof source.removeListener !== 'function')) {
    throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_SIGNAL_SOURCE_INVALID');
  }
  const deadline = configuration.stopDeadlineMs ?? 15_000;
  if (!Number.isSafeInteger(deadline) || deadline < MIN_STOP_MS ||
      deadline > MAX_STOP_MS) {
    throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_DEADLINE_INVALID');
  }

  const host = configuration.host;
  let state = 'CREATED';
  let listenersAttached = false;
  let startPromise = null;
  let stopPromise = null;
  let terminalReported = false;
  let stopReason = null;
  let terminalCode = null;

  function status() {
    const snapshot = safeHostSnapshot(host);
    return Object.freeze({
      state, stopReason, terminalCode,
      signalHandlersAttached: listenersAttached,
      underlyingHostState: snapshot?.state ?? null,
      // Loopback locator is operational metadata, never a public URL.
      loopback: state === 'RUNNING' ? snapshot?.loopback ?? null : null,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    });
  }

  function detachSignals() {
    if (!listenersAttached) return;
    listenersAttached = false;
    for (const signal of SIGNALS) {
      try { source.removeListener(signal, handlers[signal]); }
      catch (_) { terminalCode = 'GUARDIAN_SUPERVISOR_DETACH_FAILED'; state = 'FAILED'; }
    }
  }
  function notifyTerminal() {
    if (terminalReported) return;
    terminalReported = true;
    const receipt = Object.freeze({
      state,
      reason: stopReason ?? 'STARTUP_FAILED',
      errorCode: terminalCode,
      hostStopped: state === 'STOPPED',
      activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
    try {
      const result = configuration.onTerminal(receipt);
      if (result && typeof result.then === 'function') {
        // This is an unsupported callback contract. Consume a possible
        // rejection so a misconfigured async owner callback cannot create an
        // unhandled rejection while the supervisor fails closed.
        Promise.resolve(result).catch(() => {});
        throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_ASYNC_TERMINAL_HANDLER');
      }
    } catch (_) {
      // An unhandled process-manager callback is not a clean shutdown.
      terminalCode = 'GUARDIAN_SUPERVISOR_TERMINAL_HANDLER_FAILED';
      state = 'FAILED';
    }
  }
  const handlers = Object.freeze({
    SIGTERM: () => { void stop('SIGTERM'); },
    SIGINT: () => { void stop('SIGINT'); },
  });
  function attachSignals() {
    if (listenersAttached) return;
    // Set the flag before installation to permit cleanup of a partial attach.
    listenersAttached = true;
    try {
      for (const signal of SIGNALS) source.on(signal, handlers[signal]);
    } catch (_) {
      detachSignals();
      throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_ATTACH_FAILED');
    }
  }

  async function start() {
    if (state !== 'CREATED') {
      throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_STATE_INVALID');
    }
    state = 'STARTING';
    try { attachSignals(); }
    catch (error) {
      state = 'FAILED';
      terminalCode = error.code ?? 'GUARDIAN_SUPERVISOR_ATTACH_FAILED';
      notifyTerminal();
      throw error;
    }
    startPromise = Promise.resolve().then(() => host.start()).then(
      () => {
        if (safeHostSnapshot(host)?.state !== 'RUNNING') {
          throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_HOST_NOT_READY');
        }
        if (!stopPromise) state = 'RUNNING';
        return status();
      },
      (error) => { throw error; },
    ).catch(async (error) => {
      state = 'FAILED';
      terminalCode = error instanceof GuardianSupervisorError ?
        error.code : 'GUARDIAN_SUPERVISOR_START_FAILED';
      // Even a rejected startup can leave a partially opened listener.
      // Cleanup is best effort and bounded; failure remains FAILED, never
      // auto-restart or claim ready. Terminal callback must be informed.
      try { await underDeadline(() => host.stop(), deadline); }
      catch (_) {
        terminalCode = 'GUARDIAN_SUPERVISOR_START_CLEANUP_UNVERIFIED';
      }
      detachSignals();
      notifyTerminal();
      throw new GuardianSupervisorError(terminalCode);
    });
    return startPromise;
  }

  async function stop(reason = 'MANUAL') {
    if (!['MANUAL', ...SIGNALS].includes(reason)) {
      throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_STOP_REASON_INVALID');
    }
    if (stopPromise) return stopPromise;
    if (state === 'STOPPED' || state === 'FAILED') return status();
    stopReason = reason;
    if (state === 'CREATED') {
      state = 'STOPPED';
      notifyTerminal();
      return status();
    }
    if (state !== 'STARTING' && state !== 'RUNNING') {
      throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_STATE_INVALID');
    }
    state = 'STOPPING';
    stopPromise = (async () => {
      try {
        if (startPromise) await startPromise;
        if (state === 'FAILED') return status();
        await underDeadline(() => host.stop(), deadline);
        if (safeHostSnapshot(host)?.state !== 'STOPPED') {
          throw new GuardianSupervisorError('GUARDIAN_SUPERVISOR_STOP_UNVERIFIED');
        }
        state = 'STOPPED';
      } catch (error) {
        // Even when stop() fails or times out, this adapter must not claim
        // that the host ceased listening. External supervisor must kill the
        // process; no automatic restart or release is ever allowed.
        state = 'FAILED';
        terminalCode = error instanceof GuardianSupervisorError ?
          error.code : 'GUARDIAN_SUPERVISOR_STOP_FAILED';
      } finally {
        detachSignals();
        notifyTerminal();
      }
      // Any failure to detach a signal handler or notify the parent must be
      // reflected in the final return, not hidden behind an earlier snapshot.
      return status();
    })();
    return stopPromise;
  }

  return Object.freeze({ start, stop, status });
}

module.exports = { createGuardianProcessSupervisor, GuardianSupervisorError };
