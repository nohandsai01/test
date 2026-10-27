/**
 * Explicit child-side adapter for the protected Guardian Host Runner.
 * The owner-supplied factory builds configuration INSIDE the child process;
 * no key, token or D1 configuration is passed over parent IPC or argv.
 *
 * Import and construction are inert. Only explicit start() creates a runner,
 * starts the protected host, probes its local health endpoint and sends READY.
 * Only the existing Supervisor can emit a terminal signal receipt.
 *
 * G27: after local health is verified and before READY, the child sends
 * HELLO and accepts exactly one parent BIND generation. Every later frame
 * carries that generation; probes for any other generation get no answer.
 */
'use strict';

const http = require('node:http');

const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V2';
const GENERATION = /^[0-9a-f]{32}$/;
function exactFrame(value, keys) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key)) &&
    value.protocol === PROTOCOL &&
    value.activationAllowed === false &&
    value.releaseAuthority === 'NOT_ISSUED';
}
function bindFrame(value) {
  return exactFrame(value, ['protocol', 'event', 'generation',
    'activationAllowed', 'releaseAuthority']) &&
    value.event === 'BIND' && typeof value.generation === 'string' &&
    GENERATION.test(value.generation);
}
function probeFrame(value) {
  return exactFrame(value, ['protocol', 'event', 'generation', 'challenge',
    'activationAllowed', 'releaseAuthority']) &&
    value.event === 'HEALTH_PROBE' &&
    typeof value.generation === 'string' &&
    typeof value.challenge === 'string' &&
    /^[0-9a-f]{32}$/.test(value.challenge);
}
function childError(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}
function valid(obj) {
  return obj !== null && typeof obj === 'object' && !Array.isArray(obj);
}
function validateStatus(status) {
  return valid(status) && status.state === 'RUNNING' &&
    status.activationAllowed === false &&
    status.releaseAuthority === 'NOT_ISSUED' &&
    valid(status.loopback) &&
    ['127.0.0.1', '::1'].includes(status.loopback.address) &&
    Number.isSafeInteger(status.loopback.port) &&
    status.loopback.port > 0 && status.loopback.port <= 65535;
}
function probeLocalHealth(address, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false, bytes = 0;
    const chunks = [];
    const end = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(true);
    };
    const request = http.get({
      host: address, port, path: '/healthz',
      agent: false, timeout: timeoutMs,
      headers: { Connection: 'close' },
    }, (response) => {
      if (response.statusCode !== 200 ||
          !/^application\/json/.test(response.headers['content-type'] || '')) {
        request.destroy();
        end(childError('GUARDIAN_CHILD_HEALTH_REJECTED'));
        return;
      }
      response.on('data', (fragment) => {
        bytes += fragment.length;
        if (bytes > 1024) {
          request.destroy();
          end(childError('GUARDIAN_CHILD_HEALTH_OVERSIZE'));
        } else chunks.push(fragment);
      });
      response.on('error', () => end(childError('GUARDIAN_CHILD_HEALTH_UNAVAILABLE')));
      response.on('end', () => {
        try {
          const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!valid(payload) || payload.running !== true ||
              payload.feature !== 'OFF_OR_SOURCE_ONLY' ||
              payload.releaseAuthority !== 'NOT_ISSUED') {
            throw new Error('unverified');
          }
          end(null);
        } catch (_) { end(childError('GUARDIAN_CHILD_HEALTH_INVALID')); }
      });
    });
    request.once('timeout', () => {
      request.destroy();
      end(childError('GUARDIAN_CHILD_HEALTH_TIMEOUT'));
    });
    request.once('error', () =>
      end(childError('GUARDIAN_CHILD_HEALTH_UNAVAILABLE')));
  });
}

function createGuardianChildRuntime({ createRunner, ipc = process,
  healthTimeoutMs = 1500, bindTimeoutMs = 2000 } = {}) {
  if (typeof createRunner !== 'function' ||
      !ipc || typeof ipc.send !== 'function' ||
      typeof ipc.disconnect !== 'function' ||
      !Number.isSafeInteger(healthTimeoutMs) || healthTimeoutMs < 50 ||
      healthTimeoutMs > 5000 ||
      !Number.isSafeInteger(bindTimeoutMs) || bindTimeoutMs < 50 ||
      bindTimeoutMs > 10_000) {
    throw childError('GUARDIAN_CHILD_RUNTIME_CONFIG_INVALID');
  }
  let state = 'CREATED', runner = null, terminalSent = false;
  // Set once from the first valid BIND; never replaced by a later BIND.
  let generation = null, bindWaiter = null;
  function send(frame) {
    return new Promise((resolve, reject) => {
      if (ipc.connected === false) {
        reject(childError('GUARDIAN_CHILD_IPC_UNAVAILABLE'));
        return;
      }
      try {
        ipc.send(frame, (error) => error ?
          reject(childError('GUARDIAN_CHILD_IPC_UNAVAILABLE')) : resolve());
      } catch (_) { reject(childError('GUARDIAN_CHILD_IPC_UNAVAILABLE')); }
    });
  }
  function onTerminal(receipt) {
    if (terminalSent) return;
    terminalSent = true;
    state = receipt?.hostStopped === true &&
      receipt?.state === 'STOPPED' &&
      receipt?.releaseAuthority === 'NOT_ISSUED' &&
      receipt?.activationAllowed === false ? 'STOPPED' : 'FAILED';
    // Only a clean stop can produce the parent's accepted TERMINAL. Bad
    // termination is deliberately rejected by the parent fail-closed logic.
    // An unbound child has no identity to report; it only disconnects and
    // the parent records its exit as unverified.
    const disconnect = () => {
      try { if (ipc.connected) ipc.disconnect(); } catch (_) {}
    };
    if (generation === null) {
      disconnect();
      return;
    }
    const frame = {
      protocol: PROTOCOL, event: 'TERMINAL', generation, state,
      hostStopped: state === 'STOPPED',
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    };
    void send(frame).catch(() => {}).finally(disconnect);
  }

  function onFrame(frame) {
    if (bindFrame(frame)) {
      // First valid BIND wins; a rebind attempt cannot move this process
      // to another generation and is otherwise ignored.
      if (generation === null && bindWaiter) {
        generation = frame.generation;
        const waiter = bindWaiter;
        bindWaiter = null;
        waiter.resolve();
      }
      return;
    }
    void onProbe(frame);
  }
  let bindTimer = null;
  function awaitBind() {
    const pending = new Promise((resolve, reject) => {
      bindTimer = setTimeout(() => {
        bindWaiter = null;
        reject(childError('GUARDIAN_CHILD_BIND_TIMEOUT'));
      }, bindTimeoutMs);
      bindWaiter = { resolve: () => { clearTimeout(bindTimer); resolve(); } };
    });
    // A failed HELLO send abandons this promise; never leave it unhandled.
    pending.catch(() => {});
    return pending;
  }

  let probing = false;
  async function onProbe(frame) {
    // IPC is private to the owned parent. Reject unrecognized challenge
    // shapes and probes for any other generation without answering them.
    if (!probeFrame(frame) || generation === null ||
        frame.generation !== generation) return;
    let healthy = false;
    if (state === 'RUNNING' && !terminalSent && !probing) {
      probing = true;
      try {
        const before = runner.status();
        if (validateStatus(before)) {
          await probeLocalHealth(before.loopback.address,
            before.loopback.port, healthTimeoutMs);
          const after = runner.status();
          healthy = !terminalSent && state === 'RUNNING' &&
            validateStatus(after) &&
            after.loopback.address === before.loopback.address &&
            after.loopback.port === before.loopback.port;
        }
      } catch (_) {
        healthy = false;
      } finally {
        probing = false;
      }
    }
    // Never send host status or secrets over IPC; only challenge match and
    // a fresh boolean observation are visible to the parent.
    void send({
      protocol: PROTOCOL, event: 'HEALTH_RESULT', generation,
      challenge: frame.challenge, healthy,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    }).catch(() => {});
  }

  async function start() {
    if (state !== 'CREATED') {
      throw childError('GUARDIAN_CHILD_RUNTIME_STATE_INVALID');
    }
    state = 'STARTING';
    try {
      runner = createRunner({ onTerminal });
      if (!runner || typeof runner.start !== 'function' ||
          typeof runner.stop !== 'function' ||
          typeof runner.status !== 'function') {
        throw childError('GUARDIAN_CHILD_RUNNER_INVALID');
      }
      await runner.start();
      const initial = runner.status();
      if (!validateStatus(initial)) {
        throw childError('GUARDIAN_CHILD_RUNNER_NOT_READY');
      }
      await probeLocalHealth(initial.loopback.address,
        initial.loopback.port, healthTimeoutMs);
      const final = runner.status();
      if (!validateStatus(final) || terminalSent ||
          final.loopback.address !== initial.loopback.address ||
          final.loopback.port !== initial.loopback.port) {
        throw childError('GUARDIAN_CHILD_RUNNER_STATE_DRIFT');
      }
      // Register before HELLO: otherwise BIND (or a probe right after
      // READY) could arrive before the child's message listener exists.
      if (typeof ipc.on !== 'function') {
        throw childError('GUARDIAN_CHILD_IPC_LISTENER_UNAVAILABLE');
      }
      ipc.on('message', onFrame);
      const bind = awaitBind();
      await send({ protocol: PROTOCOL, event: 'HELLO',
        activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
      await bind;
      const bound = runner.status();
      if (!validateStatus(bound) || terminalSent ||
          bound.loopback.address !== initial.loopback.address ||
          bound.loopback.port !== initial.loopback.port) {
        throw childError('GUARDIAN_CHILD_RUNNER_STATE_DRIFT');
      }
      state = 'RUNNING';
      await send({ protocol: PROTOCOL, event: 'READY', generation,
        state: 'RUNNING', activationAllowed: false,
        releaseAuthority: 'NOT_ISSUED' });
      return Object.freeze({ state, healthVerified: true,
        activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
    } catch (_) {
      state = 'FAILED';
      clearTimeout(bindTimer);
      bindWaiter = null;
      if (runner && !terminalSent) {
        try { await runner.stop(); } catch (_) {}
      }
      // Do not forge a READY when a failed start leaves a live socket. An
      // unverified TERMINAL also causes the parent to hold/kill the child.
      if (!terminalSent) onTerminal({ state: 'FAILED', hostStopped: false });
      throw childError('GUARDIAN_CHILD_RUNTIME_START_UNVERIFIED');
    }
  }
  function status() {
    return Object.freeze({
      state, healthVerified: state === 'RUNNING', generationBound: generation !== null,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    });
  }
  return Object.freeze({ start, status });
}

module.exports = { createGuardianChildRuntime };
