/**
 * Explicit child-side adapter for the protected Guardian Host Runner.
 * The owner-supplied factory builds configuration INSIDE the child process;
 * no key, token or D1 configuration is passed over parent IPC or argv.
 *
 * Import and construction are inert. Only explicit start() creates a runner,
 * starts the protected host, probes its local health endpoint and sends READY.
 * Only the existing Supervisor can emit a terminal signal receipt.
 */
'use strict';

const http = require('node:http');

const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V1';
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
  healthTimeoutMs = 1500 } = {}) {
  if (typeof createRunner !== 'function' ||
      !ipc || typeof ipc.send !== 'function' ||
      typeof ipc.disconnect !== 'function' ||
      !Number.isSafeInteger(healthTimeoutMs) || healthTimeoutMs < 50 ||
      healthTimeoutMs > 5000) {
    throw childError('GUARDIAN_CHILD_RUNTIME_CONFIG_INVALID');
  }
  let state = 'CREATED', runner = null, terminalSent = false;
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
    const frame = {
      protocol: PROTOCOL, event: 'TERMINAL', state,
      hostStopped: state === 'STOPPED',
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    };
    void send(frame).catch(() => {}).finally(() => {
      try { if (ipc.connected) ipc.disconnect(); } catch (_) {}
    });
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
      await send({ protocol: PROTOCOL, event: 'READY',
        state: 'RUNNING', activationAllowed: false,
        releaseAuthority: 'NOT_ISSUED' });
      state = 'RUNNING';
      return Object.freeze({ state, healthVerified: true,
        activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
    } catch (_) {
      state = 'FAILED';
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
      state, healthVerified: state === 'RUNNING',
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    });
  }
  return Object.freeze({ start, status });
}

module.exports = { createGuardianChildRuntime };
