'use strict';
// Deliberately synthetic IPC-only child to exercise parent negative cases.
// A HEALTH_RESULT from this fixture never proves a Protected Host is healthy.
const mode = require('node:path').basename(__filename, '.cjs');
const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V2';
const base = { protocol: PROTOCOL, activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED' };
let stopped = false;
let generation = null;
let previousChallenge = null;
function send(frame) {
  if (process.connected) process.send({ ...base, ...frame });
}
process.on('message', (frame) => {
  if (frame?.event === 'BIND' && generation === null) {
    generation = frame.generation;
    send({ event: 'READY', generation, state: 'RUNNING' });
    if (mode === 'probe-unsolicited') {
      setTimeout(() => send({ event: 'HEALTH_RESULT', generation,
        challenge: 'b'.repeat(32), healthy: true }), 35);
    }
    return;
  }
  if (!frame || frame.event !== 'HEALTH_PROBE' || stopped) return;
  const result = {
    event: 'HEALTH_RESULT', generation, challenge: frame.challenge,
    healthy: true,
  };
  if (mode === 'probe-unresponsive') return;
  if (mode === 'probe-unhealthy') result.healthy = false;
  if (mode === 'probe-forged') result.challenge = 'a'.repeat(32);
  if (mode === 'probe-extra-field') result.untrusted = 'payload';
  // G28: a correct challenge echoed under another generation identity.
  if (mode === 'probe-wrong-generation') result.generation = 'e'.repeat(32);
  // G28: replay of the first, already-answered result for a second probe.
  if (mode === 'probe-replay' && previousChallenge !== null) {
    result.challenge = previousChallenge;
  }
  previousChallenge = frame.challenge;
  const deliver = () => send(result);
  if (mode === 'probe-late') setTimeout(deliver, 135);
  else if (mode === 'probe-stopping') setTimeout(deliver, 160);
  else deliver();
});
process.on('SIGTERM', () => {
  stopped = true;
  send({ event: 'TERMINAL', generation, state: 'STOPPED', hostStopped: true });
  setTimeout(() => process.exit(0), 8);
});
send({ event: 'HELLO' });
