'use strict';
// Deliberately synthetic IPC-only child to exercise parent negative cases.
// A HEALTH_RESULT from this fixture never proves a Protected Host is healthy.
const mode = require('node:path').basename(__filename, '.cjs');
const PROTOCOL = 'NOHANDS_GUARDIAN_CHILD_V1';
const base = { protocol: PROTOCOL, activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED' };
let stopped = false;
function send(frame) {
  if (process.connected) process.send({ ...base, ...frame });
}
process.on('message', (frame) => {
  if (!frame || frame.event !== 'HEALTH_PROBE' || stopped) return;
  const result = {
    event: 'HEALTH_RESULT', challenge: frame.challenge, healthy: true,
  };
  if (mode === 'probe-unresponsive') return;
  if (mode === 'probe-unhealthy') result.healthy = false;
  if (mode === 'probe-forged') result.challenge = 'a'.repeat(32);
  if (mode === 'probe-extra-field') result.untrusted = 'payload';
  const deliver = () => send(result);
  if (mode === 'probe-late') setTimeout(deliver, 135);
  else if (mode === 'probe-stopping') setTimeout(deliver, 160);
  else deliver();
});
process.on('SIGTERM', () => {
  stopped = true;
  send({ event: 'TERMINAL', state: 'STOPPED', hostStopped: true });
  setTimeout(() => process.exit(0), 8);
});
send({ event: 'READY', state: 'RUNNING' });
if (mode === 'probe-unsolicited') {
  setTimeout(() => send({ event: 'HEALTH_RESULT', challenge: 'b'.repeat(32),
    healthy: true }), 35);
}
