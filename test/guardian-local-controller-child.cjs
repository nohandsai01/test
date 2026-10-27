'use strict';
// Source-only child fixture for the local process-controller negative tests.
// The filename selects an offline scenario. No keys, network egress or D1.
const http = require('node:http');
const path = require('node:path');
const scenario = path.basename(__filename, '.cjs');
const protocol = 'NOHANDS_GUARDIAN_CHILD_V2';
const foreign = 'f'.repeat(32);
const loopback = http.createServer((_, res) => res.end('SOURCE_ONLY_HOLD'));
let generation = null;
const report = (event, details) => {
  if (process.connected) process.send({ protocol, event, ...details });
};
const hello = () => report('HELLO', {
  activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
});
const ready = (id = generation) => report('READY', {
  generation: id, state: 'RUNNING', activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED',
});
const terminal = (valid = true, id = generation) => report('TERMINAL', {
  generation: id,
  state: valid ? 'STOPPED' : 'FAILED',
  hostStopped: valid,
  activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED',
});
function bound() {
  if (scenario === 'malformed-ready' ||
      (scenario === 'env-isolation' &&
       (process.env.NOHANDS_TEST_SECRET !== undefined ||
        process.env.NODE_OPTIONS !== undefined))) {
    report('READY', { generation, state: 'RUNNING',
      activationAllowed: true, releaseAuthority: 'ISSUED' });
    return;
  }
  if (scenario === 'wrong-generation-ready') {
    ready(foreign);
    return;
  }
  if (scenario === 'double-hello') {
    hello();
    return;
  }
  ready();
  if (scenario === 'duplicate-ready') ready();
  if (scenario === 'unexpected-exit') {
    setTimeout(() => {
      process.exitCode = 9;
      loopback.close(() => { if (process.connected) process.disconnect(); });
    }, 25);
  }
}
process.on('message', (frame) => {
  if (frame?.event !== 'BIND' || typeof frame.generation !== 'string') return;
  if (generation === null) {
    generation = frame.generation;
    bound();
  }
});
if (scenario === 'premature-exit') {
  process.exitCode = 7;
  if (process.connected) process.disconnect();
} else if (scenario === 'stalled-start') {
  setInterval(() => {}, 1000);
} else {
  if (scenario === 'orphan-exit') {
    // An orphaned child must not outlive its crashed Owner parent in CI.
    process.on('disconnect', () => {
      loopback.close();
      process.exitCode = 0;
    });
  }
  loopback.listen(0, '127.0.0.1', () => {
    if (scenario === 'unbound-ready') {
      // Never asks for a generation; guesses one instead.
      ready(foreign);
      return;
    }
    hello();
  });
  process.on('SIGTERM', () => {
    if (scenario === 'ignore-stop') return;
    if (scenario === 'bad-terminal') terminal(false);
    else if (scenario === 'foreign-terminal') terminal(true, foreign);
    else terminal();
    loopback.close(() => { if (process.connected) process.disconnect(); });
  });
}
