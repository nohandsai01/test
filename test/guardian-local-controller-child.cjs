'use strict';
// Source-only child fixture for the local process-controller negative tests.
// The filename selects an offline scenario. No keys, network egress or D1.
const http = require('node:http');
const path = require('node:path');
const scenario = path.basename(__filename, '.cjs');
const protocol = 'NOHANDS_GUARDIAN_CHILD_V1';
const loopback = http.createServer((_, res) => res.end('SOURCE_ONLY_HOLD'));
const report = (event, details) => {
  if (process.connected) process.send({ protocol, event, ...details });
};
const ready = () => report('READY', {
  state: 'RUNNING', activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED',
});
const terminal = (valid = true) => report('TERMINAL', {
  state: valid ? 'STOPPED' : 'FAILED',
  hostStopped: valid,
  activationAllowed: false,
  releaseAuthority: 'NOT_ISSUED',
});
if (scenario === 'premature-exit') {
  process.exitCode = 7;
  if (process.connected) process.disconnect();
} else if (scenario === 'stalled-start') {
  setInterval(() => {}, 1000);
} else {
  loopback.listen(0, '127.0.0.1', () => {
    if (scenario === 'malformed-ready' ||
        (scenario === 'env-isolation' &&
         (process.env.NOHANDS_TEST_SECRET !== undefined ||
          process.env.NODE_OPTIONS !== undefined))) {
      report('READY', { state: 'RUNNING',
        activationAllowed: true, releaseAuthority: 'ISSUED' });
    } else {
      ready();
      if (scenario === 'duplicate-ready') ready();
      if (scenario === 'unexpected-exit') {
        setTimeout(() => {
          process.exitCode = 9;
          loopback.close(() => { if (process.connected) process.disconnect(); });
        }, 25);
      }
    }
  });
  process.on('SIGTERM', () => {
    if (scenario === 'ignore-stop') return;
    if (scenario === 'bad-terminal') terminal(false);
    else terminal();
    loopback.close(() => { if (process.connected) process.disconnect(); });
  });
}
