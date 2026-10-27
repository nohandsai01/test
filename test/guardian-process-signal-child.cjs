'use strict';
// Child process fixture: real local Node SIGTERM/SIGINT, loopback only.
// It starts no real Guardian App and never calls process.exit/kill.
const http = require('node:http');
const { createGuardianProcessSupervisor } =
  require('../merge-gate-install/guardian-candidate/guardian-process-supervisor.cjs');

const local = http.createServer((_, res) =>
  res.end(JSON.stringify({ status: 'SOURCE_ONLY_HOLD' })));
let state = 'CREATED';
const host = {
  async start() {
    await new Promise((resolve) => local.listen(0, '127.0.0.1', resolve));
    state = 'RUNNING';
  },
  async stop() {
    await new Promise((resolve) => local.close(resolve));
    state = 'STOPPED';
  },
  status() {
    return { state, activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED' };
  },
};
const supervisor = createGuardianProcessSupervisor({
  host,
  stopDeadlineMs: 1500,
  onTerminal: (receipt) => {
    process.stdout.write('TERMINAL:' + JSON.stringify(receipt) + '\n');
  },
});
supervisor.start().then(
  () => { process.stdout.write('READY\n'); },
  (error) => { process.stderr.write('FAILED:' + error.code + '\n'); },
);
