'use strict';
// G29 helper (not a test entry): a real Owner parent process that records a
// launch, starts its owned child and then dies abruptly with SIGKILL, so it
// can never write a terminal receipt. Source-only; no keys, D1 or network.
const { createGuardianLocalOperatorSession } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');

const [directory, fileName, entrypoint] = process.argv.slice(2);
const session = createGuardianLocalOperatorSession({
  directory, fileName, entrypoint,
  cwd: require('node:path').dirname(entrypoint),
  startupTimeoutMs: 4000, shutdownTimeoutMs: 600,
});
session.owner.start().then((ready) => {
  process.stdout.write('STARTED ' + ready.generationId + '\n', () => {
    process.kill(process.pid, 'SIGKILL');
  });
}, (error) => {
  process.stdout.write('FAILED ' + error.code + '\n');
  process.exitCode = 2;
});
