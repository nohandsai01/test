/**
 * Explicit, inert assembly of the existing Guardian Protected Host with its
 * process lifecycle supervisor. This file is NOT an executable launcher.
 * A separately authorized owner/runtime must supply configuration and
 * explicitly call start(); import and construction perform no I/O.
 */
'use strict';

const { createGuardianProtectedHost } =
  require('./guardian-protected-host.cjs');
const { createGuardianProcessSupervisor } =
  require('./guardian-process-supervisor.cjs');

const ACCEPTED = new Set(['protectedHostConfig', 'onTerminal',
  'signalSource', 'stopDeadlineMs']);

function createGuardianHostProcessRunner(options) {
  if (!options || typeof options !== 'object' ||
      Array.isArray(options) ||
      Object.keys(options).some((key) => !ACCEPTED.has(key)) ||
      !options.protectedHostConfig ||
      typeof options.onTerminal !== 'function') {
    throw new Error('GUARDIAN_PROCESS_RUNNER_CONFIG_INVALID');
  }

  // This is intentionally a direct composition of existing independently
  // validated components, not a second configuration or permission system.
  // The Protected Host remains the authority for D1/GitHub preflight and
  // mode grants; the Supervisor owns only SIGTERM/SIGINT and shutdown receipts.
  const host = createGuardianProtectedHost(options.protectedHostConfig);
  const supervisor = createGuardianProcessSupervisor({
    host,
    onTerminal: options.onTerminal,
    ...(options.signalSource === undefined ? {} :
      { signalSource: options.signalSource }),
    ...(options.stopDeadlineMs === undefined ? {} :
      { stopDeadlineMs: options.stopDeadlineMs }),
  });

  // Do not expose Host secrets, raw configuration, D1 binding or Check writers.
  return Object.freeze({
    start: () => supervisor.start(),
    stop: () => supervisor.stop(),
    status: () => supervisor.status(),
  });
}

module.exports = { createGuardianHostProcessRunner };
