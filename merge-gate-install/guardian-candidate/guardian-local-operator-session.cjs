/**
 * Inert and strictly separated local Guardian lifecycle and diagnostics.
 *
 * Owner controls START/STOP, while the Operator receives a distinct
 * read-only inspect-only facade. No imports or constructors spawn a child,
 * bind a listener or read production credentials. Fail-closed journal writes
 * are synchronous, allowing the child controller to reject a false STOPPED.
 */
'use strict';

const { createGuardianLocalProcessController } =
  require('./guardian-local-process-controller.cjs');
const { createGuardianLocalReceiptJournal } =
  require('./guardian-local-receipt-journal.cjs');
const { createGuardianLocalDiagnostics } =
  require('./guardian-local-diagnostics.cjs');
const { createGuardianLocalEvidenceVerifier } =
  require('./guardian-local-evidence-verifier.cjs');
const { createGuardianLocalHealthObservation } =
  require('./guardian-local-health-observation.cjs');
const { createGuardianLocalRuntimeAssessment } =
  require('./guardian-local-runtime-assessment.cjs');
const { createGuardianLocalTerminalPersistence } =
  require('./guardian-local-terminal-persistence.cjs');

const FIELDS = new Set(['cwd', 'entrypoint', 'directory', 'fileName',
  'startupTimeoutMs', 'shutdownTimeoutMs', 'healthProbeTimeoutMs',
  'maxJournalBytes', 'healthObservationMaxAgeMs']);

function createGuardianLocalOperatorSession(options) {
  if (!options || typeof options !== 'object' ||
      Array.isArray(options) ||
      Object.keys(options).some((name) => !FIELDS.has(name))) {
    throw new Error('GUARDIAN_LOCAL_OPERATOR_SESSION_INVALID');
  }
  // All three components independently enforce immutable owner-approved
  // scopes, pinned entrypoint, directory/file protection and safe receipt
  // formats. No caller-supplied store or writer can bypass those checks.
  const journal = createGuardianLocalReceiptJournal({
    directory: options.directory,
    fileName: options.fileName,
    ...(options.maxJournalBytes === undefined ? {} :
      { maxBytes: options.maxJournalBytes }),
  });
  const controller = createGuardianLocalProcessController({
    cwd: options.cwd, entrypoint: options.entrypoint,
    onTerminal: journal.append,
    ...(options.startupTimeoutMs === undefined ? {} :
      { startupTimeoutMs: options.startupTimeoutMs }),
    ...(options.shutdownTimeoutMs === undefined ? {} :
      { shutdownTimeoutMs: options.shutdownTimeoutMs }),
    ...(options.healthProbeTimeoutMs === undefined ? {} :
      { healthProbeTimeoutMs: options.healthProbeTimeoutMs }),
  });
  const diagnostics = createGuardianLocalDiagnostics({
    controller, directory: options.directory,
    fileName: options.fileName,
    ...(options.maxJournalBytes === undefined ? {} :
      { maxBytes: options.maxJournalBytes }),
  });

  const evidenceVerifier = createGuardianLocalEvidenceVerifier({
    directory: options.directory,
    fileName: options.fileName,
    ...(options.maxJournalBytes === undefined ? {} :
      { maxBytes: options.maxJournalBytes }),
  });

  const healthObservation = createGuardianLocalHealthObservation({
    controller,
    ...(options.healthObservationMaxAgeMs === undefined ? {} :
      { maxAgeMs: options.healthObservationMaxAgeMs }),
  });
  const runtimeAssessment = createGuardianLocalRuntimeAssessment({
    controller, diagnostics, healthObservation,
  });
  const terminalPersistence = createGuardianLocalTerminalPersistence({
    controller, diagnostics,
  });

  // These two capabilities MUST NOT be composed into a single Operator
  // object. An Operator read cannot call start(), stop(), reset() or touch D1.
  const owner = Object.freeze({
    start: () => controller.start(),
    stop: () => controller.stop(),
    status: () => controller.status(),
  });
  const operator = Object.freeze({
    inspect: () => diagnostics.inspect(),
    recentEvents: (options) => diagnostics.recentEvents(options),
    incidentEvidence: (options) => diagnostics.incidentEvidence(options),
    verifyIncidentEvidence: (packet) => evidenceVerifier.verify(packet),
    observeLocalContinuity: () => evidenceVerifier.observeContinuity(),
    faultTriage: () => diagnostics.faultTriage(),
    probeRuntime: () => healthObservation.probe(),
    observeRuntimeHealth: () => healthObservation.observe(),
    assessRuntime: () => runtimeAssessment.assess(),
    diagnoseTerminalPersistence: () => terminalPersistence.diagnose(),
  });
  return Object.freeze({ owner, operator });
}
module.exports = { createGuardianLocalOperatorSession };
