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
const { createGuardianLocalJournalBudget } =
  require('./guardian-local-journal-budget.cjs');
const { createGuardianLocalStoragePressure } =
  require('./guardian-local-storage-pressure.cjs');
const { createGuardianLocalTerminalStorageCorrelation } =
  require('./guardian-local-terminal-storage-correlation.cjs');
const { createGuardianOfflineIncidentBrief } =
  require('./guardian-local-offline-incident-brief.cjs');
const { createGuardianLocalLedgerAudit } =
  require('./guardian-local-event-ledger-audit.cjs');
const { createGuardianCaseworkDiagnostics } =
  require('./guardian-local-casework-diagnostics.cjs');
const { createGuardianCaseworkGenerationAssessment } =
  require('./guardian-local-casework-generation-assessment.cjs');

const FIELDS = new Set(['cwd', 'entrypoint', 'directory', 'fileName',
  'startupTimeoutMs', 'shutdownTimeoutMs', 'healthProbeTimeoutMs',
  'maxJournalBytes', 'healthObservationMaxAgeMs',
  'caseworkDirectory', 'caseworkFileName']);

function createGuardianLocalOperatorSession(options) {
  if (!options || typeof options !== 'object' ||
      Array.isArray(options) ||
      Object.keys(options).some((name) => !FIELDS.has(name))) {
    throw new Error('GUARDIAN_LOCAL_OPERATOR_SESSION_INVALID');
  }
  if ((options.caseworkDirectory === undefined) !==
      (options.caseworkFileName === undefined)) {
    throw new Error('GUARDIAN_LOCAL_CASEWORK_SCOPE_INVALID');
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
    // Each launched generation is durable before its child exists.
    onLaunch: journal.recordLaunch,
    // Only a V2 READY verified by the owned parent may mark local liveness.
    onReady: journal.recordReady,
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
  const journalBudget = createGuardianLocalJournalBudget({
    controller, directory: options.directory, fileName: options.fileName,
    ...(options.maxJournalBytes === undefined ? {} :
      { maxBytes: options.maxJournalBytes }),
  });
  const storagePressure = createGuardianLocalStoragePressure({
    controller, directory: options.directory, journalBudget,
  });
  const terminalStorageCorrelation =
    createGuardianLocalTerminalStorageCorrelation({
      controller, terminalPersistence, storagePressure,
    });

  // These two capabilities MUST NOT be composed into a single Operator
  // object. An Operator read cannot call start(), stop(), reset() or touch D1.
  const owner = Object.freeze({
    start: () => controller.start(),
    stop: () => controller.stop(),
    status: () => controller.status(),
  });
  const readOnlyCore = Object.freeze({
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
    assessJournalBudget: () => journalBudget.assess(),
    assessJournalStorage: () => storagePressure.assess(),
    assessTerminalStorage: () => terminalStorageCorrelation.assess(),
  });
  // G37 integrates independent existing offline consumers only AFTER the
  // Generation V2 journal+ledger protected read contract is installed.
  // Construction is inert; no capture, child control or disk write here.
  const offlineBrief = createGuardianOfflineIncidentBrief({
    operator: readOnlyCore, limit: 5, maxCaptureMs: 1000,
  });
  const completeLedgerAudit = createGuardianLocalLedgerAudit({
    operator: readOnlyCore, pageSize: 50, maxCaptureMs: 5000,
  });
  const caseworkAssessment = options.caseworkDirectory === undefined ? null :
    createGuardianCaseworkGenerationAssessment({
      caseworkDiagnostics:createGuardianCaseworkDiagnostics({
        directory:options.caseworkDirectory,fileName:options.caseworkFileName,
      }),
      operator:Object.freeze({
        assessRuntime:readOnlyCore.assessRuntime,
        captureOfflineIncidentBrief:()=>offlineBrief.capture(),
        auditCompleteEventLedger:()=>completeLedgerAudit.capture(),
      }),
    });
  const operator = Object.freeze({
    ...readOnlyCore,
    captureOfflineIncidentBrief: () => offlineBrief.capture(),
    auditCompleteEventLedger: () => completeLedgerAudit.capture(),
    ...(caseworkAssessment ? {
      assessCaseworkGenerationEvidence:()=>caseworkAssessment.assess(),
    } : {}),
  });
  return Object.freeze({ owner, operator });
}
module.exports = { createGuardianLocalOperatorSession };
