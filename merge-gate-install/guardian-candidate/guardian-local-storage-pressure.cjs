/**
 * Read-only local filesystem pressure observation for Guardian Operators.
 *
 * Combines the already-protected journal file-limit observation with bounded
 * filesystem statfs snapshots. This is local capacity telemetry, NEVER an
 * append guarantee, filesystem reservation, process attestation or authority.
 * No writes, child lifecycle, D1, credentials, or GitHub Check operations.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MIB = 1_048_576n;
const CRITICAL_BYTES = MIB;
const WARNING_BYTES = 8n * MIB;
const REPORT_CAP_MIB = 64n;
const STATES = new Set([
  'CREATED', 'STARTING', 'RUNNING', 'STOPPING', 'STOPPED', 'FAILED',
]);
const PRIORITIES = new Set(['P1', 'P2', 'P3']);
const REQUIRED_STATUS = [
  'state', 'errorCode', 'pid', 'activationAllowed',
  'releaseAuthority', 'automaticRestartAllowed',
];
const REQUIRED_BUDGET = [
  'schemaVersion', 'kind', 'authority', 'status', 'priority',
  'classification', 'nextAction', 'processState', 'journalFileBytes',
  'journalLimitBytes', 'journalLimitRemainingBytes',
  'maximumReceiptBytes', 'filesystemFreeSpace', 'appendReadiness',
  'liveness', 'manualInterventionRequired', 'automaticRestartAllowed',
  'activationAllowed', 'releaseAuthority',
];

function dataFields(value, required, optional = []) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    const desc = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(desc);
    if (keys.length < required.length ||
        keys.length > required.length + optional.length ||
        keys.some((key) => typeof key !== 'string' ||
          (!required.includes(key) && !optional.includes(key)))) {
      return null;
    }
    const result = Object.create(null);
    for (const key of required) {
      if (!Object.hasOwn(desc, key) ||
          !Object.hasOwn(desc[key], 'value')) return null;
      result[key] = desc[key].value;
    }
    for (const key of optional) {
      if (Object.hasOwn(desc, key)) {
        if (!Object.hasOwn(desc[key], 'value')) return null;
        result[key] = desc[key].value;
      }
    }
    return result;
  } catch (_) {
    return null;
  }
}

function statusSnapshot(controller) {
  try {
    const x = dataFields(controller.status(), REQUIRED_STATUS,
      ['generationId']);
    if (!x || !STATES.has(x.state) ||
        !(x.pid === null ||
          (Number.isSafeInteger(x.pid) && x.pid > 0)) ||
        !(x.errorCode === null ||
          (typeof x.errorCode === 'string' &&
           /^GUARDIAN_[A-Z0-9_]{1,100}$/.test(x.errorCode))) ||
        !(x.generationId == null ||
          (typeof x.generationId === 'string' &&
           /^[0-9a-f]{32}$/.test(x.generationId))) ||
        x.activationAllowed !== false ||
        x.automaticRestartAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED') return null;
    return Object.freeze({
      state: x.state, pid: x.pid, errorCode: x.errorCode,
      generationId: x.generationId ?? null,
    });
  } catch (_) {
    return null;
  }
}

function sameStatus(a, b) {
  return !!a && !!b && a.state === b.state && a.pid === b.pid &&
    a.errorCode === b.errorCode && a.generationId === b.generationId;
}

function budgetSnapshot(budget) {
  try {
    const x = dataFields(budget.assess(), REQUIRED_BUDGET);
    if (!x || x.schemaVersion !== 1 ||
        x.kind !== 'GUARDIAN_LOCAL_JOURNAL_BUDGET_V1' ||
        x.authority !== 'LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        x.status !== 'SOURCE_ONLY_HOLD' ||
        !PRIORITIES.has(x.priority) ||
        typeof x.classification !== 'string' ||
        !/^JOURNAL_[A-Z0-9_]{1,100}$/.test(x.classification) ||
        typeof x.nextAction !== 'string' ||
        !/^OWNER_[A-Z0-9_]{1,100}$/.test(x.nextAction) ||
        !STATES.has(x.processState) ||
        x.maximumReceiptBytes !== 512 ||
        x.filesystemFreeSpace !== 'NOT_VERIFIED' ||
        x.appendReadiness !== 'NOT_PROVEN' ||
        x.liveness !== 'NOT_PROVEN' ||
        x.manualInterventionRequired !== true ||
        x.activationAllowed !== false ||
        x.automaticRestartAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED') return null;
    const absent = x.journalFileBytes === null &&
      x.journalLimitBytes === null &&
      x.journalLimitRemainingBytes === null &&
      x.priority === 'P2' &&
      x.classification === 'JOURNAL_BASELINE_NOT_CREATED' &&
      x.processState === 'CREATED';
    const present = Number.isSafeInteger(x.journalFileBytes) &&
      x.journalFileBytes >= 0 &&
      Number.isSafeInteger(x.journalLimitBytes) &&
      x.journalLimitBytes >= 1024 && x.journalLimitBytes <= 10_485_760 &&
      Number.isSafeInteger(x.journalLimitRemainingBytes) &&
      x.journalLimitRemainingBytes ===
        x.journalLimitBytes - x.journalFileBytes &&
      x.journalLimitRemainingBytes >= 0;
    if (!absent && !present) return null;
    return Object.freeze({
      priority: x.priority, classification: x.classification,
      processState: x.processState,
      fileBytes: x.journalFileBytes,
      limitBytes: x.journalLimitBytes,
      remainingBytes: x.journalLimitRemainingBytes,
    });
  } catch (_) {
    return null;
  }
}

function sameBudget(a, b) {
  return !!a && !!b && a.priority === b.priority &&
    a.classification === b.classification &&
    a.processState === b.processState &&
    a.fileBytes === b.fileBytes && a.limitBytes === b.limitBytes &&
    a.remainingBytes === b.remainingBytes;
}

function ownedDirectory(s) {
  try {
    return !!s && s.isDirectory() && !s.isSymbolicLink() &&
      (s.mode & 0o077n) === 0n &&
      (typeof process.getuid !== 'function' ||
        s.uid === BigInt(process.getuid()));
  } catch (_) {
    return false;
  }
}
function sameDirectory(a, b) {
  return !!a && !!b && a.dev === b.dev && a.ino === b.ino &&
    a.mode === b.mode && a.uid === b.uid && a.nlink === b.nlink &&
    a.size === b.size && a.ctimeNs === b.ctimeNs &&
    a.mtimeNs === b.mtimeNs;
}

function observe(directory) {
  if (!Number.isInteger(fs.constants.O_NOFOLLOW) ||
      !Number.isInteger(fs.constants.O_DIRECTORY) ||
      typeof fs.statfsSync !== 'function') return null;
  let fd;
  let value = null;
  try {
    const initial = fs.lstatSync(directory, { bigint: true });
    if (!ownedDirectory(initial)) return null;
    const real = fs.realpathSync(directory);
    fd = fs.openSync(directory, fs.constants.O_RDONLY |
      fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    if (!sameDirectory(initial, fs.fstatSync(fd, { bigint: true }))) {
      return null;
    }
    const stat = fs.statfsSync(directory, { bigint: true });
    if (!stat || typeof stat.bsize !== 'bigint' ||
        typeof stat.blocks !== 'bigint' ||
        typeof stat.bfree !== 'bigint' ||
        typeof stat.bavail !== 'bigint' ||
        typeof stat.type !== 'bigint' ||
        stat.bsize <= 0n || stat.blocks < 0n ||
        stat.bfree < 0n || stat.bfree > stat.blocks ||
        stat.bavail < 0n || stat.bavail > stat.bfree) return null;
    const after = fs.lstatSync(directory, { bigint: true });
    if (!ownedDirectory(after) ||
        !sameDirectory(initial, after) ||
        !sameDirectory(initial, fs.fstatSync(fd, { bigint: true })) ||
        fs.realpathSync(directory) !== real) return null;
    value = {
      directory: initial, real, type: stat.type, blockSize: stat.bsize,
      available: stat.bavail * stat.bsize,
    };
  } catch (_) {
    return null;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) { value = null; }
    }
  }
  return value;
}

function report(priority, classification, nextAction,
  controller = null, budget = null, available = null) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_STORAGE_PRESSURE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    priority, classification, nextAction,
    processState: controller?.state ?? 'UNVERIFIED',
    journalBudgetPriority: budget?.priority ?? 'UNVERIFIED',
    // Saturated diagnostic bucket: 64 means "at least 64 MiB", not exact.
    filesystemAvailableMiBCappedAt64: available === null ?
      null : Number((available / MIB) > REPORT_CAP_MIB ?
        REPORT_CAP_MIB : (available / MIB)),
    filesystemFreeSpace: available === null ?
      'NOT_VERIFIED' : 'LOCAL_STATFS_SNAPSHOT_ONLY',
    filesystemReservation: 'NOT_PROVEN',
    appendReadiness: 'NOT_PROVEN',
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}

function denied() {
  return report('P0', 'STORAGE_PRESSURE_UNVERIFIED',
    'OWNER_INVESTIGATE_LOCAL_STORAGE');
}

function createGuardianLocalStoragePressure(options) {
  const x = dataFields(options,
    ['controller', 'directory', 'journalBudget']);
  try {
    if (!x || typeof x.directory !== 'string' ||
        !path.isAbsolute(x.directory) ||
        path.resolve(x.directory) !== x.directory ||
        typeof Object.getOwnPropertyDescriptor(x.controller,
          'status')?.value !== 'function' ||
        typeof Object.getOwnPropertyDescriptor(x.journalBudget,
          'assess')?.value !== 'function') {
      throw new Error('invalid');
    }
  } catch (_) {
    throw new Error('GUARDIAN_LOCAL_STORAGE_CONFIG_INVALID');
  }

  function assess() {
    const before = statusSnapshot(x.controller);
    if (!before) return denied();
    const initialBudget = budgetSnapshot(x.journalBudget);
    const initial = observe(x.directory);
    const middle = statusSnapshot(x.controller);
    if (!initialBudget || !initial ||
        initialBudget.processState !== before.state ||
        !sameStatus(before, middle)) return denied();

    const observed = observe(x.directory);
    const finalBudget = budgetSnapshot(x.journalBudget);
    const after = statusSnapshot(x.controller);
    if (!observed || !finalBudget ||
        !sameStatus(before, after) ||
        !sameBudget(initialBudget, finalBudget) ||
        !sameDirectory(initial.directory, observed.directory) ||
        initial.real !== observed.real ||
        initial.type !== observed.type ||
        initial.blockSize !== observed.blockSize) return denied();

    // The smaller free-space sample is conservative but remains an
    // unreserved, transient local filesystem observation.
    const available = initial.available < observed.available ?
      initial.available : observed.available;
    if (available < CRITICAL_BYTES) {
      return report('P1', 'FILESYSTEM_FREE_CAPACITY_CRITICAL',
        'OWNER_INVESTIGATE_LOCAL_STORAGE', before, finalBudget, available);
    }
    if (finalBudget.priority === 'P1') {
      return report('P1', 'JOURNAL_FILE_LIMIT_AT_RISK',
        'OWNER_REVIEW_JOURNAL_LIMIT', before, finalBudget, available);
    }
    if (available < WARNING_BYTES) {
      return report('P2', 'FILESYSTEM_FREE_CAPACITY_LOW',
        'OWNER_PLAN_LOCAL_STORAGE', before, finalBudget, available);
    }
    if (finalBudget.priority === 'P2') {
      return report('P2', 'JOURNAL_BUDGET_NEEDS_ATTENTION',
        'OWNER_REVIEW_JOURNAL_LIMIT', before, finalBudget, available);
    }
    return report('P3', 'LOCAL_STORAGE_HEADROOM_SNAPSHOT_ONLY',
      'OWNER_CONTINUE_MANUAL_HOLD', before, finalBudget, available);
  }
  return Object.freeze({ assess });
}

module.exports = { createGuardianLocalStoragePressure };
