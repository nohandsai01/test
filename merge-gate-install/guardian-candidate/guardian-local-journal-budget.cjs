/**
 * Read-only local receipt-journal byte-limit diagnostics.
 *
 * This checks headroom against the configured MAX JOURNAL FILE SIZE, not
 * filesystem free space, durability, append readiness or writer identity.
 * A large remaining allowance is never permission to start/restart/release.
 * No writes, process control, active probes, D1 or GitHub Check authority.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const FILENAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const ERROR = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const STATES = new Set(['CREATED', 'STARTING', 'RUNNING', 'STOPPING',
  'STOPPED', 'FAILED']);
const REQUIRED_STATUS = Object.freeze([
  'state', 'errorCode', 'pid', 'activationAllowed', 'releaseAuthority',
  'automaticRestartAllowed',
]);
const MAX_RECEIPT_BYTES = 512;
const EARLY_WARNING_BYTES = MAX_RECEIPT_BYTES * 4;

function plainFields(value, required, optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    const desc = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(desc);
    if (keys.length < required.length ||
        keys.length > required.length + optional.length ||
        keys.some((k) => typeof k !== 'string' ||
          (!required.includes(k) && !optional.includes(k)))) return null;
    const out = Object.create(null);
    for (const k of required) {
      if (!Object.hasOwn(desc, k) || !Object.hasOwn(desc[k], 'value')) {
        return null;
      }
      out[k] = desc[k].value;
    }
    for (const k of optional) {
      if (Object.hasOwn(desc, k)) {
        if (!Object.hasOwn(desc[k], 'value')) return null;
        out[k] = desc[k].value;
      }
    }
    return out;
  } catch (_) { return null; }
}

function controllerSnapshot(controller) {
  try {
    const x = plainFields(controller.status(), REQUIRED_STATUS,
      ['generationId']);
    if (!x || !STATES.has(x.state) ||
        !(x.pid === null || (Number.isSafeInteger(x.pid) && x.pid > 0)) ||
        !(x.errorCode === null || (typeof x.errorCode === 'string' &&
          ERROR.test(x.errorCode))) ||
        !(x.generationId === undefined || x.generationId === null ||
          (typeof x.generationId === 'string' &&
           /^[0-9a-f]{32}$/.test(x.generationId))) ||
        x.activationAllowed !== false ||
        x.releaseAuthority !== 'NOT_ISSUED' ||
        x.automaticRestartAllowed !== false) return null;
    return Object.freeze({
      state: x.state, errorCode: x.errorCode, pid: x.pid,
      generationId: x.generationId ?? null,
    });
  } catch (_) { return null; }
}

function sameController(a, b) {
  return !!a && !!b && a.state === b.state &&
    a.errorCode === b.errorCode && a.pid === b.pid &&
    a.generationId === b.generationId;
}
function owned(stat, type) {
  try {
    return !!stat && (type === 'directory' ?
      stat.isDirectory() : stat.isFile()) &&
      !stat.isSymbolicLink() &&
      (stat.mode & 0o077n) === 0n &&
      (typeof process.getuid !== 'function' ||
        stat.uid === BigInt(process.getuid())) &&
      (type !== 'file' || stat.nlink === 1n);
  } catch (_) { return false; }
}
function sameIdentity(a, b) {
  return !!a && !!b &&
    a.dev === b.dev && a.ino === b.ino &&
    a.mode === b.mode && a.uid === b.uid &&
    a.nlink === b.nlink && a.size === b.size &&
    a.ctimeNs === b.ctimeNs && a.mtimeNs === b.mtimeNs;
}
function report(priority, classification, nextAction,
  controller = null, fileBytes = null, maxBytes = null) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_JOURNAL_BUDGET_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    priority, classification, nextAction,
    processState: controller?.state ?? 'UNVERIFIED',
    journalFileBytes: fileBytes,
    journalLimitBytes: maxBytes,
    journalLimitRemainingBytes: fileBytes === null ? null :
      maxBytes - fileBytes,
    maximumReceiptBytes: MAX_RECEIPT_BYTES,
    filesystemFreeSpace: 'NOT_VERIFIED',
    appendReadiness: 'NOT_PROVEN',
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function denied() {
  return report('P0', 'JOURNAL_BUDGET_UNVERIFIED',
    'OWNER_INVESTIGATE_LOCAL_JOURNAL');
}

function createGuardianLocalJournalBudget(options) {
  const x = plainFields(options, ['controller', 'directory', 'fileName'],
    ['maxBytes']);
  let controller;
  try {
    if (!x || typeof x.directory !== 'string' ||
        !path.isAbsolute(x.directory) ||
        path.resolve(x.directory) !== x.directory ||
        !FILENAME.test(x.fileName) ||
        typeof Object.getOwnPropertyDescriptor(x.controller,
          'status')?.value !== 'function') {
      throw new Error('invalid options');
    }
    controller = x.controller;
  } catch (_) {
    throw new Error('GUARDIAN_JOURNAL_BUDGET_CONFIG_INVALID');
  }
  const maxBytes = x.maxBytes ?? 1_048_576;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024 ||
      maxBytes > 10_485_760) {
    throw new Error('GUARDIAN_JOURNAL_BUDGET_CONFIG_INVALID');
  }
  const target = path.join(x.directory, x.fileName);
  // Fail closed rather than silently following symlinks on a platform
  // without the required no-follow and directory-open primitives.
  const supported = Number.isInteger(fs.constants.O_NOFOLLOW) &&
    Number.isInteger(fs.constants.O_DIRECTORY);

  function examine() {
    if (!supported) return null;
    let dirFd, fileFd, value = null;
    try {
      const dirBefore = fs.lstatSync(x.directory, { bigint: true });
      // macOS legitimately exposes /var through /private/var. Reject a
      // symlink at the directory itself (lstat), but bind the canonical
      // parent resolution between both independent observations.
      if (!owned(dirBefore, 'directory')) return null;
      const resolvedDir = fs.realpathSync(x.directory);
      dirFd = fs.openSync(x.directory, fs.constants.O_RDONLY |
        fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY);
      if (!sameIdentity(dirBefore,
        fs.fstatSync(dirFd, { bigint: true }))) return null;
      let before;
      try {
        before = fs.lstatSync(target, { bigint: true });
      } catch (error) {
        if (error?.code !== 'ENOENT') return null;
        before = null;
      }
      if (before === null) {
        // Absence is diagnostic, not evidence that a later creation
        // will succeed or that this path is writable.
        try {
          fs.lstatSync(target);
          return null;
        } catch (error) {
          if (error?.code !== 'ENOENT') return null;
        }
        value = { fileBytes: null, absent: true, dirStat: dirBefore,
          resolvedDir, fileStat: null };
      } else {
        if (!owned(before, 'file') ||
            before.size < 0n || before.size > BigInt(maxBytes)) return null;
        fileFd = fs.openSync(target, fs.constants.O_RDONLY |
          fs.constants.O_NOFOLLOW);
        const opened = fs.fstatSync(fileFd, { bigint: true });
        const after = fs.lstatSync(target, { bigint: true });
        if (!owned(opened, 'file') ||
            !sameIdentity(before, opened) ||
            !sameIdentity(before, after)) return null;
        value = { fileBytes: Number(before.size), absent: false,
          dirStat: dirBefore, resolvedDir, fileStat: before };
      }
      const dirAfter = fs.lstatSync(x.directory, { bigint: true });
      if (fs.realpathSync(x.directory) !== resolvedDir ||
          !owned(dirAfter, 'directory') ||
          !sameIdentity(dirBefore, dirAfter) ||
          !sameIdentity(dirBefore,
            fs.fstatSync(dirFd, { bigint: true }))) return null;
    } catch (_) {
      value = null;
    } finally {
      // Failed close also invalidates the observation.
      if (fileFd !== undefined) {
        try { fs.closeSync(fileFd); } catch (_) { value = null; }
      }
      if (dirFd !== undefined) {
        try { fs.closeSync(dirFd); } catch (_) { value = null; }
      }
    }
    return value;
  }

  function assess() {
    // Two complete filesystem observations separated by a controller read:
    // a concurrent append, file replacement, directory swap or PID/generation
    // transition cannot produce a report based on a single stale stat.
    const before = controllerSnapshot(controller);
    if (!before) return denied();
    const first = examine();
    const middle = controllerSnapshot(controller);
    if (!first || !sameController(before, middle)) return denied();
    const observed = examine();
    const after = controllerSnapshot(controller);
    if (!observed || !sameController(before, after) ||
        observed.absent !== first.absent ||
        observed.fileBytes !== first.fileBytes ||
        observed.resolvedDir !== first.resolvedDir ||
        !sameIdentity(observed.dirStat, first.dirStat) ||
        (!observed.absent &&
         !sameIdentity(observed.fileStat, first.fileStat))) return denied();

    if (observed.absent) {
      return before.state === 'CREATED' ?
        report('P2', 'JOURNAL_BASELINE_NOT_CREATED',
          'OWNER_VERIFY_LOCAL_JOURNAL_BEFORE_START', before) :
        denied();
    }
    const remaining = maxBytes - observed.fileBytes;
    if (remaining < MAX_RECEIPT_BYTES) {
      return report('P1', 'JOURNAL_LIMIT_AT_RISK',
        'OWNER_REVIEW_JOURNAL_LIMIT', before,
        observed.fileBytes, maxBytes);
    }
    if (remaining < EARLY_WARNING_BYTES) {
      return report('P2', 'JOURNAL_LIMIT_NEAR',
        'OWNER_PLAN_JOURNAL_RETENTION', before,
        observed.fileBytes, maxBytes);
    }
    return report('P3', 'JOURNAL_FILE_LIMIT_HEADROOM_ONLY',
      'OWNER_CONTINUE_MANUAL_HOLD', before,
      observed.fileBytes, maxBytes);
  }
  return Object.freeze({ assess });
}

module.exports = { createGuardianLocalJournalBudget };
