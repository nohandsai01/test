/**
 * Guardian G27D — owner-controlled offline handoff intake and rejection log.
 *
 * Only offline JSON text from an already-created incident bundle is accepted.
 * Intake is NOT trust approval: even fully consistent data is QUARANTINED.
 * The owned append-only receipt journal stores no raw input or incident
 * events, and storage uncertainty always fails closed.
 *
 * Import and constructor do not write to disk or contact network/services.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  verifyBundle, verifyBundleHistory,
} = require('./guardian-local-offline-brief-verifier.cjs');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');

const CONFIG = new Set(['directory', 'fileName', 'maxJournalBytes']);
const FILENAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const MAX_INPUT_BYTES = 96_000;
const MAX_LINE_BYTES = 512;
const REASONS = new Set([
  'GUARDIAN_INTAKE_LOCAL_HISTORY_QUARANTINED',
  'GUARDIAN_INTAKE_BUNDLE_INVALID',
  'GUARDIAN_INTAKE_HISTORY_INCOMPLETE',
  'GUARDIAN_INTAKE_HISTORY_CONFLICT',
  'GUARDIAN_INTAKE_HISTORY_UNVERIFIED',
  'GUARDIAN_INTAKE_INPUT_INVALID',
  'GUARDIAN_INTAKE_STORAGE_UNVERIFIED',
]);

function failure(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
function localOutcome(decision, reason, digest = null, receiptId = null,
  receiptSha256 = null) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_LOCAL_OFFLINE_INTAKE_V1',
    status: 'SOURCE_ONLY_HOLD',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    decision, reason,
    bundleSha256: digest,
    receiptId, receiptSha256,
    custodyVerified: false,
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function validateDirectory(directory) {
  try {
    const actual = fs.realpathSync(directory);
    const st = fs.statSync(actual);
    if (!st.isDirectory() || (st.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' && st.uid !== process.getuid())) {
      return null;
    }
    return Object.freeze({
      path: actual, dev: st.dev, ino: st.ino,
    });
  } catch (_) { return null; }
}
function mapHistoryReason(reason) {
  switch (reason) {
    case 'GUARDIAN_BRIEF_CONTINUITY_INCOMPLETE_HISTORY':
      return 'GUARDIAN_INTAKE_HISTORY_INCOMPLETE';
    case 'GUARDIAN_BRIEF_CONTINUITY_CONFLICT':
      return 'GUARDIAN_INTAKE_HISTORY_CONFLICT';
    default:
      return 'GUARDIAN_INTAKE_HISTORY_UNVERIFIED';
  }
}

function createGuardianOfflineIntake(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config) ||
      Reflect.ownKeys(config).some((key) => typeof key !== 'string' ||
        !CONFIG.has(key)) ||
      typeof config.directory !== 'string' ||
      !path.isAbsolute(config.directory) ||
      typeof config.fileName !== 'string' ||
      !FILENAME.test(config.fileName)) {
    throw failure('GUARDIAN_INTAKE_CONFIG_INVALID');
  }
  const limit = config.maxJournalBytes ?? 1_048_576;
  if (!Number.isSafeInteger(limit) || limit < 1024 ||
      limit > 10_485_760) throw failure('GUARDIAN_INTAKE_CONFIG_INVALID');
  const pinned = validateDirectory(config.directory);
  if (!pinned) throw failure('GUARDIAN_INTAKE_DIRECTORY_UNVERIFIED');
  const filename = path.join(pinned.path, config.fileName);
  const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND |
    fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0) |
    (fs.constants.O_CLOEXEC ?? 0);

  function receive(input) {
    let decision = 'REJECTED';
    let reason = 'GUARDIAN_INTAKE_INPUT_INVALID';
    let bundleSha256 = null;
    try {
      // The handoff boundary is a UTF-8 JSON string only. Do not accept a
      // mutable object, stream, Buffer, arbitrary iterable or provider Proxy.
      if (typeof input === 'string') {
        const bytes = Buffer.from(input, 'utf8');
        if (bytes.length > 0 && bytes.length <= MAX_INPUT_BYTES &&
            bytes.toString('utf8') === input) {
          // Syntactically malformed, duplicate-key, invalid UTF-8 or
          // trailing-content input is different from a parsable bundle
          // whose own checksum, fields or history are unverified.
          parseUniqueKeySourceLock(bytes);
          const bundle = verifyBundle(input);
          if (bundle.comparison !== 'MATCH_LOCAL_CHECKSUM_ONLY') {
            reason = 'GUARDIAN_INTAKE_BUNDLE_INVALID';
          } else {
            bundleSha256 = bundle.bundleSha256;
            const history = verifyBundleHistory(input);
            if (history.comparison === 'LOCAL_STRUCTURAL_OBSERVATION_ONLY' &&
                history.bundleSha256 === bundleSha256) {
              decision = 'QUARANTINED';
              reason = 'GUARDIAN_INTAKE_LOCAL_HISTORY_QUARANTINED';
            } else {
              reason = mapHistoryReason(history.reason);
            }
          }
        }
      }
    } catch (_) {
      decision = 'REJECTED';
      reason = 'GUARDIAN_INTAKE_INPUT_INVALID';
      bundleSha256 = null;
    }

    // The receipt is deliberately less detailed than the supplied evidence.
    // We hash no unknown/oversized rejection input and never record raw JSON.
    const receiptId = crypto.randomUUID();
    const entry = Object.freeze({
      schemaVersion: 1,
      kind: 'GUARDIAN_LOCAL_OFFLINE_INTAKE_RECORD_V1',
      receiptId, timestamp: new Date().toISOString(),
      decision, reason, bundleSha256,
      custodyVerified: false,
      liveness: 'NOT_PROVEN',
      automaticRestartAllowed: false,
      activationAllowed: false,
      releaseAuthority: 'NOT_ISSUED',
    });
    if (!REASONS.has(reason)) {
      return localOutcome('REJECTED', 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED');
    }
    const serialized = Buffer.from(JSON.stringify(entry) + '\n');
    if (serialized.length > MAX_LINE_BYTES) {
      return localOutcome('REJECTED', 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED');
    }
    let fd;
    try {
      const current = validateDirectory(config.directory);
      if (!current || current.path !== pinned.path ||
          current.dev !== pinned.dev || current.ino !== pinned.ino) {
        throw failure('GUARDIAN_INTAKE_DIRECTORY_CHANGED');
      }
      fd = fs.openSync(filename, flags, 0o600);
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 ||
          (before.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' &&
           before.uid !== process.getuid()) ||
          before.size > limit - serialized.length) {
        throw failure('GUARDIAN_INTAKE_JOURNAL_UNVERIFIED');
      }
      const written = fs.writeSync(fd, serialized, 0, serialized.length);
      if (written !== serialized.length) {
        throw failure('GUARDIAN_INTAKE_SHORT_WRITE');
      }
      fs.fsyncSync(fd);
      const after = fs.fstatSync(fd);
      if (after.dev !== before.dev || after.ino !== before.ino ||
          after.size < before.size + serialized.length) {
        throw failure('GUARDIAN_INTAKE_WRITE_UNVERIFIED');
      }
    } catch (_) {
      return localOutcome('REJECTED', 'GUARDIAN_INTAKE_STORAGE_UNVERIFIED');
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch (_) {}
      }
    }
    const receiptSha256 = crypto.createHash('sha256')
      .update(serialized).digest('hex');
    return localOutcome(decision, reason, bundleSha256, receiptId, receiptSha256);
  }
  return Object.freeze({ receive });
}

module.exports = { createGuardianOfflineIntake };
