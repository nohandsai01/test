/**
 * G32: passive, ephemeral baseline witness for the local generation pair.
 *
 * This is NOT a trusted external anchor. Its first reading is always
 * UNANCHORED; only later same-observer changes can be detected. No writes,
 * keys, process controls, GitHub/D1 traffic or automatic HOLD release.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createGuardianLocalDiagnostics } = require('./guardian-local-diagnostics.cjs');
const { generationLedgerName } = require('./guardian-local-receipt-journal.cjs');

const FILE = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const CONFIG = Object.freeze(['directory', 'fileName', 'maxBytes']);
const TRUSTABLE_REASONS = new Set([
  'GUARDIAN_DIAGNOSTICS_CLEAN_STOP',
  'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED',
  'GUARDIAN_DIAGNOSTICS_GENERATION_UNTERMINATED',
  'GUARDIAN_DIAGNOSTICS_CONCURRENT_GENERATION_OBSERVED',
  'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE',
]);
const LIMIT = 10_485_760;

function copyConfig(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some((k) => typeof k !== 'string' || !CONFIG.includes(k))) return null;
    const desc = Object.getOwnPropertyDescriptors(value);
    const out = {};
    for (const k of keys) {
      if (!desc[k] || !Object.hasOwn(desc[k], 'value') ||
          desc[k].enumerable !== true) return null;
      out[k] = desc[k].value;
    }
    return Object.freeze(out);
  } catch (_) { return null; }
}
function sum(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function sameFile(a, b) {
  if (a?.state !== b?.state) return false;
  if (a.state === 'ABSENT') return true;
  return a.state === 'PRESENT' &&
    a.dev === b.dev && a.ino === b.ino &&
    a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs &&
    a.size === b.size && a.bytes.equals(b.bytes);
}
function report(reason, journal = null, ledger = null, sequence = 0) {
  const compatible = reason === 'GUARDIAN_BASELINE_UNANCHORED_FIRST_PAIR' ||
    reason === 'GUARDIAN_BASELINE_EPHEMERAL_APPEND_OBSERVED';
  return Object.freeze({
    schemaVersion: 1, kind: 'GUARDIAN_LOCAL_GENERATION_BASELINE_V1',
    authority: 'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status: 'SOURCE_ONLY_HOLD',
    comparison: compatible ? 'LOCAL_MEMORY_ONLY' : 'NOT_VERIFIED',
    reason, observationSequence: sequence,
    journalSha256: compatible ? sum(journal.bytes) : null,
    ledgerSha256: compatible ? sum(ledger.bytes) : null,
    journalBytes: compatible ? journal.size : 0,
    ledgerBytes: compatible ? ledger.size : 0,
    externalAnchorVerified: false, custodyVerified: false,
    historicalCompletenessVerified: false, liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false, activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function createGuardianLocalBaselineWitness(options) {
  const config = copyConfig(options);
  if (!config || typeof config.directory !== 'string' ||
      !path.isAbsolute(config.directory) ||
      typeof config.fileName !== 'string' || !FILE.test(config.fileName)) {
    throw new Error('GUARDIAN_BASELINE_CONFIG_INVALID');
  }
  const max = config.maxBytes ?? 1_048_576;
  if (!Number.isSafeInteger(max) || max < 1024 || max > LIMIT) {
    throw new Error('GUARDIAN_BASELINE_CONFIG_INVALID');
  }
  let root, directoryIdentity;
  try {
    root = fs.realpathSync(config.directory);
    const st = fs.lstatSync(root);
    if (!st.isDirectory() || st.isSymbolicLink() ||
        (st.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' && st.uid !== process.getuid())) {
      throw new Error('unsafe');
    }
    directoryIdentity = Object.freeze({ dev: st.dev, ino: st.ino });
  } catch (_) { throw new Error('GUARDIAN_BASELINE_DIRECTORY_UNVERIFIED'); }
  const paths = Object.freeze([
    path.join(root, config.fileName),
    path.join(root, generationLedgerName(config.fileName)),
  ]);
  const controller = Object.freeze({ status: () => Object.freeze({
    state: 'CREATED', pid: null, errorCode: null, generationId: null,
    activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
    automaticRestartAllowed: false,
  }) });
  const diagnostics = createGuardianLocalDiagnostics({
    directory: root, fileName: config.fileName,
    maxBytes: max, controller,
  });
  function trustedDir() {
    try {
      const st = fs.lstatSync(root);
      return st.isDirectory() && !st.isSymbolicLink() &&
        st.dev === directoryIdentity.dev &&
        st.ino === directoryIdentity.ino &&
        (st.mode & 0o077) === 0 &&
        (typeof process.getuid !== 'function' || st.uid === process.getuid()) &&
        fs.realpathSync(config.directory) === root;
    } catch (_) { return false; }
  }
  function readOne(filename) {
    let fd;
    try {
      fd = fs.openSync(filename, fs.constants.O_RDONLY |
        (fs.constants.O_NOFOLLOW ?? 0));
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 ||
          before.size < 1 || before.size > max ||
          (before.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' &&
            before.uid !== process.getuid())) return null;
      const bytes = Buffer.alloc(before.size);
      let offset = 0;
      while (offset < bytes.length) {
        const n = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
        if (!Number.isSafeInteger(n) || n <= 0) return null;
        offset += n;
      }
      const after = fs.fstatSync(fd), visible = fs.lstatSync(filename);
      if (before.dev !== after.dev || before.ino !== after.ino ||
          before.size !== after.size ||
          before.mtimeMs !== after.mtimeMs ||
          before.ctimeMs !== after.ctimeMs ||
          before.dev !== visible.dev || before.ino !== visible.ino ||
          visible.isSymbolicLink() || visible.nlink !== 1 ||
          (visible.mode & 0o077) !== 0 ||
          bytes.at(-1) !== 10 ||
          !Buffer.from(bytes.toString('utf8'), 'utf8').equals(bytes)) return null;
      return Object.freeze({
        state: 'PRESENT', dev: before.dev, ino: before.ino,
        mtimeMs: before.mtimeMs, ctimeMs: before.ctimeMs,
        size: before.size, bytes,
      });
    } catch (error) {
      return error?.code === 'ENOENT' ?
        Object.freeze({ state: 'ABSENT' }) : null;
    } finally {
      if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) {} }
    }
  }

  let previous = null, seq = 0, latched = null;
  function inspect() {
    if (latched) return report(latched, null, null, seq);
    if (!trustedDir()) {
      latched = 'GUARDIAN_BASELINE_DIRECTORY_UNVERIFIED';
      return report(latched, null, null, seq);
    }
    const a = paths.map(readOne);
    if (a.some(x => x === null)) {
      latched = 'GUARDIAN_BASELINE_PAIR_UNVERIFIED';
      return report(latched, null, null, seq);
    }
    if (a.every(x => x.state === 'ABSENT')) {
      if (previous) {
        latched = 'GUARDIAN_BASELINE_BOTH_REMOVED_AFTER_OBSERVATION';
        return report(latched, null, null, seq);
      }
      return report('GUARDIAN_BASELINE_UNATTESTED_DUAL_ABSENCE');
    }
    if (a.some(x => x.state === 'ABSENT')) {
      if (previous) latched = 'GUARDIAN_BASELINE_PARTIAL_REMOVAL';
      return report(latched ?? 'GUARDIAN_BASELINE_PAIR_INCOMPLETE');
    }
    const diagnostic = diagnostics.inspect();
    if (!TRUSTABLE_REASONS.has(diagnostic.reason) ||
        diagnostic.journalSha256 !== sum(a[0].bytes)) {
      // Preserve the already observed G31 read-race distinction without
      // retrying or losing the permanent fail-closed latch.
      latched = diagnostic.reason ===
        'GUARDIAN_DIAGNOSTICS_PAIR_CHANGED_DURING_READ' ?
        'GUARDIAN_BASELINE_PAIR_CHANGED_DURING_READ' :
        'GUARDIAN_BASELINE_RECONCILIATION_UNVERIFIED';
      return report(latched, null, null, seq);
    }
    const b = paths.map(readOne);
    if (!trustedDir() || b.some((x, i) => !sameFile(a[i], x))) {
      latched = 'GUARDIAN_BASELINE_PAIR_CHANGED_DURING_READ';
      return report(latched, null, null, seq);
    }
    if (previous) {
      for (let i=0; i<2; i++) {
        const before = previous[i], current = b[i];
        if (current.dev !== before.dev || current.ino !== before.ino ||
            current.size < before.size ||
            !current.bytes.subarray(0, before.size).equals(before.bytes)) {
          latched = 'GUARDIAN_BASELINE_CONTINUITY_BROKEN';
          return report(latched, null, null, seq);
        }
      }
    }
    previous = b;
    seq++;
    return report(seq === 1 ? 'GUARDIAN_BASELINE_UNANCHORED_FIRST_PAIR' :
      'GUARDIAN_BASELINE_EPHEMERAL_APPEND_OBSERVED', b[0], b[1], seq);
  }
  return Object.freeze({ inspect });
}
module.exports = { createGuardianLocalBaselineWitness };
