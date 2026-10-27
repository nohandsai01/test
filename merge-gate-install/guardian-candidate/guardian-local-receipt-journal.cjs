/**
 * Owner-controlled, append-only local lifecycle evidence.
 *
 * No filesystem write at import or construction. Terminal callback is
 * synchronous so storage failure makes the parent Controller fail closed.
 * Only allowlisted primitives are recorded; never serialized Host objects,
 * tokens, keys, D1 records, arbitrary exception messages or provider blobs.
 *
 * G27-G30: a receipt bound to a process generation is written as
 * schemaVersion 2. recordLaunch() appends that generation to a sibling
 * owner-only ledger BEFORE spawn, so a parent crash leaves a launched
 * generation without a terminal receipt: durable, never auto-cleared.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const FIELDS = new Set(['directory', 'fileName', 'maxBytes']);
const ERROR_CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const FILE_NAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const GENERATION = /^[0-9a-f]{32}$/;
const MAX_RECORD_BYTES = 512;
const LEGACY_KEYS = Object.freeze(['state', 'errorCode', 'hostStopped',
  'activationAllowed', 'releaseAuthority', 'automaticRestartAllowed']);
const BOUND_KEYS = Object.freeze([...LEGACY_KEYS, 'generationId']);
const LAUNCH_KEYS = Object.freeze(['generationId', 'activationAllowed',
  'releaseAuthority']);

function code(message) {
  const err = new Error(message);
  err.code = message;
  return err;
}
// The ledger name is derived, never caller-selected, and deliberately does
// not match the journal FILE_NAME pattern so one can never be read as the other.
function generationLedgerName(fileName) {
  return fileName.replace(/\.jsonl$/, '.generations.jsonl');
}
function exactKeys(value, keys) {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((field) => Object.hasOwn(value, field));
}

// Volatile same-process witness only. A launch is marked active AFTER its
// durable ledger append; terminal attempts remove it even on failed journal
// writes. This is not an OS attestation or a cross-process liveness lease.
const activeByJournal = new Map();
function localWitnessKey(directory, filename) {
  return path.join(directory, filename);
}
function observeLocalActiveGenerations(directory, fileName) {
  const active = activeByJournal.get(localWitnessKey(directory, fileName));
  return Object.freeze(active ? [...active] : []);
}
function createGuardianLocalReceiptJournal(options) {
  if (!options || typeof options !== 'object' ||
      Array.isArray(options) ||
      Object.keys(options).some((field) => !FIELDS.has(field)) ||
      typeof options.directory !== 'string' ||
      !path.isAbsolute(options.directory) ||
      !FILE_NAME.test(options.fileName || '')) {
    throw code('GUARDIAN_JOURNAL_CONFIG_INVALID');
  }
  const maxBytes = options.maxBytes ?? 1_048_576;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024 ||
      maxBytes > 10_485_760) {
    throw code('GUARDIAN_JOURNAL_CONFIG_INVALID');
  }
  let directory;
  try {
    directory = fs.realpathSync(options.directory);
    const stat = fs.statSync(directory);
    if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
      throw new Error('unsafe evidence directory');
    }
  } catch (_) { throw code('GUARDIAN_JOURNAL_DIRECTORY_UNVERIFIED'); }

  const target = path.join(directory, options.fileName);
  const ledger = path.join(directory, generationLedgerName(options.fileName));
  const witnessKey = localWitnessKey(directory, options.fileName);
  const pendingLaunches = new Set();
  function markActive(id) {
    let active = activeByJournal.get(witnessKey);
    if (!active) {
      active = new Set();
      activeByJournal.set(witnessKey, active);
    }
    active.add(id);
  }
  function retire(id) {
    const active = activeByJournal.get(witnessKey);
    if (!active) return;
    active.delete(id);
    if (active.size === 0) activeByJournal.delete(witnessKey);
  }
  const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND |
    fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0);
  function write(file, data) {
    let fd;
    try {
      fd = fs.openSync(file, flags, 0o600);
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > maxBytes - data.length ||
          (stat.mode & 0o077) !== 0 ||
          (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
        throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
      }
      if (fs.writeSync(fd, data, 0, data.length) !== data.length) {
        throw code('GUARDIAN_JOURNAL_WRITE_UNVERIFIED');
      }
      fs.fsyncSync(fd);
    } catch (_) {
      throw code('GUARDIAN_JOURNAL_WRITE_FAILED');
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }
  function append(receipt) {
    // A receipt without generationId is a legacy, unbound v1 receipt: it
    // remains readable history but can never close a launched generation.
    const bound = exactKeys(receipt, BOUND_KEYS);
    if (!(bound || exactKeys(receipt, LEGACY_KEYS)) ||
        (bound && !(receipt.generationId === null ||
          (typeof receipt.generationId === 'string' &&
           GENERATION.test(receipt.generationId)))) ||
        !['STOPPED', 'FAILED'].includes(receipt.state) ||
        !(receipt.errorCode === null ||
          (typeof receipt.errorCode === 'string' && ERROR_CODE.test(receipt.errorCode))) ||
        receipt.hostStopped !== (receipt.state === 'STOPPED') ||
        receipt.activationAllowed !== false ||
        receipt.releaseAuthority !== 'NOT_ISSUED' ||
        receipt.automaticRestartAllowed !== false) {
      throw code('GUARDIAN_JOURNAL_RECEIPT_INVALID');
    }
    const data = Buffer.from(JSON.stringify({
      schemaVersion: bound ? 2 : 1, eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      ...(bound ? { generationId: receipt.generationId } : {}),
      state: receipt.state, errorCode: receipt.errorCode,
      hostStopped: receipt.hostStopped,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    }) + '\n');
    if (data.length > MAX_RECORD_BYTES) {
      throw code('GUARDIAN_JOURNAL_RECEIPT_INVALID');
    }
    // A completed/failed child is no longer a live witness even when
    // writing its terminal record fails. The missing terminal will then
    // remain a P1 owner-reconciliation HOLD.
    if (bound && receipt.generationId !== null) {
      pendingLaunches.delete(receipt.generationId);
      retire(receipt.generationId);
    }
    write(target, data);
    return Object.freeze({ persisted: true,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
  }
  // Synchronous, so the Controller refuses to spawn when it cannot persist.
  function recordLaunch(launch) {
    if (!exactKeys(launch, LAUNCH_KEYS) ||
        typeof launch.generationId !== 'string' ||
        !GENERATION.test(launch.generationId) ||
        launch.activationAllowed !== false ||
        launch.releaseAuthority !== 'NOT_ISSUED') {
      throw code('GUARDIAN_JOURNAL_LAUNCH_INVALID');
    }
    write(ledger, Buffer.from(JSON.stringify({
      schemaVersion: 1, kind: 'GUARDIAN_GENERATION_LAUNCH_V1',
      eventId: crypto.randomUUID(), timestamp: new Date().toISOString(),
      generationId: launch.generationId,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    }) + '\n'));
    pendingLaunches.add(launch.generationId);
    return Object.freeze({ persisted: true,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
  }
  // Unlike Launch, a verified parent-side V2 READY means this specific
  // owned child reached RUNNING. Keep only a volatile local witness and
  // refuse any READY not preceded by this instance's durable Launch.
  function recordReady(ready) {
    if (!exactKeys(ready, LAUNCH_KEYS) ||
        typeof ready.generationId !== 'string' ||
        !GENERATION.test(ready.generationId) ||
        ready.activationAllowed !== false ||
        ready.releaseAuthority !== 'NOT_ISSUED' ||
        !pendingLaunches.has(ready.generationId)) {
      throw code('GUARDIAN_JOURNAL_READY_INVALID');
    }
    pendingLaunches.delete(ready.generationId);
    markActive(ready.generationId);
    return Object.freeze({ witnessed: true,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
  }
  return Object.freeze({ append, recordLaunch, recordReady });
}

module.exports = { createGuardianLocalReceiptJournal, generationLedgerName,
  observeLocalActiveGenerations };
