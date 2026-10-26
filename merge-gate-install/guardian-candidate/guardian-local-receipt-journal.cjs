/**
 * Owner-controlled, append-only local lifecycle evidence.
 *
 * No filesystem write at import or construction. Terminal callback is
 * synchronous so storage failure makes the parent Controller fail closed.
 * Only allowlisted primitives are recorded; never serialized Host objects,
 * tokens, keys, D1 records, arbitrary exception messages or provider blobs.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const FIELDS = new Set(['directory', 'fileName', 'maxBytes']);
const ERROR_CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const FILE_NAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const MAX_RECORD_BYTES = 512;

function code(message) {
  const err = new Error(message);
  err.code = message;
  return err;
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
  const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND |
    fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0);
  function append(receipt) {
    const keys = ['state', 'errorCode', 'hostStopped',
      'activationAllowed', 'releaseAuthority', 'automaticRestartAllowed'];
    if (!receipt || typeof receipt !== 'object' ||
        Array.isArray(receipt) ||
        Object.keys(receipt).length !== keys.length ||
        !keys.every((field) => Object.hasOwn(receipt, field)) ||
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
      schemaVersion: 1, eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      state: receipt.state, errorCode: receipt.errorCode,
      hostStopped: receipt.hostStopped,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED',
      automaticRestartAllowed: false,
    }) + '\n');
    if (data.length > MAX_RECORD_BYTES) {
      throw code('GUARDIAN_JOURNAL_RECEIPT_INVALID');
    }

    let fd;
    try {
      fd = fs.openSync(target, flags, 0o600);
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
    return Object.freeze({ persisted: true,
      activationAllowed: false, releaseAuthority: 'NOT_ISSUED' });
  }
  return Object.freeze({ append });
}

module.exports = { createGuardianLocalReceiptJournal };
