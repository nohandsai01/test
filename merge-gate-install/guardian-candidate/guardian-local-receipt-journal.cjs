/**
 * Owner-controlled, append-only local lifecycle evidence.
 *
 * No filesystem write at import or construction. Terminal callback is
 * synchronous so storage failure makes the parent Controller fail closed.
 * Directory/file identity is rechecked before append and after fsync;
 * same-inode truncation/content drift is checked against a memory-only
 * high-watermark SHA-256 snapshot. No repair or historical attestation.
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
  const configuredDirectory = options.directory;
  let directory, directoryAnchor;
  try {
    directory = fs.realpathSync(configuredDirectory);
    directoryAnchor = fs.lstatSync(directory);
    if (!directoryAnchor.isDirectory() || directoryAnchor.isSymbolicLink() ||
        (directoryAnchor.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' &&
         directoryAnchor.uid !== process.getuid())) {
      throw new Error('unsafe evidence directory');
    }
  } catch (_) { throw code('GUARDIAN_JOURNAL_DIRECTORY_UNVERIFIED'); }

  const target = path.join(directory, options.fileName);
  const flags = fs.constants.O_RDWR | fs.constants.O_APPEND |
    fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0) |
    (fs.constants.O_NONBLOCK ?? 0);
  // In-memory identity guard; not a signed or persistent chain of custody.
  // Once this instance has appended, it may never silently start a new file.
  let committedSnapshot = null;
  function sameIdentity(a, b) {
    return a.dev === b.dev && a.ino === b.ino;
  }
  function trustedDirectory() {
    try {
      const st = fs.lstatSync(directory);
      return st.isDirectory() && !st.isSymbolicLink() &&
        sameIdentity(st, directoryAnchor) && (st.mode & 0o077) === 0 &&
        (typeof process.getuid !== 'function' ||
         st.uid === process.getuid()) &&
        fs.realpathSync(configuredDirectory) === directory;
    } catch (_) { return false; }
  }
  function trustedFile(fd) {
    if (!trustedDirectory()) throw code('GUARDIAN_JOURNAL_DIRECTORY_UNVERIFIED');
    const st = fs.fstatSync(fd);
    const visible = fs.lstatSync(target);
    if (!st.isFile() || !visible.isFile() || visible.isSymbolicLink() ||
        st.nlink !== 1 || visible.nlink !== 1 ||
        !sameIdentity(st, visible) ||
        (st.mode & 0o077) !== 0 || (visible.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' &&
          (st.uid !== process.getuid() || visible.uid !== process.getuid())) ||
        (committedSnapshot !== null &&
         !sameIdentity(st, committedSnapshot))) {
      throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
    }
    return st;
  }
  // Bounded, synchronous hash of the current fd. Non-atomic cross-process
  // mutations can still race the size and pathname checks.
  function fingerprint(fd, prefixBytes, fileBytes) {
    if (!Number.isSafeInteger(prefixBytes) || prefixBytes < 0 ||
        prefixBytes > maxBytes || !Number.isSafeInteger(fileBytes) ||
        fileBytes < prefixBytes || fileBytes > maxBytes ||
        trustedFile(fd).size !== fileBytes) {
      throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
    }
    const sha = crypto.createHash('sha256');
    const block = Buffer.alloc(64 * 1024);
    for (let offset = 0; offset < prefixBytes;) {
      const read = fs.readSync(fd, block, 0,
        Math.min(block.length, prefixBytes - offset), offset);
      if (read <= 0) throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
      sha.update(block.subarray(0, read));
      offset += read;
    }
    if (trustedFile(fd).size !== fileBytes) {
      throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
    }
    return sha.digest('hex');
  }
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
      if (!trustedDirectory()) {
        throw code('GUARDIAN_JOURNAL_DIRECTORY_UNVERIFIED');
      }
      // Do not recreate a file once this instance has recorded evidence.
      // In particular, deleting an existing journal must not reset history.
      if (committedSnapshot !== null) {
        const existing = fs.lstatSync(target);
        if (!existing.isFile() || existing.isSymbolicLink() ||
            !sameIdentity(existing, committedSnapshot)) {
          throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
        }
      }
      fd = fs.openSync(target, flags, 0o600);
      const stat = trustedFile(fd);
      if (stat.size > maxBytes - data.length) {
        throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
      }
      const previousDigest = fingerprint(fd, stat.size, stat.size);
      // Identity, size and newline checks permit complete-row truncation or
      // a same-inode same-length rewrite. Compare the last committed bytes.
      if (committedSnapshot !== null &&
          (stat.size !== committedSnapshot.size ||
           previousDigest !== committedSnapshot.sha256)) {
        throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
      }
      // Preserve a partial final record after an uncertain previous write.
      // Never silently concatenate a new valid receipt onto truncated JSONL.
      if (stat.size > 0) {
        const tail = Buffer.alloc(1);
        if (fs.readSync(fd, tail, 0, 1, stat.size - 1) !== 1 ||
            tail[0] !== 10) {
          throw code('GUARDIAN_JOURNAL_FILE_UNVERIFIED');
        }
      }
      // Recheck the pathname immediately before append; identity checks
      // remain best-effort and are not a transactional filesystem lock.
      trustedFile(fd);
      if (fs.writeSync(fd, data, 0, data.length) !== data.length) {
        throw code('GUARDIAN_JOURNAL_WRITE_UNVERIFIED');
      }
      fs.fsyncSync(fd);
      const after = trustedFile(fd);
      if (after.size !== stat.size + data.length ||
          !sameIdentity(after, stat)) {
        throw code('GUARDIAN_JOURNAL_WRITE_UNVERIFIED');
      }
      // Protect the old prefix against mutation between the first scan
      // and fsync; then snapshot the full committed journal for next time.
      if (fingerprint(fd, stat.size, after.size) !== previousDigest) {
        throw code('GUARDIAN_JOURNAL_WRITE_UNVERIFIED');
      }
      const persistedDigest = fingerprint(fd, after.size, after.size);
      committedSnapshot = Object.freeze({
        dev: after.dev, ino: after.ino, size: after.size,
        sha256: persistedDigest,
      });
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
