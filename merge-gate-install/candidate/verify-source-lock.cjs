/**
 * Git blob identity binding for an inert Merge Gate CI candidate.
 *
 * Checks only exact source bytes against a pinned Git blob snapshot.
 * This is NOT a GitHub-hosted CI, signature, reviewer, or issuer attestation.
 * No branch protection, workflow, deployment, or runtime settings are changed.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const REPO = 'nohandsai01/test';
const BRANCH = 'feat/merge-gate-postqa-20261022';
const MANAGED_PATHS = Object.freeze([
  'nohands.yml',
  'merge-gate-install/candidate/trusted-evidence.yml.example',
  'merge-gate-install/candidate/source-contract.cjs',
  'merge-gate-install/candidate/source-contract.json',
  'merge-gate-install/candidate/policy-source-binding.cjs',
  'merge-gate-install/candidate/workflow-source-binding.cjs',
  'merge-gate-install/candidate/verify-source-lock.cjs',
  'merge-gate-install/candidate/candidate-preflight.cjs',
  'merge-gate-install/candidate/error-codes.json',
  'merge-gate-install/candidate/DELIVERY.md',
]);
const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;

// A parsed object loses duplicate JSON members. Inspect the raw lock syntax
// first so a different JSON consumer cannot see a different activation value.
function parseUniqueKeySourceLock(bytes) {
  const raw = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
  if (raw.length === 0 || raw.length > 256_000) throw new Error('Invalid lock size.');
  const input = raw.toString('utf8');
  if (!Buffer.from(input, 'utf8').equals(raw)) throw new Error('Invalid UTF-8 lock.');
  const parsed = JSON.parse(input);
  let offset = 0;
  const whitespace = () => { while (/\s/.test(input[offset] || '') && offset < input.length) offset++; };
  const stringToken = () => {
    const start = offset++;
    while (offset < input.length) {
      if (input[offset] === '\\') { offset += 2; continue; }
      if (input[offset++] === '"') return JSON.parse(input.slice(start, offset));
    }
    throw new Error('Unterminated JSON string.');
  };
  const walk = () => {
    whitespace();
    if (input[offset] === '{') {
      offset++;
      whitespace();
      const keys = new Set();
      while (input[offset] !== '}') {
        const key = stringToken();
        if (keys.has(key)) throw new Error('Duplicate JSON member.');
        keys.add(key);
        whitespace();
        offset++; // colon (the preceding JSON.parse validated grammar)
        walk();
        whitespace();
        if (input[offset] !== ',') break;
        offset++;
        whitespace();
      }
      offset++; // closing brace
    } else if (input[offset] === '[') {
      offset++;
      whitespace();
      while (input[offset] !== ']') {
        walk();
        whitespace();
        if (input[offset] !== ',') break;
        offset++;
      }
      offset++; // closing bracket
    } else if (input[offset] === '"') {
      stringToken();
    } else {
      while (offset < input.length && !/[\s,}\]]/.test(input[offset])) offset++;
    }
  };
  walk();
  whitespace();
  if (offset !== input.length) throw new Error('Invalid JSON layout.');
  return parsed;
}

// Hash regular files only, not symlink target contents (which Git records as
// mode 120000 and link-text bytes). Apply this to both source-only CLIs.
function readManagedRegularFile(root, relativePath) {
  if (!MANAGED_PATHS.includes(relativePath)) throw new Error('Unmanaged file.');
  let filename = path.resolve(root);
  const parts = relativePath.split('/');
  for (const [index, part] of parts.entries()) {
    filename = path.join(filename, part);
    const stat = fs.lstatSync(filename);
    if (index < parts.length - 1 ? !stat.isDirectory() : !stat.isFile()) {
      throw new Error('Source path is not a regular Git file.');
    }
  }
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error('Source is not a regular file.');
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function gitBlobSha1(bytes) {
  const content = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
  const header = Buffer.from('blob ' + content.length + '\0');
  return crypto.createHash('sha1').update(header).update(content).digest('hex');
}

function record(value) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function inspectSourceLock(lock, sources) {
  const findings = [];
  const issue = (code, detail) => findings.push({ code, detail });
  const fail = () => ({
    status: 'SOURCE_LOCK_REJECTED',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    findings,
  });

  if (!record(lock) || !record(sources)) {
    issue('SOURCE_LOCK_INPUT_INVALID', 'Expected a lock object and source map.');
    return fail();
  }

  const exactKeys = (value, required, code) => {
    if (!record(value) ||
        JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...required].sort())) {
      issue(code, 'Unexpected or missing keys.');
      return false;
    }
    return true;
  };

  exactKeys(lock, ['schemaVersion', 'repository', 'branch', 'mode', 'gitObjectFormat', 'activation', 'files'],
    'SOURCE_LOCK_FIELDS_INVALID');
  if (lock.schemaVersion !== 1 || lock.repository !== REPO || lock.branch !== BRANCH ||
      lock.mode !== 'SOURCE_ONLY' || lock.gitObjectFormat !== 'sha1') {
    issue('SOURCE_LOCK_SCOPE_MISMATCH', 'Repository, branch, mode, or object format changed.');
  }

  if (exactKeys(lock.activation,
    ['workflowInstalled', 'issuerApproved', 'branchChecksConfigured', 'featureEnabled'],
    'SOURCE_LOCK_ACTIVATION_FIELDS_INVALID')) {
    for (const [key, value] of Object.entries(lock.activation)) {
      if (value !== false) issue('SOURCE_LOCK_ACTIVATION_NOT_OFF', key);
    }
  }

  if (!Array.isArray(lock.files) || lock.files.length !== MANAGED_PATHS.length) {
    issue('SOURCE_LOCK_FILE_SET_INVALID', 'The exact candidate source set is mandatory.');
    return fail();
  }

  const seen = new Set();
  for (const entry of lock.files) {
    if (!exactKeys(entry, ['path', 'gitBlobSha1'], 'SOURCE_LOCK_ENTRY_INVALID')) continue;
    if (!MANAGED_PATHS.includes(entry.path)) {
      issue('SOURCE_LOCK_UNAUTHORIZED_PATH', String(entry.path));
      continue;
    }
    if (seen.has(entry.path)) issue('SOURCE_LOCK_DUPLICATE_PATH', entry.path);
    seen.add(entry.path);
    if (typeof entry.gitBlobSha1 !== 'string' || !SHA1.test(entry.gitBlobSha1)) {
      issue('SOURCE_LOCK_SHA_INVALID', entry.path);
      continue;
    }

    const bytes = sources[entry.path];
    if (!Buffer.isBuffer(bytes) && typeof bytes !== 'string') {
      issue('SOURCE_LOCK_SOURCE_MISSING', entry.path);
      continue;
    }
    if (gitBlobSha1(bytes) !== entry.gitBlobSha1) {
      issue('SOURCE_LOCK_BLOB_DRIFT', entry.path);
    }
  }
  for (const required of MANAGED_PATHS) {
    if (!seen.has(required)) issue('SOURCE_LOCK_PATH_MISSING', required);
  }
  for (const actual of Object.keys(sources)) {
    if (!MANAGED_PATHS.includes(actual)) issue('SOURCE_LOCK_UNEXPECTED_SOURCE', actual);
  }

  const result = fail();
  if (!findings.length) result.status = 'SOURCE_BYTES_MATCH_CANDIDATE_LOCK';
  return result;
}

// Expected SHA-256 MUST originate outside the candidate-controlled branch
// (e.g. a separately reviewed immutable policy commit or signed manifest).
// Neither this function nor the branch-local CI can establish that provenance.
// This method is an anchor-verification primitive, NEVER an authority grant.
function inspectExternallyAnchoredLock(rawLockBytes, expectedSha256, sources) {
  const rejected = (code) => ({
    status: 'SOURCE_LOCK_REJECTED', trusted: false, activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    findings: [{ code, detail: 'Independent lock anchor unavailable or mismatched.' }],
  });
  if ((!Buffer.isBuffer(rawLockBytes) && typeof rawLockBytes !== 'string') ||
      typeof expectedSha256 !== 'string' || !SHA256.test(expectedSha256)) {
    return rejected('SOURCE_LOCK_EXTERNAL_ANCHOR_UNAVAILABLE');
  }
  const raw = Buffer.isBuffer(rawLockBytes) ? rawLockBytes : Buffer.from(rawLockBytes, 'utf8');
  if (raw.length === 0 || raw.length > 256_000) return rejected('SOURCE_LOCK_ANCHOR_INPUT_INVALID');
  if (crypto.createHash('sha256').update(raw).digest('hex') !== expectedSha256) {
    return rejected('SOURCE_LOCK_EXTERNAL_ANCHOR_MISMATCH');
  }
  try {
    const result = inspectSourceLock(parseUniqueKeySourceLock(raw), sources);
    if (result.findings.length) return result;
    return { ...result, status: 'SOURCE_LOCK_MATCHES_EXTERNAL_DIGEST_ONLY',
      externalAnchorProven: false };
  } catch (_) {
    return rejected('SOURCE_LOCK_ANCHOR_INPUT_INVALID');
  }
}

function main(args) {
  if (args.length !== 2) {
    process.stderr.write('Usage: node verify-source-lock.cjs <source-lock.json> <repository-root>\n');
    return 2;
  }

  try {
    const lock = parseUniqueKeySourceLock(fs.readFileSync(args[0]));
    const root = path.resolve(args[1]);
    const sources = Object.create(null);
    for (const file of MANAGED_PATHS) {
      // Paths are hard-coded, not provided by the lock file.
      sources[file] = readManagedRegularFile(root, file);
    }
    const result = inspectSourceLock(lock, Object.assign({}, sources));
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    // Matching bytes alone are not hosted CI evidence: never exit 0.
    return result.findings.length ? 1 : 3;
  } catch (_) {
    process.stdout.write(JSON.stringify({
      status: 'SOURCE_LOCK_REJECTED',
      trusted: false,
      activationAllowed: false,
      hostedCheckEvidence: 'NOT_VERIFIED',
      findings: [{ code: 'SOURCE_LOCK_UNREADABLE', detail: 'A source input is unavailable or malformed.' }],
    }) + '\n');
    return 2;
  }
}

module.exports = { gitBlobSha1, inspectSourceLock, inspectExternallyAnchoredLock,
  parseUniqueKeySourceLock, readManagedRegularFile, MANAGED_PATHS };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
