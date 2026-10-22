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
const BRANCH = 'feat/merge-gate-ci-candidate-20261022';
const MANAGED_PATHS = Object.freeze([
  'nohands.yml',
  'merge-gate-install/candidate/trusted-evidence.yml.example',
  'merge-gate-install/candidate/source-contract.cjs',
  'merge-gate-install/candidate/source-contract.json',
  'merge-gate-install/candidate/policy-source-binding.cjs',
  'merge-gate-install/candidate/verify-source-lock.cjs',
  'merge-gate-install/candidate/candidate-preflight.cjs',
  'merge-gate-install/candidate/error-codes.json',
  'merge-gate-install/candidate/DELIVERY.md',
]);
const SHA1 = /^[0-9a-f]{40}$/;

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

function main(args) {
  if (args.length !== 2) {
    process.stderr.write('Usage: node verify-source-lock.cjs <source-lock.json> <repository-root>\n');
    return 2;
  }

  try {
    const lock = JSON.parse(fs.readFileSync(args[0], 'utf8'));
    const root = path.resolve(args[1]);
    const sources = Object.create(null);
    for (const file of MANAGED_PATHS) {
      // Paths are hard-coded, not provided by the lock file.
      sources[file] = fs.readFileSync(path.join(root, file));
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

module.exports = { gitBlobSha1, inspectSourceLock, MANAGED_PATHS };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
