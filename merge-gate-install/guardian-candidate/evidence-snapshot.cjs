/**
 * SOURCE-ONLY candidate for a future, independently authenticated Guardian App.
 * Checking untrusted JSON snapshots NEVER proves GitHub provenance or permits
 * a required check, merge, deployment, payment, or feature activation.
 */
'use strict';

const { parseUniqueKeySourceLock } = require('../candidate/verify-source-lock.cjs');
const REPO = 'nohandsai01/test';
const REQUIRED = 'NO HANDS Merge Gate Required Check';
const SHA = /^[0-9a-f]{40}$/;
const TYPES = ['tests', 'ci'];

function record(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) &&
    Object.getPrototypeOf(x) === Object.prototype;
}
function keys(x, fields) {
  return record(x) && JSON.stringify(Object.keys(x).sort()) ===
    JSON.stringify([...fields].sort());
}
function result(findings) {
  return {
    schemaVersion: 1,
    status: findings.length ? 'SNAPSHOT_SOURCE_REJECTED' : 'SNAPSHOT_SHAPE_MATCH_ONLY',
    mode: 'SOURCE_ONLY', trusted: false, activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED', authoritativeRequiredCheck: 'NOT_ISSUED',
    unresolvedAuthority: [
      'INDEPENDENT_POLICY_SOURCE_NOT_VERIFIED',
      'AUTHENTICATED_GITHUB_RESPONSE_NOT_VERIFIED',
      'LAST_PUSH_AND_REVIEW_PROVENANCE_NOT_VERIFIED',
      'BRANCH_RULESET_NOT_VERIFIED',
    ],
    findings,
  };
}
function parseBytes(x) {
  if (!Buffer.isBuffer(x) && typeof x !== 'string') throw new Error('Raw JSON required.');
  // This parser rejects duplicate JSON keys and non-UTF8 input. Passing raw
  // bytes prevents caller-supplied Proxy/getter mutations during inspection.
  return parseUniqueKeySourceLock(x);
}

function inspectEvidenceSnapshot(rawPolicy, rawSnapshot) {
  const findings = [];
  const reject = (code, detail) => findings.push({ code, detail });
  let policy, snapshot;
  try {
    policy = parseBytes(rawPolicy);
    snapshot = parseBytes(rawSnapshot);
  } catch (_) {
    reject('SNAPSHOT_INPUT_INVALID', 'Malformed, duplicate-key, non-UTF8 or oversized JSON.');
    return result(findings);
  }

  if (!keys(policy, ['schemaVersion', 'repository', 'targetBranch', 'headSha', 'evidence'])) {
    reject('POLICY_FIELDS_INVALID', 'Unexpected or missing policy fields.');
    return result(findings);
  }
  if (policy.schemaVersion !== 1 || policy.repository !== REPO ||
      policy.targetBranch !== 'main' || typeof policy.headSha !== 'string' ||
      !SHA.test(policy.headSha)) {
    reject('POLICY_SCOPE_INVALID', 'Only exact repository, main, and pinned lowercase SHA.');
  }

  const expected = new Map(), names = new Set();
  if (!Array.isArray(policy.evidence) || policy.evidence.length !== 2) {
    reject('POLICY_EVIDENCE_SET_INVALID', 'Exactly tests and ci are required.');
  } else {
    for (const entry of policy.evidence) {
      if (!keys(entry, ['type', 'checkName', 'issuerAppId']) ||
          !TYPES.includes(entry.type) || expected.has(entry.type) ||
          typeof entry.checkName !== 'string' || entry.checkName.length < 1 ||
          entry.checkName.length > 120 || /[\x00-\x1f]/.test(entry.checkName) ||
          entry.checkName === REQUIRED || names.has(entry.checkName) ||
          !Number.isSafeInteger(entry.issuerAppId) || entry.issuerAppId <= 0) {
        reject('POLICY_EVIDENCE_MAPPING_INVALID', 'Unapproved or duplicate type/name/App ID.');
        continue;
      }
      expected.set(entry.type, entry);
      names.add(entry.checkName);
    }
    for (const type of TYPES) {
      if (!expected.has(type)) reject('POLICY_EVIDENCE_MISSING', type);
    }
  }

  if (!keys(snapshot, ['repository', 'pullRequest', 'checkRuns'])) {
    reject('SNAPSHOT_FIELDS_INVALID', 'Unexpected or missing snapshot fields.');
    return result(findings);
  }
  if (snapshot.repository !== REPO) reject('SNAPSHOT_REPOSITORY_MISMATCH', 'Wrong repository.');
  const pr = snapshot.pullRequest;
  if (!record(pr) || !Number.isSafeInteger(pr.number) || pr.number <= 0 ||
      pr.state !== 'open' || !record(pr.base) || !record(pr.head) ||
      pr.base.ref !== 'main' || pr.head.sha !== policy.headSha ||
      pr.base.repo?.full_name !== REPO || pr.head.repo?.full_name !== REPO) {
    reject('SNAPSHOT_PR_HEAD_MISMATCH', 'PR, base branch, or exact head mismatch.');
  }

  const checks = snapshot.checkRuns;
  if (!record(checks) || !Number.isSafeInteger(checks.total_count) ||
      checks.total_count < 0 || !Array.isArray(checks.check_runs) ||
      checks.total_count !== checks.check_runs.length) {
    reject('SNAPSHOT_CHECK_PAGE_INCOMPLETE', 'All check-run pages must be present.');
    return result(findings);
  }
  for (const type of TYPES) {
    const spec = expected.get(type);
    if (!spec) continue;
    const matches = checks.check_runs.filter((run) => record(run) && run.name === spec.checkName);
    if (matches.length !== 1) {
      reject('SNAPSHOT_CHECK_AMBIGUOUS', type + ': requires one approved-name run.');
      continue;
    }
    const run = matches[0];
    if (!Number.isSafeInteger(run.id) || run.id <= 0 ||
        run.head_sha !== policy.headSha || run.app?.id !== spec.issuerAppId ||
        run.status !== 'completed' || run.conclusion !== 'success' ||
        typeof run.completed_at !== 'string' || !Number.isFinite(Date.parse(run.completed_at))) {
      reject('SNAPSHOT_CHECK_NOT_ACCEPTABLE', type + ': SHA, issuer, or result mismatch.');
    }
  }
  return result(findings);
}

module.exports = { inspectEvidenceSnapshot };
