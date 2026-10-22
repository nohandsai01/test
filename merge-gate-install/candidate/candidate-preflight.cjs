/**
 * One entry point for an INERT Merge Gate CI source candidate.
 *
 * Combines the exact contract, the static nohands.yml binding, and the
 * Git-blob source lock. No actual GitHub Check/Workflow result is read.
 * All outputs explicitly withhold trusted evidence and activation.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { validateCandidateContract } = require('./source-contract.cjs');
const { inspectCandidatePolicy } = require('./policy-source-binding.cjs');
const { inspectSourceLock, MANAGED_PATHS } = require('./verify-source-lock.cjs');

const CANDIDATE = 'merge-gate-install/candidate';

function inspectCandidatePreflight(contract, policyText, sourceLock, sources) {
  const contractResult = validateCandidateContract(contract);
  const policyResult = inspectCandidatePolicy(contract, policyText);
  const sourceLockResult = inspectSourceLock(sourceLock, sources);

  // Policy inspector already includes contract findings; avoid duplicates.
  const policyOnlyFindings = policyResult.findings.slice(contractResult.findings.length);
  const findings = [
    ...contractResult.findings.map((finding) => ({ stage: 'contract', ...finding })),
    ...policyOnlyFindings.map((finding) => ({ stage: 'policy', ...finding })),
    ...sourceLockResult.findings.map((finding) => ({ stage: 'source_lock', ...finding })),
  ];

  return {
    status: findings.length ? 'CANDIDATE_SOURCE_REJECTED' : 'CANDIDATE_SOURCE_PREPARED_ONLY',
    mode: 'SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    checks: {
      contract: contractResult.status,
      policy: policyResult.status,
      sourceLock: sourceLockResult.status,
    },
    findings,
  };
}

function failure(code) {
  return {
    status: 'CANDIDATE_SOURCE_REJECTED',
    mode: 'SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    checks: {
      contract: 'NOT_EVALUATED',
      policy: 'NOT_EVALUATED',
      sourceLock: 'NOT_EVALUATED',
    },
    findings: [{ stage: 'input', code, detail: 'Source inputs unavailable or malformed.' }],
  };
}

function main(args) {
  if (args.length !== 1) {
    process.stderr.write('Usage: node candidate-preflight.cjs <repository-root>\n');
    return 2;
  }

  let result;
  try {
    const root = path.resolve(args[0]);
    const contract = JSON.parse(fs.readFileSync(path.join(root, CANDIDATE, 'source-contract.json'), 'utf8'));
    const policyText = fs.readFileSync(path.join(root, 'nohands.yml'), 'utf8');
    const sourceLock = JSON.parse(fs.readFileSync(path.join(root, CANDIDATE, 'source-lock.json'), 'utf8'));
    const sources = {};
    // This list is owned by the lock verifier, never by untrusted manifest entries.
    for (const file of MANAGED_PATHS) {
      sources[file] = fs.readFileSync(path.join(root, file));
    }
    result = inspectCandidatePreflight(contract, policyText, sourceLock, sources);
  } catch (_) {
    result = failure('CANDIDATE_PREFLIGHT_INPUT_UNREADABLE');
  }
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  // Deliberately NEVER exit 0: source-only matching is not hosted CI PASS.
  return result.findings.length ? 1 : 3;
}

module.exports = { inspectCandidatePreflight };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
