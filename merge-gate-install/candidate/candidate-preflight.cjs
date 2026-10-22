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
const { inspectWorkflowTemplate } = require('./workflow-source-binding.cjs');

const CANDIDATE = 'merge-gate-install/candidate';

function validateErrorCatalog(catalog, findings) {
  const fail = (detail) => findings.push({ stage: 'catalog', code: 'ERROR_CATALOG_INVALID', detail });
  const isRecord = (value) => value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
  const expectedStages = ['contract', 'policy', 'workflow_template', 'source_lock', 'input'];
  if (!isRecord(catalog) ||
      JSON.stringify(Object.keys(catalog).sort()) !== JSON.stringify([
        'schemaVersion', 'repository', 'mode', 'trusted',
        'activationAllowed', 'hostedCheckEvidence', 'stages',
      ].sort()) ||
      catalog.schemaVersion !== 1 || catalog.repository !== 'nohandsai01/test' ||
      catalog.mode !== 'SOURCE_ONLY' || catalog.trusted !== false ||
      catalog.activationAllowed !== false || catalog.hostedCheckEvidence !== 'NOT_VERIFIED' ||
      !isRecord(catalog.stages) ||
      JSON.stringify(Object.keys(catalog.stages).sort()) !== JSON.stringify(expectedStages.sort())) {
    fail('Catalog schema, source-only scope, or stage set does not match.');
    return;
  }
  for (const stage of expectedStages) {
    const codes = catalog.stages[stage];
    if (!Array.isArray(codes) || !codes.length ||
        codes.some((code) => typeof code !== 'string' || !/^[A-Z][A-Z0-9_]+$/.test(code)) ||
        new Set(codes).size !== codes.length) {
      fail('Invalid or duplicate catalog codes in ' + stage + '.');
      return;
    }
  }
  for (const finding of [...findings]) {
    if (!catalog.stages[finding.stage]?.includes(finding.code)) {
      findings.push({
        stage: 'catalog',
        code: 'ERROR_CATALOG_UNMAPPED_CODE',
        detail: finding.stage + ':' + finding.code,
      });
    }
  }
}


function inspectCandidatePreflight(contract, policyText, workflowSourceText, sourceLock, sources, errorCatalog) {
  const contractResult = validateCandidateContract(contract);
  const policyResult = inspectCandidatePolicy(contract, policyText);
  const workflowResult = inspectWorkflowTemplate(workflowSourceText);
  const sourceLockResult = inspectSourceLock(sourceLock, sources);

  // Policy inspector already includes contract findings; avoid duplicates.
  const policyOnlyFindings = policyResult.findings.slice(contractResult.findings.length);
  const findings = [
    ...contractResult.findings.map((finding) => ({ stage: 'contract', ...finding })),
    ...policyOnlyFindings.map((finding) => ({ stage: 'policy', ...finding })),
    ...workflowResult.findings.map((finding) => ({ stage: 'workflow_template', ...finding })),
    ...sourceLockResult.findings.map((finding) => ({ stage: 'source_lock', ...finding })),
  ];

  validateErrorCatalog(errorCatalog, findings);

  return {
    errorCodeSchemaVersion: 1,
    status: findings.length ? 'CANDIDATE_SOURCE_REJECTED' : 'CANDIDATE_SOURCE_PREPARED_ONLY',
    mode: 'SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    checks: {
      contract: contractResult.status,
      policy: policyResult.status,
      workflowTemplate: workflowResult.status,
      sourceLock: sourceLockResult.status,
    },
    findings,
  };
}

function failure(code) {
  return {
    errorCodeSchemaVersion: 1,
    status: 'CANDIDATE_SOURCE_REJECTED',
    mode: 'SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    hostedCheckEvidence: 'NOT_VERIFIED',
    checks: {
      contract: 'NOT_EVALUATED',
      policy: 'NOT_EVALUATED',
      workflowTemplate: 'NOT_EVALUATED',
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
    const workflowSourceText = fs.readFileSync(path.join(root, CANDIDATE, 'trusted-evidence.yml.example'), 'utf8');
    const sourceLock = JSON.parse(fs.readFileSync(path.join(root, CANDIDATE, 'source-lock.json'), 'utf8'));
    const errorCatalog = JSON.parse(fs.readFileSync(path.join(root, CANDIDATE, 'error-codes.json'), 'utf8'));
    const sources = {};
    // This list is owned by the lock verifier, never by untrusted manifest entries.
    for (const file of MANAGED_PATHS) {
      sources[file] = fs.readFileSync(path.join(root, file));
    }
    result = inspectCandidatePreflight(contract, policyText, workflowSourceText, sourceLock, sources, errorCatalog);
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
