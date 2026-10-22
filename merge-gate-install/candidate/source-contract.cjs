/**
 * Source-only contract inspector for the NO HANDS Merge Gate CI candidate.
 * This module does NOT verify GitHub-hosted checks, workflow provenance,
 * signed runs, issuer identity, last push or any runtime security property.
 * It never returns "trusted", "PASS", or an activation authorization.
 *
 * No network, credential, payment, workflow or deployment side effects.
 */
'use strict';

const fs = require('node:fs');

const REPO = 'nohandsai01/test';
const BRANCH = 'feat/merge-gate-ci-candidate-20261022';
const EVIDENCE_KEYS = ['tests', 'ci'];
// Tests and CI are separate evidence TYPES, not two identity-free GitHub
// required checks. The single authoritative context belongs to the dedicated
// issuer App, as required by company-os's existing H1 Ruleset contract.
const REQUIRED_CHECK = 'NO HANDS Merge Gate Required Check';
const SOURCE_PATH = 'merge-gate-install/candidate/trusted-evidence.yml.example';
const PROPOSED_PATH = '.github/workflows/nohands-merge-gate-evidence.yml';

function isRecord(value) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function validateCandidateContract(contract) {
  const findings = [];
  const reject = (code, detail) => findings.push({ code, detail });
  if (!isRecord(contract)) {
    return {
      status: 'INVALID_CANDIDATE_SOURCE',
      trusted: false,
      activationAllowed: false,
      findings: [{ code: 'CONTRACT_NOT_OBJECT', detail: 'Expected a JSON object.' }],
    };
  }

  const exactKeys = (object, expected, code) => {
    if (!isRecord(object)) {
      reject(code, 'Expected an object.');
      return false;
    }
    const found = Object.keys(object).sort();
    const wanted = [...expected].sort();
    if (JSON.stringify(found) !== JSON.stringify(wanted)) {
      reject(code, 'Unexpected or missing fields: ' + found.join(', '));
      return false;
    }
    return true;
  };

  exactKeys(contract,
    ['schemaVersion', 'scope', 'mode', 'workflowSource', 'proposedWorkflowPath',
      'authoritativeCheckName', 'activation', 'evidence'],
    'CONTRACT_FIELDS_INVALID');
  if (contract.schemaVersion !== 2) reject('SCHEMA_VERSION_UNSUPPORTED', 'Only schema version 2 is accepted.');
  if (contract.mode !== 'SOURCE_ONLY') reject('MODE_NOT_SOURCE_ONLY', 'Candidate must remain source-only.');

  if (exactKeys(contract.scope, ['repository', 'branch', 'baseBranch'], 'SCOPE_FIELDS_INVALID')) {
    if (contract.scope.repository !== REPO || contract.scope.branch !== BRANCH ||
        contract.scope.baseBranch !== 'main') {
      reject('WRONG_REPOSITORY_OR_BRANCH', 'Scope must match the authorized isolated branch.');
    }
  }

  if (contract.workflowSource !== SOURCE_PATH ||
      contract.proposedWorkflowPath !== PROPOSED_PATH) {
    reject('WORKFLOW_SOURCE_PATH_MISMATCH', 'Only the non-executable example at its approved path is allowed.');
  }
  if (contract.authoritativeCheckName !== REQUIRED_CHECK) {
    reject('UNAPPROVED_CHECK_NAME', 'One dedicated-App required context is mandatory.');
  }

  const gates = ['workflowInstalled', 'issuerApproved', 'branchChecksConfigured', 'featureEnabled'];
  if (exactKeys(contract.activation, gates, 'ACTIVATION_FIELDS_INVALID')) {
    for (const gate of gates) {
      if (contract.activation[gate] !== false) {
        reject('ACTIVATION_GATE_NOT_OFF', gate + ' must be exactly false.');
      }
    }
  }

  if (!Array.isArray(contract.evidence) || contract.evidence.length !== 2) {
    reject('EVIDENCE_SET_INVALID', 'Exactly two internal evidence types are required.');
  } else {
    const keys = new Set();
    for (const item of contract.evidence) {
      if (!exactKeys(item, ['key', 'role'], 'EVIDENCE_FIELDS_INVALID')) continue;
      if (!EVIDENCE_KEYS.includes(item.key)) {
        reject('UNKNOWN_EVIDENCE_KEY', 'Only tests and ci are permitted.');
      }
      if (keys.has(item.key)) reject('DUPLICATE_EVIDENCE_KEY', String(item.key));
      keys.add(item.key);
      if (item.role !== 'INTERNAL_EVIDENCE_NOT_REQUIRED_CHECK') {
        reject('UNAPPROVED_CHECK_NAME', String(item.key));
      }
    }
    for (const key of EVIDENCE_KEYS) {
      if (!keys.has(key)) reject('MISSING_EVIDENCE_KEY', key);
    }
  }

  return {
    status: findings.length ? 'INVALID_CANDIDATE_SOURCE' : 'CANDIDATE_SOURCE_ONLY',
    trusted: false,
    activationAllowed: false,
    findings,
  };
}

function main(argv) {
  if (argv.length !== 1) {
    process.stderr.write('Usage: node source-contract.cjs <candidate-contract.json>\n');
    return 2;
  }
  let contract;
  try {
    contract = JSON.parse(fs.readFileSync(argv[0], 'utf8'));
  } catch (_) {
    process.stdout.write(JSON.stringify({
      status: 'INVALID_CANDIDATE_SOURCE',
      trusted: false,
      activationAllowed: false,
      findings: [{ code: 'CONTRACT_UNREADABLE', detail: 'Cannot read or parse the supplied JSON file.' }],
    }) + '\n');
    return 2;
  }
  const result = validateCandidateContract(contract);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  // Even valid candidate source is not a successful hosted CI check.
  return result.findings.length ? 1 : 3;
}

module.exports = { validateCandidateContract };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
