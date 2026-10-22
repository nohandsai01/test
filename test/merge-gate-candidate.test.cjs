'use strict';

// Source-only candidate QA. Passing these tests does not create trusted
// Merge Gate evidence or authorize installation, merge, or launch.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const dir = path.join(root, 'merge-gate-install', 'candidate');
const { validateCandidateContract } = require(path.join(dir, 'source-contract.cjs'));
const { inspectCandidatePolicy } = require(path.join(dir, 'policy-source-binding.cjs'));
const { inspectWorkflowTemplate } = require(path.join(dir, 'workflow-source-binding.cjs'));
const { inspectSourceLock, MANAGED_PATHS } = require(path.join(dir, 'verify-source-lock.cjs'));
const { inspectCandidatePreflight } = require(path.join(dir, 'candidate-preflight.cjs'));

const read = (name) => fs.readFileSync(path.join(dir, name), 'utf8');
const json = (name) => JSON.parse(read(name));
const policy = () => fs.readFileSync(path.join(root, 'nohands.yml'), 'utf8');
const copy = (value) => JSON.parse(JSON.stringify(value));
function sources() {
  return Object.fromEntries(MANAGED_PATHS.map((name) =>
    [name, fs.readFileSync(path.join(root, name))]));
}
function inputs() {
  return [json('source-contract.json'), policy(),
    read('trusted-evidence.yml.example'), json('source-lock.json'),
    sources(), json('error-codes.json')];
}
function sourceOnly(result) {
  assert.equal(result.trusted, false);
  assert.equal(result.activationAllowed, false);
  if ('hostedCheckEvidence' in result) {
    assert.equal(result.hostedCheckEvidence, 'NOT_VERIFIED');
  }
  assert.notEqual(result.status, 'PASS');
}

test('contract: valid source stays untrusted', () => {
  const result = validateCandidateContract(json('source-contract.json'));
  assert.equal(result.status, 'CANDIDATE_SOURCE_ONLY');
  assert.deepEqual(result.findings, []);
  sourceOnly(result);
});
test('contract: enabling a workflow is rejected', () => {
  const manifest = json('source-contract.json');
  manifest.activation.workflowInstalled = true;
  const result = validateCandidateContract(manifest);
  assert(result.findings.some((f) => f.code === 'ACTIVATION_GATE_NOT_OFF'));
  sourceOnly(result);
});
test('contract: check identity drift is rejected', () => {
  const manifest = json('source-contract.json');
  manifest.evidence[0].checkName = 'renamed-check';
  const result = validateCandidateContract(manifest);
  assert(result.findings.some((f) => f.code === 'UNAPPROVED_CHECK_NAME'));
  sourceOnly(result);
});
test('contract: unknown field is rejected', () => {
  const manifest = json('source-contract.json');
  manifest.untrustedField = true;
  const result = validateCandidateContract(manifest);
  assert(result.findings.some((f) => f.code === 'CONTRACT_FIELDS_INVALID'));
  sourceOnly(result);
});
test('contract: wrong mode and repository are rejected', () => {
  const manifest = json('source-contract.json');
  manifest.mode = 'ACTIVE';
  manifest.scope.repository = 'other/repo';
  const result = validateCandidateContract(manifest);
  assert(result.findings.some((f) => f.code === 'MODE_NOT_SOURCE_ONLY'));
  assert(result.findings.some((f) => f.code === 'WRONG_REPOSITORY_OR_BRANCH'));
  sourceOnly(result);
});
test('policy: source-only required evidence is accepted structurally', () => {
  const result = inspectCandidatePolicy(json('source-contract.json'), policy());
  assert.equal(result.status, 'POLICY_BOUND_SOURCE_ONLY');
  assert.deepEqual(result.findings, []);
  sourceOnly(result);
});
test('policy: premature hosted mapping is rejected', () => {
  const changed = policy() + 'trusted_evidence_workflows:\n  - "tests|not-trusted|workflow.yml"\n';
  const result = inspectCandidatePolicy(json('source-contract.json'), changed);
  assert(result.findings.some((f) => f.code === 'TRUSTED_MAPPING_PREMATURE'));
  sourceOnly(result);
});
test('policy: changed required evidence is rejected', () => {
  const changed = policy().replace('  - ci\n', '  - untrusted-check\n');
  assert.notEqual(changed, policy());
  const result = inspectCandidatePolicy(json('source-contract.json'), changed);
  assert(result.findings.some((f) => f.code === 'REQUIRED_EVIDENCE_DRIFT'));
  sourceOnly(result);
});
test('template: exact inert workflow is recognized but never trusted', () => {
  const result = inspectWorkflowTemplate(read('trusted-evidence.yml.example'));
  assert.equal(result.status, 'WORKFLOW_TEMPLATE_SOURCE_ONLY');
  assert.deepEqual(result.findings, []);
  sourceOnly(result);
});
test('template: replacing fail-closed with success is rejected', () => {
  const original = read('trusted-evidence.yml.example');
  const changed = original.replace('exit 1', 'exit 0');
  assert.notEqual(changed, original);
  const result = inspectWorkflowTemplate(changed);
  assert(result.findings.some((f) => f.code === 'WORKFLOW_TEMPLATE_DRIFT'));
  sourceOnly(result);
});
test('lock: exact pinned source set matches bytes only', () => {
  const result = inspectSourceLock(json('source-lock.json'), sources());
  assert.equal(result.status, 'SOURCE_BYTES_MATCH_CANDIDATE_LOCK');
  assert.deepEqual(result.findings, []);
  sourceOnly(result);
});
test('lock: edited source bytes are rejected', () => {
  const changed = sources();
  const name = 'merge-gate-install/candidate/source-contract.json';
  changed[name] = Buffer.concat([changed[name], Buffer.from(' ')]);
  const result = inspectSourceLock(json('source-lock.json'), changed);
  assert(result.findings.some((f) => f.code === 'SOURCE_LOCK_BLOB_DRIFT'));
  sourceOnly(result);
});
test('lock: injected source is rejected', () => {
  const changed = sources();
  changed['unexpected.txt'] = Buffer.from('a');
  const result = inspectSourceLock(json('source-lock.json'), changed);
  assert(result.findings.some((f) => f.code === 'SOURCE_LOCK_UNEXPECTED_SOURCE'));
  sourceOnly(result);
});
test('lock: removed managed path is rejected', () => {
  const changed = json('source-lock.json');
  changed.files.pop();
  const result = inspectSourceLock(changed, sources());
  assert(result.findings.some((f) => f.code === 'SOURCE_LOCK_FILE_SET_INVALID'));
  sourceOnly(result);
});
test('preflight: exact source is prepared only, not passed', () => {
  const result = inspectCandidatePreflight(...inputs());
  assert.equal(result.status, 'CANDIDATE_SOURCE_PREPARED_ONLY');
  assert.deepEqual(result.findings, []);
  assert.equal(result.mode, 'SOURCE_ONLY');
  sourceOnly(result);
});
test('preflight: workflow drift rejects candidate', () => {
  const args = inputs();
  args[2] = args[2].replace('exit 1', 'exit 0');
  const result = inspectCandidatePreflight(...args);
  assert.equal(result.status, 'CANDIDATE_SOURCE_REJECTED');
  assert(result.findings.some((f) => f.stage === 'workflow_template'));
  sourceOnly(result);
});
test('preflight: missing error catalog mapping is rejected', () => {
  const args = inputs();
  args[2] = args[2].replace('exit 1', 'exit 0');
  args[5].stages.workflow_template =
    args[5].stages.workflow_template.filter((x) => x !== 'WORKFLOW_TEMPLATE_DRIFT');
  const result = inspectCandidatePreflight(...args);
  assert(result.findings.some((f) => f.code === 'ERROR_CATALOG_UNMAPPED_CODE'));
  sourceOnly(result);
});
test('preflight: malformed error catalog is rejected', () => {
  const args = inputs();
  args[5].mode = 'ACTIVE';
  const result = inspectCandidatePreflight(...args);
  assert(result.findings.some((f) => f.code === 'ERROR_CATALOG_INVALID'));
  sourceOnly(result);
});
