'use strict';

// Source-only candidate QA. Passing these tests does not create trusted
// Merge Gate evidence or authorize installation, merge, or launch.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const dir = path.join(root, 'merge-gate-install', 'candidate');
const { validateCandidateContract } = require(path.join(dir, 'source-contract.cjs'));
const { inspectCandidatePolicy } = require(path.join(dir, 'policy-source-binding.cjs'));
const { inspectWorkflowTemplate } = require(path.join(dir, 'workflow-source-binding.cjs'));
const { inspectSourceLock, inspectExternallyAnchoredLock, parseUniqueKeySourceLock,
  readManagedRegularFile, MANAGED_PATHS } = require(path.join(dir, 'verify-source-lock.cjs'));
const { inspectCandidatePreflight } = require(path.join(dir, 'candidate-preflight.cjs'));
const { inspectChangedPaths } = require(path.join(dir, 'check-change-scope.cjs'));

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
  manifest.authoritativeCheckName = 'renamed-check';
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
for (const [label, injection] of [
  ['quoted trusted mapping key', '"trusted_evidence_workflows":\n  - bad\n'],
  ['spaced trusted mapping key', 'trusted_evidence_workflows :\n  - bad\n'],
  ['flow-style required evidence override', '"required_evidence": [tests]\n'],
  ['duplicate version', 'version: 1\n'],
  ['unknown policy key', 'unapproved_policy_key:\n  - bad\n'],
]) {
  test('policy: reject ' + label, () => {
    const result = inspectCandidatePolicy(json('source-contract.json'), policy() + injection);
    assert.notEqual(result.status, 'POLICY_BOUND_SOURCE_ONLY');
    assert(result.findings.length > 0);
    sourceOnly(result);
  });
}
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
test('lock: reject duplicate root, nested, and escaped JSON member spellings', () => {
  const raw = read('source-lock.json');
  for (const forged of [
    raw.replace('"schemaVersion": 1,', '"schemaVersion": 1, "schemaVersion": 1,'),
    raw.replace('"workflowInstalled": false,', '"workflowInstalled": true, "workflowInstalled": false,'),
    raw.replace('"activation": {', '"\\u0061ctivation": { "featureEnabled": true }, "activation": {'),
  ]) {
    assert.notEqual(forged, raw);
    assert.throws(() => parseUniqueKeySourceLock(forged), /Duplicate JSON member/);
    const digest = crypto.createHash('sha256').update(forged).digest('hex');
    const result = inspectExternallyAnchoredLock(forged, digest, sources());
    assert.equal(result.status, 'SOURCE_LOCK_REJECTED');
    sourceOnly(result);
  }
  assert.deepEqual(parseUniqueKeySourceLock(raw), json('source-lock.json'));
});
test('lock: only regular managed source paths are readable', () => {
  assert.deepEqual(readManagedRegularFile(root, 'nohands.yml'), fs.readFileSync(path.join(root, 'nohands.yml')));
  const temporary = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'mg-source-path-'));
  try {
    const outside = path.join(temporary, 'outside');
    fs.writeFileSync(outside, 'source');
    fs.symlinkSync(outside, path.join(temporary, 'nohands.yml'));
    assert.throws(() => readManagedRegularFile(temporary, 'nohands.yml'), /regular Git file/);
    fs.mkdirSync(path.join(temporary, 'merge-gate-install'));
    fs.symlinkSync(temporary, path.join(temporary, 'merge-gate-install', 'candidate'));
    assert.throws(() => readManagedRegularFile(temporary,
      'merge-gate-install/candidate/DELIVERY.md'), /regular Git file/);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
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
test('lock: independently supplied digest catches a forged re-pin', () => {
  const old = read('source-lock.json');
  const expected = crypto.createHash('sha256').update(old).digest('hex');
  const forged = json('source-lock.json');
  forged.files[0].gitBlobSha1 = '0'.repeat(40);
  const result = inspectExternallyAnchoredLock(JSON.stringify(forged), expected, sources());
  assert(result.findings.some(f => f.code === 'SOURCE_LOCK_EXTERNAL_ANCHOR_MISMATCH'));
  sourceOnly(result);
});
test('lock: no external digest cannot be treated as verified', () => {
  const result = inspectExternallyAnchoredLock(read('source-lock.json'), undefined, sources());
  assert(result.findings.some(f => f.code === 'SOURCE_LOCK_EXTERNAL_ANCHOR_UNAVAILABLE'));
  sourceOnly(result);
});
test('lock: matching caller digest still does not prove trusted provenance', () => {
  const raw = read('source-lock.json');
  const result = inspectExternallyAnchoredLock(raw, crypto.createHash('sha256').update(raw).digest('hex'), sources());
  assert.equal(result.status, 'SOURCE_LOCK_MATCHES_EXTERNAL_DIGEST_ONLY');
  assert.equal(result.externalAnchorProven, false);
  sourceOnly(result);
});
test('preflight: exact source is prepared only, not passed', () => {
  const result = inspectCandidatePreflight(...inputs());
  assert.equal(result.status, 'CANDIDATE_SOURCE_PREPARED_ONLY');
  assert.deepEqual(result.findings, []);
  assert.equal(result.mode, 'SOURCE_ONLY');
  sourceOnly(result);
});
test('preflight CLI: loads each managed path exactly once', () => {
  const script = `
    const fs = require('node:fs');
    const path = require('node:path');
    const root = process.argv[1];
    const opened = new Map();
    const realOpen = fs.openSync;
    fs.openSync = function(filename, ...args) {
      if (typeof filename === 'string' && filename.startsWith(root + path.sep)) {
        opened.set(filename, (opened.get(filename) || 0) + 1);
      }
      return realOpen.call(this, filename, ...args);
    };
    const verifier = require(path.join(root, 'merge-gate-install/candidate/verify-source-lock.cjs'));
    const preflight = require(path.join(root, 'merge-gate-install/candidate/candidate-preflight.cjs'));
    const exitCode = preflight.main([root]);
    for (const name of verifier.MANAGED_PATHS) {
      if (opened.get(path.join(root, name)) !== 1) process.exit(97);
    }
    process.exit(exitCode);
  `;
  const result = spawnSync(process.execPath, ['-e', script, root], { encoding: 'utf8' });
  assert.equal(result.status, 3, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.status, 'CANDIDATE_SOURCE_PREPARED_ONLY');
  sourceOnly(output);
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
test('change scope: candidate files are allowed without granting authority', () => {
  const result = inspectChangedPaths(['nohands.yml', 'merge-gate-install/required-check.yml.example',
    '.github/workflows/merge-gate-candidate-qa.yml']);
  assert.equal(result.status, 'CANDIDATE_CHANGE_SCOPE_ONLY');
  assert.equal(result.activationAllowed, false);
  assert.equal(result.trusted, false);
});
test('change scope: unrelated workflows and files reject', () => {
  const result = inspectChangedPaths(['.github/workflows/other.yml', 'src/payload.cjs']);
  assert.equal(result.status, 'CANDIDATE_CHANGE_SCOPE_REJECTED');
  assert.equal(result.findings.length, 2);
});
test('change scope: traversal and empty diff reject', () => {
  for (const files of [['merge-gate-install/../src/x'], [], ['']]) {
    const result = inspectChangedPaths(files);
    assert.equal(result.status, 'CANDIDATE_CHANGE_SCOPE_REJECTED');
    assert.equal(result.trusted, false);
    assert.equal(result.activationAllowed, false);
  }
});
