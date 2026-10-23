'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { verifySignedPolicy } = require('../merge-gate-install/guardian-candidate/signed-policy.cjs');
const { verifyWebhook, processGuardianReconciliation } =
  require('../merge-gate-install/guardian-candidate/guardian-webhook-runtime.cjs');
const { postConclusiveSuccessCheck } = require('../merge-gate-install/guardian-candidate/github-app-identity.cjs');

const SHA = 'a'.repeat(40);
const CHECK = 'NO HANDS Merge Gate Required Check';
const REPO = 'nohandsai01/test';

function signedPayload(releasePolicy) {
  const payload = {
    schemaVersion: 3, pullNumber: 12,
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    evidencePolicy: {
      schemaVersion: 1, repository: REPO, targetBranch: 'main', headSha: SHA,
      evidence: [
        { type: 'tests', checkName: 'tests-run', issuerAppId: 777 },
        { type: 'ci', checkName: 'ci-run', issuerAppId: 778 },
      ],
    },
    releasePolicy,
  };
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const bytes = Buffer.from(JSON.stringify(payload));
  const signature = crypto.sign(null, bytes, privateKey);
  const envelope = JSON.stringify({
    schemaVersion: 1, algorithm: 'Ed25519',
    payloadBase64: bytes.toString('base64'),
    signatureBase64: signature.toString('base64'),
  });
  return { envelope, pem: publicKey.export({ format: 'pem', type: 'spki' }) };
}

const RELEASE = {
  schemaVersion: 1, guardianAppId: 999,
  reviewerIds: [222], minApprovals: 1,
  workflows: [
    { type: 'tests', workflowId: 800, event: 'push' },
    { type: 'ci', workflowId: 801, event: 'push' },
  ],
};

test('v3 independent signature binds full-mode reviewer, issuer and workflows', () => {
  const signed = signedPayload(RELEASE);
  const accepted = verifySignedPolicy(signed.envelope, signed.pem,
    { requirePullBinding: true, expectedPullNumber: 12 });
  assert.equal(accepted.signatureChecked, true);
  assert.deepEqual(accepted.releasePolicy, RELEASE);
  const duplicate = signedPayload({ ...RELEASE, reviewerIds: [222, 222] });
  assert.equal(verifySignedPolicy(duplicate.envelope, duplicate.pem,
    { requirePullBinding: true, expectedPullNumber: 12 }).signatureChecked, false);
  const selfEvidence = signedPayload({ ...RELEASE, guardianAppId: 777 });
  assert.equal(verifySignedPolicy(selfEvidence.envelope, selfEvidence.pem,
    { requirePullBinding: true, expectedPullNumber: 12 }).signatureChecked, false);
});

test('authenticated review and workflow completion event targets remain exact-head bound', () => {
  const secret = 's'.repeat(32);
  const pr = { number: 12, base: { ref: 'main', repo: { full_name: REPO } },
    head: { sha: SHA, repo: { full_name: REPO } } };
  const target = { repository: { full_name: REPO }, installation: { id: 42 } };
  const check = (event, body) => {
    const rawBody = Buffer.from(JSON.stringify(body));
    const sig = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
    return verifyWebhook({ rawBody, trustedInstallationId: 42,
      webhookSecret: secret, headers: {
        'x-hub-signature-256': 'sha256=' + sig,
        'x-github-event': event,
        'x-github-delivery': '12345678-1234-1234-1234-123456789abc',
      } });
  };
  assert.equal(check('pull_request_review', {
    ...target, action: 'submitted', pull_request: pr,
  }).ok, true);
  assert.equal(check('workflow_run', {
    ...target, action: 'completed', workflow_run: {
      head_sha: SHA, conclusion: 'success', pull_requests: [{ number: 12 }],
    },
  }).ok, true);
  assert.equal(check('workflow_run', {
    ...target, action: 'completed', workflow_run: {
      head_sha: SHA, conclusion: 'success', pull_requests: [],
    },
  }).ok, false);
});

test('success Check Run writer refuses default-OFF call before any transport', async () => {
  await assert.rejects(postConclusiveSuccessCheck({
    token: 'not-a-token', headSha: SHA, summary: 'valid summary', appId: 999,
  }), { code: 'GUARDIAN_SUCCESS_CHECK_NOT_AUTHORIZED' });
});

test('owner reconciliation stays OFF without independent host authorization', async () => {
  const result = await processGuardianReconciliation({
    pullNumber: 12, headSha: SHA, host: {}, operatorSession: 'untrusted',
  });
  assert.equal(result.reason, 'OWNER_RECONCILIATION_OFF_OR_INVALID');
  assert.equal(result.activationAllowed, false);
});

test('conclusive provenance requires exact workflow jobs, reviewer and app-pinned rule', async () => {
  const collectorPath = require.resolve('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
  const provenancePath = require.resolve('../merge-gate-install/guardian-candidate/guardian-provenance.cjs');
  const collector = require(collectorPath);
  const prior = collector.readGuardianGithubJson;
  let files = [{ filename: 'src/a.cjs', status: 'modified' }];
  let rulesAppId = 999;
  collector.readGuardianGithubJson = async (path) => {
    if (path.includes('/pulls/12/commits')) return {
      body: [{ sha: SHA, author: { id: 111 }, committer: { id: 111 } }], link: '',
    };
    if (path.includes('/pulls/12/reviews')) return {
      body: [{ id: 60, user: { id: 222, type: 'User' }, state: 'APPROVED',
        submitted_at: '2026-10-23T12:00:00Z', commit_id: SHA }], link: '',
    };
    if (path.includes('/pulls/12/files')) return { body: files, link: '' };
    if (path.includes('/rules/branches/main')) return {
      body: [
        { type: 'required_status_checks', parameters: {
          required_status_checks: [{ context: CHECK, integration_id: rulesAppId }],
        } },
        { type: 'pull_request', parameters: {
          required_approving_review_count: 1,
          dismiss_stale_reviews_on_push: true,
          require_last_push_approval: true,
        } },
      ], link: '',
    };
    const workflow = /\/actions\/workflows\/(\d+)\/runs/.exec(path);
    if (workflow) {
      const n = Number(workflow[1]);
      const id = n === 800 ? 1001 : 1002;
      return { body: { total_count: 1, workflow_runs: [{
        id, workflow_id: n, head_sha: SHA,
        check_suite_id: n === 800 ? 44 : 45, event: 'push',
        status: 'completed', conclusion: 'success', run_attempt: 1,
        created_at: '2026-10-23T12:00:00Z', updated_at: '2026-10-23T12:01:00Z',
        repository: { full_name: REPO },
      }] }, link: '' };
    }
    const jobs = /\/actions\/runs\/(\d+)\/jobs/.exec(path);
    if (jobs) {
      const id = Number(jobs[1]);
      const checkId = id === 1001 ? 501 : 502;
      return { body: { total_count: 1, jobs: [{
        id: checkId + 100, check_run_url:
          'https://api.github.com/repos/nohandsai01/test/check-runs/' + checkId,
        run_id: id, run_attempt: 1, head_sha: SHA,
        name: id === 1001 ? 'tests-run' : 'ci-run',
        status: 'completed', conclusion: 'success',
        completed_at: '2026-10-23T12:01:00Z',
      }] }, link: '' };
    }
    throw new Error('Unexpected GitHub endpoint: ' + path);
  };
  delete require.cache[provenancePath];
  const { collectGuardianConclusiveProvenance } = require(provenancePath);
  const base = { pullNumber: 12, headSha: SHA, installationToken: 'token-with-length',
    guardianAppId: 999, releasePolicy: RELEASE,
    expectedEvidence: [
      { type: 'tests', checkName: 'tests-run', issuerAppId: 777 },
      { type: 'ci', checkName: 'ci-run', issuerAppId: 778 },
    ],
    snapshot: { pullRequest: { number: 12, state: 'open', draft: false,
      author: { id: 111, type: 'User' }, head: { sha: SHA } },
    checkRuns: { check_runs: [
      { id: 501, name: 'tests-run', app: { id: 777 }, check_suite: { id: 44 },
        head_sha: SHA, status: 'completed', conclusion: 'success' },
      { id: 502, name: 'ci-run', app: { id: 778 }, check_suite: { id: 45 },
        head_sha: SHA, status: 'completed', conclusion: 'success' },
    ] } },
  };
  try {
    const okay = await collectGuardianConclusiveProvenance(base);
    assert.equal(okay.approvedCount, 1);
    assert.equal(okay.workflowProofs.length, 2);
    rulesAppId = 1000;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_REQUIRED_CHECK_APP_NOT_PINNED' });
    rulesAppId = 999;
    files = [{ filename: '.github/workflows/hijack.yml', status: 'added' }];
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
  } finally {
    collector.readGuardianGithubJson = prior;
    delete require.cache[provenancePath];
  }
});
