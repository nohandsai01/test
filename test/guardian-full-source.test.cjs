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

test('conflicting raw write switches HOLD before any external reservation', async () => {
  let writes = 0;
  const result = await processGuardianReconciliation({
    pullNumber: 12, headSha: SHA, operatorSession: 'owner',
    host: {
      enableOwnerReconciliation: true,
      ownerReconciliationGrant: 'EXPLICIT_OWNER_RECONCILIATION',
      authorizeReconciliation: async () => true,
      reconciliationRateLimiter: { allow: async () => true },
      trustedInstallationId: 42,
      enableFullCheckWrites: true,
      founderAuthorizedFullMode: 'EXPLICIT_FULL_CHECK_WRITES',
      enableFailureCheckWrites: true,
      // Deliberately missing the failure-only grant: the old mode calculation
      // would have incorrectly selected full mode.
      deliveryStore: { reserveOnce: async () => { writes++; return true; } },
    },
  });
  assert.equal(result.reason, 'FEATURE_OFF');
  assert.equal(result.activationAllowed, false);
  assert.equal(writes, 0);
});

test('conclusive provenance requires exact workflow jobs, reviewer and app-pinned rule', async () => {
  const collectorPath = require.resolve('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
  const provenancePath = require.resolve('../merge-gate-install/guardian-candidate/guardian-provenance.cjs');
  const collector = require(collectorPath);
  const prior = collector.readGuardianGithubJson;
  let files = [{ filename: 'src/a.cjs', status: 'modified' }];
  let driftFirstFilePage = false;
  let firstFilePageReads = 0;
  let rulesAppId = 999;
  let rulesetBypassActors = [];
  let rulesetIdentity = 'valid';
  let extraRuleset = false;
  let extraRulesetBypassActors = [];
  let ruleChecks = [
    { context: CHECK, integration_id: 999 },
    { context: 'tests-run', integration_id: 777 },
    { context: 'ci-run', integration_id: 778 },
  ];
  collector.readGuardianGithubJson = async (path) => {
    if (path.includes('/pulls/12/commits')) return {
      body: [{ sha: SHA, author: { id: 111 }, committer: { id: 111 } }], link: '',
    };
    if (path.includes('/pulls/12/reviews')) return {
      body: [{ id: 60, user: { id: 222, type: 'User' }, state: 'APPROVED',
        submitted_at: '2026-10-23T12:00:00Z', commit_id: SHA }], link: '',
    };
    if (path.includes('/pulls/12/files')) {
      const page = Number(new URL(path, 'https://api.github.com').searchParams.get('page'));
      const start = (page - 1) * 25;
      let rows = files.slice(start, start + 25);
      if (page === 1 && driftFirstFilePage && ++firstFilePageReads === 2) {
        rows = rows.map((item, index) => index === 0 ?
          { ...item, filename: 'src/changed-during-read.cjs' } : item);
      }
      return {
        body: rows,
        link: start + 25 < files.length ?
          '<https://api.github.com/repos/nohandsai01/test/pulls/12/files?page=' +
            (page + 1) + '>; rel="next"' : '',
      };
    }
    if (path.includes('/rules/branches/main')) return {
      body: [
        { type: 'required_status_checks', ruleset_id: rulesetIdentity === 'missing' ? undefined : 101,
          ruleset_source_type: 'Repository', ruleset_source: REPO, parameters: {
          required_status_checks: ruleChecks.map((item) => item.context === CHECK ?
            { ...item, integration_id: rulesAppId } : item),
        } },
        { type: 'pull_request', ruleset_id: 101,
          ruleset_source_type: 'Repository', ruleset_source: REPO, parameters: {
          required_approving_review_count: 1,
          dismiss_stale_reviews_on_push: true,
          require_last_push_approval: true,
        } },
        ...(extraRuleset ? [{ type: 'creation', ruleset_id: 102,
          ruleset_source_type: 'Repository', ruleset_source: REPO }] : []),
      ], link: '',
    };
    if (path.endsWith('/rulesets/101')) return {
      body: {
        id: 101, target: 'branch', source_type: 'Repository', source: REPO,
        enforcement: 'active',
        ...(rulesetBypassActors === undefined ? {} : { bypass_actors: rulesetBypassActors }),
      }, link: '',
    };
    if (path.endsWith('/rulesets/102')) return {
      body: { id: 102, target: 'branch', source_type: 'Repository', source: REPO,
        enforcement: 'active', bypass_actors: extraRulesetBypassActors }, link: '',
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
      changedFiles: 1, commitCount: 1,
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
    assert.equal(okay.rulesetBypassActorsVerified, true);
    for (const bypass_mode of ['always', 'pull_request', 'exempt']) {
      rulesetBypassActors = [{ actor_type: 'RepositoryRole', actor_id: 5, bypass_mode }];
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_RULESET_BYPASS_ACTORS_PRESENT' });
    }
    rulesetBypassActors = undefined; // GitHub omits this without ruleset write access.
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_RULESET_BYPASS_ACTORS_UNOBSERVABLE' });
    rulesetBypassActors = [];
    extraRuleset = true;
    const multipleOkay = await collectGuardianConclusiveProvenance(base);
    assert.equal(multipleOkay.rulesetBypassActorsVerified, true);
    extraRulesetBypassActors = [{ actor_type: 'User', actor_id: 77, bypass_mode: 'always' }];
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_RULESET_BYPASS_ACTORS_PRESENT' });
    extraRuleset = false;
    extraRulesetBypassActors = [];
    rulesetIdentity = 'missing';
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_ACTIVE_RULESET_IDENTITY_UNVERIFIED' });
    rulesetIdentity = 'valid';
    rulesAppId = 1000;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_REQUIRED_CHECK_APP_NOT_PINNED' });
    rulesAppId = 999;
    ruleChecks = ruleChecks.filter((item) => item.context !== 'ci-run');
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_EVIDENCE_REQUIRED_CHECK_APP_NOT_PINNED' });
    ruleChecks.push({ context: 'ci-run', integration_id: 779 });
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_EVIDENCE_REQUIRED_CHECK_APP_NOT_PINNED' });
    ruleChecks[ruleChecks.length - 1].integration_id = 778;
    ruleChecks.push({ context: 'ci-run', integration_id: 778 });
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_EVIDENCE_REQUIRED_CHECK_APP_NOT_PINNED' });
    ruleChecks.pop();
    files = [{ filename: '.github/workflows/hijack.yml', status: 'added' }];
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
    // A GitHub rename reports both paths. An allowed destination must not
    // conceal a workflow or traversal-containing origin.
    for (const oldPath of [
      '.github/workflows/hijack.yml',
      'src/../.github/workflows/hijack.yml',
      'src/./legacy.cjs',
      'src//legacy.cjs',
    ]) {
      files = [{ filename: 'src/moved.cjs', previous_filename: oldPath, status: 'renamed' }];
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
    }
    files = [{ filename: 'src/../docs/moved.cjs',
      previous_filename: 'src/legacy.cjs', status: 'renamed' }];
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
    // Copied files need the same source check. Missing, protected, or
    // malformed origins must fail closed even with a safe destination.
    for (const operation of ['renamed', 'copied']) {
      for (const oldPath of [
        '.github/workflows/protected.yml', 'src/../protected.yml',
        'docs/./nested.md', 'test//fixture.cjs',
        'src/legacy.cjs/..', 'src/legacy.cjs',
      ]) {
        const dest = oldPath === 'src/legacy.cjs' ?
          'src/legacy.cjs' : 'src/moved.cjs';
        files = [{ filename: dest, previous_filename: oldPath,
          status: operation }];
        await assert.rejects(collectGuardianConclusiveProvenance(base),
          { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
      }
      files = [{ filename: 'src/moved.cjs', status: operation }];
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
      files = [{ filename: 'src/moved.cjs', previous_filename: null,
        status: operation }];
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
      files = [{ filename: 'src/moved.cjs', previous_filename: 'src/legacy.cjs',
        status: operation }];
      const validMove = await collectGuardianConclusiveProvenance(base);
      assert.equal(validMove.changedFileCount, 1);
    }
    // A change with a conflicting rename/copy origin cannot be reclassified
    // as an ordinary add or edit to bypass source provenance validation.
    for (const operation of ['added', 'modified', 'removed', 'changed']) {
      files = [{ filename: 'src/moved.cjs', status: operation,
        previous_filename: '.github/workflows/protected.yml' }];
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' });
      files = [{ filename: 'src/moved.cjs', status: operation }];
      const validOrdinary = await collectGuardianConclusiveProvenance(base);
      assert.equal(validOrdinary.changedFileCount, 1);
    }
    files = [{ filename: 'src/duplicate.cjs', status: 'modified' },
      { filename: 'src/duplicate.cjs', status: 'renamed',
        previous_filename: 'src/legacy.cjs' }];
    base.snapshot.pullRequest.changedFiles = 2;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_FILE_RESPONSE_INVALID' });
    files = [{ filename: 'src/first.cjs', status: 'renamed',
      previous_filename: 'src/original.cjs' },
      { filename: 'src/second.cjs', status: 'renamed',
        previous_filename: 'src/original.cjs' }];
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_DUPLICATE_RENAME_ORIGIN' });
    // GitHub can legitimately report multiple copies of the same source.
    files[0].status = 'copied';
    files[1].status = 'copied';
    assert.equal((await collectGuardianConclusiveProvenance(base)).changedFileCount, 2);
    // PR-level file count is independent from the array returned by GitHub
    // pagination. Missing, excess, or out-of-cap counts all HOLD.
    files = [{ filename: 'src/a.cjs', status: 'modified' }];
    base.snapshot.pullRequest.changedFiles = 2;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_CHANGED_FILE_COUNT_MISMATCH' });
    files = [{ filename: 'src/a.cjs', status: 'modified' },
      { filename: 'src/b.cjs', status: 'modified' }];
    base.snapshot.pullRequest.changedFiles = 1;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_CHANGED_FILE_COUNT_MISMATCH' });
    for (const badCount of [undefined, null, -1, 0, 301, '1', 1.5]) {
      base.snapshot.pullRequest.changedFiles = badCount;
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_PR_CHANGED_FILE_COUNT_UNVERIFIED' });
    }
    base.snapshot.pullRequest.changedFiles = 2;
    const complete = await collectGuardianConclusiveProvenance(base);
    assert.equal(complete.changedFileCount, 2);
    // PR commit counts are read independently of the commit-page list.
    // An omitted contributor at the pagination cap must not be ignored.
    for (const badCount of [undefined, null, 0, -1, 251, '1', 1.1]) {
      base.snapshot.pullRequest.commitCount = badCount;
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_PR_COMMIT_COUNT_UNVERIFIED' });
    }
    base.snapshot.pullRequest.commitCount = 2;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PR_COMMIT_COUNT_MISMATCH' });
    base.snapshot.pullRequest.commitCount = 1;
    assert.equal((await collectGuardianConclusiveProvenance(base)).changedFileCount, 2);
    // Two GitHub pages are accepted only when every row and the independent
    // PR-level changed_files count agree.
    files = Array.from({ length: 26 }, (_, index) => ({
      filename: 'src/safe-' + index + '.cjs', status: 'modified',
    }));
    base.snapshot.pullRequest.changedFiles = 26;
    assert.equal((await collectGuardianConclusiveProvenance(base)).changedFileCount, 26);
    // Same count and pagination structure but a modified first page must
    // reject, rather than mix old/new rows into one false positive proof.
    driftFirstFilePage = true;
    firstFilePageReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PROVENANCE_PAGE_CHANGED' });
    driftFirstFilePage = false;
    files = [{ filename: 'src/a.cjs', status: 'modified' }];
    base.snapshot.pullRequest.changedFiles = 1;
    assert.equal((await collectGuardianConclusiveProvenance(base)).changedFileCount, 1);
  } finally {
    collector.readGuardianGithubJson = prior;
    delete require.cache[provenancePath];
  }
});
