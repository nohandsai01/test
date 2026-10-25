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
    review: { state: 'approved', commit_id: SHA },
  }).ok, true);
  assert.equal(check('pull_request_review', {
    ...target, action: 'submitted', pull_request: pr,
    review: { state: 'approved', commit_id: 'b'.repeat(40) },
  }).reason, 'WEBHOOK_REVIEW_EXACT_HEAD_UNVERIFIED');
  assert.equal(check('pull_request_review', {
    ...target, action: 'dismissed', pull_request: pr,
    review: { state: 'dismissed', commit_id: SHA },
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
  let driftSecondFilePage = false;
  let secondFilePageReads = 0;
  let driftWorkflowRuns = false;
  let workflowRunReads = 0;
  let competingWorkflowRun = false;
  let jobAttempt = 1;
  let jobCompletedAt = '2026-10-23T12:01:00Z';
  let driftWorkflowJobs = false;
  let workflowJobReads = 0;
  let driftReviewPage = false;
  let driftReviewAfterWorkflows = false;
  let reviewPageReads = 0;
  let driftRulesAfterWorkflows = false;
  let branchRuleReads = 0;
  let driftRulesetAfterWorkflows = false;
  let rulesetReads = 0;
  let commits = [{ sha: SHA, author: { id: 111 }, committer: { id: 111 } }];
  let reviews = [{ id: 60, user: { id: 222, type: 'User' }, state: 'APPROVED',
    submitted_at: '2026-10-23T12:00:00Z', commit_id: SHA }];
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
      body: commits, link: '',
    };
    if (path.includes('/pulls/12/reviews')) {
      ++reviewPageReads;
      const mutate = (driftReviewPage && reviewPageReads === 2) ||
        (driftReviewAfterWorkflows && reviewPageReads >= 3);
      return { body: mutate ? reviews.map((review) => ({
        ...review, state: 'CHANGES_REQUESTED',
      })) : reviews, link: '' };
    }
    if (path.includes('/pulls/12/files')) {
      const page = Number(new URL(path, 'https://api.github.com').searchParams.get('page'));
      const start = (page - 1) * 25;
      let rows = files.slice(start, start + 25);
      if (page === 1 && driftFirstFilePage && ++firstFilePageReads === 2) {
        rows = rows.map((item, index) => index === 0 ?
          { ...item, filename: 'src/changed-during-read.cjs' } : item);
      }
      if (page === 2 && driftSecondFilePage && ++secondFilePageReads === 2) {
        rows = rows.map((item, index) => index === 0 ?
          { ...item, filename: 'src/changed-middle-page.cjs' } : item);
      }
      return {
        body: rows,
        link: start + 25 < files.length ?
          '<https://api.github.com/repos/nohandsai01/test/pulls/12/files?page=' +
            (page + 1) + '>; rel="next"' : '',
      };
    }
    if (path.includes('/rules/branches/main')) {
      ++branchRuleReads;
      const lateChange = driftRulesAfterWorkflows && branchRuleReads >= 2;
      return { body: [
        { type: 'required_status_checks', ruleset_id: rulesetIdentity === 'missing' ? undefined : 101,
          ruleset_source_type: 'Repository', ruleset_source: REPO, parameters: {
          required_status_checks: ruleChecks.map((item) => item.context === CHECK ?
            { ...item, integration_id: lateChange ? 12345 : rulesAppId } : item),
        } },
        { type: 'pull_request', ruleset_id: 101,
          ruleset_source_type: 'Repository', ruleset_source: REPO, parameters: {
          required_approving_review_count: 1,
          dismiss_stale_reviews_on_push: true,
          require_last_push_approval: true,
        } },
        ...(extraRuleset ? [{ type: 'creation', ruleset_id: 102,
          ruleset_source_type: 'Repository', ruleset_source: REPO }] : []),
      ], link: '' };
    }
    if (path.endsWith('/rulesets/101')) {
      ++rulesetReads;
      return { body: {
        id: 101, target: 'branch', source_type: 'Repository', source: REPO,
        enforcement: driftRulesetAfterWorkflows && rulesetReads >= 2 ?
          'disabled' : 'active',
        ...(rulesetBypassActors === undefined ? {} : { bypass_actors: rulesetBypassActors }),
      }, link: '' };
    }
    if (path.endsWith('/rulesets/102')) return {
      body: { id: 102, target: 'branch', source_type: 'Repository', source: REPO,
        enforcement: 'active', bypass_actors: extraRulesetBypassActors }, link: '',
    };
    const workflow = /\/actions\/workflows\/(\d+)\/runs/.exec(path);
    if (workflow) {
      const n = Number(workflow[1]);
      const id = n === 800 ? 1001 : 1002;
      const mutated = n === 800 && driftWorkflowRuns && ++workflowRunReads === 2;
      const primary = {
        id, workflow_id: n, head_sha: SHA,
        check_suite_id: n === 800 ? 44 : 45, event: 'push',
        status: 'completed', conclusion: mutated ? 'failure' : 'success', run_attempt: 1,
        created_at: '2026-10-23T12:00:00Z', updated_at: '2026-10-23T12:01:00Z',
        repository: { full_name: REPO },
      };
      const runs = [primary];
      if (competingWorkflowRun && n === 800) {
        runs.push({ ...primary, id: 1099, check_suite_id: 99,
          conclusion: 'failure', run_attempt: 2 });
      }
      return { body: { total_count: runs.length, workflow_runs: runs }, link: '' };
    }
    const jobs = /\/actions\/runs\/(\d+)\/jobs/.exec(path);
    if (jobs) {
      const id = Number(jobs[1]);
      const checkId = id === 1001 ? 501 : 502;
      const mutated = id === 1001 && driftWorkflowJobs && ++workflowJobReads === 2;
      return { body: { total_count: 1, jobs: [{
        id: checkId + 100, check_run_url:
          'https://api.github.com/repos/nohandsai01/test/check-runs/' + checkId,
        run_id: id, run_attempt: jobAttempt, head_sha: SHA,
        name: id === 1001 ? 'tests-run' : 'ci-run',
        status: 'completed', conclusion: mutated ? 'failure' : 'success',
        completed_at: jobCompletedAt,
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
    checkRuns: { total_count: 2, check_runs: [
      { id: 501, name: 'tests-run', app: { id: 777 }, check_suite: { id: 44 },
        head_sha: SHA, status: 'completed', conclusion: 'success',
        completed_at: '2026-10-23T12:01:00Z' },
      { id: 502, name: 'ci-run', app: { id: 778 }, check_suite: { id: 45 },
        head_sha: SHA, status: 'completed', conclusion: 'success',
        completed_at: '2026-10-23T12:01:00Z' },
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
    driftSecondFilePage = true;
    secondFilePageReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PROVENANCE_PAGE_CHANGED' });
    driftSecondFilePage = false;
    files = [{ filename: 'src/a.cjs', status: 'modified' }];
    base.snapshot.pullRequest.changedFiles = 1;
    assert.equal((await collectGuardianConclusiveProvenance(base)).changedFileCount, 1);

    // The PR's required workflow and job lists are mutable during reading.
    // Reject a disappearing success even when the list count stays unchanged.
    driftWorkflowRuns = true;
    workflowRunReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PROVENANCE_PAGE_CHANGED' });
    driftWorkflowRuns = false;
    driftWorkflowJobs = true;
    workflowJobReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PROVENANCE_PAGE_CHANGED' });
    driftWorkflowJobs = false;
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);

    // Any unlinked author or committer makes reviewer independence unprovable.
    for (const incomplete of [
      { sha: SHA, author: null, committer: { id: 111 } },
      { sha: SHA, author: { id: 111 }, committer: null },
      { sha: SHA, author: { id: '111' }, committer: { id: 111 } },
    ]) {
      commits = [incomplete];
      await assert.rejects(collectGuardianConclusiveProvenance(base),
        { code: 'GUARDIAN_COMMIT_ACTOR_IDENTITY_UNVERIFIED' });
    }
    commits = [{ sha: SHA, author: { id: 222 }, committer: { id: 111 } }];
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_REVIEWER_IS_COMMIT_CONTRIBUTOR' });
    commits = [{ sha: SHA, author: { id: 111 }, committer: { id: 111 } }];

    // A blocking review by an outsider cannot be hidden by a distinct
    // allowed approver. A later dismissal of that review restores eligibility.
    reviews.push({ id: 61, user: { id: 333, type: 'User' },
      state: 'CHANGES_REQUESTED', submitted_at: '2026-10-23T12:01:00Z',
      commit_id: SHA });
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_REVIEW_CHANGES_REQUESTED' });
    reviews.push({ id: 62, user: { id: 333, type: 'User' },
      state: 'DISMISSED', submitted_at: '2026-10-23T12:02:00Z',
      commit_id: SHA });
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);
    reviews = reviews.slice(0, 1);
    driftReviewPage = true;
    reviewPageReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_PROVENANCE_PAGE_CHANGED' });
    driftReviewPage = false;
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);

    // A reviewer may revoke approval only after all initial review pages
    // were stable. The final second-pass review comparison must still HOLD.
    driftReviewAfterWorkflows = true;
    reviewPageReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_REVIEWS_CHANGED_DURING_PROVENANCE' });
    driftReviewAfterWorkflows = false;
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);

    // Same branch status-check contexts changing late cannot borrow an
    // earlier Guardian pin or required-check protection observation.
    driftRulesAfterWorkflows = true;
    branchRuleReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_RULES_CHANGED_DURING_PROVENANCE' });
    driftRulesAfterWorkflows = false;
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);

    // A ruleset can become inactive after its first trusted observation.
    driftRulesetAfterWorkflows = true;
    rulesetReads = 0;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_ACTIVE_RULESET_IDENTITY_UNVERIFIED' });
    driftRulesetAfterWorkflows = false;
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);

    // A conflicting red Check is not hidden by picking an earlier green
    // Check with the same required workflow context.
    base.snapshot.checkRuns.check_runs.push({
      ...base.snapshot.checkRuns.check_runs[0], id: 909,
      conclusion: 'failure',
    });
    base.snapshot.checkRuns.total_count = 3;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_WORKFLOW_EXPECTED_CHECK_MISSING' });
    base.snapshot.checkRuns.check_runs.pop();
    base.snapshot.checkRuns.total_count = 2;

    // Even a second same-head run of the approved workflow is ambiguous,
    // regardless of which check-suite is linked to the passing Check.
    competingWorkflowRun = true;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_WORKFLOW_RUN_AMBIGUOUS' });
    competingWorkflowRun = false;

    // A stale job or check cannot be claimed after the run has ended or
    // before the run started; exact attempt numbers are also required.
    jobAttempt = 2;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_CHECK_NOT_ASSOCIATED_WITH_WORKFLOW_JOB' });
    jobAttempt = 1;
    jobCompletedAt = '2026-10-23T12:05:00Z';
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_CHECK_NOT_ASSOCIATED_WITH_WORKFLOW_JOB' });
    jobCompletedAt = '2026-10-23T12:01:00Z';
    base.snapshot.checkRuns.check_runs[0].completed_at = '2026-10-23T11:59:59Z';
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_CHECK_NOT_ASSOCIATED_WITH_WORKFLOW_JOB' });
    base.snapshot.checkRuns.check_runs[0].completed_at = '2026-10-23T12:01:00Z';
    base.snapshot.checkRuns.total_count = 1;
    await assert.rejects(collectGuardianConclusiveProvenance(base),
      { code: 'GUARDIAN_CONCLUSIVE_INPUT_INVALID' });
    base.snapshot.checkRuns.total_count = 2;
    assert.equal((await collectGuardianConclusiveProvenance(base)).approvedCount, 1);
  } finally {
    collector.readGuardianGithubJson = prior;
    delete require.cache[provenancePath];
  }
});
