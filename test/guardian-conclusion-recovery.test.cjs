'use strict';
// Offline, source-only reconciliation contract. No actual GitHub API call,
// Check POST, credential creation, D1 mutation or production operation.
const test = require('node:test');
const assert = require('node:assert/strict');
const collectorPath = require.resolve(
  '../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
const modulePath = require.resolve(
  '../merge-gate-install/guardian-candidate/guardian-conclusion-reconcile.cjs');

const REPO = 'nohandsai01/test';
const SHA = 'a'.repeat(40);
const APP = 999;
const NAME = 'NO HANDS Merge Gate Required Check';
const CREATED = '2026-10-26T01:00:00.000Z';
const COMPLETED = '2026-10-26T01:01:00.000Z';
function reservation(overrides = {}) {
  return { repositoryId: 88, pullNumber: 12, headSha: SHA,
    deliveryHash: 'b'.repeat(64), createdAt: CREATED, ...overrides };
}
function check(overrides = {}) {
  return { id: 501, name: NAME, head_sha: SHA, app: { id: APP },
    check_suite: { id: 10 }, status: 'completed', conclusion: 'failure',
    completed_at: COMPLETED, ...overrides };
}
function snapshot(checks = [], extras = {}) {
  return {
    repository: REPO,
    pullRequest: { number: 12, state: 'open',
      base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: SHA, repo: { full_name: REPO } },
    },
    checkRuns: { total_count: checks.length, check_runs: checks },
    ...extras,
  };
}
function input(store) {
  return { repositoryId: 88, pullNumber: 12, headSha: SHA,
    expectedAppId: APP, installationToken: 'synthetic-readonly-installation-token',
    conclusionStore: store };
}
async function scenario({ row = reservation(), checks = [],
  observed = snapshot(checks), githubError = false,
  storeError = false } = {}, call) {
  const collector = require(collectorPath);
  const original = collector.collectAuthenticatedGithubSnapshot;
  const calls = { remote: 0, lookups: 0, writes: 0 };
  const store = Object.freeze({
    getReservation: async ({ repositoryId, pullNumber, headSha }) => {
      calls.lookups++;
      assert.deepEqual([repositoryId, pullNumber, headSha], [88, 12, SHA]);
      if (storeError) throw new Error('synthetic D1 unavailable');
      return row;
    },
    reserveOnce: async () => { calls.writes++; throw new Error('MUST NOT WRITE'); },
  });
  collector.collectAuthenticatedGithubSnapshot = async (args) => {
    calls.remote++;
    assert.equal(args.pullNumber, 12);
    assert.equal(args.expectedHeadSha, SHA);
    assert.ok(args.installationToken.startsWith('synthetic-'));
    if (githubError) throw new Error('synthetic GitHub unavailable');
    return observed;
  };
  delete require.cache[modulePath];
  const { reconcileGuardianConclusion } = require(modulePath);
  try { return await call({ reconcileGuardianConclusion, store, calls }); }
  finally {
    collector.collectAuthenticatedGithubSnapshot = original;
    delete require.cache[modulePath];
  }
}
function safety(result) {
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.trusted, false);
  assert.equal(result.activationAllowed, false);
  assert.equal(result.authoritativeRequiredCheck, 'NOT_ISSUED');
  assert.equal(result.automaticRetryAllowed, false);
  assert.equal(result.releaseAuthorized, false);
  assert.equal(Object.isFrozen(result), true);
}

test('missing reservation avoids all remote reads and never authorizes retry', async () => {
  await scenario({ row: null }, async ({ reconcileGuardianConclusion, store, calls }) => {
    const result = await reconcileGuardianConclusion(input(store));
    assert.equal(result.reason, 'RECONCILIATION_NO_RESERVATION');
    safety(result);
    assert.equal(calls.remote, 0);
    assert.equal(calls.writes, 0);
  });
});

test('uncertain durable read and invalid reservation fail closed', async () => {
  await scenario({ storeError: true }, async ({ reconcileGuardianConclusion, store, calls }) => {
    const result = await reconcileGuardianConclusion(input(store));
    assert.equal(result.reason, 'RECONCILIATION_DURABLE_READ_UNVERIFIED');
    safety(result);
    assert.equal(calls.remote, 0);
  });
  for (const invalid of [reservation({ headSha: 'c'.repeat(40) }),
    reservation({ deliveryHash: 'wrong' }),
    reservation({ createdAt: 'not-a-date' }),
    reservation({ repositoryId: 99 })]) {
    await scenario({ row: invalid }, async ({ reconcileGuardianConclusion, store, calls }) => {
      const result = await reconcileGuardianConclusion(input(store));
      assert.equal(result.reason, 'RECONCILIATION_RESERVATION_INVALID');
      safety(result);
      assert.equal(calls.remote, 0);
    });
  }
});

test('missing Check is an observation and cannot trigger an automatic retry', async () => {
  await scenario({}, async ({ reconcileGuardianConclusion, store, calls }) => {
    const result = await reconcileGuardianConclusion(input(store));
    assert.equal(result.reason,
      'RECONCILIATION_NO_CHECK_OBSERVED_NOT_SAFE_TO_RETRY');
    assert.equal(result.reservationObserved, true);
    safety(result);
    assert.equal(calls.remote, 1);
    assert.equal(calls.writes, 0);
  });
});

test('one completed, correctly attributed Check is observed only, never ALLOW', async () => {
  for (const conclusion of ['failure', 'success']) {
    await scenario({ checks: [check({ conclusion })] },
      async ({ reconcileGuardianConclusion, store, calls }) => {
        const result = await reconcileGuardianConclusion(input(store));
        assert.equal(result.reason, 'RECONCILIATION_CHECK_OBSERVED_ONLY');
        assert.equal(result.observedConclusion, conclusion);
        assert.equal(result.observedCheckRunId, 501);
        assert.equal(result.reservationObserved, true);
        safety(result);
        assert.equal(calls.writes, 0);
      });
  }
});

test('duplicate, wrong issuer, stale timestamp and incomplete Check never reconcile positively', async () => {
  const cases = [
    { checks: [check(), check({ id: 502, conclusion: 'success' })],
      reason: 'RECONCILIATION_AMBIGUOUS_CHECKS' },
    { checks: [check({ app: { id: 1000 } })],
      reason: 'RECONCILIATION_CHECK_ISSUER_OR_SHA_UNVERIFIED' },
    { checks: [check({ head_sha: 'c'.repeat(40) })],
      reason: 'RECONCILIATION_CHECK_ISSUER_OR_SHA_UNVERIFIED' },
    { checks: [check({ status: 'in_progress', conclusion: null })],
      reason: 'RECONCILIATION_CHECK_NOT_CONCLUSIVE' },
    { checks: [check({ completed_at: '2026-10-25T23:59:59Z' })],
      reason: 'RECONCILIATION_CHECK_PREDATES_RESERVATION' },
  ];
  for (const item of cases) {
    await scenario(item, async ({ reconcileGuardianConclusion, store, calls }) => {
      const result = await reconcileGuardianConclusion(input(store));
      assert.equal(result.reason, item.reason);
      safety(result);
      assert.equal(calls.writes, 0);
    });
  }
});

test('GitHub failure or inconsistent snapshot does not mark reconciliation safe', async () => {
  await scenario({ githubError: true },
    async ({ reconcileGuardianConclusion, store }) => {
      const result = await reconcileGuardianConclusion(input(store));
      assert.equal(result.reason, 'RECONCILIATION_GITHUB_EVIDENCE_UNAVAILABLE');
      safety(result);
    });
  await scenario({ observed: snapshot([check()],
    { repository: 'attacker/repository' }) },
    async ({ reconcileGuardianConclusion, store }) => {
      const result = await reconcileGuardianConclusion(input(store));
      assert.equal(result.reason, 'RECONCILIATION_SNAPSHOT_INVALID');
      safety(result);
    });
  await scenario({ observed: snapshot([check()], { checkRuns: {
    total_count: 2, check_runs: [check()],
  } }) }, async ({ reconcileGuardianConclusion, store }) => {
    const result = await reconcileGuardianConclusion(input(store));
    assert.equal(result.reason, 'RECONCILIATION_SNAPSHOT_INVALID');
    safety(result);
  });
});

test('untrusted caller input never reads D1 or GitHub', async () => {
  await scenario({}, async ({ reconcileGuardianConclusion, store, calls }) => {
    for (const altered of [
      { repositoryId: 0 }, { expectedAppId: 0 }, { headSha: 'BAD' },
      { installationToken: 'invalid' }, { conclusionStore: {} },
    ]) {
      const result = await reconcileGuardianConclusion({
        ...input(store), ...altered,
      });
      assert.equal(result.reason,
        'RECONCILIATION_INPUT_OR_OWNER_AUTHORITY_INVALID');
      safety(result);
    }
    assert.equal(calls.lookups, 0);
    assert.equal(calls.remote, 0);
  });
});
