'use strict';
// Operator diagnostic batch is entirely read-only. Fake providers exercise the
// actual single-PR reconcile path; no GitHub token or D1 write is performed.
const test = require('node:test');
const assert = require('node:assert/strict');
const collectorPath = require.resolve('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
const reconcilePath = require.resolve('../merge-gate-install/guardian-candidate/guardian-conclusion-reconcile.cjs');
const batchPath = require.resolve('../merge-gate-install/guardian-candidate/guardian-conclusion-batch.cjs');
const REPO = 'nohandsai01/test';
const NAME = 'NO HANDS Merge Gate Required Check';
const APP = 999;
const TOKEN = 'synthetic-protected-installation-token-NEVER-LEAK';
const sha = value => value.repeat(40);
const item = (pullNumber, c = 'a') => ({ pullNumber, headSha: sha(c) });
function row(target, overrides = {}) {
  return { repositoryId: 88, pullNumber: target.pullNumber,
    headSha: target.headSha, deliveryHash: 'd'.repeat(64),
    createdAt: '2026-10-26T01:00:00.000Z', ...overrides };
}
function check(target, overrides = {}) {
  return { id: 1000 + target.pullNumber, name: NAME,
    head_sha: target.headSha, app: { id: APP }, status: 'completed',
    conclusion: 'success', completed_at: '2026-10-26T01:01:00Z',
    ...overrides };
}
function snapshot(target, checks = [], overrides = {}) {
  return {
    repository: REPO,
    pullRequest: { number: target.pullNumber, state: 'open',
      base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: target.headSha, repo: { full_name: REPO } },
    },
    checkRuns: { total_count: checks.length, check_runs: checks },
    ...overrides,
  };
}
function args(targets, conclusionStore) {
  return { repositoryId: 88, targets, expectedAppId: APP,
    installationToken: TOKEN, conclusionStore };
}
function noAuthority(result) {
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.status, 'SOURCE_ONLY_HOLD');
  assert.equal(result.trusted, false);
  assert.equal(result.activationAllowed, false);
  assert.equal(result.releaseAuthorized, false);
  assert.equal(result.automaticRetryAllowed, false);
  assert.equal(result.authoritativeRequiredCheck, 'NOT_ISSUED');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.entries), true);
  assert.equal(Object.isFrozen(result.countsByReason), true);
  assert.ok(!JSON.stringify(result).includes(TOKEN));
  assert.ok(!JSON.stringify(result).includes('d'.repeat(64)));
  for (const entry of result.entries) {
    assert.equal(entry.status, 'SOURCE_ONLY_HOLD');
    assert.equal(Object.isFrozen(entry), true);
    assert.ok(!Object.hasOwn(entry, 'installationToken'));
    assert.ok(!Object.hasOwn(entry, 'deliveryHash'));
  }
}
// One fake trusted owner backend is installed for the entire, serial batch.
// It captures any attempted write and throws; successful tests prove none.
async function withBackend(lookup, read, fn) {
  const collector = require(collectorPath);
  const original = collector.collectAuthenticatedGithubSnapshot;
  const calls = { d1: [], github: [], writes: 0, active: 0, maxActive: 0 };
  const conclusionStore = Object.freeze({
    async getReservation(target) {
      calls.d1.push({ ...target });
      return lookup(target, calls);
    },
    async reserveOnce() { calls.writes++; throw Error('NEVER_RESERVE'); },
    async clearReservation() { calls.writes++; throw Error('NEVER_CLEAR'); },
  });
  collector.collectAuthenticatedGithubSnapshot = async ({ pullNumber,
    expectedHeadSha, installationToken }) => {
    calls.github.push({ pullNumber, headSha: expectedHeadSha });
    assert.equal(installationToken, TOKEN);
    calls.active++;
    calls.maxActive = Math.max(calls.maxActive, calls.active);
    try { return await read(item(pullNumber, expectedHeadSha[0]), calls); }
    finally { calls.active--; }
  };
  delete require.cache[reconcilePath];
  delete require.cache[batchPath];
  const { reconcileGuardianConclusionBatch, MAX_BATCH_TARGETS } = require(batchPath);
  try {
    await fn({ reconcileGuardianConclusionBatch, MAX_BATCH_TARGETS,
      conclusionStore, calls });
  } finally {
    collector.collectAuthenticatedGithubSnapshot = original;
    delete require.cache[reconcilePath];
    delete require.cache[batchPath];
  }
}

test('multi-PR triage reports missing reservation, observed Check and conflicting Checks without authority', async () => {
  const targets = [item(12), item(13, 'b'), item(14, 'c')];
  await withBackend(t => t.pullNumber === 12 ? null : row(t),
    t => snapshot(t, t.pullNumber === 14
      ? [check(t), check(t, { id: 3000, conclusion: 'failure' })]
      : [check(t)]), async ({ reconcileGuardianConclusionBatch, conclusionStore, calls }) => {
      const result = await reconcileGuardianConclusionBatch(args(targets, conclusionStore));
      noAuthority(result);
      assert.equal(result.reason, 'RECONCILIATION_BATCH_OBSERVATIONS_ONLY');
      assert.equal(result.evaluatedTargetCount, 3);
      assert.equal(result.maximumTargetCount, 8);
      assert.deepEqual(result.entries.map(e => e.reason), [
        'RECONCILIATION_NO_RESERVATION',
        'RECONCILIATION_CHECK_OBSERVED_ONLY',
        'RECONCILIATION_AMBIGUOUS_CHECKS',
      ]);
      assert.equal(result.entries[1].observedConclusion, 'success');
      assert.equal(result.entries[1].observedCheckRunId, 1013);
      assert.equal(result.entries[2].observedMatchingNameCount, 2);
      assert.equal(result.entries[0].remoteReadPerformed, false);
      assert.deepEqual(Object.values(result.countsByReason).sort(), [1, 1, 1]);
      assert.equal(calls.d1.length, 3);
      assert.equal(calls.github.length, 2, 'no reservation means no GitHub read');
      assert.equal(calls.writes, 0);
    });
});

test('invalid, repeated, oversized and adversarial targets fail atomically before any D1/GitHub', async () => {
  await withBackend(t => row(t), t => snapshot(t),
    async ({ reconcileGuardianConclusionBatch: batch, conclusionStore, calls, MAX_BATCH_TARGETS }) => {
      assert.equal(MAX_BATCH_TARGETS, 8);
      const bad = [undefined, null, [], Array.from({ length: 9 }, (_, k) => item(k + 1)),
        [item(12), item(12)], [item(12), { ...item(13), headSha: sha('A') }],
        [item(12), { ...item(13), pullNumber: 0 }],
        [item(12), { ...item(13), pullNumber: 1.5 }],
        [item(12), { ...item(13), headSha: 'bad-sha' }],
        [item(12), null], [item(12), ['array']],
        [item(12), { get pullNumber() { throw Error('SECRET-LEAK'); } }],
      ];
      for (const targets of bad) {
        const result = await batch(args(targets, conclusionStore));
        noAuthority(result);
        assert.equal(result.reason, 'RECONCILIATION_BATCH_INPUT_INVALID');
        assert.equal(result.entries.length, 0);
      }
      for (const overrides of [
        { repositoryId: 0 }, { repositoryId: '88' },
        { expectedAppId: -1 }, { conclusionStore: {} },
        { installationToken: 'too-short' },
        { installationToken: 'x'.repeat(4097) },
        { installationToken: TOKEN + '\n' },
      ]) {
        const result = await batch({ ...args([item(12)], conclusionStore), ...overrides });
        noAuthority(result);
        assert.equal(result.reason, 'RECONCILIATION_BATCH_INPUT_INVALID');
      }
      assert.equal(calls.d1.length, 0);
      assert.equal(calls.github.length, 0);
      assert.equal(calls.writes, 0);
    });
});

test('one failing read does not contaminate other results, all are HOLD', async () => {
  await withBackend(t => {
    if (t.pullNumber === 13) throw Error('SECRET-D1-ERROR');
    return row(t);
  }, t => {
    if (t.pullNumber === 14) throw Error('SECRET-GITHUB-ERROR');
    return snapshot(t, [check(t)]);
  }, async ({ reconcileGuardianConclusionBatch: batch, conclusionStore, calls }) => {
    const result = await batch(args([item(12), item(13), item(14), item(15)], conclusionStore));
    noAuthority(result);
    assert.deepEqual(result.entries.map(e => e.reason), [
      'RECONCILIATION_CHECK_OBSERVED_ONLY',
      'RECONCILIATION_DURABLE_READ_UNVERIFIED',
      'RECONCILIATION_GITHUB_EVIDENCE_UNAVAILABLE',
      'RECONCILIATION_CHECK_OBSERVED_ONLY',
    ]);
    assert.equal(calls.d1.length, 4);
    assert.equal(calls.github.length, 3);
    assert.ok(!JSON.stringify(result).includes('SECRET'));
    assert.equal(calls.writes, 0);
  });
});

test('snapshot identity binds inputs before the first await; later caller mutation cannot retarget reads', async () => {
  const targets = [item(12), item(13)];
  await withBackend(async t => {
    // Caller edits array and object AFTER the first asynchronous read.
    if (t.pullNumber === 12) {
      targets[1].pullNumber = 777;
      targets[1].headSha = sha('f');
      targets.push(item(99));
    }
    return row(t);
  }, t => snapshot(t, [check(t)]), async ({ reconcileGuardianConclusionBatch: batch, conclusionStore, calls }) => {
    const report = await batch(args(targets, conclusionStore));
    noAuthority(report);
    assert.deepEqual(report.entries.map(e => e.pullNumber), [12, 13]);
    assert.deepEqual(calls.d1.map(x => x.pullNumber), [12, 13]);
    assert.deepEqual(calls.github.map(x => x.pullNumber), [12, 13]);
    assert.equal(calls.writes, 0);
  });
});

test('max eight targets are serialized and never authorize a second Check POST', async () => {
  await withBackend(t => row(t), async t => {
    await Promise.resolve();
    return snapshot(t, [check(t)]);
  }, async ({ reconcileGuardianConclusionBatch: batch, conclusionStore, calls }) => {
    const targets = Array.from({ length: 8 }, (_, k) => item(k + 1));
    const report = await batch(args(targets, conclusionStore));
    noAuthority(report);
    assert.equal(report.entries.length, 8);
    assert.equal(report.countsByReason.RECONCILIATION_CHECK_OBSERVED_ONLY, 8);
    assert.equal(calls.maxActive, 1, 'never burst into concurrent remote reads');
    assert.equal(calls.github.length, 8);
    assert.equal(calls.writes, 0);
  });
});

test('GitHub repo/issuer/head conflict and stale Check stay classified only, never trusted', async () => {
  await withBackend(t => row(t), t => {
    if (t.pullNumber === 12) return snapshot(t, [check(t, { app: { id: 444 } })]);
    if (t.pullNumber === 13) return snapshot(t, [check(t)], { repository: 'untrusted/repo' });
    if (t.pullNumber === 14) return snapshot(t, [check(t, { completed_at: '2026-10-25T23:00:00Z' })]);
    return snapshot(t, [check(t, { status: 'in_progress', conclusion: null })]);
  }, async ({ reconcileGuardianConclusionBatch: batch, conclusionStore }) => {
    const report = await batch(args([item(12), item(13), item(14), item(15)], conclusionStore));
    noAuthority(report);
    assert.deepEqual(report.entries.map(e => e.reason), [
      'RECONCILIATION_CHECK_ISSUER_OR_SHA_UNVERIFIED',
      'RECONCILIATION_SNAPSHOT_INVALID',
      'RECONCILIATION_CHECK_PREDATES_RESERVATION',
      'RECONCILIATION_CHECK_NOT_CONCLUSIVE',
    ]);
  });
});

test('import and invalid input do not open external resources or request write authority', async () => {
  // A module import cannot do I/O; no caller token or owner store is present.
  delete require.cache[batchPath];
  const { reconcileGuardianConclusionBatch: batch } = require(batchPath);
  const result = await batch();
  noAuthority(result);
  assert.equal(result.reason, 'RECONCILIATION_BATCH_INPUT_INVALID');
  assert.equal(result.entries.length, 0);
});
