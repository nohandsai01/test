'use strict';

// Source-only orchestration contract. All GitHub HTTP, signing, storage and
// Check writers are synthetic. No network access, credentials or real writes.
const test = require('node:test');
const assert = require('node:assert/strict');

const SHA = 'a'.repeat(40);
const APP = 999;
const INSTALL = 42;
const OWNER = 100;
const REPOSITORY = 88;
const REPO = 'nohandsai01/test';
const URL = '/repos/nohandsai01/test/pulls/12';
const secret = 'synthetic-host-webhook-secret-' + 'z'.repeat(35);

const modulePaths = {
  runtime: require.resolve('../merge-gate-install/guardian-candidate/guardian-webhook-runtime.cjs'),
  collector: require.resolve('../merge-gate-install/guardian-candidate/github-rest-collector.cjs'),
  api: require.resolve('../merge-gate-install/guardian-candidate/github-app-identity.cjs'),
  authority: require.resolve('../merge-gate-install/guardian-candidate/independent-policy-source.cjs'),
  evaluator: require.resolve('../merge-gate-install/guardian-candidate/read-and-evaluate.cjs'),
  signed: require.resolve('../merge-gate-install/guardian-candidate/signed-policy.cjs'),
};

function currentPr(headSha = SHA, overrides = {}) {
  return {
    number: 12, state: 'open', draft: false,
    base: { ref: 'main', repo: { full_name: REPO, id: REPOSITORY } },
    head: { sha: headSha, repo: { full_name: REPO, id: REPOSITORY } },
    ...overrides,
  };
}

function hostConfig(overrides = {}) {
  const deliveries = new Set(), conclusions = new Set();
  return {
    enableOwnerReconciliation: true,
    ownerReconciliationGrant: 'EXPLICIT_OWNER_RECONCILIATION',
    authorizeReconciliation: async () => true,
    reconciliationRateLimiter: { allow: async () => true },
    trustedInstallationId: INSTALL,
    enableFailureCheckWrites: true,
    founderAuthorizedFailureOnly: 'EXPLICIT_FAILURE_ONLY',
    webhookSecret: secret,
    deliveryStore: { reserveOnce: async (deliveryId) => {
      if (deliveries.has(deliveryId)) return false;
      deliveries.add(deliveryId);
      return true;
    } },
    conclusionStore: { reserveOnce: async ({ repositoryId, pullNumber, headSha }) => {
      const key = [repositoryId, pullNumber, headSha].join(':');
      if (conclusions.has(key)) return false;
      conclusions.add(key);
      return true;
    } },
    installationStore: {
      getVerifiedBinding: async () => ({
        installationId: INSTALL, appId: APP,
        ownerAccountId: OWNER, repositoryId: REPOSITORY,
      }),
    },
    policyAuthority: {},
    guardianAppId: APP, expectedOwnerAccountId: OWNER,
    expectedRepositoryId: REPOSITORY,
    githubAppPrivateKeyPem: 'synthetic-no-secret',
    ...overrides,
  };
}

async function withSyntheticHost(config, fn) {
  const collector = require(modulePaths.collector);
  const api = require(modulePaths.api);
  const authority = require(modulePaths.authority);
  const evaluator = require(modulePaths.evaluator);
  const signed = require(modulePaths.signed);
  const patches = [];
  function patch(object, key, value) {
    patches.push({ object, key, previous: object[key] });
    object[key] = value;
  }
  const calls = { pulls: 0, failureWrites: 0, successWrites: 0,
    scopeReads: 0, tokenMints: 0 };
  patch(collector, 'readGuardianGithubJson', async (path) => {
    assert.equal(path, URL);
    calls.pulls++;
    if (config.failPull === true) throw new Error('synthetic GET unavailable');
    const head = typeof config.headForRead === 'function' ?
      config.headForRead(calls.pulls) : SHA;
    return { body: currentPr(head, config.prOverrides || {}), link: '' };
  });
  patch(api, 'mintScopedInstallationToken', async () => {
    calls.tokenMints++;
    return { token: 'synthetic-app-installation-token-long-enough' };
  });
  patch(api, 'revalidateCurrentInstallationScope', async () => {
    calls.scopeReads++;
    if (config.failScope) throw new Error('synthetic suspended install');
    return { current: true };
  });
  patch(api, 'postFailureOnlyCheck', async ({ headSha, appId }) => {
    calls.failureWrites++;
    assert.equal(headSha, SHA);
    assert.equal(appId, APP);
    if (config.failPost) throw new Error('uncertain synthetic POST');
    return { checkRunId: 9001, headSha, conclusion: 'failure' };
  });
  patch(api, 'postConclusiveSuccessCheck', async ({ headSha, appId }) => {
    calls.successWrites++;
    assert.equal(headSha, SHA);
    assert.equal(appId, APP);
    if (config.failPost) throw new Error('uncertain synthetic POST');
    return { checkRunId: 9002, headSha, conclusion: 'success' };
  });
  patch(authority, 'fetchIndependentlySignedPolicy', async () =>
    config.policy === 'valid' ?
      { envelope: 'synthetic-envelope', publicKeyPem: 'synthetic-key' } : null);
  patch(evaluator, 'readAndEvaluateGuardianCandidate', async () => {
    if (config.evidenceReason) return {
      reason: config.evidenceReason, eligibleForSuccess: false,
    };
    return { reason: 'EVIDENCE_CONCLUSIVE_CANDIDATE',
      eligibleForSuccess: true, signedPolicySha256: 'synthetic-digest' };
  });
  patch(signed, 'verifySignedPolicy', () => ({
    signatureChecked: config.signedValid !== false,
    headSha: SHA, payloadSha256: 'synthetic-digest',
    releasePolicy: { guardianAppId: APP },
  }));
  delete require.cache[modulePaths.runtime];
  const runtime = require(modulePaths.runtime);
  try { return await fn({ runtime, calls }); }
  finally {
    for (const entry of patches.reverse()) entry.object[entry.key] = entry.previous;
    delete require.cache[modulePaths.runtime];
  }
}

function reconcile(runtime, host, headSha = SHA) {
  return runtime.processGuardianReconciliation({
    pullNumber: 12, headSha, host, operatorSession: 'synthetic-owner',
  });
}

test('feature OFF cannot reserve a delivery or publish a Check', async () => {
  await withSyntheticHost({}, async ({ runtime, calls }) => {
    const response = await reconcile(runtime, hostConfig({
      enableFailureCheckWrites: false,
    }));
    assert.equal(response.reason, 'FEATURE_OFF');
    assert.deepEqual([calls.tokenMints, calls.pulls, calls.failureWrites], [0, 0, 0]);
  });
});

test('both write modes require a durable conclusion store', async () => {
  await withSyntheticHost({}, async ({ runtime, calls }) => {
    const host = hostConfig({ conclusionStore: undefined });
    assert.equal((await reconcile(runtime, host)).reason,
      'HOST_TRUST_OR_DURABLE_REPLAY_STORE_MISSING');
    assert.equal(calls.failureWrites, 0);
  });
});

test('failure-only reserves once for same head across concurrent events', async () => {
  await withSyntheticHost({}, async ({ runtime, calls }) => {
    const host = hostConfig();
    const responses = await Promise.all([
      reconcile(runtime, host), reconcile(runtime, host), reconcile(runtime, host),
    ]);
    assert.equal(responses.filter((r) =>
      r.reason === 'FAILURE_ONLY_CHECK_RECORDED').length, 1);
    assert.equal(responses.filter((r) =>
      r.reason === 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED').length, 2);
    assert.equal(calls.failureWrites, 1);
    assert.equal(calls.successWrites, 0);
  });
});

test('stale closed, draft, wrong-repo or moved head never consumes conclusion', async () => {
  for (const overrides of [
    { state: 'closed' }, { draft: true },
    { base: { ref: 'other', repo: { full_name: REPO, id: REPOSITORY } } },
    { head: { sha: SHA, repo: { full_name: REPO, id: 999 } } },
    { head: { sha: 'b'.repeat(40),
      repo: { full_name: REPO, id: REPOSITORY } } },
  ]) {
    await withSyntheticHost({ prOverrides: overrides },
      async ({ runtime, calls }) => {
        const response = await reconcile(runtime, hostConfig());
        assert.equal(response.reason, 'FRESH_PR_TARGET_UNVERIFIED');
        assert.equal(calls.failureWrites, 0);
        assert.equal(calls.pulls, 1);
      });
  }
});

test('PR moves after atomic reservation: tombstone remains and zero Checks issued', async () => {
  await withSyntheticHost({ headForRead: (n) =>
    n === 1 ? SHA : 'b'.repeat(40) }, async ({ runtime, calls }) => {
    const host = hostConfig();
    const one = await reconcile(runtime, host);
    assert.equal(one.reason, 'PR_TARGET_CHANGED_AFTER_RESERVATION');
    assert.equal(calls.failureWrites, 0);
    const again = await reconcile(runtime, host);
    assert.equal(again.reason, 'FRESH_PR_TARGET_UNVERIFIED');
    assert.equal(calls.failureWrites, 0);
  });
});

test('uncertain Check POST burns durable slot, cannot silently retry same head', async () => {
  await withSyntheticHost({ failPost: true }, async ({ runtime, calls }) => {
    const host = hostConfig();
    const first = await reconcile(runtime, host);
    const second = await reconcile(runtime, host);
    assert.equal(first.reason, 'FAILURE_ONLY_CHECK_NOT_CONFIRMED');
    assert.equal(second.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
    assert.equal(calls.failureWrites, 1);
  });
});

test('source-only full-mode positive uses identical once-per-head guard', async () => {
  await withSyntheticHost({ policy: 'valid' }, async ({ runtime, calls }) => {
    const host = hostConfig({
      enableFailureCheckWrites: false,
      enableFullCheckWrites: true,
      founderAuthorizedFullMode: 'EXPLICIT_FULL_CHECK_WRITES',
    });
    const first = await reconcile(runtime, host);
    const duplicate = await reconcile(runtime, host);
    assert.equal(first.reason, 'SUCCESS_CHECK_RECORDED_RELEASE_HOLD');
    assert.equal(duplicate.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
    assert.equal(calls.successWrites, 1);
    assert.equal(calls.failureWrites, 0);
  });
});

test('nonconclusive full-mode evidence does not burn once-per-head slot', async () => {
  await withSyntheticHost({ policy: 'valid',
    evidenceReason: 'GUARDIAN_INDEPENDENT_EXACT_HEAD_APPROVALS_MISSING' },
  async ({ runtime, calls }) => {
    const host = hostConfig({
      enableFailureCheckWrites: false,
      enableFullCheckWrites: true,
      founderAuthorizedFullMode: 'EXPLICIT_FULL_CHECK_WRITES',
    });
    const a = await reconcile(runtime, host);
    const b = await reconcile(runtime, host);
    assert.equal(a.reason, 'AWAITING_CONCLUSIVE_EXACT_HEAD_EVIDENCE');
    assert.equal(b.reason, 'AWAITING_CONCLUSIVE_EXACT_HEAD_EVIDENCE');
    assert.equal(calls.pulls, 0);
    assert.equal(calls.successWrites, 0);
  });
});

test('terminal conclusive safety failure consumes one slot and emits only failure', async () => {
  await withSyntheticHost({ policy: 'valid',
    evidenceReason: 'GUARDIAN_PR_CHANGED_PROTECTED_SOURCE' },
  async ({ runtime, calls }) => {
    const host = hostConfig({
      enableFailureCheckWrites: false,
      enableFullCheckWrites: true,
      founderAuthorizedFullMode: 'EXPLICIT_FULL_CHECK_WRITES',
    });
    const first = await reconcile(runtime, host);
    const next = await reconcile(runtime, host);
    assert.equal(first.reason, 'FAILURE_ONLY_CHECK_RECORDED');
    assert.equal(next.reason, 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
    assert.equal(calls.failureWrites, 1);
    assert.equal(calls.successWrites, 0);
  });
});


test('same signed GitHub delivery ID is one-use across replayed webhook callbacks', async () => {
  const crypto = require('node:crypto');
  await withSyntheticHost({}, async ({ runtime, calls }) => {
    const host = hostConfig();
    const payload = {
      action: 'opened', number: 12,
      repository: { full_name: REPO }, installation: { id: INSTALL },
      pull_request: { number: 12,
        base: { ref: 'main', repo: { full_name: REPO } },
        head: { sha: SHA, repo: { full_name: REPO } },
      },
    };
    const rawBody = Buffer.from(JSON.stringify(payload));
    const signature = crypto.createHmac('sha256', secret)
      .update(rawBody).digest('hex');
    const headers = {
      'x-hub-signature-256': 'sha256=' + signature,
      'x-github-event': 'pull_request',
      'x-github-delivery': '12345678-1234-1234-1234-123456789abc',
    };
    const first = await runtime.processGuardianDelivery({ rawBody, headers, host });
    const replay = await runtime.processGuardianDelivery({ rawBody, headers, host });
    assert.equal(first.reason, 'FAILURE_ONLY_CHECK_RECORDED');
    assert.equal(replay.reason, 'DELIVERY_DUPLICATE_OR_NOT_RESERVED');
    assert.equal(calls.failureWrites, 1);
  });
});

test('old review event is rejected at HMAC-authenticated ingress, no reservations', async () => {
  const crypto = require('node:crypto');
  await withSyntheticHost({}, async ({ runtime, calls }) => {
    let reservations = 0;
    const host = hostConfig({
      deliveryStore: { reserveOnce: async () => { reservations++; return true; } },
    });
    const rawBody = Buffer.from(JSON.stringify({
      action: 'submitted',
      repository: { full_name: REPO },
      installation: { id: INSTALL },
      pull_request: { number: 12,
        base: { ref: 'main', repo: { full_name: REPO } },
        head: { sha: SHA, repo: { full_name: REPO } },
      },
      review: { state: 'approved', commit_id: 'b'.repeat(40) },
    }));
    const signature = crypto.createHmac('sha256', secret)
      .update(rawBody).digest('hex');
    const result = await runtime.processGuardianDelivery({ rawBody, host,
      headers: {
        'x-hub-signature-256': 'sha256=' + signature,
        'x-github-event': 'pull_request_review',
        'x-github-delivery': 'a2345678-1234-1234-1234-123456789abc',
      },
    });
    assert.equal(result.reason, 'WEBHOOK_REVIEW_EXACT_HEAD_UNVERIFIED');
    assert.equal(reservations, 0);
    assert.equal(calls.tokenMints, 0);
    assert.equal(calls.failureWrites, 0);
  });
});

test('durable storage errors and fresh scope failures never reach writer', async () => {
  await withSyntheticHost({}, async ({ runtime, calls }) => {
    const host = hostConfig({ conclusionStore: {
      reserveOnce: async () => { throw new Error('synthetic store offline'); },
    } });
    const result = await reconcile(runtime, host);
    assert.equal(result.reason, 'CONCLUSION_RESERVATION_UNVERIFIED');
    assert.equal(calls.failureWrites, 0);
  });
  await withSyntheticHost({ failScope: true }, async ({ runtime, calls }) => {
    const result = await reconcile(runtime, hostConfig());
    assert.equal(result.reason, 'FRESH_INSTALLATION_SCOPE_UNVERIFIED');
    assert.equal(calls.pulls, 0);
    assert.equal(calls.failureWrites, 0);
  });
});

test('invalid full-mode signature never reserves or publishes', async () => {
  await withSyntheticHost({ policy: 'valid', signedValid: false },
    async ({ runtime, calls }) => {
      let conclusions = 0;
      const host = hostConfig({
        enableFailureCheckWrites: false,
        enableFullCheckWrites: true,
        founderAuthorizedFullMode: 'EXPLICIT_FULL_CHECK_WRITES',
        conclusionStore: {
          reserveOnce: async () => { conclusions++; return true; },
        },
      });
      const result = await reconcile(runtime, host);
      assert.equal(result.reason, 'SIGNED_SUCCESS_AUTHORITY_STALE');
      assert.equal(conclusions, 0);
      assert.equal(calls.successWrites, 0);
    });
});
