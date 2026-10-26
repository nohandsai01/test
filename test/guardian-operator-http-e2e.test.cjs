'use strict';

// Loopback-only HTTP + real temporary SQLite D1 adapter. This test has no
// GitHub App credentials, no real API calls and no Check write transport.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = '../merge-gate-install/guardian-candidate/';
const COLLECTOR = require.resolve(ROOT + 'github-rest-collector.cjs');
const SINGLE = require.resolve(ROOT + 'guardian-conclusion-reconcile.cjs');
const BATCH = require.resolve(ROOT + 'guardian-conclusion-batch.cjs');
const OPERATOR = require.resolve(ROOT + 'guardian-operator-http.cjs');
const SERVER = require.resolve(ROOT + 'guardian-http-server.cjs');
const { createGuardianD1Stores } = require(ROOT + 'guardian-d1-stores.cjs');

const ROUTE = '/guardian/operator/check-reconcile';
const REPO = 'nohandsai01/test';
const SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
const CSRF = 'synthetic-csrf-token-123456789';
const TOKEN = 'synthetic-read-token-no-github-connection';

function adapter(db) {
  return {
    prepare(sql) {
      const prepared = db.prepare(sql);
      return { bind(...args) { return {
        async run() {
          const result = prepared.run(...args);
          return { success: true, meta: { changes: Number(result.changes) } };
        },
        async first() { return prepared.get(...args) ?? null; },
      }; } };
    },
  };
}
function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync(
    path.join(__dirname, ROOT, 'guardian-d1-schema.sql'), 'utf8'));
  return { db, store: createGuardianD1Stores(adapter(db)).conclusionStore };
}
function offlineSnapshot({ pullNumber, expectedHeadSha }) {
  return { repository: REPO,
    pullRequest: {
      number: pullNumber, state: 'open',
      base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: expectedHeadSha, repo: { full_name: REPO } },
    },
    checkRuns: {
      total_count: 1,
      check_runs: [{
        id: 501, name: 'NO HANDS Merge Gate Required Check',
        app: { id: 999 }, head_sha: expectedHeadSha,
        status: 'completed', conclusion: 'failure',
        completed_at: '2099-01-01T00:00:00Z',
      }],
    },
  };
}
function makeHost(store, counters, overrides = {}) {
  const operatorReadOnly = {
    publicOrigin: 'https://operator.example',
    ownerAccountId: 100, repositoryId: 88, guardianAppId: 999,
    conclusionStore: store,
    authenticateOwnerRequest: async () => {
      counters.auth++;
      return { sessionId: 'synthetic-owner-session-123', ownerAccountId: 100 };
    },
    verifyCsrf: async ({ token }) => {
      counters.csrf++;
      return token === CSRF;
    },
    rateLimiter: { allow: async () => { counters.rate++; return true; } },
    issueReadOnlyToken: async () => {
      counters.tokens++;
      return { repositoryId: 88, appId: 999, value: TOKEN,
        expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        permissions: { checks: 'read', pull_requests: 'read', metadata: 'read' } };
    },
    ...overrides,
  };
  return { enableReadOnlyOperatorRoutes: true, operatorReadOnly };
}
async function withHost({ enabled = true, overrideOperator = {},
  batchOverride = null } = {}, run) {
  const original = require(COLLECTOR).collectAuthenticatedGithubSnapshot;
  const calls = { remote: 0, auth: 0, csrf: 0, rate: 0, tokens: 0 };
  require(COLLECTOR).collectAuthenticatedGithubSnapshot = async (input) => {
    calls.remote++;
    assert.equal(input.installationToken, TOKEN);
    assert.equal(input.expectedHeadSha.length, 40);
    return offlineSnapshot(input);
  };
  for (const key of [SINGLE, BATCH, OPERATOR, SERVER]) delete require.cache[key];
  const batchModule = require(BATCH);
  const originalBatch = batchModule.reconcileGuardianConclusionBatch;
  if (batchOverride) batchModule.reconcileGuardianConclusionBatch = batchOverride;
  const { createGuardianHttpServer } = require(SERVER);
  const { db, store } = fixture();
  const host = enabled ? makeHost(store, calls, overrideOperator) : {};
  const server = createGuardianHttpServer({ host });
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return await run({ port: server.address().port, calls, store, host, db });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    db.close();
    require(COLLECTOR).collectAuthenticatedGithubSnapshot = original;
    batchModule.reconcileGuardianConclusionBatch = originalBatch;
    for (const key of [SINGLE, BATCH, OPERATOR, SERVER]) delete require.cache[key];
  }
}
function payload(targets = [{ pullNumber: 12, headSha: SHA }]) {
  return JSON.stringify({ schemaVersion: 1, targets });
}
function send(port, { body = payload(), target = ROUTE, method = 'POST',
  headers = {}, lengthOverride } = {}) {
  return new Promise((resolve, reject) => {
    const content = Buffer.from(body);
    const request = http.request({
      hostname: '127.0.0.1', port, path: target, method,
      headers: {
        Host: 'operator.example',
        Origin: 'https://operator.example',
        'Content-Type': 'application/json',
        'X-Guardian-Csrf': CSRF,
        ...(lengthOverride !== undefined ? {} :
          { 'Content-Length': content.length }),
        ...headers,
      },
    }, (response) => {
      const bytes = [];
      response.on('data', (part) => bytes.push(part));
      response.on('end', () => {
        try {
          resolve({ status: response.statusCode,
            headers: response.headers,
            body: JSON.parse(Buffer.concat(bytes).toString('utf8')),
          });
        } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.end(method === 'GET' ? undefined : content);
  });
}

test('default OFF host never exposes operator route, health shows no authority', async () => {
  await withHost({ enabled: false }, async ({ port, calls }) => {
    const unknown = await send(port);
    assert.equal(unknown.status, 404);
    const health = await send(port, { method: 'GET', target: '/healthz' });
    assert.equal(health.status, 200);
    assert.equal(health.body.feature, 'OFF_OR_SOURCE_ONLY');
    assert.equal(calls.remote, 0);
    assert.equal(calls.tokens, 0);
  });
});

test('read-only owner route exposes one sanitized HOLD for a persisted Check', async () => {
  await withHost({}, async ({ port, store, calls, db }) => {
    assert.equal(await store.reserveOnce({
      repositoryId: 88, pullNumber: 12, headSha: SHA,
      deliveryId: '12345678-1234-1234-1234-123456789abc',
    }), true);
    const response = await send(port);
    assert.equal(response.status, 200);
    assert.equal(response.body.status, 'SOURCE_ONLY_HOLD');
    assert.equal(response.body.activationAllowed, false);
    assert.equal(response.body.automaticRetryAllowed, false);
    assert.equal(response.body.releaseAuthorized, false);
    assert.equal(response.body.authoritativeRequiredCheck, 'NOT_ISSUED');
    assert.deepEqual(response.body.observations.map((v) => v.reason),
      ['RECONCILIATION_CHECK_OBSERVED_ONLY']);
    assert.equal(calls.remote, 1);
    assert.equal(calls.tokens, 1);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['content-security-policy'], "default-src 'none'");
    assert.equal(JSON.stringify(response.body).includes(TOKEN), false);
    assert.equal(JSON.stringify(response.body).includes('deliveryHash'), false);
    assert.equal(db.prepare(
      'SELECT count(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
  });
});

test('multiple PR heads use immutable input and sequential read-only observations', async () => {
  await withHost({}, async ({ port, store, calls }) => {
    assert.equal(await store.reserveOnce({
      repositoryId: 88, pullNumber: 12, headSha: SHA,
      deliveryId: '12345678-1234-1234-1234-123456789abc',
    }), true);
    const response = await send(port, {
      body: payload([{ pullNumber: 12, headSha: SHA },
        { pullNumber: 13, headSha: OTHER_SHA }]),
    });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.observations.map((entry) => entry.reason), [
      'RECONCILIATION_CHECK_OBSERVED_ONLY',
      'RECONCILIATION_NO_RESERVATION',
    ]);
    assert.equal(calls.remote, 1);
    assert.equal(response.body.observations[0].headSha, SHA);
    assert.equal(response.body.observations[1].headSha, OTHER_SHA);
  });
});

test('HTTP auth, origin, method and CSRF violations reject before token/SQL reads', async () => {
  await withHost({}, async ({ port, calls }) => {
    const variants = [
      { method: 'GET' }, { headers: { Host: 'attacker.example' } },
      { headers: { Origin: 'https://attacker.example' } },
      { headers: { 'X-Guardian-Csrf': 'incorrect-csrf-value-12345' } },
      { headers: { 'Content-Type': 'text/plain' } },
      { target: ROUTE + '?pull=12' },
    ];
    for (const opts of variants) {
      const r = await send(port, opts);
      assert.notEqual(r.status, 200);
    }
    assert.equal(calls.tokens, 0);
    assert.equal(calls.remote, 0);
  });
});

test('duplicate-key JSON, duplicate targets and >8 targets are rejected', async () => {
  await withHost({}, async ({ port, calls }) => {
    const variants = [
      '{"schemaVersion":1,"schemaVersion":1,"targets":[{"pullNumber":12,"headSha":"' + SHA + '"}]}',
      '{"schemaVersion":1,"targets":[{"pullNumber":12,"headSha":"' + SHA + '","headSha":"' + SHA + '"}]}',
      payload([{ pullNumber: 12, headSha: SHA }, { pullNumber: 12, headSha: SHA }]),
      payload(Array.from({ length: 9 }, (_, index) =>
        ({ pullNumber: index + 1, headSha: SHA }))),
      JSON.stringify({ schemaVersion: 1, targets: [{ pullNumber: 12, headSha: SHA }],
        unexpected: true }),
    ];
    for (const body of variants) {
      const response = await send(port, { body });
      assert.equal(response.status, 400);
      assert.equal(response.body.activationAllowed, false);
    }
    assert.equal(calls.tokens, 0);
    assert.equal(calls.remote, 0);
  });
});

test('owner auth and rate failures refuse all token and GitHub reads', async () => {
  await withHost({ overrideOperator: {
    authenticateOwnerRequest: async () => ({
      sessionId: 'synthetic-owner-session-123', ownerAccountId: 101 }),
  } }, async ({ port, calls }) => {
    assert.equal((await send(port)).status, 401);
    assert.equal(calls.remote, 0);
    assert.equal(calls.tokens, 0);
  });
  await withHost({ overrideOperator: {
    rateLimiter: { allow: async () => false },
  } }, async ({ port, calls }) => {
    assert.equal((await send(port)).status, 429);
    assert.equal(calls.remote, 0);
    assert.equal(calls.tokens, 0);
  });
});

test('write-capable, wrong-repo or overscoped read token is never used', async () => {
  const responses = [
    { repositoryId: 88, appId: 999, value: TOKEN,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      permissions: { checks: 'write', pull_requests: 'read', metadata: 'read' } },
    { repositoryId: 89, appId: 999, value: TOKEN,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      permissions: { checks: 'read', pull_requests: 'read', metadata: 'read' } },
    { repositoryId: 88, appId: 999, value: TOKEN,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      permissions: { checks: 'read', pull_requests: 'read', metadata: 'read',
        contents: 'write' } },
    { repositoryId: 88, appId: 999, value: TOKEN,
      expiresAt: new Date(Date.now() - 1_000).toISOString(),
      permissions: { checks: 'read', pull_requests: 'read', metadata: 'read' } },
    { repositoryId: 88, appId: 999, value: TOKEN,
      expiresAt: new Date(Date.now() + 3_600_000 + 120_000).toISOString(),
      permissions: { checks: 'read', pull_requests: 'read', metadata: 'read' } },
  ];
  for (const returned of responses) {
    await withHost({ overrideOperator: {
      issueReadOnlyToken: async () => returned,
    } }, async ({ port, calls }) => {
      const result = await send(port);
      assert.equal(result.status, 503);
      assert.equal(result.body.activationAllowed, false);
      assert.equal(calls.remote, 0);
    });
  }
});

test('missing protected host dependencies cannot enable reconciliation route', () => {
  const { createGuardianHttpServer } = require(SERVER);
  assert.throws(() => createGuardianHttpServer({
    host: { enableReadOnlyOperatorRoutes: true, operatorReadOnly: {} },
  }), /GUARDIAN_OPERATOR_TRUST_CONFIGURATION_MISSING/);
});


function forgedBatch(entries, extra = {}) {
  return {
    schemaVersion: 1,
    status: 'SOURCE_ONLY_HOLD',
    reason: 'RECONCILIATION_BATCH_OBSERVATIONS_ONLY',
    trusted: false,
    activationAllowed: false,
    releaseAuthorized: false,
    automaticRetryAllowed: false,
    authoritativeRequiredCheck: 'NOT_ISSUED',
    evaluatedTargetCount: entries.length,
    entries,
    ...extra,
  };
}
const cleanObservation = () => ({
  pullNumber: 12, headSha: SHA, status: 'SOURCE_ONLY_HOLD',
  reason: 'RECONCILIATION_CHECK_OBSERVED_ONLY',
  observedCheckRunId: 501, observedConclusion: 'failure',
  reservationObserved: true,
});

test('forged batch output or wrong target never leaks into HTTP reply', async () => {
  const poisoned = [
    forgedBatch([{ ...cleanObservation(), token: 'EXFILTRATE' }]),
    forgedBatch([{ ...cleanObservation(), trusted: true }]),
    forgedBatch([{ ...cleanObservation(), headSha: OTHER_SHA }]),
    forgedBatch([{ ...cleanObservation(), pullNumber: 13 }]),
    forgedBatch([{ ...cleanObservation(), reason: 'RECONCILIATION_OK\nSECRET' }]),
    forgedBatch([{ ...cleanObservation(), observedCheckRunId: '501' }]),
    forgedBatch([{ ...cleanObservation(), observedConclusion: 'neutral' }]),
    forgedBatch([cleanObservation()], { trusted: true }),
    forgedBatch([cleanObservation()], { reason: 'TRUSTED_APPROVAL' }),
    forgedBatch([cleanObservation()], { evaluatedTargetCount: 2 }),
  ];
  for (const report of poisoned) {
    await withHost({ batchOverride: async () => report },
      async ({ port, calls }) => {
        const result = await send(port);
        assert.equal(result.status, 503);
        assert.equal(result.body.reason, 'GUARDIAN_OPERATOR_RESULT_UNVERIFIED');
        assert.equal(result.body.activationAllowed, false);
        assert.equal(JSON.stringify(result.body).includes('EXFILTRATE'), false);
        assert.equal(calls.tokens, 1);
        assert.equal(calls.remote, 0);
      });
  }
});

test('batch result accessors and invalid optional fields fail without reading secrets', async () => {
  const entry = cleanObservation();
  Object.defineProperty(entry, 'reason', {
    enumerable: true, get() { throw new Error('synthetic secret getter'); },
  });
  for (const report of [
    forgedBatch([entry]),
    forgedBatch([{ ...cleanObservation(), reservationObserved: 'true' }]),
    forgedBatch([{ ...cleanObservation(), observedMatchingNameCount: -1 }]),
    forgedBatch([{ ...cleanObservation(), observedCheckRunId: 0 }]),
  ]) {
    await withHost({ batchOverride: async () => report },
      async ({ port, calls }) => {
        const res = await send(port);
        assert.equal(res.status, 503);
        assert.equal(res.body.activationAllowed, false);
        assert.equal(JSON.stringify(res.body).includes('synthetic secret'), false);
        assert.equal(calls.remote, 0);
      });
  }
});

test('owner session revoked during D1/GitHub reads prevents release of observations', async () => {
  let authCalls = 0;
  await withHost({ overrideOperator: {
    authenticateOwnerRequest: async () => {
      authCalls++;
      return { sessionId: 'synthetic-owner-session-123',
        ownerAccountId: authCalls === 1 ? 100 : 101 };
    },
  } }, async ({ port, store, calls }) => {
    assert.equal(await store.reserveOnce({
      repositoryId: 88, pullNumber: 12, headSha: SHA,
      deliveryId: '12345678-1234-1234-1234-123456789abc',
    }), true);
    const response = await send(port);
    assert.equal(response.status, 401);
    assert.equal(response.body.reason, 'GUARDIAN_OPERATOR_AUTH_REVOKED');
    assert.equal(response.body.observations, undefined);
    assert.equal(response.body.activationAllowed, false);
    assert.equal(calls.remote, 1);
    assert.equal(authCalls, 2);
  });
});

test('successful response cannot contain unexpected output metadata or token', async () => {
  await withHost({ batchOverride: async () => forgedBatch([cleanObservation()]) },
    async ({ port }) => {
      const result = await send(port);
      assert.equal(result.status, 200);
      assert.equal(result.body.observations.length, 1);
      assert.deepEqual(Object.keys(result.body.observations[0]).sort(), [
        'headSha', 'observedCheckRunId', 'observedConclusion',
        'pullNumber', 'reason', 'reservationObserved', 'status',
      ].sort());
      assert.equal(JSON.stringify(result.body).includes(TOKEN), false);
      assert.equal(result.body.authoritativeRequiredCheck, 'NOT_ISSUED');
      assert.equal(result.body.automaticRetryAllowed, false);
    });
});

test('oversized payload metadata is rejected before authentication or GitHub', async () => {
  await withHost({}, async ({ port, calls }) => {
    const result = await send(port, { body: ' '.repeat(4100) });
    assert.equal(result.status, 413);
    assert.equal(result.body.reason, 'GUARDIAN_OPERATOR_BODY_BOUND_INVALID');
    assert.equal(calls.auth, 0);
    assert.equal(calls.remote, 0);
  });
});


test('read token expiry during batch returns HOLD without leaking observations', async () => {
  const originalNow = Date.now;
  const start = originalNow();
  try {
    await withHost({ batchOverride: async () => {
      Date.now = () => start + 20 * 60_000;
      return forgedBatch([cleanObservation()]);
    } }, async ({ port }) => {
      const result = await send(port);
      assert.equal(result.status, 503);
      assert.equal(result.body.reason,
        'GUARDIAN_OPERATOR_TOKEN_EXPIRED_DURING_READ');
      assert.equal(result.body.observations, undefined);
      assert.equal(result.body.activationAllowed, false);
    });
  } finally {
    Date.now = originalNow;
  }
});
