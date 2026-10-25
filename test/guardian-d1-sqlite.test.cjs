'use strict';
// Real SQLite schema + D1 API adapter on a temporary isolated test database.
// No Cloudflare D1 bindings, credentials, network, or production mutation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Worker } = require('node:worker_threads');
const { DatabaseSync } = require('node:sqlite');
const { createGuardianD1Stores } =
  require('../merge-gate-install/guardian-candidate/guardian-d1-stores.cjs');

const SCHEMA = path.join(__dirname, '../merge-gate-install/guardian-candidate/guardian-d1-schema.sql');
const WORKER = path.join(__dirname, 'guardian-d1-worker.cjs');
const SHA = 'a'.repeat(40);
const DELIVERY = '12345678-1234-1234-1234-123456789abc';
const ALT_DELIVERY = '22345678-1234-1234-1234-123456789abc';
const CLAIM = Object.freeze({
  repositoryId: 88, pullNumber: 12, headSha: SHA, deliveryId: DELIVERY,
});

function connect(dbFile) {
  const db = new DatabaseSync(dbFile);
  db.exec('PRAGMA busy_timeout=5000');
  return db;
}
function d1Adapter(db) {
  return {
    prepare(sql) {
      const statement = db.prepare(sql);
      return {
        bind(...params) {
          return {
            async run() {
              const result = statement.run(...params);
              return { success: true, meta: { changes: Number(result.changes) } };
            },
            async first() { return statement.get(...params) ?? null; },
          };
        },
      };
    },
  };
}
async function fixture(fn) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'nohands-guardian-d1-'));
  const file = path.join(temporary, 'guardian-test.sqlite');
  const connections = [];
  try {
    const first = connect(file);
    connections.push(first);
    first.exec('PRAGMA journal_mode=WAL');
    first.exec(fs.readFileSync(SCHEMA, 'utf8'));
    const second = connect(file);
    connections.push(second);
    return await fn({
      file,
      firstDb: first,
      secondDb: second,
      first: createGuardianD1Stores(d1Adapter(first)),
      second: createGuardianD1Stores(d1Adapter(second)),
    });
  } finally {
    for (const db of connections.reverse()) db.close();
    fs.rmSync(temporary, { force: true, recursive: true });
  }
}

function raceWorker(dbFile, claim, release) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER, { workerData: { dbFile, claim } });
    let ready = false, settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      worker.terminate().catch(() => {});
      reject(error);
    };
    worker.on('error', fail);
    worker.on('exit', (code) => {
      if (!settled) fail(new Error('Worker unexpectedly exited: ' + code));
    });
    worker.on('message', (payload) => {
      if (payload.ready) {
        if (ready) return fail(new Error('Duplicate worker ready signal'));
        ready = true;
        release.push(() => worker.postMessage('go'));
        return;
      }
      if (settled) return;
      settled = true;
      resolve(payload);
    });
  });
}

test('real SQLite schema persists exactly one delivery and one conclusion across independent D1 adapters', async () => {
  await fixture(async ({ first, second, firstDb }) => {
    assert.equal(await first.deliveryStore.reserveOnce(DELIVERY, {
      installationId: 42, pullNumber: 12, headSha: SHA,
    }), true);
    assert.equal(await second.deliveryStore.reserveOnce(DELIVERY.toUpperCase(), {
      installationId: 42, pullNumber: 12, headSha: SHA,
    }), false);
    assert.equal(await first.conclusionStore.reserveOnce(CLAIM), true);
    assert.equal(await second.conclusionStore.reserveOnce({
      ...CLAIM, deliveryId: ALT_DELIVERY,
    }), false);
    assert.equal(firstDb.prepare(
      'SELECT COUNT(*) AS n FROM guardian_delivery_receipts').get().n, 1);
    assert.equal(firstDb.prepare(
      'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
  });
});

test('real D1 conclusion is unique per repo/PR/head but allows separate head', async () => {
  await fixture(async ({ first, second, firstDb }) => {
    const claims = await Promise.all([
      first.conclusionStore.reserveOnce(CLAIM),
      second.conclusionStore.reserveOnce({ ...CLAIM, deliveryId: ALT_DELIVERY }),
    ]);
    assert.deepEqual(claims.sort(), [false, true]);
    assert.equal(await first.conclusionStore.reserveOnce({
      ...CLAIM, headSha: 'b'.repeat(40), deliveryId: ALT_DELIVERY,
    }), true);
    // Duplicate delivery ID across different heads must also remain blocked.
    assert.equal(await second.conclusionStore.reserveOnce({
      ...CLAIM, headSha: 'c'.repeat(40),
    }), false);
    assert.equal(firstDb.prepare(
      'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 2);
  });
});

test('four independent Node workers race on same SQLite unique slot', async () => {
  await fixture(async ({ file, firstDb }) => {
    const release = [];
    const tasks = Array.from({ length: 4 }, (_, index) =>
      raceWorker(file, { ...CLAIM,
        deliveryId: String(index + 1) + DELIVERY.slice(1),
      }, release));
    // Start each worker after all have sent ready, allowing concurrency.
    // Readiness is asynchronous; poll only in the test process (no GitHub I/O).
    const started = Date.now();
    while (release.length < tasks.length) {
      await new Promise((resolve) => setTimeout(resolve, 2));
      assert.ok(Date.now() - started < 5000, 'worker initialization timed out');
    }
    release.forEach((go) => go());
    const outcomes = await Promise.all(tasks);
    assert.equal(outcomes.filter((v) => v.ok === true).length, 1);
    assert.equal(outcomes.filter((v) => v.ok === false).length, 3);
    assert.equal(outcomes.filter((v) => v.errorCode).length, 0);
    assert.equal(firstDb.prepare(
      'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
  });
});

test('SQLite data persists a tombstone across connection restart', async () => {
  await fixture(async ({ file, first, firstDb }) => {
    assert.equal(await first.conclusionStore.reserveOnce(CLAIM), true);
    const reopen = connect(file);
    try {
      const again = createGuardianD1Stores(d1Adapter(reopen));
      assert.equal(await again.conclusionStore.reserveOnce({
        ...CLAIM, deliveryId: ALT_DELIVERY,
      }), false);
      assert.equal(reopen.prepare(
        'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
    } finally { reopen.close(); }
    assert.equal(firstDb.prepare(
      'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
  });
});

test('unexpected D1 mutation receipt and wrong readback never produce true', async () => {
  for (const anomaly of [
    { success: true, meta: { changes: 2 } },
    { success: false, meta: { changes: 1 } },
    { success: true, meta: { changes: -1 } },
    { success: true, meta: { changes: '1' } },
  ]) {
    const fake = createGuardianD1Stores({
      prepare: () => ({ bind: () => ({
        run: async () => anomaly,
        first: async () => { throw new Error('MUST NOT READ'); },
      }) }),
    });
    await assert.rejects(fake.conclusionStore.reserveOnce(CLAIM),
      { code: 'GUARDIAN_D1_RESULT_UNVERIFIED' });
  }
  for (const invalid of [null, { repository_id: 88, pull_number: 12,
    head_sha: 'b'.repeat(40), delivery_hash: 'c'.repeat(64) }]) {
    const fake = createGuardianD1Stores({
      prepare: () => ({ bind: () => ({
        run: async () => ({ success: true, meta: { changes: 1 } }),
        first: async () => invalid,
      }) }),
    });
    await assert.rejects(fake.conclusionStore.reserveOnce(CLAIM),
      { code: 'GUARDIAN_CONCLUSION_RESERVATION_READBACK_INVALID' });
    await assert.rejects(fake.deliveryStore.reserveOnce(DELIVERY, {
      installationId: 42, pullNumber: 12, headSha: SHA,
    }), { code: 'GUARDIAN_DELIVERY_RESERVATION_READBACK_INVALID' });
  }
});

test('uncertain post-write read leaves durable tombstone and blocks retry', async () => {
  await fixture(async ({ firstDb, second, first }) => {
    const source = d1Adapter(firstDb);
    let sabotage = true;
    const wrapped = {
      prepare(sql) {
        const statement = source.prepare(sql);
        return {
          bind(...params) {
            const bound = statement.bind(...params);
            return {
              run: () => bound.run(),
              first: async () => {
                if (sabotage) {
                  sabotage = false;
                  throw new Error('synthetic read interruption');
                }
                return bound.first();
              },
            };
          },
        };
      },
    };
    const unstable = createGuardianD1Stores(wrapped);
    await assert.rejects(unstable.conclusionStore.reserveOnce(CLAIM),
      { code: 'GUARDIAN_D1_READ_FAILED' });
    assert.equal(await second.conclusionStore.reserveOnce({
      ...CLAIM, deliveryId: ALT_DELIVERY,
    }), false);
    assert.equal(await first.conclusionStore.reserveOnce(CLAIM), false);
  });
});

test('SQL schema invalid rows are rejected rather than producing a claimed reservation', async () => {
  await fixture(async ({ firstDb }) => {
    assert.throws(() => firstDb.prepare(
      'INSERT INTO guardian_conclusion_reservations ' +
      '(repository_id,pull_number,head_sha,delivery_hash) VALUES (?, ?, ?, ?)'
    ).run(-1, 12, SHA, 'a'.repeat(64)));
    assert.throws(() => firstDb.prepare(
      'INSERT INTO guardian_delivery_receipts ' +
      '(delivery_hash, installation_id, pull_number, head_sha) VALUES (?, ?, ?, ?)'
    ).run('a'.repeat(64), -1, 12, SHA));
  });
});


test('two independently instantiated Guardian hosts share one SQLite-backed D1 Check slot', async () => {
  await fixture(async ({ first, second, firstDb }) => {
    const appId = 999, installationId = 42;
    const binding = { installationId, appId, ownerAccountId: 100,
      repositoryId: CLAIM.repositoryId, verifiedAt: '2026-10-26T00:00:00.000Z' };
    assert.equal(await first.installationStore.bindVerifiedOnce(binding), true);
    const collectorPath = require.resolve('../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
    const apiPath = require.resolve('../merge-gate-install/guardian-candidate/github-app-identity.cjs');
    const authorityPath = require.resolve('../merge-gate-install/guardian-candidate/independent-policy-source.cjs');
    const runtimePath = require.resolve('../merge-gate-install/guardian-candidate/guardian-webhook-runtime.cjs');
    const collector = require(collectorPath);
    const api = require(apiPath);
    const authority = require(authorityPath);
    const original = [];
    const patch = (object, name, value) => {
      original.push([object, name, object[name]]);
      object[name] = value;
    };
    let checks = 0;
    patch(collector, 'readGuardianGithubJson', async (url) => {
      assert.equal(url, '/repos/nohandsai01/test/pulls/12');
      return { link: '', body: { number: 12, state: 'open', draft: false,
        base: { ref: 'main', repo: { full_name: 'nohandsai01/test', id: 88 } },
        head: { sha: SHA, repo: { full_name: 'nohandsai01/test', id: 88 } },
      } };
    });
    patch(api, 'mintScopedInstallationToken', async () => ({ token: 'synthetic-only' }));
    patch(api, 'revalidateCurrentInstallationScope', async () => ({ current: true }));
    patch(api, 'postFailureOnlyCheck', async () => {
      checks++;
      return { checkRunId: 100, headSha: SHA, conclusion: 'failure' };
    });
    patch(authority, 'fetchIndependentlySignedPolicy', async () => null);
    delete require.cache[runtimePath];
    const { processGuardianReconciliation } = require(runtimePath);
    function host(store) {
      return {
        enableOwnerReconciliation: true,
        ownerReconciliationGrant: 'EXPLICIT_OWNER_RECONCILIATION',
        authorizeReconciliation: async () => true,
        reconciliationRateLimiter: { allow: async () => true },
        trustedInstallationId: installationId,
        enableFailureCheckWrites: true,
        founderAuthorizedFailureOnly: 'EXPLICIT_FAILURE_ONLY',
        deliveryStore: store.deliveryStore,
        conclusionStore: store.conclusionStore,
        installationStore: store.installationStore,
        policyAuthority: {}, guardianAppId: appId,
        expectedOwnerAccountId: 100, expectedRepositoryId: CLAIM.repositoryId,
        githubAppPrivateKeyPem: 'synthetic-not-real-key',
      };
    }
    function invoke(store) {
      return processGuardianReconciliation({
        pullNumber: 12, headSha: SHA, host: host(store),
        operatorSession: 'offline-synthetic-owner',
      });
    }
    try {
      const outcomes = await Promise.all([invoke(first), invoke(second)]);
      assert.equal(outcomes.filter((v) =>
        v.reason === 'FAILURE_ONLY_CHECK_RECORDED').length, 1);
      assert.equal(outcomes.filter((v) =>
        v.reason === 'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED').length, 1);
      assert.equal(checks, 1);
      assert.equal((await invoke(first)).reason,
        'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
      assert.equal(checks, 1);
      assert.equal(firstDb.prepare(
        'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
    } finally {
      for (const [object, name, value] of original.reverse()) object[name] = value;
      delete require.cache[runtimePath];
    }
  });
});


test('real D1 install intent is single-consume, owner-bound and expires fail closed', async () => {
  await fixture(async ({ first, second }) => {
    const stateSha256 = 'c'.repeat(64);
    const ownerSessionId = 'synthetic-owner-session-123';
    const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
    const now = new Date().toISOString();
    const args = { stateSha256, ownerSessionId, expiresAt };
    assert.equal(await first.intentStore.putIfAbsent(args), true);
    assert.equal(await second.intentStore.putIfAbsent(args), false);
    assert.equal(await second.intentStore.consumeIfOwnerAndUnexpired({
      stateSha256, ownerSessionId: 'another-owner-session-id', now,
    }), false);
    const result = await Promise.all([
      first.intentStore.consumeIfOwnerAndUnexpired({
        stateSha256, ownerSessionId, now,
      }),
      second.intentStore.consumeIfOwnerAndUnexpired({
        stateSha256, ownerSessionId, now,
      }),
    ]);
    assert.deepEqual(result.sort(), [false, true]);
    assert.equal(await first.intentStore.consumeIfOwnerAndUnexpired({
      stateSha256, ownerSessionId, now,
    }), false);
    assert.equal(await first.intentStore.consumeIfOwnerAndUnexpired({
      stateSha256, ownerSessionId, now: new Date(Date.now() + 6 * 60_000).toISOString(),
    }), false);
  });
});

test('real D1 OAuth state and PKCE verifier are consumed once by bound browser session', async () => {
  await fixture(async ({ first, second }) => {
    const now = new Date().toISOString();
    const stateSha256 = 'd'.repeat(64);
    const installationStateSha256 = 'e'.repeat(64);
    const browserSessionId = 'synthetic-browser-session-123';
    const args = {
      stateSha256, browserSessionId,
      installationStateSha256,
      installationId: 42, setupAction: 'install',
      codeVerifier: 'z'.repeat(43),
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    };
    assert.equal(await first.oauthStore.putIfAbsent(args), true);
    assert.equal(await second.oauthStore.putIfAbsent(args), false);
    assert.equal(await second.oauthStore.takeOnce({
      stateSha256, browserSessionId: 'wrong-browser-session-id',
      installationStateSha256, now,
    }), null);
    const accepted = await first.oauthStore.takeOnce({
      stateSha256, browserSessionId, installationStateSha256, now,
    });
    assert.deepEqual(accepted, {
      installationId: 42, setupAction: 'install',
      codeVerifier: 'z'.repeat(43),
    });
    assert.equal(await second.oauthStore.takeOnce({
      stateSha256, browserSessionId, installationStateSha256, now,
    }), null);
  });
});

test('verified installation binding is immutable across D1 connections', async () => {
  await fixture(async ({ first, second }) => {
    const verifiedAt = '2026-10-26T00:00:00.000Z';
    const binding = { installationId: 42, appId: 999,
      ownerAccountId: 100, repositoryId: 88, verifiedAt };
    assert.equal(await first.installationStore.bindVerifiedOnce(binding), true);
    assert.equal(await second.installationStore.bindVerifiedOnce({
      ...binding, repositoryId: 99,
    }), false);
    assert.deepEqual(await second.installationStore.getVerifiedBinding(42), {
      installationId: 42, appId: 999,
      ownerAccountId: 100, repositoryId: 88, verifiedAt,
    });
  });
});


test('read-only D1 reconciliation lookup returns exact immutable tombstone across connections', async () => {
  await fixture(async ({ first, second, firstDb }) => {
    assert.equal(await first.conclusionStore.getReservation({
      repositoryId: 88, pullNumber: 12, headSha: SHA,
    }), null);
    assert.equal(await first.conclusionStore.reserveOnce(CLAIM), true);
    const row = await second.conclusionStore.getReservation({
      repositoryId: 88, pullNumber: 12, headSha: SHA,
    });
    assert.equal(row.repositoryId, 88);
    assert.equal(row.pullNumber, 12);
    assert.equal(row.headSha, SHA);
    assert.match(row.deliveryHash, /^[a-f0-9]{64}$/);
    assert.match(row.createdAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.ok(Object.isFrozen(row));
    assert.equal(await second.conclusionStore.getReservation({
      repositoryId: 88, pullNumber: 12, headSha: 'c'.repeat(40),
    }), null);
    assert.equal(firstDb.prepare(
      'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
  });
});

test('D1 reconciliation refuses malformed row or uncertain read after SQL reservation', async () => {
  const values = [
    { repository_id: 88, pull_number: 12, head_sha: SHA,
      delivery_hash: 'BAD', created_at: '2026-10-26T01:00:00.000Z' },
    { repository_id: 88, pull_number: 12, head_sha: 'b'.repeat(40),
      delivery_hash: 'c'.repeat(64), created_at: '2026-10-26T01:00:00.000Z' },
    { repository_id: 88, pull_number: 12, head_sha: SHA,
      delivery_hash: 'c'.repeat(64), created_at: 'bad-time' },
  ];
  for (const value of values) {
    const fake = createGuardianD1Stores({
      prepare: () => ({ bind: () => ({
        first: async () => value,
      }) }),
    });
    await assert.rejects(fake.conclusionStore.getReservation({
      repositoryId: 88, pullNumber: 12, headSha: SHA,
    }), { code: 'GUARDIAN_CONCLUSION_LOOKUP_ROW_INVALID' });
  }
  const unstable = createGuardianD1Stores({
    prepare: () => ({ bind: () => ({
      first: async () => { throw new Error('synthetic D1 timeout'); },
    }) }),
  });
  await assert.rejects(unstable.conclusionStore.getReservation({
    repositoryId: 88, pullNumber: 12, headSha: SHA,
  }), { code: 'GUARDIAN_D1_READ_FAILED' });
  await assert.rejects(unstable.conclusionStore.getReservation({
    repositoryId: -1, pullNumber: 12, headSha: SHA,
  }), { code: 'GUARDIAN_CONCLUSION_LOOKUP_INVALID' });
});

test('operator reconciliation consumes real persisted D1 reservation but makes no writes', async () => {
  await fixture(async ({ first, second, firstDb }) => {
    assert.equal(await first.conclusionStore.reserveOnce(CLAIM), true);
    const collectorPath = require.resolve(
      '../merge-gate-install/guardian-candidate/github-rest-collector.cjs');
    const modulePath = require.resolve(
      '../merge-gate-install/guardian-candidate/guardian-conclusion-reconcile.cjs');
    const collector = require(collectorPath);
    const previous = collector.collectAuthenticatedGithubSnapshot;
    const checkName = 'NO HANDS Merge Gate Required Check';
    collector.collectAuthenticatedGithubSnapshot = async () => ({
      repository: 'nohandsai01/test',
      pullRequest: { number: 12,
        base: { ref: 'main', repo: { full_name: 'nohandsai01/test' } },
        head: { sha: SHA, repo: { full_name: 'nohandsai01/test' } },
      },
      checkRuns: { total_count: 1, check_runs: [{
        id: 700, name: checkName, head_sha: SHA,
        app: { id: 999 }, status: 'completed', conclusion: 'failure',
        completed_at: new Date(Date.now() + 60_000).toISOString(),
      }] },
    });
    delete require.cache[modulePath];
    try {
      const { reconcileGuardianConclusion } = require(modulePath);
      const result = await reconcileGuardianConclusion({
        repositoryId: 88, pullNumber: 12, headSha: SHA,
        expectedAppId: 999, installationToken: 'synthetic-readonly-long-token',
        conclusionStore: second.conclusionStore,
      });
      assert.equal(result.reason, 'RECONCILIATION_CHECK_OBSERVED_ONLY');
      assert.equal(result.authoritativeRequiredCheck, 'NOT_ISSUED');
      assert.equal(result.automaticRetryAllowed, false);
      assert.equal(result.trusted, false);
      assert.equal(firstDb.prepare(
        'SELECT COUNT(*) AS n FROM guardian_conclusion_reservations').get().n, 1);
      assert.equal(await second.conclusionStore.reserveOnce({
        ...CLAIM, deliveryId: ALT_DELIVERY,
      }), false);
    } finally {
      collector.collectAuthenticatedGithubSnapshot = previous;
      delete require.cache[modulePath];
    }
  });
});
