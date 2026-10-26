'use strict';

// Final integration: protected host + webhook runtime + D1 durable reservation
// + read-only operator Check reconciliation, on one loopback listener and a
// real temporary SQLite file with the actual Guardian schema. GitHub, policy
// and Check transports are stubbed; https egress is blocked; keys are
// ephemeral synthetic test keys. No real D1, App, Check or payment.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DIR = path.join(__dirname, '../merge-gate-install/guardian-candidate');
const ROOT = '../merge-gate-install/guardian-candidate/';
const paths = Object.fromEntries(Object.entries({
  host: 'guardian-protected-host.cjs', server: 'guardian-http-server.cjs',
  runtime: 'guardian-webhook-runtime.cjs', operator: 'guardian-operator-http.cjs',
  batch: 'guardian-conclusion-batch.cjs', single: 'guardian-conclusion-reconcile.cjs',
  api: 'github-app-identity.cjs', collector: 'github-rest-collector.cjs',
  authority: 'independent-policy-source.cjs', evaluator: 'read-and-evaluate.cjs',
  signed: 'signed-policy.cjs',
}).map(([key, file]) => [key, require.resolve(ROOT + file)]));
const RELOAD = ['host', 'server', 'runtime', 'operator', 'batch', 'single'];
const SCHEMA = fs.readFileSync(path.join(DIR, 'guardian-d1-schema.sql'), 'utf8');

const SHA = 'a'.repeat(40);
const APP = 999, INSTALL = 42, OWNER = 100, REPOSITORY = 88;
const REPO = 'nohandsai01/test';
const SECRET = 'synthetic-host-webhook-secret-' + 'z'.repeat(35);
const CSRF = 'synthetic-csrf-token-123456789';
const READ_TOKEN = 'synthetic-read-token-no-github-connection';
const ORIGIN = 'https://operator.example';
const ROUTE = '/guardian/operator/check-reconcile';
const APP_KEY = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ format: 'pem', type: 'pkcs8' });
const POLICY_PUBLIC = crypto.generateKeyPairSync('ed25519').publicKey;
const POLICY_PIN = crypto.createHash('sha256')
  .update(POLICY_PUBLIC.export({ format: 'der', type: 'spki' })).digest('hex');

function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec(SCHEMA);
  db.prepare('INSERT OR IGNORE INTO guardian_installation_bindings VALUES (?, ?, ?, ?, ?)')
    .run(INSTALL, APP, OWNER, REPOSITORY, '2026-10-26T00:00:00.000Z');
  return db;
}
function d1(db, faults = { mode: null }) {
  return { prepare(sql) {
    if (faults.mode === 'throw') throw new Error('synthetic D1 outage');
    const statement = db.prepare(sql);
    return { bind(...args) { return {
      async run() {
        const result = statement.run(...args);
        return { success: true, meta: { changes: Number(result.changes) } };
      },
      async first() { return statement.get(...args) ?? null; },
    }; } };
  } };
}
const reservations = (db) =>
  db.prepare('SELECT * FROM guardian_conclusion_reservations ORDER BY head_sha').all()
    .map((row) => ({ ...row }));
function tempFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nohands-guardian-final-'));
  return { file: path.join(dir, 'guardian.sqlite'), dir };
}

function operatorConfig(counters, overrides = {}) {
  return {
    publicOrigin: ORIGIN,
    authenticateOwnerRequest: async () => {
      counters.auth++;
      return { sessionId: 'synthetic-owner-session-123', ownerAccountId: OWNER };
    },
    verifyCsrf: async ({ token }) => token === CSRF,
    rateLimiter: { allow: async () => true },
    issueReadOnlyToken: async () => {
      counters.readTokens++;
      return { repositoryId: REPOSITORY, appId: APP, value: READ_TOKEN,
        expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
        permissions: { checks: 'read', pull_requests: 'read', metadata: 'read' } };
    },
    ...overrides,
  };
}
function hostConfig(binding, counters, { operator = {}, ...overrides } = {}) {
  return {
    listenAddress: '127.0.0.1', port: 0,
    mode: 'FAILURE_ONLY', modeGrant: 'EXPLICIT_FAILURE_ONLY',
    guardianAppId: APP, trustedInstallationId: INSTALL,
    expectedOwnerAccountId: OWNER, expectedRepositoryId: REPOSITORY,
    webhookSecret: SECRET, githubAppPrivateKeyPem: APP_KEY,
    policyAuthority: { hostname: 'policy.example.com',
      publicKeyPem: POLICY_PUBLIC.export({ format: 'pem', type: 'spki' }),
      pinnedSpkiSha256: POLICY_PIN },
    d1Binding: binding,
    operatorReadOnly: operatorConfig(counters, operator),
    ...overrides,
  };
}

function snapshot({ pullNumber, expectedHeadSha }) {
  return { repository: REPO,
    pullRequest: { number: pullNumber, state: 'open',
      base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: expectedHeadSha, repo: { full_name: REPO } } },
    checkRuns: { total_count: 1, check_runs: [{
      id: 9001, name: 'NO HANDS Merge Gate Required Check', app: { id: APP },
      head_sha: expectedHeadSha, status: 'completed', conclusion: 'failure',
      completed_at: '2099-01-01T00:00:00Z' }] } };
}

async function withCandidate(options, run) {
  const modules = Object.fromEntries(['api', 'collector', 'authority', 'evaluator',
    'signed'].map((key) => [key, require(paths[key])]));
  const patches = [];
  const patch = (object, key, value) => {
    patches.push({ object, key, previous: object[key] });
    object[key] = value;
  };
  const calls = { egress: 0, failureWrites: 0, successWrites: 0, snapshots: 0,
    auth: 0, readTokens: 0 };
  patch(https, 'request', () => { calls.egress++; throw new Error('egress blocked'); });
  patch(https, 'get', () => { calls.egress++; throw new Error('egress blocked'); });
  patch(modules.api, 'mintScopedInstallationToken', async () =>
    ({ token: 'synthetic-installation-token-long-enough' }));
  patch(modules.api, 'revalidateCurrentInstallationScope', async () => ({ current: true }));
  patch(modules.api, 'postFailureOnlyCheck', async ({ headSha }) => {
    calls.failureWrites++;
    return { checkRunId: 9001, headSha, conclusion: 'failure' };
  });
  patch(modules.api, 'postConclusiveSuccessCheck', async () => {
    calls.successWrites++;
    throw new Error('success writer must not be reachable in failure-only mode');
  });
  patch(modules.collector, 'readGuardianGithubJson', async () => ({ link: '',
    body: { number: 12, state: 'open', draft: false,
      base: { ref: 'main', repo: { full_name: REPO, id: REPOSITORY } },
      head: { sha: SHA, repo: { full_name: REPO, id: REPOSITORY } } } }));
  patch(modules.collector, 'collectAuthenticatedGithubSnapshot', async (input) => {
    calls.snapshots++;
    assert.equal(input.installationToken, READ_TOKEN);
    return options.snapshot ? options.snapshot(input) : snapshot(input);
  });
  patch(modules.authority, 'fetchIndependentlySignedPolicy', async () =>
    ({ envelope: 'synthetic-envelope', publicKeyPem: 'synthetic-key' }));
  patch(modules.evaluator, 'readAndEvaluateGuardianCandidate', async () =>
    ({ reason: 'GUARDIAN_REVIEW_APPROVALS_INSUFFICIENT', eligibleForSuccess: false }));
  patch(modules.signed, 'verifySignedPolicy', () => ({ signatureChecked: false }));
  for (const key of RELOAD) delete require.cache[paths[key]];
  const { createGuardianProtectedHost } = require(paths.host);
  const created = [];
  const create = (config) => {
    const host = createGuardianProtectedHost(config);
    created.push(host);
    return host;
  };
  try {
    return await run({ create, calls });
  } finally {
    for (const host of created) {
      if (host.status().state === 'RUNNING') await host.stop().catch(() => {});
    }
    for (const entry of patches.reverse()) entry.object[entry.key] = entry.previous;
    for (const key of RELOAD) delete require.cache[paths[key]];
  }
}

function send(port, { method, target, body, headers }) {
  return new Promise((resolve, reject) => {
    const content = Buffer.from(body);
    const req = http.request({ hostname: '127.0.0.1', port, path: target, method,
      agent: false, headers: { 'Content-Length': content.length, ...headers } }, (res) => {
      const bytes = [];
      res.on('data', (part) => bytes.push(part));
      res.on('end', () => resolve({ status: res.statusCode,
        body: JSON.parse(Buffer.concat(bytes).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(content);
  });
}
function webhook(port, deliveryId = crypto.randomUUID()) {
  const body = JSON.stringify({ action: 'synchronize', number: 12,
    repository: { full_name: REPO }, installation: { id: INSTALL },
    pull_request: { number: 12, base: { ref: 'main', repo: { full_name: REPO } },
      head: { sha: SHA, repo: { full_name: REPO } } } });
  return send(port, { method: 'POST', target: '/github/webhook', body, headers: {
    'Content-Type': 'application/json', 'X-GitHub-Event': 'pull_request',
    'X-GitHub-Delivery': deliveryId,
    'X-Hub-Signature-256': 'sha256=' +
      crypto.createHmac('sha256', SECRET).update(body).digest('hex') } });
}
const operatorBody = () =>
  JSON.stringify({ schemaVersion: 1, targets: [{ pullNumber: 12, headSha: SHA }] });
const operatorHeaders = (length) => ({ Host: 'operator.example', Origin: ORIGIN,
  'Content-Type': 'application/json', 'X-Guardian-Csrf': CSRF,
  ...(length === undefined ? {} : { 'Content-Length': length }) });
function operator(port) {
  return send(port, { method: 'POST', target: ROUTE, body: operatorBody(),
    headers: operatorHeaders() });
}
const portOf = (host) => host.status().address.port;

test('webhook Check, read-only operator observation and restart share one durable reservation', async () => {
  const { file, dir } = tempFile();
  try {
    await withCandidate({}, async ({ create, calls }) => {
      const db = openDb(file);
      const host = create(hostConfig(d1(db), calls));
      await host.start();
      const published = await webhook(portOf(host));
      assert.equal(published.body.reason, 'FAILURE_ONLY_CHECK_RECORDED');
      const before = reservations(db);
      assert.equal(before.length, 1);

      const observed = await operator(portOf(host));
      assert.equal(observed.status, 200);
      assert.deepEqual(observed.body.observations.map((o) => o.reason),
        ['RECONCILIATION_CHECK_OBSERVED_ONLY']);
      assert.equal(observed.body.automaticRetryAllowed, false);
      assert.equal(observed.body.releaseAuthorized, false);
      assert.equal(JSON.stringify(observed.body).includes(READ_TOKEN), false);
      assert.deepEqual(reservations(db), before, 'operator query must not mutate D1');

      await host.restart();
      assert.deepEqual(reservations(db), before, 'restart must not clear the reservation');
      assert.equal((await operator(portOf(host))).body.observations[0].reservationObserved, true);
      assert.equal((await webhook(portOf(host))).body.reason,
        'CONCLUSION_ALREADY_RESERVED_OR_UNRECONCILED');
      assert.deepEqual([calls.failureWrites, calls.successWrites, calls.egress], [1, 0, 0]);
      await host.stop();
      db.close();
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('operator through the host fails closed on revoked session, expired token and stalled dependency', async () => {
  const originalNow = Date.now;
  let authCalls = 0;
  const cases = [
    { name: 'session revoked', operator: { authenticateOwnerRequest: async () => {
      authCalls++;
      return { sessionId: 'synthetic-owner-session-123',
        ownerAccountId: authCalls % 2 === 1 ? OWNER : OWNER + 1 };
    } }, status: 401, reason: 'GUARDIAN_OPERATOR_AUTH_REVOKED' },
    { name: 'token expired during read', snapshot: (input) => {
      const start = originalNow();
      Date.now = () => start + 20 * 60_000;
      return snapshot(input);
    }, status: 503, reason: 'GUARDIAN_OPERATOR_TOKEN_EXPIRED_DURING_READ' },
    { name: 'GitHub read stalled', operator: { requestTimeoutMs: 75 },
      snapshot: () => new Promise(() => {}),
      status: 503, reason: 'GUARDIAN_OPERATOR_READ_DEADLINE_EXCEEDED' },
    { name: 'token issuer stalled', operator: { requestTimeoutMs: 75,
      issueReadOnlyToken: () => new Promise(() => {}) },
    status: 503, reason: 'GUARDIAN_OPERATOR_READ_DEADLINE_EXCEEDED' },
  ];
  for (const scenario of cases) {
    try {
      await withCandidate({ snapshot: scenario.snapshot }, async ({ create, calls }) => {
        const db = openDb(':memory:');
        const host = create(hostConfig(d1(db), calls, { operator: scenario.operator }));
        await host.start();
        await webhook(portOf(host));
        const before = reservations(db);
        const result = await operator(portOf(host));
        Date.now = originalNow;
        assert.equal(result.status, scenario.status, scenario.name);
        assert.equal(result.body.reason, scenario.reason, scenario.name);
        assert.equal(result.body.observations, undefined, scenario.name);
        assert.equal(result.body.activationAllowed, false);
        assert.deepEqual(reservations(db), before, scenario.name);
        assert.equal(calls.failureWrites, 1, scenario.name);
        await host.stop();
        db.close();
      });
    } finally { Date.now = originalNow; }
  }
});

test('client disconnect and host stop abort an in-flight operator request without a response or write', async () => {
  for (const trigger of ['client', 'stop']) {
    let markStarted, markAborted;
    const started = new Promise((resolve) => { markStarted = resolve; });
    const aborted = new Promise((resolve) => { markAborted = resolve; });
    await withCandidate({}, async ({ create, calls }) => {
      const db = openDb(':memory:');
      const host = create(hostConfig(d1(db), calls, { drainTimeoutMs: 50, operator: {
        requestTimeoutMs: 5000,
        issueReadOnlyToken: ({ signal }) => new Promise((resolve, reject) => {
          markStarted();
          const cancel = () => { markAborted(); reject(new Error('aborted')); };
          signal.addEventListener('abort', cancel, { once: true });
          if (signal.aborted) cancel();
        }),
      } }));
      await host.start();
      const body = Buffer.from(operatorBody());
      const req = http.request({ hostname: '127.0.0.1', port: portOf(host), path: ROUTE,
        method: 'POST', agent: false, headers: operatorHeaders(body.length) });
      let responded = false;
      req.on('response', () => { responded = true; });
      req.on('error', () => {});
      req.end(body);
      await started;
      let stopped;
      const stopStarted = performance.now();
      if (trigger === 'client') req.destroy(); else stopped = await host.stop();
      // Drain deadline is 50 ms; stop must force-close instead of waiting for
      // the operator's own 5 s request deadline.
      if (stopped) assert.ok(performance.now() - stopStarted < 1500, 'stop did not force-close');
      await Promise.race([aborted, new Promise((_, reject) =>
        setTimeout(() => reject(new Error('abort not propagated: ' + trigger)), 2000))]);
      assert.equal(responded, false, trigger);
      if (stopped) assert.equal(stopped.abandonedInFlight, 1);
      assert.deepEqual([calls.snapshots, calls.failureWrites], [0, 0], trigger);
      assert.equal(reservations(db).length, 0);
      db.close();
    });
  }
});

test('D1 outage on the operator path latches host HOLD so no later webhook can publish', async () => {
  await withCandidate({}, async ({ create, calls }) => {
    const db = openDb(':memory:');
    const faults = { mode: null };
    const host = create(hostConfig(d1(db, faults), calls, { dependencyFaultThreshold: 1 }));
    await host.start();
    faults.mode = 'throw';
    const result = await operator(portOf(host));
    assert.notEqual(result.body.observations?.[0]?.reason, 'RECONCILIATION_CHECK_OBSERVED_ONLY');
    assert.equal(host.status().holdReason, 'GUARDIAN_HOST_D1_FAULT_HOLD');
    faults.mode = null;
    const blocked = await webhook(portOf(host));
    assert.equal(blocked.status, 503);
    assert.equal(blocked.body.reason, 'GUARDIAN_HOST_D1_FAULT_HOLD');
    assert.equal((await operator(portOf(host))).body.reason, 'GUARDIAN_HOST_D1_FAULT_HOLD');
    assert.deepEqual([calls.failureWrites, calls.snapshots], [0, 0]);
    assert.equal(reservations(db).length, 0);
    await host.stop();
    db.close();
  });
});

test('two integrated hosts on one D1 file: one Check, identical read-only observations', async () => {
  const { file, dir } = tempFile();
  try {
    await withCandidate({}, async ({ create, calls }) => {
      const dbA = openDb(file), dbB = openDb(file);
      const a = create(hostConfig(d1(dbA), calls));
      const b = create(hostConfig(d1(dbB), calls));
      await Promise.all([a.start(), b.start()]);
      const results = await Promise.all([webhook(portOf(a)), webhook(portOf(b)),
        webhook(portOf(a)), webhook(portOf(b))]);
      assert.equal(results.filter((r) =>
        r.body.reason === 'FAILURE_ONLY_CHECK_RECORDED').length, 1);
      assert.equal(calls.failureWrites, 1);
      const before = reservations(dbA);
      const [viewA, viewB] = await Promise.all([operator(portOf(a)), operator(portOf(b))]);
      assert.deepEqual(viewA.body.observations, viewB.body.observations);
      assert.equal(viewA.body.observations[0].reason, 'RECONCILIATION_CHECK_OBSERVED_ONLY');
      assert.deepEqual(reservations(dbB), before);
      assert.equal(calls.egress, 0);
      dbA.close(); dbB.close();
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('host names the rejected section when operator is valid but onboarding is not', async () => {
  await withCandidate({}, async ({ create, calls }) => {
    const db = openDb(':memory:');
    const config = hostConfig(d1(db), calls, {
      ownerOnboarding: { publicOrigin: 'https://owner.example' } });
    assert.throws(() => create(config), (error) =>
      error.code === 'GUARDIAN_HOST_CONFIG_INVALID' && error.field === 'ownerOnboarding');
    const badOperator = hostConfig(d1(db), calls, { operator: { requestTimeoutMs: 5 } });
    assert.throws(() => create(badOperator), (error) => error.field === 'operatorReadOnly');
    db.close();
  });
});

// Static closure check over the committed candidate source: the only module
// that can call a Check writer or reserve a conclusion is the webhook runtime,
// and the operator chain cannot reach it.
test('only the webhook runtime can reach Check writers or conclusion reservation', () => {
  const files = fs.readdirSync(DIR).filter((name) => name.endsWith('.cjs'));
  const source = Object.fromEntries(files.map((name) =>
    [name, fs.readFileSync(path.join(DIR, name), 'utf8')]));
  const writerUse = /\b(?:postFailureOnlyCheck|postConclusiveSuccessCheck)\b/;
  for (const [name, code] of Object.entries(source)) {
    if (name === 'github-app-identity.cjs' || name === 'guardian-webhook-runtime.cjs') continue;
    assert.equal(writerUse.test(code), false, name + ' references a Check writer');
    assert.equal(/\.reserveOnce\s*\(/.test(code), false, name + ' reserves directly');
    assert.equal(/\bprocessGuardianReconciliation\b/.test(code), false,
      name + ' reaches owner reconciliation');
  }
  const imports = (name) => [...source[name].matchAll(/require\('\.\/([^']+)'\)/g)]
    .map((match) => match[1]);
  const closure = (start) => {
    const seen = new Set(), queue = [start];
    while (queue.length) {
      const next = queue.pop();
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push(...imports(next));
    }
    return seen;
  };
  const operatorChain = closure('guardian-operator-http.cjs');
  for (const forbidden of ['github-app-identity.cjs', 'guardian-webhook-runtime.cjs',
    'guardian-d1-stores.cjs']) {
    assert.equal(operatorChain.has(forbidden), false, 'operator chain reaches ' + forbidden);
  }
  assert.match(source['guardian-protected-host.cjs'], /enableOwnerReconciliation: false/);
  assert.equal(/enableOwnerReconciliation:\s*true/.test(source['guardian-protected-host.cjs']), false);
});
